"""Router du module Diagnostic d'ingestion.

Expose la seule vue possible sur les flux rejetés par Akvorado : puisqu'un
flux rejeté n'est jamais stocké dans ClickHouse, ces routes interrogent
directement les métriques Prometheus de l'outlet (via `fetch_outlet_metrics`).
En cas d'échec de récupération des métriques, la page/le JSON reste
utilisable avec un message d'erreur clair — jamais un 500 nu, jamais une
page blanche.

TENDANCE (2026-08-09) — DÉFAUT MESURÉ : voir la docstring de
`app.services.ingestion` pour le rationnel complet. Chaque appel de ces deux
routes lit d'abord le point de comparaison (`annotate_trend`, AVANT
persistance) puis écrit le point courant (`record_rejection_history`, APRÈS
lecture) dans `ingestion_rejection_history` — l'ORDRE est important : lire
avant d'écrire évite de comparer le point courant à lui-même.

PURGE DES CUMULS FIGÉS (2026-08-10) — les trois routes POST de ce module
(`/purge`, `/purge-all-flat`, `/unmask-all`) masquent ou rétablissent des
lignes de rejet à l'écran. Elles ne touchent JAMAIS aux compteurs Akvorado :
un compteur Prometheus ne peut pas être remis à zéro autrement qu'en
redémarrant l'outlet (ce qui couperait l'ingestion). Voir le rationnel complet
dans `app.services.ingestion`.

Chacune répond en DOUBLE FORMAT, comme les actions de `db_health` : un
FRAGMENT HTML si l'en-tête `HX-Request` est présent, du JSON sinon. DÉFAUT
DÉJÀ RENCONTRÉ 9 FOIS sur ce projet : un bouton HTMX qui reçoit du JSON brut
l'insère TEL QUEL dans la page — l'exploitant lit alors un dictionnaire Python
au milieu de l'écran.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from app.clients.prometheus import fetch_outlet_metrics
from app.models import RejectionReason
from app.services.ingestion import (
    PurgeOutcome,
    annotate_trend,
    apply_rejection_masks,
    build_rejection_reasons,
    list_rejection_masks,
    purge_all_flat_rejections,
    purge_rejection,
    record_rejection_history,
    unmask_all_rejections,
    unmask_one_rejection,
)

log = logging.getLogger(__name__)

router = APIRouter()


def get_db_connection() -> sqlite3.Connection:
    """Placeholder — `app/main.py` doit surcharger cette dépendance avec la
    connexion SQLite réelle (même convention que les autres routers, ex.
    `app.routers.db_health.get_db_connection`).

    Raises:
        RuntimeError: si appelée sans override — signale un défaut de
            câblage plutôt que d'échouer silencieusement.
    """
    raise RuntimeError(
        "get_db_connection non câblée : app/main.py doit surcharger cette "
        "dépendance avec la connexion SQLite réelle."
    )


DbConnection = Annotated[sqlite3.Connection, Depends(get_db_connection)]


def _reasons_with_trend(
    metrics_reasons: list[RejectionReason], conn: sqlite3.Connection
) -> list[RejectionReason]:
    """Annote la tendance puis persiste le point courant — dans cet ORDRE.

    La lecture du point de comparaison (`annotate_trend`) doit précéder
    l'écriture du point courant (`record_rejection_history`) : écrire d'abord
    ferait comparer le point qu'on vient d'insérer à lui-même (delta toujours
    nul, un "flat" trompeur au lieu d'un "unknown" honnête sur la toute
    première mesure).
    """
    annotated = annotate_trend(conn, metrics_reasons)
    record_rejection_history(conn, metrics_reasons)
    return annotated


def _record_audit(conn: sqlite3.Connection, action: str, detail: str) -> None:
    """Trace un geste de masquage dans `audit_log` — même contrat que
    `app.routers.db_health._record_audit`.

    Masquer une ligne rouge est un geste d'exploitation : il doit laisser une
    trace, au même titre que les autres actions d'écriture. Un échec
    d'écriture de l'audit est journalisé mais jamais fatal pour le geste
    lui-même (la purge a déjà eu lieu).
    """
    try:
        conn.execute(
            "INSERT INTO audit_log (actor, action, detail) VALUES (?, ?, ?)",
            ("anonymous", action, detail),
        )
        conn.commit()
    except sqlite3.Error:
        log.error("ingestion: echec ecriture audit_log", exc_info=True)


def _actor(request: Request) -> str:
    """Utilisateur authentifié, publié sur `request.state` par le middleware
    d'authentification (`app.main.require_authentication`).

    Défaut 'anonymous' si l'attribut est absent — c'est le cas dans les tests
    de router isolés, qui ne montent pas le middleware. Jamais une identité
    inventée."""
    return str(getattr(request.state, "auth_username", "anonymous"))


async def _current_reasons(conn: sqlite3.Connection) -> list[RejectionReason]:
    """Mesure courante ANNOTÉE de la tendance, sans appliquer les masques.

    Les routes de purge ont besoin de la liste COMPLÈTE (masques non
    appliqués) : c'est sur elle que se décide ce qui est masquable, et c'est
    elle qui porte le cumul à mémoriser comme ligne de base. Filtrer d'abord
    rendrait un motif déjà masqué impossible à re-purger après reprise.
    """
    metrics = await fetch_outlet_metrics()
    return _reasons_with_trend(build_rejection_reasons(metrics), conn)


def _purge_response(
    request: Request, outcome: PurgeOutcome, conn: sqlite3.Connection
) -> JSONResponse | HTMLResponse:
    """Rend le résultat d'une purge : fragment HTML pour HTMX, JSON sinon.

    Le fragment porte aussi le nombre total de lignes actuellement masquées —
    l'écran doit rester capable de dire combien de rejets sont escamotés juste
    après le geste, sans attendre le rafraîchissement périodique.
    """
    payload = outcome.as_payload()
    payload["masked_total"] = len(list_rejection_masks(conn))

    if request.headers.get("HX-Request") == "true":
        templates = request.app.state.templates
        response: HTMLResponse = templates.TemplateResponse(
            request, "_ingestion_purge_fragment.html", {"result": payload}
        )
        return response

    return JSONResponse(content=payload)


@router.get("/api/ingestion")
async def list_rejections(conn: DbConnection) -> JSONResponse:
    """Liste des motifs de rejet à l'ingestion, en JSON.

    Réponse succès : `{"items": [...], "total": N, "masked": M}` — chaque item
    porte `trend_delta`/`trend_state` (voir `app.models.RejectionReason`), et
    `masked` annonce combien de motifs sont escamotés par une purge (voir
    `apply_rejection_masks`). Ne JAMAIS omettre ce compte : un consommateur
    d'API qui verrait une liste raccourcie sans savoir que des lignes sont
    masquées serait exactement le zéro silencieux qu'on cherche à éviter.
    Réponse échec de récupération des métriques : `{"error": "..."}`,
    jamais un 500 nu.
    """
    try:
        metrics = await fetch_outlet_metrics()
    except RuntimeError as exc:
        log.error("échec de récupération des métriques outlet pour /api/ingestion: %s", exc)
        return JSONResponse(status_code=200, content={"error": str(exc)})

    reasons = _reasons_with_trend(build_rejection_reasons(metrics), conn)
    visible, hidden = apply_rejection_masks(conn, reasons)
    return JSONResponse(
        content={
            "items": [reason.model_dump() for reason in visible],
            "total": len(visible),
            "masked": hidden,
        }
    )


@router.get("/ingestion")
async def get_ingestion(request: Request, conn: DbConnection) -> HTMLResponse:
    """Page HTML du diagnostic d'ingestion.

    En cas d'échec de récupération des métriques outlet, la page est quand
    même rendue avec un message d'erreur clair (jamais de 500 nu, jamais de
    page blanche). Chaque motif porte sa tendance récente (voir docstring du
    module) — un cumul figé depuis des heures ne s'affiche plus avec la même
    urgence visuelle qu'un rejet en cours (voir `ingestion.html`).
    """
    templates = request.app.state.templates
    error: str | None = None
    reasons: list[RejectionReason] = []
    masked_count = 0

    try:
        metrics = await fetch_outlet_metrics()
        annotated = _reasons_with_trend(build_rejection_reasons(metrics), conn)
        reasons, masked_count = apply_rejection_masks(conn, annotated)
    except RuntimeError as exc:
        log.error("échec de récupération des métriques outlet pour /ingestion: %s", exc)
        error = str(exc)

    # La liste des masques est toujours fournie au gabarit, même en erreur de
    # récupération des métriques : l'exploitant doit pouvoir RÉTABLIR ce qu'il
    # a masqué même quand l'outlet ne répond pas (sinon un masquage devient
    # irréversible pendant une panne — exactement le moment où il voudrait
    # tout revoir).
    masks = list_rejection_masks(conn)

    response: HTMLResponse = templates.TemplateResponse(
        request,
        "ingestion.html",
        {
            "items": reasons,
            "total": len(reasons),
            "error": error,
            "masked_count": masked_count,
            "masks": masks,
            "has_flat": any(r.trend_state == "flat" for r in reasons),
        },
    )
    return response


# ---------------------------------------------------------------------------
# Purge des cumuls figés — masquage côté Okvorado, JAMAIS de remise à zéro
# d'un compteur Prometheus (impossible sans redémarrer l'outlet, ce qui
# couperait l'ingestion). Voir `app.services.ingestion` pour le rationnel.
# ---------------------------------------------------------------------------


class PurgeRejectionRequest(BaseModel):
    """Couple (exportateur, motif) à masquer.

    Aucune allowlist ici, contrairement aux tables ClickHouse : ces deux
    valeurs ne sont jamais interpolées dans du SQL (toujours passées en
    paramètres liés `?`), et elles ne peuvent produire un masquage que si
    elles correspondent EXACTEMENT à un motif présent dans la mesure courante
    — une valeur arbitraire retourne `not_found`, pas un masque fantôme.
    `min_length=1` écarte la chaîne vide, qui ne peut correspondre à rien.
    """

    exporter: str = Field(min_length=1, max_length=255)
    error: str = Field(min_length=1, max_length=500)


@router.post("/api/ingestion/purge", response_model=None)
async def purge_one_rejection(
    request: Request, body: PurgeRejectionRequest, conn: DbConnection
) -> JSONResponse | HTMLResponse:
    """Masque UN couple (exportateur, motif) figé.

    REFUSE un motif dont le compteur grimpe encore (`refused_active`) ou dont
    la tendance est inconnue (`refused_unknown`) : la purge nettoie du bruit
    historique, elle ne doit jamais faire disparaître une panne en cours. Le
    refus est EXPLICITE dans la réponse — jamais un « 0 purgé » muet.
    """
    try:
        reasons = await _current_reasons(conn)
    except RuntimeError as exc:
        log.error("ingestion: purge impossible, métriques outlet indisponibles: %s", exc)
        return _purge_response(
            request,
            PurgeOutcome(
                error=(
                    "Métriques de l'outlet indisponibles : impossible de vérifier que "
                    f"ce rejet est bien figé avant de le masquer ({exc})."
                )
            ),
            conn,
        )

    outcome = purge_rejection(
        conn, reasons, exporter=body.exporter, error=body.error, actor=_actor(request)
    )
    if outcome.purged:
        _record_audit(
            conn,
            "ingestion_purge_rejection",
            f"exporter={body.exporter} error={body.error}",
        )
    return _purge_response(request, outcome, conn)


@router.post("/api/ingestion/purge-all-flat", response_model=None)
async def purge_all_flat(request: Request, conn: DbConnection) -> JSONResponse | HTMLResponse:
    """Masque d'un coup TOUS les cumuls prouvés figés.

    C'est le geste qui passe à l'échelle (cible produit : 350 routeurs, où
    purger ligne à ligne ne tient pas). Reste strictement SÉLECTIF : les
    motifs actifs ou de tendance inconnue sont laissés visibles et comptés
    en refus.
    """
    try:
        reasons = await _current_reasons(conn)
    except RuntimeError as exc:
        log.error("ingestion: purge globale impossible, métriques indisponibles: %s", exc)
        return _purge_response(
            request,
            PurgeOutcome(
                error=(
                    "Métriques de l'outlet indisponibles : impossible de déterminer "
                    f"quels rejets sont figés ({exc})."
                )
            ),
            conn,
        )

    outcome = purge_all_flat_rejections(conn, reasons, actor=_actor(request))
    if outcome.purged:
        _record_audit(
            conn,
            "ingestion_purge_all_flat",
            f"purged={outcome.purged} refused_active={outcome.refused_active} "
            f"refused_unknown={outcome.refused_unknown}",
        )
    return _purge_response(request, outcome, conn)


def _unmask_response(
    request: Request, restored: int, conn: sqlite3.Connection
) -> JSONResponse | HTMLResponse:
    """Rend le résultat d'une annulation de purge (fragment HTML ou JSON)."""
    payload = {
        "status": "ok",
        "restored": restored,
        "masked_total": len(list_rejection_masks(conn)),
    }
    if request.headers.get("HX-Request") == "true":
        templates = request.app.state.templates
        response: HTMLResponse = templates.TemplateResponse(
            request, "_ingestion_unmask_fragment.html", {"result": payload}
        )
        return response
    return JSONResponse(content=payload)


@router.post("/api/ingestion/unmask-all", response_model=None)
async def unmask_all(request: Request, conn: DbConnection) -> JSONResponse | HTMLResponse:
    """Rétablit TOUS les rejets masqués — annulation complète des purges.

    RÉVERSIBILITÉ : sans ce geste, un masquage serait définitif, donc
    lui-même un zéro silencieux. Après cet appel, chaque motif retrouve son
    cumul BRUT à l'écran.
    """
    restored = unmask_all_rejections(conn)
    if restored:
        _record_audit(conn, "ingestion_unmask_all", f"restored={restored}")
    return _unmask_response(request, restored, conn)


@router.post("/api/ingestion/unmask", response_model=None)
async def unmask_one(
    request: Request, body: PurgeRejectionRequest, conn: DbConnection
) -> JSONResponse | HTMLResponse:
    """Rétablit UN couple masqué — annulation ciblée, sans tout réafficher."""
    restored = unmask_one_rejection(conn, exporter=body.exporter, error=body.error)
    if restored:
        _record_audit(
            conn, "ingestion_unmask_rejection", f"exporter={body.exporter} error={body.error}"
        )
    return _unmask_response(request, restored, conn)
