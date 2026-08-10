"""Router Santé DB (LOT db_health) — page HTML + API JSON de surveillance
ClickHouse et actions de maintien SÛRES.

INTERDIT ABSOLU DE CE LOT : aucune route de ce routeur ne redémarre
ClickHouse — voir `app.services.db_health` pour le rationnel complet. Les
deux seules actions exposées (`OPTIMIZE TABLE`, purge de parts détachées)
sont des gestes ciblés, réversibles au sens où ils ne perdent aucune donnée
de flux, et déclenchés UNIQUEMENT par une demande explicite (clic
exploitant), jamais par la routine périodique.

Le client ClickHouse est injecté via `get_clickhouse_client` (même
convention que `app.routers.retention`), jamais importé directement.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, field_validator

from app.models import DbHealthSnapshot, DetachedPartsHealth, HealthState
from app.services.db_health import (
    MONITORED_TABLES,
    SYSTEM_LOG_TABLES,
    ClickHouseQueryable,
    DetachedPartsPurgeAllPreview,
    build_unavailable_snapshot,
    collect_snapshot,
    execute_detached_parts_purge,
    execute_detached_parts_purge_all,
    optimize_table,
    preview_detached_parts_purge,
    preview_detached_parts_purge_all,
)
from app.templating import build_templates

log = logging.getLogger(__name__)

router = APIRouter()

templates = build_templates()

_HISTORY_LIMIT = 200
"""Nombre maximal de points d'historique renvoyés à l'écran — assez pour un
graphe de dérive sur plusieurs jours au pas de 5 minutes (~288 points/jour),
sans faire exploser la taille de la réponse."""


def get_clickhouse_client() -> ClickHouseQueryable:
    """Placeholder — surchargé par `app/main.py` (voir `_wire_dependencies`).

    Raises:
        RuntimeError: si appelée sans override — signale un défaut de
            câblage plutôt que d'échouer silencieusement.
    """
    raise RuntimeError(
        "get_clickhouse_client n'est pas cablee : l'application doit fournir "
        "app.dependency_overrides[get_clickhouse_client] (voir app/deps.py) "
        "avec une instance compatible ClickHouseQueryable."
    )


def get_db_connection() -> sqlite3.Connection:
    """Placeholder — `app/main.py` doit surcharger cette dépendance avec la
    connexion SQLite réelle (même convention que les autres routers)."""
    raise RuntimeError(
        "get_db_connection non câblée : app/main.py doit surcharger cette "
        "dépendance avec la connexion SQLite réelle."
    )


def get_memory_limit_bytes() -> int:
    """Placeholder — surchargé par `app/main.py` avec `settings.db_health_memory_limit_bytes`."""
    raise RuntimeError("get_memory_limit_bytes non câblée : app/main.py doit la surcharger.")


DbConnection = Annotated[sqlite3.Connection, Depends(get_db_connection)]


def _error_response(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": message})


def _record_audit(conn: sqlite3.Connection, action: str, detail: str) -> None:
    """Insère une ligne dans `audit_log` — même schéma/convention que
    `app.routers.retention._record_audit`. Échec journalisé mais jamais
    fatal pour la requête métier qui l'a déclenché."""
    try:
        conn.execute(
            "INSERT INTO audit_log (actor, action, detail) VALUES (?, ?, ?)",
            ("ui", action, detail),
        )
        conn.commit()
    except sqlite3.Error:
        log.error("db_health: echec ecriture audit_log", exc_info=True, extra={"action": action})


def _record_history(conn: sqlite3.Connection, snapshot: DbHealthSnapshot) -> None:
    """Persiste le snapshot dans `db_health_history` — pour voir une dérive
    s'installer. Échec journalisé mais jamais fatal : un historique manquant
    n'empêche pas l'écran d'afficher l'état COURANT."""
    try:
        conn.execute(
            "INSERT INTO db_health_history (checked_at, overall_state, snapshot_json) "
            "VALUES (?, ?, ?)",
            (
                snapshot.checked_at.isoformat(),
                snapshot.overall_state.value,
                snapshot.model_dump_json(),
            ),
        )
        conn.commit()
    except sqlite3.Error:
        log.error("db_health: echec ecriture db_health_history", exc_info=True)


def _load_history(conn: sqlite3.Connection, limit: int = _HISTORY_LIMIT) -> list[dict[str, Any]]:
    """Lit les derniers points d'historique, du plus récent au plus ancien.

    ZÉRO SILENCIEUX : un échec de lecture retourne une liste vide ET journalise
    l'erreur — l'appelant (template) doit distinguer "aucun historique encore"
    de "lecture impossible" via le log, le comportement écran reste
    dégradé-mais-explicite (section vide plutôt qu'une exception qui casse
    toute la page).
    """
    try:
        rows = conn.execute(
            "SELECT checked_at, overall_state, snapshot_json FROM db_health_history "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    except sqlite3.Error:
        log.error("db_health: echec lecture db_health_history", exc_info=True)
        return []
    return [
        {"checked_at": row[0], "overall_state": row[1], "snapshot": json.loads(row[2])}
        for row in rows
    ]


def _snapshot_or_unavailable(
    client: ClickHouseQueryable, memory_limit_bytes: int
) -> DbHealthSnapshot:
    """Calcule le snapshot ; si même la première requête échoue (le client ne
    répond à rien), retourne un snapshot `UNAVAILABLE` explicite plutôt que
    de laisser l'exception remonter jusqu'à l'écran."""
    try:
        return collect_snapshot(client, memory_limit_bytes)
    except Exception as exc:
        log.error("db_health: echec total de la collecte de sante", exc_info=True)
        return build_unavailable_snapshot(str(exc))


@router.get("/db-health", response_class=HTMLResponse)
def get_db_health(
    request: Request,
    client: Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)],
    conn: DbConnection,
    memory_limit_bytes: Annotated[int, Depends(get_memory_limit_bytes)],
) -> Any:
    """Page HTML de surveillance de santé ClickHouse."""
    snapshot = _snapshot_or_unavailable(client, memory_limit_bytes)
    history = _load_history(conn, limit=50)

    return templates.TemplateResponse(
        request,
        "db_health.html",
        {
            "snapshot": snapshot,
            "history": history,
            "monitored_tables": sorted(MONITORED_TABLES),
            "system_log_tables": sorted(SYSTEM_LOG_TABLES),
            "HealthState": HealthState,
        },
    )


@router.get("/api/db-health")
def api_get_db_health(
    client: Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)],
    memory_limit_bytes: Annotated[int, Depends(get_memory_limit_bytes)],
) -> JSONResponse:
    """État de santé courant, en JSON — ne persiste rien dans l'historique
    (c'est la routine périodique qui alimente `db_health_history`, cet
    endpoint est un instantané à la demande)."""
    snapshot = _snapshot_or_unavailable(client, memory_limit_bytes)
    return JSONResponse(content=snapshot.model_dump(mode="json"))


@router.get("/api/db-health/history")
def api_get_db_health_history(conn: DbConnection) -> JSONResponse:
    """Historique des snapshots persistés par la routine périodique."""
    history = _load_history(conn)
    return JSONResponse(content={"items": history, "total": len(history)})


# ---------------------------------------------------------------------------
# OPTIMIZE TABLE — geste coûteux, preview puis execute
# ---------------------------------------------------------------------------


class OptimizePreviewRequest(BaseModel):
    table: str
    final: bool = False

    @field_validator("table")
    @classmethod
    def table_must_be_monitored(cls, value: str) -> str:
        if value not in MONITORED_TABLES:
            raise ValueError(f"table hors allowlist: {value!r}")
        return value


@router.post("/api/db-health/optimize/preview", response_model=None)
def preview_optimize(
    request: Request,
    body: OptimizePreviewRequest,
    client: Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)],
) -> JSONResponse | HTMLResponse:
    """Annonce ce que ferait un OPTIMIZE — n'exécute RIEN.

    Affiche le nombre de parts actives concernées et l'avertissement de coût
    (I/O disque, saturation temporaire possible si `final=True`) — exigence
    explicite de la tâche : mesurer/prévenir AVANT, jamais exécuter à l'aveugle.

    DÉFAUT MESURÉ (2026-08-09) : cette route est appelée par un formulaire
    HTMX (`db_health.html`, section « Forcer la fusion des parts ») qui
    insère la réponse telle quelle dans la page — avant ce correctif, le
    JSON brut s'affichait en clair à l'écran. Même double format que
    `preview_detached_purge_all` ci-dessous et `app.routers.retention.preview_purge`
    (voir leurs docstrings) : un appel HTMX (header `HX-Request`) reçoit un
    fragment HTML lisible, un appel API direct reçoit le JSON inchangé — le
    mode API n'est jamais cassé.
    """
    try:
        from app.services.db_health import collect_parts_health

        parts = collect_parts_health(client)
    except Exception as exc:
        log.error("db_health: echec lecture parts pour preview optimize", exc_info=True)
        return _error_response(502, f"Erreur ClickHouse lors de la lecture des parts: {exc}")

    current = next((p for p in parts if p.table == body.table), None)
    active_parts = current.total_active_parts if current else 0
    sql_preview = f"OPTIMIZE TABLE default.{body.table}" + (" FINAL" if body.final else "")

    warning = (
        "OPTIMIZE ... FINAL fusionne TOUTES les parts actives en une seule : "
        "coûteux en I/O disque, peut saturer temporairement l'espace disque "
        "(ClickHouse écrit la part fusionnée avant de libérer les anciennes). "
        "Réservé aux cas où la fusion normale ne suit manifestement plus."
        if body.final
        else "OPTIMIZE (sans FINAL) fusionne les parts éligibles selon la "
        "politique normale de ClickHouse — geste modéré, recommandé en premier."
    )

    payload = {
        "status": "ok",
        "table": body.table,
        "final": body.final,
        "active_parts": active_parts,
        "sql_statement": sql_preview,
        "warning": warning,
        "executed": False,
    }

    if request.headers.get("HX-Request") == "true":
        return templates.TemplateResponse(
            request, "_optimize_preview_fragment.html", {"preview": payload}
        )

    return JSONResponse(content=payload)


class OptimizeExecuteRequest(BaseModel):
    table: str
    final: bool = False

    @field_validator("table")
    @classmethod
    def table_must_be_monitored(cls, value: str) -> str:
        if value not in MONITORED_TABLES:
            raise ValueError(f"table hors allowlist: {value!r}")
        return value


@router.post("/api/db-health/optimize/execute", response_model=None)
def execute_optimize(
    request: Request,
    body: OptimizeExecuteRequest,
    client: Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)],
    conn: DbConnection,
) -> JSONResponse | HTMLResponse:
    """Exécute réellement `OPTIMIZE TABLE` — geste coûteux mais RÉVERSIBLE au
    sens où aucune donnée de flux n'est perdue (fusion, pas suppression).

    Même double format HTMX/API que `preview_optimize` ci-dessus — défaut
    mesuré identique (2026-08-09) : le formulaire d'exécution insérait le
    JSON brut dans `#optimize-execute-result`.
    """
    try:
        sql_statement = optimize_table(client, body.table, final=body.final)
    except ValueError as exc:
        log.error("db_health: optimize refuse par la garde securite", extra={"table": body.table})
        return _error_response(400, str(exc))
    except Exception as exc:
        log.error(
            "db_health: echec execution OPTIMIZE",
            exc_info=True,
            extra={"table": body.table, "final": body.final},
        )
        return _error_response(502, f"Erreur ClickHouse lors de l'OPTIMIZE: {exc}")

    _record_audit(
        conn, "db_health_optimize", f"table={body.table} final={body.final} sql={sql_statement}"
    )

    payload = {
        "status": "ok",
        "table": body.table,
        "final": body.final,
        "sql_statement": sql_statement,
    }

    if request.headers.get("HX-Request") == "true":
        return templates.TemplateResponse(
            request, "_optimize_execute_fragment.html", {"result": payload}
        )

    return JSONResponse(content=payload)


# ---------------------------------------------------------------------------
# Purge des parts détachées — preview puis execute
# ---------------------------------------------------------------------------


@router.get("/api/db-health/detached-parts/preview", response_model=None)
def preview_detached_purge(
    request: Request,
    client: Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)],
) -> JSONResponse | HTMLResponse:
    """Annonce ce qui SERAIT purgé — n'en supprime aucune.

    Expose désormais `by_group` (base/table/raison/taille) — contexte
    métier demandé (2026-08-09) : une part `broken-on-start` à 0 octet se
    purge sans réfléchir, une part volumineuse mérite examen avant
    suppression. L'exploitant ne peut pas décider sur le seul compte.

    Même double format HTMX/API que `preview_optimize` — défaut mesuré
    identique (2026-08-09) : le bouton « Prévisualiser (flux uniquement) »
    insérait le JSON brut dans `#detached-preview-result`.
    """
    try:
        preview: DetachedPartsHealth = preview_detached_parts_purge(client)
    except Exception as exc:
        log.error("db_health: echec lecture parts detachees pour preview", exc_info=True)
        return _error_response(502, f"Erreur ClickHouse lors de la lecture: {exc}")

    payload = {
        "status": "ok",
        "count": preview.count,
        "total_bytes": preview.total_bytes,
        "state": preview.state.value,
        "by_group": [
            {
                "database": g.database,
                "table": g.table,
                "reason": g.reason,
                "count": g.count,
                "bytes_on_disk": g.bytes_on_disk,
            }
            for g in preview.by_group
        ],
    }

    if request.headers.get("HX-Request") == "true":
        return templates.TemplateResponse(
            request, "_detached_purge_preview_fragment.html", {"preview": payload}
        )

    return JSONResponse(content=payload)


class DetachedPurgeExecuteRequest(BaseModel):
    table: str

    @field_validator("table")
    @classmethod
    def table_must_be_monitored(cls, value: str) -> str:
        if value not in MONITORED_TABLES:
            raise ValueError(f"table hors allowlist: {value!r}")
        return value


@router.post("/api/db-health/detached-parts/execute", response_model=None)
def execute_detached_purge(
    request: Request,
    body: DetachedPurgeExecuteRequest,
    client: Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)],
    conn: DbConnection,
) -> JSONResponse | HTMLResponse:
    """Supprime réellement les parts détachées d'une table — elles n'occupaient
    que du disque sans servir aux requêtes (ni aux flux, ni aux agrégats).

    Même double format HTMX/API que `preview_detached_purge` — défaut mesuré
    identique (2026-08-09).
    """
    try:
        count_before = execute_detached_parts_purge(client, body.table)
    except ValueError as exc:
        log.error(
            "db_health: purge parts detachees refusee par la garde securite",
            extra={"table": body.table},
        )
        return _error_response(400, str(exc))
    except Exception as exc:
        log.error(
            "db_health: echec purge parts detachees", exc_info=True, extra={"table": body.table}
        )
        return _error_response(502, f"Erreur ClickHouse lors de la purge: {exc}")

    _record_audit(
        conn, "db_health_purge_detached_parts", f"table={body.table} parts_avant={count_before}"
    )

    payload = {"status": "ok", "table": body.table, "parts_avant": count_before}

    if request.headers.get("HX-Request") == "true":
        return templates.TemplateResponse(
            request, "_detached_purge_execute_fragment.html", {"result": payload}
        )

    return JSONResponse(content=payload)


# ---------------------------------------------------------------------------
# Purge COMPLÈTE des parts détachées — flux + tables système, preview/execute
# ---------------------------------------------------------------------------
#
# DÉFAUT MESURÉ (2026-08-09) : les deux routes ci-dessus ne couvrent que
# `MONITORED_TABLES` (tables de flux `default.*`) — après un crash réel,
# l'écran annonçait 46 parts détachées critiques mais ne pouvait en réparer
# que 18, les 28 autres étant sur des tables système (`query_log`,
# `part_log`, ...). Les deux routes ci-dessous ferment cet écart : elles
# nettoient TOUT ce que l'écran annonce, en respectant le même contrat
# preview → execute (aperçu immuable, aucun nouveau scan à l'exécution).


@router.get("/api/db-health/detached-parts/preview-all", response_model=None)
def preview_detached_purge_all(
    request: Request,
    client: Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)],
) -> JSONResponse | HTMLResponse:
    """Annonce la purge COMPLÈTE (tables de flux + tables système) — n'en
    supprime aucune.

    Même double format de réponse que `app.routers.retention.preview_purge`
    (voir sa docstring pour le rationnel complet) : un appel HTMX reçoit un
    FRAGMENT HTML embarquant le preview sérialisé dans un champ caché — c'est
    la SEULE façon pour `/execute-all` de recevoir "exactement ce que
    l'exploitant a vu" sans JavaScript custom (CSP `script-src 'self'` sans
    `unsafe-eval` interdit `hx-vals="js:..."`). Un appel API direct reçoit le
    JSON brut.
    """
    try:
        preview: DetachedPartsPurgeAllPreview = preview_detached_parts_purge_all(client)
    except Exception as exc:
        log.error("db_health: echec lecture parts detachees pour preview complet", exc_info=True)
        return _error_response(502, f"Erreur ClickHouse lors de la lecture: {exc}")

    preview_dump = preview.model_dump(mode="json")

    if request.headers.get("HX-Request") == "true":
        return templates.TemplateResponse(
            request,
            "_detached_parts_purge_all_fragment.html",
            {"preview": preview_dump, "preview_json": json.dumps(preview_dump)},
        )

    payload = {"status": "ok", "preview": preview_dump}
    return JSONResponse(content=payload)


class DetachedPurgeAllExecuteRequest(BaseModel):
    """Reçoit le PREVIEW COMPLET calculé par `/preview-all`, jamais des
    paramètres bruts reconstruits côté client — même choix anti-TOCTOU que
    `app.routers.retention.PurgeExecuteRequest` (voir sa docstring) : ce que
    l'exploitant a vu et confirmé à l'écran est exactement ce qui est purgé,
    jamais un nouveau scan de `system.detached_parts` au moment du clic."""

    preview: dict[str, Any]

    @field_validator("preview", mode="before")
    @classmethod
    def preview_may_be_json_string(cls, value: Any) -> Any:
        """Accepte `preview` en chaîne JSON (formulaire HTML avec
        `hx-ext="json-enc"`, champ caché) ou en objet (appel API direct) —
        même geste que `PurgeExecuteRequest.preview_may_be_json_string`."""
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError(f"preview n'est pas un JSON valide: {exc}") from exc
        return value


@router.post("/api/db-health/detached-parts/execute-all", response_model=None)
def execute_detached_purge_all(
    request: Request,
    body: DetachedPurgeAllExecuteRequest,
    client: Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)],
    conn: DbConnection,
) -> JSONResponse | HTMLResponse:
    """Purge réellement TOUTES les tables listées dans `body.preview` — la
    liste figée par `/preview-all`, jamais un nouveau scan.

    Chaque cible est REVALIDÉE contre les deux allowlists avant exécution
    (`execute_detached_parts_purge_all` → `validate_detached_parts_target`) :
    défense en profondeur, ce routeur ne fait jamais confiance à un `preview`
    reçu en paramètre sans le recontrôler, même s'il vient de son propre
    endpoint `/preview-all`.

    ZÉRO SILENCIEUX : un échec partiel (une table en erreur, les autres OK)
    produit un état DISTINCT (`is_complete=False`, `failures` non vide),
    jamais un succès global trompeur — `status` reste `"ok"` (la requête
    HTTP a réussi) mais l'exploitant doit lire `is_complete`/`failures`.

    Même double format HTMX/API que `preview_detached_purge_all` — défaut
    mesuré (2026-08-09) : le preview avait déjà son fragment
    (`_detached_parts_purge_all_fragment.html`) mais le bouton « Purger tout »
    qu'il contient (`hx-target="this"`) recevait encore le JSON brut de
    `/execute-all` en réponse.
    """
    try:
        preview = DetachedPartsPurgeAllPreview.model_validate(body.preview)
    except Exception as exc:
        log.error("db_health: preview de purge complete invalide", exc_info=True)
        return _error_response(400, f"preview invalide: {exc}")

    if not preview.targets:
        return _error_response(400, "aucune cible dans le preview — rien a purger")

    try:
        result = execute_detached_parts_purge_all(client, preview)
    except Exception as exc:
        log.error("db_health: echec purge complete parts detachees", exc_info=True)
        return _error_response(502, f"Erreur ClickHouse lors de la purge: {exc}")

    _record_audit(
        conn,
        "db_health_purge_detached_parts_all",
        f"reussies={result.purged_tables} echecs={result.failures}",
    )

    payload = {
        "status": "ok",
        "purged_tables": result.purged_tables,
        "failures": result.failures,
        "is_complete": result.is_complete,
        "parts_before": result.parts_before,
    }

    if request.headers.get("HX-Request") == "true":
        return templates.TemplateResponse(
            request, "_detached_purge_execute_all_fragment.html", {"result": payload}
        )

    return JSONResponse(content=payload)
