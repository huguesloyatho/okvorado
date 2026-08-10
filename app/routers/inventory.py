"""Router Inventaire équipement — écran « Device Summary » (MIB-II système).

`GET /inventory` liste tous les équipements déjà inventoriés (une ligne par
exportateur), `GET /inventory/{adresse}` détaille un équipement (deux
colonnes libellé/valeur, reproduisant la capture ManageEngine de référence),
`POST /inventory/collect` déclenche une collecte manuelle immédiate sur TOUS
les exportateurs connus (bouton « Collecter »).

L'adresse à interroger vient TOUJOURS de `load_exporter_statuses` (les
exportateurs observés/déclarés par Akvorado) — jamais d'une saisie libre,
cf. `app.services.snmp_inventory` (règle sécurité de la tâche).

COEXISTENCE SNMPv2c / SNMPv3 (migration progressive du parc, 350 routeurs
SFR) : `POST /inventory/{adresse}/snmp-version` permet de choisir, PAR
ÉQUIPEMENT, la version SNMP à utiliser pour les collectes suivantes — le
choix est appliqué IMMÉDIATEMENT (une collecte est relancée dans la foulée
avec la version choisie), pas seulement mémorisé pour plus tard. Les
collectes "en masse" (`POST /inventory/collect`, tâche de fond périodique)
utilisent `settings.snmp_version_default` comme défaut, avec la version
déjà persistée par device (`snmp_inventory.snmp_version`) comme override —
cf. `_collect_all_respecting_versions_deja_choisies` ci-dessous.

SÉCURITÉ : les mots de passe SNMPv3 (`settings.snmp_v3_auth_password`,
`settings.snmp_v3_priv_password`) ne transitent JAMAIS dans un template, une
réponse HTTP, ou un log de ce routeur — seul `SnmpV3Credentials` (construit
ici depuis `settings`, jamais depuis une saisie utilisateur) les porte, et il
ne sort jamais de la frontière `app.services.snmp_inventory`.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from html import escape
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.config import settings
from app.services import snmp_inventory
from app.templating import build_templates

log = logging.getLogger(__name__)

router = APIRouter(tags=["inventory"])

# Versions SNMP acceptées depuis l'écran — allowlist FERMÉE, jamais une
# valeur de saisie libre propagée telle quelle vers `collect_one`.
_VALID_SNMP_VERSIONS: frozenset[str] = frozenset({"v2c", "v3"})


class SetSnmpVersionRequest(BaseModel):
    """Corps JSON de `POST /inventory/{address}/snmp-version` (htmx
    `json-enc`). `snmp_version` est validée contre `_VALID_SNMP_VERSIONS`
    dans le routeur — jamais propagée telle quelle à `collect_one` sans ce
    contrôle."""

    snmp_version: str


# ---------------------------------------------------------------------------
# Dépendances — surchargées dans app/main.py, même convention que les
# autres routers (diagnostics.py, views.py) : un placeholder qui échoue
# bruyamment tant qu'il n'est pas câblé.
# ---------------------------------------------------------------------------


def get_db_connection() -> sqlite3.Connection:
    """Placeholder — app/main.py doit surcharger cette dépendance."""
    raise RuntimeError(
        "get_db_connection non câblée : app/main.py doit surcharger cette "
        "dépendance avec la connexion SQLite réelle."
    )


def get_templates() -> Jinja2Templates:
    return build_templates()


DbConnection = Annotated[sqlite3.Connection, Depends(get_db_connection)]
Templates = Annotated[Jinja2Templates, Depends(get_templates)]


# ---------------------------------------------------------------------------
# Liste des adresses connues — déléguée au module Exportateurs (LOT 1),
# jamais reconstruite ici depuis une saisie utilisateur.
# ---------------------------------------------------------------------------


async def _known_exporter_addresses() -> list[str]:
    """Adresses des exportateurs CONNUS (observés/déclarés), pour la collecte
    globale. Import différé : évite un couplage au chargement du module si
    `app.routers.exporters` n'est pas encore monté (même robustesse que les
    autres montages indépendants de `app/main.py::_register_routers`)."""
    from app.config import DEFAULT_WINDOW
    from app.routers.exporters import load_exporter_statuses

    try:
        statuses = await load_exporter_statuses(DEFAULT_WINDOW)
    except Exception as exc:  # noqa: BLE001 - dégradation : collecte vide, jamais un 500
        log.error("impossible de lister les exportateurs connus pour la collecte snmp: %s", exc)
        return []
    return [status.address for status in statuses]


# ---------------------------------------------------------------------------
# SNMPv3 — credentials globaux construits depuis `settings`, jamais depuis
# une saisie utilisateur (cf. docstring de module).
# ---------------------------------------------------------------------------


def _v3_credentials_from_settings() -> snmp_inventory.SnmpV3Credentials | None:
    """Construit les credentials v3 globaux depuis `settings.snmp_v3_*`.

    `None` si `snmp_v3_username` est vide : v3 non configuré côté Okvorado
    (fail-safe, même convention que `snmp_community` vide). Ce `None` ne
    signifie JAMAIS un échec d'authentification (l'agent n'est pas encore
    contacté) — `collect_one` le traite comme `no_response`, pas
    `auth_failure` (cf. `app.services.snmp_inventory.collect_one`)."""
    if not settings.snmp_v3_username:
        return None
    return snmp_inventory.SnmpV3Credentials(
        username=settings.snmp_v3_username,
        security_level=settings.snmp_v3_security_level,
        auth_protocol=settings.snmp_v3_auth_protocol or None,
        auth_password=settings.snmp_v3_auth_password or None,
        priv_protocol=settings.snmp_v3_priv_protocol or None,
        priv_password=settings.snmp_v3_priv_password or None,
    )


def _snmp_configured() -> bool:
    """Vrai si AU MOINS une version SNMP (v2c ou v3) est utilisable — l'écran
    n'affiche l'avertissement « SNMP non configuré » que si NI l'une NI
    l'autre n'est disponible (le parc coexiste progressivement, cf. tête de
    fichier)."""
    return bool(settings.snmp_community) or bool(settings.snmp_v3_username)


def _collect_one_with_effective_version(
    conn: sqlite3.Connection, *, address: str, snmp_version: str
) -> snmp_inventory.InventoryItem:
    """Sonde `address` avec la version demandée, en résolvant les credentials
    depuis `settings` — jamais depuis une saisie utilisateur. Lève
    `ValueError` si la version demandée n'est pas configurée (appelant
    responsable de vérifier avant, cf. `post_set_snmp_version`)."""
    if snmp_version == "v3":
        return snmp_inventory.collect_one(
            conn,
            address=address,
            snmp_version="v3",
            v3_credentials=_v3_credentials_from_settings(),
        )
    return snmp_inventory.collect_one(
        conn, address=address, snmp_version="v2c", community=settings.snmp_community
    )


@router.get("/inventory", response_class=HTMLResponse)
async def get_inventory_page(
    request: Request,
    conn: DbConnection,
    templates: Templates,
) -> HTMLResponse:
    """Page Inventaire : une ligne par équipement déjà collecté.

    N'échoue jamais bruyamment : une base vide (aucune collecte encore
    lancée) affiche un message explicite, pas une erreur.
    """
    error: str | None = None
    items: list[snmp_inventory.InventoryItem] = []
    try:
        items = snmp_inventory.list_inventory(conn)
    except Exception as exc:
        log.error("echec chargement inventaire snmp: %s", exc, exc_info=True)
        error = f"Impossible de charger l'inventaire pour le moment : {exc}"

    return templates.TemplateResponse(
        request,
        "inventory.html",
        {
            "active_page": "inventory",
            "items": items,
            "total": len(items),
            "error": error,
            "snmp_configured": _snmp_configured(),
        },
    )


@router.get("/inventory/{address}", response_class=HTMLResponse)
async def get_inventory_detail_page(
    request: Request,
    address: str,
    conn: DbConnection,
    templates: Templates,
) -> HTMLResponse:
    """Détail « Device Summary » d'UN équipement — structure deux colonnes,
    calquée sur la capture ManageEngine de référence."""
    item = snmp_inventory.get_inventory_item(conn, address)
    if item is None:
        message = f"Aucun inventaire pour {address!r} : lance une collecte depuis /inventory."
        log.error("inventaire snmp introuvable: address=%s", address)
        return HTMLResponse(
            f'<p class="notice notice-error">{escape(message)}</p>', status_code=404
        )

    return templates.TemplateResponse(
        request,
        "inventory_detail.html",
        {"active_page": "inventory", "item": item},
    )


def _current_snmp_version(conn: sqlite3.Connection, address: str) -> str:
    """Version SNMP à utiliser pour RECOLLECTER `address` : celle déjà
    persistée pour ce device (choix fait via `/snmp-version`) si connue,
    sinon `settings.snmp_version_default` (défaut global, cf. tête de
    fichier)."""
    existing = snmp_inventory.get_inventory_item(conn, address)
    if existing is not None:
        return existing.snmp_version
    return settings.snmp_version_default


@router.post("/inventory/{address}/collect", response_class=HTMLResponse)
async def post_collect_inventory_one(
    request: Request,
    address: str,
    conn: DbConnection,
    templates: Templates,
) -> HTMLResponse:
    """Bouton « Recollecter » de l'écran détail : ne sonde QUE cette adresse,
    avec la version SNMP déjà choisie pour cet équipement (v2c par défaut,
    ou la dernière version sélectionnée via `/snmp-version`)."""
    snmp_version = _current_snmp_version(conn, address)
    if not _snmp_configured():
        log.error("collecte snmp demandee sans aucune version configuree: address=%s", address)
        return HTMLResponse(
            '<p class="notice notice-error">SNMP non configuré '
            "(ni communauté v2c, ni utilisateur v3) : la collecte est désactivée.</p>",
            status_code=422,
        )

    # `collect_one` est SYNCHRONE et bloquant (elle appelle `asyncio.run()` en
    # interne pour piloter pysnmp — cf. `_snmp_get_scalars`) : l'exécuter
    # directement depuis cette route `async def` échoue avec "asyncio.run()
    # cannot be called from a running event loop" (mesuré en prod, .7,
    # 2026-08-08 : la collecte retombait en 'no_response' pour TOUT agent,
    # y compris un agent qui répond réellement — un zéro silencieux du point
    # de vue de l'écran, qui affichait "pas de réponse SNMP" pour un agent
    # up). `asyncio.to_thread` exécute l'appel bloquant dans un thread à part,
    # laissant la boucle événements d'uvicorn libre.
    await asyncio.to_thread(
        _collect_one_with_effective_version, conn, address=address, snmp_version=snmp_version
    )
    item = snmp_inventory.get_inventory_item(conn, address)
    if item is None:
        # `collect_one` upserte TOUJOURS une ligne (succès ou 'no_response') :
        # ce cas ne devrait jamais survenir. S'il survient quand même, 422
        # (et non 500) reste SWAPPABLE par htmx-config.js — cf.
        # tests/test_htmx_error_visibility.py, un message HTMX en 500 ne
        # s'affiche jamais.
        log.error("inventaire snmp introuvable juste apres collecte: address=%s", address)
        return HTMLResponse(
            '<p class="notice notice-error">Collecte lancée mais résultat introuvable.</p>',
            status_code=422,
        )

    return templates.TemplateResponse(
        request,
        "inventory_detail.html",
        {"active_page": "inventory", "item": item},
    )


@router.post("/inventory/{address}/snmp-version", response_class=HTMLResponse)
async def post_set_snmp_version(
    request: Request,
    address: str,
    conn: DbConnection,
    templates: Templates,
    body: SetSnmpVersionRequest,
) -> HTMLResponse:
    """Change la version SNMP utilisée pour CET équipement et relance
    IMMÉDIATEMENT une collecte avec la nouvelle version — le choix se voit
    tout de suite (`status='ok'`/`'auth_failure'`/`'no_response'` reflète la
    nouvelle version dès cette réponse), jamais un réglage silencieux qui ne
    prendrait effet qu'à la prochaine collecte de fond.

    Allowlist FERMÉE (`_VALID_SNMP_VERSIONS`) : une valeur hors `v2c`/`v3`
    est refusée en 422, jamais propagée telle quelle à `collect_one`."""
    if body.snmp_version not in _VALID_SNMP_VERSIONS:
        log.error(
            "version snmp invalide demandee: address=%s snmp_version=%r",
            address,
            body.snmp_version,
        )
        return HTMLResponse(
            f'<p class="notice notice-error">Version SNMP invalide : '
            f"{escape(body.snmp_version)!r} (attendu v2c ou v3).</p>",
            status_code=422,
        )

    if body.snmp_version == "v3" and _v3_credentials_from_settings() is None:
        log.error("bascule v3 demandee sans credentials v3 configures: address=%s", address)
        return HTMLResponse(
            '<p class="notice notice-error">SNMPv3 non configuré '
            "(OKVORADO_SNMP_V3_USERNAME vide) : impossible de basculer cet "
            "équipement en v3 tant que les identifiants globaux ne sont pas "
            "renseignés.</p>",
            status_code=422,
        )
    if body.snmp_version == "v2c" and not settings.snmp_community:
        log.error("bascule v2c demandee sans communaute configuree: address=%s", address)
        return HTMLResponse(
            '<p class="notice notice-error">SNMPv2c non configuré '
            "(OKVORADO_SNMP_COMMUNITY vide) : impossible de basculer cet "
            "équipement en v2c tant que la communauté n'est pas renseignée.</p>",
            status_code=422,
        )

    # Même garde de thread que `post_collect_inventory_one` : `collect_one`
    # est synchrone/bloquant (pysnmp piloté via `asyncio.run()` interne).
    await asyncio.to_thread(
        _collect_one_with_effective_version,
        conn,
        address=address,
        snmp_version=body.snmp_version,
    )
    item = snmp_inventory.get_inventory_item(conn, address)
    if item is None:
        log.error("inventaire snmp introuvable juste apres bascule de version: address=%s", address)
        return HTMLResponse(
            '<p class="notice notice-error">Bascule de version lancée mais résultat '
            "introuvable.</p>",
            status_code=422,
        )

    return templates.TemplateResponse(
        request,
        "inventory_detail.html",
        {"active_page": "inventory", "item": item},
    )


def _collect_all_respecting_versions_deja_choisies(
    conn: sqlite3.Connection, *, addresses: list[str]
) -> list[snmp_inventory.InventoryItem]:
    """Collecte globale qui respecte la version SNMP DÉJÀ CHOISIE par device
    (persistée via `/snmp-version`) — un équipement migré en v3 ne doit
    jamais être recollecté silencieusement en v2c par le bouton global.

    `snmp_version_default`/`community` restent le triplet par défaut pour
    toute adresse SANS historique de collecte (jamais vue) ; `overrides`
    porte la version déjà connue de chaque device déjà inventorié, avec ses
    credentials v3 globaux si cette version est `'v3'` (cf. `collect_all`,
    design « défaut + table d'exceptions clairsemée »)."""
    overrides: dict[str, tuple[str, snmp_inventory.SnmpV3Credentials | None]] = {}
    for address in addresses:
        existing = snmp_inventory.get_inventory_item(conn, address)
        if existing is None:
            continue
        if existing.snmp_version == "v3":
            overrides[address] = ("v3", _v3_credentials_from_settings())
        else:
            overrides[address] = ("v2c", None)

    return snmp_inventory.collect_all(
        conn,
        addresses=addresses,
        community=settings.snmp_community,
        snmp_version=settings.snmp_version_default,
        v3_credentials=_v3_credentials_from_settings()
        if settings.snmp_version_default == "v3"
        else None,
        overrides=overrides,
    )


@router.post("/inventory/collect", response_class=HTMLResponse)
async def post_collect_inventory(
    request: Request,
    conn: DbConnection,
    templates: Templates,
) -> HTMLResponse:
    """Bouton « Collecter » : lance une collecte immédiate sur tous les
    exportateurs connus, puis réaffiche la page (HTMX swap complet).

    Chaque équipement est recollecté avec la version SNMP déjà choisie pour
    lui (v2c par défaut, ou v3 s'il a été migré via `/snmp-version`) — cf.
    `_collect_all_respecting_versions_deja_choisies`."""
    error: str | None = None
    if not _snmp_configured():
        error = (
            "SNMP non configuré (ni communauté v2c, ni utilisateur v3) : "
            "la collecte est désactivée."
        )
        log.error("collecte snmp demandee sans aucune version configuree")
    else:
        addresses = await _known_exporter_addresses()
        try:
            # Même garde que `post_collect_inventory_one` ci-dessus : appel
            # bloquant déporté dans un thread, jamais exécuté directement
            # dans la boucle événements d'uvicorn.
            await asyncio.to_thread(
                _collect_all_respecting_versions_deja_choisies,
                conn,
                addresses=addresses,
            )
        except Exception as exc:
            log.error("echec collecte snmp globale: %s", exc, exc_info=True)
            error = f"La collecte a échoué : {exc}"

    items = snmp_inventory.list_inventory(conn)
    return templates.TemplateResponse(
        request,
        "inventory.html",
        {
            "active_page": "inventory",
            "items": items,
            "total": len(items),
            "error": error,
            "snmp_configured": _snmp_configured(),
        },
    )
