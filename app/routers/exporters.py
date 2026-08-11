"""Router FastAPI du module Exportateurs.

`GET /exporters` rend la page HTML (Jinja2, HTMX pour le rafraîchissement du
tableau) ; `GET /api/exporters` expose le JSON `{"items": [...], "total": N}`
utilisé par HTMX comme par toute intégration externe.

Le croisement complet (ClickHouse + outlet.yaml + métriques Prometheus outlet
du LOT 4) est effectué par `load_exporter_statuses()`. Cette fonction est un
point d'extension délibéré : elle est référencée par nom depuis les tests
(`monkeypatch.setattr(exporters_router, "load_exporter_statuses", ...)`) pour
substituer entièrement l'accès infra sans toucher au routing.

RÉSOLUTION AUTOMATIQUE DES ifIndex PAR SNMP (2026-08-10)
--------------------------------------------------------
`POST /exporters/{address}/resolve-snmp` et `POST /exporters/resolve-snmp-all`
remplacent le geste MANUEL « saisir le nouvel ifIndex puis cliquer », qui ne
passe pas l'échelle : la cible est un parc de 350 routeurs (cf. CLAUDE.md), et
`outlet.yaml` portait une liste `if-indexes` écrite à la main PAR MACHINE,
avec des valeurs (999, 2932, 1222, 235, 39...) ne correspondant à AUCUNE
interface réelle — d'où « Interface inconnue » sur 4 exportateurs sur 11. Le
mécanisme complet est documenté dans
`app.services.snmp_inventory.resolve_interface_table`.

Le geste manuel (`/config/exporters/{cidr}/fix-ifindex`) est CONSERVÉ comme
repli : un équipement sans agent SNMP reste corrigeable à la main.

SÉCURITÉ (CLAUDE.md) appliquée à ces deux routes :
  - l'adresse est validée comme IP ET vérifiée présente dans la liste des
    exportateurs CONNUS avant tout sondage — Okvorado ne doit pas devenir un
    scanner SNMP pilotable depuis une URL ;
  - les credentials viennent de `settings`, jamais d'une saisie, et ne
    transitent ni dans un gabarit, ni dans une réponse, ni dans un log ;
  - aucune écriture directe d'`outlet.yaml` : tout passe par la file
    d'attente (`stage_change`), donc par `apply_pending_changes` et son
    verrou optimiste + backup + écriture atomique.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.clients.akvorado_yaml import load_declared_exporters
from app.clients.clickhouse import connect, fetch_observed_exporters
from app.clients.prometheus import fetch_outlet_metrics
from app.config import DEFAULT_WINDOW, WINDOW_CHOICES, settings, window_to_interval
from app.models import ExporterHealth, ExporterStatus
from app.services import snmp_inventory
from app.services.config_writer import stage_change
from app.services.exporters import (
    InterfaceFiltrageResult,
    _declared_interface_names,
    build_exporter_statuses,
    build_if_indexes_from_snmp,
    filtrer_interfaces_exploitables,
    resolve_interface_table_ssh,
)
from app.templating import build_templates

log = logging.getLogger(__name__)

router = APIRouter(tags=["exporters"])

_templates = build_templates()

#: Auteur enregistré dans la file d'attente pour un changement issu de la
#: résolution SNMP. Distinct de l'auteur d'une saisie manuelle : l'historique
#: doit dire si un ifIndex vient de l'équipement ou d'un humain.
_SNMP_AUTHOR = "snmp-auto"


# ---------------------------------------------------------------------------
# Dépendances — surchargées dans app/main.py, même convention que les autres
# routers (inventory.py, config.py) : un placeholder qui échoue bruyamment
# tant qu'il n'est pas câblé, jamais une connexion implicite.
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


async def load_exporter_statuses(window: str) -> list[ExporterStatus]:
    """Assemble la vue croisée déclaré x observé x ingéré pour une fenêtre donnée.

    Trois sources sont croisées :
      - `outlet.yaml` : ce qui est DÉCLARÉ ;
      - ClickHouse : ce qui est OBSERVÉ (les flux réellement stockés) ;
      - métriques Prometheus de l'outlet : ce qui est INGÉRÉ ou REJETÉ.

    La troisième est indispensable : un flux rejeté n'atteint jamais ClickHouse,
    donc sans elle un exportateur à 100 % de rejet apparaît comme simplement
    « silencieux », ce qui masque la vraie cause. Si les métriques ne sont pas
    récupérables, on dégrade avec des compteurs vides plutôt que d'échouer —
    les quatre autres états restent corrects.
    """
    declared = load_declared_exporters(settings.akvorado_config_path)

    client = connect(settings)
    try:
        observed = fetch_observed_exporters(client, window_to_interval(window))
    finally:
        client.close()

    try:
        metrics = await fetch_outlet_metrics()
        forwarded = metrics.forwarded_by_exporter
        rejected = metrics.rejected_by_exporter
        reasons = metrics.rejection_reasons
    except Exception as exc:  # noqa: BLE001 - dégradation volontaire, cf. docstring
        log.error("metriques outlet non recuperees, etat REJECTED indisponible: %s", exc)
        forwarded, rejected, reasons = {}, {}, {}

    return build_exporter_statuses(
        declared=declared,
        observed=observed,
        forwarded_by_exporter=forwarded,
        rejected_by_exporter=rejected,
        rejection_reasons=reasons,
        now=datetime.now(UTC),
    )


def _validate_window_or_422(window: str) -> str:
    if window not in WINDOW_CHOICES:
        raise HTTPException(
            status_code=422,
            detail=f"fenetre invalide: {window!r} (attendu: {', '.join(WINDOW_CHOICES)})",
        )
    return window


@router.get("/api/exporters")
async def list_exporters(
    window: str = Query(default=DEFAULT_WINDOW),
) -> JSONResponse:
    """Retourne les exportateurs au format `{"items": [...], "total": N}`."""
    validated_window = _validate_window_or_422(window)

    try:
        statuses = await load_exporter_statuses(validated_window)
    except Exception:
        log.error(
            "echec chargement exportateurs pour l'API: window=%s",
            validated_window,
            exc_info=True,
        )
        return JSONResponse(
            status_code=502,
            content={"error": "impossible de charger les exportateurs (backend indisponible)"},
        )

    return JSONResponse(
        content={
            "items": [status.model_dump(mode="json") for status in statuses],
            "total": len(statuses),
        }
    )


@router.get("/exporters")
async def get_exporters(
    request: Request,
    window: str = Query(default=DEFAULT_WINDOW),
) -> HTMLResponse:
    """Rend la page Exportateurs.

    Si le backend (ClickHouse/YAML) est indisponible, la page s'affiche quand
    même avec un message d'erreur clair — jamais une stacktrace ni un 500 nu.
    """
    validated_window = _validate_window_or_422(window)

    error: str | None = None
    statuses: list[ExporterStatus] = []
    try:
        statuses = await load_exporter_statuses(validated_window)
    except Exception as exc:
        log.error(
            "echec chargement exportateurs pour la page HTML: window=%s",
            validated_window,
            exc_info=True,
        )
        error = f"Impossible de charger les exportateurs pour le moment : {exc}"

    templates = getattr(request.app.state, "templates", _templates)
    return templates.TemplateResponse(
        request,
        "exporters.html",
        {
            "items": statuses,
            "total": len(statuses),
            "window": validated_window,
            "window_choices": WINDOW_CHOICES,
            "error": error,
            "active_page": "exporters",
            "snmp_configured": _snmp_configured(),
            "ssh_fallback_enabled": settings.ssh_ifindex_fallback_enabled,
        },
    )


# ---------------------------------------------------------------------------
# Résolution automatique des ifIndex par SNMP — cf. docstring de module
# ---------------------------------------------------------------------------


@dataclass
class _ResolveRow:
    """Le sort d'UN exportateur dans la résolution globale.

    Une ligne par exportateur traité, avec son état PROPRE : c'est ce qui
    interdit le compteur global seul (« 340/350 résolus » masquerait QUI a
    échoué et POURQUOI, donc les 10 restants ne seraient jamais traités —
    zéro silencieux, CLAUDE.md).
    """

    address: str
    name: str
    status: str
    message: str
    interface_count: int = 0
    staged: bool = False
    source: str = "snmp"
    """`'snmp'` ou `'ssh'` — QUELLE source a résolu la table. Distinction
    OBLIGATOIRE à l'écran (cf. CLAUDE.md, mission SSH 2026-08-11) : un succès
    SSH qui se lirait comme un succès SNMP masquerait que l'agent SNMP est
    absent de l'hôte, information dont l'exploitant a besoin pour savoir si
    la voie PRINCIPALE (transposable en entreprise) fonctionne réellement."""

    total_vues: int = 0
    total_ecartees: int = 0
    """Décompte du filtrage `filtrer_interfaces_exploitables` — OBLIGATOIRE à
    l'écran (jonction ajoutée 2026-08-11) : sans lui, un exportateur qui
    déclare des dizaines d'interfaces de bruit de virtualisation verrait son
    filtrage disparaître silencieusement derrière un simple compteur
    d'interfaces retenues."""


def _snmp_configured() -> bool:
    """Vrai si AU MOINS une version SNMP est utilisable (v2c ou v3).

    Même règle que `app.routers.inventory._snmp_configured` : le parc migre
    progressivement, une seule des deux versions suffit à résoudre."""
    return bool(settings.snmp_community) or bool(settings.snmp_v3_username)


def _v3_credentials_from_settings() -> snmp_inventory.SnmpV3Credentials | None:
    """Credentials v3 globaux depuis `settings` — JAMAIS depuis une saisie.

    Duplique volontairement `app.routers.inventory._v3_credentials_from_settings`
    plutôt que de l'importer : importer un routeur depuis un autre routeur
    créerait un couplage de montage (les routers d'Okvorado se montent
    indépendamment dans `app.main._register_routers`) pour six lignes sans
    logique métier."""
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


def _resolve_snmp_blocking(address: str) -> snmp_inventory.InterfaceTableResult:
    """Sonde UN équipement par SNMP, en choisissant la version disponible.

    Préfère v2c si une communauté est configurée (c'est encore la majorité du
    parc), sinon v3. Bloquant : `resolve_interface_table` appelle
    `asyncio.run()` en interne via `_snmp_walk_interfaces` — l'exécuter
    directement depuis une route `async def` échouerait avec « asyncio.run()
    cannot be called from a running event loop » (défaut MESURÉ en prod le
    2026-08-08 sur la collecte d'inventaire : TOUT agent, y compris ceux qui
    répondaient, retombait en `no_response`, un zéro silencieux parfait).
    D'où l'appel systématique via `asyncio.to_thread` côté route.
    """
    if settings.snmp_community:
        return snmp_inventory.resolve_interface_table(
            address=address, snmp_version="v2c", community=settings.snmp_community
        )
    return snmp_inventory.resolve_interface_table(
        address=address, snmp_version="v3", v3_credentials=_v3_credentials_from_settings()
    )


def _resolve_one_blocking(address: str) -> tuple[snmp_inventory.InterfaceTableResult, str]:
    """Sonde UN équipement, SNMP en voie PRINCIPALE, SSH en COMPLÉMENT de secours.

    BLOCAGE MESURÉ (2026-08-11) : `snmpd` n'est pas déployé sur une partie du
    parc homelab où l'ifIndex de `tailscale0` a dérivé — SNMP y rend
    systématiquement `no_response`. Le bouton « Résoudre par SNMP » reste la
    voie PRINCIPALE (inchangée, nécessaire pour la cible entreprise : Palo
    Alto, routeurs SFR répondent en SNMP). SSH ne prend le relais QUE si :
      1. SNMP a répondu `no_response` (pas `auth_failure` : un agent qui
         REFUSE l'authentification a répondu, ce n'est pas le cas visé — le
         corriger, c'est corriger les credentials SNMP, pas basculer de
         protocole) ;
      2. `settings.ssh_ifindex_fallback_enabled` est activé (défaut `False` :
         ne dégrade JAMAIS la cible entreprise où SNMP répond nativement).

    Retourne `(résultat, source)` — `source` vaut `'snmp'` ou `'ssh'`, pour
    que l'écran DISE laquelle des deux voies a résolu (zéro silencieux : un
    succès SSH qui se lirait comme un succès SNMP masquerait l'absence
    d'agent SNMP sur l'hôte).
    """
    snmp_result = _resolve_snmp_blocking(address)
    if snmp_result.status != "no_response" or not settings.ssh_ifindex_fallback_enabled:
        return snmp_result, "snmp"

    log.info(
        "resolution snmp muette, repli ssh active: address=%s",
        address,
    )
    ssh_result = resolve_interface_table_ssh(
        address=address,
        ssh_user=settings.ssh_ifindex_user,
        timeout_seconds=settings.ssh_ifindex_timeout_seconds,
    )
    if ssh_result.is_usable:
        return ssh_result, "ssh"
    # Le repli SSH a lui aussi échoué : on rend le résultat SSH (message
    # orienté action propre à SSH) plutôt que de revenir au message SNMP —
    # c'est la DERNIÈRE tentative faite, l'exploitant doit voir son échec à
    # elle, pas celui de la voie déjà connue comme muette.
    return ssh_result, "ssh"


@dataclass
class _StageResult:
    """Sort de `_stage_resolved_if_indexes` — ZÉRO SILENCIEUX.

    `staged` seul ne suffit pas : un appelant a aussi besoin de savoir COMBIEN
    d'interfaces le filtre a écartées (`filtrage`), sinon un filtrage actif
    devient lui-même un zéro silencieux (l'exploitant voit « 3 résolues » sans
    savoir que N ont été retirées, cf. le cas d'un exportateur Docker mesuré
    qui déclare des dizaines d'interfaces `veth*`/`br-*` bruyantes)."""

    staged: bool
    filtrage: InterfaceFiltrageResult | None = None


def _stage_resolved_if_indexes(
    conn: sqlite3.Connection,
    status: ExporterStatus,
    table: dict[int, str],
) -> _StageResult:
    """Filtre puis met en file d'attente le remplacement des `if-indexes`.

    JONCTION AJOUTÉE (2026-08-11, signalée par le coordinateur) : la table
    brute (SNMP ou repli SSH — indifféremment, cette fonction est le POINT DE
    JONCTION UNIQUE des deux chemins) est d'abord passée par
    `filtrer_interfaces_exploitables` pour écarter les interfaces sans valeur
    NetFlow (`lo`, `docker0`, `br-*`, `veth*` par défaut,
    `OKVORADO_INTERFACE_EXCLUDE_PATTERNS`). Sans ce filtre, un exportateur
    Docker peut déclarer des dizaines d'interfaces qui sont du pur bruit de
    virtualisation (cas mesuré sur le parc homelab). `declared_names` protège
    toute interface DÉJÀ déclarée par l'exploitant : le filtre ne défait
    jamais une décision humaine.

    Réutilise ensuite le MÉCANISME D'ÉCRITURE EXISTANT (`stage_change` ->
    `apply_pending_changes`), qui porte déjà le verrou optimiste, le backup
    horodaté, l'écriture atomique et le rollback. Écrire `outlet.yaml`
    directement depuis ici dupliquerait ces garanties — et un YAML tronqué
    empêche Akvorado de redémarrer.

    Ne met RIEN en file d'attente si l'exportateur n'a pas de déclaration
    nominative, si le filtre écarte TOUTES les interfaces vues
    (`filtrage.tout_ecarte` — signal d'alarme, pas un résultat à appliquer
    silencieusement), ou si la traduction finale ne produit aucune interface
    exploitable.
    """
    if status.declared is None:
        log.error(
            "resolution snmp sans declaration nominative, aucun changement mis en attente: "
            "address=%s",
            status.address,
        )
        return _StageResult(staged=False)

    declared_names = _declared_interface_names(status.declared)
    filtrage = filtrer_interfaces_exploitables(table, declared_names=declared_names)

    if filtrage.tout_ecarte:
        log.error(
            "resolution snmp: filtre a ecarte TOUTES les interfaces vues, aucun changement "
            "mis en attente: address=%s total_vues=%d motifs_probablement_inadaptes=true",
            status.address,
            filtrage.total_vues,
        )
        return _StageResult(staged=False, filtrage=filtrage)

    table_filtree = {if_index: spec.name for if_index, spec in filtrage.retenues.items()}

    resolved = build_if_indexes_from_snmp(table_filtree, existing=status.declared.if_indexes)
    if not resolved:
        log.error(
            "resolution snmp sans aucune interface exploitable, aucun changement mis en attente: "
            "address=%s",
            status.address,
        )
        return _StageResult(staged=False, filtrage=filtrage)

    stage_change(
        conn,
        "update_exporter",
        {
            "cidr": status.declared.cidr,
            "name": status.declared.name,
            "if_indexes": {
                str(if_index): {
                    "name": spec.name,
                    "description": spec.description,
                    "speed": spec.speed,
                    "boundary": spec.boundary.value,
                }
                for if_index, spec in resolved.items()
            },
            "default": (
                {
                    "name": status.declared.default.name,
                    "description": status.declared.default.description,
                    "speed": status.declared.default.speed,
                    "boundary": status.declared.default.boundary.value,
                }
                if status.declared.default is not None
                else None
            ),
            "is_catchall": status.declared.is_catchall,
        },
        _SNMP_AUTHOR,
    )
    log.info(
        "resolution snmp mise en attente: address=%s cidr=%s interfaces=%d "
        "ecartees_par_filtre=%d",
        status.address,
        status.declared.cidr,
        len(resolved),
        filtrage.total_ecartees,
    )
    return _StageResult(staged=True, filtrage=filtrage)


def _error_fragment(message: str, status_code: int = 422) -> HTMLResponse:
    """Message d'erreur en HTML, jamais en JSON brut ni en 500.

    422 et non 500 : htmx ne remplace PAS la cible sur une réponse 5xx — un
    message rendu en 500 serait INVISIBLE à l'écran (défaut mesuré, cf.
    tests/test_htmx_error_visibility.py). Le message doit être LU.
    """
    from html import escape  # noqa: PLC0415 - colocalisé avec son unique usage

    return HTMLResponse(
        f'<p class="notice notice-error">{escape(message)}</p>', status_code=status_code
    )


def _needs_resolution(status: ExporterStatus) -> bool:
    """Un exportateur est candidat à la résolution s'il est en anomalie
    d'interface ET porte une déclaration nominative à corriger.

    On ne réécrit JAMAIS la configuration d'un exportateur sain : le fait que
    sa table SNMP soit lisible ne justifie pas de toucher à une déclaration
    qui fonctionne."""
    return status.health == ExporterHealth.UNKNOWN_INTERFACE and status.declared is not None


@router.post("/exporters/{address}/resolve-snmp", response_class=HTMLResponse)
async def post_resolve_snmp_one(
    request: Request,
    address: str,
    conn: DbConnection,
    templates: Templates,
) -> HTMLResponse:
    """Bouton « Résoudre par SNMP » d'UNE ligne : interroge l'équipement,
    montre la table trouvée, met la correction en file d'attente.

    Refuse AVANT tout accès réseau : une adresse qui n'est pas une IP, ou une
    IP absente de la liste des exportateurs connus (cf. docstring de module,
    section sécurité).
    """
    try:
        ipaddress.ip_address(address)
    except ValueError:
        log.error("resolution snmp refusee, adresse invalide: address=%r", address)
        return _error_fragment(
            f"Adresse invalide : {address!r}. Aucune requête SNMP n'a été émise."
        )

    if not _snmp_configured():
        return _error_fragment(
            "SNMP n'est pas configuré dans Okvorado (ni communauté v2c, ni utilisateur v3) : "
            "aucun équipement n'a été interrogé. Renseigner OKVORADO_SNMP_COMMUNITY ou "
            "OKVORADO_SNMP_V3_USERNAME."
        )

    try:
        statuses = await load_exporter_statuses(DEFAULT_WINDOW)
    except Exception as exc:  # noqa: BLE001 - jamais un 500 nu, cf. `_error_fragment`
        log.error("resolution snmp: chargement des exportateurs echoue: %s", exc, exc_info=True)
        return _error_fragment(
            f"Impossible de vérifier la liste des exportateurs connus : {exc}. "
            "Aucune requête SNMP n'a été émise."
        )

    status = next((item for item in statuses if item.address == address), None)
    if status is None:
        log.error("resolution snmp refusee, exportateur inconnu: address=%s", address)
        return _error_fragment(
            f"{address} ne fait pas partie des exportateurs connus : aucune requête SNMP "
            "n'a été émise. Okvorado n'interroge que les exportateurs observés ou déclarés."
        )

    result, source = await asyncio.to_thread(_resolve_one_blocking, address)

    if not result.is_usable:
        # ZÉRO SILENCIEUX : l'échec est DIT, avec son motif propre et une
        # consigne d'action — jamais une table vide à l'écran.
        return _error_fragment(result.message)

    stage_result = _stage_resolved_if_indexes(conn, status, result.interfaces)

    if stage_result.filtrage is not None and stage_result.filtrage.tout_ecarte:
        # SIGNAL D'ALARME, pas un résultat : le filtre a écarté TOUTES les
        # interfaces vues, probablement des motifs inadaptés à cet équipement
        # (OKVORADO_INTERFACE_EXCLUDE_PATTERNS) plutôt qu'un vrai succès vide.
        return _error_fragment(
            f"L'équipement a répondu ({stage_result.filtrage.total_vues} interface(s) lue(s)) "
            "mais le filtre d'exclusion les a TOUTES écartées : aucun changement n'a été mis "
            "en attente. Vérifier OKVORADO_INTERFACE_EXCLUDE_PATTERNS — les motifs sont "
            "probablement inadaptés à cet équipement."
        )

    return templates.TemplateResponse(
        request,
        "_snmp_resolve_one_fragment.html",
        {
            "address": address,
            "exporter_name": status.name,
            "result": result,
            "staged": stage_result.staged,
            "source": source,
            "filtrage": stage_result.filtrage,
        },
    )


@router.get("/exporters/resolve-snmp-clear", response_class=HTMLResponse)
async def get_resolve_snmp_clear() -> HTMLResponse:
    """Vide le compte rendu SNMP — et RELANCE ainsi le rafraîchissement auto.

    Existe pour une raison de CSP, pas par goût du détour : la politique du
    projet est `script-src 'self'` SANS `unsafe-inline` (`app/main.py`), donc
    un `onclick="...innerHTML = ''"` serait bloqué par le navigateur, EN
    SILENCE. Le bouton passe donc par htmx — le seul script déjà autorisé — et
    htmx a besoin d'une réponse à insérer : c'est cette chaîne vide.

    Le lien avec l'auto-rafraîchissement (défaut mesuré à l'écran le
    2026-08-10) : le poll `every 30s` du formulaire de fenêtre est suspendu
    tant que `#snmp-resolve-all-result` n'est pas vide, sinon il remplaçait la
    section entière et détruisait le compte rendu que l'exploitant était en
    train de lire. Vider ce conteneur est donc EXACTEMENT le geste qui rend la
    main au rafraîchissement.

    Lecture seule, aucun effet de bord : d'où un GET.
    """
    return HTMLResponse("")


@router.post("/exporters/resolve-snmp-all", response_class=HTMLResponse)
async def post_resolve_snmp_all(
    request: Request,
    conn: DbConnection,
    templates: Templates,
) -> HTMLResponse:
    """Bouton global « Tout résoudre » : traite TOUS les exportateurs en
    anomalie d'interface, en une fois.

    C'EST LE GESTE QUI TIENT À 350 ROUTEURS. Deux propriétés non
    négociables :

    1. Un échec n'interrompt PAS les suivants. Un agent muet en position 2 ne
       doit pas empêcher les 348 autres d'être résolus — sinon le geste
       global ne vaut pas mieux que le geste unitaire.
    2. Le compte rendu est PAR EXPORTATEUR, avec un état distinct chacun. Le
       récapitulatif chiffré n'existe qu'EN COMPLÉMENT du détail : « 340/350 »
       tout seul masquerait qui a échoué et pourquoi (zéro silencieux).
    """
    if not _snmp_configured():
        return _error_fragment(
            "SNMP n'est pas configuré dans Okvorado (ni communauté v2c, ni utilisateur v3) : "
            "aucun équipement n'a été interrogé. Renseigner OKVORADO_SNMP_COMMUNITY ou "
            "OKVORADO_SNMP_V3_USERNAME."
        )

    try:
        statuses = await load_exporter_statuses(DEFAULT_WINDOW)
    except Exception as exc:  # noqa: BLE001 - jamais un 500 nu
        log.error(
            "resolution snmp globale: chargement des exportateurs echoue: %s", exc, exc_info=True
        )
        return _error_fragment(
            f"Impossible de charger la liste des exportateurs : {exc}. "
            "Aucune requête SNMP n'a été émise."
        )

    candidates = [status for status in statuses if _needs_resolution(status)]

    # SONDAGE CONCURRENT — mesuré à l'écran le 2026-08-10.
    # CONFIG_HARDCODE_OK: les valeurs citées ci-dessous sont une MESURE datée
    # consignée en commentaire, pas une adresse lue par le code.
    #
    # La version initiale bouclait avec un `await` PAR exportateur, donc en
    # SÉQUENTIEL : chaque machine sans agent SNMP coûte son timeout complet
    # (3,4 s mesurées sur un exportateur muet du homelab), et le bouton mettait
    # 9,8 s à répondre pour 11 exportateurs — pendant lesquelles l'écran ne
    # montrait RIEN. À 350 routeurs, la cible produit (CLAUDE.md), cette
    # addition de timeouts se compterait en MINUTES : le geste global perdrait
    # tout son intérêt.
    #
    # Les sondages sont indépendants (aucun état partagé, chacun sur son
    # propre thread via `to_thread`) : les lancer ensemble ramène le coût
    # total au coût du PLUS LENT, pas à leur somme. `return_exceptions=True`
    # préserve la propriété 1 — une exception isolée devient une LIGNE
    # d'erreur, jamais une interruption des autres ni un 500 nu.
    #
    # L'écriture (`_stage_resolved_if_indexes`) reste SÉQUENTIELLE plus bas :
    # elle partage la connexion SQLite, qu'on ne parallélise pas.
    resultats = await asyncio.gather(
        *(asyncio.to_thread(_resolve_one_blocking, status.address) for status in candidates),
        return_exceptions=True,
    )

    rows: list[_ResolveRow] = []
    for status, resultat_ou_erreur in zip(candidates, resultats, strict=True):
        if isinstance(resultat_ou_erreur, BaseException):
            log.error(
                "resolution snmp globale: echec inattendu sur un exportateur: address=%s erreur=%s",
                status.address,
                resultat_ou_erreur,
                exc_info=resultat_ou_erreur,
            )
            rows.append(
                _ResolveRow(
                    address=status.address,
                    name=status.name,
                    status="error",
                    message=f"Erreur inattendue pendant la résolution : {resultat_ou_erreur}",
                )
            )
            continue

        result, source = resultat_ou_erreur

        if not result.is_usable:
            rows.append(
                _ResolveRow(
                    address=status.address,
                    name=status.name,
                    status=result.status,
                    message=result.message,
                    source=source,
                )
            )
            continue

        stage_result = _stage_resolved_if_indexes(conn, status, result.interfaces)
        filtrage = stage_result.filtrage

        if filtrage is not None and filtrage.tout_ecarte:
            # SIGNAL D'ALARME dédié : distinct de `empty_table` (l'équipement
            # A répondu avec des interfaces, c'est le FILTRE qui n'en garde
            # aucune) — l'exploitant doit comprendre que ce sont ses motifs
            # d'exclusion, pas l'équipement, qui sont en cause ici.
            rows.append(
                _ResolveRow(
                    address=status.address,
                    name=status.name,
                    status="filtre_tout_ecarte",
                    message=(
                        f"{filtrage.total_vues} interface(s) lue(s) mais TOUTES écartées par "
                        "le filtre d'exclusion (OKVORADO_INTERFACE_EXCLUDE_PATTERNS) : aucun "
                        "changement mis en attente. Motifs probablement inadaptés à cet "
                        "équipement."
                    ),
                    source=source,
                    total_vues=filtrage.total_vues,
                    total_ecartees=filtrage.total_ecartees,
                )
            )
            continue

        rows.append(
            _ResolveRow(
                address=status.address,
                name=status.name,
                status="ok" if stage_result.staged else "empty_table",
                message=(
                    result.message
                    if stage_result.staged
                    else "Table résolue mais aucun changement n'a pu être mis en attente "
                    "(exportateur sans déclaration nominative)."
                ),
                interface_count=len(result.interfaces),
                staged=stage_result.staged,
                source=source,
                total_vues=filtrage.total_vues if filtrage is not None else 0,
                total_ecartees=filtrage.total_ecartees if filtrage is not None else 0,
            )
        )

    total_resolus = sum(1 for row in rows if row.status == "ok")
    log.info("resolution snmp globale terminee: traites=%d resolus=%d", len(rows), total_resolus)

    return templates.TemplateResponse(
        request,
        "_snmp_resolve_all_fragment.html",
        {
            "rows": rows,
            "total_traites": len(rows),
            "total_resolus": total_resolus,
        },
    )
