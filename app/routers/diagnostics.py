"""Router Diagnostics — vue convergence et écran par exportateur.

Consomme exclusivement `app.services.diagnostics` (SQL déjà construit, jamais
réinventé ici) et `app.clients.clickhouse` pour la connexion. Ce router ne
construit AUCUN SQL : chaque route appelle un `build_xxx_query()` du service,
exécute le résultat via le client injecté, et met en forme.

GARDE SÉCU N°1 DU PROJET : `period`, `dimension` (indirectement, via
`onglet`) sont validées par le service via une énumération/allowlist FERMÉE.
`ValueError` levée par le service devient un 422 avec message lisible —
jamais un 500 nu (cf. `tests/test_diagnostics_routes.py`).

ZÉRO SILENCIEUX : un échec de connexion ClickHouse rend un état DISTINCT et
VISIBLE (« indisponible »), jamais un tableau vide qui se confondrait avec une
vraie mesure d'absence de convergence (CLAUDE.md, règle n°2).
"""

from __future__ import annotations

import logging
import sqlite3
from html import escape
from typing import Annotated, Any, Protocol

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.services import diagnostics, portmap
from app.services.flow_sample import format_display_address
from app.templating import build_templates, humanize_bytes, humanize_number

log = logging.getLogger(__name__)

router = APIRouter(tags=["diagnostics"])


# ---------------------------------------------------------------------------
# Protocol du client ClickHouse — même contrat que app/routers/views.py
# ---------------------------------------------------------------------------


class QueryResult(Protocol):
    """Résultat minimal attendu d'une requête ClickHouse (clickhouse_connect)."""

    result_rows: list[tuple[Any, ...]]
    column_names: list[str]


class ClickHouseClient(Protocol):
    """Ce dont ce module a besoin d'un client ClickHouse.

    Signature calquée sur `clickhouse_connect.driver.client.Client.query` :
    paramètres nommés passés séparément du SQL, jamais interpolés.
    """

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> QueryResult: ...


# ---------------------------------------------------------------------------
# Dépendances — surchargées dans app/main.py (câblage réel) et les tests
# ---------------------------------------------------------------------------


def get_clickhouse_client() -> ClickHouseClient:
    """Placeholder — app/main.py doit surcharger cette dépendance."""
    raise RuntimeError(
        "get_clickhouse_client non câblée : app/main.py doit surcharger cette "
        "dépendance avec le client ClickHouse réel."
    )


def get_templates() -> Jinja2Templates:
    return build_templates()


def get_db_connection() -> sqlite3.Connection:
    """Placeholder — app/main.py doit surcharger cette dépendance.

    Même mécanisme que `app/routers/views.py::get_db_connection` (câblé sur
    `_open_db` dans `app/main.py`) : ce router résout les ports en nom
    d'application via `app.services.portmap.resolve_application`, qui a
    besoin d'une connexion SQLite sur `port_mappings` — pas un second
    câblage de dépendance."""
    raise RuntimeError(
        "get_db_connection non câblée : app/main.py (LOT 0) doit surcharger "
        "cette dépendance avec la connexion SQLite réelle."
    )


ChClient = Annotated[ClickHouseClient, Depends(get_clickhouse_client)]
Templates = Annotated[Jinja2Templates, Depends(get_templates)]
DbConnection = Annotated[sqlite3.Connection, Depends(get_db_connection)]


# ---------------------------------------------------------------------------
# Exécution de requête avec dégradation VISIBLE — jamais de zéro silencieux
# ---------------------------------------------------------------------------


def _run_query(
    client: ClickHouseClient, sql: str, parameters: dict[str, Any]
) -> tuple[list[dict[str, Any]], str | None]:
    """Exécute une requête déjà construite et rend `(items, erreur)`.

    `erreur` est `None` en cas de succès. En cas d'échec, `items` est une
    liste VIDE mais `erreur` porte un message non vide : c'est ce couple qui
    évite le zéro silencieux — l'appelant DOIT distinguer « aucune donnée » de
    « la mesure a échoué », jamais les confondre (CLAUDE.md, règle n°2).
    """
    try:
        result = client.query(sql, parameters=parameters)
    except Exception as exc:
        log.error("echec requete clickhouse diagnostics: %s", exc, exc_info=True)
        return [], f"Impossible d'interroger ClickHouse pour le moment : {exc}"

    items = [dict(zip(result.column_names, row, strict=True)) for row in result.result_rows]
    return items, None


def _erreur_html(message: str) -> str:
    """Bloc d'indisponibilité VISIBLE — jamais un tableau vide silencieux."""
    return f'<div class="notice notice-crit"><strong>Indisponible</strong>{escape(message)}</div>'


# ---------------------------------------------------------------------------
# Traduction DSCP -> nom de classe QoS (mesuré en prod : EF, AF21, CS6, CS1...)
# ---------------------------------------------------------------------------

_DSCP_CLASS_NAMES: dict[int, str] = {
    0: "BE",
    8: "CS1",
    10: "AF11",
    12: "AF12",
    14: "AF13",
    16: "CS2",
    18: "AF21",
    20: "AF22",
    22: "AF23",
    24: "CS3",
    26: "AF31",
    28: "AF32",
    30: "AF33",
    32: "CS4",
    34: "AF41",
    36: "AF42",
    38: "AF43",
    40: "CS5",
    46: "EF",
    48: "CS6",
    56: "CS7",
}
"""Table RFC 4594 / RFC 2597 des classes DSCP standard. `dscp` est une valeur
numérique 0-63 (IPTos >> 2) : sans cette table, un opérateur lirait « 46 » là
où « EF » (Expedited Forwarding, la classe voix/temps-réel) se lit d'un coup
d'œil. Mesuré en prod le 2026-08-07 : 7 classes réelles observées, dont
EF, AF21, CS6, CS1."""


def _dscp_label(dscp: int) -> str:
    """Rend le nom de classe DSCP, ou le chiffre brut si hors table connue."""
    return _DSCP_CLASS_NAMES.get(dscp, f"DSCP {dscp}")


def _injecter_applications(conn: sqlite3.Connection, items: list[dict[str, Any]]) -> None:
    """Ajoute la clé `application` à chaque ligne, in place — même choix que
    `app/routers/views.py::_resolve_services_applications` pour la vue
    « services » : une seule passe de résolution groupée par couple (port,
    proto) DISTINCT (cf. `_resoudre_applications`), jamais une requête SQLite
    par ligne, puis assignation directe pour un accès simple côté gabarit
    Jinja (`item.application`)."""
    applications = _resoudre_applications(conn, items)
    for item in items:
        dst_port = item.get("DstPort")
        proto = item.get("Proto")
        if not isinstance(dst_port, int):
            item["application"] = "—"
            continue
        proto_str = diagnostics.resolve_protocol_label(proto).lower()
        item["application"] = applications.get((dst_port, proto_str), f"{proto_str}/{dst_port}")


# ---------------------------------------------------------------------------
# Vue 1 — GET /diagnostics/convergence
# ---------------------------------------------------------------------------


@router.get("/diagnostics/convergence", response_class=HTMLResponse)
def get_convergence_page(
    request: Request,
    client: ChClient,
    conn: DbConnection,
    templates: Templates,
    period: str = Query(default="1h"),
    min_sources: int = Query(default=diagnostics.DEFAULT_MIN_SOURCES),
    limit: int = Query(default=diagnostics.DEFAULT_CONVERGENCE_LIMIT),
) -> HTMLResponse:
    """Vue de convergence : N sources internes convergeant vers UNE destination.

    Répond au cas d'usage cible (GPO/SCCM) sans savoir à l'avance quoi
    chercher : classement par nombre de sources DISTINCTES décroissant.
    """
    try:
        sql, parameters = diagnostics.build_convergence_query(
            period=period, min_sources=min_sources, limit=limit
        )
    except ValueError as exc:
        log.error("periode de convergence invalide: period=%s: %s", period, exc)
        return templates.TemplateResponse(
            request,
            "convergence.html",
            {
                "active_page": "diagnostics_convergence",
                "error": str(exc),
                "items": [],
                "total": 0,
                "period_choices": diagnostics.DIAGNOSTIC_PERIOD_CHOICES,
                "current_period": period,
                "min_sources": min_sources,
                "limit": limit,
            },
            status_code=422,
        )

    items, erreur = _run_query(client, sql, parameters)
    _injecter_applications(conn, items)

    return templates.TemplateResponse(
        request,
        "convergence.html",
        {
            "active_page": "diagnostics_convergence",
            "error": erreur,
            "items": items,
            "total": len(items),
            "period_choices": diagnostics.DIAGNOSTIC_PERIOD_CHOICES,
            "current_period": period,
            # Valeurs RÉELLEMENT appliquées (post-clamp), pas la query string
            # brute : `parameters` porte déjà ce que `build_convergence_query`
            # a effectivement lié à la requête ClickHouse (min_sources remonté
            # à 1, limit plafonnée à MAX_CONVERGENCE_LIMIT) — l'écran doit
            # montrer la mesure faite, pas la saisie non appliquée.
            "min_sources": parameters["min_sources"],
            "limit": parameters["limit"],
        },
    )


@router.get("/diagnostics/convergence/detail", response_class=HTMLResponse)
def get_convergence_detail(
    client: ChClient,
    conn: DbConnection,
    dst_addr: str = Query(...),
    dst_port: int = Query(..., ge=0, le=65535),
    proto: int = Query(default=6),
    period: str = Query(default="1h"),
    limit: int = Query(default=diagnostics.DEFAULT_CONVERGENCE_LIMIT),
) -> HTMLResponse:
    """Drill-down HTMX : détail des sources d'une destination retenue.

    Fragment inséré sous la ligne cliquée — quelles sources exactement, via
    quel exportateur/interface. C'est le geste de diagnostic complet : repérer
    l'anomalie sur la vue de convergence, cliquer, voir qui.

    `proto` (numéro IP, transmis par `hx-vals` depuis la ligne cliquée du
    tableau parent — cf. `convergence.html`) sert uniquement à résoudre le nom
    d'application affiché en en-tête du fragment ; il ne filtre PAS la requête
    ClickHouse (le classement parent porte déjà le triplet exact). Défaut à
    TCP (6) si absent, pour compatibilité avec un appel qui l'omettrait.
    """
    try:
        sql, parameters = diagnostics.build_convergence_detail_query(
            dst_addr=dst_addr, dst_port=dst_port, period=period, limit=limit
        )
    except ValueError as exc:
        log.error("periode de detail convergence invalide: period=%s: %s", period, exc)
        return HTMLResponse(
            f'<p class="notice notice-crit">{escape(str(exc))}</p>', status_code=422
        )

    items, erreur = _run_query(client, sql, parameters)
    if erreur:
        return HTMLResponse(_erreur_html(erreur))

    proto_str = diagnostics.resolve_protocol_label(proto).lower()
    application = (
        portmap.resolve_application(conn, dst_port, proto_str)
        if proto_str in portmap.VALID_PROTOS
        else f"{proto_str}/{dst_port}"
    )
    entete_application = (
        f'<p class="convergence-detail-application">'
        f"Application : <strong>{escape(application)}</strong> (port {dst_port})</p>"
    )

    if not items:
        message_vide = (
            '<p class="empty">Aucune source détaillée pour cette destination sur cette fenêtre.</p>'
        )
        return HTMLResponse(entete_application + message_vide)

    lignes = "".join(
        "<tr>"
        f"<td>{escape(format_display_address(item.get('SrcAddr')))}</td>"
        f"<td>{escape(str(item.get('ExporterName', '—')))}</td>"
        f"<td>{escape(str(item.get('InIfName', '—')))}</td>"
        f'<td class="num">{escape(humanize_bytes(item.get("total_bytes", 0)))}</td>'
        f'<td class="num">{escape(humanize_number(item.get("flow_count", 0)))}</td>'
        "</tr>"
        for item in items
    )
    return HTMLResponse(
        entete_application + '<table class="convergence-detail-table"><thead><tr>'
        "<th>Source</th><th>Exportateur</th><th>Interface</th>"
        "<th>Volume</th><th>Flux</th>"
        f"</tr></thead><tbody>{lignes}</tbody></table>"
    )


# ---------------------------------------------------------------------------
# Vue 2 — GET /exporters/{nom} — écran à 8 onglets
# ---------------------------------------------------------------------------

_ONGLETS_EXPORTATEUR: tuple[str, ...] = (
    "resume",
    "trafic",
    "interfaces",
    "applications",
    "sources",
    "destinations",
    "conversations",
    "qos",
)
"""Les 8 onglets choisis explicitement par l'utilisateur — énumération fermée,
pas de nom d'onglet libre."""


@router.get("/exporters/{exporter_name}", response_class=HTMLResponse)
def get_exporter_detail_page(
    request: Request,
    templates: Templates,
    exporter_name: str,
    period: str = Query(default="1h"),
) -> HTMLResponse:
    """Page d'accueil de l'écran exportateur : cadre des 8 onglets.

    Chaque onglet se charge en HTMX via sa PROPRE requête (`/exporters/{nom}
    /onglet/{onglet}`) — un seul chargement d'un coup ralentirait la page pour
    des données que l'utilisateur ne regarde pas forcément toutes.
    """
    if period not in diagnostics.DIAGNOSTIC_PERIOD_CHOICES:
        message = (
            f"periode invalide: {period!r} (attendu: "
            f"{', '.join(diagnostics.DIAGNOSTIC_PERIOD_CHOICES)})"
        )
        log.error("periode invalide pour l'ecran exportateur: %s", message)
        return HTMLResponse(escape(message), status_code=422)

    return templates.TemplateResponse(
        request,
        "exporter_detail.html",
        {
            "active_page": "exporters",
            "exporter_name": exporter_name,
            "period_choices": diagnostics.DIAGNOSTIC_PERIOD_CHOICES,
            "current_period": period,
            "onglets": _ONGLETS_EXPORTATEUR,
        },
    )


_LABELS_APPLICATION: dict[str, str] = {
    "DstPort": "Port",
    "Proto": "Protocole",
    "SrcAddr": "Source",
    "DstAddr": "Destination",
    "InIfName": "Interface",
    "InIfSpeed": "Débit (Mb/s)",
    "total_bytes": "Volume",
    "total_packets": "Paquets",
    "flow_count": "Flux",
    "bucket": "Horodatage",
    "SrcCountry": "Pays source",
    "DstCountry": "Pays destination",
    "SrcAS": "AS source",
    "DstAS": "AS destination",
    "SrcPort": "Port source",
}


_COLONNES_ADRESSE: frozenset[str] = frozenset({"SrcAddr", "DstAddr"})
"""Colonnes rendues via `format_display_address()` plutôt que `str()` brut —
sinon les onglets Sources/Destinations/Conversations afficheraient l'adresse
sous sa forme IPv6-mappée, illisible pour un opérateur (défaut mesuré à
l'écran le 2026-08-07 ; cf. docstring de `format_display_address`,
`flow_sample.py`, pour un exemple de forme)."""

_COLONNES_VOLUME: frozenset[str] = frozenset({"total_bytes"})
"""Colonnes rendues via `humanize_bytes()` (filtre Jinja partagé de
`app/templating.py`, déjà utilisé par `convergence.html`) — DÉFAUT MESURÉ EN
PRODUCTION (2026-08-07) : les onglets Applications/Sources/Destinations/
Conversations affichaient le volume en octets bruts (ex. `4497709712`)."""

_COLONNES_COMPTAGE: frozenset[str] = frozenset({"total_packets", "flow_count"})
"""Colonnes rendues via `humanize_number()` : séparateur de milliers, pas de
conversion d'unité (ce sont des comptages, pas un volume)."""


def _resoudre_applications(
    conn: sqlite3.Connection, items: list[dict[str, Any]]
) -> dict[tuple[int, str], str]:
    """Résout tous les couples (DstPort, Proto) DISTINCTS d'`items` en un nom
    d'application, en UNE passe de requêtes bornée au nombre de couples
    distincts — jamais une requête SQLite par ligne affichée.

    Un tableau de 50 lignes du même port ne doit interroger `port_mappings`
    qu'une seule fois par couple (port, proto) réellement différent : c'est
    ce cache local (dict) qui l'évite, `resolve_application()` lui-même
    n'étant pas mémoïsé (LOT 3, hors périmètre de ce correctif).

    Args:
        conn: connexion SQLite portant `port_mappings` (même mécanisme de
            dépendance que `app/routers/views.py`).
        items: lignes déjà résolues par ClickHouse, doit porter `DstPort`
            (int) et `Proto` (int ou déjà une chaîne 'tcp'/'udp').

    Returns:
        Un dict `(port, proto_str) -> nom d'application`, où `proto_str` est
        déjà la chaîne 'tcp'/'udp' attendue par `resolve_application`.
    """
    couples_distincts: set[tuple[int, str]] = set()
    for item in items:
        dst_port = item.get("DstPort")
        proto = item.get("Proto")
        if not isinstance(dst_port, int):
            continue
        proto_str = diagnostics.resolve_protocol_label(proto).lower()
        couples_distincts.add((dst_port, proto_str))

    return {
        (port, proto_str): portmap.resolve_application(conn, port, proto_str)
        for port, proto_str in couples_distincts
        if proto_str in portmap.VALID_PROTOS
    }


def _rendu_tableau_generique(
    items: list[dict[str, Any]],
    applications: dict[tuple[int, str], str] | None = None,
) -> str:
    """Rend un tableau HTML générique à partir des colonnes réellement présentes.

    Pas de schéma figé par onglet : chaque `build_xxx_query()` du service
    choisit ses propres colonnes, ce tableau s'y adapte plutôt que de dupliquer
    une liste de colonnes qui dériverait au premier changement du service.

    `applications` (résolu par `_resoudre_applications`, une seule passe SQLite
    pour tout le tableau) ajoute une colonne « Application » juste avant
    `DstPort` quand cette colonne est présente — le NOM en plus du NUMÉRO, un
    exploitant réseau a besoin des deux (cf. CONTRACT.md, défaut mesuré en
    prod le 2026-08-07 : port brut affiché au lieu du nom d'application)."""
    if not items:
        return '<p class="empty">Aucune donnée sur cette fenêtre.</p>'

    colonnes = list(items[0].keys())
    avec_application = applications is not None and "DstPort" in colonnes
    if avec_application:
        index_port = colonnes.index("DstPort")
        colonnes = [*colonnes[:index_port], "_application", *colonnes[index_port:]]

    def _libelle_colonne(c: str) -> str:
        return "Application" if c == "_application" else _LABELS_APPLICATION.get(c, c)

    entete = "".join(f"<th>{escape(_libelle_colonne(c))}</th>" for c in colonnes)
    corps = "".join(
        "<tr>"
        + "".join(
            f'<td class="{"num" if isinstance(row.get(c), int) else ""}">'
            + escape(
                _rendu_cellule_application(row, applications)
                if c == "_application" and applications is not None
                else _rendu_cellule_generique(c, row.get(c))
            )
            + "</td>"
            for c in colonnes
        )
        + "</tr>"
        for row in items
    )
    return f"<table><thead><tr>{entete}</tr></thead><tbody>{corps}</tbody></table>"


def _rendu_cellule_application(
    row: dict[str, Any], applications: dict[tuple[int, str], str]
) -> str:
    """Rend le nom d'application résolu pour la ligne, ou le repli `proto/port`
    déjà produit par `resolve_application()` si le couple n'a pas été résolu
    (protocole hors TCP/UDP, ex. ICMP — pas de service applicatif au sens de
    ce diagnostic)."""
    dst_port = row.get("DstPort")
    proto = row.get("Proto")
    if not isinstance(dst_port, int):
        return "—"
    proto_str = diagnostics.resolve_protocol_label(proto).lower()
    return applications.get((dst_port, proto_str), f"{proto_str}/{dst_port}")


def _rendu_cellule_generique(colonne: str, valeur: Any) -> str:
    """Rend une cellule du tableau générique dans son format lisible.

    Adresse dé-mappée, volume en unité lisible (Go/Mo/...), comptage avec
    séparateur de milliers, protocole en nom (TCP/UDP/...) — chacun via la
    fonction déjà partagée dans le projet pour ce concept, jamais une
    deuxième implémentation locale."""
    if colonne in _COLONNES_ADRESSE:
        return format_display_address(valeur)
    if colonne in _COLONNES_VOLUME:
        return humanize_bytes(valeur)
    if colonne in _COLONNES_COMPTAGE:
        return humanize_number(valeur)
    if colonne == "Proto":
        return diagnostics.resolve_protocol_label(valeur)
    return str(valeur) if valeur is not None else "—"


def _rendu_onglet_qos(items: list[dict[str, Any]]) -> str:
    """Rendu spécifique QoS : traduit `dscp` (0-63) en nom de classe lisible."""
    if not items:
        return '<p class="empty">Aucune donnée QoS sur cette fenêtre.</p>'

    lignes = "".join(
        "<tr>"
        f"<td>{escape(_dscp_label(int(item['dscp'])))}</td>"
        f'<td class="num">{escape(humanize_bytes(item.get("total_bytes", 0)))}</td>'
        f'<td class="num">{escape(humanize_number(item.get("flow_count", 0)))}</td>'
        "</tr>"
        for item in items
    )
    return (
        "<table><thead><tr><th>Classe DSCP</th><th>Volume</th><th>Flux</th>"
        f"</tr></thead><tbody>{lignes}</tbody></table>"
    )


def _construire_requete_onglet(
    onglet: str, exporter_name: str, period: str
) -> tuple[str, dict[str, Any]]:
    """Sélectionne et invoque le builder du service pour cet onglet.

    `onglet` est déjà validé contre `_ONGLETS_EXPORTATEUR` par l'appelant :
    ce dispatch reste une correspondance en dur, jamais un nom dynamique
    transmis à une construction de SQL.
    """
    if onglet == "trafic":
        return diagnostics.build_exporter_time_series_query(
            exporter_name=exporter_name, period=period
        )
    if onglet == "interfaces":
        return diagnostics.build_exporter_top_interfaces_query(
            exporter_name=exporter_name, period=period
        )
    if onglet == "applications":
        return diagnostics.build_exporter_top_applications_query(
            exporter_name=exporter_name, period=period
        )
    if onglet == "sources":
        return diagnostics.build_exporter_top_sources_query(
            exporter_name=exporter_name, period=period
        )
    if onglet == "destinations":
        return diagnostics.build_exporter_top_destinations_query(
            exporter_name=exporter_name, period=period
        )
    if onglet == "conversations":
        return diagnostics.build_exporter_top_conversations_query(
            exporter_name=exporter_name, period=period
        )
    # "qos" — dernier cas de l'énumération fermée _ONGLETS_EXPORTATEUR.
    return diagnostics.build_exporter_qos_query(exporter_name=exporter_name, period=period)


def _rendu_onglet_resume(
    client: ClickHouseClient, conn: sqlite3.Connection, exporter_name: str, period: str
) -> str:
    """Onglet Résumé : recoupe trafic total + top applications en un coup d'œil.

    Pas de builder dédié côté service (pur assemblage de présentation) : deux
    requêtes légères déjà exposées, affichées ensemble."""
    sql_trafic, params_trafic = diagnostics.build_exporter_time_series_query(
        exporter_name=exporter_name, period=period
    )
    sql_apps, params_apps = diagnostics.build_exporter_top_applications_query(
        exporter_name=exporter_name, period=period, limit=10
    )

    items_trafic, erreur_trafic = _run_query(client, sql_trafic, params_trafic)
    if erreur_trafic:
        return _erreur_html(erreur_trafic)
    items_apps, erreur_apps = _run_query(client, sql_apps, params_apps)
    if erreur_apps:
        return _erreur_html(erreur_apps)

    total_volume = sum(int(row.get("total_bytes", 0) or 0) for row in items_trafic)
    total_flux = sum(int(row.get("flow_count", 0) or 0) for row in items_trafic)
    volume_fmt = humanize_bytes(total_volume)
    flux_fmt = humanize_number(total_flux)

    applications = _resoudre_applications(conn, items_apps)
    return (
        '<div class="exporter-summary">'
        f"<p>Volume total sur la fenêtre : <strong>{volume_fmt}</strong></p>"
        f"<p>Flux observés : <strong>{flux_fmt} flux</strong></p>"
        "<h3>Applications les plus actives</h3>"
        + _rendu_tableau_generique(items_apps, applications)
        + "</div>"
    )


_ONGLETS_AVEC_RESOLUTION_APPLICATION: frozenset[str] = frozenset({"applications", "conversations"})
"""Onglets dont le tableau porte `DstPort`/`Proto` et doit donc afficher le
nom d'application résolu (`portmap.resolve_application`) en plus du numéro de
port — cf. CONTRACT.md, défaut mesuré en prod le 2026-08-07."""


@router.get("/exporters/{exporter_name}/onglet/{onglet}", response_class=HTMLResponse)
def get_exporter_tab_fragment(
    client: ChClient,
    conn: DbConnection,
    exporter_name: str,
    onglet: str,
    period: str = Query(default="1h"),
) -> HTMLResponse:
    """Fragment HTMX d'un onglet de l'écran exportateur.

    `onglet` est validé contre `_ONGLETS_EXPORTATEUR` (énumération fermée,
    jamais un nom libre transmis à une construction de SQL).
    """
    if onglet not in _ONGLETS_EXPORTATEUR:
        message = f"onglet inconnu: {onglet!r} (attendu: {', '.join(_ONGLETS_EXPORTATEUR)})"
        log.error("onglet exportateur inconnu: %s", message)
        return HTMLResponse(escape(message), status_code=422)

    try:
        if onglet == "resume":
            return HTMLResponse(_rendu_onglet_resume(client, conn, exporter_name, period))
        sql, parameters = _construire_requete_onglet(onglet, exporter_name, period)
    except ValueError as exc:
        log.error("periode invalide onglet %s: %s", onglet, exc)
        return HTMLResponse(escape(str(exc)), status_code=422)

    items, erreur = _run_query(client, sql, parameters)
    if erreur:
        return HTMLResponse(_erreur_html(erreur))

    if onglet == "qos":
        return HTMLResponse(_rendu_onglet_qos(items))

    if onglet in _ONGLETS_AVEC_RESOLUTION_APPLICATION:
        applications = _resoudre_applications(conn, items)
        return HTMLResponse(_rendu_tableau_generique(items, applications))

    return HTMLResponse(_rendu_tableau_generique(items))
