"""Router LOT 3 — Vues métier.

Traduit les flux NetFlow bruts en vues prêtes à l'emploi pour un collègue :
qui parle à qui, quels services, WAN vs mesh, dans le temps, QoS.

Le client ClickHouse est injecté (LOT 1 l'implémente) : ce module ne connaît
que le `Protocol` ci-dessous. La connexion SQLite est injectée (LOT 0) : ce
module ne connaît que `sqlite3.Connection`.

GARDE SÉCU N°1 : toutes les requêtes ClickHouse sont paramétrées
(`{nom:Type}` du driver `clickhouse_connect`). Noms de tables/colonnes en dur.
Aucune valeur utilisateur n'est interpolée dans une chaîne SQL — la fenêtre
passe exclusivement par `window_to_interval()` (table figée de littéraux).
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime, timedelta
from enum import Enum
from html import escape
from typing import Annotated, Any, Protocol

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app.config import WINDOW_CHOICES, Settings, window_to_interval
from app.config import settings as default_settings
from app.services import portmap
from app.templating import build_templates

log = logging.getLogger(__name__)

router = APIRouter(tags=["views"])


# ---------------------------------------------------------------------------
# Protocol du client ClickHouse — contrat avec LOT 1
# ---------------------------------------------------------------------------


class QueryResult(Protocol):
    """Résultat minimal attendu d'une requête ClickHouse (clickhouse_connect)."""

    result_rows: list[tuple[Any, ...]]
    column_names: list[str]


class ClickHouseClient(Protocol):
    """Ce dont ce module a besoin d'un client ClickHouse. LOT 1 l'implémente.

    Signature calquée sur `clickhouse_connect.driver.client.Client.query` :
    paramètres nommés passés séparément du SQL, jamais interpolés.
    """

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> QueryResult: ...


# ---------------------------------------------------------------------------
# Allowlist des vues — Enum en dur, pas de nom libre
# ---------------------------------------------------------------------------


class ViewName(str, Enum):
    TALKERS = "talkers"
    SERVICES = "services"
    BOUNDARY = "boundary"
    TIMESERIES = "timeseries"
    QOS = "qos"


# ---------------------------------------------------------------------------
# Dépendances — surchargées dans les tests via app.dependency_overrides
# ---------------------------------------------------------------------------


def get_settings() -> Settings:
    return default_settings


def get_db_connection() -> sqlite3.Connection:
    """Placeholder — LOT 0 fournit la vraie connexion via app/db.py.

    Cette fonction n'est jamais appelée telle quelle en test (toujours
    surchargée par `app.dependency_overrides`) ; en prod elle sera
    remplacée/branchée par le câblage de app/main.py (LOT 0).
    """
    raise RuntimeError(
        "get_db_connection non câblée : app/main.py (LOT 0) doit surcharger "
        "cette dépendance avec la connexion SQLite réelle."
    )


def get_clickhouse_client() -> ClickHouseClient:
    """Placeholder — LOT 1 fournit le vrai client via app/clients/clickhouse.py."""
    raise RuntimeError(
        "get_clickhouse_client non câblée : app/main.py (LOT 0) doit surcharger "
        "cette dépendance avec le client ClickHouse réel (LOT 1)."
    )


def get_templates() -> Jinja2Templates:
    return build_templates()


DbConnection = Annotated[sqlite3.Connection, Depends(get_db_connection)]
ChClient = Annotated[ClickHouseClient, Depends(get_clickhouse_client)]
AppSettings = Annotated[Settings, Depends(get_settings)]
Templates = Annotated[Jinja2Templates, Depends(get_templates)]


# ---------------------------------------------------------------------------
# Construction des requêtes — 5 vues métier
# ---------------------------------------------------------------------------


def _validated_interval(window: str) -> str:
    """Traduit et valide la fenêtre. Lève ValueError si hors allowlist."""
    return window_to_interval(window)


def build_top_talkers_query(window: str) -> tuple[str, dict[str, Any]]:
    """Vue 1 — Qui parle à qui : top talkers par SrcAddr/DstAddr."""
    interval = _validated_interval(window)
    sql = f"""
        SELECT
            SrcAddr,
            DstAddr,
            sum(Bytes * SamplingRate) AS total_bytes,
            sum(Packets * SamplingRate) AS total_packets,
            count() AS flow_count
        FROM flows
        WHERE TimeReceived >= now() - INTERVAL {interval}
        GROUP BY SrcAddr, DstAddr
        ORDER BY total_bytes DESC
        LIMIT {{limit:UInt32}}
    """
    return sql, {"limit": 100}


def build_services_volumetry_query(window: str) -> tuple[str, dict[str, Any]]:
    """Vue 2 — Quels services : volumétrie par DstPort/Proto."""
    interval = _validated_interval(window)
    sql = f"""
        SELECT
            DstPort,
            Proto,
            sum(Bytes * SamplingRate) AS total_bytes,
            sum(Packets * SamplingRate) AS total_packets,
            count() AS flow_count
        FROM flows
        WHERE TimeReceived >= now() - INTERVAL {interval}
        GROUP BY DstPort, Proto
        ORDER BY total_bytes DESC
        LIMIT {{limit:UInt32}}
    """
    return sql, {"limit": 100}


def build_wan_vs_mesh_query(window: str) -> tuple[str, dict[str, Any]]:
    """Vue 3 — WAN vs mesh : répartition par InIfBoundary."""
    interval = _validated_interval(window)
    sql = f"""
        SELECT
            InIfBoundary,
            sum(Bytes * SamplingRate) AS total_bytes,
            sum(Packets * SamplingRate) AS total_packets,
            count() AS flow_count
        FROM flows
        WHERE TimeReceived >= now() - INTERVAL {interval}
        GROUP BY InIfBoundary
        ORDER BY total_bytes DESC
    """
    return sql, {}


_TIME_SERIES_STEP: dict[str, str] = {
    "1h": "5 MINUTE",
    "6h": "15 MINUTE",
    "24h": "1 HOUR",
    "7d": "6 HOUR",
}


def build_time_series_query(window: str) -> tuple[str, dict[str, Any]]:
    """Vue 4 — Dans le temps : série temporelle sum(Bytes) par intervalle."""
    interval = _validated_interval(window)
    if window not in _TIME_SERIES_STEP:
        raise ValueError(f"fenetre invalide: {window!r}")
    step = _TIME_SERIES_STEP[window]
    sql = f"""
        SELECT
            toStartOfInterval(TimeReceived, INTERVAL {step}) AS bucket,
            sum(Bytes * SamplingRate) AS total_bytes
        FROM flows
        WHERE TimeReceived >= now() - INTERVAL {interval}
        GROUP BY bucket
        ORDER BY bucket ASC
    """
    return sql, {}


def compute_previous_period_bounds(
    window: str, now: datetime | None = None
) -> tuple[datetime, datetime, datetime, datetime]:
    """Calcule (début_actuel, fin_actuelle, début_précédent, fin_précédente).

    La période précédente a exactement la même durée que la période actuelle
    et se termine pile où celle-ci commence (pas de recouvrement, pas de trou).
    """
    interval = _validated_interval(window)  # valide la fenêtre (allowlist)
    duration = _interval_to_timedelta(interval)
    reference = now or datetime.now(UTC)

    current_end = reference
    current_start = reference - duration
    previous_end = current_start
    previous_start = previous_end - duration
    return current_start, current_end, previous_start, previous_end


def _interval_to_timedelta(interval: str) -> timedelta:
    amount_str, unit = interval.split(" ", 1)
    amount = int(amount_str)
    unit_map = {
        "HOUR": timedelta(hours=1),
        "DAY": timedelta(days=1),
        "MINUTE": timedelta(minutes=1),
    }
    return amount * unit_map[unit]


def build_previous_period_query(
    window: str, now: datetime | None = None
) -> tuple[str, dict[str, Any]]:
    """Requête de comparaison à la période précédente (même durée, décalée)."""
    _, _, previous_start, previous_end = compute_previous_period_bounds(window, now=now)
    sql = """
        SELECT sum(Bytes * SamplingRate) AS total_bytes
        FROM flows
        WHERE TimeReceived >= {previous_start:DateTime} AND TimeReceived < {previous_end:DateTime}
    """
    return sql, {
        "previous_start": previous_start.strftime("%Y-%m-%d %H:%M:%S"),
        "previous_end": previous_end.strftime("%Y-%m-%d %H:%M:%S"),
    }


# ---------------------------------------------------------------------------
# Vue 5 — QoS : détection dynamique de l'absence de IPTos
# ---------------------------------------------------------------------------

_QOS_DEGRADED_REASON = (
    "La colonne IPTos n'existe pas dans le schéma ClickHouse actuel (option "
    "Akvorado non activée). Pour l'activer : ajouter 'IPTos' à schema.enabled "
    "dans la configuration Akvorado (outlet.yaml), puis redéployer l'outlet."
)

_QOS_TAILSCALE_WARNING = (
    "Même une fois IPTos activé, ~99% des flux afficheront ToS 0 : tailscale "
    "ne propage pas le marquage DSCP/ToS à l'enveloppe WireGuard (mesuré : "
    "seulement ~1% des flux portent un marquage réel)."
)


def _has_iptos_column(client: ClickHouseClient) -> bool:
    """Interroge system.columns pour détecter la présence de IPTos sur flows."""
    result = client.query(
        "SELECT name FROM system.columns WHERE table = {table:String} AND name = {column:String}",
        {"table": "flows", "column": "IPTos"},
    )
    return len(result.result_rows) > 0


def get_qos_view(client: ClickHouseClient, window: str) -> dict[str, Any]:
    """Vue 5 — QoS. Ne suppose JAMAIS la présence de IPTos, ne plante jamais.

    Retourne soit un état dégradé explicite (colonne absente ou erreur de
    schéma), soit les données avec un avertissement sur le marquage
    tailscale/WireGuard.
    """
    try:
        has_iptos = _has_iptos_column(client)
    except Exception as exc:
        log.error("qos_view: échec de la détection de la colonne IPTos: %s", exc)
        return {
            "available": False,
            "reason": (f"{_QOS_DEGRADED_REASON} (impossible de vérifier le schéma : {exc})"),
            "items": [],
            "total": 0,
        }

    if not has_iptos:
        return {
            "available": False,
            "reason": _QOS_DEGRADED_REASON,
            "items": [],
            "total": 0,
        }

    interval = _validated_interval(window)
    sql = f"""
        SELECT
            IPTos,
            sum(Bytes * SamplingRate) AS total_bytes,
            count() AS flow_count
        FROM flows
        WHERE TimeReceived >= now() - INTERVAL {interval}
        GROUP BY IPTos
        ORDER BY total_bytes DESC
    """
    try:
        result = client.query(sql, {})
    except Exception as exc:
        log.error("qos_view: échec de la requête IPTos: %s", exc)
        return {
            "available": False,
            "reason": f"{_QOS_DEGRADED_REASON} (erreur requête : {exc})",
            "items": [],
            "total": 0,
        }

    items = [dict(zip(result.column_names, row, strict=True)) for row in result.result_rows]
    return {
        "available": True,
        "warning": _QOS_TAILSCALE_WARNING,
        "items": items,
        "total": len(items),
    }


# ---------------------------------------------------------------------------
# Exécution des vues 1..4 avec gestion d'erreur propre
# ---------------------------------------------------------------------------

_QUERY_BUILDERS: dict[ViewName, Any] = {
    ViewName.TALKERS: build_top_talkers_query,
    ViewName.SERVICES: build_services_volumetry_query,
    ViewName.BOUNDARY: build_wan_vs_mesh_query,
    ViewName.TIMESERIES: build_time_series_query,
}


def _run_view_query(client: ClickHouseClient, view_name: ViewName, window: str) -> dict[str, Any]:
    builder = _QUERY_BUILDERS[view_name]
    sql, params = builder(window)
    try:
        result = client.query(sql, params)
    except Exception as exc:
        log.error(
            "views: échec requête ClickHouse pour la vue %s (window=%s): %s",
            view_name.value,
            window,
            exc,
        )
        return {"error": f"Échec de la requête ClickHouse pour la vue '{view_name.value}': {exc}"}

    items = [dict(zip(result.column_names, row, strict=True)) for row in result.result_rows]

    payload: dict[str, Any] = {"items": items, "total": len(items)}

    if view_name == ViewName.TIMESERIES:
        payload["previous_period"] = _fetch_previous_period_total(client, window)

    return payload


def _fetch_previous_period_total(client: ClickHouseClient, window: str) -> dict[str, Any]:
    sql, params = build_previous_period_query(window)
    try:
        result = client.query(sql, params)
    except Exception as exc:
        log.error("views: échec requête période précédente (window=%s): %s", window, exc)
        return {"error": str(exc), "total_bytes": None}
    if not result.result_rows:
        return {"total_bytes": 0}
    return {"total_bytes": result.result_rows[0][0]}


# ---------------------------------------------------------------------------
# Résolution applicative pour la vue "services"
# ---------------------------------------------------------------------------

_PROTO_NUMBER_TO_NAME = {1: "icmp", 6: "tcp", 17: "udp"}


def _resolve_services_applications(conn: sqlite3.Connection, items: list[dict[str, Any]]) -> None:
    """Ajoute la clé 'application' à chaque ligne de la vue services, in place."""
    for item in items:
        proto_number = item.get("Proto")
        dst_port = item.get("DstPort")
        proto_name = (
            _PROTO_NUMBER_TO_NAME.get(proto_number, str(proto_number))
            if isinstance(proto_number, int)
            else str(proto_number)
        )
        if isinstance(dst_port, int):
            item["application"] = portmap.resolve_application(conn, dst_port, proto_name)
        else:
            item["application"] = f"{proto_name}/{dst_port}"


# ---------------------------------------------------------------------------
# Pydantic — payloads du CRUD port-mappings
# ---------------------------------------------------------------------------


class PortMappingIn(BaseModel):
    port: int = Field(ge=portmap.MIN_PORT, le=portmap.MAX_PORT)
    proto: str
    application: str = Field(min_length=1, max_length=portmap.MAX_APPLICATION_LENGTH)

    def validate_proto_choice(self) -> None:
        if self.proto not in portmap.VALID_PROTOS:
            raise ValueError(f"proto invalide: {self.proto!r}")


# ---------------------------------------------------------------------------
# Routes HTML
# ---------------------------------------------------------------------------


@router.get("/views", response_class=HTMLResponse)
def get_views_page(
    request: Request,
    conn: DbConnection,
    app_settings: AppSettings,
    templates: Templates,
    window: str = Query(default="1h"),
) -> HTMLResponse:
    if window not in WINDOW_CHOICES:
        window = "1h"

    port_mappings = portmap.list_mappings(conn)

    context = {
        "request": request,
        "active_page": "views",
        "akvorado_url": app_settings.akvorado_console_url,
        "window_choices": list(WINDOW_CHOICES),
        "current_window": window,
        "akvorado_console_url": app_settings.akvorado_console_url,
        "port_mappings": port_mappings,
        "qos_available": False,
        "qos_reason": _QOS_DEGRADED_REASON,
    }
    return templates.TemplateResponse(request, "views.html", context)


# ---------------------------------------------------------------------------
# Routes API — vues
# ---------------------------------------------------------------------------


@router.get("/api/views/{view_name}")
def get_view_data(
    view_name: ViewName,
    conn: DbConnection,
    client: ChClient,
    window: str = Query(default="1h"),
) -> dict[str, Any]:
    if window not in WINDOW_CHOICES:
        raise HTTPException(
            status_code=422,
            detail=f"fenetre invalide: {window!r} (attendu: {', '.join(WINDOW_CHOICES)})",
        )

    if view_name == ViewName.QOS:
        return get_qos_view(client, window)

    payload = _run_view_query(client, view_name, window)

    if view_name == ViewName.SERVICES and "items" in payload:
        _resolve_services_applications(conn, payload["items"])

    return payload


_VIEW_COLUMN_LABELS: dict[str, str] = {
    "SrcAddr": "Source",
    "DstAddr": "Destination",
    "total_bytes": "Volume",
    "total_packets": "Paquets",
    "flow_count": "Flux",
    "DstPort": "Port",
    "Proto": "Protocole",
    "application": "Application",
    "InIfBoundary": "Périmètre",
    "bucket": "Horodatage",
}

_BOUNDARY_LABELS: dict[str, str] = {
    "external": "Vers Internet (WAN)",
    "internal": "Mesh interne",
    "undefined": "Non classifié",
}


def _humanize_bytes(value: int) -> str:
    """Formate un volume en unités lisibles (un collègue ne lit pas des octets bruts)."""
    size = float(value)
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if size < 1024 or unit == "To":
            return f"{size:.0f} {unit}" if unit == "o" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} To"


def _humanize_cell(column: str, value: Any) -> str:
    """Rend une cellule lisible : IP dé-mappée, volume en Go, périmètre en clair."""
    if value is None:
        return "—"
    if column == "total_bytes" and isinstance(value, int):
        return _humanize_bytes(value)
    if column == "InIfBoundary":
        return _BOUNDARY_LABELS.get(str(value), str(value))
    text = str(value)
    if column in {"SrcAddr", "DstAddr"} and text.startswith("::ffff:"):
        return text[7:]
    if isinstance(value, int):
        return f"{value:,}".replace(",", " ")
    return text


@router.get("/views/fragment/{view_name}", response_class=HTMLResponse)
def get_view_fragment(
    view_name: ViewName,
    conn: DbConnection,
    client: ChClient,
    window: str = Query(default="1h"),
) -> HTMLResponse:
    """Rend une vue en fragment HTML pour HTMX.

    `/api/views/{name}` reste la source JSON (contrat d'API, consommable par un
    script). Cette route rend le MÊME contenu en tableau lisible : injecter du
    JSON brut dans le DOM afficherait des accolades à l'utilisateur.
    """
    if window not in WINDOW_CHOICES:
        return HTMLResponse(
            f'<p class="empty">Fenêtre invalide : {escape(window)}</p>', status_code=422
        )

    try:
        if view_name == ViewName.QOS:
            payload = get_qos_view(client, window)
        else:
            payload = _run_view_query(client, view_name, window)
            if view_name == ViewName.SERVICES and "items" in payload:
                _resolve_services_applications(conn, payload["items"])
    except Exception as exc:  # noqa: BLE001 - dégradation visible, jamais de 500 nu
        log.error("echec rendu de la vue %s (window=%s): %s", view_name.value, window, exc)
        return HTMLResponse(
            '<p class="notice notice-crit">Impossible d\'afficher cette vue '
            "pour le moment. L'incident est journalisé.</p>"
        )

    if payload.get("available") is False:
        reason = escape(str(payload.get("reason", "")))
        return HTMLResponse(
            '<div class="notice notice-warn">'
            "<strong>Colonne absente du schéma</strong>"
            f"{reason}</div>"
        )

    items: list[dict[str, Any]] = payload.get("items", [])
    if not items:
        return HTMLResponse('<p class="empty">Aucune donnée sur cette fenêtre.</p>')

    columns = list(items[0].keys())
    head = "".join(f"<th>{escape(_VIEW_COLUMN_LABELS.get(c, c))}</th>" for c in columns)
    body = "".join(
        "<tr>"
        + "".join(
            f'<td class="{"num" if isinstance(row.get(c), int) else ""}">'
            f"{escape(_humanize_cell(c, row.get(c)))}</td>"
            for c in columns
        )
        + "</tr>"
        for row in items[:25]
    )
    return HTMLResponse(f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")


# ---------------------------------------------------------------------------
# Routes API — CRUD port-mappings
# ---------------------------------------------------------------------------


@router.get("/api/portmap")
def get_portmap(conn: DbConnection) -> dict[str, Any]:
    mappings = portmap.list_mappings(conn)
    return {"items": [m.model_dump() for m in mappings], "total": len(mappings)}


@router.post("/api/portmap", status_code=201)
def create_portmap(payload: PortMappingIn, conn: DbConnection) -> dict[str, Any]:
    if payload.proto not in portmap.VALID_PROTOS:
        raise HTTPException(status_code=422, detail=f"proto invalide: {payload.proto!r}")
    try:
        mapping = portmap.create_mapping(
            conn,
            port=payload.port,
            proto=payload.proto,
            application=payload.application,
            source="custom",
        )
    except portmap.ValidationError as exc:
        log.error("create_portmap: validation échouée: %s", exc)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"status": "ok", **mapping.model_dump()}


@router.post("/views/portmap", response_class=HTMLResponse)
def create_portmap_from_form(
    conn: DbConnection,
    port: Annotated[int, Form()],
    proto: Annotated[str, Form()],
    application: Annotated[str, Form()],
) -> HTMLResponse:
    """Ajout d'une correspondance depuis le FORMULAIRE de la page (HTMX).

    `/api/portmap` attend du JSON (contrat d'API) ; un `<form>` HTML envoie du
    `application/x-www-form-urlencoded`. Sans cette route, l'ajout à la souris
    échouerait en 422 — or toute action métier doit être faisable à la souris.
    Retourne directement la ligne de tableau à insérer.
    """
    if proto not in portmap.VALID_PROTOS:
        log.error("ajout correspondance refuse: proto invalide %r", proto)
        return HTMLResponse(
            f'<tr><td colspan="4" class="notice notice-crit">Protocole invalide : '
            f"{escape(proto)}</td></tr>",
            status_code=422,
        )
    try:
        mapping = portmap.create_mapping(
            conn, port=port, proto=proto, application=application, source="custom"
        )
        conn.commit()
    except portmap.ValidationError as exc:
        log.error("ajout correspondance refuse: %s", exc)
        return HTMLResponse(
            f'<tr><td colspan="4" class="notice notice-crit">{escape(str(exc))}</td></tr>',
            status_code=422,
        )

    return HTMLResponse(
        f"<tr>"
        f'<td class="num">{mapping.port}</td>'
        f"<td>{escape(mapping.proto)}</td>"
        f"<td>{escape(mapping.application)}</td>"
        f'<td><button class="danger" hx-delete="/views/portmap/{mapping.port}/'
        f'{escape(mapping.proto)}" hx-target="closest tr" hx-swap="outerHTML">'
        f"Supprimer</button></td>"
        f"</tr>"
    )


@router.delete("/views/portmap/{port}/{proto}", response_class=HTMLResponse)
def delete_portmap_from_ui(port: int, proto: str, conn: DbConnection) -> HTMLResponse:
    """Suppression depuis l'UI : retourne du vide pour retirer la ligne du tableau."""
    if not (portmap.MIN_PORT <= port <= portmap.MAX_PORT) or proto not in portmap.VALID_PROTOS:
        log.error("suppression refusee: port=%s proto=%r hors bornes", port, proto)
        return HTMLResponse("", status_code=422)
    portmap.delete_mapping(conn, port=port, proto=proto)
    conn.commit()
    return HTMLResponse("")


@router.delete("/api/portmap/{port}/{proto}")
def delete_portmap(port: int, proto: str, conn: DbConnection) -> dict[str, Any]:
    if not (portmap.MIN_PORT <= port <= portmap.MAX_PORT) or proto not in portmap.VALID_PROTOS:
        raise HTTPException(status_code=422, detail="port ou proto invalide")
    portmap.delete_mapping(conn, port=port, proto=proto)
    return {"status": "ok"}
