"""Tests du LOT 3 — module Vues métier.

Aucun test ici n'exige d'infra : SQLite tourne en `:memory:`, le client
ClickHouse est un faux objet respectant le `Protocol` défini par ce lot.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.routers import views as views_router
from app.services.portmap import (
    ValidationError,
    create_mapping,
    delete_mapping,
    list_mappings,
    resolve_application,
    seed_iana_defaults,
)

# ---------------------------------------------------------------------------
# Fixtures SQLite
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS port_mappings (
    port INTEGER NOT NULL,
    proto TEXT NOT NULL,
    application TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'custom',
    port_end INTEGER,
    PRIMARY KEY (port, proto)
);
"""


@pytest.fixture
def db() -> sqlite3.Connection:
    # check_same_thread=False : TestClient exécute les endpoints FastAPI dans
    # un threadpool ; la connexion :memory: doit rester utilisable depuis ce
    # thread. Pas un souci en prod (LOT 0 gère sa propre connexion).
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(SCHEMA)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# resolve_application
# ---------------------------------------------------------------------------


def test_resolve_application_known_iana_port(db: sqlite3.Connection) -> None:
    seed_iana_defaults(db)
    assert resolve_application(db, 443, "tcp") == "HTTPS"


def test_resolve_application_custom_overrides_iana(db: sqlite3.Connection) -> None:
    seed_iana_defaults(db)
    # 443 est un port IANA connu ; une surcharge custom doit primer.
    create_mapping(db, port=443, proto="tcp", application="Mon Reverse Proxy Maison")
    assert resolve_application(db, 443, "tcp") == "Mon Reverse Proxy Maison"


def test_resolve_application_unknown_port_fallback(db: sqlite3.Connection) -> None:
    seed_iana_defaults(db)
    assert resolve_application(db, 49152, "tcp") == "tcp/49152"


def test_resolve_application_unknown_udp_fallback(db: sqlite3.Connection) -> None:
    seed_iana_defaults(db)
    assert resolve_application(db, 49999, "udp") == "udp/49999"


def test_resolve_application_custom_homelab_overrides(db: sqlite3.Connection) -> None:
    seed_iana_defaults(db)
    assert resolve_application(db, 8082, "tcp") == "Akvorado"
    assert resolve_application(db, 2055, "udp") == "NetFlow v9"


# ---------------------------------------------------------------------------
# Seed idempotent
# ---------------------------------------------------------------------------


def test_seed_iana_defaults_is_idempotent(db: sqlite3.Connection) -> None:
    seed_iana_defaults(db)
    count_after_first = len(list_mappings(db))
    seed_iana_defaults(db)
    count_after_second = len(list_mappings(db))
    assert count_after_first == count_after_second


def test_seed_iana_defaults_covers_minimum_ports(db: sqlite3.Connection) -> None:
    seed_iana_defaults(db)
    mappings = {(m.port, m.proto): m.application for m in list_mappings(db)}
    expected = {
        (22, "tcp"): "SSH",
        (53, "udp"): "DNS",
        (80, "tcp"): "HTTP",
        (443, "tcp"): "HTTPS",
        (123, "udp"): "NTP",
        (3306, "tcp"): "MySQL",
        (5432, "tcp"): "PostgreSQL",
        (6379, "tcp"): "Redis",
        (9092, "tcp"): "Kafka",
        (2049, "tcp"): "NFS",
        (445, "tcp"): "SMB",
        (3389, "tcp"): "RDP",
        (161, "udp"): "SNMP",
    }
    for key, app in expected.items():
        assert key in mappings, f"port manquant: {key}"
        assert mappings[key] == app
    assert len(mappings) >= 40


def test_seed_does_not_duplicate_rows(db: sqlite3.Connection) -> None:
    seed_iana_defaults(db)
    seed_iana_defaults(db)
    seed_iana_defaults(db)
    rows = db.execute("SELECT COUNT(*) FROM port_mappings").fetchone()[0]
    assert rows == len(list_mappings(db))


def test_custom_override_survives_reseed(db: sqlite3.Connection) -> None:
    seed_iana_defaults(db)
    create_mapping(db, port=22, proto="tcp", application="Bastion perso")
    seed_iana_defaults(db)
    assert resolve_application(db, 22, "tcp") == "Bastion perso"
    mapping = next(m for m in list_mappings(db) if m.port == 22 and m.proto == "tcp")
    assert mapping.source == "custom"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_create_mapping_rejects_port_out_of_range_low(db: sqlite3.Connection) -> None:
    with pytest.raises(ValidationError):
        create_mapping(db, port=0, proto="tcp", application="X")


def test_create_mapping_rejects_port_out_of_range_high(db: sqlite3.Connection) -> None:
    with pytest.raises(ValidationError):
        create_mapping(db, port=65536, proto="tcp", application="X")


def test_create_mapping_rejects_invalid_proto(db: sqlite3.Connection) -> None:
    with pytest.raises(ValidationError):
        create_mapping(db, port=8080, proto="sctp", application="X")


def test_create_mapping_rejects_empty_application(db: sqlite3.Connection) -> None:
    with pytest.raises(ValidationError):
        create_mapping(db, port=8080, proto="tcp", application="")


def test_create_mapping_rejects_application_too_long(db: sqlite3.Connection) -> None:
    with pytest.raises(ValidationError):
        create_mapping(db, port=8080, proto="tcp", application="x" * 300)


# ---------------------------------------------------------------------------
# Injection SQL sur le CRUD portmap — TEST OBLIGATOIRE
# ---------------------------------------------------------------------------


def test_create_mapping_stores_sql_injection_attempt_as_literal_string(
    db: sqlite3.Connection,
) -> None:
    malicious = "'; DROP TABLE port_mappings; --"
    create_mapping(db, port=9999, proto="tcp", application=malicious)

    # La table doit survivre.
    tables = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='port_mappings'"
    ).fetchall()
    assert len(tables) == 1

    stored = resolve_application(db, 9999, "tcp")
    assert stored == malicious


def test_delete_mapping_port_param_not_interpolated(db: sqlite3.Connection) -> None:
    create_mapping(db, port=9999, proto="tcp", application="Test App")
    delete_mapping(db, port=9999, proto="tcp")
    tables = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='port_mappings'"
    ).fetchall()
    assert len(tables) == 1
    assert resolve_application(db, 9999, "tcp") == "tcp/9999"


# ---------------------------------------------------------------------------
# CRUD basique
# ---------------------------------------------------------------------------


def test_create_and_list_mapping(db: sqlite3.Connection) -> None:
    create_mapping(db, port=12345, proto="tcp", application="Mon Service")
    mappings = list_mappings(db)
    assert any(m.port == 12345 and m.application == "Mon Service" for m in mappings)


def test_delete_mapping_removes_row(db: sqlite3.Connection) -> None:
    create_mapping(db, port=12345, proto="tcp", application="Mon Service")
    delete_mapping(db, port=12345, proto="tcp")
    mappings = list_mappings(db)
    assert not any(m.port == 12345 for m in mappings)


def test_create_mapping_upserts_existing_port_proto(db: sqlite3.Connection) -> None:
    create_mapping(db, port=12345, proto="tcp", application="Premier nom")
    create_mapping(db, port=12345, proto="tcp", application="Nom corrigé")
    mappings = [m for m in list_mappings(db) if m.port == 12345 and m.proto == "tcp"]
    assert len(mappings) == 1
    assert mappings[0].application == "Nom corrigé"


# ---------------------------------------------------------------------------
# Faux client ClickHouse respectant le Protocol du module `views`
# ---------------------------------------------------------------------------


class FakeClickHouseClient:
    """Faux client injecté dans les tests — respecte le `Protocol` ClickHouseClient."""

    def __init__(
        self,
        rows: list[tuple[Any, ...]] | None = None,
        columns: list[str] | None = None,
        raise_error: Exception | None = None,
        has_iptos: bool = False,
    ) -> None:
        self.rows = rows or []
        self.columns = columns or []
        self.raise_error = raise_error
        self.has_iptos = has_iptos
        self.last_query: str | None = None
        self.last_parameters: dict[str, Any] | None = None

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> Any:
        self.last_query = sql
        self.last_parameters = parameters
        if self.raise_error is not None:
            raise self.raise_error
        if "system.columns" in sql:
            if self.has_iptos:
                return _FakeResult([("IPTos",)], ["name"])
            return _FakeResult([], ["name"])
        return _FakeResult(self.rows, self.columns)


class _FakeResult:
    def __init__(self, result_rows: list[tuple[Any, ...]], column_names: list[str]) -> None:
        self.result_rows = result_rows
        self.column_names = column_names


# ---------------------------------------------------------------------------
# Construction des requêtes des 5 vues — paramètres, pas d'interpolation
# ---------------------------------------------------------------------------


def test_top_talkers_query_uses_parameters_not_interpolation() -> None:
    from app.routers.views import build_top_talkers_query

    sql, params = build_top_talkers_query(window="1h")
    assert "{interval:String}" in sql or "{window" in sql or "INTERVAL" in sql
    assert "1h" not in sql  # la valeur ne doit jamais apparaître littéralement dans le SQL
    assert isinstance(params, dict)


def test_services_volumetry_query_uses_parameters() -> None:
    from app.routers.views import build_services_volumetry_query

    sql, params = build_services_volumetry_query(window="24h")
    assert "24h" not in sql
    assert isinstance(params, dict)


def test_wan_vs_mesh_query_uses_parameters() -> None:
    from app.routers.views import build_wan_vs_mesh_query

    sql, params = build_wan_vs_mesh_query(window="6h")
    assert "6h" not in sql
    assert "InIfBoundary" in sql
    assert isinstance(params, dict)


def test_time_series_query_uses_parameters() -> None:
    from app.routers.views import build_time_series_query

    sql, params = build_time_series_query(window="7d")
    assert "7d" not in sql
    assert isinstance(params, dict)


def test_time_series_previous_period_window_shift_correct() -> None:
    from app.routers.views import compute_previous_period_bounds

    # Fenêtre "1h" décalée : la période précédente doit avoir la même durée
    # et se terminer exactement où commence la période courante.
    current_start, current_end, previous_start, previous_end = compute_previous_period_bounds("1h")
    current_duration = current_end - current_start
    previous_duration = previous_end - previous_start
    assert current_duration == previous_duration
    assert previous_end == current_start


def test_time_series_previous_period_window_shift_7d() -> None:
    from app.routers.views import compute_previous_period_bounds

    current_start, current_end, previous_start, previous_end = compute_previous_period_bounds("7d")
    assert (current_end - current_start) == (previous_end - previous_start)
    assert previous_end == current_start


def test_query_builders_never_interpolate_user_window_literal() -> None:
    """Aucune des fonctions de construction de requête n'accepte une fenêtre libre."""
    from app.routers.views import build_top_talkers_query

    with pytest.raises((ValueError, KeyError)):
        build_top_talkers_query(window="'; DROP TABLE flows; --")


# ---------------------------------------------------------------------------
# Vue QoS — colonne IPTos absente (TEST OBLIGATOIRE)
# ---------------------------------------------------------------------------


def test_qos_view_reports_unavailable_when_iptos_column_missing() -> None:
    from app.routers.views import get_qos_view

    client = FakeClickHouseClient(has_iptos=False)
    result = get_qos_view(client, window="1h")
    assert result["available"] is False
    assert "IPTos" in result["reason"]
    assert "enabled" in result["reason"] or "schema" in result["reason"].lower()


def test_qos_view_available_but_warns_about_tailscale_marking() -> None:
    from app.routers.views import get_qos_view

    client = FakeClickHouseClient(
        has_iptos=True,
        rows=[(0, 950_000_000, 9900), (46, 9_500_000, 100)],
        columns=["IPTos", "bytes", "flows"],
    )
    result = get_qos_view(client, window="1h")
    assert result["available"] is True
    assert "tailscale" in result["warning"].lower()


def test_qos_view_does_not_raise_when_client_errors_on_columns_check() -> None:
    from app.routers.views import get_qos_view

    client = FakeClickHouseClient(raise_error=RuntimeError("connection refused"))
    result = get_qos_view(client, window="1h")
    assert result["available"] is False


# ---------------------------------------------------------------------------
# Router FastAPI — TestClient avec client mocké
# ---------------------------------------------------------------------------


@pytest.fixture
def app_client(db: sqlite3.Connection, tmp_path: Any) -> TestClient:
    from fastapi import FastAPI

    from app.templating import build_templates

    seed_iana_defaults(db)

    app = FastAPI()
    templates = build_templates("app/templates")
    settings = Settings(akvorado_host="127.0.0.1")

    fake_ch = FakeClickHouseClient(
        rows=[
            ("::ffff:192.0.2.18", "::ffff:192.0.2.24", 123456, 42, 10),
        ],
        columns=["SrcAddr", "DstAddr", "bytes", "packets", "flows"],
    )

    app.dependency_overrides[views_router.get_db_connection] = lambda: db
    app.dependency_overrides[views_router.get_clickhouse_client] = lambda: fake_ch
    app.dependency_overrides[views_router.get_settings] = lambda: settings
    app.dependency_overrides[views_router.get_templates] = lambda: templates
    app.include_router(views_router.router)
    return TestClient(app)


def test_get_views_page_returns_200(app_client: TestClient) -> None:
    response = app_client.get("/views")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_api_view_talkers_returns_200_with_structure(app_client: TestClient) -> None:
    response = app_client.get("/api/views/talkers")
    assert response.status_code == 200
    payload = response.json()
    assert "items" in payload
    assert "total" in payload


def test_api_view_services_returns_200(app_client: TestClient) -> None:
    response = app_client.get("/api/views/services")
    assert response.status_code == 200
    payload = response.json()
    assert "items" in payload
    assert "total" in payload


def test_api_view_boundary_returns_200(app_client: TestClient) -> None:
    response = app_client.get("/api/views/boundary")
    assert response.status_code == 200


def test_api_view_timeseries_returns_200(app_client: TestClient) -> None:
    response = app_client.get("/api/views/timeseries")
    assert response.status_code == 200


def test_api_view_qos_returns_200(app_client: TestClient) -> None:
    response = app_client.get("/api/views/qos")
    assert response.status_code == 200
    payload = response.json()
    assert "available" in payload


def test_api_view_unknown_name_returns_404_or_422(app_client: TestClient) -> None:
    response = app_client.get("/api/views/does-not-exist")
    assert response.status_code in (404, 422)


def test_api_view_invalid_window_rejected(app_client: TestClient) -> None:
    response = app_client.get("/api/views/talkers?window=5m")
    assert response.status_code == 422


def test_clickhouse_error_returns_clean_message_not_500(app_client: TestClient, db: Any) -> None:
    from fastapi import FastAPI

    from app.templating import build_templates

    app = FastAPI()
    templates = build_templates("app/templates")
    settings = Settings(akvorado_host="127.0.0.1")
    broken_client = FakeClickHouseClient(raise_error=ConnectionError("clickhouse unreachable"))

    app.dependency_overrides[views_router.get_db_connection] = lambda: db
    app.dependency_overrides[views_router.get_clickhouse_client] = lambda: broken_client
    app.dependency_overrides[views_router.get_settings] = lambda: settings
    app.dependency_overrides[views_router.get_templates] = lambda: templates
    app.include_router(views_router.router)
    client = TestClient(app)

    response = client.get("/api/views/talkers")
    assert response.status_code in (200, 502, 503)
    if response.status_code == 200:
        payload = response.json()
        assert "error" in payload or payload.get("items") == []
    else:
        payload = response.json()
        assert "error" in payload or "detail" in payload


# ---------------------------------------------------------------------------
# CRUD port-mappings via le router
# ---------------------------------------------------------------------------


def test_get_api_portmap_returns_items(app_client: TestClient) -> None:
    response = app_client.get("/api/portmap")
    assert response.status_code == 200
    payload = response.json()
    assert "items" in payload
    assert payload["total"] >= 40


def test_post_api_portmap_creates_mapping(app_client: TestClient) -> None:
    response = app_client.post(
        "/api/portmap",
        json={"port": 54321, "proto": "tcp", "application": "Mon App"},
    )
    assert response.status_code in (200, 201)
    listing = app_client.get("/api/portmap").json()
    assert any(
        item["port"] == 54321 and item["application"] == "Mon App" for item in listing["items"]
    )


def test_post_api_portmap_invalid_port_returns_422(app_client: TestClient) -> None:
    response = app_client.post(
        "/api/portmap",
        json={"port": 70000, "proto": "tcp", "application": "X"},
    )
    assert response.status_code == 422


def test_post_api_portmap_invalid_proto_returns_422(app_client: TestClient) -> None:
    response = app_client.post(
        "/api/portmap",
        json={"port": 8080, "proto": "sctp", "application": "X"},
    )
    assert response.status_code == 422


def test_post_api_portmap_empty_application_returns_422(app_client: TestClient) -> None:
    response = app_client.post(
        "/api/portmap",
        json={"port": 8080, "proto": "tcp", "application": ""},
    )
    assert response.status_code == 422


def test_delete_api_portmap_removes_mapping(app_client: TestClient) -> None:
    app_client.post(
        "/api/portmap",
        json={"port": 54322, "proto": "udp", "application": "Éphémère"},
    )
    response = app_client.delete("/api/portmap/54322/udp")
    assert response.status_code in (200, 204)
    listing = app_client.get("/api/portmap").json()
    assert not any(item["port"] == 54322 for item in listing["items"])


# ---------------------------------------------------------------------------
# Rendu du template sans exception
# ---------------------------------------------------------------------------


def test_views_template_renders_without_exception() -> None:
    from starlette.requests import Request

    from app.templating import build_templates

    templates = build_templates("app/templates")
    scope: dict[str, object] = {
        "type": "http",
        "method": "GET",
        "path": "/views",
        "headers": [],
        "query_string": b"",
        "server": ("test", 80),
        "scheme": "http",
        "root_path": "",
        "client": ("test", 123),
        "app": None,
    }
    request = Request(scope)

    context = {
        "request": request,
        "active_page": "views",
        "akvorado_url": "http://192.0.2.6:8082",
        "window_choices": ["1h", "6h", "24h", "7d"],
        "current_window": "1h",
        "akvorado_console_url": "http://192.0.2.6:8082",
        "port_mappings": [],
        "qos_available": False,
        "qos_reason": "colonne IPTos absente du schéma",
    }
    html = templates.get_template("views.html").render(context)
    assert "Vues métier" in html  # rendu via base.html, titre présent
    assert "qui parle à qui" in html.lower()
