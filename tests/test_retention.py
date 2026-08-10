"""Tests du module Rétention (LOT 2) — TDD, aucune infra requise.

Toutes les fixtures sont en dur. Le client ClickHouse est mocké via le
Protocol `ClickHouseQueryable` défini dans `app.services.retention`.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.db import SCHEMA
from app.models import AppliedTtl, TableRetention
from app.services.purge import PURGEABLE_TABLES
from app.services.retention import (
    ALLOWED_TABLES,
    MAX_TTL_DAYS,
    apply_ttl,
    build_ttl_alter_statement,
    compute_growth_rate,
    estimate_purge_impact,
    format_bytes,
    load_retention_status,
    parse_ttl_seconds,
    project_disk_usage,
)

# ---------------------------------------------------------------------------
# Fixtures en dur — reflètent CONTRACT.md (état mesuré 2026-08-04/05)
# ---------------------------------------------------------------------------

FLOWS_BYTES = 400 * 1024 * 1024  # ~400 MiB
FLOWS_ROWS = 123_456_789
TTL_15D_SECONDS = 1_296_000


class FakeClickHouseClient:
    """Double de test implémentant le Protocol ClickHouseQueryable."""

    def __init__(self, tables_result: list[tuple[Any, ...]], parts_result: list[tuple[Any, ...]]):
        self._tables_result = tables_result
        self._parts_result = parts_result
        self.queries: list[tuple[str, dict[str, Any] | None]] = []

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> list[tuple[Any, ...]]:
        self.queries.append((sql, parameters))
        if "system.tables" in sql:
            return self._tables_result
        if "system.parts" in sql:
            return self._parts_result
        return []


# ---------------------------------------------------------------------------
# Parsing de l'expression TTL
# ---------------------------------------------------------------------------


class TestParseTtlSecondsRealEngineFull:
    """Regression : le `engine_full` REEL contient des toInterval AVANT le TTL.

    Defaut vecu (2026-08-05) : un search() naif attrapait le toIntervalSecond du
    PARTITION BY (25920 = 0,3 jour) au lieu de celui du TTL (1296000 = 15 jours).
    Les fixtures precedentes ne contenaient que le fragment TTL, jamais la chaine
    complete — d'ou un test vert sur un code faux.
    """

    REAL_FLOWS_ENGINE_FULL = (
        "MergeTree PARTITION BY toYYYYMMDDhhmmss(toStartOfInterval(TimeReceived, "
        "toIntervalSecond(25920))) PRIMARY KEY toStartOfFiveMinutes(TimeReceived) "
        "ORDER BY (toStartOfFiveMinutes(TimeReceived), ExporterAddress, InIfName, "
        "OutIfName) TTL TimeReceived + toIntervalSecond(1296000) SETTINGS "
        "index_granularity = 8192"
    )

    REAL_AGG_ENGINE_FULL = (
        "SummingMergeTree PARTITION BY toYYYYMMDDhhmmss(toStartOfInterval("
        "TimeReceived, toIntervalSecond(518400))) ORDER BY (TimeReceived, "
        "ExporterAddress) TTL TimeReceived + toIntervalSecond(31104000) SETTINGS "
        "index_granularity = 8192"
    )

    def test_flows_ttl_is_retention_not_partition(self) -> None:
        assert parse_ttl_seconds(self.REAL_FLOWS_ENGINE_FULL) == 1_296_000

    def test_flows_ttl_in_days_is_15(self) -> None:
        seconds = parse_ttl_seconds(self.REAL_FLOWS_ENGINE_FULL)
        assert seconds is not None
        assert seconds / 86400 == 15.0

    def test_aggregate_ttl_is_retention_not_partition(self) -> None:
        assert parse_ttl_seconds(self.REAL_AGG_ENGINE_FULL) == 31_104_000

    def test_engine_full_without_ttl_returns_none(self) -> None:
        engine = (
            "MergeTree PARTITION BY toStartOfInterval(TimeReceived, "
            "toIntervalSecond(25920)) ORDER BY TimeReceived SETTINGS x = 1"
        )
        assert parse_ttl_seconds(engine) is None


class TestParseTtlSeconds:
    def test_toIntervalSecond(self) -> None:
        assert parse_ttl_seconds("TimeReceived + toIntervalSecond(1296000)") == 1_296_000

    def test_toIntervalDay(self) -> None:
        assert parse_ttl_seconds("TimeReceived + toIntervalDay(15)") == 15 * 86400

    def test_toIntervalMinute(self) -> None:
        assert parse_ttl_seconds("TimeReceived + toIntervalMinute(30)") == 30 * 60

    def test_toIntervalHour(self) -> None:
        assert parse_ttl_seconds("TimeReceived + toIntervalHour(2)") == 2 * 3600

    def test_toIntervalWeek(self) -> None:
        assert parse_ttl_seconds("TimeReceived + toIntervalWeek(1)") == 7 * 86400

    def test_interval_keyword_second(self) -> None:
        assert parse_ttl_seconds("TimeReceived + INTERVAL 1296000 SECOND") == 1_296_000

    def test_interval_keyword_day(self) -> None:
        assert parse_ttl_seconds("TimeReceived + INTERVAL 15 DAY") == 15 * 86400

    def test_interval_keyword_lowercase(self) -> None:
        assert parse_ttl_seconds("TimeReceived + interval 15 day") == 15 * 86400

    def test_empty_string(self) -> None:
        assert parse_ttl_seconds("") is None

    def test_none_like_whitespace(self) -> None:
        assert parse_ttl_seconds("   ") is None

    def test_unknown_expression_no_exception(self) -> None:
        assert parse_ttl_seconds("some garbage TTL expr $$$") is None

    def test_unrecognized_unit_no_exception(self) -> None:
        assert parse_ttl_seconds("TimeReceived + toIntervalFortnight(3)") is None


# ---------------------------------------------------------------------------
# load_retention_status
# ---------------------------------------------------------------------------


class TestLoadRetentionStatus:
    def test_builds_table_retention_list(self) -> None:
        tables_result = [
            ("flows", "MergeTree", "TimeReceived + toIntervalSecond(1296000)"),
            ("flows_1m0s", "SummingMergeTree", "TimeReceived + toIntervalSecond(1296000)"),
        ]
        parts_result = [
            ("flows", FLOWS_BYTES, FLOWS_ROWS),
            ("flows_1m0s", 21 * 1024 * 1024, 1_000_000),
        ]
        client = FakeClickHouseClient(tables_result, parts_result)

        result = load_retention_status(client)

        assert len(result) == 2
        assert all(isinstance(item, TableRetention) for item in result)
        flows = next(item for item in result if item.table == "flows")
        assert flows.ttl_seconds == TTL_15D_SECONDS
        assert flows.bytes_on_disk == FLOWS_BYTES
        assert flows.rows == FLOWS_ROWS
        assert flows.engine == "MergeTree"

    def test_table_without_parts_defaults_to_zero(self) -> None:
        tables_result = [
            ("flows_1h0m0s", "SummingMergeTree", "TimeReceived + toIntervalSecond(1296000)")
        ]
        parts_result: list[tuple[Any, ...]] = []
        client = FakeClickHouseClient(tables_result, parts_result)

        result = load_retention_status(client)

        assert len(result) == 1
        assert result[0].bytes_on_disk == 0
        assert result[0].rows == 0

    def test_unparseable_ttl_yields_none_not_exception(self) -> None:
        tables_result = [("flows", "MergeTree", "garbage expr")]
        parts_result = [("flows", 100, 10)]
        client = FakeClickHouseClient(tables_result, parts_result)

        result = load_retention_status(client)

        assert result[0].ttl_seconds is None

    def test_uses_read_only_queries(self) -> None:
        client = FakeClickHouseClient([], [])
        load_retention_status(client)
        for sql, _ in client.queries:
            upper = sql.upper()
            assert "ALTER" not in upper
            assert "DROP" not in upper
            assert "DELETE" not in upper
            assert "INSERT" not in upper


# ---------------------------------------------------------------------------
# compute_growth_rate
# ---------------------------------------------------------------------------


class TestComputeGrowthRate:
    def test_stationary_regime_15_days(self) -> None:
        # 400 MiB / 15 j
        rate = compute_growth_rate(bytes_on_disk=FLOWS_BYTES, ttl_seconds=TTL_15D_SECONDS)
        assert rate == pytest.approx(FLOWS_BYTES / 15, rel=1e-6)

    def test_ttl_none_returns_none(self) -> None:
        assert compute_growth_rate(bytes_on_disk=FLOWS_BYTES, ttl_seconds=None) is None

    def test_ttl_zero_returns_none(self) -> None:
        assert compute_growth_rate(bytes_on_disk=FLOWS_BYTES, ttl_seconds=0) is None

    def test_zero_bytes_zero_growth(self) -> None:
        assert compute_growth_rate(bytes_on_disk=0, ttl_seconds=TTL_15D_SECONDS) == 0


# ---------------------------------------------------------------------------
# project_disk_usage — fonction pure
# ---------------------------------------------------------------------------


class TestProjectDiskUsage:
    def test_nominal_projection(self) -> None:
        growth_per_day = FLOWS_BYTES / 15
        projected = project_disk_usage("flows", new_ttl_days=30, growth_per_day=growth_per_day)
        assert projected == pytest.approx(growth_per_day * 30, rel=1e-6)

    def test_ttl_zero_gives_zero(self) -> None:
        assert project_disk_usage("flows", new_ttl_days=0, growth_per_day=1000.0) == 0

    def test_huge_ttl(self) -> None:
        growth_per_day = 1000.0
        projected = project_disk_usage("flows", new_ttl_days=3650, growth_per_day=growth_per_day)
        assert projected == pytest.approx(3650 * 1000.0, rel=1e-6)

    def test_zero_growth_gives_zero(self) -> None:
        assert project_disk_usage("flows", new_ttl_days=100, growth_per_day=0.0) == 0

    def test_negative_ttl_raises(self) -> None:
        with pytest.raises(ValueError):
            project_disk_usage("flows", new_ttl_days=-1, growth_per_day=1000.0)


# ---------------------------------------------------------------------------
# build_ttl_alter_statement — garde sécu critique
# ---------------------------------------------------------------------------


class TestBuildTtlAlterStatement:
    @pytest.mark.parametrize("table", sorted(ALLOWED_TABLES))
    def test_allowed_tables_produce_statement(self, table: str) -> None:
        stmt = build_ttl_alter_statement(table, ttl_days=30)
        assert table in stmt
        assert "ALTER TABLE" in stmt
        assert "MODIFY TTL" in stmt
        assert "30" in stmt

    def test_table_outside_allowlist_raises(self) -> None:
        with pytest.raises(ValueError):
            build_ttl_alter_statement("exporters", ttl_days=30)

    def test_sql_injection_attempt_raises(self) -> None:
        with pytest.raises(ValueError):
            build_ttl_alter_statement("flows; DROP TABLE x", ttl_days=30)

    def test_sql_injection_via_comment_raises(self) -> None:
        with pytest.raises(ValueError):
            build_ttl_alter_statement("flows -- comment", ttl_days=30)

    def test_path_traversal_like_name_raises(self) -> None:
        with pytest.raises(ValueError):
            build_ttl_alter_statement("../../etc/passwd", ttl_days=30)

    def test_unicode_lookalike_raises(self) -> None:
        with pytest.raises(ValueError):
            build_ttl_alter_statement("flоws", ttl_days=30)  # 'о' cyrillique

    def test_empty_table_raises(self) -> None:
        with pytest.raises(ValueError):
            build_ttl_alter_statement("", ttl_days=30)

    def test_negative_ttl_days_raises(self) -> None:
        with pytest.raises(ValueError):
            build_ttl_alter_statement("flows", ttl_days=-1)

    def test_zero_ttl_days_raises(self) -> None:
        with pytest.raises(ValueError):
            build_ttl_alter_statement("flows", ttl_days=0)

    def test_huge_ttl_days_raises(self) -> None:
        with pytest.raises(ValueError):
            build_ttl_alter_statement("flows", ttl_days=999_999)

    def test_upper_bound_accepted(self) -> None:
        stmt = build_ttl_alter_statement("flows", ttl_days=3650)
        assert "3650" in stmt

    def test_non_int_like_injection_in_ttl_days_type_rejected(self) -> None:
        # Le type-hint impose int ; on vérifie le comportement runtime si un
        # bool (sous-type d'int en Python) ou une valeur limite est fournie.
        with pytest.raises(ValueError):
            build_ttl_alter_statement("flows", ttl_days=3651)


# ---------------------------------------------------------------------------
# estimate_purge_impact
# ---------------------------------------------------------------------------


class TestEstimatePurgeImpact:
    def test_lowering_ttl_purges_data(self) -> None:
        growth_per_day = FLOWS_BYTES / 15
        purged = estimate_purge_impact(
            current_ttl_days=15,
            new_ttl_days=7,
            bytes_on_disk=FLOWS_BYTES,
            growth_per_day=growth_per_day,
        )
        assert purged is not None
        assert purged == pytest.approx(growth_per_day * (15 - 7), rel=1e-6)
        assert purged > 0

    def test_raising_ttl_purges_nothing(self) -> None:
        growth_per_day = FLOWS_BYTES / 15
        purged = estimate_purge_impact(
            current_ttl_days=15,
            new_ttl_days=30,
            bytes_on_disk=FLOWS_BYTES,
            growth_per_day=growth_per_day,
        )
        assert purged == 0

    def test_equal_ttl_purges_nothing(self) -> None:
        growth_per_day = FLOWS_BYTES / 15
        purged = estimate_purge_impact(
            current_ttl_days=15,
            new_ttl_days=15,
            bytes_on_disk=FLOWS_BYTES,
            growth_per_day=growth_per_day,
        )
        assert purged == 0

    def test_current_ttl_none_returns_none(self) -> None:
        purged = estimate_purge_impact(
            current_ttl_days=None,
            new_ttl_days=7,
            bytes_on_disk=FLOWS_BYTES,
            growth_per_day=1000.0,
        )
        assert purged is None


# ---------------------------------------------------------------------------
# Projection 180 jours (6 mois) — dérivée du calcul, pas recopiée en dur
# ---------------------------------------------------------------------------


class TestProjection180Days:
    def test_max_ttl_days_covers_180_without_change(self) -> None:
        assert 180 <= MAX_TTL_DAYS

    def test_flows_projection_at_180_days_derived_from_growth_rate(self) -> None:
        # Le nombre attendu est DÉRIVÉ de compute_growth_rate, pas recopié :
        # 400 MiB / 15 j de croissance mesurée, extrapolé à 180 j.
        growth_per_day = compute_growth_rate(bytes_on_disk=FLOWS_BYTES, ttl_seconds=TTL_15D_SECONDS)
        assert growth_per_day is not None

        projected = project_disk_usage("flows", new_ttl_days=180, growth_per_day=growth_per_day)

        expected = (FLOWS_BYTES / 15) * 180  # dérivé, pas une constante en dur
        assert projected == pytest.approx(expected, rel=1e-9)
        # Sanité métier : 180j / 15j = 12x le volume actuel (~4,7 Go).
        assert projected == pytest.approx(FLOWS_BYTES * 12, rel=1e-9)

    def test_flows_projection_at_180_days_via_full_pipeline_from_fake_client(self) -> None:
        # Bout en bout : system.tables/system.parts -> load_retention_status
        # -> compute_growth_rate -> project_disk_usage, sans aucune constante
        # recopiée depuis l'énoncé.
        tables_result = [("flows", "MergeTree", "TimeReceived + toIntervalSecond(1296000)")]
        parts_result = [("flows", FLOWS_BYTES, FLOWS_ROWS)]
        client = FakeClickHouseClient(tables_result, parts_result)

        items = load_retention_status(client)
        flows = next(item for item in items if item.table == "flows")
        growth_per_day = compute_growth_rate(flows.bytes_on_disk, flows.ttl_seconds)
        assert growth_per_day is not None

        projected = project_disk_usage("flows", new_ttl_days=180, growth_per_day=growth_per_day)

        expected = (flows.bytes_on_disk / 15) * 180
        assert projected == pytest.approx(expected, rel=1e-9)


# ---------------------------------------------------------------------------
# apply_ttl — exécution réelle (v2), garde sécu AVANT tout accès ClickHouse
# ---------------------------------------------------------------------------


class TestApplyTtl:
    def test_out_of_bounds_ttl_raises_before_any_query(self) -> None:
        client = FakeClickHouseClient([], [])

        with pytest.raises(ValueError):
            apply_ttl(client, "flows", ttl_days=4000)

        alter_queries = [sql for sql, _ in client.queries if "ALTER" in sql.upper()]
        assert alter_queries == []
        assert client.queries == []  # aucun accès ClickHouse du tout

    def test_table_outside_allowlist_raises_before_any_query(self) -> None:
        client = FakeClickHouseClient([], [])

        with pytest.raises(ValueError):
            apply_ttl(client, "exporters", ttl_days=30)

        alter_queries = [sql for sql, _ in client.queries if "ALTER" in sql.upper()]
        assert alter_queries == []
        assert client.queries == []

    def test_valid_call_executes_exact_sql_and_returns_applied_ttl(self) -> None:
        client = FakeClickHouseClient([], [])
        expected_sql = build_ttl_alter_statement("flows", ttl_days=30)

        result = apply_ttl(client, "flows", ttl_days=30)

        assert isinstance(result, AppliedTtl)
        assert result.table == "flows"
        assert result.ttl_days == 30
        assert result.sql_statement == expected_sql
        assert client.queries == [(expected_sql, None)]
        assert result.applied_at is not None

    def test_client_failure_is_logged_before_propagating(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        class BrokenClient:
            def __init__(self) -> None:
                self.queries: list[tuple[str, dict[str, Any] | None]] = []

            def query(
                self, sql: str, parameters: dict[str, Any] | None = None
            ) -> list[tuple[Any, ...]]:
                self.queries.append((sql, parameters))
                raise ConnectionError("clickhouse unreachable")

        client = BrokenClient()

        with caplog.at_level("ERROR"):
            with pytest.raises(ConnectionError):
                apply_ttl(client, "flows", ttl_days=30)  # type: ignore[arg-type]

        assert any(record.levelname == "ERROR" for record in caplog.records)


# ---------------------------------------------------------------------------
# format_bytes
# ---------------------------------------------------------------------------


class TestFormatBytes:
    def test_bytes(self) -> None:
        assert format_bytes(500) == "500 o"

    def test_kilobytes(self) -> None:
        assert format_bytes(828 * 1024) == "828,0 Ko"

    def test_megabytes(self) -> None:
        result = format_bytes(400 * 1024 * 1024)
        assert "Mo" in result
        assert result.startswith("400")

    def test_gigabytes(self) -> None:
        result = format_bytes(int(3.5 * 1024**3))
        assert "Go" in result
        assert result.startswith("3,5")

    def test_zero(self) -> None:
        assert format_bytes(0) == "0 o"


# ---------------------------------------------------------------------------
# Router — TestClient avec client ClickHouse mocké
# ---------------------------------------------------------------------------


def _memory_conn() -> sqlite3.Connection:
    # `check_same_thread=False` : le TestClient de FastAPI/Starlette exécute
    # les requêtes dans un threadpool, alors que cette connexion est créée
    # dans le thread du test — sans ce paramètre, sqlite3 refuse l'accès
    # cross-thread (`ProgrammingError`). Sûr ici : un seul test, un seul
    # accès séquentiel (jamais deux requêtes concurrentes sur la même connexion).
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _make_app_with_fake_client(
    client: FakeClickHouseClient,
    *,
    conn: sqlite3.Connection | None = None,
    backup_directory: Path | None = None,
) -> TestClient:
    from fastapi import FastAPI

    from app.routers import retention as retention_router

    app = FastAPI()
    app.dependency_overrides[retention_router.get_clickhouse_client] = lambda: client
    app.dependency_overrides[retention_router.get_db_connection] = lambda: (
        conn if conn is not None else _memory_conn()
    )
    app.dependency_overrides[retention_router.get_backup_directory] = lambda: (
        backup_directory if backup_directory is not None else Path("/tmp")
    )
    app.include_router(retention_router.router)
    return TestClient(app)


class TestRetentionRouter:
    def _fake_client(self) -> FakeClickHouseClient:
        tables_result = [
            ("flows", "MergeTree", "TimeReceived + toIntervalSecond(1296000)"),
            ("flows_1m0s", "SummingMergeTree", "TimeReceived + toIntervalSecond(1296000)"),
            ("flows_5m0s", "SummingMergeTree", "TimeReceived + toIntervalSecond(1296000)"),
            ("flows_1h0m0s", "SummingMergeTree", "TimeReceived + toIntervalSecond(1296000)"),
        ]
        parts_result = [
            ("flows", FLOWS_BYTES, FLOWS_ROWS),
            ("flows_1m0s", 21 * 1024 * 1024, 1_000_000),
            ("flows_5m0s", 6 * 1024 * 1024, 200_000),
            ("flows_1h0m0s", 828 * 1024, 10_000),
        ]
        return FakeClickHouseClient(tables_result, parts_result)

    def test_get_api_retention_returns_items_and_total(self) -> None:
        client = self._fake_client()
        http_client = _make_app_with_fake_client(client)

        response = http_client.get("/api/retention")

        assert response.status_code == 200
        payload = response.json()
        assert "items" in payload
        assert "total" in payload
        assert payload["total"] == 4
        assert len(payload["items"]) == 4

    def test_get_retention_html_page(self) -> None:
        client = self._fake_client()
        http_client = _make_app_with_fake_client(client)

        response = http_client.get("/retention")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_preview_valid_table(self) -> None:
        client = self._fake_client()
        http_client = _make_app_with_fake_client(client)

        response = http_client.post(
            "/api/retention/preview", json={"table": "flows", "ttl_days": 30}
        )

        assert response.status_code == 200
        payload = response.json()
        assert "sql_statement" in payload
        assert "projected_bytes" in payload
        assert "purged_bytes" in payload

    def test_preview_invalid_table_returns_422(self) -> None:
        client = self._fake_client()
        http_client = _make_app_with_fake_client(client)

        response = http_client.post(
            "/api/retention/preview", json={"table": "exporters", "ttl_days": 30}
        )

        assert response.status_code == 422

    def test_preview_ttl_days_out_of_bounds_returns_422(self) -> None:
        client = self._fake_client()
        http_client = _make_app_with_fake_client(client)

        response = http_client.post(
            "/api/retention/preview", json={"table": "flows", "ttl_days": -5}
        )

        assert response.status_code == 422

    def test_preview_does_not_mutate_clickhouse(self) -> None:
        client = self._fake_client()
        http_client = _make_app_with_fake_client(client)

        http_client.post("/api/retention/preview", json={"table": "flows", "ttl_days": 7})

        for sql, _ in client.queries:
            upper = sql.upper()
            assert "ALTER" not in upper
            assert "DROP" not in upper

    def test_clickhouse_unreachable_returns_clean_error(self) -> None:
        class BrokenClient:
            def query(
                self, sql: str, parameters: dict[str, Any] | None = None
            ) -> list[tuple[Any, ...]]:
                raise ConnectionError("clickhouse unreachable")

        http_client = _make_app_with_fake_client(BrokenClient())  # type: ignore[arg-type]

        response = http_client.get("/api/retention")

        assert response.status_code != 500 or response.json().get("error") is not None
        payload = response.json()
        assert "error" in payload


# ---------------------------------------------------------------------------
# Template — rendu sans exception
# ---------------------------------------------------------------------------


class TestRetentionTemplate:
    def _render(self, items: list[TableRetention]) -> str:
        templates_dir = "app/templates"
        # Passer par la FABRIQUE de l'application, pas par un Environment nu.
        # DÉFAUT MESURÉ (2026-08-08) : un `Environment(...)` construit ici à la
        # main n'enregistre AUCUN filtre applicatif — l'ajout du filtre
        # `prefixed` (support du proxy Grafana) a fait échouer ce test avec
        # « No filter named 'prefixed' », alors que l'application, elle,
        # fonctionnait. Un moteur de test qui diverge du moteur de production
        # ne teste pas la production : il teste une fiction.
        from app.templating import build_templates

        env = build_templates(templates_dir).env
        # base.html [LOT 0] peut ne pas encore exister : on fournit un stub
        # minimal si absent pour ne pas dépendre d'un autre lot dans ce test.
        import os

        base_path = os.path.join(templates_dir, "base.html")
        if not os.path.exists(base_path):
            with open(base_path, "w") as fh:
                fh.write(
                    "<html><head><title>{% block title %}{% endblock %}</title></head>"
                    "<body>{% block content %}{% endblock %}</body></html>"
                )
        template = env.get_template("retention.html")
        return template.render(
            items=items,
            disk_used_bytes=int(3.5 * 1024**3),
            disk_total_bytes=125 * 1024**3,
            format_bytes=format_bytes,
            projection_days=180,
            projection_rows=[
                {
                    "table": item.table,
                    "current_bytes": item.bytes_on_disk,
                    "projected_bytes": None,
                }
                for item in items
            ],
            settings={},
            docker_log_max_size="10m",
            docker_log_max_file="3",
            purgeable_tables=sorted(PURGEABLE_TABLES),
        )

    def test_renders_without_exception(self) -> None:
        items = [
            TableRetention(
                table="flows",
                engine="MergeTree",
                ttl_seconds=TTL_15D_SECONDS,
                bytes_on_disk=FLOWS_BYTES,
                rows=FLOWS_ROWS,
            ),
        ]
        html = self._render(items)
        assert "flows" in html

    def test_renders_recommendation_text(self) -> None:
        items = [
            TableRetention(
                table="flows_1h0m0s",
                engine="SummingMergeTree",
                ttl_seconds=TTL_15D_SECONDS,
                bytes_on_disk=828 * 1024,
                rows=10_000,
            ),
        ]
        html = self._render(items)
        assert "1 an" in html or "365" in html


# ---------------------------------------------------------------------------
# Template — rendu via le VRAI routeur (settings/projection/purge injectés)
# ---------------------------------------------------------------------------


class TestRetentionTemplateFullContext:
    """Contrairement à `TestRetentionTemplate` (rendu Jinja isolé, contexte à
    la main), cette classe passe par le routeur réel + `TestClient` : c'est ce
    qui prouve que `get_retention()` construit bien un contexte que le
    template consomme sans exception, avec les 4 nouvelles sections.
    """

    def _fake_client(self) -> FakeClickHouseClient:
        tables_result = [("flows", "MergeTree", "TimeReceived + toIntervalSecond(1296000)")]
        parts_result = [("flows", FLOWS_BYTES, FLOWS_ROWS)]
        return FakeClickHouseClient(tables_result, parts_result)

    def test_page_renders_all_new_sections(self) -> None:
        client = self._fake_client()
        http_client = _make_app_with_fake_client(client)

        response = http_client.get("/retention")

        assert response.status_code == 200
        html = response.text
        assert "Occupation projetée à 180 jours" in html
        assert "Logs Docker" in html
        assert "Sauvegardes de configuration" in html
        assert "Historique interne" in html
        for table in sorted(PURGEABLE_TABLES):
            assert table in html

    @pytest.mark.parametrize(
        "template_name",
        ["retention.html", "_purge_preview_fragment.html"],
    )
    def test_page_no_onclick_attribute_csp(self, template_name: str) -> None:
        """CSP stricte (`script-src 'self'` sans `unsafe-inline`) : aucun
        `onclick=` ne doit apparaître dans le HTML rendu, sur AUCUN gabarit
        servi par ce module — y compris le fragment de confirmation de purge,
        pas seulement la page principale. Les commentaires Jinja `{# ... #}`
        sont retirés avant le grep — ce module documente volontairement la
        règle CSP en langage naturel, jamais avec la chaîne littérale
        interdite, précisément pour ne jamais faire mordre ce test sur sa
        propre documentation (piège vécu : `_purge_preview_fragment.html`
        mentionne `onclick=` dans son commentaire d'explication CSP).
        """
        template_path = Path("app/templates") / template_name
        raw = template_path.read_text(encoding="utf-8")
        import re

        without_comments = re.sub(r"\{#.*?#\}", "", raw, flags=re.DOTALL)
        assert "onclick=" not in without_comments


# ---------------------------------------------------------------------------
# POST /api/retention/apply — application réelle du TTL (v2)
# ---------------------------------------------------------------------------


class TestApplyRetentionRouter:
    def _fake_client(self) -> FakeClickHouseClient:
        tables_result = [("flows", "MergeTree", "TimeReceived + toIntervalSecond(1296000)")]
        parts_result = [("flows", FLOWS_BYTES, FLOWS_ROWS)]
        return FakeClickHouseClient(tables_result, parts_result)

    def test_apply_valid_table_and_ttl_returns_200(self) -> None:
        client = self._fake_client()
        http_client = _make_app_with_fake_client(client)

        response = http_client.post("/api/retention/apply", json={"table": "flows", "ttl_days": 30})

        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "ok"
        assert payload["table"] == "flows"
        assert payload["ttl_days"] == 30
        assert "applied_at" in payload
        assert "sql_statement" in payload
        # apply_ttl() a bien exécuté l'ALTER contre le client mocké.
        alter_queries = [sql for sql, _ in client.queries if "ALTER" in sql.upper()]
        assert len(alter_queries) == 1

    def test_apply_table_outside_allowlist_returns_400_and_does_not_query(self) -> None:
        client = self._fake_client()
        http_client = _make_app_with_fake_client(client)

        response = http_client.post(
            "/api/retention/apply", json={"table": "exporters", "ttl_days": 30}
        )

        assert response.status_code in (400, 422)
        # Preuve de morsure : aucune requête ClickHouse n'a été émise, allowlist
        # ou bornes hors limite doivent refuser AVANT tout accès réseau.
        assert client.queries == []

    def test_apply_ttl_days_out_of_bounds_returns_400_and_does_not_query(self) -> None:
        client = self._fake_client()
        http_client = _make_app_with_fake_client(client)

        response = http_client.post(
            "/api/retention/apply", json={"table": "flows", "ttl_days": 5000}
        )

        assert response.status_code in (400, 422)
        assert client.queries == []

    def test_apply_clickhouse_failure_returns_502(self) -> None:
        class BrokenClient:
            def __init__(self) -> None:
                self.queries: list[tuple[str, dict[str, Any] | None]] = []

            def query(
                self, sql: str, parameters: dict[str, Any] | None = None
            ) -> list[tuple[Any, ...]]:
                self.queries.append((sql, parameters))
                raise ConnectionError("clickhouse unreachable")

        http_client = _make_app_with_fake_client(BrokenClient())  # type: ignore[arg-type]

        response = http_client.post("/api/retention/apply", json={"table": "flows", "ttl_days": 30})

        assert response.status_code == 502
        assert "error" in response.json()

    def test_apply_writes_audit_log_entry(self) -> None:
        client = self._fake_client()
        conn = _memory_conn()
        http_client = _make_app_with_fake_client(client, conn=conn)

        response = http_client.post("/api/retention/apply", json={"table": "flows", "ttl_days": 45})

        assert response.status_code == 200
        rows = conn.execute(
            "SELECT action, detail FROM audit_log WHERE action = 'retention_apply_ttl'"
        ).fetchall()
        assert len(rows) == 1
        assert "flows" in rows[0][1]
        assert "45" in rows[0][1]


# ---------------------------------------------------------------------------
# GET/POST /api/retention/settings
# ---------------------------------------------------------------------------


class TestRetentionSettingsRouter:
    def _fake_client(self) -> FakeClickHouseClient:
        return FakeClickHouseClient([], [])

    def test_get_settings_empty_returns_empty_items(self) -> None:
        http_client = _make_app_with_fake_client(self._fake_client())

        response = http_client.get("/api/retention/settings")

        assert response.status_code == 200
        assert response.json() == {"items": {}}

    def test_post_settings_upserts_only_provided_fields(self) -> None:
        client = self._fake_client()
        conn = _memory_conn()
        http_client = _make_app_with_fake_client(client, conn=conn)

        response = http_client.post(
            "/api/retention/settings",
            json={"docker_log_max_size_mb": 20, "backup_keep_n": 5},
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "ok"
        assert set(payload["updated"]) == {"docker_log_max_size_mb", "backup_keep_n"}

        get_response = http_client.get("/api/retention/settings")
        items = get_response.json()["items"]
        assert items["docker_log_max_size_mb"] == "20"
        assert items["backup_keep_n"] == "5"
        assert "audit_log_max_age_days" not in items

    def test_post_settings_second_call_updates_existing_key(self) -> None:
        client = self._fake_client()
        conn = _memory_conn()
        http_client = _make_app_with_fake_client(client, conn=conn)

        http_client.post("/api/retention/settings", json={"backup_keep_n": 5})
        http_client.post("/api/retention/settings", json={"backup_keep_n": 9})

        items = http_client.get("/api/retention/settings").json()["items"]
        assert items["backup_keep_n"] == "9"
        rows = conn.execute("SELECT COUNT(*) FROM retention_settings").fetchone()
        assert rows[0] == 1  # upsert, pas un doublon

    def test_post_settings_empty_payload_returns_400(self) -> None:
        http_client = _make_app_with_fake_client(self._fake_client())

        response = http_client.post("/api/retention/settings", json={})

        assert response.status_code == 400

    def test_post_settings_boolean_field_serialized_as_text(self) -> None:
        client = self._fake_client()
        conn = _memory_conn()
        http_client = _make_app_with_fake_client(client, conn=conn)

        http_client.post("/api/retention/settings", json={"purge_auto_enabled": True})

        items = http_client.get("/api/retention/settings").json()["items"]
        assert items["purge_auto_enabled"] == "true"


# ---------------------------------------------------------------------------
# POST /api/retention/purge/preview et /purge/execute — geste en deux temps
# ---------------------------------------------------------------------------


class TestPurgeRouter:
    def _fake_client(self) -> FakeClickHouseClient:
        return FakeClickHouseClient([], [])

    def _make_backup(self, directory: Path, timestamp: str) -> Path:
        path = directory / f"outlet.yaml.bak-{timestamp}"
        path.write_bytes(b"x")
        return path

    def test_preview_backups_does_not_delete_any_file(self, tmp_path: Path) -> None:
        for ts in ("20260101000000", "20260102000000", "20260103000000"):
            self._make_backup(tmp_path, ts)
        http_client = _make_app_with_fake_client(self._fake_client(), backup_directory=tmp_path)

        response = http_client.post(
            "/api/retention/purge/preview", json={"target": "backups", "keep_n": 1}
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["preview"]["total_count"] == 2
        # Preuve de morsure : les 3 fichiers sont TOUJOURS sur disque.
        assert len(list(tmp_path.glob("*.bak-*"))) == 3

    def test_preview_table_does_not_delete_any_row(self) -> None:
        conn = _memory_conn()
        conn.execute(
            "INSERT INTO audit_log (happened_at, actor, action, detail) "
            "VALUES (datetime('now', '-100 days'), 'x', 'a', '')"
        )
        conn.commit()
        http_client = _make_app_with_fake_client(self._fake_client(), conn=conn)

        response = http_client.post(
            "/api/retention/purge/preview",
            json={"target": "audit_log", "max_age_days": 30},
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["preview"]["rows_to_delete"] == 1
        remaining = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        assert remaining == 1  # rien supprimé par le preview

    def test_preview_table_outside_allowlist_returns_400(self) -> None:
        http_client = _make_app_with_fake_client(self._fake_client())

        response = http_client.post(
            "/api/retention/purge/preview",
            json={"target": "port_mappings", "max_age_days": 30},
        )

        assert response.status_code == 422  # Literal fermé côté Pydantic

    def test_preview_backups_missing_keep_n_returns_400(self, tmp_path: Path) -> None:
        http_client = _make_app_with_fake_client(self._fake_client(), backup_directory=tmp_path)

        response = http_client.post("/api/retention/purge/preview", json={"target": "backups"})

        assert response.status_code == 400

    def test_no_purge_executes_without_explicit_execute_call(self, tmp_path: Path) -> None:
        """Preuve business : appeler UNIQUEMENT /purge/preview (à répétition,
        même) ne supprime jamais rien — seul un appel explicite à
        /purge/execute peut le faire.
        """
        for ts in ("20260101000000", "20260102000000"):
            self._make_backup(tmp_path, ts)
        http_client = _make_app_with_fake_client(self._fake_client(), backup_directory=tmp_path)

        for _ in range(3):
            http_client.post(
                "/api/retention/purge/preview", json={"target": "backups", "keep_n": 0}
            )

        assert len(list(tmp_path.glob("*.bak-*"))) == 2

    def test_execute_backups_deletes_exactly_previewed_files(self, tmp_path: Path) -> None:
        for ts in ("20260101000000", "20260102000000", "20260103000000"):
            self._make_backup(tmp_path, ts)
        http_client = _make_app_with_fake_client(self._fake_client(), backup_directory=tmp_path)

        preview = http_client.post(
            "/api/retention/purge/preview", json={"target": "backups", "keep_n": 1}
        ).json()["preview"]

        response = http_client.post(
            "/api/retention/purge/execute",
            json={"target": "backups", "preview": preview},
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["deleted_count"] == 2
        assert len(list(tmp_path.glob("*.bak-*"))) == 1

    def test_execute_table_deletes_exactly_previewed_rows(self) -> None:
        # `pending_config_changes` plutôt que `audit_log` comme cible ICI :
        # purger `audit_log` insère lui-même une ligne d'audit dans... audit_log
        # une fois l'exécution terminée (`_record_audit`), ce qui fait
        # légitimement remonter son propre compte de 1 après une purge qui en a
        # bien supprimé 1 — piège vécu en écrivant ce test (RED sur une
        # assertion naïve `COUNT(*) == 1`, alors que `deleted_count` valait
        # bien 1 : la purge ÉTAIT correcte, seule la lecture de contrôle du
        # test comptait aussi la trace d'audit fraîchement écrite).
        conn = _memory_conn()
        conn.execute(
            "INSERT INTO pending_config_changes (change_type, payload, created_at) "
            "VALUES ('x', '{}', datetime('now', '-100 days'))"
        )
        conn.execute(
            "INSERT INTO pending_config_changes (change_type, payload, created_at) "
            "VALUES ('x', '{}', datetime('now'))"
        )
        conn.commit()
        http_client = _make_app_with_fake_client(self._fake_client(), conn=conn)

        preview = http_client.post(
            "/api/retention/purge/preview",
            json={"target": "pending_config_changes", "max_age_days": 30},
        ).json()["preview"]

        response = http_client.post(
            "/api/retention/purge/execute",
            json={"target": "pending_config_changes", "preview": preview},
        )

        assert response.status_code == 200
        assert response.json()["deleted_count"] == 1
        remaining = conn.execute("SELECT COUNT(*) FROM pending_config_changes").fetchone()[0]
        assert remaining == 1

    def test_execute_writes_audit_log_entry(self, tmp_path: Path) -> None:
        self._make_backup(tmp_path, "20260101000000")
        conn = _memory_conn()
        http_client = _make_app_with_fake_client(
            self._fake_client(), conn=conn, backup_directory=tmp_path
        )

        preview = http_client.post(
            "/api/retention/purge/preview", json={"target": "backups", "keep_n": 0}
        ).json()["preview"]
        http_client.post(
            "/api/retention/purge/execute",
            json={"target": "backups", "preview": preview},
        )

        rows = conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'retention_purge_execute'"
        ).fetchall()
        assert len(rows) == 1
        assert "backups" in rows[0][0]

    def test_preview_via_htmx_returns_html_fragment_with_confirm_button(
        self, tmp_path: Path
    ) -> None:
        """Défaut réel corrigé (2026-08-08) : le diff-reviewer a constaté que
        l'écran affichait le preview mais n'offrait AUCUN moyen de le
        confirmer — aucun `hx-post="/api/retention/purge/execute"` nulle part
        dans le template. Un appel HTMX (header `HX-Request`) doit désormais
        recevoir un FRAGMENT HTML contenant ce bouton, pas seulement du JSON.
        """
        self._make_backup(tmp_path, "20260101000000")
        self._make_backup(tmp_path, "20260102000000")
        http_client = _make_app_with_fake_client(self._fake_client(), backup_directory=tmp_path)

        response = http_client.post(
            "/api/retention/purge/preview",
            json={"target": "backups", "keep_n": 0},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert 'hx-post="/api/retention/purge/execute"' in response.text
        assert "Confirmer la purge" in response.text
        assert 'name="preview"' in response.text
        assert 'name="target"' in response.text

    def test_preview_via_htmx_with_nothing_to_purge_has_no_confirm_button(
        self, tmp_path: Path
    ) -> None:
        """Rien à purger (0 lignes/fichiers) ne doit PAS afficher de bouton de
        confirmation — un clic sur "Confirmer" sans rien à purger serait un
        geste qui ne fait rien, source de confusion."""
        http_client = _make_app_with_fake_client(self._fake_client(), backup_directory=tmp_path)

        response = http_client.post(
            "/api/retention/purge/preview",
            json={"target": "backups", "keep_n": 5},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        assert 'hx-post="/api/retention/purge/execute"' not in response.text

    def test_execute_accepts_preview_as_json_string_from_html_form(self) -> None:
        """Le formulaire de confirmation transporte `preview` en CHAÎNE JSON
        (sérialisation `json-enc` d'un `<input type="hidden">`), pas en objet
        imbriqué — c'est ce que `PurgeExecuteRequest.preview_may_be_json_string`
        doit accepter. Preuve de morsure : sans ce validator, cet appel
        recevrait 422 (échec de validation Pydantic sur un `dict` attendu)."""
        conn = _memory_conn()
        conn.execute(
            "INSERT INTO audit_log (happened_at, actor, action, detail) "
            "VALUES (datetime('now', '-100 days'), 'x', 'a', '')"
        )
        conn.commit()
        http_client = _make_app_with_fake_client(self._fake_client(), conn=conn)

        preview = http_client.post(
            "/api/retention/purge/preview",
            json={"target": "pending_config_changes", "max_age_days": 30},
        ).json()["preview"]
        preview_json_string = json.dumps(preview)

        response = http_client.post(
            "/api/retention/purge/execute",
            json={"target": "pending_config_changes", "preview": preview_json_string},
        )

        assert response.status_code == 200
        assert response.json()["deleted_count"] == 0  # aucune ligne dans cette table ici

    def test_execute_rejects_malformed_json_string_preview(self) -> None:
        http_client = _make_app_with_fake_client(self._fake_client())

        response = http_client.post(
            "/api/retention/purge/execute",
            json={"target": "audit_log", "preview": "pas du json valide {{{"},
        )

        assert response.status_code == 422


# ---------------------------------------------------------------------------
# DÉFAUT MESURÉ (2026-08-09) : du JSON brut s'affichait à l'écran sur un
# appel HTMX — mêmes routes que `db_health.py` (voir sa suite de tests), même
# double contrat : fragment HTML lisible côté HTMX, JSON inchangé côté API.
# ---------------------------------------------------------------------------


class TestRetentionActionsHtmxFragments:
    def _fake_client(self) -> FakeClickHouseClient:
        tables_result = [
            ("flows", "MergeTree", "TimeReceived + toIntervalSecond(1296000)"),
        ]
        parts_result = [("flows", FLOWS_BYTES, FLOWS_ROWS)]
        return FakeClickHouseClient(tables_result, parts_result)

    def test_preview_retention_htmx_call_returns_html_never_raw_json(self) -> None:
        http_client = _make_app_with_fake_client(self._fake_client())

        response = http_client.post(
            "/api/retention/preview",
            json={"table": "flows", "ttl_days": 30},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        body = response.text
        assert '"status"' not in body
        assert "flows" in body

    def test_preview_retention_api_call_still_returns_json(self) -> None:
        http_client = _make_app_with_fake_client(self._fake_client())

        response = http_client.post(
            "/api/retention/preview", json={"table": "flows", "ttl_days": 30}
        )

        assert "application/json" in response.headers["content-type"]
        assert response.json()["status"] == "ok"

    def test_apply_retention_htmx_call_returns_html_never_raw_json(self) -> None:
        conn = _memory_conn()
        http_client = _make_app_with_fake_client(self._fake_client(), conn=conn)

        response = http_client.post(
            "/api/retention/apply",
            json={"table": "flows", "ttl_days": 30},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert '"status"' not in response.text

    def test_apply_retention_api_call_still_returns_json(self) -> None:
        conn = _memory_conn()
        http_client = _make_app_with_fake_client(self._fake_client(), conn=conn)

        response = http_client.post(
            "/api/retention/apply", json={"table": "flows", "ttl_days": 30}
        )

        assert "application/json" in response.headers["content-type"]
        assert response.json()["status"] == "ok"

    def test_update_settings_htmx_call_returns_html_never_raw_json(self) -> None:
        conn = _memory_conn()
        http_client = _make_app_with_fake_client(self._fake_client(), conn=conn)

        response = http_client.post(
            "/api/retention/settings",
            json={"docker_log_max_size_mb": 20},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        body = response.text
        assert '"status"' not in body
        assert "docker_log_max_size_mb" in body

    def test_update_settings_api_call_still_returns_json(self) -> None:
        conn = _memory_conn()
        http_client = _make_app_with_fake_client(self._fake_client(), conn=conn)

        response = http_client.post(
            "/api/retention/settings", json={"docker_log_max_size_mb": 20}
        )

        assert "application/json" in response.headers["content-type"]
        assert response.json()["status"] == "ok"

    def test_purge_execute_htmx_call_returns_html_never_raw_json(self) -> None:
        conn = _memory_conn()
        http_client = _make_app_with_fake_client(self._fake_client(), conn=conn)

        preview = http_client.post(
            "/api/retention/purge/preview",
            json={"target": "pending_config_changes", "max_age_days": 30},
        ).json()["preview"]

        response = http_client.post(
            "/api/retention/purge/execute",
            json={"target": "pending_config_changes", "preview": preview},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert '"status"' not in response.text

    def test_purge_execute_api_call_still_returns_json(self) -> None:
        conn = _memory_conn()
        http_client = _make_app_with_fake_client(self._fake_client(), conn=conn)

        preview = http_client.post(
            "/api/retention/purge/preview",
            json={"target": "pending_config_changes", "max_age_days": 30},
        ).json()["preview"]

        response = http_client.post(
            "/api/retention/purge/execute",
            json={"target": "pending_config_changes", "preview": preview},
        )

        assert "application/json" in response.headers["content-type"]
        assert response.json()["status"] == "ok"
