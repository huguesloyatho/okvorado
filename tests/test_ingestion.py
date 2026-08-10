"""Tests du LOT 4 — module Diagnostic d'ingestion.

Aucun test ici n'exige d'infra (pas d'appel réseau réel vers l'outlet) : le
fetch httpx est mocké, le texte Prometheus est fourni en échantillon figé.

Contexte métier : un flux rejeté par Akvorado n'arrive JAMAIS dans ClickHouse.
La seule source de vérité sur les rejets est ce endpoint Prometheus. Le cas
réel à faire ressortir est l'exportateur 192.0.2.18 : 2 161 545 flux rejetés,
0 forwarded, motif "input and output interfaces missing" (softflowd 1.1.0).
"""

from __future__ import annotations

import sqlite3
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from app.clients.prometheus import OutletMetrics, fetch_outlet_metrics, parse_outlet_metrics
from app.db import SCHEMA
from app.models import RejectionReason
from app.services.ingestion import (
    TREND_WINDOW_SECONDS,
    annotate_trend,
    apply_rejection_masks,
    build_rejection_reasons,
    compute_rejection_rate,
    list_rejection_masks,
    purge_all_flat_rejections,
    purge_rejection,
    record_rejection_history,
    unmask_all_rejections,
    unmask_one_rejection,
)

# ---------------------------------------------------------------------------
# Échantillon réel figé — CONTRACT.md, mesuré 2026-08-05
# ---------------------------------------------------------------------------

REAL_SAMPLE = (
    "# HELP akvorado_outlet_core_flows_errors_total Number of flows discarded\n"
    "# TYPE akvorado_outlet_core_flows_errors_total counter\n"
    'akvorado_outlet_core_flows_errors_total{error="input and output interfaces missing",'
    'exporter="192.0.2.18"} 2.161545e+06\n'
    'akvorado_outlet_core_forwarded_flows_total{exporter="192.0.2.24"} 1.0557793e+07\n'
    "akvorado_outlet_kafkaoutput_dropped_messages_total 0\n"
    "akvorado_outlet_metadata_provider_errors_total 0\n"
    'akvorado_outlet_kafkainput_connect_errors_total{node_id="1",worker="0"} 13\n'
    'akvorado_outlet_routing_provider_bmp_errors_total{error="cannot decode BMP header",'
    'exporter="203.0.113.1"} 2\n'
)


# ---------------------------------------------------------------------------
# Parsing — fonction pure, échantillon réel complet
# ---------------------------------------------------------------------------


class TestParseOutletMetricsRealSample:
    def test_forwarded_by_exporter(self) -> None:
        metrics = parse_outlet_metrics(REAL_SAMPLE)
        assert metrics.forwarded_by_exporter == {"192.0.2.24": 10_557_793}

    def test_rejected_by_exporter(self) -> None:
        metrics = parse_outlet_metrics(REAL_SAMPLE)
        assert metrics.rejected_by_exporter == {"192.0.2.18": 2_161_545}

    def test_rejection_reasons(self) -> None:
        metrics = parse_outlet_metrics(REAL_SAMPLE)
        assert metrics.rejection_reasons == {
            "192.0.2.18": {"input and output interfaces missing": 2_161_545}
        }

    def test_returns_outlet_metrics_instance(self) -> None:
        metrics = parse_outlet_metrics(REAL_SAMPLE)
        assert isinstance(metrics, OutletMetrics)


# ---------------------------------------------------------------------------
# Notation scientifique — piège obligatoire
# ---------------------------------------------------------------------------


class TestScientificNotation:
    def test_scientific_notation_parsed_as_int(self) -> None:
        text = (
            'akvorado_outlet_core_flows_errors_total{error="x",exporter="1.2.3.4"} 2.161545e+06\n'
        )
        metrics = parse_outlet_metrics(text)
        assert metrics.rejection_reasons["1.2.3.4"]["x"] == 2_161_545

    def test_naive_int_parsing_would_fail_this_case(self) -> None:
        # Preuve que int() naïf plante sur cette valeur : documente le piège.
        with pytest.raises(ValueError):
            int("2.161545e+06")

    def test_large_scientific_value(self) -> None:
        text = 'akvorado_outlet_core_forwarded_flows_total{exporter="9.9.9.9"} 1.0557793e+07\n'
        metrics = parse_outlet_metrics(text)
        assert metrics.forwarded_by_exporter["9.9.9.9"] == 10_557_793

    def test_integer_notation_without_exponent(self) -> None:
        text = 'akvorado_outlet_kafkainput_connect_errors_total{node_id="1",worker="0"} 13\n'
        metrics = parse_outlet_metrics(text)
        assert metrics.kafka_connect_errors == 13


# ---------------------------------------------------------------------------
# Lignes à ignorer proprement (comments, sans labels, vide, malformée)
# ---------------------------------------------------------------------------


class TestParsingRobustness:
    def test_help_and_type_comments_ignored(self) -> None:
        text = (
            "# HELP akvorado_outlet_core_flows_errors_total help text\n"
            "# TYPE akvorado_outlet_core_flows_errors_total counter\n"
            'akvorado_outlet_core_flows_errors_total{error="x",exporter="1.1.1.1"} 5\n'
        )
        metrics = parse_outlet_metrics(text)
        assert metrics.rejection_reasons == {"1.1.1.1": {"x": 5}}

    def test_metric_without_labels(self) -> None:
        text = "akvorado_outlet_kafkaoutput_dropped_messages_total 0\n"
        metrics = parse_outlet_metrics(text)
        assert metrics.kafka_dropped_messages == 0

    def test_blank_lines_ignored(self) -> None:
        text = '\n\nakvorado_outlet_core_flows_errors_total{error="x",exporter="1.1.1.1"} 5\n\n'
        metrics = parse_outlet_metrics(text)
        assert metrics.rejection_reasons == {"1.1.1.1": {"x": 5}}

    def test_malformed_line_ignored_without_exception(self) -> None:
        text = (
            "this is not a valid prometheus line ###\n"
            'akvorado_outlet_core_flows_errors_total{error="x",exporter="1.1.1.1"} 5\n'
            "another=garbage=line\n"
        )
        metrics = parse_outlet_metrics(text)
        assert metrics.rejection_reasons == {"1.1.1.1": {"x": 5}}

    def test_empty_input_returns_empty_dicts(self) -> None:
        metrics = parse_outlet_metrics("")
        assert metrics.forwarded_by_exporter == {}
        assert metrics.rejected_by_exporter == {}
        assert metrics.rejection_reasons == {}

    def test_only_comments_returns_empty_dicts(self) -> None:
        text = "# HELP x\n# TYPE x counter\n"
        metrics = parse_outlet_metrics(text)
        assert metrics.forwarded_by_exporter == {}
        assert metrics.rejected_by_exporter == {}


# ---------------------------------------------------------------------------
# Labels avec espaces / guillemets échappés
# ---------------------------------------------------------------------------


class TestLabelParsing:
    def test_label_value_with_spaces(self) -> None:
        text = (
            "akvorado_outlet_core_flows_errors_total"
            '{error="input and output interfaces missing",exporter="192.0.2.18"} 42\n'
        )
        metrics = parse_outlet_metrics(text)
        assert "input and output interfaces missing" in metrics.rejection_reasons["192.0.2.18"]

    def test_label_value_with_escaped_quote(self) -> None:
        text = (
            "akvorado_outlet_core_flows_errors_total"
            '{error="some \\"quoted\\" reason",exporter="1.2.3.4"} 3\n'
        )
        metrics = parse_outlet_metrics(text)
        errors = metrics.rejection_reasons["1.2.3.4"]
        assert list(errors.values()) == [3]

    def test_exporter_label_is_plain_ip_not_ipv6_mapped(self) -> None:
        text = 'akvorado_outlet_core_flows_errors_total{error="x",exporter="192.0.2.18"} 1\n'
        metrics = parse_outlet_metrics(text)
        assert "192.0.2.18" in metrics.rejection_reasons
        assert "::ffff:192.0.2.18" not in metrics.rejection_reasons


# ---------------------------------------------------------------------------
# Métriques absentes → dicts vides, jamais d'exception
# ---------------------------------------------------------------------------


class TestMissingMetrics:
    def test_no_rejections_at_all(self) -> None:
        text = 'akvorado_outlet_core_forwarded_flows_total{exporter="1.2.3.4"} 100\n'
        metrics = parse_outlet_metrics(text)
        assert metrics.rejected_by_exporter == {}
        assert metrics.rejection_reasons == {}

    def test_no_forwarded_at_all(self) -> None:
        text = 'akvorado_outlet_core_flows_errors_total{error="x",exporter="1.2.3.4"} 100\n'
        metrics = parse_outlet_metrics(text)
        assert metrics.forwarded_by_exporter == {}


# ---------------------------------------------------------------------------
# Fetch — I/O mockée via de faux clients httpx (aucun appel réseau réel).
# On simule ici des comportements httpx (ConnectError, TimeoutException,
# HTTPStatusError) sur un client entièrement factice, pour vérifier que
# fetch_outlet_metrics() gère chaque cas proprement (RuntimeError contrôlée).
# ---------------------------------------------------------------------------


class TestFetchOutletMetrics:
    async def test_fetch_success_parses_response_body(self, monkeypatch: Any) -> None:
        class FakeResponse:
            status_code = 200
            text = REAL_SAMPLE

            def raise_for_status(self) -> None:
                return None

        class FakeAsyncClient:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            async def __aenter__(self) -> FakeAsyncClient:
                return self

            async def __aexit__(self, *args: Any) -> None:
                return None

            async def get(self, url: str) -> FakeResponse:
                return FakeResponse()

        monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)

        metrics = await fetch_outlet_metrics()

        assert metrics.rejected_by_exporter == {"192.0.2.18": 2_161_545}

    async def test_fetch_simulated_connect_error_raises_runtime_error(
        self, monkeypatch: Any
    ) -> None:
        class FakeConnectErrorClient:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            async def __aenter__(self) -> FakeConnectErrorClient:
                return self

            async def __aexit__(self, *args: Any) -> None:
                return None

            async def get(self, url: str) -> Any:
                raise httpx.ConnectError("simulated connect failure (mock, no real network)")

        monkeypatch.setattr(httpx, "AsyncClient", FakeConnectErrorClient)

        with pytest.raises(RuntimeError):
            await fetch_outlet_metrics()

    async def test_fetch_simulated_timeout_raises_runtime_error(self, monkeypatch: Any) -> None:
        class FakeTimeoutClient:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            async def __aenter__(self) -> FakeTimeoutClient:
                return self

            async def __aexit__(self, *args: Any) -> None:
                return None

            async def get(self, url: str) -> Any:
                raise httpx.TimeoutException("simulated timeout (mock, no real network)")

        monkeypatch.setattr(httpx, "AsyncClient", FakeTimeoutClient)

        with pytest.raises(RuntimeError):
            await fetch_outlet_metrics()

    async def test_fetch_simulated_http_error_status_raises_runtime_error(
        self, monkeypatch: Any
    ) -> None:
        class ErrorResponse:
            status_code = 500
            text = "internal server error"

            def raise_for_status(self) -> None:
                request = httpx.Request("GET", "http://example/metrics")
                response = httpx.Response(500, request=request)
                raise httpx.HTTPStatusError("server error", request=request, response=response)

        class FakeErrorAsyncClient:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            async def __aenter__(self) -> FakeErrorAsyncClient:
                return self

            async def __aexit__(self, *args: Any) -> None:
                return None

            async def get(self, url: str) -> ErrorResponse:
                return ErrorResponse()

        monkeypatch.setattr(httpx, "AsyncClient", FakeErrorAsyncClient)

        with pytest.raises(RuntimeError):
            await fetch_outlet_metrics()


# ---------------------------------------------------------------------------
# Service — traduction en RejectionReason + taux de rejet
# ---------------------------------------------------------------------------


class TestComputeRejectionRate:
    def test_case_18_full_rejection(self) -> None:
        rate = compute_rejection_rate(rejected=2_161_545, forwarded=0)
        assert rate == 1.0

    def test_nominal_partial_rejection(self) -> None:
        rate = compute_rejection_rate(rejected=10, forwarded=90)
        assert rate == pytest.approx(0.1)

    def test_no_rejection_no_forward_zero_division_safe(self) -> None:
        rate = compute_rejection_rate(rejected=0, forwarded=0)
        assert rate == 0.0

    def test_all_forwarded_zero_rejected(self) -> None:
        rate = compute_rejection_rate(rejected=0, forwarded=1000)
        assert rate == 0.0


class TestBuildRejectionReasonsKnownMotif:
    def test_softflowd_motif_explanation_and_remediation(self) -> None:
        metrics = OutletMetrics(
            forwarded_by_exporter={},
            rejected_by_exporter={"192.0.2.18": 2_161_545},
            rejection_reasons={"192.0.2.18": {"input and output interfaces missing": 2_161_545}},
        )
        reasons = build_rejection_reasons(metrics)

        assert len(reasons) == 1
        reason = reasons[0]
        assert isinstance(reason, RejectionReason)
        assert reason.exporter == "192.0.2.18"
        assert reason.error == "input and output interfaces missing"
        assert reason.count == 2_161_545
        assert "softflowd" in reason.explanation.lower()
        assert "1.1.1" in reason.remediation

    def test_metadata_missing_motif_explique_le_disjoncteur_snmp(self) -> None:
        """`metadata missing` doit avoir une explication, pas le repli generique.

        MESURE A L'ECRAN (2026-08-09) sur un deploiement NEUF sur machine nue :
        l'exportateur 192.0.2.24 emettait 25 591 flux tous rejetes en
        « metadata missing », et l'ecran Ingestion affichait « Motif non
        repertorie dans la base de connaissance ». Or c'est le motif le PLUS
        courant d'une installation neuve.

        Mecanisme mesure dans les logs de l'outlet : le poller SNMP echoue en
        « context deadline exceeded », puis l'outlet ouvre son disjoncteur
        (« provider breaker open ») ; les flux arrivent mais aucun n'atteint
        ClickHouse tant que SNMP ne repond pas.
        """
        metrics = OutletMetrics(
            forwarded_by_exporter={},
            rejected_by_exporter={"192.0.2.24": 25_591},
            rejection_reasons={"192.0.2.24": {"metadata missing": 25_591}},
        )
        reasons = build_rejection_reasons(metrics)

        assert len(reasons) == 1
        reason = reasons[0]
        assert "non répertorié" not in reason.explanation.lower(), (
            "le motif le plus courant d'une installation neuve tombe encore dans le repli generique"
        )
        assert "snmp" in reason.explanation.lower()
        # La remediation doit etre actionnable : le port SNMP a verifier.
        assert "161" in reason.remediation

    def test_bmp_motif_explanation(self) -> None:
        metrics = OutletMetrics(
            forwarded_by_exporter={},
            rejected_by_exporter={},
            rejection_reasons={"203.0.113.1": {"cannot decode BMP header": 2}},
        )
        reasons = build_rejection_reasons(metrics)

        assert len(reasons) == 1
        assert "bmp" in reasons[0].explanation.lower() or "bgp" in reasons[0].explanation.lower()


class TestBuildRejectionReasonsUnknownMotif:
    def test_unknown_motif_generic_honest_explanation(self) -> None:
        metrics = OutletMetrics(
            forwarded_by_exporter={},
            rejected_by_exporter={},
            rejection_reasons={"5.5.5.5": {"some brand new motif never seen": 7}},
        )
        reasons = build_rejection_reasons(metrics)

        assert len(reasons) == 1
        assert reasons[0].count == 7
        # Explication honnête, pas inventée : doit signaler l'absence de connaissance.
        assert "non répertorié" in reasons[0].explanation.lower()


class TestBuildRejectionReasonsCriticalCaseFirst:
    def test_case_18_ranked_first_when_100_percent_rejected(self) -> None:
        metrics = OutletMetrics(
            forwarded_by_exporter={"192.0.2.24": 10_557_793},
            rejected_by_exporter={"192.0.2.18": 2_161_545, "192.0.2.24": 3},
            rejection_reasons={
                "192.0.2.18": {"input and output interfaces missing": 2_161_545},
                "192.0.2.24": {"minor glitch": 3},
            },
        )
        reasons = build_rejection_reasons(metrics)

        assert reasons[0].exporter == "192.0.2.18"

    def test_empty_metrics_returns_empty_list(self) -> None:
        metrics = OutletMetrics(
            forwarded_by_exporter={}, rejected_by_exporter={}, rejection_reasons={}
        )
        reasons = build_rejection_reasons(metrics)
        assert reasons == []


# ---------------------------------------------------------------------------
# Router FastAPI — isolé, cf. pattern LOT 1 / LOT 2
# ---------------------------------------------------------------------------


def _memory_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _make_test_app(conn: sqlite3.Connection | None = None) -> Any:
    from fastapi import FastAPI

    from app.routers import ingestion as ingestion_router
    from app.templating import build_templates

    test_app = FastAPI()
    templates = build_templates("app/templates")
    test_app.state.templates = templates
    test_app.dependency_overrides[ingestion_router.get_db_connection] = lambda: (
        conn if conn is not None else _memory_conn()
    )
    test_app.include_router(ingestion_router.router)
    return test_app


def _base_stub_if_missing() -> None:
    import os

    templates_dir = "app/templates"
    base_path = os.path.join(templates_dir, "base.html")
    if not os.path.exists(base_path):
        with open(base_path, "w") as fh:
            fh.write(
                "<html><head><title>{% block title %}{% endblock %}</title></head>"
                "<body>{% block content %}{% endblock %}</body></html>"
            )


class TestIngestionRouter:
    def test_api_ingestion_returns_200_and_conforms(self, monkeypatch: Any) -> None:
        async def fake_fetch_outlet_metrics() -> OutletMetrics:
            return OutletMetrics(
                forwarded_by_exporter={"192.0.2.24": 10_557_793},
                rejected_by_exporter={"192.0.2.18": 2_161_545},
                rejection_reasons={
                    "192.0.2.18": {"input and output interfaces missing": 2_161_545}
                },
            )

        from app.routers import ingestion as ingestion_router

        monkeypatch.setattr(ingestion_router, "fetch_outlet_metrics", fake_fetch_outlet_metrics)

        client = TestClient(_make_test_app())
        response = client.get("/api/ingestion")

        assert response.status_code == 200
        payload = response.json()
        assert "items" in payload
        assert "total" in payload
        assert payload["total"] == 1
        assert payload["items"][0]["exporter"] == "192.0.2.18"

    def test_get_ingestion_page_returns_html(self, monkeypatch: Any) -> None:
        _base_stub_if_missing()

        async def fake_fetch_outlet_metrics() -> OutletMetrics:
            return OutletMetrics(
                forwarded_by_exporter={"192.0.2.24": 10_557_793},
                rejected_by_exporter={"192.0.2.18": 2_161_545},
                rejection_reasons={
                    "192.0.2.18": {"input and output interfaces missing": 2_161_545}
                },
            )

        from app.routers import ingestion as ingestion_router

        monkeypatch.setattr(ingestion_router, "fetch_outlet_metrics", fake_fetch_outlet_metrics)

        client = TestClient(_make_test_app())
        response = client.get("/ingestion")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "192.0.2.18" in response.text

    def test_get_ingestion_page_handles_fetch_failure_gracefully(self, monkeypatch: Any) -> None:
        _base_stub_if_missing()

        async def failing_fetch_outlet_metrics() -> OutletMetrics:
            raise RuntimeError("simulated fetch failure for test purposes (mock)")

        from app.routers import ingestion as ingestion_router

        monkeypatch.setattr(ingestion_router, "fetch_outlet_metrics", failing_fetch_outlet_metrics)

        client = TestClient(_make_test_app())
        response = client.get("/ingestion")

        # Pas de 500 nu : la page reste utilisable avec un message d'erreur clair.
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert response.text

    def test_api_ingestion_handles_fetch_failure_without_500(self, monkeypatch: Any) -> None:
        async def failing_fetch_outlet_metrics() -> OutletMetrics:
            raise RuntimeError("simulated fetch failure for test purposes (mock)")

        from app.routers import ingestion as ingestion_router

        monkeypatch.setattr(ingestion_router, "fetch_outlet_metrics", failing_fetch_outlet_metrics)

        client = TestClient(_make_test_app())
        response = client.get("/api/ingestion")

        assert response.status_code != 500
        payload = response.json()
        assert "error" in payload


# ---------------------------------------------------------------------------
# Template — rendu sans exception
# ---------------------------------------------------------------------------


class TestIngestionTemplate:
    def _render(self, items: list[RejectionReason], error: str | None = None) -> str:
        from starlette.requests import Request

        from app.templating import build_templates

        _base_stub_if_missing()

        templates = build_templates("app/templates")

        scope: dict[str, object] = {
            "type": "http",
            "method": "GET",
            "path": "/ingestion",
            "headers": [],
            "query_string": b"",
            "server": ("test", 80),
            "scheme": "http",
            "client": ("test", 123),
            "app": None,
        }
        request = Request(scope)

        response = templates.TemplateResponse(
            request,
            "ingestion.html",
            {
                "items": items,
                "total": len(items),
                "error": error,
            },
        )
        return bytes(response.body).decode("utf-8")

    def test_renders_without_exception_with_case_18(self) -> None:
        reasons = [
            RejectionReason(
                error="input and output interfaces missing",
                exporter="192.0.2.18",
                count=2_161_545,
                explanation=(
                    "Akvorado rejette tout flux dont les interfaces d'entrée et de "
                    "sortie sont vides. C'est le comportement de softflowd 1.1.0."
                ),
                remediation="Compiler ou installer softflowd 1.1.1 sur cette machine.",
            )
        ]
        body = self._render(reasons)
        assert "192.0.2.18" in body
        assert "2" in body  # volume affiché sous une forme quelconque
        assert "softflowd" in body.lower()

    def test_renders_error_state_without_exception(self) -> None:
        body = self._render([], error="Erreur de récupération des métriques outlet (mock test)")
        assert "erreur" in body.lower()

    def test_autoescape_no_raw_script_injection(self) -> None:
        reasons = [
            RejectionReason(
                error="<script>alert(1)</script>",
                exporter="1.2.3.4",
                count=1,
                explanation="motif non répertorié",
                remediation="",
            )
        ]
        body = self._render(reasons)
        assert "<script>alert(1)</script>" not in body


# ---------------------------------------------------------------------------
# Tendance — DÉFAUT MESURÉ (2026-08-09) : un cumul figé depuis 11h s'affichait
# avec la même urgence visuelle qu'un rejet en cours. Ces tests couvrent le
# calcul du delta (rising/flat) et l'état distinct "unknown" quand aucun
# point de comparaison n'est encore disponible — jamais un "+0" trompeur.
# ---------------------------------------------------------------------------


def _reason(exporter: str = "203.0.113.1", error: str = "x", count: int = 100) -> RejectionReason:
    return RejectionReason(exporter=exporter, error=error, count=count)


class TestAnnotateTrendFirstMeasurement:
    def test_no_history_produces_unknown_state(self) -> None:
        """PREUVE ZÉRO SILENCIEUX : sans aucun point antérieur, la tendance est
        "unknown", jamais "flat" (qui affirmerait à tort une absence de
        mouvement) ni un delta calculé sur une base absente."""
        conn = _memory_conn()

        annotated = annotate_trend(conn, [_reason(count=555_961)])

        assert len(annotated) == 1
        assert annotated[0].trend_state == "unknown"
        assert annotated[0].trend_delta is None
        assert annotated[0].count == 555_961  # le compte lui-même n'est jamais altéré


class TestAnnotateTrendFlatVsRising:
    def test_identical_count_since_comparison_point_is_flat(self) -> None:
        """Reproduit le cas réel de la tâche : cumul figé — le compte n'a pas
        bougé depuis le point de comparaison -> "flat", pas d'urgence."""
        conn = _memory_conn()
        # Point de comparaison ANCIEN (au-delà de la fenêtre de 5 min) : même
        # compte que la mesure courante -> aucune variation depuis.
        conn.execute(
            "INSERT INTO ingestion_rejection_history "
            "(checked_at, exporter, error, count) VALUES "
            "(datetime('now', ?), ?, ?, ?)",
            (f"-{TREND_WINDOW_SECONDS + 60} seconds", "203.0.113.1", "metadata missing", 555_961),
        )
        conn.commit()

        annotated = annotate_trend(
            conn, [_reason(exporter="203.0.113.1", error="metadata missing", count=555_961)]
        )

        assert annotated[0].trend_state == "flat"
        assert annotated[0].trend_delta == 0

    def test_increased_count_since_comparison_point_is_rising(self) -> None:
        """Incident ACTIF : le compte a grimpé depuis le point de
        comparaison -> "rising", exige une action maintenant."""
        conn = _memory_conn()
        conn.execute(
            "INSERT INTO ingestion_rejection_history "
            "(checked_at, exporter, error, count) VALUES "
            "(datetime('now', ?), ?, ?, ?)",
            (f"-{TREND_WINDOW_SECONDS + 60} seconds", "192.0.2.18", "x", 1000),
        )
        conn.commit()

        annotated = annotate_trend(conn, [_reason(exporter="192.0.2.18", error="x", count=1240)])

        assert annotated[0].trend_state == "rising"
        assert annotated[0].trend_delta == 240

    def test_comparison_point_inside_window_is_ignored(self) -> None:
        """Un point de comparaison TROP RÉCENT (dans la fenêtre) ne doit pas
        être utilisé — sinon la tendance réagirait au bruit d'un seul cycle
        de scrape Prometheus plutôt qu'à une évolution réelle sur 5 min."""
        conn = _memory_conn()
        conn.execute(
            "INSERT INTO ingestion_rejection_history "
            "(checked_at, exporter, error, count) VALUES "
            "(datetime('now', '-10 seconds'), ?, ?, ?)",
            ("192.0.2.18", "x", 999),
        )
        conn.commit()

        annotated = annotate_trend(conn, [_reason(exporter="192.0.2.18", error="x", count=1000)])

        assert annotated[0].trend_state == "unknown"


class TestRecordRejectionHistory:
    def test_persists_one_row_per_reason(self) -> None:
        conn = _memory_conn()
        reasons = [
            _reason(exporter="a", error="x", count=10),
            _reason(exporter="b", error="y", count=20),
        ]

        record_rejection_history(conn, reasons)

        rows = conn.execute(
            "SELECT exporter, error, count FROM ingestion_rejection_history"
        ).fetchall()
        assert len(rows) == 2

    def test_write_failure_is_logged_never_raised(self) -> None:
        """Même contrat que `db_health._record_history` : un échec d'écriture
        de l'historique de tendance ne doit jamais faire échouer la requête
        métier qui l'a déclenché."""
        conn = _memory_conn()
        conn.close()  # connexion fermée -> toute écriture échoue

        record_rejection_history(conn, [_reason()])  # ne doit pas lever


class TestIngestionRouterTrend:
    def test_api_ingestion_first_call_reports_unknown_trend(self, monkeypatch: Any) -> None:
        async def fake_fetch_outlet_metrics() -> OutletMetrics:
            return OutletMetrics(
                forwarded_by_exporter={},
                rejected_by_exporter={"203.0.113.1": 555_961},
                rejection_reasons={"203.0.113.1": {"metadata missing": 555_961}},
            )

        from app.routers import ingestion as ingestion_router

        monkeypatch.setattr(ingestion_router, "fetch_outlet_metrics", fake_fetch_outlet_metrics)

        client = TestClient(_make_test_app())
        response = client.get("/api/ingestion")

        payload = response.json()
        assert payload["items"][0]["trend_state"] == "unknown"
        assert payload["items"][0]["trend_delta"] is None

    def test_second_call_after_stale_point_reports_flat(self, monkeypatch: Any) -> None:
        """Deux appels successifs avec le MÊME compte, séparés par un point
        de comparaison ancien injecté directement : reproduit "cumul figé"."""

        async def fake_fetch_outlet_metrics() -> OutletMetrics:
            return OutletMetrics(
                forwarded_by_exporter={},
                rejected_by_exporter={"203.0.113.1": 555_961},
                rejection_reasons={"203.0.113.1": {"metadata missing": 555_961}},
            )

        from app.routers import ingestion as ingestion_router

        monkeypatch.setattr(ingestion_router, "fetch_outlet_metrics", fake_fetch_outlet_metrics)

        conn = _memory_conn()
        conn.execute(
            "INSERT INTO ingestion_rejection_history "
            "(checked_at, exporter, error, count) VALUES "
            "(datetime('now', ?), ?, ?, ?)",
            (f"-{TREND_WINDOW_SECONDS + 60} seconds", "203.0.113.1", "metadata missing", 555_961),
        )
        conn.commit()

        client = TestClient(_make_test_app(conn=conn))
        response = client.get("/api/ingestion")

        payload = response.json()
        assert payload["items"][0]["trend_state"] == "flat"
        assert payload["items"][0]["trend_delta"] == 0

    def test_html_page_renders_trend_labels(self, monkeypatch: Any) -> None:
        _base_stub_if_missing()

        async def fake_fetch_outlet_metrics() -> OutletMetrics:
            return OutletMetrics(
                forwarded_by_exporter={},
                rejected_by_exporter={"203.0.113.1": 555_961},
                rejection_reasons={"203.0.113.1": {"metadata missing": 555_961}},
            )

        from app.routers import ingestion as ingestion_router

        monkeypatch.setattr(ingestion_router, "fetch_outlet_metrics", fake_fetch_outlet_metrics)

        client = TestClient(_make_test_app())
        response = client.get("/ingestion")

        assert response.status_code == 200
        assert "tendance inconnue" in response.text.lower()


# ---------------------------------------------------------------------------
# PURGE DES CUMULS FIGÉS (2026-08-10) — DEMANDE UTILISATEUR : « il faut ajouter
# un bouton pour purger les metadata missing ».
#
# Contexte mesuré (prod 192.0.2.6, 2026-08-10) : l'écran /ingestion affiche en
# tête, en rouge, deux exportateurs FANTÔMES (203.0.113.1 et 198.51.100.51) qui
# ont émis puis disparu — ClickHouse ne les liste plus parmi les 11 exportateurs
# actifs sur 24h. Leurs cumuls (555 961 et 238 917) sont figés depuis le
# démarrage de l'outlet (2026-08-09T12:04:59Z) et masquent les vrais problèmes.
#
# CONTRAINTE STRUCTURANTE : Okvorado ne PEUT PAS remettre à zéro un compteur
# Prometheus (impossible par conception — seul un redémarrage de l'outlet les
# efface, ce qui couperait l'ingestion). La purge est donc un MASQUAGE côté
# Okvorado : on mémorise le cumul courant comme LIGNE DE BASE, et on n'affiche
# ensuite plus que ce qui s'ajoute AU-DESSUS.
#
# ZÉRO SILENCIEUX (CLAUDE.md) — les trois garanties que ces tests prouvent :
#   1. un motif ACTIF (trend rising) ne peut PAS être purgé (refus explicite) ;
#   2. un motif purgé qui REPART réapparaît tout seul au premier incrément ;
#   3. un redémarrage de l'outlet (compteur < ligne de base) invalide le
#      masque au lieu de rendre un delta négatif ou de masquer éternellement.
# ---------------------------------------------------------------------------


def _insert_stale_point(conn: sqlite3.Connection, exporter: str, error: str, count: int) -> None:
    """Injecte un point de comparaison ANTÉRIEUR à la fenêtre de tendance.

    Sans ce point, `annotate_trend` rend "unknown" (aucune base de comparaison)
    — et un motif "unknown" n'est jamais purgeable (on ne peut pas prouver
    qu'il est figé). Ce helper est donc le préalable de tout test de purge.
    """
    conn.execute(
        "INSERT INTO ingestion_rejection_history (checked_at, exporter, error, count) "
        "VALUES (datetime('now', ?), ?, ?, ?)",
        (f"-{TREND_WINDOW_SECONDS + 60} seconds", exporter, error, count),
    )
    conn.commit()


class TestMaskSchema:
    def test_mask_table_exists_in_schema(self) -> None:
        """La persistance du masquage vit en BASE, pas en mémoire : un
        redémarrage d'Okvorado ne doit pas ressusciter des lignes purgées."""
        conn = _memory_conn()
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert "ingestion_rejection_mask" in tables

    def test_mask_is_unique_per_exporter_and_error(self) -> None:
        """Une seule ligne de base par couple (exportateur, motif) : purger deux
        fois le même couple met à jour la base, ne crée pas de doublon."""
        conn = _memory_conn()
        conn.execute(
            "INSERT INTO ingestion_rejection_mask (exporter, error, baseline_count) "
            "VALUES (?, ?, ?)",
            ("203.0.113.1", "metadata missing", 100),
        )
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO ingestion_rejection_mask (exporter, error, baseline_count) "
                "VALUES (?, ?, ?)",
                ("203.0.113.1", "metadata missing", 200),
            )


class TestPurgeRefusesActiveProblem:
    """LE CŒUR DE LA RÈGLE : la purge nettoie du BRUIT HISTORIQUE, elle ne doit
    JAMAIS faire disparaître une panne EN COURS."""

    def test_purge_of_rising_reason_is_refused(self) -> None:
        conn = _memory_conn()
        _insert_stale_point(conn, "10.0.0.1", "metadata missing", 100)
        reasons = annotate_trend(
            conn, [_reason(exporter="10.0.0.1", error="metadata missing", count=150)]
        )
        assert reasons[0].trend_state == "rising"  # préalable : le motif grimpe

        result = purge_rejection(conn, reasons, exporter="10.0.0.1", error="metadata missing")

        assert result.purged == 0
        assert result.refused_active == 1
        rows = conn.execute("SELECT COUNT(*) FROM ingestion_rejection_mask").fetchone()
        assert rows[0] == 0

    def test_purge_of_unknown_trend_is_refused(self) -> None:
        """ZÉRO SILENCIEUX : sans point de comparaison, on ne peut pas PROUVER
        que le cumul est figé — masquer sur une simple absence de mesure
        reviendrait à cacher un problème potentiellement actif."""
        conn = _memory_conn()
        reasons = annotate_trend(
            conn, [_reason(exporter="10.0.0.1", error="metadata missing", count=150)]
        )
        assert reasons[0].trend_state == "unknown"

        result = purge_rejection(conn, reasons, exporter="10.0.0.1", error="metadata missing")

        assert result.purged == 0
        assert result.refused_unknown == 1

    def test_purge_of_unmatched_couple_reports_not_found(self) -> None:
        """Un couple absent de la mesure courante n'est pas silencieusement
        masqué « au cas où » : il est signalé introuvable."""
        conn = _memory_conn()
        _insert_stale_point(conn, "10.0.0.1", "metadata missing", 100)
        reasons = annotate_trend(
            conn, [_reason(exporter="10.0.0.1", error="metadata missing", count=100)]
        )

        result = purge_rejection(conn, reasons, exporter="9.9.9.9", error="metadata missing")

        assert result.purged == 0
        assert result.not_found == 1


class TestPurgeFlatReason:
    def test_purge_records_current_count_as_baseline(self) -> None:
        conn = _memory_conn()
        _insert_stale_point(conn, "203.0.113.1", "metadata missing", 555_961)
        reasons = annotate_trend(
            conn, [_reason(exporter="203.0.113.1", error="metadata missing", count=555_961)]
        )
        assert reasons[0].trend_state == "flat"

        result = purge_rejection(
            conn, reasons, exporter="203.0.113.1", error="metadata missing", actor="tester"
        )

        assert result.purged == 1
        row = conn.execute(
            "SELECT baseline_count FROM ingestion_rejection_mask WHERE exporter = ? AND error = ?",
            ("203.0.113.1", "metadata missing"),
        ).fetchone()
        assert row[0] == 555_961

    def test_purged_reason_is_hidden_from_display(self) -> None:
        conn = _memory_conn()
        _insert_stale_point(conn, "203.0.113.1", "metadata missing", 555_961)
        reasons = annotate_trend(
            conn, [_reason(exporter="203.0.113.1", error="metadata missing", count=555_961)]
        )
        purge_rejection(conn, reasons, exporter="203.0.113.1", error="metadata missing")

        visible, hidden = apply_rejection_masks(conn, reasons)

        assert visible == []
        assert hidden == 1

    def test_purge_twice_updates_baseline_without_duplicate(self) -> None:
        conn = _memory_conn()
        _insert_stale_point(conn, "a", "e", 100)
        reasons = annotate_trend(conn, [_reason(exporter="a", error="e", count=100)])
        purge_rejection(conn, reasons, exporter="a", error="e")

        _insert_stale_point(conn, "a", "e", 300)
        reasons2 = annotate_trend(conn, [_reason(exporter="a", error="e", count=300)])
        # Le motif a repris puis s'est re-figé : il est ré-affiché (delta 200),
        # et une seconde purge doit REMPLACER la ligne de base, pas la doubler.
        purge_rejection(conn, reasons2, exporter="a", error="e")

        rows = conn.execute(
            "SELECT baseline_count FROM ingestion_rejection_mask WHERE exporter='a' AND error='e'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == 300


class TestPurgeAllFlat:
    def test_purges_every_flat_reason_and_spares_the_active_ones(self) -> None:
        """Le geste qui passe à l'échelle (cible produit : 350 routeurs) — il
        doit rester SÉLECTIF : ne toucher QUE ce qui est prouvé figé."""
        conn = _memory_conn()
        _insert_stale_point(conn, "203.0.113.1", "metadata missing", 555_961)
        _insert_stale_point(conn, "198.51.100.51", "metadata missing", 238_917)
        _insert_stale_point(conn, "192.0.2.18", "interfaces missing", 1_000)
        reasons = annotate_trend(
            conn,
            [
                _reason(exporter="203.0.113.1", error="metadata missing", count=555_961),
                _reason(exporter="198.51.100.51", error="metadata missing", count=238_917),
                _reason(exporter="192.0.2.18", error="interfaces missing", count=1_500),
                _reason(exporter="1.1.1.1", error="jamais mesuré", count=7),
            ],
        )

        result = purge_all_flat_rejections(conn, reasons, actor="tester")

        assert result.purged == 2
        assert result.refused_active == 1  # 192.0.2.18 grimpe encore
        assert result.refused_unknown == 1  # 1.1.1.1 sans point de comparaison

        visible, hidden = apply_rejection_masks(conn, reasons)
        assert hidden == 2
        assert {r.exporter for r in visible} == {"192.0.2.18", "1.1.1.1"}

    def test_purge_all_with_nothing_flat_purges_nothing(self) -> None:
        conn = _memory_conn()
        reasons = annotate_trend(conn, [_reason(exporter="a", error="e", count=10)])

        result = purge_all_flat_rejections(conn, reasons)

        assert result.purged == 0
        assert conn.execute("SELECT COUNT(*) FROM ingestion_rejection_mask").fetchone()[0] == 0


class TestMaskedReasonReappearsWhenCounterResumes:
    """GARANTIE N°2 : un masque ne survit pas à la reprise du problème."""

    def test_counter_above_baseline_reappears(self) -> None:
        conn = _memory_conn()
        _insert_stale_point(conn, "203.0.113.1", "metadata missing", 555_961)
        reasons = annotate_trend(
            conn, [_reason(exporter="203.0.113.1", error="metadata missing", count=555_961)]
        )
        purge_rejection(conn, reasons, exporter="203.0.113.1", error="metadata missing")

        # L'exportateur fantôme se remet à émettre des rejets : +42.
        resumed = annotate_trend(
            conn, [_reason(exporter="203.0.113.1", error="metadata missing", count=556_003)]
        )
        visible, hidden = apply_rejection_masks(conn, resumed)

        assert hidden == 0
        assert len(visible) == 1
        # Seul le DELTA au-dessus de la ligne de base est affiché, pas le cumul.
        assert visible[0].count == 42
        assert visible[0].masked_baseline == 555_961

    def test_reappeared_reason_is_flagged_as_resumed_after_purge(self) -> None:
        """L'exploitant doit voir que ce chiffre est un delta post-purge, pas
        un cumul brut — sinon il croirait à une chute du compteur."""
        conn = _memory_conn()
        _insert_stale_point(conn, "a", "e", 100)
        reasons = annotate_trend(conn, [_reason(exporter="a", error="e", count=100)])
        purge_rejection(conn, reasons, exporter="a", error="e")

        resumed = annotate_trend(conn, [_reason(exporter="a", error="e", count=105)])
        visible, _ = apply_rejection_masks(conn, resumed)

        assert visible[0].count == 5
        assert visible[0].masked_baseline == 100


class TestOutletRestartInvalidatesMask:
    """GARANTIE N°3 : si l'outlet redémarre, ses compteurs repartent de 0. Une
    ligne de base PLUS HAUTE que le compteur courant signifie exactement ça."""

    def test_counter_below_baseline_never_yields_negative_delta(self) -> None:
        conn = _memory_conn()
        _insert_stale_point(conn, "a", "e", 555_961)
        reasons = annotate_trend(conn, [_reason(exporter="a", error="e", count=555_961)])
        purge_rejection(conn, reasons, exporter="a", error="e")

        # Outlet redémarré : le compteur repart bas.
        restarted = annotate_trend(conn, [_reason(exporter="a", error="e", count=12)])
        visible, hidden = apply_rejection_masks(conn, restarted)

        assert hidden == 0
        assert len(visible) == 1
        assert visible[0].count == 12  # cumul courant intégral, JAMAIS négatif
        assert visible[0].count >= 0

    def test_stale_mask_is_dropped_from_database(self) -> None:
        """Le masque périmé ne doit pas rester en base : sinon il re-masquerait
        le motif dès que le nouveau cumul repasserait sous l'ancienne base."""
        conn = _memory_conn()
        _insert_stale_point(conn, "a", "e", 555_961)
        reasons = annotate_trend(conn, [_reason(exporter="a", error="e", count=555_961)])
        purge_rejection(conn, reasons, exporter="a", error="e")

        restarted = annotate_trend(conn, [_reason(exporter="a", error="e", count=12)])
        apply_rejection_masks(conn, restarted)

        rows = conn.execute("SELECT COUNT(*) FROM ingestion_rejection_mask").fetchone()
        assert rows[0] == 0


class TestUnmask:
    """GARANTIE N°4 : réversibilité. Un masquage irréversible serait lui-même
    un zéro silencieux."""

    def test_unmask_all_restores_every_hidden_reason(self) -> None:
        conn = _memory_conn()
        _insert_stale_point(conn, "a", "e", 100)
        _insert_stale_point(conn, "b", "f", 200)
        reasons = annotate_trend(
            conn,
            [
                _reason(exporter="a", error="e", count=100),
                _reason(exporter="b", error="f", count=200),
            ],
        )
        purge_all_flat_rejections(conn, reasons)
        assert apply_rejection_masks(conn, reasons)[1] == 2

        restored = unmask_all_rejections(conn)

        assert restored == 2
        visible, hidden = apply_rejection_masks(conn, reasons)
        assert hidden == 0
        assert len(visible) == 2
        # Le cumul BRUT est restauré, pas un delta.
        assert {r.count for r in visible} == {100, 200}

    def test_unmask_one_restores_only_that_couple(self) -> None:
        conn = _memory_conn()
        _insert_stale_point(conn, "a", "e", 100)
        _insert_stale_point(conn, "b", "f", 200)
        reasons = annotate_trend(
            conn,
            [
                _reason(exporter="a", error="e", count=100),
                _reason(exporter="b", error="f", count=200),
            ],
        )
        purge_all_flat_rejections(conn, reasons)

        restored = unmask_one_rejection(conn, exporter="a", error="e")

        assert restored == 1
        visible, hidden = apply_rejection_masks(conn, reasons)
        assert hidden == 1
        assert [r.exporter for r in visible] == ["a"]

    def test_unmask_all_on_empty_returns_zero(self) -> None:
        conn = _memory_conn()
        assert unmask_all_rejections(conn) == 0


class TestListMasks:
    def test_list_masks_reports_what_is_hidden(self) -> None:
        """VISIBILITÉ : l'écran doit pouvoir dire CE QUI est masqué, pas
        seulement combien."""
        conn = _memory_conn()
        _insert_stale_point(conn, "203.0.113.1", "metadata missing", 555_961)
        reasons = annotate_trend(
            conn, [_reason(exporter="203.0.113.1", error="metadata missing", count=555_961)]
        )
        purge_rejection(
            conn, reasons, exporter="203.0.113.1", error="metadata missing", actor="hugues"
        )

        masks = list_rejection_masks(conn)

        assert len(masks) == 1
        assert masks[0]["exporter"] == "203.0.113.1"
        assert masks[0]["error"] == "metadata missing"
        assert masks[0]["baseline_count"] == 555_961
        assert masks[0]["masked_by"] == "hugues"
        assert masks[0]["masked_at"]


class TestMaskPersistence:
    def test_mask_survives_reconnection_to_same_database(self, tmp_path: Any) -> None:
        """PERSISTANCE : le masquage vit sur disque — un redémarrage d'Okvorado
        (nouvelle connexion au même fichier) ne le perd pas."""
        from app.db import init_database

        db_path = str(tmp_path / "okvorado.db")
        init_database(db_path)

        conn = sqlite3.connect(db_path)
        _insert_stale_point(conn, "203.0.113.1", "metadata missing", 555_961)
        reasons = annotate_trend(
            conn, [_reason(exporter="203.0.113.1", error="metadata missing", count=555_961)]
        )
        purge_rejection(conn, reasons, exporter="203.0.113.1", error="metadata missing")
        conn.close()

        # « Redémarrage » d'Okvorado : nouvelle connexion, même fichier.
        conn2 = sqlite3.connect(db_path)
        masks = list_rejection_masks(conn2)
        assert len(masks) == 1
        assert masks[0]["baseline_count"] == 555_961
        conn2.close()

    def test_mask_read_failure_is_logged_and_hides_nothing(self) -> None:
        """ZÉRO SILENCIEUX : si la lecture des masques échoue, on n'invente pas
        un masquage — on affiche TOUT (dégradation vers le plus visible)."""
        conn = _memory_conn()
        conn.close()

        visible, hidden = apply_rejection_masks(conn, [_reason(exporter="a", error="e", count=5)])

        assert hidden == 0
        assert len(visible) == 1


# ---------------------------------------------------------------------------
# Routes de purge — fragment HTML pour HTMX, jamais du JSON brut à l'écran
# ---------------------------------------------------------------------------


class TestPurgeRoutes:
    def _client_with_flat_reason(self, monkeypatch: Any) -> tuple[Any, sqlite3.Connection]:
        async def fake_fetch_outlet_metrics() -> OutletMetrics:
            return OutletMetrics(
                forwarded_by_exporter={},
                rejected_by_exporter={"203.0.113.1": 555_961},
                rejection_reasons={"203.0.113.1": {"metadata missing": 555_961}},
            )

        from app.routers import ingestion as ingestion_router

        monkeypatch.setattr(ingestion_router, "fetch_outlet_metrics", fake_fetch_outlet_metrics)

        conn = _memory_conn()
        _insert_stale_point(conn, "203.0.113.1", "metadata missing", 555_961)
        return TestClient(_make_test_app(conn=conn)), conn

    def test_purge_one_returns_html_fragment_for_htmx(self, monkeypatch: Any) -> None:
        """DÉFAUT DÉJÀ RENCONTRÉ 9 FOIS : un bouton HTMX qui reçoit du JSON brut
        l'insère TEL QUEL dans la page. La réponse HX doit être du HTML."""
        _base_stub_if_missing()
        client, _ = self._client_with_flat_reason(monkeypatch)

        response = client.post(
            "/api/ingestion/purge",
            json={"exporter": "203.0.113.1", "error": "metadata missing"},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert not response.text.lstrip().startswith("{")
        assert "<" in response.text

    def test_purge_one_returns_json_for_api_client(self, monkeypatch: Any) -> None:
        client, conn = self._client_with_flat_reason(monkeypatch)

        response = client.post(
            "/api/ingestion/purge",
            json={"exporter": "203.0.113.1", "error": "metadata missing"},
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "ok"
        assert payload["purged"] == 1
        assert conn.execute("SELECT COUNT(*) FROM ingestion_rejection_mask").fetchone()[0] == 1

    def test_purge_one_refuses_active_reason_and_says_so(self, monkeypatch: Any) -> None:
        async def fake_fetch_outlet_metrics() -> OutletMetrics:
            return OutletMetrics(
                forwarded_by_exporter={},
                rejected_by_exporter={"10.0.0.1": 150},
                rejection_reasons={"10.0.0.1": {"metadata missing": 150}},
            )

        from app.routers import ingestion as ingestion_router

        monkeypatch.setattr(ingestion_router, "fetch_outlet_metrics", fake_fetch_outlet_metrics)

        conn = _memory_conn()
        _insert_stale_point(conn, "10.0.0.1", "metadata missing", 100)
        client = TestClient(_make_test_app(conn=conn))

        response = client.post(
            "/api/ingestion/purge",
            json={"exporter": "10.0.0.1", "error": "metadata missing"},
        )

        payload = response.json()
        assert payload["purged"] == 0
        assert payload["refused_active"] == 1
        assert conn.execute("SELECT COUNT(*) FROM ingestion_rejection_mask").fetchone()[0] == 0

    def test_purge_all_flat_route(self, monkeypatch: Any) -> None:
        client, conn = self._client_with_flat_reason(monkeypatch)

        response = client.post("/api/ingestion/purge-all-flat")

        assert response.status_code == 200
        payload = response.json()
        assert payload["purged"] == 1
        assert conn.execute("SELECT COUNT(*) FROM ingestion_rejection_mask").fetchone()[0] == 1

    def test_purge_all_flat_returns_html_fragment_for_htmx(self, monkeypatch: Any) -> None:
        _base_stub_if_missing()
        client, _ = self._client_with_flat_reason(monkeypatch)

        response = client.post("/api/ingestion/purge-all-flat", headers={"HX-Request": "true"})

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert not response.text.lstrip().startswith("{")

    def test_unmask_all_route(self, monkeypatch: Any) -> None:
        client, conn = self._client_with_flat_reason(monkeypatch)
        client.post("/api/ingestion/purge-all-flat")
        assert conn.execute("SELECT COUNT(*) FROM ingestion_rejection_mask").fetchone()[0] == 1

        response = client.post("/api/ingestion/unmask-all")

        assert response.status_code == 200
        assert response.json()["restored"] == 1
        assert conn.execute("SELECT COUNT(*) FROM ingestion_rejection_mask").fetchone()[0] == 0

    def test_unmask_all_returns_html_fragment_for_htmx(self, monkeypatch: Any) -> None:
        _base_stub_if_missing()
        client, _ = self._client_with_flat_reason(monkeypatch)
        client.post("/api/ingestion/purge-all-flat")

        response = client.post("/api/ingestion/unmask-all", headers={"HX-Request": "true"})

        assert "text/html" in response.headers["content-type"]
        assert not response.text.lstrip().startswith("{")

    def test_purge_route_records_audit_entry(self, monkeypatch: Any) -> None:
        """Traçabilité : masquer une ligne rouge est un geste d'exploitation,
        il doit laisser une trace comme les autres actions d'écriture."""
        client, conn = self._client_with_flat_reason(monkeypatch)

        client.post(
            "/api/ingestion/purge",
            json={"exporter": "203.0.113.1", "error": "metadata missing"},
        )

        rows = conn.execute(
            "SELECT action, detail FROM audit_log WHERE action LIKE 'ingestion_%'"
        ).fetchall()
        assert rows
        assert "203.0.113.1" in rows[0][1]


class TestIngestionPageWithMasks:
    def test_page_hides_purged_reason_and_announces_the_count(self, monkeypatch: Any) -> None:
        """L'écran doit dire COMBIEN de lignes sont masquées — un masquage
        invisible serait lui-même un zéro silencieux."""
        _base_stub_if_missing()

        async def fake_fetch_outlet_metrics() -> OutletMetrics:
            return OutletMetrics(
                forwarded_by_exporter={},
                rejected_by_exporter={"203.0.113.1": 555_961},
                rejection_reasons={"203.0.113.1": {"metadata missing": 555_961}},
            )

        from app.routers import ingestion as ingestion_router

        monkeypatch.setattr(ingestion_router, "fetch_outlet_metrics", fake_fetch_outlet_metrics)

        conn = _memory_conn()
        _insert_stale_point(conn, "203.0.113.1", "metadata missing", 555_961)
        client = TestClient(_make_test_app(conn=conn))

        client.post(
            "/api/ingestion/purge",
            json={"exporter": "203.0.113.1", "error": "metadata missing"},
        )
        response = client.get("/ingestion")

        assert response.status_code == 200
        body = response.text
        assert "masqué" in body.lower()

        # La ligne purgée ne doit plus figurer dans le TABLEAU DES REJETS —
        # celui-ci disparaît même entièrement, puisqu'il ne reste rien à
        # afficher une fois l'unique motif masqué.
        assert "Exportateurs à fort taux de rejet" not in body
        assert 'class="ingestion-critical-table"' not in body

        # ...mais elle DOIT rester visible dans le PANNEAU DES MASQUES, avec
        # son cumul mémorisé : un masquage invisible serait lui-même un zéro
        # silencieux (l'exploitant doit savoir CE QUI a été escamoté, et
        # pouvoir le rétablir).
        masked_start = body.find('class="ingestion-masked-table"')
        assert masked_start != -1
        assert "555 961" in body[masked_start:]
        assert "203.0.113.1" in body[masked_start:]

    def test_page_offers_purge_buttons_and_explains_the_mechanism(self, monkeypatch: Any) -> None:
        """L'écran doit expliquer HONNÊTEMENT ce que fait le bouton : le
        compteur Prometheus n'est PAS remis à zéro."""
        _base_stub_if_missing()

        async def fake_fetch_outlet_metrics() -> OutletMetrics:
            return OutletMetrics(
                forwarded_by_exporter={},
                rejected_by_exporter={"203.0.113.1": 555_961},
                rejection_reasons={"203.0.113.1": {"metadata missing": 555_961}},
            )

        from app.routers import ingestion as ingestion_router

        monkeypatch.setattr(ingestion_router, "fetch_outlet_metrics", fake_fetch_outlet_metrics)

        conn = _memory_conn()
        _insert_stale_point(conn, "203.0.113.1", "metadata missing", 555_961)
        client = TestClient(_make_test_app(conn=conn))

        body = client.get("/ingestion").text

        assert "/api/ingestion/purge" in body
        assert "/api/ingestion/purge-all-flat" in body
        assert "prometheus" in body.lower()
        # `hx-select` est HÉRITÉ : sans `unset`, les boutons insèrent un
        # fragment VIDE en silence (défaut mesuré, db_health.html/retention.html).
        assert 'hx-select="unset"' in body


class TestPurgeFragmentsUseRealCssClasses:
    """DÉFAUT MESURÉ SUR CE PROJET : « CSS cassant un HTML correct ». Une classe
    inventée produit un HTML valide, des tests verts, et un bandeau SANS AUCUN
    STYLE à l'écran — invisible autrement qu'en regardant la page.

    Ce garde-fou vérifie que chaque variante `.notice-*` employée par les
    fragments de purge existe RÉELLEMENT dans `style.css`. Pris sur le fait :
    `notice-error` avait été écrit alors que la feuille ne définit que
    `notice-info`, `notice-warn`, `notice-crit` et `notice-ok`.
    """

    def _declared_notice_variants(self) -> set[str]:
        import re
        from pathlib import Path

        css = Path("app/static/style.css").read_text(encoding="utf-8")
        return set(re.findall(r"\.(notice-[a-z]+)\b", css))

    def _used_notice_variants(self, template_name: str) -> set[str]:
        import re
        from pathlib import Path

        html = Path(f"app/templates/{template_name}").read_text(encoding="utf-8")
        used: set[str] = set()
        for class_attr in re.findall(r'class="([^"]*)"', html):
            used.update(c for c in class_attr.split() if c.startswith("notice-"))
        return used

    @pytest.mark.parametrize(
        "template_name",
        [
            "_ingestion_purge_fragment.html",
            "_ingestion_unmask_fragment.html",
            "ingestion.html",
        ],
    )
    def test_every_notice_variant_exists_in_stylesheet(self, template_name: str) -> None:
        declared = self._declared_notice_variants()
        used = self._used_notice_variants(template_name)
        unknown = used - declared
        assert not unknown, (
            f"{template_name} utilise des classes .notice-* absentes de style.css : "
            f"{sorted(unknown)}. Elles rendraient un bandeau sans style à l'écran. "
            f"Variantes réellement définies : {sorted(declared)}."
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
