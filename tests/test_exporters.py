"""Tests du LOT 1 — module Exportateurs.

Aucun test ici n'exige d'infra (ni ClickHouse, ni Akvorado, ni Prometheus) :
les clients sont mockés / injectés, le YAML est fourni en fixture en dur.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.clients.akvorado_yaml import load_declared_exporters
from app.clients.clickhouse import build_observed_exporters_query, normalize_exporter_address
from app.models import (
    Boundary,
    DeclaredExporter,
    ExporterHealth,
    InterfaceSpec,
    ObservedExporter,
)
from app.services.exporters import build_exporter_statuses

NOW = datetime(2026, 8, 5, 12, 0, 0)


# ---------------------------------------------------------------------------
# Fixtures en dur
# ---------------------------------------------------------------------------


def _declared(
    cidr: str,
    name: str,
    if_indexes: dict[int, InterfaceSpec] | None = None,
    is_catchall: bool = False,
) -> DeclaredExporter:
    return DeclaredExporter(
        cidr=cidr,
        name=name,
        if_indexes=if_indexes or {},
        is_catchall=is_catchall,
    )


def _observed(
    address: str,
    name: str,
    flows: int = 100,
    bytes_: int = 10_000,
    last_seen: datetime | None = NOW,
    interfaces: list[str] | None = None,
) -> ObservedExporter:
    return ObservedExporter(
        address=address,
        name=name,
        flows=flows,
        bytes=bytes_,
        last_seen=last_seen,
        interfaces=interfaces or ["Gi0/1"],
    )


REALISTIC_YAML = """\
metadata:
  providers:
    - type: static
      exporters:
        192.0.2.23/32:
          name: poste-collecte
          if-indexes:
            1:
              name: Gi0/1
              description: uplink mesh
              speed: 1000
              boundary: external
            2:
              name: Gi0/2
              description: lan interne
              speed: 1000
              boundary: internal
        192.0.2.24/32:
          name: routeur-agence-01
          if-indexes:
            1:
              name: Gi0/1
              description: uplink
              speed: 1000
              boundary: external
        100.64.0.0/10:
          name: mesh-catchall
          default:
            name: unknown
            boundary: undefined
"""

MALFORMED_YAML = """\
metadata:
  providers:
    - type: static
      exporters: [this, is, not, a, map
"""

EMPTY_SECTION_YAML = """\
metadata:
  providers: []
"""


# ---------------------------------------------------------------------------
# Normalisation IPv6-mapped -> IPv4
# ---------------------------------------------------------------------------


class TestNormalizeExporterAddress:
    def test_ipv6_mapped_to_ipv4(self) -> None:
        assert normalize_exporter_address("::ffff:192.0.2.18") == "192.0.2.18"

    def test_plain_ipv4_passthrough(self) -> None:
        assert normalize_exporter_address("192.0.2.18") == "192.0.2.18"

    def test_uppercase_prefix(self) -> None:
        assert normalize_exporter_address("::FFFF:192.0.2.18") == "192.0.2.18"

    def test_genuine_ipv6_unchanged(self) -> None:
        # Une IPv6 native (pas mappée v4) doit rester telle quelle, non tronquée.
        addr = "2001:db8::1"
        assert normalize_exporter_address(addr) == addr


# ---------------------------------------------------------------------------
# Construction de requête ClickHouse — paramétrage exclusif
# ---------------------------------------------------------------------------


class TestBuildObservedExportersQuery:
    def test_returns_sql_and_parameters(self) -> None:
        sql, parameters = build_observed_exporters_query("1 HOUR")
        assert isinstance(sql, str)
        assert isinstance(parameters, dict)

    def test_malicious_window_is_rejected_before_reaching_sql(self) -> None:
        """Une fenêtre forgée n'atteint jamais le SQL : elle est rejetée en amont.

        `interval_to_seconds()` n'accepte que les littéraux d'une table fermée ;
        toute autre valeur lève ValueError. C'est une garde plus forte que la
        simple liaison de paramètre : la valeur est refusée, pas juste échappée.
        """
        with pytest.raises(ValueError):
            build_observed_exporters_query("1 HOUR); DROP TABLE flows; --")

    def test_window_transits_as_bound_parameter_never_in_sql(self) -> None:
        sql, parameters = build_observed_exporters_query("1 HOUR")
        # La fenêtre transite en secondes, en paramètre lié, jamais dans la chaîne.
        assert "3600" not in sql
        assert parameters == {"window_seconds": 3600}

    def test_sql_references_fixed_table_literal(self) -> None:
        sql, _ = build_observed_exporters_query("1 HOUR")
        assert "default.flows" in sql

    def test_sql_uses_clickhouse_param_placeholder_syntax(self) -> None:
        """La forme doit être `toIntervalSecond({p:UInt32})`, pas `INTERVAL {p:String}`.

        Mesuré le 2026-08-05 sur la vraie base : `INTERVAL {p:String}` est refusé
        par ClickHouse (SYNTAX_ERROR) — la clause INTERVAL exige un littéral.
        Ce test verrouille la seule forme qui accepte un paramètre lié.
        """
        sql, params = build_observed_exporters_query("6 HOUR")
        assert "{window_seconds:UInt32}" in sql
        assert "toIntervalSecond(" in sql
        assert "INTERVAL {" not in sql
        assert params == {"window_seconds": 21600}

    def test_sql_groups_by_exporter_and_selects_required_aggregates(self) -> None:
        sql, _ = build_observed_exporters_query("24 HOUR")
        assert "ExporterAddress" in sql
        assert "ExporterName" in sql
        assert "count(" in sql
        # `Bytes * SamplingRate`, pas `Bytes` seul : ce test figeait auparavant
        # la forme FAUSSE. NetFlow échantillonné ne transporte qu'une fraction
        # des flux ; sommer `Bytes` sans réappliquer le facteur sous-estime le
        # volume d'autant. Invisible en homelab (SamplingRate = 1 partout,
        # mesuré le 2026-08-07), catastrophique sur un équipement en 1:1000.
        assert "sum(Bytes * SamplingRate)" in sql, (
            "le volume doit être ramené à l'échelle par le taux d'échantillonnage"
        )
        assert "max(TimeReceived)" in sql
        assert "groupUniqArray(InIfName)" in sql


# ---------------------------------------------------------------------------
# Parsing outlet.yaml
# ---------------------------------------------------------------------------


class TestLoadDeclaredExporters:
    def test_parses_realistic_yaml(self, tmp_path: Any) -> None:
        yaml_path = tmp_path / "outlet.yaml"
        yaml_path.write_text(REALISTIC_YAML)

        declared = load_declared_exporters(str(yaml_path))

        assert len(declared) == 3
        by_name = {d.name: d for d in declared}
        assert "poste-collecte" in by_name
        mac_mini = by_name["poste-collecte"]
        assert mac_mini.cidr == "192.0.2.23/32"
        assert mac_mini.is_catchall is False
        assert 1 in mac_mini.if_indexes
        assert mac_mini.if_indexes[1].name == "Gi0/1"
        assert mac_mini.if_indexes[1].boundary == Boundary.EXTERNAL
        assert mac_mini.if_indexes[2].boundary == Boundary.INTERNAL

    def test_detects_catchall_cidr(self, tmp_path: Any) -> None:
        yaml_path = tmp_path / "outlet.yaml"
        yaml_path.write_text(REALISTIC_YAML)

        declared = load_declared_exporters(str(yaml_path))
        by_name = {d.name: d for d in declared}

        catchall = by_name["mesh-catchall"]
        assert catchall.cidr == "100.64.0.0/10"
        assert catchall.is_catchall is True

    def test_narrow_cidr_is_not_catchall(self, tmp_path: Any) -> None:
        yaml_path = tmp_path / "outlet.yaml"
        yaml_path.write_text(REALISTIC_YAML)

        declared = load_declared_exporters(str(yaml_path))
        by_name = {d.name: d for d in declared}

        assert by_name["routeur-agence-01"].is_catchall is False

    def test_malformed_yaml_degrades_gracefully(self, tmp_path: Any) -> None:
        yaml_path = tmp_path / "outlet.yaml"
        yaml_path.write_text(MALFORMED_YAML)

        declared = load_declared_exporters(str(yaml_path))

        assert declared == []

    def test_missing_file_degrades_gracefully(self, tmp_path: Any) -> None:
        missing_path = tmp_path / "does-not-exist.yaml"

        declared = load_declared_exporters(str(missing_path))

        assert declared == []

    def test_empty_providers_section_degrades_gracefully(self, tmp_path: Any) -> None:
        yaml_path = tmp_path / "outlet.yaml"
        yaml_path.write_text(EMPTY_SECTION_YAML)

        declared = load_declared_exporters(str(yaml_path))

        assert declared == []

    def test_exporter_with_empty_if_indexes_does_not_raise(self, tmp_path: Any) -> None:
        yaml_content = """\
metadata:
  providers:
    - type: static
      exporters:
        192.0.2.99/32:
          name: no-interfaces
"""
        yaml_path = tmp_path / "outlet.yaml"
        yaml_path.write_text(yaml_content)

        declared = load_declared_exporters(str(yaml_path))

        assert len(declared) == 1
        assert declared[0].if_indexes == {}


# ---------------------------------------------------------------------------
# Logique métier — croisement déclaré x observé x ingéré
# ---------------------------------------------------------------------------


class TestBuildExporterStatusesHealthy:
    def test_nominal_healthy(self) -> None:
        declared = [
            _declared(
                "192.0.2.24/32",
                "routeur-agence-01",
                if_indexes={1: InterfaceSpec(if_index=1, name="Gi0/1", boundary=Boundary.EXTERNAL)},
            )
        ]
        observed = [_observed("192.0.2.24", "routeur-agence-01", interfaces=["Gi0/1"])]

        statuses = build_exporter_statuses(
            declared=declared,
            observed=observed,
            forwarded_by_exporter={"192.0.2.24": 1_000},
            rejected_by_exporter={},
            rejection_reasons={},
            now=NOW,
        )

        assert len(statuses) == 1
        assert statuses[0].health == ExporterHealth.HEALTHY
        assert statuses[0].address == "192.0.2.24"

    def test_edge_healthy_multiple_interfaces_all_known(self) -> None:
        declared = [
            _declared(
                "192.0.2.30/32",
                "edge-router",
                if_indexes={
                    1: InterfaceSpec(if_index=1, name="Gi0/1"),
                    2: InterfaceSpec(if_index=2, name="Gi0/2"),
                },
            )
        ]
        observed = [_observed("192.0.2.30", "edge-router", interfaces=["Gi0/1", "Gi0/2"])]

        statuses = build_exporter_statuses(
            declared=declared,
            observed=observed,
            forwarded_by_exporter={"192.0.2.30": 42},
            rejected_by_exporter={},
            rejection_reasons={},
            now=NOW,
        )

        assert statuses[0].health == ExporterHealth.HEALTHY


class TestBuildExporterStatusesSilent:
    def test_nominal_silent_declared_no_flows(self) -> None:
        declared = [_declared("192.0.2.40/32", "silent-node")]

        statuses = build_exporter_statuses(
            declared=declared,
            observed=[],
            forwarded_by_exporter={},
            rejected_by_exporter={},
            rejection_reasons={},
            now=NOW,
        )

        assert len(statuses) == 1
        assert statuses[0].health == ExporterHealth.SILENT
        assert statuses[0].address == "192.0.2.40"

    def test_edge_silent_last_seen_outside_window_no_massive_rejection(self) -> None:
        declared = [_declared("192.0.2.41/32", "stale-node")]
        # La requête ClickHouse est déjà bornée par la fenêtre en amont : un
        # exportateur à flux longs peu fréquents peut ne renvoyer aucune ligne
        # sur la fenêtre courante sans qu'il y ait le moindre rejet à
        # l'ingestion (rejected_total == 0) — c'est le cas SILENT pur, à
        # distinguer explicitement du cas REJECTED.
        statuses = build_exporter_statuses(
            declared=declared,
            observed=[],
            forwarded_by_exporter={},
            rejected_by_exporter={"192.0.2.41": 0},
            rejection_reasons={},
            now=NOW,
        )

        assert statuses[0].health == ExporterHealth.SILENT


class TestBuildExporterStatusesUndeclared:
    def test_nominal_undeclared_matches_only_catchall(self) -> None:
        declared = [_declared("100.64.0.0/10", "mesh-catchall", is_catchall=True)]
        observed = [_observed("192.0.2.77", "unknown-host")]

        statuses = build_exporter_statuses(
            declared=declared,
            observed=observed,
            forwarded_by_exporter={"192.0.2.77": 500},
            rejected_by_exporter={},
            rejection_reasons={},
            now=NOW,
        )

        assert len(statuses) == 1
        assert statuses[0].health == ExporterHealth.UNDECLARED

    def test_edge_undeclared_no_declaration_at_all(self) -> None:
        statuses = build_exporter_statuses(
            declared=[],
            observed=[_observed("192.0.2.88", "ghost-host")],
            forwarded_by_exporter={"192.0.2.88": 10},
            rejected_by_exporter={},
            rejection_reasons={},
            now=NOW,
        )

        assert statuses[0].health == ExporterHealth.UNDECLARED


class TestBuildExporterStatusesUnknownInterface:
    def test_nominal_unknown_interface(self) -> None:
        declared = [
            _declared(
                "192.0.2.50/32",
                "partial-node",
                if_indexes={1: InterfaceSpec(if_index=1, name="Gi0/1")},
            )
        ]
        observed = [_observed("192.0.2.50", "partial-node", interfaces=["Gi0/1", "Gi0/99"])]

        statuses = build_exporter_statuses(
            declared=declared,
            observed=observed,
            forwarded_by_exporter={"192.0.2.50": 200},
            rejected_by_exporter={},
            rejection_reasons={},
            now=NOW,
        )

        assert statuses[0].health == ExporterHealth.UNKNOWN_INTERFACE

    def test_edge_all_interfaces_unknown(self) -> None:
        declared = [
            _declared(
                "192.0.2.51/32",
                "renamed-ifaces",
                if_indexes={1: InterfaceSpec(if_index=1, name="Gi0/1")},
            )
        ]
        observed = [_observed("192.0.2.51", "renamed-ifaces", interfaces=["eth0"])]

        statuses = build_exporter_statuses(
            declared=declared,
            observed=observed,
            forwarded_by_exporter={"192.0.2.51": 10},
            rejected_by_exporter={},
            rejection_reasons={},
            now=NOW,
        )

        assert statuses[0].health == ExporterHealth.UNKNOWN_INTERFACE


class TestBuildExporterStatusesRejected:
    def test_real_case_18_rejected(self) -> None:
        """Cas réel .18 : rejeté massivement, 0 forwarded, dernier flux ancien."""
        declared = [_declared("192.0.2.18/32", "softflowd-node")]
        old_flow = NOW - timedelta(days=4)
        observed = [
            _observed(
                "192.0.2.18",
                "softflowd-node",
                flows=12,
                last_seen=old_flow,
                interfaces=[],
            )
        ]

        statuses = build_exporter_statuses(
            declared=declared,
            observed=observed,
            forwarded_by_exporter={"192.0.2.18": 0},
            rejected_by_exporter={"192.0.2.18": 2_161_545},
            rejection_reasons={"192.0.2.18": {"input and output interfaces missing": 2_161_545}},
            now=NOW,
        )

        assert len(statuses) == 1
        status = statuses[0]
        assert status.health == ExporterHealth.REJECTED
        assert status.rejected_total == 2_161_545
        assert status.forwarded_total == 0
        assert "softflowd" in status.explanation.lower()

    def test_edge_rejected_with_zero_recent_flows_no_forwarded(self) -> None:
        declared = [_declared("192.0.2.19/32", "rejected-no-flows")]

        statuses = build_exporter_statuses(
            declared=declared,
            observed=[],
            forwarded_by_exporter={"192.0.2.19": 0},
            rejected_by_exporter={"192.0.2.19": 500},
            rejection_reasons={"192.0.2.19": {"input and output interfaces missing": 500}},
            now=NOW,
        )

        assert statuses[0].health == ExporterHealth.REJECTED


class TestBuildExporterStatusesSortOrder:
    def test_problems_sorted_first_by_severity_then_volume(self) -> None:
        declared = [
            _declared(
                "192.0.2.24/32",
                "healthy-node",
                if_indexes={1: InterfaceSpec(if_index=1, name="Gi0/1")},
            ),
            _declared("192.0.2.18/32", "rejected-node"),
            _declared("192.0.2.40/32", "silent-node"),
        ]
        observed = [
            _observed("192.0.2.24", "healthy-node", interfaces=["Gi0/1"], flows=1000),
            _observed("192.0.2.18", "rejected-node", flows=5, interfaces=[]),
        ]

        statuses = build_exporter_statuses(
            declared=declared,
            observed=observed,
            forwarded_by_exporter={"192.0.2.24": 1000, "192.0.2.18": 0},
            rejected_by_exporter={"192.0.2.18": 2_161_545},
            rejection_reasons={"192.0.2.18": {"input and output interfaces missing": 2_161_545}},
            now=NOW,
        )

        healths = [s.health for s in statuses]
        # Les problèmes (severity >= 3) doivent précéder le sain (severity 0).
        assert healths[-1] == ExporterHealth.HEALTHY
        assert ExporterHealth.REJECTED in healths[:2]
        assert ExporterHealth.SILENT in healths[:2]


# ---------------------------------------------------------------------------
# Router FastAPI
# ---------------------------------------------------------------------------


def _make_test_app() -> Any:
    """Construit une app FastAPI minimale montant uniquement le router du LOT 1.

    Isolé de app.main (LOT 0, potentiellement absent/non stable pendant le
    développement en parallèle) : on monte juste le router testé ici.
    """
    from fastapi import FastAPI

    from app.routers import exporters as exporters_router
    from app.templating import build_templates

    test_app = FastAPI()
    templates = build_templates()
    test_app.state.templates = templates
    test_app.include_router(exporters_router.router)
    return test_app


class TestExportersRouter:
    def test_api_exporters_returns_200_and_conforms(self, monkeypatch: Any) -> None:
        async def fake_load_exporter_statuses(window: str) -> list[Any]:
            return [
                _status_healthy(),
            ]

        from app.routers import exporters as exporters_router

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", fake_load_exporter_statuses)

        client = TestClient(_make_test_app())
        response = client.get("/api/exporters")

        assert response.status_code == 200
        payload = response.json()
        assert "items" in payload
        assert "total" in payload
        assert payload["total"] == 1
        assert payload["items"][0]["health"] == "healthy"

    def test_api_exporters_invalid_window_returns_422(self) -> None:
        client = TestClient(_make_test_app())
        response = client.get("/api/exporters", params={"window": "5m"})

        assert response.status_code == 422

    def test_get_exporters_page_returns_html(self, monkeypatch: Any) -> None:
        async def fake_load_exporter_statuses(window: str) -> list[Any]:
            return [_status_healthy(), _status_rejected()]

        from app.routers import exporters as exporters_router

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", fake_load_exporter_statuses)

        client = TestClient(_make_test_app())
        response = client.get("/exporters")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_get_exporters_page_handles_backend_failure_gracefully(self, monkeypatch: Any) -> None:
        async def failing_load_exporter_statuses(window: str) -> list[Any]:
            raise ConnectionError("simulated backend failure for test purposes")

        from app.routers import exporters as exporters_router

        monkeypatch.setattr(
            exporters_router, "load_exporter_statuses", failing_load_exporter_statuses
        )

        client = TestClient(_make_test_app())
        response = client.get("/exporters")

        # Pas de 500 nu : la page doit rester utilisable avec un message d'erreur clair.
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert response.text  # contenu rendu, pas une stacktrace brute


def _status_healthy() -> Any:
    from app.models import ExporterStatus

    return ExporterStatus(
        address="192.0.2.24",
        name="routeur-agence-01",
        health=ExporterHealth.HEALTHY,
        declared=_declared(
            "192.0.2.24/32",
            "routeur-agence-01",
            if_indexes={1: InterfaceSpec(if_index=1, name="Gi0/1")},
        ),
        observed=_observed("192.0.2.24", "routeur-agence-01"),
        forwarded_total=1000,
        rejected_total=0,
        explanation="Tout va bien.",
    )


def _status_rejected() -> Any:
    from app.models import ExporterStatus

    return ExporterStatus(
        address="192.0.2.18",
        name="softflowd-node",
        health=ExporterHealth.REJECTED,
        declared=_declared("192.0.2.18/32", "softflowd-node"),
        observed=None,
        forwarded_total=0,
        rejected_total=2_161_545,
        rejection_reasons={"input and output interfaces missing": 2_161_545},
        explanation=(
            "Cet exportateur envoie des flux mais Akvorado les rejette tous "
            "(motif : interfaces d'entrée/sortie manquantes). "
            "Vérifier la version de softflowd (1.1.1 minimum) sur cette machine."
        ),
    )


# ---------------------------------------------------------------------------
# Rendu du template
# ---------------------------------------------------------------------------


class TestExportersTemplate:
    def test_renders_without_exception_with_representative_data(self) -> None:
        from starlette.requests import Request

        from app.templating import build_templates

        templates = build_templates()

        scope: dict[str, Any] = {
            "type": "http",
            "method": "GET",
            "path": "/exporters",
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
            "exporters.html",
            {
                "items": [_status_healthy(), _status_rejected()],
                "total": 2,
                "window": "1h",
                "window_choices": ["1h", "6h", "24h", "7d"],
                "error": None,
            },
        )

        body = bytes(response.body).decode("utf-8")
        assert "routeur-agence-01" in body
        assert "softflowd" in body.lower()
        # Autoescape actif : pas d'échappement cassé, pas de script injecté brut.
        assert "<script>" not in body

    def test_renders_error_state_without_exception(self) -> None:
        from starlette.requests import Request

        from app.templating import build_templates

        templates = build_templates()

        scope: dict[str, Any] = {
            "type": "http",
            "method": "GET",
            "path": "/exporters",
            "headers": [],
            "query_string": b"",
            "server": ("test", 80),
            "scheme": "http",
            "client": ("test", 123),
            "app": None,
        }
        request = Request(scope)

        error_message = "ClickHouse : connexion impossible (connection refused)"
        response = templates.TemplateResponse(
            request,
            "exporters.html",
            {
                "items": [],
                "total": 0,
                "window": "1h",
                "window_choices": ["1h", "6h", "24h", "7d"],
                "error": error_message,
            },
        )

        body = bytes(response.body).decode("utf-8")
        assert "connexion impossible" in body


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
