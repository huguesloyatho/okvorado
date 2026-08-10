"""Tests du LOT A — agent de restart Akvorado + client Okvorado.

RÈGLE ABSOLUE : aucun test ici n'appelle l'agent réel ni docker. L'agent est
exercé via `fastapi.testclient.TestClient` avec un `DockerClientLike` factice
injecté dans `create_app()`. Le client Okvorado est exercé avec `httpx` mocké
via `httpx.MockTransport` (aucune connexion réseau réelle).
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

# `restart-agent/` n'est pas un package Python importable normalement (tiret
# dans le nom du dossier, hors de `app/`) : on l'ajoute explicitement au path
# pour importer `agent.py`, exactement comme il tournera dans son container
# dédié (`uvicorn agent:app`, CWD = /app dans restart-agent/Dockerfile).
_RESTART_AGENT_DIR = Path(__file__).resolve().parent.parent / "restart-agent"
if str(_RESTART_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(_RESTART_AGENT_DIR))

# `agent.py` exécute `app = create_app()` à l'IMPORT du module (point d'entrée
# réel `uvicorn agent:app`), qui fail-fast si RESTART_AGENT_TOKEN est absent.
# Il faut donc une valeur en env AVANT ce premier import de collecte pytest ;
# `TestFailFastWithoutToken` exerce ensuite l'absence via `monkeypatch.delenv`
# + réimport ciblé, sans affecter cette collecte initiale.
os.environ.setdefault("RESTART_AGENT_TOKEN", "collection-time-placeholder-token")

import agent as restart_agent_module  # noqa: E402  (path + env setup ci-dessus requis avant l'import)

from app.clients import restart as restart_client  # noqa: E402

# SECRET_OK: token factice utilisé uniquement par ces tests (TestClient +
# httpx.MockTransport) — aucune infra réelle n'est jointe, jamais un secret prod.
TEST_TOKEN = "test-token-abc123"


# ---------------------------------------------------------------------------
# Doubles de test — aucun SDK docker réel
# ---------------------------------------------------------------------------


class FakeContainer:
    """Double d'un `docker.models.containers.Container`."""

    def __init__(
        self,
        name: str,
        *,
        status: str = "running",
        health_sequence: list[str | None] | None = None,
        fail_restart: bool = False,
        fail_stop: bool = False,
        fail_start: bool = False,
        call_log: list[str] | None = None,
    ) -> None:
        self.name = name
        self.status = status
        self._health_sequence = health_sequence if health_sequence is not None else ["healthy"]
        self._health_index = 0
        self.fail_restart = fail_restart
        self.fail_stop = fail_stop
        self.fail_start = fail_start
        self.restart_called = False
        self.stop_called = False
        self.start_called = False
        # Trace partagée (optionnelle) des appels, pour vérifier un ordre
        # cross-objet (ex: purge avant start).
        self.call_log = call_log

    def restart(self, timeout: int = 10) -> None:
        self.restart_called = True
        if self.call_log is not None:
            self.call_log.append("restart")
        if self.fail_restart:
            raise RuntimeError("docker restart a échoué (simulation de test)")

    def stop(self, timeout: int = 10) -> None:
        self.stop_called = True
        if self.call_log is not None:
            self.call_log.append("stop")
        if self.fail_stop:
            raise RuntimeError("docker stop a échoué (simulation de test)")

    def start(self) -> None:
        self.start_called = True
        if self.call_log is not None:
            self.call_log.append("start")
        if self.fail_start:
            raise RuntimeError("docker start a échoué (simulation de test)")

    def reload(self) -> None:
        if self._health_index < len(self._health_sequence) - 1:
            self._health_index += 1

    @property
    def health(self) -> str | None:
        return self._health_sequence[self._health_index]


class FakeDockerClient:
    """Double de `DockerClientLike` : dict nom de service -> `FakeContainer`."""

    def __init__(self, containers: dict[str, FakeContainer] | None = None) -> None:
        self._containers = containers or {}
        self.find_calls: list[str] = []

    def find_container(self, service_name: str) -> FakeContainer | None:
        self.find_calls.append(service_name)
        return self._containers.get(service_name)


def _healthy_client_for(*service_names: str) -> FakeDockerClient:
    return FakeDockerClient({name: FakeContainer(name) for name in service_names})


def _make_app(
    *,
    token: str = TEST_TOKEN,
    docker_client: FakeDockerClient | None = None,
    rate_limiter: restart_agent_module.RateLimiter | None = None,
) -> TestClient:
    app = restart_agent_module.create_app(
        token=token,
        docker_client=docker_client or _healthy_client_for(*restart_agent_module.ALLOWED_SERVICES),
        rate_limiter=rate_limiter,
    )
    return TestClient(app)


def _auth_header(token: str = TEST_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# GET /health — sans auth
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_health_returns_ok_without_auth(self) -> None:
        client = _make_app()
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "service": "okvorado-restart-agent"}


# ---------------------------------------------------------------------------
# Allowlist — coeur de la sécurité
# ---------------------------------------------------------------------------


class TestAllowlist:
    @pytest.mark.parametrize("service", sorted(restart_agent_module.ALLOWED_SERVICES))
    def test_allowed_service_accepted(self, service: str) -> None:
        validated = restart_agent_module.validate_requested_services([service])
        assert validated == [service]

    @pytest.mark.parametrize(
        "malicious_name",
        [
            "; rm -rf /",
            "../etc",
            "clickhouse",  # exclu volontairement : jamais de restart de la base
            "",
            "akvorado-outlet; rm -rf /",
            "akvorado-outlet && cat /etc/passwd",
            "ClickHouse",  # variation de casse : pas d'allowlist floue
            "アクボラド",  # unicode
            "akvorado-outlet\x00",  # null byte
            "../../root/akvorado/docker-compose.yml",
        ],
    )
    def test_malicious_or_unknown_service_rejected(self, malicious_name: str) -> None:
        with pytest.raises(restart_agent_module.RestartAgentError) as exc_info:
            restart_agent_module.validate_requested_services([malicious_name])
        assert exc_info.value.status_code == 403

    def test_empty_list_rejected(self) -> None:
        with pytest.raises(restart_agent_module.RestartAgentError) as exc_info:
            restart_agent_module.validate_requested_services([])
        assert exc_info.value.status_code == 403

    def test_mix_of_allowed_and_malicious_rejects_whole_request(self) -> None:
        with pytest.raises(restart_agent_module.RestartAgentError) as exc_info:
            restart_agent_module.validate_requested_services(["akvorado-outlet", "; rm -rf /"])
        assert exc_info.value.status_code == 403

    def test_endpoint_returns_403_for_malicious_service(self) -> None:
        docker_client = _healthy_client_for(*restart_agent_module.ALLOWED_SERVICES)
        client = _make_app(docker_client=docker_client)
        response = client.post(
            "/restart", json={"services": ["; rm -rf /"]}, headers=_auth_header()
        )
        assert response.status_code == 403
        # Garde n°2 : le container factice ne doit JAMAIS avoir été consulté.
        assert docker_client.find_calls == []

    def test_endpoint_returns_403_for_clickhouse(self) -> None:
        docker_client = _healthy_client_for(*restart_agent_module.ALLOWED_SERVICES, "clickhouse")
        client = _make_app(docker_client=docker_client)
        response = client.post(
            "/restart", json={"services": ["clickhouse"]}, headers=_auth_header()
        )
        assert response.status_code == 403
        assert docker_client.find_calls == []


# ---------------------------------------------------------------------------
# Token — comparaison temps constant, 401
# ---------------------------------------------------------------------------


class TestTokenAuth:
    def test_missing_token_returns_401(self) -> None:
        client = _make_app()
        response = client.post("/restart", json={"services": ["akvorado-outlet"]})
        assert response.status_code == 401

    def test_wrong_token_returns_401(self) -> None:
        client = _make_app()
        response = client.post(
            "/restart",
            json={"services": ["akvorado-outlet"]},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert response.status_code == 401

    def test_malformed_header_returns_401(self) -> None:
        client = _make_app()
        response = client.post(
            "/restart",
            json={"services": ["akvorado-outlet"]},
            headers={"Authorization": TEST_TOKEN},  # sans préfixe "Bearer "
        )
        assert response.status_code == 401

    def test_correct_token_passes_auth(self) -> None:
        client = _make_app()
        response = client.post(
            "/restart", json={"services": ["akvorado-outlet"]}, headers=_auth_header()
        )
        assert response.status_code == 200

    def test_status_endpoint_requires_token(self) -> None:
        client = _make_app()
        response = client.get("/status")
        assert response.status_code == 401

    def test_check_token_uses_constant_time_comparison(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`hmac.compare_digest` doit être l'unique mécanisme de comparaison."""
        calls: list[tuple[Any, Any]] = []
        original = restart_agent_module.hmac.compare_digest

        def _spy_compare_digest(a: Any, b: Any) -> bool:
            calls.append((a, b))
            result: bool = original(a, b)
            return result

        monkeypatch.setattr(restart_agent_module.hmac, "compare_digest", _spy_compare_digest)
        restart_agent_module.check_token(f"Bearer {TEST_TOKEN}", TEST_TOKEN)
        assert calls == [(TEST_TOKEN, TEST_TOKEN)]


# ---------------------------------------------------------------------------
# Fail-fast au démarrage sans RESTART_AGENT_TOKEN
# ---------------------------------------------------------------------------


class TestFailFastWithoutToken:
    def test_create_app_raises_without_token_and_without_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("RESTART_AGENT_TOKEN", raising=False)
        with pytest.raises(RuntimeError, match="RESTART_AGENT_TOKEN"):
            restart_agent_module.create_app()

    def test_create_app_reads_token_from_env_when_not_passed_explicitly(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("RESTART_AGENT_TOKEN", "env-token-xyz")
        app = restart_agent_module.create_app(
            docker_client=_healthy_client_for(*restart_agent_module.ALLOWED_SERVICES)
        )
        client = TestClient(app)
        response = client.post(
            "/restart",
            json={"services": ["akvorado-outlet"]},
            headers={"Authorization": "Bearer env-token-xyz"},
        )
        assert response.status_code == 200

    def test_module_level_app_import_fails_without_env_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Reproduit le vrai point d'entrée (`uvicorn agent:app`) : sans variable
        d'env au moment du chargement du module, l'import doit échouer."""
        monkeypatch.delenv("RESTART_AGENT_TOKEN", raising=False)
        # Force un rechargement du module pour ré-exécuter `app = create_app()`.
        sys.modules.pop("agent", None)
        with pytest.raises(RuntimeError, match="RESTART_AGENT_TOKEN"):
            importlib.import_module("agent")
        sys.modules.pop("agent", None)
        monkeypatch.setenv("RESTART_AGENT_TOKEN", TEST_TOKEN)
        importlib.import_module("agent")  # remet un état sain pour la suite de la session
        sys.modules.pop("agent", None)


# ---------------------------------------------------------------------------
# Rate-limit
# ---------------------------------------------------------------------------


class TestRateLimit:
    def test_second_immediate_call_returns_429(self) -> None:
        limiter = restart_agent_module.RateLimiter(interval_seconds=30.0)
        client = _make_app(rate_limiter=limiter)

        first = client.post(
            "/restart", json={"services": ["akvorado-outlet"]}, headers=_auth_header()
        )
        second = client.post(
            "/restart", json={"services": ["akvorado-outlet"]}, headers=_auth_header()
        )

        assert first.status_code == 200
        assert second.status_code == 429

    def test_rate_limiter_check_allows_after_interval_elapsed(self) -> None:
        limiter = restart_agent_module.RateLimiter(interval_seconds=0.0)
        limiter.check()
        limiter.check()  # ne doit pas lever : intervalle nul toujours écoulé

    def test_rate_limiter_check_raises_429_immediately(self) -> None:
        limiter = restart_agent_module.RateLimiter(interval_seconds=30.0)
        limiter.check()
        with pytest.raises(restart_agent_module.RestartAgentError) as exc_info:
            limiter.check()
        assert exc_info.value.status_code == 429

    def test_rate_limit_checked_after_auth_and_allowlist(self) -> None:
        """Un appel non authentifié ne doit pas consommer le rate-limit."""
        limiter = restart_agent_module.RateLimiter(interval_seconds=30.0)
        client = _make_app(rate_limiter=limiter)

        unauthenticated = client.post("/restart", json={"services": ["akvorado-outlet"]})
        authenticated = client.post(
            "/restart", json={"services": ["akvorado-outlet"]}, headers=_auth_header()
        )

        assert unauthenticated.status_code == 401
        assert authenticated.status_code == 200  # le rate-limit n'a pas été consommé avant


# ---------------------------------------------------------------------------
# Ordre déterministe de restart
# ---------------------------------------------------------------------------


class TestRestartOrder:
    def test_orchestrator_before_outlet(self) -> None:
        ordered = restart_agent_module.order_services(["akvorado-outlet", "akvorado-orchestrator"])
        assert ordered == ["akvorado-orchestrator", "akvorado-outlet"]

    def test_full_order_is_deterministic(self) -> None:
        shuffled = [
            "akvorado-console",
            "akvorado-outlet",
            "akvorado-inlet",
            "akvorado-orchestrator",
        ]
        assert restart_agent_module.order_services(shuffled) == [
            "akvorado-orchestrator",
            "akvorado-inlet",
            "akvorado-outlet",
            "akvorado-console",
        ]

    def test_order_is_stable_regardless_of_input_order(self) -> None:
        first = restart_agent_module.order_services(["akvorado-console", "akvorado-outlet"])
        second = restart_agent_module.order_services(["akvorado-outlet", "akvorado-console"])
        assert first == second == ["akvorado-outlet", "akvorado-console"]

    def test_deduplicates_requested_services(self) -> None:
        ordered = restart_agent_module.order_services(
            ["akvorado-outlet", "akvorado-outlet", "akvorado-orchestrator"]
        )
        assert ordered == ["akvorado-orchestrator", "akvorado-outlet"]

    def test_endpoint_restarts_in_deterministic_order(self) -> None:
        docker_client = _healthy_client_for(*restart_agent_module.ALLOWED_SERVICES)
        client = _make_app(docker_client=docker_client)
        response = client.post(
            "/restart",
            json={"services": ["akvorado-console", "akvorado-outlet", "akvorado-orchestrator"]},
            headers=_auth_header(),
        )
        assert response.status_code == 200
        body = response.json()
        restarted_order = [report["service"] for report in body["reports"]]
        assert restarted_order == ["akvorado-orchestrator", "akvorado-outlet", "akvorado-console"]


# ---------------------------------------------------------------------------
# restart_service — jamais de faux succès
# ---------------------------------------------------------------------------


class TestRestartServiceHealthCheck:
    def test_container_becomes_healthy_reports_success(self) -> None:
        container = FakeContainer("akvorado-outlet", health_sequence=["starting", "healthy"])
        docker_client = FakeDockerClient({"akvorado-outlet": container})

        report = restart_agent_module.restart_service(
            docker_client,
            "akvorado-outlet",
            healthy_timeout_seconds=10.0,
            poll_interval_seconds=0.0,
            sleep=lambda _seconds: None,
        )

        assert report.restarted is True
        assert report.healthy is True
        assert report.error is None
        assert container.restart_called is True

    def test_container_never_healthy_reports_healthy_false_not_success(self) -> None:
        container = FakeContainer("akvorado-outlet", health_sequence=["starting", "unhealthy"])
        docker_client = FakeDockerClient({"akvorado-outlet": container})

        fake_time = {"now": 0.0}

        def fake_now() -> float:
            return fake_time["now"]

        def fake_sleep(seconds: float) -> None:
            fake_time["now"] += seconds

        report = restart_agent_module.restart_service(
            docker_client,
            "akvorado-outlet",
            healthy_timeout_seconds=5.0,
            poll_interval_seconds=1.0,
            sleep=fake_sleep,
            now=fake_now,
        )

        assert report.restarted is True
        assert report.healthy is False
        assert report.error is not None
        assert "healthy" in report.error.lower()

    def test_container_not_found_reports_healthy_false_without_restart_attempt(self) -> None:
        docker_client = FakeDockerClient({})  # aucun container connu

        report = restart_agent_module.restart_service(docker_client, "akvorado-outlet")

        assert report.restarted is False
        assert report.healthy is False
        assert report.error is not None

    def test_docker_restart_exception_reports_healthy_false(self) -> None:
        container = FakeContainer("akvorado-outlet", fail_restart=True)
        docker_client = FakeDockerClient({"akvorado-outlet": container})

        report = restart_agent_module.restart_service(docker_client, "akvorado-outlet")

        assert report.restarted is False
        assert report.healthy is False
        assert report.error is not None

    def test_no_healthcheck_defined_never_claims_healthy(self) -> None:
        """Un container sans healthcheck (`health=None`) ne doit jamais être
        rapporté comme sain — on ne peut pas prouver ce qu'on ne mesure pas."""
        container = FakeContainer("akvorado-console", health_sequence=[None])
        docker_client = FakeDockerClient({"akvorado-console": container})

        report = restart_agent_module.restart_service(
            docker_client,
            "akvorado-console",
            healthy_timeout_seconds=5.0,
            poll_interval_seconds=0.0,
            sleep=lambda _seconds: None,
        )

        assert report.healthy is False

    def test_report_includes_duration(self) -> None:
        container = FakeContainer("akvorado-outlet", health_sequence=["healthy"])
        docker_client = FakeDockerClient({"akvorado-outlet": container})

        report = restart_agent_module.restart_service(docker_client, "akvorado-outlet")

        assert report.duration_seconds >= 0.0


# ---------------------------------------------------------------------------
# Purge du cache de metadata — optionnelle, explicite, gardée
# ---------------------------------------------------------------------------


class TestResolveMetadataCachePath:
    def test_default_path_resolves(self) -> None:
        resolved = restart_agent_module.resolve_metadata_cache_path(
            restart_agent_module.DEFAULT_METADATA_CACHE_PATH
        )
        assert resolved.name == "metadata.cache"
        assert str(resolved) == restart_agent_module.DEFAULT_METADATA_CACHE_PATH

    def test_custom_path_under_allowed_parent_resolves(self) -> None:
        resolved = restart_agent_module.resolve_metadata_cache_path(
            "/data/akvorado/run/metadata.cache"
        )
        assert resolved.name == "metadata.cache"

    @pytest.mark.parametrize(
        "bad_path",
        [
            "/data/akvorado/run/other.cache",  # mauvais nom de fichier
            "/etc/passwd",  # hors répertoire, mauvais nom
            "/data/akvorado/run/../../etc/metadata.cache",  # tentative de sortie
            "/tmp/metadata.cache",  # bon nom, mauvais répertoire
            "/data/akvorado/metadata.cache",  # pas dans le sous-répertoire run/
        ],
    )
    def test_path_outside_allowed_parent_or_wrong_name_rejected(self, bad_path: str) -> None:
        with pytest.raises(restart_agent_module.MetadataCachePathError):
            restart_agent_module.resolve_metadata_cache_path(bad_path)


class TestPurgeMetadataCache:
    def test_purge_existing_file_removes_it(self, tmp_path: Path) -> None:
        cache_file = tmp_path / "metadata.cache"
        cache_file.write_text("stale-cache-content")

        report = restart_agent_module.purge_metadata_cache(cache_file)

        assert report.purged is True
        assert not cache_file.exists()

    def test_purge_absent_file_is_not_an_error(self, tmp_path: Path) -> None:
        cache_file = tmp_path / "metadata.cache"  # jamais créé
        assert not cache_file.exists()

        report = restart_agent_module.purge_metadata_cache(cache_file)

        assert report.purged is False
        assert report.requested is True
        assert report.message is not None

    def test_purge_permission_error_does_not_raise(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache_file = tmp_path / "metadata.cache"
        cache_file.write_text("stale-cache-content")

        def _raise_permission_error(self: Path) -> None:
            raise PermissionError("permission denied (simulation de test)")

        monkeypatch.setattr(Path, "unlink", _raise_permission_error)

        report = restart_agent_module.purge_metadata_cache(cache_file)

        assert report.purged is False
        assert report.message is not None
        assert "permission" in report.message.lower() or "denied" in report.message.lower()


class TestRestartServiceWithCachePurge:
    def test_purge_requested_file_present_removes_and_reports(self, tmp_path: Path) -> None:
        cache_file = tmp_path / "metadata.cache"
        cache_file.write_text("stale")
        container = FakeContainer("akvorado-outlet", health_sequence=["healthy"])
        docker_client = FakeDockerClient({"akvorado-outlet": container})

        report = restart_agent_module.restart_service(
            docker_client, "akvorado-outlet", purge_cache_path=cache_file
        )

        assert not cache_file.exists()
        assert report.cache_purged is True
        assert container.stop_called is True
        assert container.start_called is True
        assert container.restart_called is False  # séquence stop/start, pas restart()

    def test_purge_requested_file_absent_continues_sequence(self, tmp_path: Path) -> None:
        cache_file = tmp_path / "metadata.cache"  # jamais créé
        container = FakeContainer("akvorado-outlet", health_sequence=["healthy"])
        docker_client = FakeDockerClient({"akvorado-outlet": container})

        report = restart_agent_module.restart_service(
            docker_client, "akvorado-outlet", purge_cache_path=cache_file
        )

        assert report.cache_purged is False
        assert report.healthy is True  # la séquence continue malgré l'absence
        assert container.start_called is True

    def test_no_purge_requested_file_left_intact(self, tmp_path: Path) -> None:
        cache_file = tmp_path / "metadata.cache"
        cache_file.write_text("still-here")
        container = FakeContainer("akvorado-outlet", health_sequence=["healthy"])
        docker_client = FakeDockerClient({"akvorado-outlet": container})

        report = restart_agent_module.restart_service(
            docker_client, "akvorado-outlet"
        )  # purge_cache_path=None par défaut

        assert cache_file.exists()
        assert cache_file.read_text() == "still-here"
        assert report.cache_purged is False
        assert container.restart_called is True
        assert container.stop_called is False
        assert container.start_called is False

    def test_purge_happens_before_effective_restart_start(self, tmp_path: Path) -> None:
        """L'ordre compte : stop -> purge -> start, jamais purge après coup."""
        cache_file = tmp_path / "metadata.cache"
        cache_file.write_text("stale")
        call_log: list[str] = []

        class _TracingContainer(FakeContainer):
            def stop(self, timeout: int = 10) -> None:
                super().stop(timeout=timeout)

            def start(self) -> None:
                # Au moment où start() est appelé, le fichier doit déjà avoir
                # été supprimé (garde l'ordre stop -> purge -> start réel).
                assert not cache_file.exists()
                super().start()

        container = _TracingContainer(
            "akvorado-outlet", health_sequence=["healthy"], call_log=call_log
        )
        docker_client = FakeDockerClient({"akvorado-outlet": container})

        report = restart_agent_module.restart_service(
            docker_client, "akvorado-outlet", purge_cache_path=cache_file
        )

        assert call_log == ["stop", "start"]
        assert report.cache_purged is True

    def test_stop_failure_reports_error_without_start(self, tmp_path: Path) -> None:
        cache_file = tmp_path / "metadata.cache"
        cache_file.write_text("stale")
        container = FakeContainer("akvorado-outlet", fail_stop=True)
        docker_client = FakeDockerClient({"akvorado-outlet": container})

        report = restart_agent_module.restart_service(
            docker_client, "akvorado-outlet", purge_cache_path=cache_file
        )

        assert report.restarted is False
        assert report.healthy is False
        assert container.start_called is False
        # Le stop a échoué avant la purge : le fichier n'est pas censé avoir
        # été touché par cette tentative.
        assert cache_file.exists()


class TestRestartRequestPurgeFlag:
    def test_purge_defaults_to_false(self) -> None:
        request = restart_agent_module.RestartRequest(services=["akvorado-outlet"])
        assert request.purge_metadata_cache is False

    def test_endpoint_default_does_not_purge(self, tmp_path: Path) -> None:
        cache_file = tmp_path / "metadata.cache"
        cache_file.write_text("still-here")
        docker_client = _healthy_client_for(*restart_agent_module.ALLOWED_SERVICES)
        app = restart_agent_module.create_app(
            token=TEST_TOKEN,
            docker_client=docker_client,
            metadata_cache_path_raw=str(cache_file),
        )
        client = TestClient(app)

        response = client.post(
            "/restart", json={"services": ["akvorado-outlet"]}, headers=_auth_header()
        )

        assert response.status_code == 200
        assert cache_file.exists()
        body = response.json()
        assert body["reports"][0]["cache_purged"] is False

    def test_endpoint_purge_true_removes_configured_file(self, tmp_path: Path) -> None:
        cache_file = tmp_path / "metadata.cache"
        cache_file.write_text("stale")
        docker_client = _healthy_client_for(*restart_agent_module.ALLOWED_SERVICES)
        app = restart_agent_module.create_app(
            token=TEST_TOKEN,
            docker_client=docker_client,
            metadata_cache_path_raw=str(cache_file),
            metadata_cache_allowed_parent=tmp_path,
        )
        client = TestClient(app)

        response = client.post(
            "/restart",
            json={"services": ["akvorado-outlet"], "purge_metadata_cache": True},
            headers=_auth_header(),
        )

        assert response.status_code == 200
        assert not cache_file.exists()
        body = response.json()
        assert body["reports"][0]["cache_purged"] is True

    def test_path_cannot_be_injected_from_request_body(self, tmp_path: Path) -> None:
        """Garde critique : même en tentant de fournir un chemin dans le
        corps de la requête, seul le chemin de la config serveur est utilisé
        — un attaquant en possession du token ne peut PAS choisir le fichier
        supprimé."""
        server_configured_cache = tmp_path / "metadata.cache"
        server_configured_cache.write_text("stale")
        attacker_target = tmp_path / "attacker_target.txt"
        attacker_target.write_text("do-not-delete-me")

        docker_client = _healthy_client_for(*restart_agent_module.ALLOWED_SERVICES)
        app = restart_agent_module.create_app(
            token=TEST_TOKEN,
            docker_client=docker_client,
            metadata_cache_path_raw=str(server_configured_cache),
            metadata_cache_allowed_parent=tmp_path,
        )
        client = TestClient(app)

        response = client.post(
            "/restart",
            json={
                "services": ["akvorado-outlet"],
                "purge_metadata_cache": True,
                # Champs non déclarés dans RestartRequest : Pydantic les
                # ignore silencieusement, ils ne doivent influencer AUCUN
                # comportement.
                "metadata_cache_path": str(attacker_target),
                "cache_path": str(attacker_target),
                "path": str(attacker_target),
            },
            headers=_auth_header(),
        )

        assert response.status_code == 200
        # Le fichier configuré serveur est purgé...
        assert not server_configured_cache.exists()
        # ...et la cible de l'attaquant n'a jamais été touchée.
        assert attacker_target.exists()
        assert attacker_target.read_text() == "do-not-delete-me"

    def test_endpoint_purge_true_but_path_outside_allowed_parent_refuses_silently(
        self, tmp_path: Path
    ) -> None:
        """Si la config serveur elle-même pointe hors du répertoire attendu
        (erreur de déploiement), la purge est refusée et le restart continue
        sans purge plutôt que d'échouer ou de supprimer un chemin non gardé."""
        outside_file = tmp_path / "not-named-correctly.txt"
        outside_file.write_text("should-never-be-touched")
        docker_client = _healthy_client_for(*restart_agent_module.ALLOWED_SERVICES)
        app = restart_agent_module.create_app(
            token=TEST_TOKEN,
            docker_client=docker_client,
            metadata_cache_path_raw=str(outside_file),  # mauvais nom de fichier
        )
        client = TestClient(app)

        response = client.post(
            "/restart",
            json={"services": ["akvorado-outlet"], "purge_metadata_cache": True},
            headers=_auth_header(),
        )

        assert response.status_code == 200
        assert outside_file.exists()  # jamais touché
        body = response.json()
        assert body["reports"][0]["cache_purged"] is False


# ---------------------------------------------------------------------------
# /status endpoint
# ---------------------------------------------------------------------------


class TestStatusEndpoint:
    def test_status_returns_all_allowed_services(self) -> None:
        docker_client = _healthy_client_for(*restart_agent_module.ALLOWED_SERVICES)
        client = _make_app(docker_client=docker_client)

        response = client.get("/status", headers=_auth_header())

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == len(restart_agent_module.ALLOWED_SERVICES)
        services_in_response = {item["service"] for item in body["items"]}
        assert services_in_response == set(restart_agent_module.ALLOWED_SERVICES)

    def test_status_marks_missing_container_as_absent(self) -> None:
        docker_client = FakeDockerClient({})  # aucun container présent
        client = _make_app(docker_client=docker_client)

        response = client.get("/status", headers=_auth_header())

        assert response.status_code == 200
        body = response.json()
        assert all(item["status"] == "absent" for item in body["items"])


# ---------------------------------------------------------------------------
# Client Okvorado (app/clients/restart.py) — httpx mocké, jamais d'appel réel
# ---------------------------------------------------------------------------


class _StubSettings:
    """Double minimal de `app.config.settings` pour le client."""

    def __init__(
        self,
        *,
        restart_agent_host: str = "restart-agent",
        restart_agent_port: int = 8098,
        restart_agent_token: str = TEST_TOKEN,
        restart_timeout_seconds: float = 150.0,
    ) -> None:
        self.restart_agent_host = restart_agent_host
        self.restart_agent_port = restart_agent_port
        self.restart_agent_token = restart_agent_token
        self.restart_timeout_seconds = restart_timeout_seconds


def _mock_transport(handler: Any) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _patch_client_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tous les tests du client utilisent un double de settings par défaut,
    surchargeable au cas par cas via `monkeypatch.setattr` dans le test."""
    monkeypatch.setattr(restart_client, "settings", _StubSettings())


def _patch_async_client_with_handler(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    original_async_client = httpx.AsyncClient

    def _patched_async_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = _mock_transport(handler)
        return original_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _patched_async_client)


class TestRestartAkvoradoClient:
    async def test_unreachable_agent_raises_runtime_error_with_clear_message(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _raise_connect_error(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused (simulation de test)")

        _patch_async_client_with_handler(monkeypatch, _raise_connect_error)

        with pytest.raises(RuntimeError, match="agent de restart"):
            await restart_client.restart_akvorado(["akvorado-outlet"])

    async def test_401_raises_runtime_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"detail": "token invalide"})

        _patch_async_client_with_handler(monkeypatch, _handler)

        with pytest.raises(RuntimeError, match="authentification"):
            await restart_client.restart_akvorado(["akvorado-outlet"])

    async def test_429_raises_runtime_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, json={"detail": "trop de restarts rapprochés"})

        _patch_async_client_with_handler(monkeypatch, _handler)

        with pytest.raises(RuntimeError, match="restart"):
            await restart_client.restart_akvorado(["akvorado-outlet"])

    async def test_all_services_healthy_returns_ok_true(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "status": "ok",
                    "reports": [
                        {
                            "service": "akvorado-outlet",
                            "restarted": True,
                            "healthy": True,
                            "duration_seconds": 12.3,
                            "error": None,
                        },
                        {
                            "service": "akvorado-orchestrator",
                            "restarted": True,
                            "healthy": True,
                            "duration_seconds": 8.1,
                            "error": None,
                        },
                    ],
                },
            )

        _patch_async_client_with_handler(monkeypatch, _handler)

        result = await restart_client.restart_akvorado(["akvorado-outlet", "akvorado-orchestrator"])

        assert result.ok is True
        assert len(result.reports) == 2
        assert result.message  # phrase en clair non vide

    async def test_one_service_unhealthy_returns_ok_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "status": "degraded",
                    "reports": [
                        {
                            "service": "akvorado-outlet",
                            "restarted": True,
                            "healthy": True,
                            "duration_seconds": 12.3,
                            "error": None,
                        },
                        {
                            "service": "akvorado-console",
                            "restarted": True,
                            "healthy": False,
                            "duration_seconds": 120.0,
                            "error": "container non healthy après 120s",
                        },
                    ],
                },
            )

        _patch_async_client_with_handler(monkeypatch, _handler)

        result = await restart_client.restart_akvorado(["akvorado-outlet", "akvorado-console"])

        assert result.ok is False
        assert "akvorado-console" in result.message

    async def test_missing_settings_raises_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(restart_client, "settings", _StubSettings(restart_agent_host=""))
        with pytest.raises(RuntimeError, match="restart_agent_host"):
            await restart_client.restart_akvorado(["akvorado-outlet"])


class TestFetchAkvoradoStatusClient:
    async def test_unreachable_agent_raises_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _raise_connect_error(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused (simulation de test)")

        _patch_async_client_with_handler(monkeypatch, _raise_connect_error)

        with pytest.raises(RuntimeError, match="agent de restart"):
            await restart_client.fetch_akvorado_status()

    async def test_status_parses_items(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "status": "ok",
                    "items": [
                        {
                            "service": "akvorado-outlet",
                            "name": "akvorado-akvorado-outlet-1",
                            "status": "running",
                            "health": "healthy",
                        }
                    ],
                    "total": 1,
                },
            )

        _patch_async_client_with_handler(monkeypatch, _handler)

        status = await restart_client.fetch_akvorado_status()

        assert status.total == 1
        assert status.items[0].service == "akvorado-outlet"
        assert status.items[0].health == "healthy"
