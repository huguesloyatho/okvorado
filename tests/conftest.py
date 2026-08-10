"""Fixtures partagées par tous les lots de tests.

RÈGLE ABSOLUE : aucun test ne touche l'infrastructure réelle. Ni ClickHouse, ni
l'outlet Akvorado, ni la prod. Tout passe par des doubles de test définis ici ou
dans les fichiers de test de chaque lot.
"""
# ruff: noqa: E501
# Les échantillons ci-dessous reproduisent VERBATIM le format réel capturé en
# production : les tronquer pour respecter la longueur de ligne fausserait les
# tests de parsing, qui doivent voir exactement ce que l'outlet émet.

import sqlite3
from collections.abc import Generator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.db import SCHEMA


@pytest.fixture(autouse=True)
def base_sqlite_isolee(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    """Isole `settings.sqlite_path` dans un répertoire temporaire, pour TOUS les tests.

    DÉFAUT MESURÉ (2026-08-10), trouvé en préparant la publication du dépôt :
    la suite passait ici (1901 verts) mais 10 tests ÉCHOUAIENT sur une copie
    fraîche du code, avec `no such table: port_mappings`.

    Cause : `app/main.py` ouvre `settings.sqlite_path` (défaut `./data/okvorado.db`,
    chemin RELATIF) pour ses tâches de fond. Sur la machine de développement ce
    fichier existe, peuplé par les exécutions réelles — il masquait donc la
    dépendance. Sur un clone du dépôt (le cas de tout contributeur, et de la CI),
    le fichier n'existe pas et ces tests tombent.

    Un test qui ne réussit que sur la machine où il a été écrit ne prouve rien.
    Cette fixture rend la suite auto-suffisante : chaque test reçoit une base
    neuve dans son `tmp_path`, jamais celle du poste. Elle protège au passage
    la règle absolue du fichier — aucun test ne touche de données réelles.
    """
    from app.config import settings

    chemin = tmp_path / "test-okvorado.db"
    # Le SCHÉMA doit exister, pas seulement le fichier : l'application ouvre
    # cette base et interroge ses tables (`port_mappings`…) sans la créer —
    # c'est `app/db.py` qui le fait au démarrage réel. Rediriger le chemin sans
    # initialiser laisserait exactement la même erreur, juste ailleurs.
    conn = sqlite3.connect(chemin)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()

    monkeypatch.setattr(settings, "sqlite_path", str(chemin))
    return settings.sqlite_path

# Échantillon RÉEL des métriques de l'outlet, capturé le 2026-08-05 sur .6.
# Contient les pièges à gérer : notation scientifique, labels avec espaces,
# métriques sans labels, lignes de commentaire.
SAMPLE_OUTLET_METRICS = """# HELP akvorado_outlet_core_flows_errors_total Flows with errors.
# TYPE akvorado_outlet_core_flows_errors_total counter
akvorado_outlet_core_flows_errors_total{error="input and output interfaces missing",exporter="192.0.2.18"} 2.161545e+06
# HELP akvorado_outlet_core_forwarded_flows_total Forwarded flows.
# TYPE akvorado_outlet_core_forwarded_flows_total counter
akvorado_outlet_core_forwarded_flows_total{exporter="192.0.2.13"} 1.522936e+06
akvorado_outlet_core_forwarded_flows_total{exporter="192.0.2.17"} 4.631345e+06
akvorado_outlet_core_forwarded_flows_total{exporter="192.0.2.19"} 460502
akvorado_outlet_core_forwarded_flows_total{exporter="192.0.2.21"} 1.445696e+06
akvorado_outlet_core_forwarded_flows_total{exporter="192.0.2.22"} 1.247373e+06
akvorado_outlet_core_forwarded_flows_total{exporter="192.0.2.23"} 7.175469e+06
akvorado_outlet_core_forwarded_flows_total{exporter="192.0.2.24"} 1.0557793e+07
akvorado_outlet_core_forwarded_flows_total{exporter="192.0.2.3"} 2.961713e+06
akvorado_outlet_core_forwarded_flows_total{exporter="192.0.2.6"} 5.068199e+06
akvorado_outlet_core_forwarded_flows_total{exporter="192.0.2.7"} 1.597516e+06
akvorado_outlet_kafkainput_connect_errors_total{node_id="1",worker="0"} 13
akvorado_outlet_kafkaoutput_dropped_messages_total 0
akvorado_outlet_metadata_provider_errors_total 0
akvorado_outlet_routing_provider_bmp_errors_total{error="cannot decode BMP header",exporter="203.0.113.1"} 2
"""

# Extrait RÉEL de la structure du provider `static` de outlet.yaml.
SAMPLE_OUTLET_YAML = """
metadata:
  providers:
    - type: static
      exporters:
        192.0.2.23/32:
          name: clm
          if-indexes:
            1222:
              name: tailscale0
              description: tailscale mesh
              speed: 1000
              boundary: internal
            2:
              name: eth0
              description: WAN
              speed: 1000
              boundary: external
          default:
            name: unknown
            description: unclassified
            speed: 1000
        192.0.2.18/32:
          name: poste-collecte
          default:
            name: tailscale0
            description: tailscale mesh
            speed: 1000
            boundary: internal
        100.64.0.0/10:
          name: homelab-vm
          default:
            name: unknown
            description: unclassified
            speed: 1000
"""


@pytest.fixture(autouse=True)
def _reset_metrics_cache() -> Generator[None]:
    """Vide le cache des métriques outlet avant CHAQUE test.

    `fetch_outlet_metrics()` met son résultat en cache 15 s pour éviter que des
    requêtes concurrentes n'entrent en compétition. Sans ce reset, un test de
    cas d'erreur (timeout, HTTP 500) recevrait la valeur mise en cache par un
    test précédent et passerait à tort.
    """
    from app.clients.prometheus import clear_metrics_cache

    clear_metrics_cache()
    yield
    clear_metrics_cache()


@pytest.fixture
def memory_db() -> Generator[sqlite3.Connection]:
    """Base SQLite en mémoire avec le schéma applicatif appliqué."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def sample_metrics_text() -> str:
    """Métriques Prometheus brutes de l'outlet (échantillon réel)."""
    return SAMPLE_OUTLET_METRICS


@pytest.fixture
def sample_outlet_yaml() -> str:
    """Configuration `outlet.yaml` réaliste (extrait réel)."""
    return SAMPLE_OUTLET_YAML


class FakeClickHouseClient:
    """Double de test du client ClickHouse.

    Enregistre les requêtes reçues pour permettre d'asserter qu'aucune valeur
    utilisateur n'est interpolée dans le SQL (garde sécurité n°1 du projet).
    """

    def __init__(self, rows: list[tuple[Any, ...]] | None = None) -> None:
        self.rows = rows or []
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> Any:
        self.calls.append((sql, parameters or {}))
        return _FakeResult(self.rows)

    @property
    def last_sql(self) -> str:
        return self.calls[-1][0] if self.calls else ""

    @property
    def last_parameters(self) -> dict[str, Any]:
        return self.calls[-1][1] if self.calls else {}


class _FakeResult:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.result_rows = rows
        self.result_set = rows


@pytest.fixture
def fake_clickhouse() -> FakeClickHouseClient:
    """Client ClickHouse factice, sans aucune connexion réseau."""
    return FakeClickHouseClient()


def authenticated_test_client(app: Any, *, username: str = "test-user") -> TestClient:
    """`TestClient` déjà muni d'une session valide (LOT auth).

    Toute route de `app.main.app` est désormais protégée par
    `require_authentication` (allowlist : `/health`, `/login`, `/logout`,
    `/static/*`). Les tests écrits AVANT ce lot appellent le vrai `app` sans
    jamais se connecter — sans ce helper, ils recevraient tous une
    redirection vers `/login` au lieu de la réponse qu'ils vérifient.

    Signe soi-même un cookie de session avec la clé PUBLIÉE par l'app
    (`app.state.auth_session_secret`, résolue une fois au chargement du
    module — voir `app.main`) plutôt que de passer par un vrai `/login` : ces
    tests ne portent pas sur l'authentification elle-même (couverte par
    `tests/test_auth.py`), signer directement le cookie évite d'introduire
    une dépendance à un compte/mot de passe applicatif dans des tests qui
    n'en ont pas besoin.
    """
    from app.auth import new_session_cookie

    client = TestClient(app)
    cookie_value = new_session_cookie(username, app.state.auth_session_secret)
    client.cookies.set("okvorado_session", cookie_value)
    return client
