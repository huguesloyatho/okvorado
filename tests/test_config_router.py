"""Tests du LOT C — routes et UI d'écriture de la configuration Akvorado.

Aucun test ici ne touche la prod : SQLite en mémoire, YAML en `tmp_path`,
restart injecté par un double. Voir CONTRACT.md pour la matrice de tests.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.db import SCHEMA
from app.services.config_writer import list_pending_changes, stage_change

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
        192.0.2.17/32:
          name: clm
          if-indexes:
            219:
              name: tailscale0
              description: tailscale mesh (ifIndex perime)
              speed: 1000
              boundary: internal
        100.64.0.0/10:
          name: mesh-catchall
          default:
            name: unknown
            boundary: undefined
"""


class FakeRestartOutcome:
    def __init__(self, success: bool, message: str = "ok") -> None:
        self.success = success
        self.message = message


class FakeRestartFn:
    """Double injectable pour `restart_fn` : compte les appels, résultat pilotable."""

    def __init__(self, success: bool = True, message: str = "ok") -> None:
        self.success = success
        self.message = message
        self.call_count = 0

    def __call__(self, services: tuple[str, ...] = ()) -> FakeRestartOutcome:
        self.call_count += 1
        return FakeRestartOutcome(self.success, self.message)


@pytest.fixture
def memory_conn() -> Generator[sqlite3.Connection]:
    # check_same_thread=False : TestClient exécute les endpoints FastAPI dans
    # un threadpool ; la connexion :memory: doit rester utilisable depuis ce
    # thread. Pas un souci en prod (LOT 0 gère sa propre connexion).
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def yaml_path(tmp_path: Path) -> str:
    path = tmp_path / "outlet.yaml"
    path.write_text(REALISTIC_YAML)
    return str(path)


def _make_app(
    conn: sqlite3.Connection,
    yaml_file: str,
    restart_fn: FakeRestartFn | None = None,
) -> FastAPI:
    """Construit une app FastAPI montant uniquement le router du LOT C.

    Isolé de app.main (LOT 0) : dépendances surchargées via
    `app.dependency_overrides`, comme le prescrit le pattern de views.py.
    """
    from app.routers import config as config_router

    app = FastAPI()
    app.include_router(config_router.router)

    app.dependency_overrides[config_router.get_db_connection] = lambda: conn
    app.dependency_overrides[config_router.get_akvorado_config_path] = lambda: yaml_file
    if restart_fn is not None:
        app.dependency_overrides[config_router.get_restart_fn] = lambda: restart_fn

    return app


def _client(
    conn: sqlite3.Connection, yaml_file: str, restart_fn: FakeRestartFn | None = None
) -> TestClient:
    return TestClient(_make_app(conn, yaml_file, restart_fn))


# ---------------------------------------------------------------------------
# Mise en file d'attente — ajout d'exportateur
# ---------------------------------------------------------------------------


class TestQueueAddExporter:
    def test_valid_exporter_form_returns_2xx_and_stages_change(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters",
            data={
                "cidr": "192.0.2.50/32",
                "name": "nouveau-noeud",
            },
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        assert pending[0].change_type == "add_exporter"
        assert pending[0].payload["cidr"] == "192.0.2.50/32"
        assert pending[0].payload["name"] == "nouveau-noeud"

    def test_form_urlencoded_accepted_not_422(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        """Piège vécu : une route JSON-only renvoie 422 à un <form> HTML."""
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters",
            data={"cidr": "192.0.2.51/32", "name": "form-test"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        assert response.status_code != 422

    def test_invalid_cidr_returns_422_with_readable_message_no_change_staged(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters",
            data={"cidr": "not-a-cidr", "name": "bad-cidr"},
        )

        assert response.status_code == 422
        assert response.text
        assert list_pending_changes(memory_conn) == []

    def test_empty_name_returns_422_no_change_staged(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters",
            data={"cidr": "192.0.2.52/32", "name": "   "},
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []


class TestInterfaceParDefautALaSouris:
    """Le formulaire d'ajout doit permettre de RENSEIGNER l'interface par défaut.

    DÉFAUT MESURÉ EN PRODUCTION (2026-08-11) : le formulaire ne demandait que
    CIDR + nom, donc le payload partait avec `default: None` et l'exportateur
    déclaré était écrit sans métadonnées — 100 % de ses flux rejetés en
    « metadata missing ».

    Le repli d'écriture (`akvorado_yaml.build_fallback_interface_spec`) garantit
    désormais l'INGESTION dans tous les cas. Mais garantir l'ingestion ne suffit
    pas à la règle du projet : « toute action métier faisable à la souris,
    jamais en éditant un YAML ». Un exploitant qui veut classifier son
    équipement (débit réel, périmètre interne/externe) doit pouvoir le faire à
    la déclaration, pas seulement subir `unknown`/`undefined`.
    """

    def test_les_metadonnees_saisies_sont_mises_en_attente(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters",
            data={
                "cidr": "192.0.2.60/32",
                "name": "opnsense",
                "default_name": "wan-fibre",
                "default_description": "collecte SFR",
                "default_speed": "10000",
                "default_boundary": "external",
            },
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        default = pending[0].payload["default"]
        assert default is not None, (
            "les métadonnées saisies à l'écran doivent atteindre la file "
            "d'attente, sinon le formulaire ne sert à rien"
        )
        assert default["name"] == "wan-fibre"
        assert default["description"] == "collecte SFR"
        assert default["speed"] == 10000
        assert default["boundary"] == "external"

    def test_sans_saisie_le_payload_porte_quand_meme_des_metadonnees(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        """LE GESTE RAPIDE RESTE RAPIDE : CIDR + nom seuls restent acceptés.

        C'est le cas exact qui a cassé la prod. Le payload mis en attente doit
        déjà porter des métadonnées exploitables — attendre le repli de la
        couche d'écriture suffirait techniquement, mais la file serait alors
        illisible (`default: null` affiché à l'exploitant, qui ne saurait pas
        ce qui sera réellement écrit).
        """
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters",
            data={"cidr": "192.0.2.61/32", "name": "geste-rapide"},
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        default = pending[0].payload["default"]
        assert default is not None
        assert default["name"] == "unknown"
        assert default["description"] == "unclassified"
        assert default["speed"] == 1000
        assert default["boundary"] == "undefined"

    def test_debit_invalide_refuse_sans_rien_mettre_en_attente(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        """Un débit <= 0 est refusé À LA SAISIE plutôt qu'écrit puis rejeté par
        `validate_exporters` au moment d'appliquer — l'erreur doit se voir là où
        le geste est fait."""
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters",
            data={
                "cidr": "192.0.2.62/32",
                "name": "debit-invalide",
                "default_name": "wan",
                "default_speed": "0",
                "default_boundary": "external",
            },
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []

    def test_boundary_invalide_refusee_sans_rien_mettre_en_attente(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters",
            data={
                "cidr": "192.0.2.63/32",
                "name": "boundary-invalide",
                "default_name": "wan",
                "default_speed": "1000",
                "default_boundary": "n-importe-quoi",
            },
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []

    def test_le_gabarit_expose_les_champs_a_la_souris(self) -> None:
        """Les champs doivent EXISTER dans le formulaire rendu.

        Une route qui accepte `default_*` mais un gabarit qui ne les propose
        pas laisserait la fonctionnalité inatteignable autrement qu'en forgeant
        une requête — l'une des 4 familles de défauts invisibles aux tests
        recensées dans CLAUDE.md (« service existant non branché »).
        """
        from pathlib import Path

        config_html = Path("app/templates/config.html").read_text(encoding="utf-8")
        debut = config_html.index('id="add-exporter-panel"')
        fin = config_html.index('id="add-interface-panel"')
        formulaire = config_html[debut:fin]

        assert 'name="default_name"' in formulaire
        assert 'name="default_description"' in formulaire
        assert 'name="default_speed"' in formulaire
        assert 'name="default_boundary"' in formulaire
        # Pré-remplissage : le geste rapide doit rester rapide (un formulaire
        # vide obligerait à tout saisir pour ne pas casser l'ingestion).
        assert 'value="unknown"' in formulaire
        assert 'value="1000"' in formulaire


class TestQueueAddInterface:
    def test_valid_interface_stages_change(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters/192.0.2.23%2F32/interfaces",
            data={
                "if_index": "3",
                "name": "Gi0/3",
                "description": "nouvelle interface",
                "speed": "1000",
                "boundary": "external",
            },
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        assert pending[0].change_type == "update_exporter"

    def test_if_index_zero_returns_422_no_change_staged(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters/192.0.2.23%2F32/interfaces",
            data={
                "if_index": "0",
                "name": "Gi0/3",
                "description": "",
                "speed": "1000",
                "boundary": "external",
            },
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []

    def test_if_index_negative_returns_422_no_change_staged(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters/192.0.2.23%2F32/interfaces",
            data={
                "if_index": "-5",
                "name": "Gi0/3",
                "description": "",
                "speed": "1000",
                "boundary": "external",
            },
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []

    def test_invalid_boundary_returns_422_no_change_staged(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters/192.0.2.23%2F32/interfaces",
            data={
                "if_index": "3",
                "name": "Gi0/3",
                "description": "",
                "speed": "1000",
                "boundary": "bogus-value",
            },
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []

    def test_unknown_exporter_returns_422_no_change_staged(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters/192.0.2.99%2F32/interfaces",
            data={
                "if_index": "3",
                "name": "Gi0/3",
                "description": "",
                "speed": "1000",
                "boundary": "external",
            },
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []


class TestFixIfindexButton:
    def test_fix_ifindex_stages_change_from_declared_state(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters/192.0.2.17%2F32/fix-ifindex",
            data={
                "interface_name": "tailscale0",
                "old_if_index": "219",
                "new_if_index": "409",
            },
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        assert pending[0].change_type == "fix_ifindex"
        assert pending[0].payload["old_if_index"] == 219
        assert pending[0].payload["new_if_index"] == 409

    def test_fix_ifindex_new_index_zero_returns_422(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.post(
            "/config/exporters/192.0.2.17%2F32/fix-ifindex",
            data={
                "interface_name": "tailscale0",
                "old_if_index": "219",
                "new_if_index": "0",
            },
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []


# ---------------------------------------------------------------------------
# Retrait d'un changement en attente
# ---------------------------------------------------------------------------


class TestDiscardPendingChange:
    def test_discard_removes_change_from_list(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        change_id = stage_change(
            memory_conn, "add_exporter", {"cidr": "192.0.2.60/32", "name": "x"}, "test"
        )
        client = _client(memory_conn, yaml_path)

        response = client.delete(f"/config/pending/{change_id}")

        assert response.status_code in (200, 204)
        assert list_pending_changes(memory_conn) == []

    def test_discard_unknown_id_does_not_error_out(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.delete("/config/pending/999999")

        assert response.status_code in (200, 204, 404)


# ---------------------------------------------------------------------------
# Consultation
# ---------------------------------------------------------------------------


class TestPendingApi:
    def test_api_pending_empty(self, memory_conn: sqlite3.Connection, yaml_path: str) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.get("/api/config/pending")

        assert response.status_code == 200
        payload = response.json()
        assert payload == {"items": [], "total": 0}

    def test_api_pending_lists_staged_changes(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        stage_change(memory_conn, "add_exporter", {"cidr": "192.0.2.61/32", "name": "y"}, "test")
        client = _client(memory_conn, yaml_path)

        response = client.get("/api/config/pending")

        assert response.status_code == 200
        payload = response.json()
        assert payload["total"] == 1
        assert payload["items"][0]["change_type"] == "add_exporter"


# ---------------------------------------------------------------------------
# Application des changements
# ---------------------------------------------------------------------------


class TestApplyPendingChanges:
    def test_apply_with_restart_ok_succeeds_and_clears_queue(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        stage_change(
            memory_conn,
            "fix_ifindex",
            {
                "cidr": "192.0.2.17/32",
                "interface_name": "tailscale0",
                "old_if_index": 219,
                "new_if_index": 409,
            },
            "test",
        )
        restart_fn = FakeRestartFn(success=True)
        client = _client(memory_conn, yaml_path, restart_fn)

        response = client.post("/config/apply")

        assert response.status_code == 200
        assert list_pending_changes(memory_conn) == []
        assert restart_fn.call_count == 1

    def test_apply_with_restart_ko_reports_failure_and_rollback_queue_kept(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        stage_change(
            memory_conn,
            "fix_ifindex",
            {
                "cidr": "192.0.2.17/32",
                "interface_name": "tailscale0",
                "old_if_index": 219,
                "new_if_index": 409,
            },
            "test",
        )
        restart_fn = FakeRestartFn(success=False, message="container unhealthy")
        client = _client(memory_conn, yaml_path, restart_fn)

        response = client.post("/config/apply")

        assert response.status_code == 200
        body = response.text
        assert "rollback" in body.lower() or "restaur" in body.lower()
        # La file n'est PAS vidée : rien n'a été appliqué avec succès.
        assert len(list_pending_changes(memory_conn)) == 1

    def test_apply_concurrent_modification_returns_clear_message_not_500(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        stage_change(
            memory_conn,
            "fix_ifindex",
            {
                "cidr": "192.0.2.17/32",
                "interface_name": "tailscale0",
                "old_if_index": 219,
                "new_if_index": 409,
            },
            "test",
        )
        restart_fn = FakeRestartFn(success=True)
        client = _client(memory_conn, yaml_path, restart_fn)

        # Modifie le fichier après lecture initiale -> hash change avant l'écriture.
        original = Path(yaml_path).read_text()

        import app.clients.akvorado_yaml as akvorado_yaml

        real_write = akvorado_yaml.write_declared_exporters

        def _tamper_then_write(path: str, exporters: Any, expected_hash: str) -> None:
            Path(path).write_text(original + "\n# modifie entre-temps\n")
            real_write(path, exporters, expected_hash)

        import app.services.config_writer as config_writer_module

        original_module_write = config_writer_module.write_declared_exporters

        def _patched(path: str, exporters: Any, expected_hash: str) -> None:
            Path(path).write_text(original + "\n# modifie entre-temps par un tiers\n")
            original_module_write(path, exporters, expected_hash)

        import app.routers.config as config_router_module

        monkeypatch_target = config_writer_module
        old = monkeypatch_target.write_declared_exporters
        monkeypatch_target.write_declared_exporters = _patched
        try:
            response = client.post("/config/apply")
        finally:
            monkeypatch_target.write_declared_exporters = old

        assert response.status_code == 200
        body = response.text.lower()
        assert "modifi" in body or "recharg" in body
        assert "traceback" not in body
        del config_router_module  # uniquement pour satisfaire le linter sur l'import

    def test_apply_empty_queue_succeeds_without_restart_call(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        restart_fn = FakeRestartFn(success=True)
        client = _client(memory_conn, yaml_path, restart_fn)

        response = client.post("/config/apply")

        assert response.status_code == 200
        assert restart_fn.call_count == 0


# ---------------------------------------------------------------------------
# Page HTML de gestion
# ---------------------------------------------------------------------------


class TestConfigPage:
    def test_get_config_page_renders_without_pending_changes(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        client = _client(memory_conn, yaml_path)

        response = client.get("/config")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_get_config_page_renders_with_pending_changes(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        stage_change(memory_conn, "add_exporter", {"cidr": "192.0.2.62/32", "name": "z"}, "test")
        client = _client(memory_conn, yaml_path)

        response = client.get("/config")

        assert response.status_code == 200
        body = response.text
        assert "1" in body
        assert "<script>" not in body

    def test_config_page_apply_button_has_double_submit_protection(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        stage_change(memory_conn, "add_exporter", {"cidr": "192.0.2.63/32", "name": "z"}, "test")
        client = _client(memory_conn, yaml_path)

        response = client.get("/config")

        body = response.text
        assert "hx-sync" in body or "hx-disabled-elt" in body

    def test_config_page_warns_about_restart_effect_on_apply_button(
        self, memory_conn: sqlite3.Connection, yaml_path: str
    ) -> None:
        stage_change(memory_conn, "add_exporter", {"cidr": "192.0.2.64/32", "name": "z"}, "test")
        client = _client(memory_conn, yaml_path)

        response = client.get("/config")

        body = response.text.lower()
        assert "redémarr" in body or "redemarr" in body
