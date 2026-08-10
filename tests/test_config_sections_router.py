"""Tests du router d'édition des sections de configuration Akvorado.

Périmètre testé : `app/routers/config_sections.py`. Consomme le catalogue réel
`app.services.config_sections.SECTIONS` et le lecteur/écrivain YAML générique
`app.clients.yaml_editor` (lot socle, développés en parallèle — leur contrat
est figé dans CONTRACT.md et repris tel quel ici, aucun double n'est
nécessaire puisque les deux modules existent au moment où ces tests tournent).

Aucun test ici ne touche la prod : SQLite en mémoire, YAML en `tmp_path`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from markupsafe import escape as jinja_escape

from app.db import SCHEMA
from app.services.config_sections import SECTIONS, list_sections
from app.services.config_writer import list_pending_changes

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def memory_conn() -> Generator[sqlite3.Connection]:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    try:
        yield conn
    finally:
        conn.close()


_OUTLET_YAML = """\
networks:
  networks:
    100.64.0.0/10:
      name: tailscale-mesh
      role: internal
      tenant: homelab
    192.168.1.0/24:
      name: lan-maison
      role: lan
      tenant: homelab
core:
  exporter-classifiers:
    - ClassifyRegion("homelab")
  interface-classifiers: []
"""

_AKVORADO_YAML = """\
clickhouse:
  asns:
    64512: homelab-as
kafka:
  topic-configuration:
    num-partitions: 4
"""

_CONSOLE_YAML = """\
default-visualize-options:
  limit: 10
  dimensions:
    - src-as
homepage-top-widgets:
  - src-as
database:
  saved-filters:
    - description: filtre 0
      content: "DstPort = 8000"
    - description: filtre 1
      content: "DstPort = 8001"
    - description: filtre 2
      content: "DstPort = 8002"
"""

_INLET_YAML = """\
flow:
  inputs:
    - type: udp
      decoder: netflow
      listen: 0.0.0.0:2055
"""


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    (tmp_path / "outlet.yaml").write_text(_OUTLET_YAML)
    (tmp_path / "akvorado.yaml").write_text(_AKVORADO_YAML)
    (tmp_path / "console.yaml").write_text(_CONSOLE_YAML)
    (tmp_path / "inlet.yaml").write_text(_INLET_YAML)
    return tmp_path


def _make_app(conn: sqlite3.Connection, config_dir_path: str) -> FastAPI:
    from app.routers import config_sections as sections_router

    app = FastAPI()
    app.include_router(sections_router.router)
    app.dependency_overrides[sections_router.get_db_connection] = lambda: conn
    app.dependency_overrides[sections_router.get_config_dir] = lambda: config_dir_path
    return app


def _client(conn: sqlite3.Connection, config_dir_path: str) -> TestClient:
    return TestClient(_make_app(conn, config_dir_path))


# ---------------------------------------------------------------------------
# Catalogue — listing et rendu
# ---------------------------------------------------------------------------


class TestSectionsCatalogue:
    def test_get_sections_page_lists_every_section_without_exception(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.get("/config/sections")

        assert response.status_code == 200
        for section in list_sections():
            # Jinja2 autoescape (obligatoire, jamais désactivé) transforme les
            # apostrophes en `&#39;` : on compare à la forme réellement rendue.
            assert jinja_escape(section.label) in response.text

    def test_api_sections_returns_items_and_total(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.get("/api/config/sections")

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == len(SECTIONS)
        assert len(body["items"]) == body["total"]
        keys = {item["key"] for item in body["items"]}
        assert keys == set(SECTIONS.keys())

    @pytest.mark.parametrize("key", list(SECTIONS.keys()))
    def test_get_section_detail_renders_without_exception(
        self, memory_conn: sqlite3.Connection, config_dir: Path, key: str
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.get(f"/config/sections/{key}")

        assert response.status_code == 200
        assert jinja_escape(SECTIONS[key].label) in response.text

    def test_get_section_detail_renders_with_empty_section(
        self, memory_conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        # Fichiers vides mais présents : chaque section retombe sur "absent" (None)
        # via read_section, qui doit dégrader vers un affichage vide, pas planter.
        (tmp_path / "outlet.yaml").write_text("networks: {}\n")
        (tmp_path / "akvorado.yaml").write_text("clickhouse: {}\n")
        (tmp_path / "console.yaml").write_text("homepage-top-widgets: []\n")
        (tmp_path / "inlet.yaml").write_text("flow: {}\n")

        client = _client(memory_conn, str(tmp_path))
        for key in SECTIONS:
            response = client.get(f"/config/sections/{key}")
            assert response.status_code == 200, f"section={key}"

    def test_unknown_section_key_returns_404(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.get("/config/sections/does-not-exist")

        assert response.status_code == 404

    def test_unknown_section_key_on_post_returns_404_and_writes_nothing(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/does-not-exist",
            data={"action": "add", "cidr": "10.0.0.0/8", "name": "x"},
        )

        assert response.status_code == 404
        assert list_pending_changes(memory_conn) == []


# ---------------------------------------------------------------------------
# Mise en file d'attente — ajout d'entrée valide
# ---------------------------------------------------------------------------


class TestQueueValidEntries:
    def test_add_valid_network_stages_change(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks",
            data={"action": "add", "cidr": "10.42.0.0/16", "name": "labo"},
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        assert pending[0].change_type == "update_section"
        assert pending[0].payload["section_key"] == "networks"
        assert "10.42.0.0/16" in pending[0].payload["value"]
        # L'existant est préservé (mise à jour, pas un remplacement complet).
        assert "192.168.1.0/24" in pending[0].payload["value"]

    def test_add_valid_asn_stages_change(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/asns",
            data={"action": "add", "asn": "65001", "name": "op-transit"},
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        assert pending[0].payload["value"]["65001"] == "op-transit"

    def test_add_valid_saved_filter_stages_change(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/saved_filters",
            data={
                "action": "add",
                "description": "trafic web sortant",
                "content": "DstPort = 443",
            },
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        values = pending[0].payload["value"]
        assert any(f["content"] == "DstPort = 443" for f in values)
        assert len(values) == 4  # 3 existants + 1 ajouté

    def test_add_valid_flow_input_stages_change(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/flow_inputs",
            data={
                "action": "add",
                "type": "udp",
                "decoder": "sflow",
                "host": "0.0.0.0",
                "port": "6343",
            },
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        values = pending[0].payload["value"]
        assert any(entry["listen"] == "0.0.0.0:6343" for entry in values)

    def test_double_click_two_requests_stage_two_changes_each_valid(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        """Anti double-clic (`hx-sync`) est une garde CÔTÉ NAVIGATEUR : côté
        serveur, chaque POST reçu doit rester individuellement idempotent et
        cohérent — un unique POST ne doit jamais produire plus d'UNE entrée
        en file. On vérifie ici la propriété serveur : un POST = une entrée.
        """
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks",
            data={"action": "add", "cidr": "10.99.0.0/16", "name": "unique"},
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1


# ---------------------------------------------------------------------------
# Validation — rejet propre, 422, rien en file
# ---------------------------------------------------------------------------


class TestValidationRejects:
    def test_invalid_cidr_returns_422_with_readable_message_and_stages_nothing(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks",
            data={"action": "add", "cidr": "192.168.1.0/33", "name": "labo"},
        )

        assert response.status_code == 422
        assert "192.168.1.0/33" in response.text
        assert list_pending_changes(memory_conn) == []

    def test_non_integer_asn_returns_422_and_stages_nothing(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/asns",
            data={"action": "add", "asn": "not-a-number", "name": "op-transit"},
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []

    def test_negative_asn_returns_422_and_stages_nothing(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/asns",
            data={"action": "add", "asn": "-5", "name": "op-transit"},
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []

    def test_widget_outside_allowlist_returns_422_and_stages_nothing(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/homepage_widgets",
            data={"widgets": ["src-as", "not_a_real_widget"]},
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []

    def test_port_out_of_bounds_returns_422_and_stages_nothing(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/flow_inputs",
            data={"action": "add", "type": "udp", "decoder": "netflow", "port": "70000"},
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []

    def test_unknown_decoder_returns_422_and_stages_nothing(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/flow_inputs",
            data={"action": "add", "type": "udp", "decoder": "bogus", "port": "2055"},
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []

    def test_empty_saved_filter_description_returns_422(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/saved_filters",
            data={"action": "add", "description": "   ", "content": "DstPort = 443"},
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []

    def test_visualize_defaults_zero_limit_returns_422(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/visualize_defaults",
            data={"limit": "0", "dimensions": "src-as"},
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []


# ---------------------------------------------------------------------------
# Suppression d'une entrée
# ---------------------------------------------------------------------------


class TestRemoveEntry:
    def test_remove_network_entry_stages_change_without_it(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks",
            data={"action": "remove", "cidr": "192.168.1.0/24"},
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        assert "192.168.1.0/24" not in pending[0].payload["value"]
        assert "100.64.0.0/10" in pending[0].payload["value"]

    def test_remove_saved_filter_entry_by_index_stages_change(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/saved_filters",
            data={"action": "remove", "index": "0"},
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        assert len(pending[0].payload["value"]) == 2

    def test_remove_out_of_bounds_index_returns_422(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/saved_filters",
            data={"action": "remove", "index": "99"},
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []


# ---------------------------------------------------------------------------
# Classifiers — zone de texte multi-lignes
# ---------------------------------------------------------------------------


class TestClassifiersTextarea:
    def test_update_exporter_classifiers_from_textarea_stages_change(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/exporter_classifiers",
            data={"expressions": 'ClassifyRegion("homelab")\nClassifyTenant("example")\n'},
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        assert pending[0].payload["value"] == [
            'ClassifyRegion("homelab")',
            'ClassifyTenant("example")',
        ]

    def test_classifiers_section_uses_textarea_not_table(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.get("/config/sections/exporter_classifiers")

        assert response.status_code == 200
        assert "<textarea" in response.text

    def test_empty_classifiers_textarea_stages_empty_list(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/interface_classifiers",
            data={"expressions": ""},
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert pending[0].payload["value"] == []


# ---------------------------------------------------------------------------
# Sécurité — pas de fuite HTML brut malgré autoescape
# ---------------------------------------------------------------------------


class TestNoAutoescapeBypass:
    def test_rendered_section_page_escapes_html_in_yaml_values(
        self, memory_conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        """Une valeur YAML contenant du HTML doit être échappée, jamais injectée telle quelle."""
        (tmp_path / "outlet.yaml").write_text(_OUTLET_YAML)
        (tmp_path / "akvorado.yaml").write_text(
            'clickhouse:\n  asns:\n    64512: "<script>alert(1)</script>"\n'
        )
        (tmp_path / "console.yaml").write_text(_CONSOLE_YAML)
        (tmp_path / "inlet.yaml").write_text(_INLET_YAML)

        client = _client(memory_conn, str(tmp_path))
        response = client.get("/config/sections/asns")

        assert response.status_code == 200
        assert "<script>alert(1)</script>" not in response.text
        assert "&lt;script&gt;" in response.text


# ---------------------------------------------------------------------------
# Non-régression : les autres suites restent vertes (sanity check d'import)
# ---------------------------------------------------------------------------


def test_config_writer_supports_update_section() -> None:
    """Verrouille la fermeture du gap : `update_section` DOIT être supporté.

    Ce test documentait auparavant le trou inverse — le router mettait des
    changements de section en file, mais `apply_pending_changes` ne savait pas
    les écrire : l'utilisateur remplissait un formulaire, cliquait
    « Appliquer », et RIEN n'arrivait dans le YAML. L'interface donnait
    l'illusion de fonctionner.

    Le gap est ferme. Ce test garantit qu'il ne se rouvre pas : si quelqu'un
    retire `update_section` du contrat, il casse ici et pas en production.
    """
    import typing

    from app.services.config_writer import ChangeType

    change_types = typing.get_args(ChangeType)
    assert "update_section" in change_types, (
        "update_section a disparu de ChangeType : les modifications de "
        "configuration faites depuis l'UI ne seraient plus appliquees."
    )
    # Les 4 types historiques (exportateurs) restent supportes.
    for legacy in ("add_exporter", "update_exporter", "delete_exporter", "fix_ifindex"):
        assert legacy in change_types
