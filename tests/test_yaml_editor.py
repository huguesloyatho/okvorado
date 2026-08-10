"""Tests du socle générique d'édition YAML (`app/clients/yaml_editor.py`) et du
catalogue de sections éditables (`app/services/config_sections.py`).

RÈGLE ABSOLUE : aucun test ne touche la prod. Tout se passe sur des fichiers
temporaires (`tmp_path`).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.clients.yaml_editor import (
    ConcurrentModificationError,
    compute_file_hash,
    read_section,
    write_section,
)
from app.services.config_sections import SECTIONS, ConfigSection, get_section, list_sections

# ---------------------------------------------------------------------------
# Échantillons YAML réalistes
# ---------------------------------------------------------------------------

# Extrait réaliste avec commentaires en tête ET au milieu du document, ainsi
# qu'une section imbriquée (`networks.networks`) et une liste (`core.exporter-classifiers`).
SAMPLE_YAML_WITH_COMMENTS = """\
# Config outlet — homelab (maj 2026-08-01).
# Ne pas éditer à la main sans notifier l'équipe réseau.
geoip:
  optional: true
  asn-database:
    - /usr/share/GeoIP/asn.mmdb

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
  network-sources: []

# Section core : classification des exportateurs et interfaces.
core:
  exporter-classifiers:
    - ClassifyRegion("homelab")
    - ClassifyTenant("example")
    - ClassifyRole("vm")
  interface-classifiers: []
"""

# Extrait réaliste du fichier racine `akvorado.yaml`, qui inclut d'autres
# fichiers via la directive `!include` (cas critique : ruamel doit la
# préserver telle quelle, sinon l'orchestrator ne démarre plus).
SAMPLE_AKVORADO_YAML_WITH_INCLUDE = """\
# akvorado.yaml — fichier racine de l'orchestrateur.
inlet: !include "inlet.yaml"
outlet: !include "outlet.yaml"

clickhouse:
  asns:
    64501: ACME Corporation

kafka:
  topic-configuration:
    num-partitions: 1
    replication-factor: 1
    config:
      retention.ms: "86400000"
"""


@pytest.fixture
def outlet_yaml_path(tmp_path: Path) -> Path:
    path = tmp_path / "outlet.yaml"
    path.write_text(SAMPLE_YAML_WITH_COMMENTS, encoding="utf-8")
    return path


@pytest.fixture
def akvorado_yaml_path(tmp_path: Path) -> Path:
    path = tmp_path / "akvorado.yaml"
    path.write_text(SAMPLE_AKVORADO_YAML_WITH_INCLUDE, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# compute_file_hash
# ---------------------------------------------------------------------------


class TestComputeFileHash:
    def test_hash_stable_for_unchanged_file(self, outlet_yaml_path: Path) -> None:
        assert compute_file_hash(str(outlet_yaml_path)) == compute_file_hash(str(outlet_yaml_path))

    def test_hash_changes_when_content_changes(self, outlet_yaml_path: Path) -> None:
        before = compute_file_hash(str(outlet_yaml_path))
        outlet_yaml_path.write_text(
            outlet_yaml_path.read_text(encoding="utf-8") + "\n# ajout\n", encoding="utf-8"
        )
        after = compute_file_hash(str(outlet_yaml_path))
        assert before != after


# ---------------------------------------------------------------------------
# read_section
# ---------------------------------------------------------------------------


class TestReadSection:
    def test_reads_nested_mapping(self, outlet_yaml_path: Path) -> None:
        value = read_section(str(outlet_yaml_path), "networks.networks")
        assert value is not None
        assert "100.64.0.0/10" in value
        assert value["100.64.0.0/10"]["name"] == "tailscale-mesh"
        assert value["192.168.1.0/24"]["name"] == "lan-maison"

    def test_reads_list_section(self, outlet_yaml_path: Path) -> None:
        value = read_section(str(outlet_yaml_path), "core.exporter-classifiers")
        assert value == [
            'ClassifyRegion("homelab")',
            'ClassifyTenant("example")',
            'ClassifyRole("vm")',
        ]

    def test_reads_empty_list_section(self, outlet_yaml_path: Path) -> None:
        value = read_section(str(outlet_yaml_path), "core.interface-classifiers")
        assert value == []

    def test_missing_section_returns_none(self, outlet_yaml_path: Path) -> None:
        assert read_section(str(outlet_yaml_path), "database.saved-filters") is None

    def test_missing_intermediate_key_returns_none(self, outlet_yaml_path: Path) -> None:
        assert read_section(str(outlet_yaml_path), "does.not.exist") is None

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert read_section(str(tmp_path / "absent.yaml"), "networks.networks") is None

    def test_scalar_leaf(self, outlet_yaml_path: Path) -> None:
        assert read_section(str(outlet_yaml_path), "geoip.optional") is True


# ---------------------------------------------------------------------------
# write_section — round-trip et préservation des commentaires
# ---------------------------------------------------------------------------


class TestWriteSectionRoundTrip:
    def test_preserves_header_and_mid_file_comments(self, outlet_yaml_path: Path) -> None:
        expected_hash = compute_file_hash(str(outlet_yaml_path))
        new_networks = {
            "100.64.0.0/10": {"name": "tailscale-mesh-v2", "role": "internal", "tenant": "homelab"},
            "192.168.1.0/24": {"name": "lan-maison", "role": "lan", "tenant": "homelab"},
        }
        write_section(
            str(outlet_yaml_path), "networks.networks", new_networks, expected_hash=expected_hash
        )

        content = outlet_yaml_path.read_text(encoding="utf-8")
        assert "# Config outlet — homelab (maj 2026-08-01)." in content
        assert "# Ne pas éditer à la main sans notifier l'équipe réseau." in content
        assert "# Section core : classification des exportateurs et interfaces." in content

    def test_written_value_is_readable_back(self, outlet_yaml_path: Path) -> None:
        expected_hash = compute_file_hash(str(outlet_yaml_path))
        new_networks = {
            "10.0.0.0/8": {"name": "nouveau-reseau", "role": "internal", "tenant": "homelab"},
        }
        write_section(
            str(outlet_yaml_path), "networks.networks", new_networks, expected_hash=expected_hash
        )
        reread = read_section(str(outlet_yaml_path), "networks.networks")
        assert reread == new_networks

    def test_write_list_section(self, outlet_yaml_path: Path) -> None:
        expected_hash = compute_file_hash(str(outlet_yaml_path))
        new_classifiers = ['ClassifyRegion("nouveau")']
        write_section(
            str(outlet_yaml_path),
            "core.exporter-classifiers",
            new_classifiers,
            expected_hash=expected_hash,
        )
        assert read_section(str(outlet_yaml_path), "core.exporter-classifiers") == new_classifiers

    def test_write_preserves_other_sections_untouched(self, outlet_yaml_path: Path) -> None:
        expected_hash = compute_file_hash(str(outlet_yaml_path))
        write_section(
            str(outlet_yaml_path),
            "core.interface-classifiers",
            ["ClassifyProvider()"],
            expected_hash=expected_hash,
        )
        # La section networks, non touchée, doit rester intacte.
        networks = read_section(str(outlet_yaml_path), "networks.networks")
        assert networks is not None
        assert networks["100.64.0.0/10"]["name"] == "tailscale-mesh"

    def test_write_creates_missing_section(self, outlet_yaml_path: Path) -> None:
        expected_hash = compute_file_hash(str(outlet_yaml_path))
        write_section(
            str(outlet_yaml_path),
            "database.saved-filters",
            [{"description": "flux internes", "content": "InIfBoundary = 'internal'"}],
            expected_hash=expected_hash,
        )
        reread = read_section(str(outlet_yaml_path), "database.saved-filters")
        assert reread == [{"description": "flux internes", "content": "InIfBoundary = 'internal'"}]


class TestWriteSectionPreservesInclude:
    """Cas CRITIQUE : `akvorado.yaml` contient des directives `!include`.

    Si le round-trip les casse, l'orchestrator ne démarre plus.
    """

    def test_include_directives_survive_unrelated_write(self, akvorado_yaml_path: Path) -> None:
        expected_hash = compute_file_hash(str(akvorado_yaml_path))
        write_section(
            str(akvorado_yaml_path),
            "clickhouse.asns",
            {64501: "ACME Corporation", 64502: "Homelab Corp"},
            expected_hash=expected_hash,
        )
        content = akvorado_yaml_path.read_text(encoding="utf-8")
        assert 'inlet: !include "inlet.yaml"' in content
        assert 'outlet: !include "outlet.yaml"' in content

    def test_asns_written_and_readable(self, akvorado_yaml_path: Path) -> None:
        expected_hash = compute_file_hash(str(akvorado_yaml_path))
        write_section(
            str(akvorado_yaml_path),
            "clickhouse.asns",
            {64501: "ACME Corporation", 64502: "Homelab Corp"},
            expected_hash=expected_hash,
        )
        reread = read_section(str(akvorado_yaml_path), "clickhouse.asns")
        assert reread == {64501: "ACME Corporation", 64502: "Homelab Corp"}

    def test_include_survives_round_trip_even_without_write(self, akvorado_yaml_path: Path) -> None:
        # Lire ne doit jamais modifier le fichier sur disque.
        before = akvorado_yaml_path.read_text(encoding="utf-8")
        read_section(str(akvorado_yaml_path), "clickhouse.asns")
        after = akvorado_yaml_path.read_text(encoding="utf-8")
        assert before == after


# ---------------------------------------------------------------------------
# Verrou optimiste
# ---------------------------------------------------------------------------


class TestOptimisticLock:
    def test_stale_hash_raises_and_leaves_file_untouched(self, outlet_yaml_path: Path) -> None:
        stale_hash = compute_file_hash(str(outlet_yaml_path))
        # Le fichier change entre-temps (édition SSH concurrente).
        outlet_yaml_path.write_text(
            outlet_yaml_path.read_text(encoding="utf-8") + "\n# edite entre-temps\n",
            encoding="utf-8",
        )
        content_before_attempt = outlet_yaml_path.read_text(encoding="utf-8")

        with pytest.raises(ConcurrentModificationError):
            write_section(
                str(outlet_yaml_path),
                "networks.networks",
                {"10.0.0.0/8": {"name": "x"}},
                expected_hash=stale_hash,
            )

        assert outlet_yaml_path.read_text(encoding="utf-8") == content_before_attempt


# ---------------------------------------------------------------------------
# Écriture atomique
# ---------------------------------------------------------------------------


class TestAtomicWrite:
    def test_os_replace_failure_leaves_original_file_intact(
        self, outlet_yaml_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        original_content = outlet_yaml_path.read_text(encoding="utf-8")
        expected_hash = compute_file_hash(str(outlet_yaml_path))

        def _boom(_src: object, _dst: object) -> None:
            raise OSError("simulated os.replace failure")

        monkeypatch.setattr(os, "replace", _boom)

        with pytest.raises(OSError):
            write_section(
                str(outlet_yaml_path),
                "networks.networks",
                {"10.0.0.0/8": {"name": "x"}},
                expected_hash=expected_hash,
            )

        assert outlet_yaml_path.read_text(encoding="utf-8") == original_content

    def test_no_leftover_tmp_file_after_failure(
        self, outlet_yaml_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        expected_hash = compute_file_hash(str(outlet_yaml_path))

        def _boom(_src: object, _dst: object) -> None:
            raise OSError("simulated os.replace failure")

        monkeypatch.setattr(os, "replace", _boom)

        with pytest.raises(OSError):
            write_section(
                str(outlet_yaml_path),
                "networks.networks",
                {"10.0.0.0/8": {"name": "x"}},
                expected_hash=expected_hash,
            )

        leftovers = list(outlet_yaml_path.parent.glob(f"{outlet_yaml_path.name}.tmp-*"))
        assert leftovers == []


# ---------------------------------------------------------------------------
# Backup horodaté
# ---------------------------------------------------------------------------


class TestBackup:
    def test_backup_created_before_write(self, outlet_yaml_path: Path) -> None:
        expected_hash = compute_file_hash(str(outlet_yaml_path))
        write_section(
            str(outlet_yaml_path),
            "networks.networks",
            {"10.0.0.0/8": {"name": "x"}},
            expected_hash=expected_hash,
        )
        backups = list(outlet_yaml_path.parent.glob(f"{outlet_yaml_path.name}.bak-*"))
        assert len(backups) == 1


# ---------------------------------------------------------------------------
# config_sections.py — catalogue
# ---------------------------------------------------------------------------


class TestCatalogue:
    def test_all_expected_keys_present(self) -> None:
        expected_keys = {
            "networks",
            "asns",
            "exporter_classifiers",
            "interface_classifiers",
            "visualize_defaults",
            "homepage_widgets",
            "saved_filters",
            "flow_inputs",
            "kafka_retention",
        }
        assert expected_keys <= SECTIONS.keys()

    def test_get_section_returns_matching_section(self) -> None:
        section = get_section("networks")
        assert isinstance(section, ConfigSection)
        assert section.key == "networks"
        assert section.file == "outlet.yaml"
        assert section.dotted_key == "networks.networks"
        assert section.restart_services == ("akvorado-outlet",)

    def test_get_section_unknown_key_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="inconnue|unknown|inconnu"):
            get_section("../../etc/passwd")

    def test_list_sections_returns_all_catalogue_entries(self) -> None:
        sections = list_sections()
        assert len(sections) == len(SECTIONS)
        assert all(isinstance(section, ConfigSection) for section in sections)

    def test_forged_dotted_key_never_reaches_disk(self, tmp_path: Path) -> None:
        """Un `dotted_key` forgé depuis l'extérieur (hors catalogue) ne doit
        jamais pouvoir dicter quoi que ce soit : seule une `key` du catalogue
        est acceptée, le dotted_key réellement utilisé vient TOUJOURS de
        `ConfigSection.dotted_key`, jamais d'une saisie utilisateur.
        """
        with pytest.raises(ValueError):
            get_section("networks; rm -rf /")

        # Le catalogue ne contient aucune entrée dont le dotted_key ou le file
        # pourrait avoir été influencé par une saisie extérieure : toutes les
        # valeurs sont des littéraux figés du module.
        for section in SECTIONS.values():
            assert section.file in {"outlet.yaml", "console.yaml", "akvorado.yaml", "inlet.yaml"}
            assert ".." not in section.dotted_key
            assert "/" not in section.dotted_key


# ---------------------------------------------------------------------------
# config_sections.py — validateurs
# ---------------------------------------------------------------------------


class TestNetworksValidator:
    def _validator(self) -> ConfigSection:
        return get_section("networks")

    def test_valid_networks(self) -> None:
        errors = self._validator().validator(
            {
                "100.64.0.0/10": {"name": "tailscale-mesh"},
                "192.168.1.0/24": {"name": "lan-maison"},
            }
        )
        assert errors == []

    def test_invalid_cidr(self) -> None:
        errors = self._validator().validator({"not-a-cidr": {"name": "x"}})
        assert errors != []

    def test_empty_name_rejected(self) -> None:
        errors = self._validator().validator({"100.64.0.0/10": {"name": ""}})
        assert errors != []

    def test_missing_name_rejected(self) -> None:
        errors = self._validator().validator({"100.64.0.0/10": {}})
        assert errors != []

    def test_duplicate_cidr_rejected(self) -> None:
        # Deux clés qui normalisent vers le même réseau.
        errors = self._validator().validator(
            {
                "192.0.2.1/10": {"name": "a"},
                "192.0.2.2/10": {"name": "b"},
            }
        )
        assert errors != []

    def test_not_a_mapping_rejected(self) -> None:
        errors = self._validator().validator(["not", "a", "mapping"])
        assert errors != []


class TestAsnsValidator:
    def _validator(self) -> ConfigSection:
        return get_section("asns")

    def test_valid_asns(self) -> None:
        errors = self._validator().validator({64501: "ACME Corporation", 64502: "Homelab"})
        assert errors == []

    def test_string_key_coercible_to_int_accepted(self) -> None:
        errors = self._validator().validator({"64501": "ACME Corporation"})
        assert errors == []

    def test_negative_asn_rejected(self) -> None:
        errors = self._validator().validator({-1: "invalide"})
        assert errors != []

    def test_non_integer_asn_rejected(self) -> None:
        errors = self._validator().validator({"not-an-as": "invalide"})
        assert errors != []

    def test_empty_value_rejected(self) -> None:
        errors = self._validator().validator({64501: ""})
        assert errors != []

    def test_not_a_mapping_rejected(self) -> None:
        errors = self._validator().validator([64501, "ACME"])
        assert errors != []


class TestHomepageWidgetsValidator:
    def _validator(self) -> ConfigSection:
        return get_section("homepage_widgets")

    def test_valid_widgets(self) -> None:
        errors = self._validator().validator(
            ["exporter", "dst-port", "protocol", "src-as", "dst-as", "src-country"]
        )
        assert errors == []

    def test_unknown_widget_rejected(self) -> None:
        errors = self._validator().validator(["exporter", "not-a-real-widget"])
        assert errors != []

    def test_empty_list_allowed(self) -> None:
        errors = self._validator().validator([])
        assert errors == []

    def test_not_a_list_rejected(self) -> None:
        errors = self._validator().validator({"exporter": True})
        assert errors != []


class TestSavedFiltersValidator:
    def _validator(self) -> ConfigSection:
        return get_section("saved_filters")

    def test_valid_filters(self) -> None:
        errors = self._validator().validator(
            [
                {"description": "flux internes", "content": "InIfBoundary = 'internal'"},
                {"description": "flux externes", "content": "InIfBoundary = 'external'"},
            ]
        )
        assert errors == []

    def test_missing_description_rejected(self) -> None:
        errors = self._validator().validator([{"content": "InIfBoundary = 'internal'"}])
        assert errors != []

    def test_missing_content_rejected(self) -> None:
        errors = self._validator().validator([{"description": "flux internes"}])
        assert errors != []

    def test_empty_content_rejected(self) -> None:
        errors = self._validator().validator([{"description": "flux internes", "content": "  "}])
        assert errors != []

    def test_not_a_list_rejected(self) -> None:
        errors = self._validator().validator({"description": "x", "content": "y"})
        assert errors != []


class TestFlowInputsValidator:
    def _validator(self) -> ConfigSection:
        return get_section("flow_inputs")

    def test_valid_inputs(self) -> None:
        errors = self._validator().validator(
            [
                {"type": "udp", "decoder": "netflow", "listen": "0.0.0.0:2055"},
                {"type": "udp", "decoder": "netflow", "listen": "0.0.0.0:4739"},
                {"type": "udp", "decoder": "sflow", "listen": "0.0.0.0:6343"},
            ]
        )
        assert errors == []

    def test_unknown_decoder_rejected(self) -> None:
        errors = self._validator().validator(
            [{"type": "udp", "decoder": "not-a-decoder", "listen": "0.0.0.0:2055"}]
        )
        assert errors != []

    def test_port_out_of_range_rejected(self) -> None:
        errors = self._validator().validator(
            [{"type": "udp", "decoder": "netflow", "listen": "0.0.0.0:70000"}]
        )
        assert errors != []

    def test_port_zero_rejected(self) -> None:
        errors = self._validator().validator(
            [{"type": "udp", "decoder": "netflow", "listen": "0.0.0.0:0"}]
        )
        assert errors != []

    def test_missing_field_rejected(self) -> None:
        errors = self._validator().validator([{"type": "udp", "decoder": "netflow"}])
        assert errors != []

    def test_not_a_list_rejected(self) -> None:
        errors = self._validator().validator({"type": "udp"})
        assert errors != []


class TestVisualizeDefaultsValidator:
    def _validator(self) -> ConfigSection:
        return get_section("visualize_defaults")

    def test_valid_defaults(self) -> None:
        errors = self._validator().validator({"limit": 10, "dimensions": ["src-as", "dst-as"]})
        assert errors == []

    def test_limit_not_positive_rejected(self) -> None:
        errors = self._validator().validator({"limit": 0, "dimensions": ["src-as"]})
        assert errors != []

    def test_limit_not_int_rejected(self) -> None:
        errors = self._validator().validator({"limit": "dix", "dimensions": ["src-as"]})
        assert errors != []

    def test_empty_dimensions_rejected(self) -> None:
        errors = self._validator().validator({"limit": 10, "dimensions": []})
        assert errors != []

    def test_not_a_mapping_rejected(self) -> None:
        errors = self._validator().validator(["limit", 10])
        assert errors != []


class TestStructuralValidators:
    """Les sections restantes (exporter_classifiers, interface_classifiers,
    kafka_retention) n'ont qu'une validation structurelle minimale (bon type).
    """

    def test_exporter_classifiers_accepts_list_of_strings(self) -> None:
        errors = get_section("exporter_classifiers").validator(['ClassifyRegion("homelab")'])
        assert errors == []

    def test_exporter_classifiers_rejects_non_list(self) -> None:
        errors = get_section("exporter_classifiers").validator("not-a-list")
        assert errors != []

    def test_interface_classifiers_accepts_empty_list(self) -> None:
        errors = get_section("interface_classifiers").validator([])
        assert errors == []

    def test_kafka_retention_accepts_mapping(self) -> None:
        errors = get_section("kafka_retention").validator({"num-partitions": 1})
        assert errors == []

    def test_kafka_retention_rejects_non_mapping(self) -> None:
        errors = get_section("kafka_retention").validator([1, 2, 3])
        assert errors != []
