"""Tests du LOT B — écriture réelle de `outlet.yaml`.

RÈGLE ABSOLUE : aucun test ne touche la prod. Tout se passe sur des fichiers
temporaires (`tmp_path`) et une base SQLite `:memory:`.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.clients.akvorado_yaml import (
    ConcurrentModificationError,
    _is_catchall_cidr,
    compute_config_hash,
    load_declared_exporters,
    validate_exporters,
    write_declared_exporters,
)
from app.clients.yaml_editor import compute_file_hash, read_section
from app.models import Boundary, DeclaredExporter, InterfaceSpec
from app.services.config_writer import (
    SCHEMA,
    ApplyResult,
    apply_pending_changes,
    build_ifindex_fix,
    discard_change,
    list_pending_changes,
    stage_change,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_YAML_WITH_COMMENTS = """\
# Configuration des exportateurs Akvorado — outlet.yaml
# Ne pas éditer à la main sans notifier l'équipe réseau.
metadata:
  providers:
    - type: static
      exporters:
        192.0.2.17/32:
          name: proxy-frontal
          if-indexes:
            219: {name: tailscale0, description: "Tailscale mesh", speed: 1000, boundary: internal}
            2: {name: ens18, description: "WAN Internet", speed: 1000, boundary: external}
          default: {name: unknown, description: "unclassified", speed: 1000, boundary: undefined}
        100.64.0.0/10:
          name: homelab-vm
          default: {name: unknown, description: "unclassified", speed: 1000, boundary: undefined}
"""


@pytest.fixture
def yaml_path(tmp_path: Path) -> Path:
    path = tmp_path / "outlet.yaml"
    path.write_text(SAMPLE_YAML_WITH_COMMENTS, encoding="utf-8")
    return path


@pytest.fixture
def memory_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _catchall_exporter() -> DeclaredExporter:
    return DeclaredExporter(
        cidr="100.64.0.0/10",
        name="homelab-vm",
        if_indexes={},
        default=InterfaceSpec(if_index=0, name="unknown", boundary=Boundary.UNDEFINED),
        is_catchall=True,
    )


def _nominal_exporter(if_index: int = 409) -> DeclaredExporter:
    return DeclaredExporter(
        cidr="192.0.2.17/32",
        name="proxy-frontal",
        if_indexes={
            if_index: InterfaceSpec(
                if_index=if_index,
                name="tailscale0",
                description="Tailscale mesh",
                speed=1000,
                boundary=Boundary.INTERNAL,
            ),
            2: InterfaceSpec(
                if_index=2,
                name="ens18",
                description="WAN Internet",
                speed=1000,
                boundary=Boundary.EXTERNAL,
            ),
        },
        default=InterfaceSpec(if_index=0, name="unknown", boundary=Boundary.UNDEFINED),
        is_catchall=False,
    )


# ---------------------------------------------------------------------------
# akvorado_yaml.py — hash, écriture, validation
# ---------------------------------------------------------------------------


class TestComputeConfigHash:
    def test_stable_for_same_content(self, yaml_path: Path) -> None:
        assert compute_config_hash(str(yaml_path)) == compute_config_hash(str(yaml_path))

    def test_changes_when_content_changes(self, yaml_path: Path) -> None:
        original = compute_config_hash(str(yaml_path))
        yaml_path.write_text(SAMPLE_YAML_WITH_COMMENTS + "\n# note\n", encoding="utf-8")
        assert compute_config_hash(str(yaml_path)) != original


class TestValidateExporters:
    def test_ok_with_valid_catchall_and_nominal(self) -> None:
        errors = validate_exporters([_nominal_exporter(), _catchall_exporter()])
        assert errors == []

    def test_rejects_invalid_cidr(self) -> None:
        bad = _nominal_exporter()
        bad.cidr = "not-a-cidr"
        errors = validate_exporters([bad, _catchall_exporter()])
        assert any("cidr" in error.lower() for error in errors)

    def test_rejects_duplicate_cidr(self) -> None:
        dup = _nominal_exporter()
        errors = validate_exporters([dup, dup.model_copy(), _catchall_exporter()])
        assert any("doublon" in error.lower() or "duplicate" in error.lower() for error in errors)

    def test_rejects_empty_name(self) -> None:
        bad = _nominal_exporter()
        bad.name = ""
        errors = validate_exporters([bad, _catchall_exporter()])
        assert any("name" in error.lower() or "nom" in error.lower() for error in errors)

    def test_rejects_if_index_zero(self) -> None:
        bad = _nominal_exporter()
        bad.if_indexes[0] = InterfaceSpec(if_index=0, name="broken")
        errors = validate_exporters([bad, _catchall_exporter()])
        assert any("if_index" in error.lower() or "ifindex" in error.lower() for error in errors)

    def test_rejects_if_index_negative(self) -> None:
        bad = _nominal_exporter()
        bad.if_indexes[-1] = InterfaceSpec(if_index=-1, name="broken")
        errors = validate_exporters([bad, _catchall_exporter()])
        assert any("if_index" in error.lower() or "ifindex" in error.lower() for error in errors)

    def test_rejects_invalid_boundary_is_impossible_via_enum(self) -> None:
        # Boundary est un Enum Pydantic strict : une valeur hors enum lève déjà
        # à la construction. On vérifie ici que les 3 valeurs valides passent.
        for boundary in (Boundary.INTERNAL, Boundary.EXTERNAL, Boundary.UNDEFINED):
            exp = _nominal_exporter()
            exp.default = InterfaceSpec(if_index=0, name="unknown", boundary=boundary)
            errors = validate_exporters([exp, _catchall_exporter()])
            assert errors == []

    def test_rejects_speed_zero_or_negative(self) -> None:
        bad = _nominal_exporter()
        bad.if_indexes[409] = InterfaceSpec(if_index=409, name="tailscale0", speed=0)
        errors = validate_exporters([bad, _catchall_exporter()])
        assert any("speed" in error.lower() for error in errors)

    def test_rejects_missing_catchall(self) -> None:
        errors = validate_exporters([_nominal_exporter()])
        assert any("catchall" in error.lower() for error in errors)

    def test_empty_list_rejected_for_missing_catchall(self) -> None:
        errors = validate_exporters([])
        assert any("catchall" in error.lower() for error in errors)


class TestWriteDeclaredExportersRoundTrip:
    def test_round_trip_preserves_comments_and_content(self, yaml_path: Path) -> None:
        original_hash = compute_config_hash(str(yaml_path))
        exporters = load_declared_exporters(str(yaml_path))

        write_declared_exporters(str(yaml_path), exporters, expected_hash=original_hash)

        new_content = yaml_path.read_text(encoding="utf-8")
        assert "# Configuration des exportateurs Akvorado" in new_content
        assert "# Ne pas éditer à la main" in new_content

        reloaded = load_declared_exporters(str(yaml_path))
        assert {e.cidr for e in reloaded} == {e.cidr for e in exporters}
        assert {e.name for e in reloaded} == {e.name for e in exporters}

    def test_add_exporter_present_others_intact(self, yaml_path: Path) -> None:
        original_hash = compute_config_hash(str(yaml_path))
        exporters = load_declared_exporters(str(yaml_path))
        new_exporter = DeclaredExporter(
            cidr="192.0.2.23/32",
            name="clm",
            if_indexes={},
            default=InterfaceSpec(if_index=0, name="unknown", boundary=Boundary.UNDEFINED),
            is_catchall=False,
        )
        exporters.append(new_exporter)

        write_declared_exporters(str(yaml_path), exporters, expected_hash=original_hash)

        reloaded = load_declared_exporters(str(yaml_path))
        names = {e.name for e in reloaded}
        assert "clm" in names
        assert "proxy-frontal" in names
        assert "homelab-vm" in names

    def test_fix_ifindex_219_to_409_changes_only_that_value(self, yaml_path: Path) -> None:
        original_hash = compute_config_hash(str(yaml_path))
        exporters = load_declared_exporters(str(yaml_path))
        proxy_frontal = next(e for e in exporters if e.name == "proxy-frontal")
        assert 219 in proxy_frontal.if_indexes
        old_spec = proxy_frontal.if_indexes.pop(219)
        proxy_frontal.if_indexes[409] = old_spec.model_copy(update={"if_index": 409})

        write_declared_exporters(str(yaml_path), exporters, expected_hash=original_hash)

        reloaded = load_declared_exporters(str(yaml_path))
        proxy_frontal_reloaded = next(e for e in reloaded if e.name == "proxy-frontal")
        assert 409 in proxy_frontal_reloaded.if_indexes
        assert 219 not in proxy_frontal_reloaded.if_indexes
        assert proxy_frontal_reloaded.if_indexes[409].name == "tailscale0"
        # l'autre interface n'a pas bougé
        assert 2 in proxy_frontal_reloaded.if_indexes
        assert proxy_frontal_reloaded.if_indexes[2].name == "ens18"

    def test_stale_hash_raises_and_leaves_file_untouched(self, yaml_path: Path) -> None:
        original_content = yaml_path.read_text(encoding="utf-8")
        exporters = load_declared_exporters(str(yaml_path))

        with pytest.raises(ConcurrentModificationError):
            write_declared_exporters(str(yaml_path), exporters, expected_hash="stale-hash-0000")

        assert yaml_path.read_text(encoding="utf-8") == original_content

    def test_write_failure_mid_stream_leaves_original_intact(
        self, yaml_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Simule une erreur pendant l'écriture : le fichier original doit rester intact.

        On patche `os.replace` (utilisé pour la promotion atomique) pour qu'il
        lève une exception : l'écriture ne doit alors jamais aboutir sur le
        fichier cible, et le contenu original doit être strictement préservé.
        """
        import os

        original_content = yaml_path.read_text(encoding="utf-8")
        original_hash = compute_config_hash(str(yaml_path))
        exporters = load_declared_exporters(str(yaml_path))

        def _boom(_src: str, _dst: str) -> None:
            raise OSError("simulated crash during atomic replace")

        monkeypatch.setattr(os, "replace", _boom)

        with pytest.raises(OSError):
            write_declared_exporters(str(yaml_path), exporters, expected_hash=original_hash)

        assert yaml_path.read_text(encoding="utf-8") == original_content

    def test_backup_file_created(self, yaml_path: Path) -> None:
        original_hash = compute_config_hash(str(yaml_path))
        exporters = load_declared_exporters(str(yaml_path))

        write_declared_exporters(str(yaml_path), exporters, expected_hash=original_hash)

        backups = list(yaml_path.parent.glob("outlet.yaml.bak-*"))
        assert len(backups) == 1
        assert backups[0].read_text(encoding="utf-8") == SAMPLE_YAML_WITH_COMMENTS

    def test_validation_failure_prevents_write(self, yaml_path: Path) -> None:
        original_content = yaml_path.read_text(encoding="utf-8")
        original_hash = compute_config_hash(str(yaml_path))
        exporters = load_declared_exporters(str(yaml_path))
        # Retire tous les catchalls -> validation doit échouer
        exporters = [e for e in exporters if not e.is_catchall]

        with pytest.raises(ValueError, match="catchall"):
            write_declared_exporters(str(yaml_path), exporters, expected_hash=original_hash)

        assert yaml_path.read_text(encoding="utf-8") == original_content
        backups = list(yaml_path.parent.glob("outlet.yaml.bak-*"))
        assert backups == []


# ---------------------------------------------------------------------------
# config_writer.py — file d'attente
# ---------------------------------------------------------------------------


class TestPendingChangesQueue:
    def test_stage_and_list(self, memory_conn: sqlite3.Connection) -> None:
        stage_change(
            memory_conn,
            change_type="add_exporter",
            payload={"cidr": "192.0.2.23/32", "name": "clm"},
            author="alice",
        )
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        assert pending[0].change_type == "add_exporter"
        assert pending[0].payload == {"cidr": "192.0.2.23/32", "name": "clm"}
        assert pending[0].author == "alice"

    def test_discard_change(self, memory_conn: sqlite3.Connection) -> None:
        change_id = stage_change(
            memory_conn,
            change_type="delete_exporter",
            payload={"cidr": "192.0.2.23/32"},
            author="bob",
        )
        discard_change(memory_conn, change_id)
        assert list_pending_changes(memory_conn) == []

    def test_list_preserves_order(self, memory_conn: sqlite3.Connection) -> None:
        stage_change(memory_conn, change_type="add_exporter", payload={"a": 1}, author="a")
        stage_change(memory_conn, change_type="add_exporter", payload={"b": 2}, author="b")
        pending = list_pending_changes(memory_conn)
        assert [p.payload for p in pending] == [{"a": 1}, {"b": 2}]


class TestBuildIfindexFix:
    def test_builds_fix_ifindex_change(self) -> None:
        change = build_ifindex_fix(
            cidr="192.0.2.17/32",
            interface_name="tailscale0",
            old_if_index=219,
            new_if_index=409,
            author="claude",
        )
        assert change.change_type == "fix_ifindex"
        assert change.payload["cidr"] == "192.0.2.17/32"
        assert change.payload["interface_name"] == "tailscale0"
        assert change.payload["old_if_index"] == 219
        assert change.payload["new_if_index"] == 409
        assert change.author == "claude"


# ---------------------------------------------------------------------------
# apply_pending_changes — orchestration complète
# ---------------------------------------------------------------------------


class _RestartOutcome:
    def __init__(self, success: bool, message: str = "") -> None:
        self.success = success
        self.message = message


def _ok_restart(_services: tuple[str, ...]) -> _RestartOutcome:
    return _RestartOutcome(success=True, message="containers healthy")


def _failing_restart(_services: tuple[str, ...]) -> _RestartOutcome:
    return _RestartOutcome(success=False, message="container akvorado-outlet-1 unhealthy")


class TestApplyPendingChanges:
    def test_success_writes_file_and_empties_queue(
        self, yaml_path: Path, memory_conn: sqlite3.Connection
    ) -> None:
        stage_change(
            memory_conn,
            change_type="add_exporter",
            payload={
                "cidr": "192.0.2.23/32",
                "name": "clm",
                "if_indexes": {},
                "default": {"name": "unknown", "boundary": "undefined"},
            },
            author="claude",
        )

        result: ApplyResult = apply_pending_changes(
            memory_conn, str(yaml_path), restart_fn=_ok_restart
        )

        assert result.success is True
        assert result.rolled_back is False
        reloaded = load_declared_exporters(str(yaml_path))
        assert any(e.name == "clm" for e in reloaded)
        assert list_pending_changes(memory_conn) == []

    def test_restart_failure_triggers_rollback_and_keeps_queue(
        self, yaml_path: Path, memory_conn: sqlite3.Connection
    ) -> None:
        original_content = yaml_path.read_text(encoding="utf-8")
        stage_change(
            memory_conn,
            change_type="add_exporter",
            payload={
                "cidr": "192.0.2.23/32",
                "name": "clm",
                "if_indexes": {},
                "default": {"name": "unknown", "boundary": "undefined"},
            },
            author="claude",
        )

        result: ApplyResult = apply_pending_changes(
            memory_conn, str(yaml_path), restart_fn=_failing_restart
        )

        assert result.success is False
        assert result.rolled_back is True
        assert yaml_path.read_text(encoding="utf-8") == original_content
        # la file d'attente n'est PAS vidée en cas d'échec
        assert len(list_pending_changes(memory_conn)) == 1

    def test_validation_failure_writes_nothing_and_no_backup(
        self, yaml_path: Path, memory_conn: sqlite3.Connection
    ) -> None:
        original_content = yaml_path.read_text(encoding="utf-8")
        # delete_exporter qui retire TOUS les catchalls -> validation KO
        stage_change(
            memory_conn,
            change_type="delete_exporter",
            payload={"cidr": "100.64.0.0/10"},
            author="claude",
        )

        result: ApplyResult = apply_pending_changes(
            memory_conn, str(yaml_path), restart_fn=_ok_restart
        )

        assert result.success is False
        assert yaml_path.read_text(encoding="utf-8") == original_content
        backups = list(yaml_path.parent.glob("outlet.yaml.bak-*"))
        assert backups == []
        # la file reste en attente : rien n'a été appliqué
        assert len(list_pending_changes(memory_conn)) == 1

    def test_fix_ifindex_change_applies_correctly(
        self, yaml_path: Path, memory_conn: sqlite3.Connection
    ) -> None:
        change = build_ifindex_fix(
            cidr="192.0.2.17/32",
            interface_name="tailscale0",
            old_if_index=219,
            new_if_index=409,
            author="claude",
        )
        stage_change(
            memory_conn,
            change_type=change.change_type,
            payload=change.payload,
            author=change.author,
        )

        result = apply_pending_changes(memory_conn, str(yaml_path), restart_fn=_ok_restart)

        assert result.success is True
        reloaded = load_declared_exporters(str(yaml_path))
        proxy_frontal = next(e for e in reloaded if e.name == "proxy-frontal")
        assert 409 in proxy_frontal.if_indexes
        assert 219 not in proxy_frontal.if_indexes


# ---------------------------------------------------------------------------
# apply_pending_changes — update_section (multi-fichiers)
# ---------------------------------------------------------------------------

AKVORADO_YAML_WITH_COMMENTS = """\
# akvorado.yaml — configuration racine, inclut inlet/outlet
# Ne pas éditer à la main sans notifier l'équipe réseau.
clickhouse:
  asns:
    64512: "site-A"
kafka:
  topic-configuration:
    partitions: 4
"""

CONSOLE_YAML_WITH_COMMENTS = """\
# console.yaml — configuration de la console web
database:
  saved-filters:
    - description: "trafic interne"
      content: "InIfBoundary = internal"
homepage-top-widgets:
  - exporter
default-visualize-options:
  limit: 10
  dimensions:
    - exporter
"""

INLET_YAML_WITH_COMMENTS = """\
# inlet.yaml — écoute des flux
flow:
  inputs:
    - type: udp
      decoder: netflow
      listen: "0.0.0.0:2055"
"""


@pytest.fixture
def akvorado_yaml_path(tmp_path: Path) -> Path:
    path = tmp_path / "akvorado.yaml"
    path.write_text(AKVORADO_YAML_WITH_COMMENTS, encoding="utf-8")
    return path


@pytest.fixture
def console_yaml_path(tmp_path: Path) -> Path:
    path = tmp_path / "console.yaml"
    path.write_text(CONSOLE_YAML_WITH_COMMENTS, encoding="utf-8")
    return path


@pytest.fixture
def inlet_yaml_path(tmp_path: Path) -> Path:
    path = tmp_path / "inlet.yaml"
    path.write_text(INLET_YAML_WITH_COMMENTS, encoding="utf-8")
    return path


class _RestartSpy:
    """Double injectable qui enregistre les appels et peut simuler un échec."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._fail = fail

    def __call__(self, services: tuple[str, ...]) -> _RestartOutcome:
        self.calls.append(services)
        if self._fail:
            return _RestartOutcome(success=False, message="restart simule en echec")
        return _RestartOutcome(success=True, message="containers healthy")


def _stage_update_section(
    conn: sqlite3.Connection, section_key: str, value: object, author: str = "claude"
) -> int:
    return stage_change(
        conn,
        change_type="update_section",
        payload={"section_key": section_key, "value": value},
        author=author,
    )


class TestApplyPendingChangesUpdateSection:
    def test_update_networks_writes_value_and_preserves_comments(
        self, yaml_path: Path, memory_conn: sqlite3.Connection
    ) -> None:
        _stage_update_section(
            memory_conn,
            "networks",
            {"10.0.0.0/8": {"name": "lab"}},
        )

        result = apply_pending_changes(
            memory_conn,
            {"outlet.yaml": str(yaml_path)},
            restart_fn=_RestartSpy(),
        )

        assert result.success is True
        content = yaml_path.read_text(encoding="utf-8")
        assert "# Configuration des exportateurs Akvorado" in content
        assert "# Ne pas éditer à la main" in content
        reloaded = read_section(str(yaml_path), "networks.networks")
        assert reloaded == {"10.0.0.0/8": {"name": "lab"}}
        assert list_pending_changes(memory_conn) == []

    def test_update_asns_writes_and_requests_no_restart(
        self, akvorado_yaml_path: Path, memory_conn: sqlite3.Connection
    ) -> None:
        """Les numéros d'AS doivent atterrir en ENTIERS dans le YAML.

        Ce test attendait auparavant des clés CHAÎNES (`{"64512": ...}`) : il
        figeait comme comportement attendu un défaut mesuré le 2026-08-06. La
        file d'attente sérialise en JSON, or JSON n'a pas de clé entière — la
        table des noms d'AS partait donc en `akvorado.yaml` avec des clés
        chaînes qu'Akvorado ne rapproche d'aucun AS observé. Les noms
        n'auraient jamais été appliqués, sans erreur nulle part.

        Un test qui décrit le bug plutôt que l'intention le rend permanent.
        """
        _stage_update_section(
            memory_conn,
            "asns",
            {64512: "site-A", 64513: "site-B"},
        )
        restart_spy = _RestartSpy()

        result = apply_pending_changes(
            memory_conn,
            {"akvorado.yaml": str(akvorado_yaml_path)},
            restart_fn=restart_spy,
        )

        assert result.success is True
        reloaded = read_section(str(akvorado_yaml_path), "clickhouse.asns")
        assert reloaded == {64512: "site-A", 64513: "site-B"}
        assert all(isinstance(key, int) for key in reloaded), (
            f"clés d'AS écrites en chaîne : {list(reloaded)!r} — Akvorado ne les "
            "rapprocherait d'aucun AS observé, la table resterait sans effet"
        )
        # "asns" a restart_services=() -> union vide -> restart jamais appele
        assert restart_spy.calls == []
        assert list_pending_changes(memory_conn) == []

    def test_multiple_files_in_same_queue_writes_all_and_restarts_union_once_each(
        self,
        yaml_path: Path,
        console_yaml_path: Path,
        inlet_yaml_path: Path,
        memory_conn: sqlite3.Connection,
    ) -> None:
        _stage_update_section(memory_conn, "networks", {"10.0.0.0/8": {"name": "lab"}})
        _stage_update_section(
            memory_conn,
            "saved_filters",
            [{"description": "nouveau filtre", "content": "Proto = 6"}],
        )
        _stage_update_section(
            memory_conn,
            "flow_inputs",
            [{"type": "udp", "decoder": "sflow", "listen": "0.0.0.0:6343"}],
        )
        restart_spy = _RestartSpy()

        result = apply_pending_changes(
            memory_conn,
            {
                "outlet.yaml": str(yaml_path),
                "console.yaml": str(console_yaml_path),
                "inlet.yaml": str(inlet_yaml_path),
            },
            restart_fn=restart_spy,
        )

        assert result.success is True
        assert read_section(str(yaml_path), "networks.networks") == {"10.0.0.0/8": {"name": "lab"}}
        assert read_section(str(console_yaml_path), "database.saved-filters") == [
            {"description": "nouveau filtre", "content": "Proto = 6"}
        ]
        assert read_section(str(inlet_yaml_path), "flow.inputs") == [
            {"type": "udp", "decoder": "sflow", "listen": "0.0.0.0:6343"}
        ]
        # union de {akvorado-outlet} ∪ {akvorado-console} ∪ {akvorado-inlet}, un seul appel
        assert len(restart_spy.calls) == 1
        assert set(restart_spy.calls[0]) == {
            "akvorado-outlet",
            "akvorado-console",
            "akvorado-inlet",
        }
        assert list_pending_changes(memory_conn) == []

    def test_validation_failure_writes_nothing_on_any_file(
        self,
        yaml_path: Path,
        console_yaml_path: Path,
        akvorado_yaml_path: Path,
        memory_conn: sqlite3.Connection,
    ) -> None:
        original_outlet_hash = compute_file_hash(str(yaml_path))
        original_console_hash = compute_file_hash(str(console_yaml_path))
        original_akvorado_hash = compute_file_hash(str(akvorado_yaml_path))

        _stage_update_section(memory_conn, "networks", {"10.0.0.0/8": {"name": "lab"}})
        _stage_update_section(memory_conn, "asns", {"64512": "site-A"})
        # saved_filters invalide : entree sans 'content' -> validation KO
        _stage_update_section(memory_conn, "saved_filters", [{"description": "incomplet"}])
        restart_spy = _RestartSpy()

        result = apply_pending_changes(
            memory_conn,
            {
                "outlet.yaml": str(yaml_path),
                "console.yaml": str(console_yaml_path),
                "akvorado.yaml": str(akvorado_yaml_path),
            },
            restart_fn=restart_spy,
        )

        assert result.success is False
        assert compute_file_hash(str(yaml_path)) == original_outlet_hash
        assert compute_file_hash(str(console_yaml_path)) == original_console_hash
        assert compute_file_hash(str(akvorado_yaml_path)) == original_akvorado_hash
        assert restart_spy.calls == []
        assert len(list_pending_changes(memory_conn)) == 3

    def test_write_failure_on_second_file_restores_first_and_keeps_queue(
        self,
        yaml_path: Path,
        console_yaml_path: Path,
        memory_conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        original_outlet_content = yaml_path.read_text(encoding="utf-8")
        original_console_content = console_yaml_path.read_text(encoding="utf-8")

        _stage_update_section(memory_conn, "networks", {"10.0.0.0/8": {"name": "lab"}})
        _stage_update_section(
            memory_conn,
            "saved_filters",
            [{"description": "nouveau filtre", "content": "Proto = 6"}],
        )

        import app.clients.yaml_editor as yaml_editor_module

        real_write_section = yaml_editor_module.write_section
        call_count = {"n": 0}

        def _write_section_second_file_fails(
            path: str, dotted_key: str, value: object, *, expected_hash: str
        ) -> None:
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise OSError("simulated crash writing second file")
            real_write_section(path, dotted_key, value, expected_hash=expected_hash)

        monkeypatch.setattr(
            "app.services.config_writer.write_section", _write_section_second_file_fails
        )
        restart_spy = _RestartSpy()

        result = apply_pending_changes(
            memory_conn,
            {
                "outlet.yaml": str(yaml_path),
                "console.yaml": str(console_yaml_path),
            },
            restart_fn=restart_spy,
        )

        assert result.success is False
        assert yaml_path.read_text(encoding="utf-8") == original_outlet_content
        assert console_yaml_path.read_text(encoding="utf-8") == original_console_content
        assert restart_spy.calls == []
        assert len(list_pending_changes(memory_conn)) == 2

    def test_restart_failure_restores_all_written_files_and_keeps_queue(
        self,
        yaml_path: Path,
        console_yaml_path: Path,
        memory_conn: sqlite3.Connection,
    ) -> None:
        original_outlet_content = yaml_path.read_text(encoding="utf-8")
        original_console_content = console_yaml_path.read_text(encoding="utf-8")

        _stage_update_section(memory_conn, "networks", {"10.0.0.0/8": {"name": "lab"}})
        _stage_update_section(
            memory_conn,
            "saved_filters",
            [{"description": "nouveau filtre", "content": "Proto = 6"}],
        )
        restart_spy = _RestartSpy(fail=True)

        result = apply_pending_changes(
            memory_conn,
            {
                "outlet.yaml": str(yaml_path),
                "console.yaml": str(console_yaml_path),
            },
            restart_fn=restart_spy,
        )

        assert result.success is False
        assert result.rolled_back is True
        assert yaml_path.read_text(encoding="utf-8") == original_outlet_content
        assert console_yaml_path.read_text(encoding="utf-8") == original_console_content
        assert len(list_pending_changes(memory_conn)) == 2

    def test_mixed_exporter_and_section_changes_both_applied(
        self, yaml_path: Path, memory_conn: sqlite3.Connection
    ) -> None:
        stage_change(
            memory_conn,
            change_type="add_exporter",
            payload={
                "cidr": "192.0.2.23/32",
                "name": "clm",
                "if_indexes": {},
                "default": {"name": "unknown", "boundary": "undefined"},
            },
            author="claude",
        )
        _stage_update_section(memory_conn, "networks", {"10.0.0.0/8": {"name": "lab"}})
        restart_spy = _RestartSpy()

        result = apply_pending_changes(
            memory_conn,
            {"outlet.yaml": str(yaml_path)},
            restart_fn=restart_spy,
        )

        assert result.success is True
        reloaded_exporters = load_declared_exporters(str(yaml_path))
        assert any(e.name == "clm" for e in reloaded_exporters)
        assert read_section(str(yaml_path), "networks.networks") == {"10.0.0.0/8": {"name": "lab"}}
        assert restart_spy.calls == [("akvorado-outlet",)]
        assert list_pending_changes(memory_conn) == []

    def test_concurrent_modification_between_read_and_write_raises_and_writes_nothing(
        self,
        yaml_path: Path,
        memory_conn: sqlite3.Connection,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Le fichier est modifié EXTERNEMENT entre la lecture du hash faite par
        `apply_pending_changes` et l'écriture réelle faite par `write_section`
        (SSH manuel pendant que l'UI est ouverte). On simule cette fenêtre en
        modifiant le fichier sur disque au moment précis où `write_section` est
        appelé (monkeypatch), pour que le hash lu en amont par
        `apply_pending_changes` soit déjà périmé au moment de l'écriture réelle.
        """
        original_content = yaml_path.read_text(encoding="utf-8")
        _stage_update_section(memory_conn, "networks", {"10.0.0.0/8": {"name": "lab"}})

        import app.clients.yaml_editor as yaml_editor_module

        real_write_section = yaml_editor_module.write_section

        def _write_section_with_concurrent_edit(
            path: str, dotted_key: str, value: object, *, expected_hash: str
        ) -> None:
            Path(path).write_text(original_content + "\n# modifie en SSH\n", encoding="utf-8")
            real_write_section(path, dotted_key, value, expected_hash=expected_hash)

        monkeypatch.setattr(
            "app.services.config_writer.write_section", _write_section_with_concurrent_edit
        )

        result = apply_pending_changes(
            memory_conn,
            {"outlet.yaml": str(yaml_path)},
            restart_fn=_RestartSpy(),
        )

        assert result.success is False
        assert "modifi" in result.message.lower() or "concurrent" in result.message.lower()
        assert yaml_path.read_text(encoding="utf-8") == original_content + "\n# modifie en SSH\n"
        assert len(list_pending_changes(memory_conn)) == 1

    def test_unknown_section_key_in_payload_errors_without_writing(
        self, yaml_path: Path, memory_conn: sqlite3.Connection
    ) -> None:
        original_content = yaml_path.read_text(encoding="utf-8")
        _stage_update_section(memory_conn, "does_not_exist", {"a": 1})

        result = apply_pending_changes(
            memory_conn,
            {"outlet.yaml": str(yaml_path)},
            restart_fn=_RestartSpy(),
        )

        assert result.success is False
        assert yaml_path.read_text(encoding="utf-8") == original_content
        assert len(list_pending_changes(memory_conn)) == 1

    def test_empty_queue_is_trivial_success_without_restart_call(
        self, yaml_path: Path, memory_conn: sqlite3.Connection
    ) -> None:
        restart_spy = _RestartSpy()

        result = apply_pending_changes(
            memory_conn,
            {"outlet.yaml": str(yaml_path)},
            restart_fn=restart_spy,
        )

        assert result.success is True
        assert restart_spy.calls == []


class TestTypesDeClesApresJson:
    """Le passage par la file d'attente ne doit pas changer le TYPE des clés.

    DÉFAUT MESURÉ (2026-08-06) : la file stocke chaque changement en JSON, et
    **JSON n'a pas de clé entière**. Un mapping `{64501: "ACME"}` mis en
    attente en ressortait en `{"64501": "ACME"}`. Écrite telle quelle dans
    `akvorado.yaml`, la table des noms d'AS aurait porté des clés CHAÎNES
    qu'Akvorado ne rapproche d'aucun AS observé : les noms n'auraient jamais
    été appliqués — sans erreur nulle part, et avec un « changement appliqué »
    affiché en succès. Le zéro silencieux, appliqué à de la configuration.
    """

    def test_json_transforme_bien_les_cles_entieres_en_chaines(self) -> None:
        """La prémisse du défaut, vérifiée plutôt que supposée."""
        import json

        apres = json.loads(json.dumps({64501: "ACME"}))
        assert list(apres) == ["64501"], (
            "si JSON préservait les clés entières, la restauration serait inutile"
        )

    def test_les_cles_entieres_sont_restaurees_avant_ecriture(self) -> None:
        import json

        from app.services.config_sections import get_section
        from app.services.config_writer import _restore_key_types

        apres_file = json.loads(json.dumps({64501: "ACME", 64502: "Autre"}))
        restaure = _restore_key_types(apres_file, get_section("asns"))

        assert restaure == {64501: "ACME", 64502: "Autre"}
        assert all(isinstance(key, int) for key in restaure), (
            "clés d'AS écrites en chaîne : Akvorado ne les rapprocherait "
            "d'aucun AS observé, la table resterait sans effet"
        )

    def test_les_sections_a_cles_non_entieres_ne_sont_pas_touchees(self) -> None:
        """Un CIDR n'est pas un entier : le convertir le détruirait."""
        from app.services.config_sections import get_section
        from app.services.config_writer import _restore_key_types

        plan = {"100.64.0.0/10": {"name": "mesh"}, "192.168.1.0/24": {"name": "lan"}}
        assert _restore_key_types(plan, get_section("networks")) == plan

    def test_une_cle_non_convertible_est_preservee_pas_avalee(self) -> None:
        """Convertir en silence ce qui n'est pas un entier serait le défaut même.

        La clé est laissée telle quelle pour que la validation de section, qui
        suit, produise un message précis.
        """
        from app.services.config_sections import get_section
        from app.services.config_writer import _restore_key_types

        assert _restore_key_types({"pas-un-entier": "x"}, get_section("asns")) == {
            "pas-un-entier": "x"
        }


class TestCatchallIPv6:
    """`_is_catchall_cidr` doit reconnaitre le catchall IPv6, pas seulement IPv4.

    DEFAUT MESURE A L'ECRAN (2026-08-09), sur un deploiement NEUF de `stack/`
    sur machine nue : l'ecran Exportateurs affichait « 1 exportateur » — ligne
    `exportateur-non-resolu`, adresse `::` — alors que ClickHouse contenait
    ZERO flux.

    Cause : la fonction ne traitait que l'IPv4 (`if network.version == 4: ...`
    puis `return False`). `::/0`, qui couvre l'Internet entier, etait donc
    classe NON-catchall, et `_find_declared_match` le traitait comme la
    declaration NOMINATIVE d'un routeur reel.

    Pourquoi ce n'est pas un cas particulier : Akvorado ecoute en IPv6 par
    defaut et le template du paquet ecrit `::/0` pour le repli SNMP. TOUTE
    installation neuve affichait donc un routeur fantome, et l'exploitant
    cherchait une panne sur un equipement inexistant. C'est la famille du
    « zero silencieux » : une valeur FABRIQUEE rendue indiscernable d'une
    vraie mesure.
    """

    def test_ipv6_catchall_est_reconnu(self) -> None:
        # Le cas exact du template livre : sans cette ligne, routeur fantome.
        assert _is_catchall_cidr("::/0") is True

    def test_ipv6_prefixe_large_est_catchall(self) -> None:
        # Un /64 couvre un reseau entier : ce n'est pas un routeur nomme.
        assert _is_catchall_cidr("2001:db8::/64") is True

    def test_ipv6_adresse_unique_reste_nominative(self) -> None:
        # /128 = l'equivalent IPv6 du /32 : une machine precise, donc declaree.
        assert _is_catchall_cidr("2001:db8::1/128") is False

    def test_ipv4_inchange(self) -> None:
        # NON-REGRESSION : le comportement IPv4 existant ne bouge pas.
        assert _is_catchall_cidr("0.0.0.0/0") is True
        assert _is_catchall_cidr("10.0.0.0/8") is True
        assert _is_catchall_cidr("10.0.0.1/32") is False

    def test_cidr_invalide_reste_non_catchall(self) -> None:
        # NON-REGRESSION : degradation sure, jamais d'exception.
        assert _is_catchall_cidr("pas-un-cidr") is False

    def test_le_repli_snmp_du_template_ne_cree_pas_un_exportateur_nominatif(
        self, tmp_path: Path
    ) -> None:
        """Le defaut TEL QU'IL S'EST PRODUIT, bout en bout depuis le YAML.

        Reproduit la forme reelle du `outlet.yaml` genere par `stack/` : le
        repli SNMP `::/0`. Il doit etre lu comme catchall, jamais comme la
        declaration d'un routeur.
        """
        yaml_path = tmp_path / "outlet.yaml"
        yaml_path.write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: snmp\n"
            "      exporters:\n"
            '        "::/0":\n'
            "          name: exportateur-non-resolu\n"
            "          default:\n"
            "            name: interface-non-resolue\n",
            encoding="utf-8",
        )

        declared = load_declared_exporters(str(yaml_path))

        assert len(declared) == 1
        assert declared[0].is_catchall is True, (
            "le repli SNMP ::/0 est lu comme un routeur declare -> "
            "exportateur fantome a l'ecran sur toute installation neuve"
        )
