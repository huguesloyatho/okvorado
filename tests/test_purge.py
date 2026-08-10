"""Tests du service Purge (`app/services/purge.py`).

Aucune infra : `sqlite3.connect(":memory:")` pour les tables, `tmp_path` pour
les fichiers `.bak-*`. Chaque test de garde ci-dessous a été fait mordre
volontairement (cycle RED/GREEN documenté dans le rapport de livraison).
"""

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.db import SCHEMA
from app.services.purge import (
    PURGEABLE_TABLES,
    execute_backup_purge,
    execute_table_purge,
    list_backup_files,
    preview_backup_purge,
    preview_table_purge,
)


def _il_y_a_jours(n: int) -> str:
    """Horodatage SQLite situé `n` jours dans le passé, relatif à MAINTENANT.

    DÉFAUT MESURÉ (2026-08-09) : ces tests portaient des dates EN DUR
    (« 2026-08-01 ») censées représenter une ligne « trop récente pour être
    purgée » face à un seuil de 30 jours. Le simple écoulement du temps les
    fait basculer du côté éligible — un test a cassé tout seul le 9 août,
    sans qu'aucune ligne applicative n'ait changé, et a fait suspecter à tort
    la modification en cours. Un oracle qui dépend de l'ÂGE se calcule
    toujours par rapport à l'instant présent, jamais sur une date figée.
    """
    return (datetime.now() - timedelta(days=n)).strftime("%Y-%m-%d %H:%M:%S")


@pytest.fixture
def memory_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _make_backup(directory: Path, timestamp: str, content: bytes = b"x") -> Path:
    path = directory / f"outlet.yaml.bak-{timestamp}"
    path.write_bytes(content)
    return path


# ---------------------------------------------------------------------------
# list_backup_files — tri chronologique via tri lexicographique du nom
# ---------------------------------------------------------------------------


def test_list_backup_files_triees_du_plus_recent_au_plus_ancien(tmp_path: Path) -> None:
    _make_backup(tmp_path, "20260101000000")
    _make_backup(tmp_path, "20260103000000")
    _make_backup(tmp_path, "20260102000000")

    files = list_backup_files(tmp_path)

    assert [f.name for f in files] == [
        "outlet.yaml.bak-20260103000000",
        "outlet.yaml.bak-20260102000000",
        "outlet.yaml.bak-20260101000000",
    ]


def test_list_backup_files_ignore_les_fichiers_hors_pattern(tmp_path: Path) -> None:
    _make_backup(tmp_path, "20260101000000")
    (tmp_path / "outlet.yaml").write_text("config")
    (tmp_path / "outlet.yaml.tmp-20260101000000").write_text("scratch")

    files = list_backup_files(tmp_path)

    assert [f.name for f in files] == ["outlet.yaml.bak-20260101000000"]


# ---------------------------------------------------------------------------
# preview_backup_purge — AUCUN effet de bord (preuve de morsure)
# ---------------------------------------------------------------------------


def test_preview_backup_purge_naffecte_aucun_fichier_sur_disque(tmp_path: Path) -> None:
    timestamps = [
        "20260101000000",
        "20260102000000",
        "20260103000000",
        "20260104000000",
        "20260105000000",
    ]
    for ts in timestamps:
        _make_backup(tmp_path, ts)

    preview_backup_purge(tmp_path, keep_n=2)

    # RED d'origine : une implémentation naïve qui supprimerait pendant le
    # preview ferait tomber cette assertion à 2 (ou moins) au lieu de 5 —
    # c'est la preuve que ce test mord vraiment sur un effet de bord.
    remaining = list(tmp_path.glob("*.bak-*"))
    assert len(remaining) == 5


def test_preview_backup_purge_annonce_le_perimetre_exact(tmp_path: Path) -> None:
    timestamps = [
        "20260101000000",
        "20260102000000",
        "20260103000000",
        "20260104000000",
        "20260105000000",
    ]
    paths = [_make_backup(tmp_path, ts, content=b"abcd") for ts in timestamps]

    preview = preview_backup_purge(tmp_path, keep_n=2)

    # keep_n=2 garde les 2 plus récents (...105, ...104) -> 3 candidats à la
    # suppression, exactement les 3 plus anciens.
    assert preview.total_count == 3
    assert set(preview.files_to_delete) == {
        "outlet.yaml.bak-20260101000000",
        "outlet.yaml.bak-20260102000000",
        "outlet.yaml.bak-20260103000000",
    }
    assert preview.total_bytes == 3 * len(b"abcd")
    assert preview.keep_n == 2
    assert preview.directory == str(tmp_path)
    assert len(paths) == 5  # sanity: les 5 fichiers existent bien au départ


def test_preview_backup_purge_keep_n_zero_supprime_tout(tmp_path: Path) -> None:
    _make_backup(tmp_path, "20260101000000")
    _make_backup(tmp_path, "20260102000000")

    preview = preview_backup_purge(tmp_path, keep_n=0)

    assert preview.total_count == 2


def test_preview_backup_purge_keep_n_superieur_au_total_ne_supprime_rien(tmp_path: Path) -> None:
    _make_backup(tmp_path, "20260101000000")

    preview = preview_backup_purge(tmp_path, keep_n=10)

    assert preview.total_count == 0
    assert preview.files_to_delete == []


def test_preview_backup_purge_keep_n_negatif_leve_value_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="keep_n"):
        preview_backup_purge(tmp_path, keep_n=-1)


# ---------------------------------------------------------------------------
# execute_backup_purge — supprime réellement, et RIEN DE PLUS
# ---------------------------------------------------------------------------


def test_execute_backup_purge_supprime_exactement_le_preview_et_garde_le_reste(
    tmp_path: Path,
) -> None:
    timestamps = [
        "20260101000000",
        "20260102000000",
        "20260103000000",
        "20260104000000",
        "20260105000000",
    ]
    for ts in timestamps:
        _make_backup(tmp_path, ts)

    preview = preview_backup_purge(tmp_path, keep_n=2)
    result = execute_backup_purge(preview)

    assert result.deleted_count == 3
    assert result.errors == []

    remaining_names = {f.name for f in tmp_path.glob("*.bak-*")}
    assert remaining_names == {
        "outlet.yaml.bak-20260104000000",
        "outlet.yaml.bak-20260105000000",
    }


def test_execute_backup_purge_fichier_absent_entre_preview_et_execute_va_dans_errors(
    tmp_path: Path,
) -> None:
    _make_backup(tmp_path, "20260101000000")
    _make_backup(tmp_path, "20260102000000")
    _make_backup(tmp_path, "20260103000000")

    preview = preview_backup_purge(tmp_path, keep_n=0)
    assert preview.total_count == 3

    # Simule une disparition manuelle d'UN des fichiers du preview avant execute.
    (tmp_path / "outlet.yaml.bak-20260102000000").unlink()

    result = execute_backup_purge(preview)

    assert len(result.errors) == 1
    assert "20260102000000" in result.errors[0]
    # Les DEUX autres fichiers du preview doivent quand même avoir été supprimés.
    assert result.deleted_count == 2
    assert list(tmp_path.glob("*.bak-*")) == []


# ---------------------------------------------------------------------------
# preview_table_purge — AUCUN effet de bord, périmètre exact
# ---------------------------------------------------------------------------


def _insert_audit_row(conn: sqlite3.Connection, happened_at: str, action: str = "test") -> None:
    conn.execute(
        "INSERT INTO audit_log (happened_at, actor, action, detail) VALUES (?, 'test', ?, '')",
        (happened_at, action),
    )
    conn.commit()


def test_preview_table_purge_naffecte_aucune_ligne(memory_conn: sqlite3.Connection) -> None:
    _insert_audit_row(memory_conn, "2020-01-01 00:00:00")
    _insert_audit_row(memory_conn, _il_y_a_jours(5))

    count_before = memory_conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]

    preview_table_purge(memory_conn, "audit_log", max_age_days=30)

    # RED d'origine : une implémentation qui exécuterait le DELETE pendant le
    # preview ferait tomber count_after à 1 au lieu de 2.
    count_after = memory_conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    assert count_after == count_before == 2


def test_preview_table_purge_annonce_le_perimetre_exact(memory_conn: sqlite3.Connection) -> None:
    _insert_audit_row(memory_conn, "2020-01-01 00:00:00")  # tres vieux
    _insert_audit_row(memory_conn, "2020-06-01 00:00:00")  # tres vieux
    _insert_audit_row(memory_conn, _il_y_a_jours(5))  # recent

    preview = preview_table_purge(memory_conn, "audit_log", max_age_days=30)

    assert preview.rows_to_delete == 2
    assert preview.table == "audit_log"
    assert preview.max_age_days == 30
    assert preview.oldest_row_age_days is not None
    assert preview.oldest_row_age_days > 0


def test_preview_table_purge_aucune_ligne_ancienne_donne_zero(
    memory_conn: sqlite3.Connection,
) -> None:
    _insert_audit_row(memory_conn, _il_y_a_jours(5))

    preview = preview_table_purge(memory_conn, "audit_log", max_age_days=30)

    assert preview.rows_to_delete == 0
    assert preview.oldest_row_age_days is None


def test_preview_table_purge_max_age_days_zero_leve_value_error(
    memory_conn: sqlite3.Connection,
) -> None:
    with pytest.raises(ValueError, match="max_age_days"):
        preview_table_purge(memory_conn, "audit_log", max_age_days=0)


def test_preview_table_purge_max_age_days_negatif_leve_value_error(
    memory_conn: sqlite3.Connection,
) -> None:
    with pytest.raises(ValueError, match="max_age_days"):
        preview_table_purge(memory_conn, "audit_log", max_age_days=-5)


# ---------------------------------------------------------------------------
# Table hors allowlist — refusée AVANT tout accès SQL (preuve de morsure)
# ---------------------------------------------------------------------------


def test_preview_table_purge_table_hors_allowlist_leve_value_error_sans_toucher_la_db(
    memory_conn: sqlite3.Connection,
) -> None:
    assert "exporters" not in PURGEABLE_TABLES

    # État de référence : nombre total de lignes dans TOUTES les tables
    # connues du schéma. Si l'implémentation exécutait une requête SQL avant
    # la validation de l'allowlist, une table `exporters` inexistante lèverait
    # une `sqlite3.OperationalError` (et pas un `ValueError` métier) — la
    # preuve que la garde agit AVANT tout accès SQL est que l'exception levée
    # est bien celle attendue, pas une erreur SQL de "no such table".
    with pytest.raises(ValueError, match="allowlist") as exc_info:
        preview_table_purge(memory_conn, "exporters", max_age_days=30)

    assert not isinstance(exc_info.value, sqlite3.Error)

    # La connexion reste utilisable normalement ensuite : aucune transaction
    # laissée en état incohérent par la tentative refusée.
    memory_conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()


def test_execute_table_purge_table_hors_allowlist_leve_value_error(
    memory_conn: sqlite3.Connection,
) -> None:
    from app.services.purge import TablePurgePreview

    # Construit un preview "forgé" directement (contourne preview_table_purge)
    # pour prouver que execute_table_purge revalide lui-même — défense en
    # profondeur, ne fait jamais confiance à l'objet reçu.
    forged_preview = TablePurgePreview(
        table="exporters",
        max_age_days=30,
        rows_to_delete=999,
        oldest_row_age_days=None,
    )

    with pytest.raises(ValueError, match="allowlist"):
        execute_table_purge(memory_conn, forged_preview)


# ---------------------------------------------------------------------------
# execute_table_purge — supprime réellement, les lignes récentes survivent
# ---------------------------------------------------------------------------


def test_execute_table_purge_supprime_les_vieilles_lignes_et_garde_les_recentes(
    memory_conn: sqlite3.Connection,
) -> None:
    _insert_audit_row(memory_conn, "2020-01-01 00:00:00", action="vieux-1")
    _insert_audit_row(memory_conn, "2020-06-01 00:00:00", action="vieux-2")
    _insert_audit_row(memory_conn, _il_y_a_jours(5), action="recent")

    preview = preview_table_purge(memory_conn, "audit_log", max_age_days=30)
    result = execute_table_purge(memory_conn, preview)

    assert result.deleted_count == 2

    remaining_actions = {
        row[0] for row in memory_conn.execute("SELECT action FROM audit_log").fetchall()
    }
    assert remaining_actions == {"recent"}


def test_execute_table_purge_sur_pending_config_changes(memory_conn: sqlite3.Connection) -> None:
    memory_conn.execute(
        "INSERT INTO pending_config_changes (change_type, payload, author, created_at) "
        "VALUES ('add_exporter', '{}', 'test', '2020-01-01 00:00:00')"
    )
    memory_conn.execute(
        "INSERT INTO pending_config_changes (change_type, payload, author, created_at) "
        "VALUES ('add_exporter', '{}', 'test', '2026-08-01 00:00:00')"
    )
    memory_conn.commit()

    preview = preview_table_purge(memory_conn, "pending_config_changes", max_age_days=30)
    assert preview.rows_to_delete == 1

    result = execute_table_purge(memory_conn, preview)
    assert result.deleted_count == 1

    remaining = memory_conn.execute("SELECT COUNT(*) FROM pending_config_changes").fetchone()[0]
    assert remaining == 1


def test_execute_table_purge_sur_snmp_inventory(memory_conn: sqlite3.Connection) -> None:
    memory_conn.execute(
        "INSERT INTO snmp_inventory (address, status, last_attempt_at) "
        "VALUES ('192.0.2.1', 'ok', '2020-01-01 00:00:00')"
    )
    memory_conn.execute(
        "INSERT INTO snmp_inventory (address, status, last_attempt_at) "
        "VALUES ('192.0.2.2', 'ok', '2026-08-01 00:00:00')"
    )
    memory_conn.commit()

    preview = preview_table_purge(memory_conn, "snmp_inventory", max_age_days=30)
    result = execute_table_purge(memory_conn, preview)

    assert result.deleted_count == 1
    remaining = memory_conn.execute("SELECT address FROM snmp_inventory").fetchall()
    assert [row[0] for row in remaining] == ["192.0.2.2"]


def test_execute_table_purge_ignore_une_ligne_devenue_eligible_apres_le_preview(
    memory_conn: sqlite3.Connection,
) -> None:
    """Anti-TOCTOU RÉEL — défaut reproduit le 2026-08-08 (revue de diff) :
    l'ancienne implémentation d'`execute_table_purge` ré-exécutait la même
    clause temporelle (`WHERE happened_at < datetime('now', ?)`) au lieu de
    supprimer les lignes FIGÉES par le preview. Une ligne absente du preview
    (pas encore assez vieille) qui devient éligible ENTRE le preview et
    l'exécution — via une correction manuelle de date, un fuseau horaire, une
    horloge système ajustée, ou simplement l'écoulement du temps sur un
    intervalle proche du seuil — était alors supprimée quand même,
    contredisant la promesse documentée du module (« ce que l'utilisateur a
    vu est exactement ce qui part »).

    `execute_table_purge` doit supprimer UNIQUEMENT `preview.row_ids`, jamais
    un nouveau scan de la table.
    """
    # Date RELATIVE à maintenant, jamais une date en dur.
    # DÉFAUT MESURÉ (2026-08-09) : ce test portait `"2026-07-10 00:00:00"`
    # avec un seuil de 30 jours — donc « pas encore éligible » au moment où
    # il a été écrit. Le 9 août, cette même ligne a dépassé les 30 jours et
    # le test a cassé tout seul, sans qu'aucune ligne de code applicatif
    # n'ait changé. Une date en dur dans un test dont l'oracle dépend de
    # l'ÂGE est une bombe à retardement : elle se déclenche un jour arbitraire
    # et fait accuser à tort la modification en cours.
    ligne_recente = (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S")
    _insert_audit_row(memory_conn, ligne_recente, action="pas-encore-eligible")

    preview = preview_table_purge(memory_conn, "audit_log", max_age_days=30)
    assert preview.rows_to_delete == 0
    assert preview.row_ids == []

    # La ligne devient éligible APRÈS le preview (simulé ici par une
    # modification directe — en prod ce serait l'écoulement du temps réel
    # entre deux appels HTTP preview/execute, ou une horloge ajustée).
    memory_conn.execute(
        "UPDATE audit_log SET happened_at = datetime('now', '-31 days') "
        "WHERE action = 'pas-encore-eligible'"
    )
    memory_conn.commit()

    result = execute_table_purge(memory_conn, preview)

    assert result.deleted_count == 0
    remaining = memory_conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    assert remaining == 1  # la ligne survit : absente du preview confirmé


def test_execute_table_purge_supprime_precisement_les_row_ids_fige(
    memory_conn: sqlite3.Connection,
) -> None:
    """Le nombre de lignes supprimées correspond EXACTEMENT à `row_ids`, même
    si de nouvelles lignes tout aussi vieilles apparaissent entre-temps."""
    _insert_audit_row(memory_conn, "2020-01-01 00:00:00", action="dans-le-preview")

    preview = preview_table_purge(memory_conn, "audit_log", max_age_days=30)
    assert preview.rows_to_delete == 1

    # Une NOUVELLE ligne tout aussi ancienne apparaît après le preview.
    _insert_audit_row(memory_conn, "2020-01-01 00:00:00", action="apparue-apres-preview")

    result = execute_table_purge(memory_conn, preview)

    assert result.deleted_count == 1  # seulement celle du preview, pas la nouvelle
    remaining_actions = {
        row[0] for row in memory_conn.execute("SELECT action FROM audit_log").fetchall()
    }
    assert remaining_actions == {"apparue-apres-preview"}
