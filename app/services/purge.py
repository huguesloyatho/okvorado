"""Service Purge — suppression contrôlée de données locales à Okvorado.

Deux familles de purge, toutes deux en deux temps **preview puis execute** :

1. Fichiers de backup `.bak-YYYYmmddHHMMSS` produits par
   `app/clients/akvorado_yaml.py` avant chaque écriture de `outlet.yaml`.
2. Lignes anciennes des tables SQLite internes de ce projet (jamais les
   tables ClickHouse : la rétention de `flows*` est le périmètre de
   `app/services/retention.py`, pas de celui-ci).

RÈGLE ABSOLUE DU PROJET (CLAUDE.md) : ne jamais supprimer de données réelles
sans que l'utilisateur l'ait demandé explicitement. Le découpage preview/
execute rend cette règle mécanique plutôt que déclarative :
- `preview_*` est une fonction **pure côté effet** (aucune écriture, aucune
  suppression) — elle ne fait qu'annoncer ce qui SERAIT supprimé.
- `execute_*` ne supprime QUE ce que le preview a listé, jamais un nouveau
  scan du répertoire/de la table au moment de l'exécution (protection TOCTOU :
  ce que l'utilisateur a vu et confirmé est exactement ce qui part).
- Aucune fonction de ce module ne s'invoque toute seule : le déclenchement
  (bouton, tâche planifiée) est décidé par le routeur/l'appelant, hors
  périmètre de ce fichier.

Zéro silencieux : `execute_backup_purge` distingue une suppression réussie
d'un fichier disparu entre-temps (`errors`, pas une exception fatale) — un
`deleted_count` ne masque jamais un échec partiel.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from pydantic import BaseModel

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Purge des fichiers de backup `.bak-*`
# ---------------------------------------------------------------------------


class BackupPurgePreview(BaseModel):
    """Ce qui SERAIT supprimé par une purge des fichiers `.bak-*`.

    `directory` et `files_to_delete` (noms de fichiers, pas de chemins
    absolus — on évite d'exposer la structure disque complète dans une
    réponse qui peut être affichée/loggée) permettent de reconstruire les
    chemins exacts à l'exécution sans re-scanner le répertoire.
    """

    directory: str
    files_to_delete: list[str]
    total_count: int
    total_bytes: int
    keep_n: int


class BackupPurgeResult(BaseModel):
    """Résultat réel d'une purge de fichiers `.bak-*`.

    `errors` non vide signifie une suppression PARTIELLE : `deleted_count`
    seul ne permet jamais de le déduire (zéro silencieux — CLAUDE.md règle
    n°2), l'appelant doit toujours lire `errors`.
    """

    deleted_count: int
    deleted_bytes: int
    errors: list[str]


def list_backup_files(directory: Path, pattern: str = "*.bak-*") -> list[Path]:
    """Liste les fichiers de backup d'un répertoire, du plus récent au plus ancien.

    Le format produit par `akvorado_yaml.py` est `<fichier>.bak-YYYYmmddHHMMSS` :
    l'horodatage est ISO-like (année puis mois puis jour...), donc le tri
    LEXICOGRAPHIQUE des noms est équivalent au tri chronologique. Pas besoin
    de parser l'horodatage — trier les `Path` par leur `.name` en ordre
    décroissant suffit et évite tout risque de format de date mal parsé.

    HYPOTHÈSE DE CONFIANCE : `directory` provient de la config applicative
    (appelant de confiance), jamais d'un input utilisateur final — aucune
    protection anti path-traversal n'est nécessaire ici (voir CONTRACT.md,
    le profil de menace de ce projet porte sur le SQL et pas sur ce chemin).
    """
    return sorted(directory.glob(pattern), key=lambda p: p.name, reverse=True)


def preview_backup_purge(directory: Path, keep_n: int) -> BackupPurgePreview:
    """Annonce quels fichiers `.bak-*` SERAIENT supprimés — n'en supprime aucun.

    Garde les `keep_n` fichiers les plus récents (les premiers de
    `list_backup_files`, déjà triés du plus récent au plus ancien), le reste
    est candidat à la suppression. Fonction pure côté effet : appelable sans
    risque à tout moment pour rafraîchir un écran de confirmation.

    Raises:
        ValueError: si `keep_n` est négatif.
    """
    if keep_n < 0:
        raise ValueError(f"keep_n doit être positif ou nul, reçu {keep_n!r}")

    all_backups = list_backup_files(directory)
    to_delete = all_backups[keep_n:]
    total_bytes = 0
    files_to_delete: list[str] = []
    for backup_path in to_delete:
        try:
            total_bytes += backup_path.stat().st_size
        except OSError as exc:
            # Le fichier a pu disparaître entre le glob() et le stat() (course
            # bénigne, ex. une autre purge concurrente) : on ne le compte pas
            # dans les octets mais on le garde dans la liste — c'est
            # `execute_backup_purge` qui traitera son absence proprement.
            log.error(
                "impossible de lire la taille du backup, ignoree dans le total: path=%s erreur=%s",
                backup_path,
                exc,
            )
        files_to_delete.append(backup_path.name)

    return BackupPurgePreview(
        directory=str(directory),
        files_to_delete=files_to_delete,
        total_count=len(files_to_delete),
        total_bytes=total_bytes,
        keep_n=keep_n,
    )


def execute_backup_purge(preview: BackupPurgePreview) -> BackupPurgeResult:
    """Supprime réellement les fichiers listés dans `preview` — rien d'autre.

    Reconstruit les chemins depuis `preview.directory` + les noms déjà
    validés par `preview_backup_purge` : ne re-scanne JAMAIS le répertoire
    (protection TOCTOU — ce que l'utilisateur a confirmé à l'écran est
    exactement ce qui est supprimé, pas un nouvel état du disque qui aurait
    pu diverger entre le preview et la confirmation).

    Un fichier déjà absent (supprimé entre-temps par un autre appel, ou
    manuellement) n'est PAS une erreur fatale : elle est journalisée et
    ajoutée à `errors`, les autres fichiers du preview sont quand même
    traités.
    """
    directory = Path(preview.directory)
    deleted_count = 0
    deleted_bytes = 0
    errors: list[str] = []

    for file_name in preview.files_to_delete:
        target = directory / file_name
        try:
            size = target.stat().st_size
            target.unlink()
        except OSError as exc:
            log.error(
                "suppression du backup impossible: path=%s erreur=%s",
                target,
                exc,
            )
            errors.append(f"{file_name}: {exc}")
            continue
        deleted_count += 1
        deleted_bytes += size

    log.info(
        "purge backups terminee: directory=%s supprimes=%d octets=%d erreurs=%d",
        preview.directory,
        deleted_count,
        deleted_bytes,
        len(errors),
    )
    return BackupPurgeResult(
        deleted_count=deleted_count, deleted_bytes=deleted_bytes, errors=errors
    )


# ---------------------------------------------------------------------------
# Purge des tables SQLite internes — allowlist en dur
# ---------------------------------------------------------------------------

PURGEABLE_TABLES: frozenset[str] = frozenset(
    {"audit_log", "pending_config_changes", "snmp_inventory"}
)
"""Allowlist en dur des tables SQLite internes purgeables par ce module.

Même garde de conception que `ALLOWED_TABLES` dans `app/services/retention.py` :
jamais dynamique, jamais dérivée d'un input. Étendre cette liste est un choix
de code, pas une donnée de configuration.
"""

_DATE_COLUMN_BY_TABLE: dict[str, str] = {
    "audit_log": "happened_at",
    "pending_config_changes": "created_at",
    "snmp_inventory": "last_attempt_at",
}
"""Colonne de référence temporelle par table purgeable, en dur.

Le nom de table ET le nom de colonne injectés dans le SQL des fonctions de ce
module proviennent EXCLUSIVEMENT de `PURGEABLE_TABLES` / ce dict — jamais
d'un paramètre libre. C'est la même garde sécurité n°1 que le reste du
projet (CONTRACT.md) appliquée aux tables SQLite locales.
"""


class TablePurgePreview(BaseModel):
    """Ce qui SERAIT supprimé par une purge d'une table SQLite interne.

    `row_ids` fige les `rowid` SQLite exacts identifiés au moment du preview
    — voir `execute_table_purge` pour pourquoi c'est indispensable (pas
    seulement une commodité) à la garantie anti-TOCTOU du module.
    """

    table: str
    max_age_days: int
    rows_to_delete: int
    oldest_row_age_days: float | None
    row_ids: list[int] = []


class TablePurgeResult(BaseModel):
    """Résultat réel d'une purge de table SQLite interne."""

    deleted_count: int


def _validate_purgeable_table(table: str) -> str:
    """Valide `table` contre l'allowlist et retourne sa colonne date associée.

    Lève AVANT toute requête SQL — aucun accès à la base n'a lieu si la table
    n'est pas autorisée, condition explicitement exigée par la spec (une
    table hors allowlist ne doit déclencher aucun SELECT/DELETE).

    Raises:
        ValueError: si `table` n'appartient pas à `PURGEABLE_TABLES`.
    """
    if table not in PURGEABLE_TABLES:
        raise ValueError(
            f"table hors allowlist purge: {table!r} (autorisées: {sorted(PURGEABLE_TABLES)})"
        )
    return _DATE_COLUMN_BY_TABLE[table]


def preview_table_purge(
    conn: sqlite3.Connection, table: str, max_age_days: int
) -> TablePurgePreview:
    """Annonce combien de lignes SERAIENT supprimées — n'en supprime aucune.

    `SELECT COUNT(*)` / `MIN(...)` sont des lectures pures : aucun effet de
    bord sur la table, appelable librement pour rafraîchir un écran de
    confirmation.

    Raises:
        ValueError: si `table` est hors allowlist (AUCUNE requête SQL n'est
            exécutée dans ce cas) ou si `max_age_days` < 1.
    """
    date_column = _validate_purgeable_table(table)
    if max_age_days < 1:
        raise ValueError(f"max_age_days doit être >= 1, reçu {max_age_days!r}")

    # `table` et `date_column` sont ici garantis appartenir aux constantes en
    # dur ci-dessus (littéraux connus) : l'interpolation est sûre, le seul
    # paramètre libre (`max_age_days`, un int déjà validé) passe en paramètre
    # lié SQLite, jamais concaténé en texte.
    #
    # `rowid` (pas seulement COUNT) : anti-TOCTOU RÉEL, pas documentaire.
    # Reproduit (2026-08-08, revue de diff) : sans figer les lignes exactes
    # ici, `execute_table_purge` qui ré-exécute la MÊME clause temporelle
    # peut supprimer une ligne absente de CE preview — une ligne qui n'était
    # pas encore assez ancienne au moment du preview mais l'est devenue avant
    # l'exécution (fenêtre réelle avec `_purge_periodic_loop`, qui appelle
    # les deux à la suite mais peut tourner sur une table qui grossit). Figer
    # les `rowid` ici et ne supprimer QUE ceux-là à l'exécution rend la
    # promesse du module ("ce que l'utilisateur a vu est exactement ce qui
    # part") vraie plutôt que déclarative.
    rows = conn.execute(
        f"SELECT rowid, {date_column} FROM {table} "  # noqa: S608
        f"WHERE {date_column} < datetime('now', ?)",
        (f"-{max_age_days} days",),
    ).fetchall()
    row_ids = [int(row[0]) for row in rows]
    rows_to_delete = len(row_ids)

    oldest_row_age_days: float | None = None
    if rows_to_delete > 0:
        oldest_row = conn.execute(
            f"SELECT MIN(julianday('now') - julianday({date_column})) FROM {table} "  # noqa: S608
            f"WHERE {date_column} < datetime('now', ?)",
            (f"-{max_age_days} days",),
        ).fetchone()
        if oldest_row is not None and oldest_row[0] is not None:
            oldest_row_age_days = float(oldest_row[0])

    return TablePurgePreview(
        table=table,
        max_age_days=max_age_days,
        rows_to_delete=rows_to_delete,
        oldest_row_age_days=oldest_row_age_days,
        row_ids=row_ids,
    )


def execute_table_purge(conn: sqlite3.Connection, preview: TablePurgePreview) -> TablePurgeResult:
    """Supprime EXACTEMENT les lignes identifiées par `preview.row_ids`, puis commit.

    Revalide `preview.table` contre `PURGEABLE_TABLES` : défense en
    profondeur, ce module ne fait jamais confiance à un objet `preview` reçu
    en paramètre sans le recontrôler (il a pu transiter par un routeur, être
    désérialisé, etc.).

    ANTI-TOCTOU RÉEL (pas seulement documenté) : supprime par `rowid IN (...)`
    sur la liste FIGÉE au moment du preview — jamais un nouveau `DELETE WHERE
    date_column < ...` qui recalculerait la clause temporelle et pourrait
    inclure une ligne devenue éligible ENTRE le preview et cette exécution
    (défaut réel reproduit le 2026-08-08 : preview annonçait 0, l'ancienne
    version supprimait 1). Ce que l'utilisateur a vu dans le preview est ici
    ce qui part, ni plus ni moins.

    Un `preview.row_ids` vide signifie "rien à supprimer" (résultat neutre,
    pas une erreur) : `preview_table_purge` le produit naturellement quand
    aucune ligne n'est éligible.

    Raises:
        ValueError: si `preview.table` est hors allowlist.
    """
    _validate_purgeable_table(preview.table)

    if not preview.row_ids:
        log.info("purge table: rien a supprimer (preview.row_ids vide) table=%s", preview.table)
        return TablePurgeResult(deleted_count=0)

    # `table` validé contre l'allowlist ci-dessus (littéral connu). Les
    # `rowid` sont des entiers déjà typés par Pydantic (`list[int]`), jamais
    # une chaîne libre : paramètres liés, jamais interpolés dans le SQL.
    placeholders = ",".join("?" for _ in preview.row_ids)
    cursor = conn.execute(
        f"DELETE FROM {preview.table} WHERE rowid IN ({placeholders})",  # noqa: S608
        preview.row_ids,
    )
    conn.commit()
    deleted_count = cursor.rowcount if cursor.rowcount >= 0 else 0

    log.info(
        "purge table terminee: table=%s max_age_days=%d supprimees=%d (sur %d annoncees)",
        preview.table,
        preview.max_age_days,
        deleted_count,
        len(preview.row_ids),
    )
    return TablePurgeResult(deleted_count=deleted_count)
