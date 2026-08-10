"""Base SQLite locale d'Okvorado.

Contient UNIQUEMENT les données propres à l'application (correspondances
port -> application, journal d'audit). La configuration Akvorado et les flux
restent chez Akvorado : cette base ne duplique aucune source de vérité externe.
"""

import logging
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from app.config import settings

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS port_mappings (
    port        INTEGER NOT NULL,
    proto       TEXT    NOT NULL,
    application TEXT    NOT NULL,
    source      TEXT    NOT NULL DEFAULT 'custom',
    port_end    INTEGER,
    PRIMARY KEY (port, proto)
);

-- État du dernier rechargement du catalogue applicatif IANA (LOT app_catalog).
-- Une seule ligne (id=1, upsert). ZÉRO SILENCIEUX : un échec réseau doit
-- produire un état DISTINCT ('error'/'offline_fallback'), jamais laisser
-- l'écran deviner un succès parce que le catalogue contient déjà des entrées
-- d'un rechargement précédent.
CREATE TABLE IF NOT EXISTS app_catalog_reload_status (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    status       TEXT    NOT NULL,
    detail       TEXT    NOT NULL DEFAULT '',
    entries_iana INTEGER NOT NULL DEFAULT 0,
    happened_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    happened_at TEXT   NOT NULL DEFAULT (datetime('now')),
    actor      TEXT    NOT NULL DEFAULT 'anonymous',
    action     TEXT    NOT NULL,
    detail     TEXT    NOT NULL DEFAULT ''
);

-- File d'attente des changements de configuration Akvorado.
-- Les modifications sont accumulees ici puis appliquees EN UN SEUL LOT : chaque
-- application redemarre l'outlet, ce qui troue la collecte quelques secondes
-- (UDP ne retransmet pas). Grouper N changements = 1 seul trou au lieu de N.
CREATE TABLE IF NOT EXISTS pending_config_changes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    change_type TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    author      TEXT    NOT NULL DEFAULT 'anonymous',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Inventaire équipement SNMP (MIB-II système) — un enregistrement par
-- exportateur interrogé. Distinct des tables Exportateurs (interfaces) : ici
-- ce sont les 5 objets scalaires système (sysName, sysDescr, sysLocation,
-- sysContact, sysUpTime), ce qu'aucune table ClickHouse d'Akvorado ne porte.
--
-- `status` distingue une collecte réussie ('ok') d'un agent muet
-- ('no_response') : ZÉRO SILENCIEUX (CLAUDE.md règle n°2) — un agent qui ne
-- répond pas ne doit JAMAIS laisser les colonnes sys_* à vide en silence,
-- ce qui serait indiscernable d'un équipement dont le nom est réellement
-- vide. Les dernières valeurs connues sont conservées telles quelles lors
-- d'un échec (pas d'écrasement), `status`/`last_attempt_at` portent l'état
-- de la DERNIÈRE tentative, `last_success_at` celui de la DERNIÈRE réussite.
-- `snmp_version` ('v2c' ou 'v3') : SEULE la version choisie est persistée par
-- device. Les mots de passe SNMPv3 ne sont JAMAIS stockés ici (ni dans aucune
-- autre table SQLite) — un device en 'v3' utilise TOUJOURS les credentials
-- v3 GLOBAUX de `settings` (variables d'environnement, jamais en base). Le
-- fichier SQLite `data/okvorado.db` n'est pas un coffre-fort : il pourrait
-- être copié/exfiltré sans le contrôle d'accès d'un secret manager, d'où ce
-- choix de conception (voir `app.services.snmp_inventory` pour le détail).
CREATE TABLE IF NOT EXISTS snmp_inventory (
    address          TEXT    PRIMARY KEY,
    sys_name         TEXT,
    sys_descr        TEXT,
    sys_location     TEXT,
    sys_contact      TEXT,
    sys_uptime_ticks INTEGER,
    status           TEXT    NOT NULL DEFAULT 'no_response',
    first_seen_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    last_attempt_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    last_success_at  TEXT,
    snmp_version     TEXT    NOT NULL DEFAULT 'v2c'
);

-- Réglages de rétention/purge applicative, clé/valeur (service `purge.py` +
-- routeur, hors périmètre de ce fichier). Une ligne par réglage, upsert par
-- `setting_key`. `setting_value` reste une chaîne : le typage applicatif
-- (int, bool, ...) est décidé par le consommateur, pas par le schéma —
-- ce module ne fait qu'assurer la persistance et la traçabilité (`modified_by`,
-- `modified_at`).
--
-- Clés connues (non exhaustif, à titre de documentation) :
--   'docker_log_max_size_mb'  : taille max des logs Docker avant rotation
--   'backup_keep_n'           : nombre de fichiers .bak conservés par purge
--   'audit_log_max_age_days'  : âge max des lignes conservées dans audit_log
--   'purge_auto_enabled'      : "true"/"false" — active une purge automatique
--       (à ce jour AUCUNE purge ne s'exécute automatiquement, voir
--       app/services/purge.py — le preview seul n'a aucun effet de bord).
CREATE TABLE IF NOT EXISTS retention_settings (
    setting_key   TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL,
    modified_by   TEXT NOT NULL DEFAULT 'anonymous',
    modified_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Historique des snapshots de santé ClickHouse (LOT db_health) — permet de
-- voir une DÉRIVE s'installer (ex. parts actives qui grimpent progressivement
-- sur plusieurs jours) plutôt qu'un seul point de mesure. Une ligne par cycle
-- de la routine périodique (`app.main._db_health_periodic_loop`).
--
-- `overall_state` porte l'état ZÉRO SILENCIEUX : 'unavailable' est un état
-- DISTINCT de 'healthy', jamais une ligne absente qu'on confondrait avec
-- "tout allait bien" (une absence de ligne pourrait aussi signifier "la
-- routine ne tournait pas" — deux causes différentes, une seule ligne
-- explicite les distingue).
-- `snapshot_json` porte le `DbHealthSnapshot.model_dump_json()` complet :
-- l'écran d'historique n'a pas besoin d'un schéma colonne par indicateur,
-- et un nouvel indicateur ajouté plus tard n'exige aucune migration.
CREATE TABLE IF NOT EXISTS db_health_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    overall_state TEXT    NOT NULL,
    snapshot_json TEXT    NOT NULL
);

-- Historique des compteurs de rejet à l'ingestion (LOT db_health, étendu
-- diagnostic d'ingestion) — DÉFAUT MESURÉ (2026-08-09) : l'écran Ingestion
-- affichait un cumul Prometheus figé depuis 11h (séquelle d'un incident
-- réseau du matin) avec la même urgence visuelle qu'un rejet en cours. Les
-- compteurs `akvorado_outlet_core_flows_errors_total` sont CUMULATIFS depuis
-- le démarrage du conteneur outlet, jamais remis à zéro — un exploitant ne
-- peut PAS distinguer "incident réglé, cumul figé" de "incident en cours,
-- ça continue de grimper" à partir du seul total. Une ligne par (exportateur,
-- motif) à CHAQUE chargement de l'écran/appel API (même motif que
-- `db_health_history`, persisté par la routine appelante plutôt que par un
-- scheduler dédié — il n'y a pas de valeur à mesurer plus souvent que l'écran
-- n'est consulté).
--
-- Le delta affiché à l'écran (colonne "tendance") compare le compte COURANT
-- au dernier point antérieur à la fenêtre de comparaison (ex. 5 minutes) :
-- delta = 0 -> figé (séquelle passée), delta > 0 -> ça continue de grimper
-- MAINTENANT. ZÉRO SILENCIEUX (CLAUDE.md règle n°2) : l'ABSENCE de point de
-- comparaison (première mesure, ou aucun point encore assez ancien) produit
-- un état DISTINCT ("tendance inconnue" côté service), jamais un "+0" qui
-- laisserait croire à tort que le rejet est réglé.
CREATE TABLE IF NOT EXISTS ingestion_rejection_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at TEXT    NOT NULL DEFAULT (datetime('now')),
    exporter   TEXT    NOT NULL,
    error      TEXT    NOT NULL,
    count      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ingestion_rejection_history_lookup
    ON ingestion_rejection_history (exporter, error, checked_at);

-- Masquage des cumuls de rejet FIGÉS (2026-08-10) — une ligne de base par
-- couple (exportateur, motif) purgé depuis l'écran Ingestion.
--
-- CONFIG_HARDCODE_OK: les adresses citées ci-dessous sont la TRACE ÉCRITE d'un
-- incident mesuré (les exportateurs fantômes observés en prod le 2026-08-10),
-- pas de la configuration. Aucune n'est lue par le code : ce module ne connaît
-- aucune adresse, il masque le couple (exportateur, motif) que l'exploitant
-- désigne à l'écran. Les paramétrer serait un contresens — on ne configure pas
-- un fait historique.
--
-- CONTEXTE MESURÉ (prod, 2026-08-10) : l'écran affichait en tête, en ROUGE,
-- deux exportateurs FANTÔMES (203.0.113.1 à 555 961 flux perdus et
-- 198.51.100.51 à 238 917) — des adresses qui ont émis à un moment puis ont
-- disparu (ClickHouse ne les liste plus parmi les 11 exportateurs actifs sur
-- 24h). Leurs compteurs, figés depuis le démarrage de l'outlet
-- (2026-08-09T12:04:59Z), masquaient visuellement les vrais problèmes actifs.
--
-- CONTRAINTE STRUCTURANTE : Okvorado ne PEUT PAS remettre à zéro un compteur
-- Prometheus — c'est impossible par conception ; seul un redémarrage de
-- l'outlet Akvorado les efface, ce qui couperait l'ingestion (UDP ne
-- retransmet pas). La purge est donc un MASQUAGE côté Okvorado :
-- `baseline_count` mémorise le cumul AU MOMENT de la purge, et l'écran
-- n'affiche ensuite plus que le DELTA au-dessus de cette ligne.
--
-- ZÉRO SILENCIEUX (CLAUDE.md règle n°2) — trois garde-fous portés par le
-- service `app.services.ingestion` et prouvés par `tests/test_ingestion.py` :
--   1. seul un motif dont la tendance est PROUVÉE figée ("flat") peut être
--      masqué ; un motif qui grimpe ("rising") ou sans point de comparaison
--      ("unknown") est REFUSÉ — la purge nettoie du bruit historique, elle ne
--      doit jamais faire disparaître une panne en cours ;
--   2. compteur courant > `baseline_count` : le problème a REPRIS, la ligne
--      RÉAPPARAÎT d'elle-même (affichée en delta au-dessus de la base) ;
--   3. compteur courant < `baseline_count` : l'outlet a REDÉMARRÉ (ses
--      compteurs sont repartis de 0). Le masque est alors PÉRIMÉ — il est
--      supprimé et le motif réaffiché avec son cumul courant intégral. Sans
--      cela, un delta négatif serait affiché, ou pire le motif resterait
--      masqué éternellement jusqu'à ce que le nouveau cumul repasse l'ancien.
--
-- La clé primaire (exporter, error) garantit UNE seule ligne de base par
-- couple : purger deux fois le même couple met la base À JOUR, ne la double
-- pas. `masked_by`/`masked_at` tracent qui a masqué quoi et quand (l'écran
-- doit pouvoir dire CE QUI est masqué, pas seulement combien — un masquage
-- invisible serait lui-même un zéro silencieux).
CREATE TABLE IF NOT EXISTS ingestion_rejection_mask (
    exporter       TEXT    NOT NULL,
    error          TEXT    NOT NULL,
    baseline_count INTEGER NOT NULL,
    masked_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    masked_by      TEXT    NOT NULL DEFAULT 'anonymous',
    PRIMARY KEY (exporter, error)
);

-- Authentification autonome (LOT auth, étendu LOT accounts) — plusieurs
-- comptes, chacun avec son propre mot de passe et son propre TOTP (colonnes
-- déjà indexées par `username`, voir `auth_backup_codes` ci-dessous).
-- `password_hash` est TOUJOURS un hash PBKDF2-HMAC-SHA256 (voir app/auth.py),
-- jamais le mot de passe en clair. `totp_secret` reste NULL tant que le TOTP
-- n'a pas été confirmé par un premier code valide (voir `enable_totp`) : un
-- secret non confirmé ne doit jamais pouvoir verrouiller la connexion.
-- `is_default_password` porte l'avertissement affiché à l'écran tant que le
-- mot de passe n'a jamais été changé depuis l'admin initial.
-- `role` ('admin' ou 'lecteur', LOT accounts) : 'admin' accède à tout, y
-- compris l'écran de gestion des comptes et toutes les routes d'écriture ;
-- 'lecteur' est cantonné aux écrans de consultation. Défaut 'admin' — voir
-- `_ensure_auth_users_role_column` pour la justification sur base existante.
-- `last_login_at` (LOT accounts) : dernière connexion réussie, pour l'écran
-- de gestion des comptes (distinguer un compte actif d'un compte oublié).
-- NULL tant qu'aucune connexion n'a eu lieu — jamais une date arbitraire qui
-- laisserait croire à une connexion qui n'a pas eu lieu (zéro silencieux).
CREATE TABLE IF NOT EXISTS auth_users (
    username             TEXT PRIMARY KEY,
    password_hash        TEXT NOT NULL,
    totp_enabled         INTEGER NOT NULL DEFAULT 0,
    totp_secret          TEXT,
    is_default_password  INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL DEFAULT (datetime('now')),
    role                 TEXT NOT NULL DEFAULT 'admin',
    last_login_at        TEXT
);

-- Codes de secours TOTP — à usage unique, HACHÉS (jamais en clair, même garde
-- que password_hash). `used_at` NULL = code encore valide ; une fois consommé
-- il reste en base (traçabilité) mais n'est plus jamais accepté.
CREATE TABLE IF NOT EXISTS auth_backup_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL,
    code_hash  TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def _ensure_port_mappings_range_column(conn: sqlite3.Connection) -> None:
    """Ajoute `port_end` à `port_mappings` si absente (migration additive).

    `CREATE TABLE IF NOT EXISTS` ne touche jamais une table déjà créée par une
    version antérieure du schéma : sur une base existante (LOT 3, colonne
    absente), le catalogue applicatif ne pourrait jamais représenter une plage
    de ports (ex. `50000-51000` — usage FTP passif, plages métier SFR) sans
    cette migration. `PRAGMA table_info` rend l'ajout idempotent : relancer
    `init_database()` sur une base qui a déjà la colonne ne lève jamais
    `duplicate column name`.

    `port_end` reste NULL pour une correspondance à port unique (le cas
    dominant, 100% des entrées IANA) : NULL signifie « pas de plage », jamais
    une plage vide.
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(port_mappings)").fetchall()}
    if "port_end" not in columns:
        conn.execute("ALTER TABLE port_mappings ADD COLUMN port_end INTEGER")


def _ensure_snmp_inventory_version_column(conn: sqlite3.Connection) -> None:
    """Ajoute `snmp_version` à `snmp_inventory` si absente (migration additive).

    Même pattern que `_ensure_port_mappings_range_column` : sur une base
    existante créée avant l'introduction de SNMPv3, `CREATE TABLE IF NOT
    EXISTS` ne touche pas la table déjà créée. `PRAGMA table_info` rend
    l'ajout idempotent. Défaut `'v2c'` : un device déjà inventorié avant la
    migration reste en v2c (comportement historique), jamais basculé en v3
    silencieusement (ce qui échouerait sans credentials configurés).
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(snmp_inventory)").fetchall()}
    if "snmp_version" not in columns:
        conn.execute(
            "ALTER TABLE snmp_inventory ADD COLUMN snmp_version TEXT NOT NULL DEFAULT 'v2c'"
        )


def _ensure_auth_users_role_column(conn: sqlite3.Connection) -> None:
    """Ajoute `role` à `auth_users` si absente (migration additive, LOT accounts).

    Même pattern que `_ensure_port_mappings_range_column` : sur une base
    EXISTANTE créée avant la gestion multi-comptes, `CREATE TABLE IF NOT
    EXISTS` ne touche pas la table déjà créée. `PRAGMA table_info` rend
    l'ajout idempotent.

    Défaut `'admin'` — pas `'lecteur'` : avant ce lot, l'application n'avait
    JAMAIS qu'un seul compte (l'admin initial, `OKVORADO_AUTH_USER`), qui
    accédait à tout. Faire migrer ce compte vers `'lecteur'` le priverait
    silencieusement de l'accès aux routes d'écriture qu'il utilisait déjà
    (config, rétention...) — une régression d'accès au démarrage, sur une
    base qui fonctionnait. `'admin'` préserve le comportement observé avant
    la migration, à l'identique.
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(auth_users)").fetchall()}
    if "role" not in columns:
        conn.execute("ALTER TABLE auth_users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")


def _ensure_auth_users_last_login_column(conn: sqlite3.Connection) -> None:
    """Ajoute `last_login_at` à `auth_users` si absente (migration additive, LOT accounts).

    Même pattern que ci-dessus. NULL par défaut (colonne nullable sans
    DEFAULT) : un compte migré depuis une base existante n'a pas de date de
    dernière connexion connue — NULL est l'état honnête, jamais une date
    arbitraire (zéro silencieux, CLAUDE.md règle n°2)."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(auth_users)").fetchall()}
    if "last_login_at" not in columns:
        conn.execute("ALTER TABLE auth_users ADD COLUMN last_login_at TEXT")


def init_database(path: str | None = None) -> None:
    """Crée le schéma s'il n'existe pas. Idempotent."""
    target = Path(path or settings.sqlite_path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(target) as conn:
            conn.executescript(SCHEMA)
            _ensure_port_mappings_range_column(conn)
            _ensure_snmp_inventory_version_column(conn)
            _ensure_auth_users_role_column(conn)
            _ensure_auth_users_last_login_column(conn)
            conn.commit()
        log.info("base sqlite initialisee: %s", target)
    except (sqlite3.Error, OSError) as exc:
        log.error("impossible d'initialiser la base sqlite %s: %s", target, exc)
        raise


@contextmanager
def get_connection(path: str | None = None) -> Generator[sqlite3.Connection]:
    """Ouvre une connexion SQLite avec row_factory nommée."""
    target = str(path or settings.sqlite_path)
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
