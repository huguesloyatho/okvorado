"""Service Santé DB — surveillance ClickHouse, sans jamais agir dans le dos
de l'exploitant.

DEMANDE UTILISATEUR (SFR, remplacement ManageEngine NetFlow Analyzer,
350 routeurs) : l'ancienne instance nécessitait de redémarrer régulièrement
une base qui « crachait ». Diagnostic mesuré sur `.6` (11 exportateurs,
84 M lignes) : ce n'est pas la base qui « crache », c'est l'ACCUMULATION DE
PARTS qui dépasse la capacité de fusion — le symptôme (instabilité) a une
cause mécanique précise (`TOO_MANY_PARTS`), pas mystérieuse.

CE MODULE NE REDÉMARRE JAMAIS CLICKHOUSE — GARDE-FOU CENTRAL DU LOT.
La routine surveille, prévient et alerte ; elle n'agit que sur des gestes
sûrs et réversibles (OPTIMIZE, purge de parts détachées), toujours à la
demande explicite de l'exploitant, jamais automatiquement. Un redémarrage
automatique masquerait le problème exactement comme l'ancienne instance
ManageEngine le masquait — c'est le piège que ce lot doit éviter, pas
reproduire.

ZÉRO SILENCIEUX (CLAUDE.md règle n°2) : toute fonction de lecture qui
échoue lève ou retourne un état `HealthState.UNAVAILABLE` explicite, jamais
un `0`/liste vide qu'on confondrait avec « sain ».

Seuils `parts_to_delay_insert` / `parts_to_throw_insert` LUS depuis
`system.merge_tree_settings` à chaque évaluation, jamais codés en dur : ce
sont des réglages ClickHouse ajustables (exigence explicite de la tâche).
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel

from app.models import (
    DbHealthSnapshot,
    DetachedPartEntry,
    DetachedPartsHealth,
    ErrorCounter,
    HealthIndicator,
    HealthState,
    MemoryHealth,
    MergeBacklogHealth,
    StuckMutation,
    TablePartsHealth,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Contrat client — même Protocol que app.services.retention.ClickHouseQueryable
# ---------------------------------------------------------------------------


class ClickHouseQueryable(Protocol):
    """Ce dont ce module a besoin d'un client ClickHouse — lecture seule pour
    la surveillance, écriture uniquement pour les deux actions de maintien
    (OPTIMIZE, purge de parts détachées), toujours explicitement demandées.
    """

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> list[tuple[Any, ...]]:
        """Exécute une requête et retourne les lignes sous forme de tuples."""
        ...


# ---------------------------------------------------------------------------
# Tables suivies — allowlist en dur, même garde que retention.py/purge.py
# ---------------------------------------------------------------------------

MONITORED_TABLES: frozenset[str] = frozenset(
    {"flows", "flows_1m0s", "flows_5m0s", "flows_1h0m0s", "exporters"}
)
"""Tables ClickHouse `default.*` dont on surveille les parts actives.

Allowlist en dur (garde sécu n°1 du projet) : le nom de table entre dans du
SQL (`OPTIMIZE TABLE default.<table>`) uniquement après validation contre
cette liste — jamais un nom dérivé d'un input libre.
"""

# `flows` est la table qui reçoit l'écriture continue mesurée sur .6 (10
# inserts/min, 912 lignes chacun) — c'est elle qui pilote le risque de
# TOO_MANY_PARTS. Les autres tables du schéma reçoivent moins ou pas
# d'écriture directe (agrégats matérialisés, dimension `exporters`).
_PRIMARY_WRITE_TABLE = "flows"


# ---------------------------------------------------------------------------
# Purge COMPLÈTE des parts détachées — tables SYSTÈME, deuxième allowlist
# ---------------------------------------------------------------------------
#
# DÉFAUT MESURÉ (2026-08-09) : après un crash ClickHouse, l'écran annonçait
# 46 parts détachées critiques mais ne savait en purger que 18 — les 28
# autres appartenaient à des tables SYSTÈME (`query_log`, `metric_log`,
# `trace_log`, `part_log`, `asynchronous_metric_log`, `query_views_log`,
# `processors_profile_log`, `asynchronous_insert_log`), hors de
# `MONITORED_TABLES` qui ne couvre que les 5 tables de flux `default.*`.
# L'exploitant a dû nettoyer le reste en SQL à la main.

SYSTEM_LOG_TABLES: frozenset[str] = frozenset(
    {
        "query_log",
        "metric_log",
        "trace_log",
        "part_log",
        "asynchronous_metric_log",
        "query_views_log",
        "processors_profile_log",
        "asynchronous_insert_log",
    }
)
"""Allowlist en dur des tables `system.*` dont ce module accepte de purger les
parts détachées. Même garde sécu n°1 du projet que `MONITORED_TABLES` — une
DEUXIÈME allowlist, jamais une extension de la première : `MONITORED_TABLES`
reste réservée aux tables `default.*` de flux (utilisée aussi par
`optimize_table`, dont le périmètre ne doit pas s'élargir aux tables
système), `SYSTEM_LOG_TABLES` est propre à la purge de parts détachées.

Ces 8 tables sont les tables `system.*` qui journalisent en continu
(query_log, metric_log, part_log, ...) et sont donc les seules du schéma
`system` à accumuler des parts — un crash brutal peut y laisser des
fragments `broken-on-start`, exactement comme sur `default.flows`.
"""

_SAFE_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
"""Défense en profondeur : même si un nom provient de `system.detached_parts`
(ClickHouse, pas un input utilisateur), on ne fait JAMAIS confiance
aveuglément à une valeur qui va être interpolée dans du SQL. Ce pattern
exclut tout métacaractère (`;`, `--`, espace, guillemet, point) avant même de
vérifier l'appartenance à une allowlist — même géométrie de garde que
`app.services.retention._SAFE_TABLE_NAME_RE`."""

_ALLOWED_DATABASES_BY_TABLE: dict[str, frozenset[str]] = {
    "default": MONITORED_TABLES,
    "system": SYSTEM_LOG_TABLES,
}
"""Association base → allowlist de tables autorisées pour la purge de parts
détachées. Une base absente de ce dict (donc ni `default` ni `system`) est
refusée d'office — `validate_detached_parts_target` ne considère JAMAIS une
base inconnue comme sûre par défaut."""


def validate_detached_parts_target(database: str, table: str) -> tuple[str, str]:
    """Valide un couple `(database, table)` avant toute interpolation SQL.

    RAISONNEMENT SÉCURITÉ (2026-08-09) — c'est le point délicat de cet
    élargissement : `system.detached_parts` fournit lui-même les noms de
    table à purger (on ne demande jamais à l'exploitant de taper un nom
    libre), mais "la donnée vient de ClickHouse" ne dispense PAS de la
    valider avant de la faire entrer dans du SQL. Le nom peut en théorie
    provenir d'une table système compromise, d'une version de ClickHouse qui
    expose un nom inattendu, ou d'un bug amont — la garde doit donc tenir
    MÊME si la source est normalement de confiance. Trois contrôles
    cumulatifs, dans cet ordre (le plus tôt un rejet est possible, le
    mieux) :

    1. Pattern strict `_SAFE_IDENTIFIER_RE` sur `database` ET `table` —
       rejette tout métacaractère avant même de regarder l'allowlist.
    2. `database` doit être une clé connue de `_ALLOWED_DATABASES_BY_TABLE`
       (`default` ou `system`) — jamais une base arbitraire, même si son nom
       est syntaxiquement propre.
    3. `table` doit appartenir à l'allowlist de CETTE base précise
       (`MONITORED_TABLES` pour `default`, `SYSTEM_LOG_TABLES` pour
       `system`) — un nom de table valide dans la mauvaise base est refusé
       (ex. `query_log` sous `default` n'existe pas et n'est pas autorisé).

    Returns:
        Le couple `(database, table)` inchangé, une fois validé — pratique
        d'usage pour enchaîner directement l'interpolation SQL.

    Raises:
        ValueError: si l'un des trois contrôles échoue. AUCUNE requête SQL
            n'est exécutée par cette fonction elle-même dans tous les cas.
    """
    if not isinstance(database, str) or not _SAFE_IDENTIFIER_RE.match(database):
        raise ValueError(f"nom de base invalide (pattern): {database!r}")
    if not isinstance(table, str) or not _SAFE_IDENTIFIER_RE.match(table):
        raise ValueError(f"nom de table invalide (pattern): {table!r}")
    allowed_tables = _ALLOWED_DATABASES_BY_TABLE.get(database)
    if allowed_tables is None:
        raise ValueError(
            f"base hors allowlist purge parts detachees: {database!r} "
            f"(autorisées: {sorted(_ALLOWED_DATABASES_BY_TABLE)})"
        )
    if table not in allowed_tables:
        raise ValueError(
            f"table hors allowlist purge parts detachees pour {database}: {table!r} "
            f"(autorisées: {sorted(allowed_tables)})"
        )
    return database, table


# ---------------------------------------------------------------------------
# Seuils de marge — pourcentage du seuil ClickHouse à partir duquel on avertit
# ---------------------------------------------------------------------------

WARNING_PCT_OF_DELAY_THRESHOLD = 50.0
"""Un nombre de parts actives dépassant 50% de `parts_to_delay_insert` est un
signal PRÉCOCE — bien avant le ralentissement forcé (100%) ou le refus
d'écriture (`parts_to_throw_insert`, généralement 3x `parts_to_delay_insert`).
Avertir tôt est le point de la routine : la demande utilisateur est de
PRÉVENIR, pas de constater après coup."""

WARNING_MEMORY_PCT = 75.0
CRITICAL_MEMORY_PCT = 90.0

WARNING_DETACHED_PARTS_COUNT = 1
"""Toute part détachée est anormale en régime normal (aucune restauration en
cours) — dès qu'il y en a une, c'est à surveiller, pas encore critique."""

CRITICAL_DETACHED_PARTS_COUNT = 10

_ERROR_CODES_OF_INTEREST = ("TOO_MANY_PARTS", "MEMORY_LIMIT_EXCEEDED", "TIMEOUT_EXCEEDED")
"""Ces trois codes sont ceux qui annoncent concrètement le mécanisme de
crash vécu par l'utilisateur (accumulation de parts, mémoire, requêtes
bloquées) — cf. prompt de la tâche."""


# ---------------------------------------------------------------------------
# Lecture des seuils MergeTree — JAMAIS codés en dur
# ---------------------------------------------------------------------------


def fetch_merge_tree_thresholds(client: ClickHouseQueryable) -> tuple[int, int]:
    """Lit `parts_to_delay_insert` / `parts_to_throw_insert` depuis ClickHouse.

    Ces réglages sont ajustables par l'exploitant ClickHouse (SETTINGS de
    table ou réglage serveur) — les coder en dur romprait la promesse de la
    tâche dès qu'un opérateur les modifie pour absorber plus de trafic.

    Raises:
        Exception: propagée telle quelle si la requête échoue — l'appelant
            (`collect_parts_health`) est responsable de produire l'état
            `UNAVAILABLE` plutôt que de laisser cette exception remonter
            jusqu'à l'écran.
    """
    rows = client.query(
        "SELECT name, value FROM system.merge_tree_settings "
        "WHERE name IN ({delay:String}, {throw:String})",
        {"delay": "parts_to_delay_insert", "throw": "parts_to_throw_insert"},
    )
    values: dict[str, int] = {str(row[0]): int(row[1]) for row in rows}
    delay = values.get("parts_to_delay_insert", 0)
    throw = values.get("parts_to_throw_insert", 0)
    return delay, throw


# ---------------------------------------------------------------------------
# Parts actives par table
# ---------------------------------------------------------------------------


def evaluate_parts_state(
    max_parts_in_partition: int, delay_threshold: int, throw_threshold: int
) -> HealthState:
    """Classe l'état d'une table à partir du MAXIMUM de parts actives DANS
    UNE SEULE PARTITION et des seuils RÉELS lus sur le serveur (jamais des
    constantes du projet).

    ⚠️ BUG CORRIGÉ (2026-08-08) : `parts_to_delay_insert` et
    `parts_to_throw_insert` sont des seuils ClickHouse PAR PARTITION, jamais
    un total de table — source qui tranche, code ClickHouse
    (`src/Storages/MergeTree/MergeTreeSettings.cpp`) : "If the number of
    active parts in a SINGLE PARTITION exceeds the `parts_to_delay_insert`
    value, an INSERT is artificially slowed down." Comparer un total de
    table à ces seuils déclenche une fausse alerte dès que la table a
    plusieurs partitions actives (le cas normal ici : partitionnement
    horaire par `toStartOfInterval(TimeReceived, 25920s)`), alors qu'aucune
    partition individuelle n'approche le seuil. L'ancien code (`count()
    GROUP BY table`) faisait exactement cette confusion.

    - `>= throw_threshold` (sur le MAX par partition) : ClickHouse REFUSE
      l'écriture — CRITIQUE.
    - `>= delay_threshold` (sur le MAX par partition) : ClickHouse RALENTIT
      l'écriture — CRITIQUE (déjà un impact utilisateur, pas une simple
      anticipation).
    - `>= WARNING_PCT_OF_DELAY_THRESHOLD % de delay_threshold` : signal
      précoce — À SURVEILLER.
    - sinon : SAIN.
    """
    if throw_threshold > 0 and max_parts_in_partition >= throw_threshold:
        return HealthState.CRITICAL
    if delay_threshold > 0 and max_parts_in_partition >= delay_threshold:
        return HealthState.CRITICAL
    warning_floor = delay_threshold * (WARNING_PCT_OF_DELAY_THRESHOLD / 100)
    if delay_threshold > 0 and max_parts_in_partition >= warning_floor:
        return HealthState.WARNING
    return HealthState.HEALTHY


def collect_parts_health(client: ClickHouseQueryable) -> list[TablePartsHealth]:
    """Parts actives par table suivie, rapportées aux seuils réels.

    ⚠️ Groupe par `(table, partition)`, PAS par `table` seule : les seuils
    ClickHouse `parts_to_delay_insert`/`parts_to_throw_insert` s'appliquent
    au nombre de parts actives d'UNE SEULE PARTITION (cf. docstring de
    `evaluate_parts_state`). L'état de chaque table est donc décidé par le
    MAXIMUM de parts observé dans une de ses partitions, jamais par la somme
    de toutes ses partitions — cette somme reste calculée et exposée
    (`total_active_parts`) à titre informatif seulement.

    ZÉRO SILENCIEUX : si la lecture échoue, lève l'exception plutôt que de
    retourner une liste vide qui se confondrait avec « aucune table à
    risque ». C'est `collect_snapshot` qui traduit cet échec en
    `HealthState.UNAVAILABLE` pour l'écran.
    """
    delay_threshold, throw_threshold = fetch_merge_tree_thresholds(client)

    rows = client.query(
        "SELECT table, partition, count() FROM system.parts "
        "WHERE active AND database = {database:String} "
        "AND table IN ({tables:Array(String)}) GROUP BY table, partition",
        {"database": "default", "tables": sorted(MONITORED_TABLES)},
    )
    # Par table : liste des comptes de parts, un par partition active.
    partition_counts_by_table: dict[str, list[int]] = {}
    for row in rows:
        table = str(row[0])
        count = int(row[2])
        partition_counts_by_table.setdefault(table, []).append(count)

    results: list[TablePartsHealth] = []
    for table in sorted(MONITORED_TABLES):
        partition_counts = partition_counts_by_table.get(table, [])
        max_in_partition = max(partition_counts, default=0)
        total_parts = sum(partition_counts)
        state = evaluate_parts_state(max_in_partition, delay_threshold, throw_threshold)
        results.append(
            TablePartsHealth(
                table=table,
                total_active_parts=total_parts,
                max_active_parts_in_partition=max_in_partition,
                partition_count=len(partition_counts),
                parts_to_delay_insert=delay_threshold,
                parts_to_throw_insert=throw_threshold,
                state=state,
            )
        )
    return results


# ---------------------------------------------------------------------------
# Fusions en retard — SIGNAL D'ALERTE N°1
# ---------------------------------------------------------------------------

WARNING_BACKLOG_PARTS = 50
"""Écart (parts créées - parts fusionnées) sur la fenêtre d'observation, à
partir duquel on avertit — c'est le signe que la fusion commence à ne plus
suivre le rythme d'ingestion."""

CRITICAL_BACKLOG_PARTS = 200


def evaluate_backlog_state(backlog: int) -> HealthState:
    if backlog >= CRITICAL_BACKLOG_PARTS:
        return HealthState.CRITICAL
    if backlog >= WARNING_BACKLOG_PARTS:
        return HealthState.WARNING
    return HealthState.HEALTHY


def collect_merge_backlog(client: ClickHouseQueryable, window_hours: int = 1) -> MergeBacklogHealth:
    """Compare parts créées vs parts CONSOMMÉES par fusion sur la fenêtre,
    table `flows`.

    Lit `system.part_log` — c'est la seule table qui journalise l'historique
    des parts (system.parts ne montre que l'état COURANT, pas le flux
    créées/consommées). Si `part_log` n'est pas activé (réglage serveur), la
    requête retourne 0 lignes plutôt que d'échouer : ce n'est pas une erreur
    de connexion, c'est une fonctionnalité optionnelle absente — traité
    comme "aucune donnée sur la fenêtre", pas comme `UNAVAILABLE`.

    ⚠️ BUG CORRIGÉ (mesuré sur .6 le 2026-08-08, validation réelle avant
    livraison) : compter `count()` des événements `MergeParts` compte le
    nombre d'OPÉRATIONS de fusion, pas le nombre de parts qu'elles
    consomment — un seul événement `MergeParts` fusionne PLUSIEURS parts
    sources (`merged_from`, un array) en une seule nouvelle part. Comparer
    `count(NewPart)` à `count(MergeParts)` sous-estime systématiquement la
    fusion et déclenchait un état CRITIQUE même quand le système est sain
    (mesuré : 105 NewPart vs 22 MergeParts sur l'heure courante — semblait
    un backlog de 83, alors que `sum(length(merged_from))` = 133 parts
    RÉELLEMENT consommées, supérieur aux 105 créées : la fusion suit). La
    bonne mesure est `sum(length(merged_from))` pour les événements
    `MergeParts`, pas leur simple décompte.
    """
    rows = client.query(
        "SELECT "
        "countIf(event_type = {new_part:String}) AS parts_created, "
        "sumIf(length(merged_from), event_type = {merge_parts:String}) AS parts_merged "
        "FROM system.part_log "
        "WHERE database = {database:String} AND table = {table:String} "
        "AND event_time >= now() - toIntervalHour({hours:UInt32})",
        {
            "database": "default",
            "table": _PRIMARY_WRITE_TABLE,
            "hours": window_hours,
            "new_part": "NewPart",
            "merge_parts": "MergeParts",
        },
    )
    parts_created = int(rows[0][0]) if rows and rows[0][0] is not None else 0
    parts_merged = int(rows[0][1]) if rows and rows[0][1] is not None else 0
    backlog = parts_created - parts_merged
    return MergeBacklogHealth(
        window_label=f"{window_hours}h",
        parts_created=parts_created,
        parts_merged=parts_merged,
        state=evaluate_backlog_state(backlog),
    )


# ---------------------------------------------------------------------------
# Erreurs cumulées
# ---------------------------------------------------------------------------


def collect_errors_of_interest(client: ClickHouseQueryable) -> list[ErrorCounter]:
    """Compteurs `system.errors` pour les codes qui annoncent le crash vécu.

    `system.errors` est un CUMUL depuis le démarrage du serveur — un compteur
    non nul mais ancien (`last_error_time` loin dans le passé) n'a pas le
    même sens qu'un compteur qui vient de bouger ; les deux sont retournés,
    l'interprétation (icône, couleur) reste du côté de l'affichage.
    """
    rows = client.query(
        "SELECT name, value, last_error_time FROM system.errors "
        "WHERE name IN ({codes:Array(String)})",
        {"codes": list(_ERROR_CODES_OF_INTEREST)},
    )
    results: list[ErrorCounter] = []
    for row in rows:
        name = str(row[0])
        value = int(row[1])
        last_error_time = row[2] if len(row) > 2 and row[2] is not None else None
        if value <= 0:
            continue  # zéro erreur cumulée : rien à signaler pour ce code
        results.append(ErrorCounter(name=name, value=value, last_error_time=last_error_time))
    return results


def evaluate_errors_state(errors: list[ErrorCounter]) -> HealthState:
    """Toute présence d'un des 3 codes surveillés est CRITIQUE : ce sont
    précisément les erreurs qui correspondent au mécanisme de crash décrit
    par l'utilisateur, jamais un simple avertissement."""
    return HealthState.CRITICAL if errors else HealthState.HEALTHY


# ---------------------------------------------------------------------------
# Mutations bloquées
# ---------------------------------------------------------------------------


def collect_stuck_mutations(client: ClickHouseQueryable) -> list[StuckMutation]:
    """Mutations `is_done=0` avec un motif d'échec renseigné.

    Une mutation `is_done=0` SANS `latest_fail_reason` est simplement EN
    COURS (normal, pas un problème) — seules celles qui ont un motif
    d'échec sont retournées ici.
    """
    rows = client.query(
        "SELECT table, mutation_id, command, create_time, latest_fail_reason "
        "FROM system.mutations WHERE is_done = 0 AND latest_fail_reason != {empty:String}",
        {"empty": ""},
    )
    return [
        StuckMutation(
            table=str(row[0]),
            mutation_id=str(row[1]),
            command=str(row[2]),
            create_time=row[3],
            latest_fail_reason=str(row[4]),
        )
        for row in rows
    ]


def evaluate_mutations_state(stuck: list[StuckMutation]) -> HealthState:
    return HealthState.CRITICAL if stuck else HealthState.HEALTHY


# ---------------------------------------------------------------------------
# Parts détachées
# ---------------------------------------------------------------------------


def collect_detached_parts(client: ClickHouseQueryable) -> DetachedPartsHealth:
    """Parts détachées TOUTES BASES CONFONDUES — `default.*` (flux) ET
    `system.*` (journaux) — c'est ce total que l'écran affiche comme « X
    parts détachées », donc il doit refléter TOUT ce qui est réellement
    détaché, pas seulement ce qu'`execute_detached_parts_purge` d'origine
    savait nettoyer (défaut mesuré le 2026-08-09 : 46 annoncées, 18
    réparables).

    `by_group` détaille chaque `(database, table, reason)` — ajouté pour
    exposer la RAISON (`system.detached_parts.reason`) et la TAILLE par
    groupe : une part `broken-on-start` à 0 octet se purge sans réfléchir,
    une part volumineuse mérite examen avant suppression (contexte métier
    demandé, cf. tâche 2026-08-09).
    """
    rows = client.query("SELECT count(), sum(bytes_on_disk) FROM system.detached_parts")
    count = int(rows[0][0]) if rows else 0
    total_bytes = int(rows[0][1]) if rows and rows[0][1] is not None else 0

    # Marqueur SQL distinct ("GROUP BY database, table, reason") de la requête
    # ci-dessus : nécessaire pour que le double de test (FakeClickHouseClient,
    # routage par sous-chaîne) puisse répondre différemment à cette requête
    # de détail et à la requête de comptage global, sans ambiguïté.
    group_rows = client.query(
        "SELECT database, table, reason, count(), sum(bytes_on_disk) "
        "FROM system.detached_parts GROUP BY database, table, reason "
        "ORDER BY database, table, reason"
    )
    by_group: list[DetachedPartEntry] = []
    for row in group_rows:
        # Garde défensive : une ligne qui n'a pas exactement les 5 colonnes
        # attendues est ignorée plutôt que de faire planter toute la
        # collecte de santé — ne devrait jamais arriver avec un VRAI
        # ClickHouse (la requête ci-dessus fixe le nombre de colonnes), mais
        # protège contre un double de test mal aligné ou un pilote qui
        # tronquerait une ligne.
        if len(row) < 5:
            log.error(
                "db_health: ligne group-by detached_parts incomplete ignoree: %r", row
            )
            continue
        by_group.append(
            DetachedPartEntry(
                database=str(row[0]),
                table=str(row[1]),
                reason=str(row[2]) if row[2] else "(raison non renseignée)",
                count=int(row[3]),
                bytes_on_disk=int(row[4]) if row[4] is not None else 0,
            )
        )

    if count >= CRITICAL_DETACHED_PARTS_COUNT:
        state = HealthState.CRITICAL
    elif count >= WARNING_DETACHED_PARTS_COUNT:
        state = HealthState.WARNING
    else:
        state = HealthState.HEALTHY
    return DetachedPartsHealth(count=count, total_bytes=total_bytes, state=state, by_group=by_group)


# ---------------------------------------------------------------------------
# Mémoire
# ---------------------------------------------------------------------------


def describe_memory_limit_source(memory: MemoryHealth) -> str:
    """Phrase en clair qui dit QUEL plafond a décidé le pourcentage affiché et
    D'OÙ IL VIENT — même esprit que `threshold_label` pour les autres
    indicateurs (ex. « lus depuis system.merge_tree_settings »).

    Réutilisée par l'indicateur de synthèse ET par le template (section
    « Mémoire » détaillée) pour ne jamais avoir deux formulations
    divergentes du même fait."""
    if memory.limit_source == "clickhouse":
        return (
            f"limite ClickHouse max_server_memory_usage="
            f"{memory.clickhouse_limit_bytes} octets (lue depuis "
            "system.server_settings) — c'est elle qui REFUSE les requêtes "
            "en premier"
        )
    if memory.limit_source == "clickhouse_computed":
        return (
            f"limite ClickHouse calculée="
            f"{memory.clickhouse_limit_bytes} octets "
            "(max_server_memory_usage=0 = pas de limite explicite ; "
            "reconstituée via max_server_memory_usage_to_ram_ratio × "
            "OSMemoryTotal) — c'est elle qui REFUSE les requêtes en premier"
        )
    # limit_source == "config"
    if memory.clickhouse_limit_unavailable_reason:
        return (
            f"limite ClickHouse INDÉTERMINÉE ({memory.clickhouse_limit_unavailable_reason}) "
            f"— repli sur la config OKVORADO_DB_HEALTH_MEMORY_LIMIT_BYTES="
            f"{memory.configured_limit_bytes} octets (limite du conteneur, pas mesurée en direct)"
        )
    return (
        f"limite de configuration OKVORADO_DB_HEALTH_MEMORY_LIMIT_BYTES="
        f"{memory.configured_limit_bytes} octets (limite du conteneur, connue par "
        f"config) — INFÉRIEURE à la limite ClickHouse "
        f"({memory.clickhouse_limit_bytes} octets) : c'est elle qui mord en premier ici"
    )


def fetch_clickhouse_memory_limit(client: ClickHouseQueryable) -> tuple[int | None, bool]:
    """Lit le plafond mémoire RÉEL appliqué par ClickHouse — celui qui fait
    REFUSER les requêtes (`MEMORY_LIMIT_EXCEEDED`), distinct de la limite
    Docker du conteneur qui, elle, tue le process par OOM.

    DÉFAUT MESURÉ (2026-08-09) : sur `.6`, `max_server_memory_usage` mesuré
    dans `system.server_settings` vaut 1,80 Gio — INFÉRIEUR à la limite
    Docker de 2 Gio codée en dur comme défaut de config. C'est cette limite
    ClickHouse qui mord EN PREMIER (refus de requête avant OOM du conteneur),
    et l'ancien code ne la lisait jamais, comparant `MemoryResident` au
    mauvais seuil.

    ⚠️ PIÈGE : `max_server_memory_usage` peut valoir `0`, ce qui NE signifie
    PAS "pas de limite" mais "pas de limite EXPLICITE" — ClickHouse calcule
    alors la limite effective depuis `max_server_memory_usage_to_ram_ratio`
    (défaut serveur 0.9) multiplié par la RAM totale vue par le process
    (`system.asynchronous_metrics`, métrique `OSMemoryTotal`). Ce cas est
    traité ici : la fonction ne retourne JAMAIS 0 comme limite (diviser par
    zéro ou afficher un pourcentage absurde), elle reconstitue la valeur
    effective quand c'est calculable, et signale explicitement (second
    élément du tuple = `True`) que la valeur est déduite plutôt que réglée.

    Returns:
        `(limit_bytes, is_computed)` — `limit_bytes` est `None` si la lecture
        a totalement échoué (l'appelant doit alors produire un état
        "indisponible" pour ce plafond précis, jamais retomber en silence
        sur la config). `is_computed=True` si `limit_bytes` a été reconstitué
        via le ratio RAM (réglage serveur à 0).

    Raises:
        Exception: propagée telle quelle si la requête `max_server_memory_usage`
            échoue — l'appelant (`collect_memory_health`) est responsable de
            traduire cet échec en état "limite indéterminée".
    """
    rows = client.query(
        "SELECT value FROM system.server_settings "
        "WHERE name = {setting:String}",
        {"setting": "max_server_memory_usage"},
    )
    raw_limit = int(float(rows[0][0])) if rows and rows[0][0] is not None else 0

    if raw_limit > 0:
        return raw_limit, False

    # raw_limit == 0 (ou réglage absent) : pas de limite EXPLICITE — ClickHouse
    # calcule depuis le ratio RAM. On tente de reconstituer la même valeur ;
    # si le ratio ou la RAM totale ne sont pas lisibles, on retourne None
    # plutôt qu'une limite inventée (zéro silencieux).
    ratio_rows = client.query(
        "SELECT value FROM system.server_settings "
        "WHERE name = {setting:String}",
        {"setting": "max_server_memory_usage_to_ram_ratio"},
    )
    ram_rows = client.query(
        "SELECT value FROM system.asynchronous_metrics "
        "WHERE metric = {metric:String}",
        {"metric": "OSMemoryTotal"},
    )
    if not ratio_rows or ratio_rows[0][0] is None or not ram_rows or ram_rows[0][0] is None:
        return None, False

    ratio = float(ratio_rows[0][0])
    ram_total = int(float(ram_rows[0][0]))
    if ratio <= 0 or ram_total <= 0:
        return None, False

    computed_limit = int(ram_total * ratio)
    return computed_limit, True


def collect_memory_health(client: ClickHouseQueryable, configured_limit_bytes: int) -> MemoryHealth:
    """Mémoire résidente du serveur ClickHouse (`system.asynchronous_metrics`),
    rapportée au plafond qui MORD EN PREMIER entre la limite ClickHouse
    (`max_server_memory_usage`, lue en direct, jamais codée en dur — même
    principe que `fetch_merge_tree_thresholds`) et `configured_limit_bytes`
    (repli de configuration, typiquement la limite Docker du conteneur —
    connue par config, PAS lue depuis ClickHouse, ce module n'a pas accès au
    socket Docker).

    DÉFAUT MESURÉ (2026-08-09) : avant cette fonction, l'unique plafond
    utilisé était `configured_limit_bytes` — une valeur codée en dur qui
    n'est correcte que par coïncidence sur le déploiement de référence.
    Désormais la limite ClickHouse est LUE, et c'est la PLUS PETITE des deux
    limites connues qui décide le pourcentage affiché (c'est elle qui refuse
    les requêtes en premier). Si les deux sont égales, ClickHouse est
    considéré comme la source qui mord (c'est elle qui refuse la requête,
    l'OOM Docker ne serait qu'une conséquence si ClickHouse dépassait sa
    propre limite sans la faire respecter).

    ZÉRO SILENCIEUX : si la lecture de la limite ClickHouse échoue, l'appel
    ne retombe JAMAIS en silence sur `configured_limit_bytes` en le
    présentant comme mesuré — `clickhouse_limit_unavailable_reason` est
    renseigné et `limit_source="config"` documente explicitement que c'est
    un repli, pas une mesure.
    """
    rows = client.query(
        "SELECT value FROM system.asynchronous_metrics WHERE metric = {metric:String}",
        {"metric": "MemoryResident"},
    )
    resident_bytes = int(float(rows[0][0])) if rows and rows[0][0] is not None else 0

    clickhouse_limit_bytes: int | None = None
    clickhouse_limit_is_computed = False
    clickhouse_limit_unavailable_reason = ""
    try:
        clickhouse_limit_bytes, clickhouse_limit_is_computed = fetch_clickhouse_memory_limit(client)
        if clickhouse_limit_bytes is None:
            clickhouse_limit_unavailable_reason = (
                "max_server_memory_usage=0 (pas de limite explicite) et "
                "max_server_memory_usage_to_ram_ratio/OSMemoryTotal illisibles "
                "— impossible de reconstituer la limite effective"
            )
    except Exception as exc:
        log.error("db_health: echec lecture limite memoire ClickHouse", exc_info=True)
        clickhouse_limit_unavailable_reason = f"lecture system.server_settings impossible: {exc}"

    # Le plafond qui MORD EN PREMIER : le plus petit des deux, ClickHouse
    # prioritaire à égalité (voir docstring). Si la limite ClickHouse est
    # indisponible, on retombe sur la config SEULEMENT en le signalant
    # explicitement via limit_source (jamais en silence).
    if clickhouse_limit_bytes is not None and clickhouse_limit_bytes > 0:
        if configured_limit_bytes > 0 and configured_limit_bytes < clickhouse_limit_bytes:
            effective_limit = configured_limit_bytes
            limit_source = "config"
        else:
            effective_limit = clickhouse_limit_bytes
            limit_source = "clickhouse_computed" if clickhouse_limit_is_computed else "clickhouse"
    else:
        effective_limit = configured_limit_bytes
        limit_source = "config"

    pct = (resident_bytes / effective_limit * 100) if effective_limit > 0 else 0.0
    if pct >= CRITICAL_MEMORY_PCT:
        state = HealthState.CRITICAL
    elif pct >= WARNING_MEMORY_PCT:
        state = HealthState.WARNING
    else:
        state = HealthState.HEALTHY

    return MemoryHealth(
        resident_bytes=resident_bytes,
        limit_bytes=effective_limit,
        state=state,
        clickhouse_limit_bytes=clickhouse_limit_bytes,
        clickhouse_limit_is_computed=clickhouse_limit_is_computed,
        clickhouse_limit_unavailable_reason=clickhouse_limit_unavailable_reason,
        configured_limit_bytes=configured_limit_bytes,
        limit_source=limit_source,
    )


# ---------------------------------------------------------------------------
# Réplication (si un jour il y en a)
# ---------------------------------------------------------------------------


def collect_replication_active(client: ClickHouseQueryable) -> bool:
    """`True` si `system.replicas` existe ET contient au moins une ligne.

    Homelab actuel : nœud ClickHouse UNIQUE, `system.replicas` existe (table
    système toujours présente) mais est VIDE — ce n'est pas une erreur, la
    réplication n'est simplement pas configurée. Retourne `False` dans ce
    cas comme dans le cas où la table n'existe pas du tout (versions très
    anciennes) : les deux signifient "pas de réplication à surveiller ici".
    """
    try:
        rows = client.query("SELECT count() FROM system.replicas")
    except Exception:
        log.error("db_health: lecture system.replicas impossible", exc_info=True)
        return False
    return bool(rows and int(rows[0][0]) > 0)


# ---------------------------------------------------------------------------
# Assemblage — snapshot complet, ZÉRO SILENCIEUX
# ---------------------------------------------------------------------------


def _overall_state(states: list[HealthState]) -> HealthState:
    """Le pire état l'emporte — un exploitant ne doit jamais voir "sain" si
    UN SEUL indicateur est critique."""
    if not states:
        return HealthState.UNAVAILABLE
    return max(states, key=lambda s: s.severity)


def collect_snapshot(client: ClickHouseQueryable, memory_limit_bytes: int) -> DbHealthSnapshot:
    """Collecte l'ensemble des indicateurs de santé — snapshot unique servant
    à la fois à l'écran et à l'historique persisté par la routine périodique.

    ZÉRO SILENCIEUX : chaque section est protégée individuellement. Un échec
    partiel (ex. `part_log` désactivé) ne doit pas empêcher les autres
    indicateurs de s'afficher ; un échec TOTAL (ClickHouse ne répond à aucune
    requête) produit un snapshot `UNAVAILABLE` explicite, jamais un snapshot
    "sain" par défaut.
    """
    now = datetime.now(UTC)
    indicators: list[HealthIndicator] = []
    states: list[HealthState] = []

    try:
        parts_by_table = collect_parts_health(client)
        for p in parts_by_table:
            states.append(p.state)
            indicators.append(
                HealthIndicator(
                    key=f"parts.{p.table}",
                    label=f"Parts actives — {p.table}",
                    state=p.state,
                    # Valeur DÉCISIONNELLE = maximum par partition (ce que
                    # ClickHouse compare réellement aux seuils) ; le total
                    # de table est ajouté entre parenthèses à titre
                    # contextuel seulement, jamais comparé au seuil.
                    value_label=(
                        f"{p.max_active_parts_in_partition} parts "
                        f"(max sur 1 partition parmi {p.partition_count}; "
                        f"{p.total_active_parts} au total)"
                    ),
                    threshold_label=(
                        f"seuil ralentissement={p.parts_to_delay_insert}, "
                        f"seuil refus={p.parts_to_throw_insert} — "
                        "PAR PARTITION (lus depuis system.merge_tree_settings)"
                    ),
                )
            )
    except Exception as exc:
        log.error("db_health: echec collecte parts actives", exc_info=True)
        parts_by_table = []
        indicators.append(
            HealthIndicator(
                key="parts",
                label="Parts actives",
                state=HealthState.UNAVAILABLE,
                value_label="indisponible",
                detail=str(exc),
            )
        )
        states.append(HealthState.UNAVAILABLE)

    try:
        merge_backlog = collect_merge_backlog(client)
        states.append(merge_backlog.state)
        indicators.append(
            HealthIndicator(
                key="merge_backlog",
                label="Fusions en retard",
                state=merge_backlog.state,
                value_label=(
                    f"{merge_backlog.parts_created} créées / "
                    f"{merge_backlog.parts_merged} fusionnées sur {merge_backlog.window_label} "
                    f"(écart {merge_backlog.backlog:+d})"
                ),
                threshold_label=(
                    f"avertissement à {WARNING_BACKLOG_PARTS} parts d'écart, "
                    f"critique à {CRITICAL_BACKLOG_PARTS}"
                ),
            )
        )
    except Exception as exc:
        log.error("db_health: echec collecte fusions en retard", exc_info=True)
        merge_backlog = None
        indicators.append(
            HealthIndicator(
                key="merge_backlog",
                label="Fusions en retard",
                state=HealthState.UNAVAILABLE,
                value_label="indisponible",
                detail=str(exc),
            )
        )
        states.append(HealthState.UNAVAILABLE)

    try:
        errors = collect_errors_of_interest(client)
        error_state = evaluate_errors_state(errors)
        states.append(error_state)
        indicators.append(
            HealthIndicator(
                key="errors",
                label="Erreurs cumulées (TOO_MANY_PARTS / mémoire / timeout)",
                state=error_state,
                value_label=(
                    ", ".join(f"{e.name}={e.value}" for e in errors) if errors else "aucune"
                ),
                threshold_label=(
                    "présence de TOO_MANY_PARTS/MEMORY_LIMIT_EXCEEDED/TIMEOUT_EXCEEDED = critique"
                ),
            )
        )
    except Exception as exc:
        log.error("db_health: echec collecte erreurs", exc_info=True)
        errors = []
        indicators.append(
            HealthIndicator(
                key="errors",
                label="Erreurs cumulées",
                state=HealthState.UNAVAILABLE,
                value_label="indisponible",
                detail=str(exc),
            )
        )
        states.append(HealthState.UNAVAILABLE)

    try:
        stuck_mutations = collect_stuck_mutations(client)
        mutations_state = evaluate_mutations_state(stuck_mutations)
        states.append(mutations_state)
        indicators.append(
            HealthIndicator(
                key="mutations",
                label="Mutations bloquées",
                state=mutations_state,
                value_label=f"{len(stuck_mutations)} bloquée(s)",
            )
        )
    except Exception as exc:
        log.error("db_health: echec collecte mutations", exc_info=True)
        stuck_mutations = []
        indicators.append(
            HealthIndicator(
                key="mutations",
                label="Mutations bloquées",
                state=HealthState.UNAVAILABLE,
                value_label="indisponible",
                detail=str(exc),
            )
        )
        states.append(HealthState.UNAVAILABLE)

    try:
        detached = collect_detached_parts(client)
        states.append(detached.state)
        indicators.append(
            HealthIndicator(
                key="detached_parts",
                label="Parts détachées",
                state=detached.state,
                value_label=f"{detached.count} part(s), {detached.total_bytes} octets",
                threshold_label=(
                    f"avertissement dès {WARNING_DETACHED_PARTS_COUNT}, "
                    f"critique à {CRITICAL_DETACHED_PARTS_COUNT}"
                ),
            )
        )
    except Exception as exc:
        log.error("db_health: echec collecte parts detachees", exc_info=True)
        detached = None
        indicators.append(
            HealthIndicator(
                key="detached_parts",
                label="Parts détachées",
                state=HealthState.UNAVAILABLE,
                value_label="indisponible",
                detail=str(exc),
            )
        )
        states.append(HealthState.UNAVAILABLE)

    try:
        memory = collect_memory_health(client, memory_limit_bytes)
        states.append(memory.state)
        indicators.append(
            HealthIndicator(
                key="memory",
                label="Mémoire",
                state=memory.state,
                value_label=(
                    f"{memory.pct_used:.0f}% "
                    f"({memory.resident_bytes} / {memory.limit_bytes} octets)"
                ),
                threshold_label=(
                    f"avertissement à {WARNING_MEMORY_PCT:.0f}%, critique à "
                    f"{CRITICAL_MEMORY_PCT:.0f}% — plafond retenu: "
                    f"{describe_memory_limit_source(memory)}"
                ),
            )
        )
    except Exception as exc:
        log.error("db_health: echec collecte memoire", exc_info=True)
        memory = None
        indicators.append(
            HealthIndicator(
                key="memory",
                label="Mémoire",
                state=HealthState.UNAVAILABLE,
                value_label="indisponible",
                detail=str(exc),
            )
        )
        states.append(HealthState.UNAVAILABLE)

    replication_active = collect_replication_active(client)

    overall = _overall_state(states)
    return DbHealthSnapshot(
        checked_at=now,
        overall_state=overall,
        parts_by_table=parts_by_table,
        merge_backlog=merge_backlog,
        errors=errors,
        memory=memory,
        stuck_mutations=stuck_mutations,
        detached_parts=detached,
        replication_active=replication_active,
        indicators=indicators,
    )


def build_unavailable_snapshot(error_message: str) -> DbHealthSnapshot:
    """Snapshot explicite pour le cas où la connexion à ClickHouse échoue
    totalement (impossible à établir, refusée, ou expirée) avant même
    d'atteindre `collect_snapshot`.

    ZÉRO SILENCIEUX : appelé par le routeur dans ce cas. L'écran affiche
    "indisponible", jamais un tableau vide qu'on confondrait avec "aucune
    table à risque".
    """
    return DbHealthSnapshot(
        checked_at=datetime.now(UTC),
        overall_state=HealthState.UNAVAILABLE,
        error_message=error_message,
    )


# ---------------------------------------------------------------------------
# Actions de maintien — SÛRES UNIQUEMENT, toujours à la demande explicite
# ---------------------------------------------------------------------------
#
# INTERDIT ABSOLU DE CE MODULE : aucune fonction ci-dessous ni ailleurs dans
# ce fichier ne redémarre, n'arrête, ni ne recrée le serveur ClickHouse. La
# demande utilisateur porte explicitement sur une routine qui SURVEILLE et
# PRÉVIENT plutôt que de reproduire le geste "redémarrer la base qui
# crashait" qui masquait le problème sur l'ancienne instance ManageEngine.
# Toute action ci-dessous est un ALTER/OPTIMIZE/DELETE ciblé sur des objets
# précis (jamais le process serveur), et n'est déclenchée par AUCUNE boucle
# automatique de ce module — uniquement par un appel explicite du routeur,
# lui-même déclenché par un clic exploitant (voir app/routers/db_health.py).


def optimize_table(client: ClickHouseQueryable, table: str, final: bool = False) -> str:
    """Force la fusion des parts actives d'une table — geste COÛTEUX.

    `OPTIMIZE TABLE ... FINAL` fusionne TOUTES les parts en une seule :
    mesuré coûteux en I/O disque et peut saturer temporairement l'espace
    disque (ClickHouse a besoin d'espace pour écrire la part fusionnée avant
    de libérer les anciennes) — exigence de la tâche : mesurer le coût avant
    et prévenir à l'écran, jamais l'exécuter à l'aveugle.

    `OPTIMIZE TABLE` SANS `FINAL` est la variante moins agressive : elle
    fusionne les parts éligibles selon la politique normale de ClickHouse
    (parts de taille proche), sans forcer une fusion complète — c'est le
    choix par défaut recommandé à l'écran, `FINAL` reste disponible mais
    signalé comme plus coûteux.

    GARDE SÉCU : `table` doit appartenir à `MONITORED_TABLES` — jamais un nom
    dérivé d'un input libre, même geste de défense que
    `app.services.retention.build_ttl_alter_statement`.

    Returns:
        L'ordre SQL exécuté (pour audit/affichage), jamais exécuté deux fois
        implicitement par cette fonction.

    Raises:
        ValueError: si `table` est hors allowlist — AUCUNE requête n'est
            exécutée dans ce cas.
    """
    if table not in MONITORED_TABLES:
        raise ValueError(
            f"table hors allowlist db_health: {table!r} (autorisées: {sorted(MONITORED_TABLES)})"
        )
    sql = f"OPTIMIZE TABLE default.{table}" + (" FINAL" if final else "")
    try:
        client.query(sql)
    except Exception:
        log.error(
            "db_health: echec OPTIMIZE TABLE",
            exc_info=True,
            extra={"table": table, "final": final},
        )
        raise
    log.info("db_health: OPTIMIZE TABLE execute table=%s final=%s", table, final)
    return sql


def preview_detached_parts_purge(client: ClickHouseQueryable) -> DetachedPartsHealth:
    """Annonce ce qui SERAIT purgé — n'en supprime aucune (même pattern
    preview/execute que `app.services.purge`)."""
    return collect_detached_parts(client)


class DetachedPartsPurgeAllPreview(BaseModel):
    """Ce qui SERAIT purgé par une purge COMPLÈTE (tables de flux + tables
    système) — n'en supprime aucune.

    `targets` fige la liste EXACTE des couples `(database, table)` déjà
    validés contre les deux allowlists au moment du preview — c'est cette
    liste, et EXCLUSIVEMENT elle, qu'`execute_detached_parts_purge_all`
    parcourt : jamais un nouveau `SELECT DISTINCT database, table FROM
    system.detached_parts` au moment de l'exécution (même garde anti-TOCTOU
    que `app.services.purge.TablePurgePreview.row_ids` — ce que l'exploitant
    a vu à l'écran est exactement ce qui part, pas un état recalculé qui
    aurait pu diverger entre-temps si une autre purge tourne en parallèle).
    """

    targets: list[tuple[str, str]]
    detail: DetachedPartsHealth


class DetachedPartsPurgeAllResult(BaseModel):
    """Résultat réel d'une purge complète — ZÉRO SILENCIEUX : `failures` non
    vide signifie une purge PARTIELLE, jamais masquée par un `purged_tables`
    qui semblerait un succès total à lui seul (même contrat que
    `app.services.purge.BackupPurgeResult.errors`)."""

    purged_tables: list[str]
    failures: list[str]
    parts_before: int

    @property
    def is_complete(self) -> bool:
        """`True` seulement si AUCUNE table n'a échoué — l'écran doit lire
        cette propriété plutôt que de déduire un succès de `purged_tables`
        seul (une liste non vide ne prouve rien sur l'absence d'échecs)."""
        return not self.failures


def preview_detached_parts_purge_all(client: ClickHouseQueryable) -> DetachedPartsPurgeAllPreview:
    """Annonce la purge COMPLÈTE — tables de flux (`MONITORED_TABLES`) ET
    tables système (`SYSTEM_LOG_TABLES`) — n'en supprime aucune.

    DÉFAUT CORRIGÉ (2026-08-09) : `preview_detached_parts_purge` (ci-dessus)
    ne fait qu'annoncer le TOTAL déjà connu — il ne dit jamais QUELLES tables
    seraient réellement purgées, ni si l'exécution pourrait les couvrir
    toutes. Cette fonction construit la liste EXACTE des cibles depuis
    `system.detached_parts` lui-même (c'est ClickHouse qui fournit les noms,
    jamais l'exploitant), valide CHAQUE couple via
    `validate_detached_parts_target` avant de le retenir, et exclut
    silencieusement tout couple qui échouerait cette validation (défense en
    profondeur : un nom hors des deux allowlists n'est ni exécuté, ni même
    proposé à l'écran comme purgeable).
    """
    detail = collect_detached_parts(client)
    targets: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for entry in detail.by_group:
        pair = (entry.database, entry.table)
        if pair in seen:
            continue
        try:
            validate_detached_parts_target(entry.database, entry.table)
        except ValueError:
            log.error(
                "db_health: table detachee hors allowlist ignoree du preview complet",
                extra={"database": entry.database, "table": entry.table},
            )
            continue
        seen.add(pair)
        targets.append(pair)
    return DetachedPartsPurgeAllPreview(targets=targets, detail=detail)


def execute_detached_parts_purge_all(
    client: ClickHouseQueryable, preview: DetachedPartsPurgeAllPreview
) -> DetachedPartsPurgeAllResult:
    """Purge réellement TOUTES les tables listées dans `preview.targets` —
    jamais une nouvelle liste recalculée (anti-TOCTOU, cf. docstring de
    `DetachedPartsPurgeAllPreview`).

    Chaque cible est REVALIDÉE via `validate_detached_parts_target` avant
    interpolation SQL — défense en profondeur : ce module ne fait jamais
    confiance à un objet `preview` reçu en paramètre sans le recontrôler
    (même geste que `app.services.purge.execute_table_purge`), même si ce
    `preview` a été construit par `preview_detached_parts_purge_all` dans le
    même processus.

    ZÉRO SILENCIEUX : un échec sur UNE table (ex. verrou concurrent, table
    renommée entre le preview et l'exécution) n'interrompt PAS le nettoyage
    des autres — il est collecté dans `failures`, jamais avalé. Le succès
    global n'est jamais déduit de `purged_tables` seul : l'appelant doit lire
    `failures`.
    """
    purged_tables: list[str] = []
    failures: list[str] = []
    for database, table in preview.targets:
        try:
            validate_detached_parts_target(database, table)
        except ValueError as exc:
            log.error(
                "db_health: cible de purge complete refusee par la garde securite",
                extra={"database": database, "table": table},
            )
            failures.append(f"{database}.{table}: {exc}")
            continue
        try:
            client.query(f"ALTER TABLE {database}.{table} DROP DETACHED PARTITION ALL")
        except Exception as exc:
            log.error(
                "db_health: echec purge parts detachees (purge complete)",
                exc_info=True,
                extra={"database": database, "table": table},
            )
            failures.append(f"{database}.{table}: {exc}")
            continue
        purged_tables.append(f"{database}.{table}")

    log.info(
        "db_health: purge complete parts detachees terminee reussies=%d echecs=%d parts_avant=%d",
        len(purged_tables),
        len(failures),
        preview.detail.count,
    )
    return DetachedPartsPurgeAllResult(
        purged_tables=purged_tables, failures=failures, parts_before=preview.detail.count
    )


def execute_detached_parts_purge(client: ClickHouseQueryable, table: str) -> int:
    """Supprime les parts détachées d'UNE table via `ALTER TABLE ... DROP
    DETACHED PARTITION ALL`.

    ClickHouse ne propose pas de suppression sélective d'une part détachée
    par son nom en une requête sûre (il faudrait lister et cibler chaque
    part individuellement) : la primitive disponible et sûre est
    `DROP DETACHED PARTITION ALL`, qui supprime TOUTES les parts détachées
    de la table ciblée — c'est le geste que ce module expose.

    GARDE SÉCU : `table` validé contre `MONITORED_TABLES` avant toute requête.

    Returns:
        Le nombre de parts détachées qui existaient AVANT la purge (mesuré
        par `preview_detached_parts_purge`, appelé en interne) — sert
        d'estimation du nombre supprimé, ClickHouse ne retourne pas de
        compte exact sur ce DDL.
    """
    if table not in MONITORED_TABLES:
        raise ValueError(
            f"table hors allowlist db_health: {table!r} (autorisées: {sorted(MONITORED_TABLES)})"
        )
    before = collect_detached_parts(client)
    try:
        client.query(f"ALTER TABLE default.{table} DROP DETACHED PARTITION ALL")
    except Exception:
        log.error("db_health: echec purge parts detachees", exc_info=True, extra={"table": table})
        raise
    log.info(
        "db_health: purge parts detachees terminee table=%s parts_avant=%d",
        table,
        before.count,
    )
    return before.count
