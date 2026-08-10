"""Service Rétention — TTL et projection disque des tables ClickHouse (LOT 2).

Ce module ne dépend PAS de l'implémentation concrète du client ClickHouse
(LOT 1) : il définit un `Protocol` typé (`ClickHouseQueryable`) que l'appelant
injecte, ce qui permet de tester toute la logique avec de simples doubles en
mémoire (voir `tests/test_retention.py`), sans infra.

Sécurité : c'est ici le SEUL endroit du projet où un nom de table peut entrer
dans du texte SQL (`build_ttl_alter_statement`). Il est validé contre une
allowlist en dur — voir la docstring de cette fonction.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any, Protocol

from app.models import AppliedTtl, TableRetention

log = logging.getLogger(__name__)

ALLOWED_TABLES: frozenset[str] = frozenset({"flows", "flows_1m0s", "flows_5m0s", "flows_1h0m0s"})
"""Allowlist en dur des tables ClickHouse pilotables par ce module.

Toute table hors de cette liste est refusée par `build_ttl_alter_statement`.
Ne JAMAIS étendre dynamiquement cette liste depuis une source externe
(config, DB, input utilisateur) : c'est la garde n°1 du projet (CONTRACT.md).
"""

MIN_TTL_DAYS = 1
MAX_TTL_DAYS = 3650


class ClickHouseQueryable(Protocol):
    """Ce dont ce module a besoin d'un client ClickHouse — lecture seule.

    Aucun import direct du client concret ici : l'appelant (router, tests)
    injecte l'implémentation.

    ⚠️ POINT D'INTÉGRATION LOT 1 : le client réel `clickhouse_connect.Client`
    (`app/clients/clickhouse.py`, fonction `connect()`) retourne un objet
    `QueryResult` dont les lignes sont dans `.result_rows` — PAS directement
    `list[tuple]`. L'adaptateur (probablement dans `app/deps.py` [LOT 0]) doit
    donc envelopper l'appel réel, ex. :
        class ClickHouseClientAdapter:
            def __init__(self, client): self._client = client
            def query(self, sql, parameters=None):
                return self._client.query(sql, parameters=parameters).result_rows
    Ce module ne fait aucune hypothèse au-delà de cette signature `query(sql,
    parameters) -> list[tuple]`.
    """

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> list[tuple[Any, ...]]:
        """Exécute une requête et retourne les lignes sous forme de tuples."""
        ...


# ---------------------------------------------------------------------------
# Parsing de l'expression TTL
# ---------------------------------------------------------------------------

_INTERVAL_UNIT_SECONDS: dict[str, int] = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
    "week": 7 * 86400,
}

# Formes reconnues :
#   toIntervalSecond(1296000) / toIntervalDay(15) / toIntervalMinute(30) / ...
_TO_INTERVAL_RE = re.compile(
    r"toInterval(?P<unit>Second|Minute|Hour|Day|Week)\s*\(\s*(?P<value>\d+)\s*\)",
    re.IGNORECASE,
)

# INTERVAL 1296000 SECOND / INTERVAL 15 DAY (SQL standard, insensible à la casse)
_INTERVAL_KEYWORD_RE = re.compile(
    r"INTERVAL\s+(?P<value>\d+)\s+(?P<unit>SECOND|MINUTE|HOUR|DAY|WEEK)S?",
    re.IGNORECASE,
)


_ENGINE_FULL_MARKERS_RE = re.compile(r"\b(PARTITION BY|ORDER BY|PRIMARY KEY|SETTINGS)\b")
"""Marqueurs d'un `engine_full` complet (par opposition a une clause TTL isolee).

Sert a distinguer "expression TTL nue" de "definition de moteur entiere" : dans le
second cas, l'absence de `TTL ` signifie qu'il n'y a AUCUNE retention, et il ne
faut surtout pas retomber sur le `toInterval...()` du partitionnement.
"""


def parse_ttl_seconds(ttl_expression: str) -> int | None:
    """Parse une expression TTL ClickHouse et retourne sa durée en secondes.

    Formes reconnues : `toIntervalSecond(N)`, `toIntervalDay(N)`,
    `toIntervalMinute(N)`, `toIntervalHour(N)`, `toIntervalWeek(N)`, ainsi que
    la forme SQL standard `INTERVAL N SECOND|DAY|...`.

    Toute expression vide, inconnue, ou dont l'unité n'est pas reconnue
    retourne `None` — cette fonction ne lève JAMAIS d'exception : un TTL
    illisible ne doit pas casser l'écran de rétention.
    """
    if not ttl_expression or not ttl_expression.strip():
        return None

    # ⚠️ On reçoit souvent le `engine_full` COMPLET, qui contient d'autres
    # `toInterval...()` AVANT la clause TTL. Exemple réel de `default.flows` :
    #   MergeTree PARTITION BY toYYYYMMDDhhmmss(toStartOfInterval(TimeReceived,
    #     toIntervalSecond(25920))) ... TTL TimeReceived + toIntervalSecond(1296000)
    # Un `search()` naïf attrape 25920 (le partitionnement) au lieu de 1296000
    # (la rétention) — soit 0,3 jour affiché au lieu de 15. On isole donc la
    # clause TTL AVANT de chercher l'intervalle.
    ttl_index = ttl_expression.find("TTL ")
    if ttl_index >= 0:
        ttl_expression = ttl_expression[ttl_index + 4 :]
        # La clause TTL s'arrête au SETTINGS suivant s'il existe.
        settings_index = ttl_expression.find("SETTINGS")
        if settings_index >= 0:
            ttl_expression = ttl_expression[:settings_index]
    elif _ENGINE_FULL_MARKERS_RE.search(ttl_expression):
        # C'est un `engine_full` complet SANS clause TTL : la table n'a aucune
        # rétention. Sans ce garde-fou on retomberait sur le toInterval du
        # PARTITION BY et on annoncerait un TTL qui n'existe pas.
        return None

    match = _TO_INTERVAL_RE.search(ttl_expression)
    if match:
        unit = match.group("unit").lower()
        value = int(match.group("value"))
        multiplier = _INTERVAL_UNIT_SECONDS.get(unit)
        if multiplier is None:
            return None
        return value * multiplier

    match = _INTERVAL_KEYWORD_RE.search(ttl_expression)
    if match:
        unit = match.group("unit").lower()
        value = int(match.group("value"))
        multiplier = _INTERVAL_UNIT_SECONDS.get(unit)
        if multiplier is None:
            return None
        return value * multiplier

    return None


# ---------------------------------------------------------------------------
# Lecture de l'état réel (lecture seule)
# ---------------------------------------------------------------------------


def load_retention_status(client: ClickHouseQueryable) -> list[TableRetention]:
    """Lit l'état de rétention réel des tables ClickHouse.

    Requêtes en LECTURE SEULE uniquement :
    - TTL depuis `system.tables` (expression parsée via `parse_ttl_seconds`).
    - Taille/lignes depuis `system.parts` (parts actives, groupées par table).

    Une table présente dans `system.tables` mais sans partie active (donc
    absente de `system.parts`) obtient `bytes_on_disk=0` et `rows=0`.
    """
    tables_rows = client.query(
        "SELECT table, engine, engine_full FROM system.tables WHERE database = {database:String}",
        {"database": "default"},
    )

    parts_rows = client.query(
        "SELECT table, sum(bytes_on_disk), sum(rows) FROM system.parts WHERE active GROUP BY table"
    )
    sizes_by_table: dict[str, tuple[int, int]] = {}
    for row in parts_rows:
        table_name = str(row[0])
        bytes_on_disk = int(row[1]) if row[1] is not None else 0
        rows = int(row[2]) if row[2] is not None else 0
        sizes_by_table[table_name] = (bytes_on_disk, rows)

    results: list[TableRetention] = []
    for row in tables_rows:
        table_name = str(row[0])
        engine = str(row[1])
        ttl_expression = str(row[2]) if len(row) > 2 and row[2] is not None else ""
        ttl_seconds = parse_ttl_seconds(ttl_expression)
        bytes_on_disk, rows = sizes_by_table.get(table_name, (0, 0))
        results.append(
            TableRetention(
                table=table_name,
                engine=engine,
                ttl_seconds=ttl_seconds,
                bytes_on_disk=bytes_on_disk,
                rows=rows,
            )
        )
    return results


# ---------------------------------------------------------------------------
# Estimation de croissance
# ---------------------------------------------------------------------------


def compute_growth_rate(bytes_on_disk: int, ttl_seconds: int | None) -> float | None:
    """Estime la croissance quotidienne (octets/jour) d'une table.

    HYPOTHÈSE (à afficher explicitement dans l'UI, ce n'est PAS une mesure) :
    si la table est en régime STATIONNAIRE (le volume ingéré quotidien est
    stable depuis au moins une durée = TTL), alors la taille actuelle sur
    disque représente environ `ttl_days` jours d'accumulation, et la
    croissance quotidienne moyenne ≈ `bytes_on_disk / ttl_days`.

    Cette hypothèse peut être fausse si : la table est plus jeune que son
    TTL (sous-estimation de la croissance), ou le trafic a changé récemment
    (sur/sous-estimation). Aucune série temporelle n'est utilisée ici.

    Retourne `None` si le TTL est inconnu ou nul (division impossible).
    """
    if ttl_seconds is None or ttl_seconds <= 0:
        return None
    ttl_days = ttl_seconds / 86400
    return bytes_on_disk / ttl_days


# ---------------------------------------------------------------------------
# Projection d'occupation disque — fonction pure
# ---------------------------------------------------------------------------


def project_disk_usage(table: str, new_ttl_days: int, growth_per_day: float) -> float:
    """Projette l'occupation disque d'une table pour un nouveau TTL.

    Fonction PURE : aucun accès I/O, entièrement testable. Le paramètre
    `table` n'est pas utilisé dans le calcul (il documente l'intention à
    l'appel et permet une future différenciation par table) ; il n'entre
    dans aucune requête SQL ici — cette fonction ne construit pas de SQL.

    Raises:
        ValueError: si `new_ttl_days` est négatif.
    """
    if new_ttl_days < 0:
        raise ValueError(f"new_ttl_days doit être positif ou nul, reçu {new_ttl_days!r}")
    if growth_per_day <= 0:
        return 0
    return growth_per_day * new_ttl_days


# ---------------------------------------------------------------------------
# Construction de l'ordre ALTER TTL — GARDE SÉCU CRITIQUE
# ---------------------------------------------------------------------------

_SAFE_TABLE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def build_ttl_alter_statement(table: str, ttl_days: int) -> str:
    """Construit (sans l'exécuter) l'ordre `ALTER TABLE ... MODIFY TTL ...`.

    ⚠️ EN V1 CET ORDRE N'EST JAMAIS EXÉCUTÉ. Il est retourné pour affichage
    en preview uniquement — l'exécution réelle est hors périmètre v1.

    GARDE SÉCU CRITIQUE : `table` doit appartenir à `ALLOWED_TABLES` (allowlist
    en dur des 4 tables connues). Une double vérification est appliquée :
    appartenance à l'allowlist ET conformité à un pattern strict
    `^[a-z][a-z0-9_]*$` (défense en profondeur contre toute variante
    d'injection — homoglyphes unicode, métacaractères, séquences `--`/`;`).
    `ttl_days` doit être un entier borné dans [MIN_TTL_DAYS, MAX_TTL_DAYS].

    Raises:
        ValueError: si `table` est hors allowlist ou ne respecte pas le
            pattern strict, ou si `ttl_days` est hors bornes.
    """
    if not isinstance(table, str) or not _SAFE_TABLE_NAME_RE.match(table):
        raise ValueError(f"nom de table invalide (pattern): {table!r}")
    if table not in ALLOWED_TABLES:
        raise ValueError(f"table hors allowlist: {table!r} (autorisées: {sorted(ALLOWED_TABLES)})")
    if not isinstance(ttl_days, int) or isinstance(ttl_days, bool):
        raise ValueError(f"ttl_days doit être un entier, reçu {ttl_days!r}")
    if not (MIN_TTL_DAYS <= ttl_days <= MAX_TTL_DAYS):
        raise ValueError(f"ttl_days hors bornes [{MIN_TTL_DAYS}, {MAX_TTL_DAYS}]: {ttl_days!r}")

    # `table` est ici garanti appartenir à ALLOWED_TABLES (littéral connu) :
    # l'interpolation directe est sûre car le champ n'est plus un input libre.
    return f"ALTER TABLE default.{table} MODIFY TTL TimeReceived + toIntervalDay({ttl_days})"


# ---------------------------------------------------------------------------
# Exécution réelle de l'ordre ALTER TTL (v2) — GARDE SÉCU CRITIQUE
# ---------------------------------------------------------------------------


def apply_ttl(client: ClickHouseQueryable, table: str, ttl_days: int) -> AppliedTtl:
    """Construit ET exécute réellement l'ordre `ALTER TABLE ... MODIFY TTL ...`.

    Réutilise `build_ttl_alter_statement` pour la construction du SQL : la
    garde sécu (allowlist + pattern strict + bornes) n'est PAS dupliquée ici,
    elle vit exclusivement dans cette fonction. `build_ttl_alter_statement`
    est appelée AVANT tout accès ClickHouse — si elle lève `ValueError`
    (table hors allowlist ou `ttl_days` hors bornes), `client.query()` n'est
    jamais invoquée et l'exception se propage telle quelle.

    Raises:
        ValueError: propagée depuis `build_ttl_alter_statement` — table hors
            allowlist ou `ttl_days` hors bornes. `client.query()` n'est PAS
            appelée dans ce cas.
        Exception: toute exception levée par `client.query()` (ClickHouse
            indisponible, erreur SQL) est loguée avec contexte avant d'être
            re-propagée telle quelle — jamais avalée silencieusement.
    """
    sql_statement = build_ttl_alter_statement(table, ttl_days)

    try:
        client.query(sql_statement)
    except Exception:
        log.error(
            "retention: echec execution ALTER TTL",
            exc_info=True,
            extra={"table": table, "ttl_days": ttl_days},
        )
        raise

    return AppliedTtl(
        table=table,
        ttl_days=ttl_days,
        sql_statement=sql_statement,
        applied_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# Impact d'une purge (baisse de TTL)
# ---------------------------------------------------------------------------


def estimate_purge_impact(
    current_ttl_days: float | None,
    new_ttl_days: int,
    bytes_on_disk: int,
    growth_per_day: float,
) -> float | None:
    """Estime le volume détruit (octets) si `new_ttl_days` < `current_ttl_days`.

    Baisser un TTL détruit des données de façon IRRÉVERSIBLE (ClickHouse
    purge les parts hors TTL au prochain merge). Cette estimation doit être
    affichée AVANT toute confirmation utilisateur.

    Basée sur la même hypothèse de régime stationnaire que
    `compute_growth_rate` : le volume purgé ≈ croissance/jour × jours retirés.

    Retourne 0 si le nouveau TTL est ≥ à l'actuel (aucune purge).
    Retourne `None` si le TTL actuel est inconnu (impossible de comparer).
    """
    if current_ttl_days is None:
        return None
    days_removed = current_ttl_days - new_ttl_days
    if days_removed <= 0:
        return 0
    return growth_per_day * days_removed


# ---------------------------------------------------------------------------
# Formatage lisible des octets
# ---------------------------------------------------------------------------

_UNITS = ("o", "Ko", "Mo", "Go", "To")


def format_bytes(value: int) -> str:
    """Formate un nombre d'octets en unité lisible (o/Ko/Mo/Go/To), locale FR.

    Les unités binaires (1024) sont utilisées. La virgule décimale est
    utilisée à la française pour toute unité au-delà de l'octet.
    """
    if value < 1024:
        return f"{value} o"
    size = float(value)
    unit_index = 0
    while size >= 1024 and unit_index < len(_UNITS) - 1:
        size /= 1024
        unit_index += 1
    formatted = f"{size:.1f}".replace(".", ",")
    return f"{formatted} {_UNITS[unit_index]}"
