"""Tests du module Santé DB (LOT db_health) — TDD, aucune infra requise.

Toutes les fixtures sont en dur. Le client ClickHouse est mocké via le
Protocol `ClickHouseQueryable` défini dans `app.services.db_health`, même
convention que `tests/test_retention.py`.

MORSURE EXIGÉE PAR LA TÂCHE :
- un seuil franchi produit l'état critique (sabote, vérifie l'échec, restaure)
- les seuils sont LUS depuis ClickHouse, pas codés en dur
- une requête en échec produit "indisponible", jamais un état sain trompeur
- aucune action destructive ne s'exécute sans demande explicite
- aucun redémarrage de ClickHouse n'est possible depuis le code
- la page est atteignable depuis le menu (couvert par tests/test_navigation.py)
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.db import SCHEMA
from app.models import HealthState
from app.services.db_health import (
    CRITICAL_BACKLOG_PARTS,
    CRITICAL_DETACHED_PARTS_COUNT,
    CRITICAL_MEMORY_PCT,
    MONITORED_TABLES,
    SYSTEM_LOG_TABLES,
    WARNING_BACKLOG_PARTS,
    WARNING_DETACHED_PARTS_COUNT,
    WARNING_MEMORY_PCT,
    WARNING_PCT_OF_DELAY_THRESHOLD,
    DetachedPartsPurgeAllPreview,
    build_unavailable_snapshot,
    collect_detached_parts,
    collect_errors_of_interest,
    collect_memory_health,
    collect_merge_backlog,
    collect_parts_health,
    collect_replication_active,
    collect_snapshot,
    collect_stuck_mutations,
    describe_memory_limit_source,
    evaluate_backlog_state,
    evaluate_errors_state,
    evaluate_mutations_state,
    evaluate_parts_state,
    execute_detached_parts_purge,
    execute_detached_parts_purge_all,
    fetch_clickhouse_memory_limit,
    fetch_merge_tree_thresholds,
    optimize_table,
    preview_detached_parts_purge,
    preview_detached_parts_purge_all,
    validate_detached_parts_target,
)

# ---------------------------------------------------------------------------
# Double de test — même convention que tests/test_retention.py
# ---------------------------------------------------------------------------


class FakeClickHouseClient:
    """Double de test du client ClickHouse — route par sous-chaîne du SQL.

    Enregistre les requêtes reçues pour permettre d'asserter qu'aucune valeur
    utilisateur n'est interpolée dans le SQL (garde sécurité n°1 du projet).
    """

    def __init__(self, responses: dict[str, list[tuple[Any, ...]]] | None = None) -> None:
        self.responses = responses or {}
        self.queries: list[tuple[str, dict[str, Any] | None]] = []
        self.raise_on: set[str] = set()
        """Sous-chaînes de SQL sur lesquelles lever une exception, pour
        simuler un échec ciblé (ex. seulement system.mutations en échec,
        le reste répond normalement)."""

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> list[tuple[Any, ...]]:
        self.queries.append((sql, parameters))
        for marker in self.raise_on:
            if marker in sql:
                raise RuntimeError(f"echec simule pour requete contenant {marker!r}")
        # Marqueur le PLUS LONG (donc le plus spécifique) qui matche gagne —
        # nécessaire depuis l'ajout de la requête de détail groupée
        # ("... GROUP BY database, table, reason") qui contient le marqueur
        # plus court "system.detached_parts" utilisé par la requête de
        # comptage global : sans ce tri, la première requête interceptait
        # aussi les réponses destinées à la seconde.
        matching_markers = sorted(
            (marker for marker in self.responses if marker in sql), key=len, reverse=True
        )
        if matching_markers:
            rows = self.responses[matching_markers[0]]
            # Simule le filtre serveur `WHERE name IN ({codes:Array(String)})`
            # émis par collect_errors_of_interest : sans ce filtre, le
            # double retournerait des lignes qu'un VRAI ClickHouse
            # n'aurait jamais renvoyées, faussant le test qui vérifie le
            # filtrage.
            if parameters and "codes" in parameters and rows and len(rows[0]) > 0:
                allowed = set(parameters["codes"])
                return [row for row in rows if row[0] in allowed]
            return rows
        return []

    @property
    def last_sql(self) -> str:
        return self.queries[-1][0] if self.queries else ""

    @property
    def last_parameters(self) -> dict[str, Any]:
        return self.queries[-1][1] or {} if self.queries else {}


def _default_responses(
    delay: int = 1000, throw: int = 3000, active_parts: int = 109
) -> dict[str, list[tuple[Any, ...]]]:
    """Réponses par défaut — reproduit l'état mesuré sur `.6` (109 parts,
    seuils 1000/3000, aucune erreur, aucune mutation bloquée, mémoire saine).

    `active_parts` ici représente le nombre de parts dans UNE SEULE
    partition (fixture par défaut : tout dans une seule partition
    'p0') — c'est le grain que `collect_parts_health` compare réellement
    aux seuils depuis la correction du bug total/partition (2026-08-08).
    """
    return {
        "system.merge_tree_settings": [
            ("parts_to_delay_insert", delay),
            ("parts_to_throw_insert", throw),
        ],
        "system.parts": [("flows", "p0", active_parts)],
        # Une seule ligne (parts_created, parts_merged) — la requête réelle
        # agrège countIf(NewPart) et sumIf(length(merged_from), MergeParts)
        # en une passe, pas une ligne par event_type (bug corrigé le
        # 2026-08-08, cf. docstring de collect_merge_backlog).
        "system.part_log": [(600, 610)],
        "system.errors": [],
        "system.mutations": [],
        "system.detached_parts": [(0, 0)],
        "system.asynchronous_metrics": [(1_180_000_000,)],
        "system.replicas": [(0,)],
    }


# ---------------------------------------------------------------------------
# Seuils lus depuis ClickHouse — jamais codés en dur
# ---------------------------------------------------------------------------


class TestThresholdsAreReadFromClickHouse:
    def test_fetch_merge_tree_thresholds_reads_real_values(self) -> None:
        client = FakeClickHouseClient(_default_responses(delay=1000, throw=3000))

        delay, throw = fetch_merge_tree_thresholds(client)

        assert delay == 1000
        assert throw == 3000

    def test_fetch_merge_tree_thresholds_reflects_custom_server_settings(self) -> None:
        """MORSURE : si le serveur a des seuils DIFFÉRENTS des valeurs
        habituelles (opérateur qui a augmenté la capacité), la fonction doit
        les refléter — la preuve qu'ils ne sont PAS codés en dur dans ce
        module est que changer la fixture change le résultat."""
        client = FakeClickHouseClient(_default_responses(delay=5000, throw=15000))

        delay, throw = fetch_merge_tree_thresholds(client)

        assert delay == 5000
        assert throw == 15000

    def test_collect_parts_health_uses_thresholds_from_client_not_constants(self) -> None:
        """Avec des seuils serveur très bas, un nombre de parts normalement
        sain devient critique — preuve que collect_parts_health() ne
        retombe jamais sur une constante interne."""
        client = FakeClickHouseClient(_default_responses(delay=50, throw=100, active_parts=109))

        results = collect_parts_health(client)

        flows = next(p for p in results if p.table == "flows")
        assert flows.parts_to_delay_insert == 50
        assert flows.parts_to_throw_insert == 100
        assert flows.state == HealthState.CRITICAL  # 109 >= 100 (throw)

    def test_no_table_or_column_name_is_interpolated_from_free_input(self) -> None:
        """Garde sécu n°1 : les tables surveillées transitent en paramètre
        lié (Array(String)), jamais interpolées en texte SQL."""
        client = FakeClickHouseClient(_default_responses())

        collect_parts_health(client)

        parts_query = next(q for q, _ in client.queries if "system.parts" in q)
        assert "{tables:Array(String)}" in parts_query
        assert "flows'" not in parts_query  # jamais de littéral de table dans le SQL


# ---------------------------------------------------------------------------
# MORSURE : un seuil franchi produit l'état critique — sabote / vérifie / restaure
# ---------------------------------------------------------------------------


class TestPartsThresholdBites:
    def test_healthy_below_warning_floor(self) -> None:
        assert evaluate_parts_state(
            max_parts_in_partition=100, delay_threshold=1000, throw_threshold=3000
        ) == (HealthState.HEALTHY)

    def test_warning_at_pct_of_delay_threshold(self) -> None:
        floor = int(1000 * (WARNING_PCT_OF_DELAY_THRESHOLD / 100))
        assert evaluate_parts_state(
            max_parts_in_partition=floor, delay_threshold=1000, throw_threshold=3000
        ) == (HealthState.WARNING)

    def test_critical_at_delay_threshold_ralentissement_force(self) -> None:
        """SABOTAGE : porte le maximum de parts actives PAR PARTITION au
        seuil exact de ralentissement forcé (1000, mesuré sur .6) — DOIT
        produire CRITIQUE."""
        state = evaluate_parts_state(
            max_parts_in_partition=1000, delay_threshold=1000, throw_threshold=3000
        )
        assert state == HealthState.CRITICAL

    def test_critical_at_throw_threshold_refus_ecriture(self) -> None:
        """SABOTAGE : porte le maximum de parts actives PAR PARTITION au
        seuil exact de refus d'écriture (3000, mesuré sur .6) — DOIT
        produire CRITIQUE."""
        state = evaluate_parts_state(
            max_parts_in_partition=3000, delay_threshold=1000, throw_threshold=3000
        )
        assert state == HealthState.CRITICAL

    def test_restore_below_threshold_returns_to_healthy(self) -> None:
        """RESTAURATION : une fois repassé sous le seuil, l'état redevient
        sain — la classification n'a pas d'effet de bord/mémoire."""
        assert evaluate_parts_state(3000, 1000, 3000) == HealthState.CRITICAL
        assert evaluate_parts_state(50, 1000, 3000) == HealthState.HEALTHY

    def test_high_total_across_many_partitions_stays_healthy_if_each_partition_is_low(
        self,
    ) -> None:
        """MORSURE — GARDE-FOU CENTRAL DE LA CORRECTION : un total de table
        largement au-dessus du seuil de refus (3000) reste SAIN si aucune
        partition individuelle ne l'approche — la preuve directe que
        `collect_parts_health` compare le MAXIMUM par partition, jamais la
        somme de toutes les partitions. Reproduit le cas mesuré sur .6 le
        2026-08-08 (27 partitions actives, 7 parts max dans la plus
        chargée, ~180 parts au total)."""
        client = FakeClickHouseClient(
            {
                "system.merge_tree_settings": [
                    ("parts_to_delay_insert", 1000),
                    ("parts_to_throw_insert", 3000),
                ],
                # 40 partitions à 100 parts chacune = 4000 au total (> 3000,
                # le seuil de refus) mais AUCUNE partition n'approche 1000.
                "system.parts": [("flows", f"p{i}", 100) for i in range(40)],
            }
        )

        results = collect_parts_health(client)

        flows = next(p for p in results if p.table == "flows")
        assert flows.total_active_parts == 4000  # bien au-dessus du seuil de refus...
        assert flows.max_active_parts_in_partition == 100  # ...mais le max reste bas
        assert flows.state == HealthState.HEALTHY  # donc SAIN, pas de fausse alerte

    def test_single_hot_partition_triggers_critical_even_with_low_total(self) -> None:
        """MORSURE inverse : une SEULE partition chaude qui franchit le
        seuil déclenche CRITIQUE même si le total de table reste modeste —
        preuve que la détection ne dépend pas non plus du total dans l'autre
        sens (un vrai danger localisé ne doit jamais être dilué par des
        partitions saines)."""
        client = FakeClickHouseClient(
            {
                "system.merge_tree_settings": [
                    ("parts_to_delay_insert", 1000),
                    ("parts_to_throw_insert", 3000),
                ],
                "system.parts": [
                    ("flows", "p_hot", 3000),
                    ("flows", "p_cold_1", 5),
                    ("flows", "p_cold_2", 5),
                ],
            }
        )

        results = collect_parts_health(client)

        flows = next(p for p in results if p.table == "flows")
        assert flows.total_active_parts == 3010
        assert flows.max_active_parts_in_partition == 3000
        assert flows.state == HealthState.CRITICAL


class TestMergeBacklogThresholdBites:
    def test_healthy_when_merge_follows(self) -> None:
        assert evaluate_backlog_state(backlog=5) == HealthState.HEALTHY

    def test_warning_at_threshold(self) -> None:
        assert evaluate_backlog_state(backlog=WARNING_BACKLOG_PARTS) == HealthState.WARNING

    def test_critical_at_threshold(self) -> None:
        """SABOTAGE : porte l'écart créées/fusionnées au seuil critique."""
        assert evaluate_backlog_state(backlog=CRITICAL_BACKLOG_PARTS) == HealthState.CRITICAL

    def test_restore_negative_backlog_is_healthy(self) -> None:
        """RESTAURATION : la fusion qui rattrape (plus fusionné que créé sur
        la fenêtre) reste saine, jamais un écart négatif classé critique."""
        assert evaluate_backlog_state(backlog=-20) == HealthState.HEALTHY

    def test_collect_merge_backlog_computes_from_part_log(self) -> None:
        """La requête réelle agrège en une seule ligne (parts_created,
        parts_merged) : parts_merged = sum(length(merged_from)) sur les
        événements MergeParts, PAS un décompte d'événements de fusion (un
        événement MergeParts consomme plusieurs parts sources — bug corrigé
        le 2026-08-08, cf. docstring de collect_merge_backlog)."""
        client = FakeClickHouseClient({"system.part_log": [(700, 120)]})

        result = collect_merge_backlog(client)

        assert result.parts_created == 700
        assert result.parts_merged == 120
        assert result.backlog == 580

    def test_collect_merge_backlog_reflects_real_measured_state_on_dot6(self) -> None:
        """MORSURE anti-régression : reproduit exactement le défaut mesuré
        sur .6 le 2026-08-08 (105 NewPart, 22 événements MergeParts
        consommant 133 parts au total) — l'ancienne implémentation
        (count() des événements) aurait donné un backlog de +83 (faux
        critique) ; la bonne implémentation donne -28 (fusion qui suit,
        sain)."""
        client = FakeClickHouseClient({"system.part_log": [(105, 133)]})

        result = collect_merge_backlog(client)

        assert result.parts_created == 105
        assert result.parts_merged == 133
        assert result.backlog == -28
        assert result.state == HealthState.HEALTHY


class TestMemoryThresholdBites:
    def test_healthy_below_warning_pct(self) -> None:
        limit = 2 * 1024**3
        client = FakeClickHouseClient({"system.asynchronous_metrics": [(int(limit * 0.5),)]})
        result = collect_memory_health(client, limit)
        assert result.state == HealthState.HEALTHY

    def test_warning_at_pct(self) -> None:
        limit = 2 * 1024**3
        resident = int(limit * (WARNING_MEMORY_PCT / 100))
        client = FakeClickHouseClient({"system.asynchronous_metrics": [(resident,)]})
        result = collect_memory_health(client, limit)
        assert result.state == HealthState.WARNING

    def test_critical_at_pct_matches_measured_container_limit(self) -> None:
        """SABOTAGE : reproduit le conteneur réel (limite 2 Gio, mesurée sur
        .6 via docker inspect) et pousse la mémoire résidente au-delà du
        seuil critique (marge de 1 point pour éviter un arrondi flottant à
        la frontière exacte, non représentatif du comportement métier testé
        par ailleurs à la frontière exacte dans evaluate_parts_state)."""
        limit = 2 * 1024**3  # 2 Gio, valeur mesurée sur .6
        resident = int(limit * ((CRITICAL_MEMORY_PCT + 1) / 100))
        client = FakeClickHouseClient({"system.asynchronous_metrics": [(resident,)]})

        result = collect_memory_health(client, limit)

        assert result.state == HealthState.CRITICAL

    def test_restore_below_threshold(self) -> None:
        limit = 2 * 1024**3
        client_crit = FakeClickHouseClient({"system.asynchronous_metrics": [(int(limit * 0.95),)]})
        client_ok = FakeClickHouseClient({"system.asynchronous_metrics": [(int(limit * 0.5),)]})

        assert collect_memory_health(client_crit, limit).state == HealthState.CRITICAL
        assert collect_memory_health(client_ok, limit).state == HealthState.HEALTHY

    def test_measured_reference_value_59_pct_is_healthy(self) -> None:
        """Reproduit la mesure réelle citée dans la tâche : 1,18 Gio / 2 Gio
        (59%) — doit être SAIN, ni warning ni critique."""
        limit = 2 * 1024**3
        resident = int(1.18 * 1024**3)
        client = FakeClickHouseClient({"system.asynchronous_metrics": [(resident,)]})

        result = collect_memory_health(client, limit)

        assert result.state == HealthState.HEALTHY
        assert 55 < result.pct_used < 62


# ---------------------------------------------------------------------------
# Limite mémoire ClickHouse — LUE en direct, pas codée en dur
# ---------------------------------------------------------------------------
#
# DÉFAUT MESURÉ (2026-08-09) : l'écran comparait `MemoryResident` à la seule
# valeur de config `db_health_memory_limit_bytes` (2 Gio codés en dur, exacts
# par coïncidence sur .6) sans jamais lire la limite RÉELLE de ClickHouse
# (`max_server_memory_usage`, system.server_settings) — mesurée à 1,80 Gio
# sur .6, INFÉRIEURE à la config, donc c'est ELLE qui refuse les requêtes en
# premier. `FakeClickHouseClient` (routage par sous-chaîne SQL) ne peut pas
# distinguer deux requêtes qui partagent le même marqueur de table avec des
# paramètres différents (MemoryResident vs OSMemoryTotal, tous deux dans
# system.asynchronous_metrics) : ce double routé-par-paramètre le permet.


class ParamRoutedFakeClickHouseClient:
    """Double de test qui route sur `(marqueur de table, paramètre nommé)` —
    nécessaire ici car `MemoryResident`/`OSMemoryTotal` partagent la table
    `system.asynchronous_metrics` et `max_server_memory_usage`/
    `..._to_ram_ratio` partagent `system.server_settings`, avec des valeurs
    de réponse DIFFÉRENTES pour chaque paramètre — chose que
    `FakeClickHouseClient` (routage par sous-chaîne SQL seule) ne peut pas
    exprimer."""

    def __init__(self, by_param: dict[tuple[str, str], list[tuple[Any, ...]]]) -> None:
        self.by_param = by_param
        self.queries: list[tuple[str, dict[str, Any] | None]] = []
        self.raise_on_param: set[str] = set()
        """Valeurs de paramètre (`metric` ou `setting`) sur lesquelles lever
        une exception — simule un échec CIBLÉ d'une seule requête (ex. la
        lecture du ratio RAM échoue mais MemoryResident répond)."""

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> list[tuple[Any, ...]]:
        self.queries.append((sql, parameters))
        param_value = None
        if parameters:
            param_value = parameters.get("metric") or parameters.get("setting")
        if param_value in self.raise_on_param:
            raise RuntimeError(f"echec simule pour parametre {param_value!r}")
        for (table_marker, wanted_param), rows in self.by_param.items():
            if table_marker in sql and param_value == wanted_param:
                return rows
        return []


class TestClickHouseMemoryLimitReadInDirect:
    def test_reads_max_server_memory_usage_when_explicit(self) -> None:
        """max_server_memory_usage > 0 : lu directement, pas calculé."""
        client = ParamRoutedFakeClickHouseClient(
            {
                (
                    "system.server_settings",
                    "max_server_memory_usage",
                ): [(1_932_735_283,)],  # ~1,80 Gio, mesuré sur .6
            }
        )

        limit_bytes, is_computed = fetch_clickhouse_memory_limit(client)

        assert limit_bytes == 1_932_735_283
        assert is_computed is False

    def test_reflects_custom_server_setting_not_hardcoded(self) -> None:
        """MORSURE : une valeur DIFFÉRENTE de celle mesurée sur .6 doit se
        refléter — preuve que la fonction ne retombe jamais sur une
        constante interne."""
        client = ParamRoutedFakeClickHouseClient(
            {
                ("system.server_settings", "max_server_memory_usage"): [(8 * 1024**3,)],
            }
        )

        limit_bytes, is_computed = fetch_clickhouse_memory_limit(client)

        assert limit_bytes == 8 * 1024**3
        assert is_computed is False

    def test_zero_setting_is_computed_from_ram_ratio_not_division_by_zero(self) -> None:
        """PIÈGE EXPLICITE DE LA TÂCHE : max_server_memory_usage=0 ne doit
        JAMAIS produire une division par zéro ni une limite nulle — la
        fonction doit reconstituer la limite effective depuis
        max_server_memory_usage_to_ram_ratio × OSMemoryTotal."""
        ram_total = 16 * 1024**3  # 16 Gio de RAM totale vue par ClickHouse
        ratio = 0.9  # défaut serveur ClickHouse
        client = ParamRoutedFakeClickHouseClient(
            {
                ("system.server_settings", "max_server_memory_usage"): [
                    (0,)
                ],
                ("system.server_settings", "max_server_memory_usage_to_ram_ratio"): [
                    (ratio,)
                ],
                ("system.asynchronous_metrics", "OSMemoryTotal"): [(ram_total,)],
            }
        )

        limit_bytes, is_computed = fetch_clickhouse_memory_limit(client)

        assert limit_bytes == int(ram_total * ratio)
        assert is_computed is True
        assert limit_bytes is not None and limit_bytes > 0  # jamais 0, jamais None ici

    def test_zero_setting_with_unreadable_ratio_returns_none_not_zero(self) -> None:
        """ZÉRO SILENCIEUX : si le ratio RAM est illisible (table absente,
        erreur), la fonction retourne `None` — jamais 0 ni une valeur
        inventée qui produirait un pourcentage absurde."""
        client = ParamRoutedFakeClickHouseClient(
            {
                ("system.server_settings", "max_server_memory_usage"): [
                    (0,)
                ],
                # max_server_memory_usage_to_ram_ratio absent du double : la
                # requête renvoie [] (aucune ligne), simule un réglage introuvable.
            }
        )

        limit_bytes, is_computed = fetch_clickhouse_memory_limit(client)

        assert limit_bytes is None
        assert is_computed is False

    def test_read_failure_propagates_to_caller(self) -> None:
        """`collect_memory_health` est responsable de traduire l'échec en
        état "indéterminé" — `fetch_clickhouse_memory_limit` propage
        l'exception telle quelle, même contrat que `fetch_merge_tree_thresholds`."""
        client = ParamRoutedFakeClickHouseClient({})
        client.raise_on_param = {"max_server_memory_usage"}

        with pytest.raises(RuntimeError):
            fetch_clickhouse_memory_limit(client)


class TestCollectMemoryHealthPicksTheBindingLimit:
    """`collect_memory_health` doit comparer au plafond qui MORD EN PREMIER
    (le plus petit des deux connus), jamais systématiquement à la config."""

    def test_clickhouse_limit_lower_than_config_is_the_binding_one(self) -> None:
        """Reproduit exactement la mesure de la tâche sur .6 : config=2 Gio,
        ClickHouse=1,80 Gio — c'est ClickHouse qui doit décider le %."""
        configured_limit = 2 * 1024**3
        clickhouse_limit = 1_932_735_283  # ~1,80 Gio, mesuré sur .6
        resident = int(1.18 * 1024**3)  # valeur mesurée dans la tâche
        client = ParamRoutedFakeClickHouseClient(
            {
                ("system.asynchronous_metrics", "MemoryResident"): [
                    (resident,)
                ],
                ("system.server_settings", "max_server_memory_usage"): [
                    (clickhouse_limit,)
                ],
            }
        )

        result = collect_memory_health(client, configured_limit)

        assert result.limit_bytes == clickhouse_limit
        assert result.limit_source == "clickhouse"
        assert result.clickhouse_limit_bytes == clickhouse_limit
        assert result.configured_limit_bytes == configured_limit
        # 1,18 / 1,80 ≈ 65% — un pourcentage DIFFÉRENT de celui calculé sur
        # la config (59%) : la preuve que c'est bien ClickHouse qui a mordu.
        assert 63 < result.pct_used < 67

    def test_config_limit_lower_than_clickhouse_is_the_binding_one(self) -> None:
        """Cas inverse : la config (limite Docker connue) est plus stricte
        que ClickHouse — c'est elle qui doit décider."""
        configured_limit = 1 * 1024**3
        clickhouse_limit = 8 * 1024**3
        # Marge de 1 point au-dessus du seuil critique — évite un arrondi
        # flottant à la frontière exacte (même précaution que
        # test_critical_at_pct_matches_measured_container_limit ci-dessus).
        resident = int(configured_limit * ((CRITICAL_MEMORY_PCT + 1) / 100))
        client = ParamRoutedFakeClickHouseClient(
            {
                ("system.asynchronous_metrics", "MemoryResident"): [
                    (resident,)
                ],
                ("system.server_settings", "max_server_memory_usage"): [
                    (clickhouse_limit,)
                ],
            }
        )

        result = collect_memory_health(client, configured_limit)

        assert result.limit_bytes == configured_limit
        assert result.limit_source == "config"
        assert result.state == HealthState.CRITICAL

    def test_clickhouse_limit_unreadable_falls_back_to_config_explicitly(self) -> None:
        """ZÉRO SILENCIEUX : la lecture ClickHouse échoue totalement (table
        absente/erreur) — le repli sur la config est EXPLICITE
        (`clickhouse_limit_unavailable_reason` non vide), jamais présenté
        comme une mesure."""
        configured_limit = 2 * 1024**3
        client = ParamRoutedFakeClickHouseClient({})
        client.raise_on_param = {"max_server_memory_usage"}

        result = collect_memory_health(client, configured_limit)

        assert result.limit_source == "config"
        assert result.clickhouse_limit_bytes is None
        assert result.clickhouse_limit_unavailable_reason != ""
        assert result.limit_bytes == configured_limit

    def test_max_server_memory_usage_zero_uses_computed_limit_not_division_by_zero(self) -> None:
        """max_server_memory_usage=0 côté serveur : le pourcentage doit
        utiliser la limite CALCULÉE (ratio × RAM), jamais planter ni
        produire un pourcentage à partir d'un plafond nul.

        `configured_limit` volontairement PLUS GRAND que la limite calculée
        (14,4 Gio) — sinon c'est la config qui mordrait en premier et le
        test ne prouverait plus rien sur le calcul via ratio."""
        configured_limit = 32 * 1024**3
        ram_total = 16 * 1024**3
        ratio = 0.9
        resident = int(1.0 * 1024**3)
        client = ParamRoutedFakeClickHouseClient(
            {
                ("system.asynchronous_metrics", "MemoryResident"): [
                    (resident,)
                ],
                ("system.server_settings", "max_server_memory_usage"): [
                    (0,)
                ],
                ("system.server_settings", "max_server_memory_usage_to_ram_ratio"): [
                    (ratio,)
                ],
                ("system.asynchronous_metrics", "OSMemoryTotal"): [(ram_total,)],
            }
        )

        result = collect_memory_health(client, configured_limit)

        assert result.limit_source == "clickhouse_computed"
        assert result.clickhouse_limit_is_computed is True
        computed = int(ram_total * ratio)
        assert result.limit_bytes == computed
        assert result.pct_used == pytest.approx(resident / computed * 100)

    def test_both_limits_unavailable_never_produces_absurd_percentage(self) -> None:
        """ZÉRO SILENCIEUX renforcé : même config=0 (déploiement mal
        configuré) et ClickHouse illisible ne doivent jamais lever de
        ZeroDivisionError ni produire un pourcentage absurde — 0.0 explicite."""
        client = ParamRoutedFakeClickHouseClient({})
        client.raise_on_param = {"max_server_memory_usage"}

        result = collect_memory_health(client, configured_limit_bytes=0)

        assert result.limit_bytes == 0
        assert result.pct_used == 0.0

    def test_describe_memory_limit_source_names_clickhouse_when_binding(self) -> None:
        """`describe_memory_limit_source` doit désigner ClickHouse comme
        source, avec sa valeur en octets, quand c'est lui qui mord."""
        configured_limit = 2 * 1024**3
        clickhouse_limit = 1_932_735_283
        client = ParamRoutedFakeClickHouseClient(
            {
                ("system.asynchronous_metrics", "MemoryResident"): [
                    (int(1.18 * 1024**3),)
                ],
                ("system.server_settings", "max_server_memory_usage"): [
                    (clickhouse_limit,)
                ],
            }
        )
        result = collect_memory_health(client, configured_limit)

        description = describe_memory_limit_source(result)

        assert "system.server_settings" in description
        assert str(clickhouse_limit) in description

    def test_describe_memory_limit_source_names_config_as_fallback_when_unavailable(self) -> None:
        """Quand la limite ClickHouse est indéterminée, la description doit
        dire explicitement que c'est un REPLI, pas une mesure."""
        configured_limit = 2 * 1024**3
        client = ParamRoutedFakeClickHouseClient({})
        client.raise_on_param = {"max_server_memory_usage"}
        result = collect_memory_health(client, configured_limit)

        description = describe_memory_limit_source(result)

        assert "INDÉTERMINÉE" in description
        assert str(configured_limit) in description


class TestDetachedPartsThresholdBites:
    def test_healthy_at_zero(self) -> None:
        client = FakeClickHouseClient({"system.detached_parts": [(0, 0)]})
        assert collect_detached_parts(client).state == HealthState.HEALTHY

    def test_warning_at_threshold(self) -> None:
        client = FakeClickHouseClient(
            {"system.detached_parts": [(WARNING_DETACHED_PARTS_COUNT, 1024)]}
        )
        assert collect_detached_parts(client).state == HealthState.WARNING

    def test_critical_at_threshold(self) -> None:
        """SABOTAGE : porte le nombre de parts détachées au seuil critique."""
        client = FakeClickHouseClient(
            {"system.detached_parts": [(CRITICAL_DETACHED_PARTS_COUNT, 1024 * 1024)]}
        )
        assert collect_detached_parts(client).state == HealthState.CRITICAL

    def test_restore_zero_after_purge_is_healthy(self) -> None:
        """RESTAURATION : après une purge (simulée par un nouveau client à
        0), l'état repasse sain."""
        before = FakeClickHouseClient({"system.detached_parts": [(20, 999)]})
        after = FakeClickHouseClient({"system.detached_parts": [(0, 0)]})
        assert collect_detached_parts(before).state == HealthState.CRITICAL
        assert collect_detached_parts(after).state == HealthState.HEALTHY


class TestErrorsOfInterestBites:
    def test_healthy_when_no_error_of_interest(self) -> None:
        client = FakeClickHouseClient({"system.errors": []})
        errors = collect_errors_of_interest(client)
        assert evaluate_errors_state(errors) == HealthState.HEALTHY

    def test_critical_when_too_many_parts_present(self) -> None:
        """SABOTAGE : simule le code d'erreur EXACT correspondant au crash
        décrit par l'utilisateur (accumulation de parts) — DOIT être critique."""
        client = FakeClickHouseClient(
            {"system.errors": [("TOO_MANY_PARTS", 3, "2026-08-08 12:00:00")]}
        )
        errors = collect_errors_of_interest(client)
        assert len(errors) == 1
        assert evaluate_errors_state(errors) == HealthState.CRITICAL

    def test_ignores_error_codes_outside_allowlist(self) -> None:
        """Reproduit les erreurs RÉELLES observées sur .6 (NETWORK_ERROR,
        ABORTED, ...) — aucune n'est dans les 3 codes surveillés, donc aucune
        ne doit apparaître dans le résultat filtré."""
        client = FakeClickHouseClient(
            {
                "system.errors": [
                    ("NETWORK_ERROR", 32, None),
                    ("ABORTED", 11, None),
                    ("SYNTAX_ERROR", 8, None),
                ]
            }
        )
        errors = collect_errors_of_interest(client)
        assert errors == []

    def test_restore_after_error_cleared(self) -> None:
        client_bad = FakeClickHouseClient({"system.errors": [("MEMORY_LIMIT_EXCEEDED", 1, None)]})
        client_ok = FakeClickHouseClient({"system.errors": []})
        assert evaluate_errors_state(collect_errors_of_interest(client_bad)) == HealthState.CRITICAL
        assert evaluate_errors_state(collect_errors_of_interest(client_ok)) == HealthState.HEALTHY


class TestStuckMutationsBites:
    def test_healthy_when_no_stuck_mutation(self) -> None:
        client = FakeClickHouseClient({"system.mutations": []})
        assert evaluate_mutations_state(collect_stuck_mutations(client)) == HealthState.HEALTHY

    def test_critical_when_mutation_has_fail_reason(self) -> None:
        client = FakeClickHouseClient(
            {
                "system.mutations": [
                    (
                        "flows",
                        "mutation_1.txt",
                        "ALTER TABLE flows DELETE WHERE 1",
                        "2026-08-08 10:00:00",
                        "Memory limit exceeded",
                    )
                ]
            }
        )
        stuck = collect_stuck_mutations(client)
        assert len(stuck) == 1
        assert evaluate_mutations_state(stuck) == HealthState.CRITICAL


class TestReplicationDetection:
    def test_single_node_replicas_table_empty_is_not_an_error(self) -> None:
        """Reproduit l'état mesuré sur .6 : system.replicas EXISTE mais est
        VIDE (nœud unique) — ce n'est pas un échec, juste "pas de réplication"."""
        client = FakeClickHouseClient({"system.replicas": [(0,)]})
        assert collect_replication_active(client) is False

    def test_replicas_present_returns_true(self) -> None:
        client = FakeClickHouseClient({"system.replicas": [(3,)]})
        assert collect_replication_active(client) is True

    def test_replicas_query_failure_returns_false_not_an_exception(self) -> None:
        client = FakeClickHouseClient({})
        client.raise_on.add("system.replicas")
        assert collect_replication_active(client) is False


# ---------------------------------------------------------------------------
# ZÉRO SILENCIEUX : une requête en échec produit "indisponible", jamais sain
# ---------------------------------------------------------------------------


class TestZeroSilentOnFailure:
    def test_total_connection_failure_produces_unavailable_snapshot(self) -> None:
        snapshot = build_unavailable_snapshot("connexion refusée (simulée)")

        assert snapshot.overall_state == HealthState.UNAVAILABLE
        assert snapshot.error_message
        assert snapshot.parts_by_table == []

    def test_partial_failure_on_parts_produces_unavailable_for_that_indicator_only(self) -> None:
        """SABOTAGE CIBLÉ : seule la requête system.merge_tree_settings
        échoue (donc collect_parts_health lève) — les AUTRES indicateurs
        doivent rester disponibles, ce n'est pas un échec total."""
        client = FakeClickHouseClient(_default_responses())
        client.raise_on.add("system.merge_tree_settings")

        snapshot = collect_snapshot(client, memory_limit_bytes=2 * 1024**3)

        parts_indicator = next(i for i in snapshot.indicators if i.key == "parts")
        assert parts_indicator.state == HealthState.UNAVAILABLE
        assert parts_indicator.value_label == "indisponible"
        # zéro silencieux : jamais "0 part" qui se confondrait avec une base saine
        assert "0 part" not in parts_indicator.value_label

        # un autre indicateur (mémoire) doit rester lisible malgré cet échec
        memory_indicator = next(i for i in snapshot.indicators if i.key == "memory")
        assert memory_indicator.state != HealthState.UNAVAILABLE

    def test_overall_state_is_unavailable_when_any_indicator_is_unavailable_and_none_critical(
        self,
    ) -> None:
        """Le pire état l'emporte : UNAVAILABLE prime sur HEALTHY (sévérité
        2 > 0) même si tous les autres indicateurs sont sains."""
        client = FakeClickHouseClient(_default_responses())
        client.raise_on.add("system.mutations")

        snapshot = collect_snapshot(client, memory_limit_bytes=2 * 1024**3)

        assert snapshot.overall_state == HealthState.UNAVAILABLE

    def test_overall_state_never_reports_healthy_when_one_indicator_is_critical(self) -> None:
        client = FakeClickHouseClient(_default_responses(delay=50, throw=100, active_parts=109))

        snapshot = collect_snapshot(client, memory_limit_bytes=2 * 1024**3)

        assert snapshot.overall_state == HealthState.CRITICAL

    def test_snapshot_all_healthy_reproduces_measured_state_on_dot6(self) -> None:
        """Reproduit l'état RÉEL mesuré sur .6 (109 parts, seuils 1000/3000,
        aucune erreur, 59% mémoire) — doit être globalement SAIN."""
        client = FakeClickHouseClient(_default_responses(delay=1000, throw=3000, active_parts=109))
        client.responses["system.asynchronous_metrics"] = [(int(1.18 * 1024**3),)]

        snapshot = collect_snapshot(client, memory_limit_bytes=2 * 1024**3)

        assert snapshot.overall_state == HealthState.HEALTHY
        flows_indicator = next(i for i in snapshot.indicators if i.key == "parts.flows")
        assert "109 parts" in flows_indicator.value_label
        assert "1000" in flows_indicator.threshold_label
        assert "3000" in flows_indicator.threshold_label


# ---------------------------------------------------------------------------
# GARDE-FOU CENTRAL : aucun redémarrage de ClickHouse n'est possible
# ---------------------------------------------------------------------------


class TestNoRestartCapabilityExists:
    def test_db_health_service_module_never_imports_a_restart_capability(self) -> None:
        """MORSURE : le module ne doit contenir AUCUN appel à un mécanisme
        de restart de service (client.restart, subprocess, docker, systemctl).

        Exclut les commentaires/docstrings (piège vécu 10 fois sur ce
        projet : un test qui grep un motif interdit échoue sur sa PROPRE
        documentation) — on retire les lignes de commentaire ET les
        triple-quoted strings avant de chercher le motif interdit.
        """
        import ast
        import inspect

        from app.services import db_health as module

        source = inspect.getsource(module)
        tree = ast.parse(source)

        forbidden_names = {"restart", "subprocess", "docker", "systemctl", "Popen"}
        found: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id.lower() in forbidden_names:
                found.append(node.id)
            if isinstance(node, ast.Attribute) and node.attr.lower() in forbidden_names:
                found.append(node.attr)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0].lower() in forbidden_names:
                        found.append(alias.name)
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0].lower() in forbidden_names:
                    found.append(node.module)

        assert not found, (
            f"capacite de redemarrage detectee dans app.services.db_health: {found} "
            "— ce module ne doit JAMAIS pouvoir redemarrer ClickHouse."
        )

    def test_db_health_router_never_imports_a_restart_capability(self) -> None:
        import ast
        import inspect

        from app.routers import db_health as module

        source = inspect.getsource(module)
        tree = ast.parse(source)

        forbidden_names = {"restart", "subprocess", "docker", "systemctl", "Popen"}
        found: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id.lower() in forbidden_names:
                found.append(node.id)
            if isinstance(node, ast.Attribute) and node.attr.lower() in forbidden_names:
                found.append(node.attr)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0].lower() in forbidden_names:
                        found.append(alias.name)
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0].lower() in forbidden_names:
                    found.append(node.module)

        assert not found, (
            f"capacite de redemarrage detectee dans app.routers.db_health: {found} "
            "— ce routeur ne doit JAMAIS pouvoir redemarrer ClickHouse."
        )

    def test_optimize_table_only_ever_issues_optimize_sql_never_a_restart(self) -> None:
        client = FakeClickHouseClient(_default_responses())

        sql = optimize_table(client, "flows", final=False)

        assert sql.startswith("OPTIMIZE TABLE")
        assert "RESTART" not in sql.upper()
        assert "SYSTEM SHUTDOWN" not in sql.upper()
        assert "SYSTEM KILL" not in sql.upper()


# ---------------------------------------------------------------------------
# Actions destructives — jamais sans demande explicite (preview/execute)
# ---------------------------------------------------------------------------


class TestOptimizeTableSafety:
    def test_optimize_table_rejects_table_outside_allowlist(self) -> None:
        client = FakeClickHouseClient(_default_responses())

        with pytest.raises(ValueError, match="allowlist"):
            optimize_table(client, "system; DROP TABLE flows", final=False)

        assert client.queries == []  # AUCUNE requête exécutée avant la validation

    def test_optimize_table_final_false_builds_plain_sql(self) -> None:
        client = FakeClickHouseClient(_default_responses())
        sql = optimize_table(client, "flows", final=False)
        assert sql == "OPTIMIZE TABLE default.flows"

    def test_optimize_table_final_true_builds_final_sql(self) -> None:
        client = FakeClickHouseClient(_default_responses())
        sql = optimize_table(client, "flows", final=True)
        assert sql == "OPTIMIZE TABLE default.flows FINAL"

    def test_optimize_table_never_executes_for_unmonitored_table(self) -> None:
        client = FakeClickHouseClient(_default_responses())
        for table in ("exporters", "system", "audit_log"):
            if table in MONITORED_TABLES:
                continue
            with pytest.raises(ValueError):
                optimize_table(client, table, final=False)
        assert client.queries == []


class TestDetachedPartsPurgeSafety:
    def test_preview_never_deletes_anything(self) -> None:
        """MORSURE : preview_detached_parts_purge ne doit exécuter aucun DDL
        de suppression — seulement un SELECT."""
        client = FakeClickHouseClient({"system.detached_parts": [(5, 1024)]})

        result = preview_detached_parts_purge(client)

        assert result.count == 5
        assert all("DROP" not in q.upper() and "DELETE" not in q.upper() for q, _ in client.queries)

    def test_execute_rejects_table_outside_allowlist(self) -> None:
        client = FakeClickHouseClient({"system.detached_parts": [(5, 1024)]})

        with pytest.raises(ValueError, match="allowlist"):
            execute_detached_parts_purge(client, "not_a_real_table")

    def test_execute_issues_drop_detached_partition_all_only_for_allowed_table(self) -> None:
        client = FakeClickHouseClient({"system.detached_parts": [(3, 512)]})

        count_before = execute_detached_parts_purge(client, "flows")

        assert count_before == 3
        drop_queries = [q for q, _ in client.queries if "DROP DETACHED" in q]
        assert len(drop_queries) == 1
        assert "default.flows" in drop_queries[0]


# ---------------------------------------------------------------------------
# Purge COMPLÈTE (tables de flux + tables système) — défaut mesuré 2026-08-09
#
# Reproduit le cas réel : 46 parts détachées annoncées (18 sur les tables de
# flux `default.*`, 28 sur des tables système `system.*`), toutes
# `broken-on-start` à 0 octet.
# ---------------------------------------------------------------------------


def _group_by_response_46_parts() -> list[tuple[Any, ...]]:
    """Reproduit le mélange réel : 18 parts sur `default.flows` (tables de
    flux) + 28 réparties sur 8 tables système — toutes `broken-on-start`,
    0 octet (fragments vides laissés par un crash brutal)."""
    system_tables_28 = list(SYSTEM_LOG_TABLES)
    # Répartit 28 parts sur les 8 tables système, au moins 1 chacune.
    counts = [4, 4, 4, 4, 3, 3, 3, 3]
    assert sum(counts) == 28
    assert len(counts) == len(system_tables_28)
    rows = [("default", "flows", "broken-on-start", 18, 0)]
    for table, count in zip(system_tables_28, counts, strict=True):
        rows.append(("system", table, "broken-on-start", count, 0))
    return rows


def _client_with_46_detached_parts(*, extra_responses: dict[str, Any] | None = None) -> Any:
    responses = {
        "system.detached_parts": [(46, 0)],
        "system.detached_parts GROUP BY database, table, reason": _group_by_response_46_parts(),
    }
    if extra_responses:
        responses.update(extra_responses)
    return FakeClickHouseClient(responses)


class TestValidateDetachedPartsTarget:
    """Garde sécu n°1 : validation avant toute interpolation SQL."""

    def test_accepts_default_flows(self) -> None:
        assert validate_detached_parts_target("default", "flows") == ("default", "flows")

    def test_accepts_system_query_log(self) -> None:
        assert validate_detached_parts_target("system", "query_log") == ("system", "query_log")

    def test_rejects_table_outside_both_allowlists(self) -> None:
        with pytest.raises(ValueError, match="allowlist"):
            validate_detached_parts_target("system", "not_a_real_system_table")

    def test_rejects_unknown_database(self) -> None:
        """MORSURE : une base ni `default` ni `system` doit être refusée,
        même si le nom de table est par ailleurs dans une allowlist."""
        with pytest.raises(ValueError, match="allowlist"):
            validate_detached_parts_target("evil_db", "flows")

    def test_rejects_table_valid_in_wrong_database(self) -> None:
        """MORSURE : `query_log` existe dans `system` mais pas `default` —
        le couple doit être refusé même si chaque nom, pris seul, existe
        quelque part dans une des deux allowlists."""
        with pytest.raises(ValueError, match="allowlist"):
            validate_detached_parts_target("default", "query_log")

    def test_rejects_sql_metacharacters_before_even_checking_allowlist(self) -> None:
        """MORSURE SÉCU : tentative d'injection via le nom de table — DOIT
        être rejetée par le pattern, jamais atteindre la comparaison
        d'allowlist (et a fortiori jamais le SQL)."""
        with pytest.raises(ValueError, match="pattern"):
            validate_detached_parts_target("default", "flows; DROP TABLE flows--")

    def test_rejects_sql_metacharacters_in_database_name(self) -> None:
        with pytest.raises(ValueError, match="pattern"):
            validate_detached_parts_target("default; DROP TABLE flows--", "flows")


class TestDetachedPartsCollectExposesReasonAndSize:
    def test_collect_detached_parts_exposes_by_group_with_reason_and_bytes(self) -> None:
        """PREUVE demandée par la tâche : l'écran doit pouvoir afficher la
        RAISON et la TAILLE, pas seulement le compte."""
        client = _client_with_46_detached_parts()

        result = collect_detached_parts(client)

        assert result.count == 46
        assert len(result.by_group) == 9  # flows + 8 tables système
        flows_group = next(g for g in result.by_group if g.table == "flows")
        assert flows_group.database == "default"
        assert flows_group.reason == "broken-on-start"
        assert flows_group.count == 18
        assert flows_group.bytes_on_disk == 0

    def test_by_group_empty_when_no_group_fixture_provided(self) -> None:
        """Rétro-compatibilité : un double de test qui ne fournit que le
        comptage global (ancienne convention) reçoit un `by_group` vide,
        jamais une erreur."""
        client = FakeClickHouseClient({"system.detached_parts": [(0, 0)]})

        result = collect_detached_parts(client)

        assert result.count == 0
        assert result.by_group == []


class TestDetachedPartsPurgeAllCoversSystemTables:
    """Le défaut central de la tâche : 46 annoncées, seules 18 réparables
    (tables de flux) — ces tests prouvent que la purge complète couvre
    désormais les 46, tables système incluses."""

    def test_preview_all_lists_both_flow_and_system_tables(self) -> None:
        client = _client_with_46_detached_parts()

        preview = preview_detached_parts_purge_all(client)

        assert preview.detail.count == 46
        assert ("default", "flows") in preview.targets
        for table in SYSTEM_LOG_TABLES:
            assert ("system", table) in preview.targets
        assert len(preview.targets) == 1 + len(SYSTEM_LOG_TABLES)  # 9 tables

    def test_preview_all_never_deletes_anything(self) -> None:
        client = _client_with_46_detached_parts()

        preview_detached_parts_purge_all(client)

        assert all(
            "DROP" not in q.upper() and "DELETE" not in q.upper() for q, _ in client.queries
        )

    def test_execute_all_purges_every_table_including_system_ones(self) -> None:
        client = _client_with_46_detached_parts()
        preview = preview_detached_parts_purge_all(client)

        result = execute_detached_parts_purge_all(client, preview)

        assert result.is_complete
        assert result.failures == []
        assert "default.flows" in result.purged_tables
        for table in SYSTEM_LOG_TABLES:
            assert f"system.{table}" in result.purged_tables
        assert len(result.purged_tables) == 9  # les 46 parts, sur 9 tables, TOUTES couvertes
        assert result.parts_before == 46

    def test_execute_all_issues_alter_table_drop_detached_for_system_tables(self) -> None:
        client = _client_with_46_detached_parts()
        preview = preview_detached_parts_purge_all(client)

        execute_detached_parts_purge_all(client, preview)

        drop_queries = [q for q, _ in client.queries if "DROP DETACHED" in q]
        assert any("system.query_log" in q for q in drop_queries)
        assert any("system.part_log" in q for q in drop_queries)
        assert any("default.flows" in q for q in drop_queries)

    def test_execute_all_rejects_table_outside_allowlist_even_inside_a_preview_object(
        self,
    ) -> None:
        """MORSURE — défense en profondeur : un `preview` construit à la main
        (pas via `preview_detached_parts_purge_all`) avec une cible hors
        allowlist doit être refusé À L'EXÉCUTION, jamais exécuté aveuglément."""
        from app.models import DetachedPartsHealth

        client = _client_with_46_detached_parts()
        forged_preview = DetachedPartsPurgeAllPreview(
            targets=[("system", "not_a_real_table"), ("default", "flows")],
            detail=DetachedPartsHealth(count=46, total_bytes=0, state=HealthState.CRITICAL),
        )

        result = execute_detached_parts_purge_all(client, forged_preview)

        assert "default.flows" in result.purged_tables  # la cible valide est quand même purgee
        assert len(result.failures) == 1
        assert "not_a_real_table" in result.failures[0]
        drop_queries = [q for q, _ in client.queries if "DROP DETACHED" in q]
        assert all("not_a_real_table" not in q for q in drop_queries)  # AUCUNE requete emise


class TestDetachedPartsPurgeAllAntiToctou:
    """L'aperçu avant exécution doit rester la règle — l'exécution supprime
    exactement ce que l'aperçu a montré, jamais un nouveau scan (même
    contrat que `app.services.purge`, cf. tâche)."""

    def test_execute_all_only_touches_targets_from_the_given_preview(self) -> None:
        """MORSURE anti-TOCTOU : un preview construit avec UNE SEULE cible
        ne doit purger QUE cette cible, même si `system.detached_parts`
        (interrogé séparément) contiendrait davantage de tables au moment de
        l'exécution — l'exécution ne re-scanne JAMAIS."""
        from app.models import DetachedPartsHealth

        # Le client "voit" toujours les 46 parts sur 9 tables si on
        # l'interroge — mais le preview donné à l'exécution n'en liste
        # qu'UNE seule : seule celle-là doit être purgée.
        client = _client_with_46_detached_parts()
        narrow_preview = DetachedPartsPurgeAllPreview(
            targets=[("default", "flows")],
            detail=DetachedPartsHealth(count=18, total_bytes=0, state=HealthState.CRITICAL),
        )

        result = execute_detached_parts_purge_all(client, narrow_preview)

        assert result.purged_tables == ["default.flows"]
        drop_queries = [q for q, _ in client.queries if "DROP DETACHED" in q]
        assert len(drop_queries) == 1
        assert "default.flows" in drop_queries[0]
        # aucune des 8 tables systeme n'a ete touchee, bien que le compte
        # global de detached_parts en montre 46
        for table in SYSTEM_LOG_TABLES:
            assert all(table not in q for q in drop_queries)


class TestDetachedPartsPurgeAllZeroSilentPartialFailure:
    """ZÉRO SILENCIEUX : une purge échouant sur une table ne doit jamais
    produire un succès global trompeur."""

    def test_partial_failure_on_one_system_table_is_reported_distinctly(self) -> None:
        """SABOTAGE CIBLÉ : `system.query_log` échoue au DROP, tout le reste
        réussit — DOIT produire `is_complete=False` et lister l'échec, pas
        un `purged_tables` qui masquerait l'échec."""
        client = _client_with_46_detached_parts()
        client.raise_on.add("ALTER TABLE system.query_log")
        preview = preview_detached_parts_purge_all(client)

        result = execute_detached_parts_purge_all(client, preview)

        assert result.is_complete is False
        assert any("query_log" in f for f in result.failures)
        # les 8 AUTRES tables ont quand meme ete purgees malgre l'echec d'une seule
        assert len(result.purged_tables) == 8
        assert "default.flows" in result.purged_tables

    def test_all_tables_failing_produces_empty_purged_and_full_failures(self) -> None:
        client = _client_with_46_detached_parts()
        client.raise_on.add("ALTER TABLE")  # toute execution DROP echoue
        preview = preview_detached_parts_purge_all(client)

        result = execute_detached_parts_purge_all(client, preview)

        assert result.purged_tables == []
        assert result.is_complete is False
        assert len(result.failures) == 9


# ---------------------------------------------------------------------------
# Router — TestClient avec client ClickHouse mocké
# ---------------------------------------------------------------------------


def _memory_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _make_app_with_fake_client(
    client: FakeClickHouseClient,
    *,
    conn: sqlite3.Connection | None = None,
    memory_limit_bytes: int = 2 * 1024**3,
) -> TestClient:
    from app.routers import db_health as db_health_router

    app = FastAPI()
    app.dependency_overrides[db_health_router.get_clickhouse_client] = lambda: client
    app.dependency_overrides[db_health_router.get_db_connection] = lambda: (
        conn if conn is not None else _memory_conn()
    )
    app.dependency_overrides[db_health_router.get_memory_limit_bytes] = lambda: memory_limit_bytes
    app.include_router(db_health_router.router)
    return TestClient(app)


class TestDbHealthRouter:
    def test_get_page_returns_html(self) -> None:
        client = FakeClickHouseClient(_default_responses())
        http_client = _make_app_with_fake_client(client)

        response = http_client.get("/db-health")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_get_page_displays_real_measured_values(self) -> None:
        """PREUVE demandée par la tâche : l'écran affiche les vrais chiffres
        (109 parts, seuils 1000/3000, 59% de mémoire)."""
        client = FakeClickHouseClient(_default_responses(delay=1000, throw=3000, active_parts=109))
        client.responses["system.asynchronous_metrics"] = [(int(1.18 * 1024**3),)]
        http_client = _make_app_with_fake_client(client)

        response = http_client.get("/db-health")

        assert response.status_code == 200
        body = response.text
        assert "109" in body
        assert "1000" in body
        assert "3000" in body

    def test_get_page_displays_both_memory_limits_and_which_one_binds(self) -> None:
        """DEMANDE UTILISATEUR (2026-08-09) : « il faut afficher une info
        compréhensible et claire sur la partie mémoire » — l'écran doit
        montrer LES DEUX plafonds (ClickHouse ET config) et dire lequel mord
        en premier, jamais une seule valeur sans origine."""
        client = FakeClickHouseClient(_default_responses())
        client.responses["system.asynchronous_metrics"] = [(int(1.18 * 1024**3),)]
        # SELECT value FROM system.server_settings WHERE name = ... : UNE
        # SEULE colonne (la valeur) — même format que la vraie requête.
        client.responses["system.server_settings"] = [(1_932_735_283,)]
        http_client = _make_app_with_fake_client(client, memory_limit_bytes=2 * 1024**3)

        response = http_client.get("/db-health")

        assert response.status_code == 200
        body = response.text
        # Les deux sources sont nommées explicitement, pas seulement un chiffre nu.
        assert "max_server_memory_usage" in body
        assert "OKVORADO_DB_HEALTH_MEMORY_LIMIT_BYTES" in body
        assert "system.server_settings" in body
        # La valeur ClickHouse (1,80 Gio) doit être RÉSOLUE, pas "indéterminée" :
        # preuve que la lecture en direct a fonctionné, pas juste le libellé statique.
        assert "indéterminée" not in body
        assert "1.8 Go" in body
        # La phrase de synthèse dit que c'est ClickHouse qui mord ici (1,80 Gio < 2 Gio).
        assert "limite ClickHouse</strong>" in body

    def test_get_page_shows_indeterminate_when_clickhouse_limit_unreadable(self) -> None:
        """ZÉRO SILENCIEUX à l'écran : si la limite ClickHouse ne peut pas
        être lue, la page dit explicitement « indéterminée », jamais un
        pourcentage calculé sur la config sans le signaler."""
        client = FakeClickHouseClient(_default_responses())
        client.responses["system.asynchronous_metrics"] = [(int(1.18 * 1024**3),)]
        client.raise_on = {"system.server_settings"}
        http_client = _make_app_with_fake_client(client, memory_limit_bytes=2 * 1024**3)

        response = http_client.get("/db-health")

        assert response.status_code == 200
        body = response.text
        assert "indéterminée" in body or "indéterminé" in body.lower()

    def test_api_get_db_health_returns_json_snapshot(self) -> None:
        client = FakeClickHouseClient(_default_responses())
        http_client = _make_app_with_fake_client(client)

        response = http_client.get("/api/db-health")

        assert response.status_code == 200
        payload = response.json()
        assert "overall_state" in payload
        assert "indicators" in payload

    def test_api_get_db_health_returns_unavailable_when_clickhouse_fails_entirely(self) -> None:
        """ZÉRO SILENCIEUX au niveau HTTP : une panne totale de la première
        requête doit produire overall_state=unavailable, jamais un 200 avec
        un état sain trompeur."""
        client = FakeClickHouseClient()
        client.raise_on.add("system.merge_tree_settings")
        client.raise_on.add("system.part_log")
        client.raise_on.add("system.errors")
        client.raise_on.add("system.mutations")
        client.raise_on.add("system.detached_parts")
        client.raise_on.add("system.asynchronous_metrics")
        client.raise_on.add("system.replicas")
        http_client = _make_app_with_fake_client(client)

        response = http_client.get("/api/db-health")

        assert response.status_code == 200  # la requête HTTP réussit...
        payload = response.json()
        assert payload["overall_state"] == "unavailable"  # ...mais l'état est explicite

    def test_optimize_preview_never_calls_execute_sql(self) -> None:
        client = FakeClickHouseClient(_default_responses())
        http_client = _make_app_with_fake_client(client)

        response = http_client.post("/api/db-health/optimize/preview", json={"table": "flows"})

        assert response.status_code == 200
        payload = response.json()
        assert payload["executed"] is False
        assert all("OPTIMIZE" not in q for q, _ in client.queries)

    def test_optimize_preview_rejects_table_outside_allowlist(self) -> None:
        client = FakeClickHouseClient(_default_responses())
        http_client = _make_app_with_fake_client(client)

        response = http_client.post(
            "/api/db-health/optimize/preview", json={"table": "not_monitored"}
        )

        assert response.status_code == 422  # rejet Pydantic (field_validator)

    def test_optimize_execute_requires_explicit_post_and_records_audit(self) -> None:
        conn = _memory_conn()
        client = FakeClickHouseClient(_default_responses())
        http_client = _make_app_with_fake_client(client, conn=conn)

        response = http_client.post(
            "/api/db-health/optimize/execute", json={"table": "flows", "final": False}
        )

        assert response.status_code == 200
        assert any("OPTIMIZE TABLE default.flows" in q for q, _ in client.queries)
        audit_rows = conn.execute(
            "SELECT action, detail FROM audit_log WHERE action = 'db_health_optimize'"
        ).fetchall()
        assert len(audit_rows) == 1

    def test_optimize_execute_rejects_table_outside_allowlist_without_any_query(self) -> None:
        client = FakeClickHouseClient(_default_responses())
        http_client = _make_app_with_fake_client(client)

        response = http_client.post(
            "/api/db-health/optimize/execute", json={"table": "not_monitored"}
        )

        assert response.status_code == 422
        assert client.queries == []

    def test_detached_parts_preview_get_never_deletes(self) -> None:
        client = FakeClickHouseClient({"system.detached_parts": [(4, 2048)]})
        http_client = _make_app_with_fake_client(client)

        response = http_client.get("/api/db-health/detached-parts/preview")

        assert response.status_code == 200
        assert response.json()["count"] == 4
        assert all("DROP" not in q.upper() for q, _ in client.queries)

    def test_detached_parts_execute_requires_explicit_post_and_records_audit(self) -> None:
        conn = _memory_conn()
        client = FakeClickHouseClient({"system.detached_parts": [(4, 2048)]})
        http_client = _make_app_with_fake_client(client, conn=conn)

        response = http_client.post(
            "/api/db-health/detached-parts/execute", json={"table": "flows"}
        )

        assert response.status_code == 200
        assert any("DROP DETACHED" in q for q, _ in client.queries)
        audit_rows = conn.execute(
            "SELECT action FROM audit_log WHERE action = 'db_health_purge_detached_parts'"
        ).fetchall()
        assert len(audit_rows) == 1

    def test_preview_all_api_call_returns_json_with_targets_and_by_group(self) -> None:
        """Appel API direct (pas de header HX-Request) : JSON brut."""
        client = _client_with_46_detached_parts()
        http_client = _make_app_with_fake_client(client)

        response = http_client.get("/api/db-health/detached-parts/preview-all")

        assert response.status_code == 200
        payload = response.json()
        assert payload["preview"]["detail"]["count"] == 46
        assert len(payload["preview"]["targets"]) == 9
        assert len(payload["preview"]["detail"]["by_group"]) == 9

    def test_preview_all_htmx_call_returns_html_fragment_with_hidden_preview_json(self) -> None:
        """Appel HTMX (header HX-Request) : fragment HTML embarquant le
        preview dans un champ caché — c'est ce que /execute-all exige
        (contrat anti-TOCTOU, pas de JS custom autorisé par la CSP)."""
        client = _client_with_46_detached_parts()
        http_client = _make_app_with_fake_client(client)

        response = http_client.get(
            "/api/db-health/detached-parts/preview-all", headers={"HX-Request": "true"}
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        body = response.text
        assert "input" in body and "hidden" in body
        assert "preview" in body
        assert "broken-on-start" in body  # raison exposee a l'ecran

    def test_preview_all_never_deletes_anything_at_http_level(self) -> None:
        client = _client_with_46_detached_parts()
        http_client = _make_app_with_fake_client(client)

        http_client.get("/api/db-health/detached-parts/preview-all")

        assert all("DROP" not in q.upper() for q, _ in client.queries)

    def test_execute_all_purges_exactly_what_preview_announced_and_records_audit(self) -> None:
        """PREUVE bout-en-bout : preview -> execute couvre les 46 parts
        (tables de flux + systeme), pas seulement 18."""
        conn = _memory_conn()
        client = _client_with_46_detached_parts()
        http_client = _make_app_with_fake_client(client, conn=conn)

        preview_response = http_client.get("/api/db-health/detached-parts/preview-all")
        preview_payload = preview_response.json()["preview"]

        execute_response = http_client.post(
            "/api/db-health/detached-parts/execute-all", json={"preview": preview_payload}
        )

        assert execute_response.status_code == 200
        result = execute_response.json()
        assert result["is_complete"] is True
        assert result["failures"] == []
        assert len(result["purged_tables"]) == 9
        assert result["parts_before"] == 46
        drop_queries = [q for q, _ in client.queries if "DROP DETACHED" in q]
        assert len(drop_queries) == 9
        assert any("system.query_log" in q for q in drop_queries)

        audit_rows = conn.execute(
            "SELECT action, detail FROM audit_log "
            "WHERE action = 'db_health_purge_detached_parts_all'"
        ).fetchall()
        assert len(audit_rows) == 1

    def test_execute_all_rejects_target_outside_allowlist_from_a_hand_crafted_body(self) -> None:
        """MORSURE sécu HTTP : un corps de requête forgé à la main (pas issu
        d'un vrai preview) avec une cible hors allowlist ne doit PAS être
        exécuté aveuglément — la garde de service revalide et rapporte
        l'échec, sans jamais interpoler ce nom dans le SQL."""
        client = _client_with_46_detached_parts()
        http_client = _make_app_with_fake_client(client)
        forged_preview = {
            "targets": [["system", "not_a_real_table"]],
            "detail": {"count": 1, "total_bytes": 0, "state": "critical", "by_group": []},
        }

        response = http_client.post(
            "/api/db-health/detached-parts/execute-all", json={"preview": forged_preview}
        )

        assert response.status_code == 200  # la requete HTTP reussit...
        payload = response.json()
        assert payload["is_complete"] is False  # ...mais rien n'a ete purge silencieusement
        assert len(payload["failures"]) == 1
        drop_queries = [q for q, _ in client.queries if "DROP DETACHED" in q]
        assert all("not_a_real_table" not in q for q in drop_queries)

    def test_execute_all_rejects_empty_targets(self) -> None:
        client = _client_with_46_detached_parts()
        http_client = _make_app_with_fake_client(client)
        empty_preview = {
            "targets": [],
            "detail": {"count": 0, "total_bytes": 0, "state": "healthy", "by_group": []},
        }

        response = http_client.post(
            "/api/db-health/detached-parts/execute-all", json={"preview": empty_preview}
        )

        assert response.status_code == 400
        assert all("DROP" not in q.upper() for q, _ in client.queries)

    def test_execute_all_partial_failure_returns_distinct_state_not_a_trompeur_200_success(
        self,
    ) -> None:
        """ZÉRO SILENCIEUX au niveau HTTP : un échec partiel doit rester
        visible dans le payload JSON, jamais masqué par status=ok seul."""
        conn = _memory_conn()
        client = _client_with_46_detached_parts()
        client.raise_on.add("ALTER TABLE system.part_log")
        http_client = _make_app_with_fake_client(client, conn=conn)

        preview_response = http_client.get("/api/db-health/detached-parts/preview-all")
        preview_payload = preview_response.json()["preview"]

        response = http_client.post(
            "/api/db-health/detached-parts/execute-all", json={"preview": preview_payload}
        )

        assert response.status_code == 200
        payload = response.json()
        assert payload["is_complete"] is False
        assert any("part_log" in f for f in payload["failures"])
        assert len(payload["purged_tables"]) == 8  # les 8 autres tables restent purgees

    def test_db_health_page_displays_reason_and_size_for_detached_parts(self) -> None:
        """PREUVE demandée par la tâche : l'écran affiche la RAISON
        (broken-on-start) et la TAILLE, pas seulement le compte de 46."""
        client = _client_with_46_detached_parts()
        http_client = _make_app_with_fake_client(client)

        response = http_client.get("/db-health")

        assert response.status_code == 200
        body = response.text
        assert "broken-on-start" in body
        assert "query_log" in body  # une table systeme est bien listee a l'ecran
        assert "46" in body

    def test_no_route_of_this_router_can_trigger_a_clickhouse_restart(self) -> None:
        """MORSURE au niveau HTTP : aucune route ne doit exister avec un nom
        évoquant un restart — inventaire des routes déclarées."""
        from app.routers import db_health as db_health_router

        paths = {route.path for route in db_health_router.router.routes}  # type: ignore[attr-defined]
        for path in paths:
            assert "restart" not in path.lower()
            assert "shutdown" not in path.lower()

    def test_history_endpoint_returns_persisted_snapshots(self) -> None:
        conn = _memory_conn()
        conn.execute(
            "INSERT INTO db_health_history (checked_at, overall_state, snapshot_json) "
            "VALUES (?, ?, ?)",
            ("2026-08-08T10:00:00", "healthy", '{"overall_state": "healthy"}'),
        )
        conn.commit()
        client = FakeClickHouseClient(_default_responses())
        http_client = _make_app_with_fake_client(client, conn=conn)

        response = http_client.get("/api/db-health/history")

        assert response.status_code == 200
        payload = response.json()
        assert payload["total"] == 1
        assert payload["items"][0]["overall_state"] == "healthy"

    def test_history_read_failure_returns_empty_list_not_an_exception(self) -> None:
        """ZÉRO SILENCIEUX inversé : un échec de lecture d'historique ne doit
        jamais faire planter l'écran — dégradation explicite (liste vide),
        journalisée (vérifié par la simple absence d'exception ici)."""
        conn = _memory_conn()
        conn.execute("DROP TABLE db_health_history")
        client = FakeClickHouseClient(_default_responses())
        http_client = _make_app_with_fake_client(client, conn=conn)

        response = http_client.get("/api/db-health/history")

        assert response.status_code == 200
        assert response.json()["items"] == []


# ---------------------------------------------------------------------------
# Historique persisté — db_health_history (app.db.SCHEMA)
# ---------------------------------------------------------------------------


class TestDbHealthHistorySchema:
    def test_schema_creates_db_health_history_table(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.executescript(SCHEMA)

        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert "db_health_history" in tables

    def test_history_table_records_overall_state_and_snapshot_json(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.executescript(SCHEMA)

        conn.execute(
            "INSERT INTO db_health_history (overall_state, snapshot_json) VALUES (?, ?)",
            ("critical", '{"overall_state": "critical"}'),
        )
        conn.commit()

        row = conn.execute("SELECT overall_state, snapshot_json FROM db_health_history").fetchone()
        assert row[0] == "critical"
        assert "critical" in row[1]


# ---------------------------------------------------------------------------
# DÉFAUT MESURÉ (2026-08-09) : du JSON brut s'affichait à l'écran sur un
# appel HTMX — ces tests couvrent les 5 routes de ce routeur qui appellent
# désormais un fragment HTML lisible côté HTMX, tout en gardant le JSON
# inchangé côté API directe (aucun header HX-Request).
# ---------------------------------------------------------------------------


class TestDbHealthActionsHtmxFragments:
    def test_optimize_preview_api_call_still_returns_json(self) -> None:
        client = FakeClickHouseClient(_default_responses())
        http_client = _make_app_with_fake_client(client)

        response = http_client.post("/api/db-health/optimize/preview", json={"table": "flows"})

        assert "application/json" in response.headers["content-type"]
        assert response.json()["status"] == "ok"

    def test_optimize_preview_htmx_call_returns_html_never_raw_json(self) -> None:
        client = FakeClickHouseClient(_default_responses())
        http_client = _make_app_with_fake_client(client)

        response = http_client.post(
            "/api/db-health/optimize/preview",
            json={"table": "flows", "final": True},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        body = response.text
        assert '"status"' not in body  # jamais de clé JSON brute visible
        assert "flows" in body
        assert "OPTIMIZE TABLE default.flows FINAL" in body

    def test_optimize_execute_htmx_call_returns_html_never_raw_json(self) -> None:
        conn = _memory_conn()
        client = FakeClickHouseClient(_default_responses())
        http_client = _make_app_with_fake_client(client, conn=conn)

        response = http_client.post(
            "/api/db-health/optimize/execute",
            json={"table": "flows", "final": False},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        body = response.text
        assert '"status"' not in body
        assert "OPTIMIZE" in body

    def test_optimize_execute_api_call_still_returns_json(self) -> None:
        conn = _memory_conn()
        client = FakeClickHouseClient(_default_responses())
        http_client = _make_app_with_fake_client(client, conn=conn)

        response = http_client.post(
            "/api/db-health/optimize/execute", json={"table": "flows", "final": False}
        )

        assert "application/json" in response.headers["content-type"]
        assert response.json()["status"] == "ok"

    def test_detached_preview_htmx_call_returns_html_never_raw_json(self) -> None:
        client = FakeClickHouseClient({"system.detached_parts": [(4, 2048)]})
        http_client = _make_app_with_fake_client(client)

        response = http_client.get(
            "/api/db-health/detached-parts/preview", headers={"HX-Request": "true"}
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert '"status"' not in response.text

    def test_detached_preview_api_call_still_returns_json(self) -> None:
        client = FakeClickHouseClient({"system.detached_parts": [(4, 2048)]})
        http_client = _make_app_with_fake_client(client)

        response = http_client.get("/api/db-health/detached-parts/preview")

        assert "application/json" in response.headers["content-type"]
        assert response.json()["count"] == 4

    def test_detached_execute_htmx_call_returns_html_never_raw_json(self) -> None:
        conn = _memory_conn()
        client = FakeClickHouseClient({"system.detached_parts": [(4, 2048)]})
        http_client = _make_app_with_fake_client(client, conn=conn)

        response = http_client.post(
            "/api/db-health/detached-parts/execute",
            json={"table": "flows"},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert '"status"' not in response.text

    def test_detached_execute_api_call_still_returns_json(self) -> None:
        conn = _memory_conn()
        client = FakeClickHouseClient({"system.detached_parts": [(4, 2048)]})
        http_client = _make_app_with_fake_client(client, conn=conn)

        response = http_client.post(
            "/api/db-health/detached-parts/execute", json={"table": "flows"}
        )

        assert "application/json" in response.headers["content-type"]
        assert response.json()["status"] == "ok"

    def test_execute_all_htmx_call_returns_html_never_raw_json(self) -> None:
        conn = _memory_conn()
        client = _client_with_46_detached_parts()
        http_client = _make_app_with_fake_client(client, conn=conn)

        preview_payload = http_client.get(
            "/api/db-health/detached-parts/preview-all"
        ).json()["preview"]

        response = http_client.post(
            "/api/db-health/detached-parts/execute-all",
            json={"preview": preview_payload},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        body = response.text
        assert '"status"' not in body
        assert "purg" in body.lower()

    def test_execute_all_api_call_still_returns_json(self) -> None:
        conn = _memory_conn()
        client = _client_with_46_detached_parts()
        http_client = _make_app_with_fake_client(client, conn=conn)

        preview_payload = http_client.get(
            "/api/db-health/detached-parts/preview-all"
        ).json()["preview"]

        response = http_client.post(
            "/api/db-health/detached-parts/execute-all", json={"preview": preview_payload}
        )

        assert "application/json" in response.headers["content-type"]
        assert response.json()["status"] == "ok"

    def test_execute_all_htmx_partial_failure_shows_failures_in_html(self) -> None:
        """ZÉRO SILENCIEUX côté fragment HTML aussi : un échec partiel doit
        rester visible dans le rendu, pas seulement dans le JSON."""
        conn = _memory_conn()
        client = _client_with_46_detached_parts()
        client.raise_on.add("ALTER TABLE system.part_log")
        http_client = _make_app_with_fake_client(client, conn=conn)

        preview_payload = http_client.get(
            "/api/db-health/detached-parts/preview-all"
        ).json()["preview"]

        response = http_client.post(
            "/api/db-health/detached-parts/execute-all",
            json={"preview": preview_payload},
            headers={"HX-Request": "true"},
        )

        assert response.status_code == 200
        body = response.text
        assert "part_log" in body
        assert '"status"' not in body
