"""Contrats de données partagés entre tous les lots.

SOURCE DE VÉRITÉ — ce module ne doit être modifié par aucun lot fonctionnel.
Voir CONTRACT.md pour la spécification complète.
"""

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, computed_field

TrendState = Literal["rising", "flat", "unknown"]
"""État de la tendance d'un compteur cumulatif (rejets à l'ingestion).

Trois valeurs FERMÉES, jamais un delta implicite (CLAUDE.md règle n°2, zéro
silencieux) :
  - "rising" : le compteur a grimpé depuis le point de comparaison — incident
    ACTIF, exige une action maintenant.
  - "flat"   : aucune variation depuis le point de comparaison — cumul figé,
    séquelle d'un incident passé, n'exige pas d'action immédiate.
  - "unknown" : aucun point de comparaison disponible (première mesure, ou
    aucun point encore assez ancien) — jamais confondu avec "flat", qui
    affirmerait à tort une absence de mouvement.
"""


class Boundary(str, Enum):
    """Classification d'une interface vis-à-vis du périmètre réseau.

    Pilote la colonne ClickHouse `InIfBoundary` / `OutIfBoundary`. Une erreur ici
    vide les dashboards Akvorado (incident vécu 2026-07-31), d'où les libellés en
    clair exposés dans l'UI plutôt qu'un menu déroulant neutre.
    """

    INTERNAL = "internal"
    EXTERNAL = "external"
    UNDEFINED = "undefined"

    @property
    def label(self) -> str:
        """Libellé en clair destiné à un utilisateur non expert."""
        return {
            Boundary.INTERNAL: "Vers le mesh interne",
            Boundary.EXTERNAL: "Vers Internet",
            Boundary.UNDEFINED: "Non classifiée",
        }[self]


class ExporterHealth(str, Enum):
    """État de santé d'un exportateur, croisant config déclarée et flux observés."""

    HEALTHY = "healthy"
    SILENT = "silent"
    UNDECLARED = "undeclared"
    UNKNOWN_INTERFACE = "unknown_interface"
    REJECTED = "rejected"

    @property
    def label(self) -> str:
        return {
            ExporterHealth.HEALTHY: "Sain",
            ExporterHealth.SILENT: "Silencieux",
            ExporterHealth.UNDECLARED: "Non déclaré",
            ExporterHealth.UNKNOWN_INTERFACE: "Interface inconnue",
            ExporterHealth.REJECTED: "Flux rejetés",
        }[self]

    @property
    def severity(self) -> int:
        """Ordre de gravité pour le tri (0 = sain, 3 = critique)."""
        return {
            ExporterHealth.HEALTHY: 0,
            ExporterHealth.UNDECLARED: 1,
            ExporterHealth.UNKNOWN_INTERFACE: 2,
            ExporterHealth.SILENT: 3,
            ExporterHealth.REJECTED: 3,
        }[self]


class InterfaceSpec(BaseModel):
    """Une interface déclarée dans le provider `static` d'Akvorado."""

    if_index: int
    name: str
    description: str = ""
    speed: int = 1000
    boundary: Boundary = Boundary.UNDEFINED


class DeclaredExporter(BaseModel):
    """Un exportateur tel que déclaré dans `outlet.yaml`."""

    cidr: str
    name: str
    if_indexes: dict[int, InterfaceSpec] = Field(default_factory=dict)
    default: InterfaceSpec | None = None
    is_catchall: bool = False


class ObservedExporter(BaseModel):
    """Un exportateur tel qu'observé dans les flux ingérés (ClickHouse)."""

    address: str
    name: str
    flows: int
    bytes: int
    last_seen: datetime | None = None
    interfaces: list[str] = Field(default_factory=list)


class ExporterStatus(BaseModel):
    """Vue unifiée d'un exportateur : déclaré x observé x ingéré.

    C'est le croisement que ni Akvorado ni ClickHouse ne savent produire seuls,
    et qui rend visible le cas d'un exportateur émettant mais 100% rejeté.
    """

    address: str
    name: str
    health: ExporterHealth
    declared: DeclaredExporter | None = None
    observed: ObservedExporter | None = None
    forwarded_total: int = 0
    rejected_total: int = 0
    rejection_reasons: dict[str, int] = Field(default_factory=dict)
    explanation: str = ""


class TableRetention(BaseModel):
    """État de rétention d'une table ClickHouse."""

    table: str
    engine: str
    ttl_seconds: int | None
    bytes_on_disk: int
    rows: int

    @computed_field  # type: ignore[prop-decorator]  # pydantic gere le combo
    @property
    def ttl_days(self) -> float | None:
        """Durée de rétention en jours.

        `computed_field` est indispensable : une simple `@property` n'est PAS
        sérialisée par `model_dump()`. Les templates et l'API reçoivent des
        dicts, donc sans cela le TTL s'affichait « 0 j » alors qu'il valait 15
        (défaut constaté au screenshot de la page Rétention, 2026-08-05).
        """
        return None if self.ttl_seconds is None else self.ttl_seconds / 86400


class AppliedTtl(BaseModel):
    """Résultat de l'exécution réelle d'un ordre `ALTER TABLE ... MODIFY TTL`.

    Produit par `app.services.retention.apply_ttl` une fois le SQL exécuté
    avec succès contre ClickHouse — voir ce module pour les garanties de
    validation (allowlist + bornes) appliquées AVANT toute exécution.
    """

    table: str
    ttl_days: int
    sql_statement: str
    applied_at: datetime


class PortMapping(BaseModel):
    """Correspondance port -> application, éditable par les utilisateurs.

    `port_end` est `None` pour une correspondance à port unique (cas
    dominant : 100% du catalogue IANA). Une plage (`port_end` non `None`,
    `port_end >= port`) couvre un besoin métier réel — ex. FTP passif ou une
    plage applicative propriétaire sur 350 routeurs SFR — qu'une entrée par
    port rendrait ingérable à la saisie comme à l'affichage.
    """

    port: int
    proto: str
    application: str
    source: str = "custom"
    port_end: int | None = None

    @property
    def is_range(self) -> bool:
        return self.port_end is not None and self.port_end != self.port

    @property
    def port_label(self) -> str:
        """Libellé lisible : `443` ou `50000-51000`."""
        if self.is_range:
            return f"{self.port}-{self.port_end}"
        return str(self.port)


class RejectionReason(BaseModel):
    """Un motif de rejet à l'ingestion, avec son explication en clair.

    `trend_delta`/`trend_state` portent la TENDANCE récente — DÉFAUT MESURÉ
    (2026-08-09) : `count` seul est un cumul Prometheus depuis le démarrage
    du conteneur outlet, jamais remis à zéro. Un exploitant ne peut pas
    distinguer un incident RÉGLÉ (cumul figé, séquelle passée) d'un incident
    EN COURS (le compteur continue de grimper) à partir du seul total — les
    deux s'affichaient avec la même urgence visuelle.

    ZÉRO SILENCIEUX (CLAUDE.md règle n°2) : `trend_state` est un état DISTINCT
    à trois valeurs, jamais un delta implicite. `UNKNOWN` (première mesure,
    aucun point de comparaison encore disponible) ne doit JAMAIS s'afficher
    comme "+0" — un "+0" affirmerait à tort que rien ne bouge, alors que
    l'absence de mesure ne permet aucune affirmation.
    """

    error: str
    exporter: str
    count: int
    explanation: str = ""
    remediation: str = ""
    trend_delta: int | None = None
    trend_state: TrendState = "unknown"
    masked_baseline: int | None = None
    """Ligne de base d'une purge, quand ce motif a été purgé PUIS a repris.

    PURGE DES CUMULS FIGÉS (2026-08-10) : un motif purgé est masqué tant que
    son compteur ne bouge plus. S'il REPART, il réapparaît — mais `count` ne
    porte alors que le DELTA au-dessus de la ligne de base, pas le cumul brut.
    `masked_baseline` rend ce décalage EXPLICITE : sans lui, l'exploitant
    verrait un compteur passer de 555 961 à 42 et croirait à une chute du
    cumul (zéro silencieux — un chiffre juste, mais illisible sans son
    référentiel). NULL = motif jamais purgé, `count` est le cumul brut.
    """


class HealthState(str, Enum):
    """État d'un indicateur de santé DB — jamais un nombre nu sans contexte.

    ZÉRO SILENCIEUX (CLAUDE.md règle n°2) : `UNAVAILABLE` est un état DISTINCT
    de `HEALTHY`, jamais une valeur neutre (0, liste vide) qui se confondrait
    avec une base saine. Une requête ClickHouse en échec DOIT produire
    `UNAVAILABLE`, jamais laisser l'écran deviner un succès.
    """

    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNAVAILABLE = "unavailable"

    @property
    def label(self) -> str:
        return {
            HealthState.HEALTHY: "Sain",
            HealthState.WARNING: "À surveiller",
            HealthState.CRITICAL: "Critique",
            HealthState.UNAVAILABLE: "Indisponible",
        }[self]

    @property
    def severity(self) -> int:
        """Ordre de gravité pour le tri (0 = sain, 3 = pire)."""
        return {
            HealthState.HEALTHY: 0,
            HealthState.WARNING: 1,
            HealthState.UNAVAILABLE: 2,
            HealthState.CRITICAL: 3,
        }[self]


class HealthIndicator(BaseModel):
    """Un indicateur de santé DB — TOUJOURS accompagné de son état ET du seuil
    qui a décidé cet état, jamais un nombre nu.

    `threshold_label` documente en clair la règle appliquée (ex. "parts_to_delay_insert
    = 1000, lu depuis system.merge_tree_settings") pour qu'un exploitant comprenne
    POURQUOI l'état est celui affiché sans relire le code.
    """

    key: str
    label: str
    state: HealthState
    value_label: str
    detail: str = ""
    threshold_label: str = ""


class TablePartsHealth(BaseModel):
    """Parts actives d'une table ClickHouse, rapportées aux seuils MergeTree.

    Les seuils (`parts_to_delay_insert`, `parts_to_throw_insert`) sont LUS
    depuis `system.merge_tree_settings` à chaque évaluation — jamais codés en
    dur : ce sont des réglages ClickHouse ajustables, pas des constantes du
    projet (exigence explicite de la tâche).

    ⚠️ BUG CORRIGÉ (2026-08-08) : ces deux seuils ClickHouse s'appliquent au
    nombre de parts actives d'une SEULE PARTITION, jamais au total de la
    table (source : `src/Storages/MergeTree/MergeTreeSettings.cpp` du code
    ClickHouse — "If the number of active parts in a SINGLE PARTITION
    exceeds..."). `max_active_parts_in_partition` est donc la valeur qui
    DÉCIDE l'état ; `total_active_parts` reste affiché comme information
    contextuelle mais ne doit JAMAIS être comparé à ces seuils.
    """

    table: str
    total_active_parts: int
    max_active_parts_in_partition: int
    partition_count: int
    parts_to_delay_insert: int
    parts_to_throw_insert: int
    state: HealthState

    @property
    def pct_of_delay_threshold(self) -> float:
        """Marge par rapport au seuil de ralentissement — calculée sur le
        MAXIMUM par partition, jamais sur le total (cf. docstring de classe)."""
        if self.parts_to_delay_insert <= 0:
            return 0.0
        return (self.max_active_parts_in_partition / self.parts_to_delay_insert) * 100


class MergeBacklogHealth(BaseModel):
    """Fusions en retard sur une fenêtre — parts créées vs parts fusionnées.

    SIGNAL D'ALERTE N°1 (cf. diagnostic) : si l'écart entre parts créées et
    parts fusionnées se creuse, ClickHouse accumule des parts plus vite qu'il
    ne les absorbe — c'est le prodrome de TOO_MANY_PARTS, pas la conséquence.
    """

    window_label: str
    parts_created: int
    parts_merged: int
    state: HealthState

    @property
    def backlog(self) -> int:
        """Écart (positif = accumulation, négatif ou nul = la fusion suit)."""
        return self.parts_created - self.parts_merged


class ErrorCounter(BaseModel):
    """Un compteur d'erreur ClickHouse cumulé depuis le démarrage du serveur.

    `system.errors` est un CUMUL depuis le démarrage, pas une fenêtre glissante
    — `last_error_time` est l'indicateur temporel pertinent, pas `value` seul
    (un value élevé mais ancien n'est pas le même signal qu'un value qui vient
    de bouger).
    """

    name: str
    value: int
    last_error_time: datetime | None = None


class StuckMutation(BaseModel):
    """Une mutation ClickHouse bloquée (`is_done=0` avec un motif d'échec)."""

    table: str
    mutation_id: str
    command: str
    create_time: datetime
    latest_fail_reason: str


class DetachedPartEntry(BaseModel):
    """Groupe de parts détachées partageant `(database, table, reason)`.

    AJOUTÉ (2026-08-09) — contexte métier demandé : une part détachée
    `broken-on-start` à 0 octet (fragment vide mis de côté par ClickHouse au
    redémarrage brutal, rien à récupérer) ne se décide pas comme une part
    volumineuse portant une autre raison (ex. `ignored`) — l'exploitant a
    besoin de la RAISON et de la TAILLE pour choisir, jamais du seul compte.
    """

    database: str
    table: str
    reason: str
    count: int
    bytes_on_disk: int


class DetachedPartsHealth(BaseModel):
    """Parts détachées — occupent le disque sans servir aux requêtes.

    `by_group` détaille chaque `(database, table, reason)` — ajouté le
    2026-08-09 pour que l'écran distingue une part `broken-on-start` à
    0 octet (purge sans réfléchir) d'une part volumineuse à examiner avant
    suppression. `count`/`total_bytes` restent les totaux globaux (tables de
    flux ET tables système confondues, cf. `collect_detached_parts`)."""

    count: int
    total_bytes: int
    state: HealthState
    by_group: list[DetachedPartEntry] = []


class MemoryHealth(BaseModel):
    """Mémoire résidente du serveur ClickHouse rapportée au plafond qui MORD EN
    PREMIER — jamais la seule valeur de configuration codée en dur.

    DÉFAUT MESURÉ (2026-08-09) : l'écran affichait « 51% — 1.0 Go / 2.0 Go » en
    comparant `MemoryResident` à `db_health_memory_limit_bytes`, une valeur de
    config par défaut (2 Gio) qui n'a de sens que par COÏNCIDENCE sur le
    déploiement de référence `.6` (calibrée sur `HostConfig.Memory` mesuré via
    `docker inspect`, jamais lue depuis ClickHouse). Or ClickHouse a sa PROPRE
    limite interne (`max_server_memory_usage`, `system.server_settings`) qui
    refuse les requêtes AVANT que le conteneur Docker ne tue le process par
    OOM — les deux plafonds n'ont ni la même valeur ni la même conséquence, et
    l'écran ne montrait ni l'un ni l'autre distinctement.

    `limit_source` documente EXPLICITEMENT quel plafond est utilisé pour le
    pourcentage affiché — jamais une valeur mesurée présentée comme identique
    à une valeur de config non vérifiée (zéro silencieux, CLAUDE.md règle
    n°2)."""

    resident_bytes: int
    limit_bytes: int
    """Plafond EFFECTIF utilisé pour le calcul de `pct_used` — celui qui mord
    en premier parmi `clickhouse_limit_bytes` et `configured_limit_bytes`
    (le plus petit des deux non nuls, ClickHouse prioritaire à égalité car
    c'est lui qui refuse les requêtes AVANT l'OOM du conteneur)."""
    state: HealthState

    clickhouse_limit_bytes: int | None = None
    """Limite lue depuis ClickHouse (`max_server_memory_usage`, ou calculée
    depuis `max_server_memory_usage_to_ram_ratio` × `OSMemoryTotal` quand le
    réglage vaut 0 — « pas de limite EXPLICITE », pas « pas de limite »).
    `None` si la lecture a échoué : distinct de 0, jamais confondu avec
    « pas de limite »."""

    clickhouse_limit_is_computed: bool = False
    """`True` si `clickhouse_limit_bytes` a été RECONSTITUÉ depuis le ratio
    RAM (réglage serveur à 0) plutôt que lu directement — l'exploitant doit
    savoir que cette valeur est déduite, pas un réglage explicite."""

    clickhouse_limit_unavailable_reason: str = ""
    """Non vide UNIQUEMENT si la lecture de la limite ClickHouse a échoué —
    l'écran doit alors dire « limite indéterminée », jamais retomber sur la
    valeur de configuration en la présentant comme mesurée."""

    configured_limit_bytes: int = 0
    """Repli de configuration (`OKVORADO_DB_HEALTH_MEMORY_LIMIT_BYTES`,
    défaut 2 Gio) — un plafond CONNU PAR CONFIGURATION (typiquement la limite
    Docker du conteneur), jamais lu depuis ClickHouse. Reste affiché même
    quand ce n'est pas lui qui décide le pourcentage, pour que l'exploitant
    voie les DEUX plafonds."""

    limit_source: str = "config"
    """Quel plafond a décidé `limit_bytes`/`pct_used` : "clickhouse" (mord en
    premier ou seul disponible), "config" (repli, ClickHouse indisponible ou
    limite ClickHouse supérieure à la config), ou "clickhouse_computed" (lu
    via le ratio RAM, `max_server_memory_usage=0`)."""

    @property
    def pct_used(self) -> float:
        if self.limit_bytes <= 0:
            return 0.0
        return (self.resident_bytes / self.limit_bytes) * 100


class DbHealthSnapshot(BaseModel):
    """Vue d'ensemble de la santé ClickHouse à un instant donné.

    C'est l'objet persisté par la routine périodique (historique) et rendu
    par l'écran — un SEUL calcul, deux consommateurs.
    """

    checked_at: datetime
    overall_state: HealthState
    parts_by_table: list[TablePartsHealth] = Field(default_factory=list)
    merge_backlog: MergeBacklogHealth | None = None
    errors: list[ErrorCounter] = Field(default_factory=list)
    memory: MemoryHealth | None = None
    stuck_mutations: list[StuckMutation] = Field(default_factory=list)
    detached_parts: DetachedPartsHealth | None = None
    replication_active: bool = False
    indicators: list[HealthIndicator] = Field(default_factory=list)
    error_message: str = ""
    """Non vide UNIQUEMENT si la collecte a (partiellement) échoué — zéro
    silencieux : un écran qui affiche ce snapshot doit toujours pouvoir
    distinguer "sain" de "je n'ai pas pu vérifier"."""
