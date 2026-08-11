"""Export de flux — outil de QUALIFICATION d'équipement, pas de reporting.

CONFIG_HARDCODE_OK: les adresses citées dans les docstrings de ce fichier sont
des illustrations de FORME de donnée (comme dans `flow_sample.py`), pas des
valeurs d'infra contactées par ce module. Le host ClickHouse vient du client
INJECTÉ, jamais d'ici ; l'adresse d'exportateur vient de l'écran et transite
exclusivement en paramètre lié.

À QUOI CE MODULE SERT (demande utilisateur 2026-08-11) : « quand je serai en
qualif, je voudrai exporter des flux avec les données des palo et des routeurs
SFR à te donner en exemple pour affiner l'intégration auto des bonnes interfaces
+ ajuster les dashboards ».

Ce n'est donc PAS un export de reporting destiné à un tableau de bord. C'est un
PRÉLÈVEMENT D'ÉCHANTILLON destiné à être TRANSMIS pour analyse, en environnement
client, sur des équipements qu'on ne connaît pas encore : des pare-feux Palo Alto
et des routeurs SFR. Trois conséquences de conception, toutes tenues ici :

1. **ISOLER UN ÉQUIPEMENT.** Un dump global noyé ne dit rien de ce que le Palo
   remplit : les 11 exportateurs du homelab sont des serveurs Linux sous
   softflowd, leurs flux DILUERAIENT ceux de l'équipement à qualifier. Le filtre
   par exportateur est donc central — et il est appliqué à DEUX niveaux (SQL
   `WHERE` + tamis en Python) pour la raison exposée dans `_matches_exporter()`.

2. **MONTRER LES CHAMPS VIDES AUTANT QUE LES REMPLIS.** C'est précisément
   l'information qui manque pour affiner l'intégration : savoir que le Palo ne
   renseigne PAS `SrcNetMask` vaut autant que de savoir qu'il renseigne `SrcAS`.
   Un export qui omettrait les colonnes vides supprimerait la moitié du signal
   utile. Ici, TOUS les champs du schéma sont rendus, avec leur taux mesuré.

3. **FICHIER AUTO-PORTANT.** Le fichier part par un canal quelconque et arrive
   chez quelqu'un qui n'a pas vu l'écran. Il doit dire seul quel équipement,
   quelle période, combien de flux, quels champs remplis, quelle version de
   schéma. D'où `ExportMetadata`, présent dans les DEUX formats.

UN CONCEPT = UNE SOURCE : ce module NE redéfinit ni le schéma des colonnes, ni la
classification par origine, ni la mesure de remplissage. Il réutilise
`app.services.field_catalog` (`read_flow_columns`, `FIELD_SEMANTICS`,
`_IDENTIFIER_RE`) et `app.services.flow_sample` (`FLOW_COLUMNS` pour les
libellés FR). Créer une seconde source de vérité sur les champs serait la
garantie qu'elles divergent — le projet a déjà mesuré cette dérive
(`FLOW_COLUMNS` ignore `IPTos`, pourtant en production).

GARDES DURES DU PROJET, toutes exercées par `tests/test_flow_export.py` :

- **Requête paramétrée exclusivement.** L'adresse d'exportateur vient d'une
  saisie (même choisie à la souris, elle transite par une requête HTTP qu'on
  peut forger) : elle passe en paramètre lié `{exporter_address:String}`, jamais
  concaténée. Tables et colonnes sont des littéraux.
- **Période en énumération FERMÉE** (`window_to_seconds`, qui lève sur toute
  valeur hors `WINDOW_CHOICES`) — refus, jamais échappement.
- **`LIMIT` toujours présent et PLAFONNÉ.** `default.flows` porte ~60 M de
  lignes et sert AUSSI la console Akvorado : une requête non bornée n'est pas
  une requête lente, c'est un incident de production.
- **`sum(Bytes * SamplingRate)`**, jamais `sum(Bytes)` seul. L'erreur est
  INVISIBLE au homelab (softflowd échantillonne à 1:1) et vaudrait un facteur
  1000 sur un routeur SFR en 1:1000 — soit exactement l'environnement que cet
  écran sert à qualifier.
- **ZÉRO SILENCIEUX.** Trois états DISTINCTS : « je n'ai pas pu mesurer »
  (`FlowExportUnavailableError`), « j'ai mesuré zéro flux » (`is_empty`, ÉNONCÉ
  dans le fichier), et « j'ai mesuré des flux ». Un fichier de 0 ligne qu'on
  confondrait avec un export complet serait le pire résultat possible ici : il
  ferait conclure « ce Palo n'émet rien » sur une panne de collecte.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any

from app.config import WINDOW_CHOICES, window_to_seconds
from app.services.field_catalog import (
    _DEFAULT_SEMANTICS,
    _IDENTIFIER_RE,
    FIELD_SEMANTICS,
    ORIGIN_LABELS,
    ClickHouseQueryable,
    FlowSchemaColumn,
    _fill_rate_aliases,
    read_flow_columns,
)
from app.services.flow_sample import FLOW_COLUMNS

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bornes et énumérations fermées
# ---------------------------------------------------------------------------

DEFAULT_EXPORT_LIMIT = 500
"""Taille d'échantillon par défaut.

Assez pour qu'un analyste voie la FORME des données d'un équipement (les valeurs
courantes de chaque champ, les interfaces citées), assez petit pour que le
fichier reste transmissible et la requête instantanée."""

MAX_EXPORT_LIMIT = 50_000
"""PLAFOND DUR — la garde qui rend la requête non bornée impossible.

Plus haut que `flow_sample.MAX_SAMPLE_LIMIT` (1 000) parce que l'usage diffère :
`flow_sample` alimente un écran de composition (il suffit d'y voir les valeurs
courantes), alors qu'ici le fichier part en ANALYSE — un champ à événements
rares (un `SrcNetMask` renseigné une fois sur mille) n'apparaîtrait pas dans
1 000 lignes, et c'est justement ce genre de champ qu'on cherche à qualifier.

50 000 lignes × ~60 colonnes reste un fichier de quelques dizaines de Mo, borné
et transmissible. Au-delà, ce n'est plus un échantillon de qualification."""

LIMIT_CHOICES: tuple[int, ...] = (100, 500, 2_000, 10_000, 50_000)
"""Tailles proposées À LA SOURIS. Une saisie libre reste plafonnée par
`_clamp_limit()` — cette table ne sert qu'à l'écran, elle n'est pas la garde."""

EXPORT_FORMATS: tuple[str, ...] = ("csv", "json")
"""Énumération FERMÉE des formats.

CSV pour l'analyse en tableur (trier, filtrer, annoter à la main pendant une
réunion de qualification). JSON pour l'analyse programmatique — c'est le format
qui préserve les types et qui porte l'en-tête de métadonnées en structure plutôt
qu'en commentaires.

POURQUOI PAS DE TROISIÈME FORMAT : Parquet/NDJSON auraient une valeur réelle
pour de gros volumes, mais ajouteraient une dépendance (pyarrow) au stack pour
un besoin — transmettre un échantillon borné pour analyse — que ces deux formats
couvrent entièrement. Le projet doit s'installer sur une machine nue en
entreprise ; chaque dépendance ajoutée est un coût de déployabilité."""

SCHEMA_VERSION = "okvorado-flow-export/1"
"""Version du format du fichier produit.

Elle accompagne CHAQUE export. Sans elle, un fichier reçu dans six mois serait
ininterprétable dès que la structure aurait bougé — or ces fichiers sont
justement destinés à être relus plus tard, hors contexte."""

FILL_RATE_WINDOW_NOTE = (
    "taux mesures sur la meme fenetre et le meme exportateur que l'export"
)

FLOWS_TABLE_LITERAL = "default.flows"
"""Nom de table en LITTÉRAL. ClickHouse n'accepte pas de paramètre lié à la
place d'un nom de table : la seule garde possible est qu'il ne soit jamais
dérivé d'une saisie. Il ne l'est pas."""


class FlowExportUnavailableError(RuntimeError):
    """La mesure n'a pas abouti — état DISTINCT d'un export vide.

    Levée quand ClickHouse ne répond pas, que la table est absente ou que le
    schéma n'est pas lisible. L'appelant DOIT afficher « indisponible » et
    surtout ne PAS produire de fichier : un fichier vide issu d'une panne serait
    lu comme « cet équipement n'émet rien », c'est-à-dire une conclusion fausse
    tirée d'une absence de mesure.
    """


# ---------------------------------------------------------------------------
# Structures rendues
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExportableDevice:
    """Un exportateur RÉELLEMENT observé dans les flux, proposable à l'écran.

    La liste vient de ClickHouse, jamais d'`outlet.yaml` : l'objectif du projet
    est qu'un équipement inconnu qui émet apparaisse tout seul. En qualification,
    le Palo qu'on vient de pointer vers le collecteur doit être sélectionnable
    sans avoir été déclaré nulle part.
    """

    address: str
    name: str
    flow_count: int
    byte_count: int

    @property
    def label(self) -> str:
        """Libellé d'écran — l'adresse seule ne suffit pas à reconnaître l'équipement."""
        if self.name and self.name != self.address:
            return f"{self.name} ({self.address})"
        return self.address


@dataclass(frozen=True)
class ExportField:
    """Un champ du schéma, AVEC son taux de remplissage chez cet équipement.

    `fill_rate is None` signifie « non mesuré » et jamais « vide » : 0.0 est une
    MESURE (le champ existe et l'équipement ne le renseigne pas), `None` est une
    absence de mesure. Les confondre est le défaut fondateur du projet.
    """

    name: str
    label: str
    clickhouse_type: str
    origin: str
    category: str
    fill_rate: float | None

    @property
    def origin_label(self) -> str:
        return ORIGIN_LABELS.get(self.origin, self.origin)

    @property
    def fill_rate_display(self) -> str:
        """Affichage HONNÊTE : « non mesuré » n'est pas « 0 % »."""
        if self.fill_rate is None:
            return "non mesuré"
        return f"{self.fill_rate:.1f} %".replace(".", ",")

    @property
    def is_filled(self) -> bool:
        """Vrai seulement si MESURÉ ET non nul."""
        return self.fill_rate is not None and self.fill_rate > 0


@dataclass(frozen=True)
class ExportMetadata:
    """L'en-tête qui rend le fichier AUTO-PORTANT.

    Celui qui reçoit le fichier doit pouvoir dire quel équipement, quelle
    période, combien de flux et quels champs sont remplis — sans poser de
    question à celui qui l'a produit. C'est l'exigence explicite de la demande.
    """

    schema_version: str
    generated_at: str
    exporter_address: str
    exporter_name: str
    window: str
    window_seconds: int
    requested_limit: int
    applied_limit: int
    flow_count: int
    field_count: int
    filled_field_count: int
    fill_rates_available: bool
    empty: bool
    empty_reason: str

    @property
    def exporter_display(self) -> str:
        """« Tous les exportateurs » est ÉCRIT, jamais laissé en case vide.

        Une case vide dans un fichier reçu s'interprète — mal. Le périmètre de
        l'export doit être énoncé littéralement.
        """
        if not self.exporter_address:
            return "tous les exportateurs"
        if self.exporter_name and self.exporter_name != self.exporter_address:
            return f"{self.exporter_name} ({self.exporter_address})"
        return self.exporter_address

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "exporter_address": self.exporter_address,
            "exporter_name": self.exporter_name,
            "exporter_display": self.exporter_display,
            "window": self.window,
            "window_seconds": self.window_seconds,
            "requested_limit": self.requested_limit,
            "applied_limit": self.applied_limit,
            "flow_count": self.flow_count,
            "field_count": self.field_count,
            "filled_field_count": self.filled_field_count,
            "fill_rates_available": self.fill_rates_available,
            "fill_rate_note": FILL_RATE_WINDOW_NOTE,
            "empty": self.empty,
            "empty_reason": self.empty_reason,
        }


@dataclass(frozen=True)
class FlowExport:
    """Le prélèvement complet : métadonnées + champs + lignes."""

    metadata: ExportMetadata
    fields: list[ExportField]
    rows: list[dict[str, Any]]
    fill_rates_available: bool

    @property
    def is_empty(self) -> bool:
        """Vrai quand la mesure a abouti et n'a rendu AUCUN flux.

        C'est une mesure exploitable (« cet équipement n'a rien émis sur la
        fenêtre »), à ne jamais confondre avec `FlowExportUnavailableError`.
        """
        return not self.rows

    @property
    def filled_fields(self) -> list[ExportField]:
        return [item for item in self.fields if item.is_filled]

    @property
    def empty_fields(self) -> list[ExportField]:
        """Les champs que cet équipement NE renseigne PAS.

        C'est la moitié utile du signal en qualification : elle dit ce qu'il
        faudra activer sur l'équipement, ou ce qu'on ne pourra pas montrer dans
        les dashboards.
        """
        return [
            item for item in self.fields if item.fill_rate is not None and item.fill_rate == 0
        ]


# ---------------------------------------------------------------------------
# Bornage de la limite
# ---------------------------------------------------------------------------


def _clamp_limit(limit: int) -> int:
    """Ramène la limite dans `[1, MAX_EXPORT_LIMIT]`.

    Une limite <= 0 est ramenée à 1 et non à 0 : un `LIMIT 0` rendrait un export
    vide INDISTINGUABLE d'une fenêtre sans flux — exactement le zéro silencieux
    que ce module refuse. Le plafond, lui, n'est pas un défaut mais une GARDE :
    il rend la requête non bornée impossible même si l'appelant demande n'importe
    quoi.
    """
    if limit < 1:
        return 1
    return min(limit, MAX_EXPORT_LIMIT)


def _validate_format(fmt: str) -> str:
    """Refuse tout format hors énumération fermée.

    REFUS, jamais repli silencieux sur CSV : un utilisateur qui a demandé du
    JSON et reçoit du CSV sans avertissement croira que le format JSON n'existe
    pas.
    """
    if fmt not in EXPORT_FORMATS:
        raise ValueError(
            f"format d'export inconnu: {fmt!r} (attendu: {', '.join(EXPORT_FORMATS)})"
        )
    return fmt


# ---------------------------------------------------------------------------
# Requêtes ClickHouse — paramétrées exclusivement
# ---------------------------------------------------------------------------

_EXPORTERS_SQL = f"""
SELECT
    ExporterAddress AS exporter_address,
    ExporterName AS exporter_name,
    count() AS flow_count,
    sum(Bytes * SamplingRate) AS byte_count
FROM {FLOWS_TABLE_LITERAL}
WHERE TimeReceived >= now() - toIntervalSecond({{window_seconds:UInt32}})
GROUP BY ExporterAddress, ExporterName
ORDER BY flow_count DESC
LIMIT 500
"""
"""Liste des exportateurs réellement observés, pour peupler le sélecteur.

`sum(Bytes * SamplingRate)` et NON `sum(Bytes)` : sur un routeur SFR en 1:1000,
l'écart est d'un facteur 1000 — et il serait invisible ici, où softflowd
échantillonne à 1:1. `count()` reste brut : c'est un nombre de flux REÇUS, pas
une estimation du trafic, le mettre à l'échelle serait une erreur symétrique.

`LIMIT 500` : même sur un parc de 350 routeurs, un sélecteur borné reste
utilisable et la requête reste bornée par construction."""


def normalize_exporter_address(address: str) -> str:
    """Retire le préfixe `::ffff:` des IPv4 stockées en IPv6-mapped.

    `ExporterAddress` est une colonne IPv6 dans ClickHouse (cf. CONTRACT.md) :
    une IPv4 s'y écrit préfixée. Cette forme ne doit atteindre ni l'écran ni le
    fichier transmis — personne ne reconnaît son équipement sous cette écriture.
    """
    lowered = address.lower()
    prefix = "::ffff:"
    if lowered.startswith(prefix):
        return address[len(prefix) :]
    return address


def build_exporters_query(window: str) -> tuple[str, dict[str, int]]:
    """Construit la requête de listing des exportateurs observés.

    Raises:
        ValueError: fenêtre hors de l'énumération fermée `WINDOW_CHOICES`,
            REFUSÉE avant tout accès réseau.
    """
    return _EXPORTERS_SQL, {"window_seconds": window_to_seconds(window)}


def list_exportable_devices(
    client: ClickHouseQueryable, window: str = "24h"
) -> list[ExportableDevice]:
    """Énumère les exportateurs qu'on peut sélectionner à l'écran.

    Returns:
        La liste des équipements observés, triée par volume de flux décroissant.
        Une liste VIDE signifie « aucun exportateur n'a émis sur la fenêtre » —
        une mesure, pas une panne.

    Raises:
        FlowExportUnavailableError: la requête n'a pas abouti.
        ValueError: fenêtre invalide.
    """
    sql, parameters = build_exporters_query(window)
    try:
        result = client.query(sql, parameters)
    except Exception as exc:
        log.error("flow_export: echec listing des exportateurs window=%s", window, exc_info=True)
        raise FlowExportUnavailableError(
            f"liste des exportateurs non recuperee (fenetre={window}): {exc}"
        ) from exc

    devices: list[ExportableDevice] = []
    for row in result.result_rows:
        address_raw, name_raw, flow_count, byte_count = row[0], row[1], row[2], row[3]
        devices.append(
            ExportableDevice(
                address=normalize_exporter_address(str(address_raw)),
                name=str(name_raw or ""),
                flow_count=int(flow_count or 0),
                byte_count=int(byte_count or 0),
            )
        )
    return devices


def build_flow_export_query(
    *, exporter_address: str, window: str, limit: int
) -> tuple[str, dict[str, Any]]:
    """Construit la requête d'extraction des flux à exporter.

    Args:
        exporter_address: adresse de l'équipement à isoler. Chaîne VIDE =
            « tous » — dans ce cas AUCUN filtre n'est posé. Poser
            `ExporterAddress = ''` remonterait zéro ligne : ce serait le défaut
            « filtre juste mais non discriminant » que le projet a déjà mesuré,
            en pire (il rendrait un export vide crédible).
        window: fenêtre de l'UI (`WINDOW_CHOICES`). Toute autre valeur lève
            `ValueError` AVANT d'atteindre le SQL — refus, pas échappement.
        limit: taille d'échantillon, plafonnée par `_clamp_limit()`.

    Returns:
        `(sql, parameters)`. Le SQL ne contient NI l'adresse, NI la fenêtre, NI
        la limite en clair : les trois transitent en paramètres liés. Le nom de
        table est un littéral du code.

    Raises:
        ValueError: fenêtre hors énumération fermée.
    """
    window_seconds = window_to_seconds(window)
    parameters: dict[str, Any] = {
        "window_seconds": window_seconds,
        "export_limit": _clamp_limit(limit),
    }

    # `SELECT *` est délibéré et n'est PAS un relâchement de garde : il n'y a ici
    # aucune saisie utilisateur dans la liste de colonnes (il n'y a pas de liste
    # du tout). Surtout, une liste figée serait un CONTRESENS fonctionnel : cet
    # écran sert à découvrir ce qu'un équipement INCONNU remplit. Recopier les
    # 61 colonnes de `FLOW_COLUMNS` (relevé du 2026-08-06) ferait manquer toute
    # colonne ajoutée depuis — la dérive est déjà MESURÉE sur ce projet
    # (`FLOW_COLUMNS` ignore `IPTos`, pourtant en production et consommée par
    # 4 dashboards). Un export de qualification amputé d'un champ que
    # l'équipement remplit est exactement le défaut qu'on cherche à éviter.
    filtre_exportateur = ""
    if exporter_address:
        # `toIPv6()` normalise la valeur LIÉE : `ExporterAddress` est une colonne
        # IPv6, comparer une IPv4 littérale à une IPv6-mapped ne matcherait pas.
        # L'adresse reste un PARAMÈTRE, jamais un morceau de SQL.
        filtre_exportateur = "\n  AND ExporterAddress = toIPv6({exporter_address:String})"
        parameters["exporter_address"] = exporter_address

    sql = f"""
SELECT *
FROM {FLOWS_TABLE_LITERAL}
WHERE TimeReceived >= now() - toIntervalSecond({{window_seconds:UInt32}}){filtre_exportateur}
ORDER BY TimeReceived DESC
LIMIT {{export_limit:UInt32}}
"""
    return sql, parameters


def build_export_fill_rate_query(
    column_names: list[str], *, exporter_address: str, window: str
) -> tuple[str, dict[str, Any]]:
    """Mesure le remplissage de chaque champ, POUR CET ÉQUIPEMENT.

    C'est la différence essentielle avec `field_catalog.build_fill_rate_query()`,
    qui mesure sur TOUT le parc et sur 24 h fixes. Un taux calculé sur tout le
    parc ne dirait RIEN de l'équipement en qualification : les 11 serveurs Linux
    du homelab noieraient sa contribution. Ici la mesure porte sur le même
    exportateur et la même fenêtre que l'export lui-même — c'est ce qui la rend
    interprétable par celui qui recevra le fichier.

    Une SEULE requête agrégée pour tous les champs : une requête par champ ferait
    60 balayages d'une table de ~60 M de lignes à chaque aperçu.

    Raises:
        ValueError: nom de colonne hors allowlist de forme, ou fenêtre invalide.
            REFUS — la valeur n'atteint pas le SQL.
    """
    if not column_names:
        raise ValueError("aucune colonne a mesurer")

    # Les noms viennent de `system.columns`, donc d'une source de confiance —
    # mais ils transitent par une f-string, ClickHouse n'acceptant pas de
    # paramètre lié à la place d'un nom de colonne. Cette validation de FORME
    # (allowlist partagée avec `field_catalog`, UNE source) est la garde qui rend
    # l'injection impossible malgré cela.
    for name in column_names:
        if not _IDENTIFIER_RE.match(name):
            raise ValueError(f"nom de colonne refuse (hors allowlist): {name!r}")

    window_seconds = window_to_seconds(window)
    parameters: dict[str, Any] = {"window_seconds": window_seconds}

    filtre_exportateur = ""
    if exporter_address:
        filtre_exportateur = "\n  AND ExporterAddress = toIPv6({exporter_address:String})"
        parameters["exporter_address"] = exporter_address

    counters = ",\n    ".join(
        f"countIf(toString({name}) NOT IN ('', '0', '[]', '\\0\\0')) AS fill_{name}"
        for name in column_names
    )
    sql = f"""
SELECT
    count() AS total,
    {counters}
FROM {FLOWS_TABLE_LITERAL}
WHERE TimeReceived >= now() - toIntervalSecond({{window_seconds:UInt32}}){filtre_exportateur}
"""
    return sql, parameters


def fetch_export_fill_rates(
    client: ClickHouseQueryable,
    column_names: list[str],
    *,
    exporter_address: str,
    window: str,
) -> dict[str, float] | None:
    """Mesure le remplissage par champ, ou rend `None` si la mesure est impossible.

    Returns:
        `{nom: pourcentage}`, ou `None` quand AUCUN flux n'est présent dans la
        fenêtre pour cet exportateur. `None` et non `{}` ni des 0 % : sans flux,
        on ne peut RIEN conclure sur le remplissage, et rendre 0 % partout ferait
        passer une fenêtre calme pour un équipement qui ne renseigne rien — le
        contresens exact que cet écran doit éviter en qualification.

    Raises:
        FlowExportUnavailableError: la requête n'a pas abouti (distinct de
            « pas de flux à mesurer »).
    """
    sql, parameters = build_export_fill_rate_query(
        column_names, exporter_address=exporter_address, window=window
    )
    try:
        result = client.query(sql, parameters)
    except Exception as exc:
        log.error("flow_export: echec mesure du remplissage", exc_info=True)
        raise FlowExportUnavailableError(f"taux de remplissage non mesure: {exc}") from exc

    rows = list(result.result_rows)
    if not rows:
        return None

    row = rows[0]
    total = int(row[0] or 0)
    if total <= 0:
        return None

    aliases = _fill_rate_aliases(sql)
    rates: dict[str, float] = {}
    for index, name in enumerate(aliases, start=1):
        if index >= len(row):
            break
        rates[name] = round(int(row[index] or 0) * 100 / total, 1)
    return rates


# ---------------------------------------------------------------------------
# Normalisation des lignes
# ---------------------------------------------------------------------------

_LABELS_BY_NAME: dict[str, str] = {column.name: column.label for column in FLOW_COLUMNS}
"""Libellés FR — réutilisés de `flow_sample.FLOW_COLUMNS`, jamais redéfinis.
Un champ absent de cette table garde son nom technique, ce qui est correct :
c'est une colonne apparue depuis le relevé, on ne va pas inventer un libellé."""


def _matches_exporter(row: dict[str, Any], exporter_address: str) -> bool:
    """Le flux appartient-il bien à l'équipement demandé ?

    POURQUOI CE TAMIS EN PLUS DU `WHERE` SQL : le filtre doit être DISCRIMINANT,
    pas seulement présent. Le projet a déjà mesuré un « filtre juste mais non
    discriminant » (cf. CLAUDE.md, famille de défauts n°3) — une clause correcte
    qui laissait pourtant passer des lignes hors périmètre, invisible aux tests
    parce que le double rendait ce qu'on lui demandait.

    Ici l'enjeu est plus lourd qu'un affichage : si des flux d'un serveur Linux
    se glissaient dans l'export d'un pare-feu, l'analyse conclurait que ce
    pare-feu renseigne des champs qu'il ne renseigne pas. Ce tamis rend la
    confusion impossible, quelle que soit la forme sous laquelle ClickHouse rend
    l'adresse (IPv4, IPv6-mapped, casse).
    """
    if not exporter_address:
        return True
    valeur = row.get("ExporterAddress")
    if valeur is None:
        return False
    return normalize_exporter_address(str(valeur)).lower() == exporter_address.lower()


def _normalize_value(value: Any) -> Any:
    """Rend une valeur brute sérialisable ET lisible.

    Les adresses IPv6-mapped sont ramenées en IPv4, les dates en ISO, les
    tableaux en listes. Aucune valeur n'est SUPPRIMÉE ni remplacée par un neutre :
    un champ vide doit rester visiblement vide dans le fichier — c'est une
    information de qualification, pas un défaut à masquer.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (list, tuple)):
        return [_normalize_value(item) for item in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip("\x00")
    # DÉFAUT MESURÉ CONTRE UN VRAI CLICKHOUSE (2026-08-11, avant livraison) : le
    # driver `clickhouse_connect` ne rend PAS les colonnes IPv6 en `str` mais en
    # objets `ipaddress.IPv6Address`. La branche `str` ci-dessous ne se
    # déclenchait donc jamais sur les vraies données, et CHAQUE adresse du
    # fichier transmis serait partie sous sa forme IPv6-mapped brute —
    # illisible pour qui analyse, alors que les doubles de test (qui rendaient
    # des `str`) affichaient un résultat parfait. C'est exactement la famille de
    # défauts « double de test plus permissif que le réel » de CLAUDE.md : seule
    # l'exécution contre un vrai serveur pouvait la révéler.
    if isinstance(value, (IPv4Address, IPv6Address)):
        return normalize_exporter_address(str(value))
    if isinstance(value, str):
        nettoye = value.rstrip("\x00")
        if nettoye.lower().startswith("::ffff:"):
            return normalize_exporter_address(nettoye)
        return nettoye
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)


def _build_fields(
    columns: list[FlowSchemaColumn], rates: dict[str, float] | None
) -> list[ExportField]:
    """Croise le schéma RÉEL avec la classification par origine du catalogue.

    TOUS les champs sont rendus, y compris ceux à 0 % : c'est l'exigence n°2 de
    cet écran. Omettre les champs vides supprimerait précisément l'information
    qu'on cherche — « cet équipement ne renseigne pas `SrcNetMask` ».
    """
    fields: list[ExportField] = []
    for column in columns:
        semantics = FIELD_SEMANTICS.get(column.name, _DEFAULT_SEMANTICS)
        fields.append(
            ExportField(
                name=column.name,
                label=_LABELS_BY_NAME.get(column.name, column.name),
                clickhouse_type=column.clickhouse_type,
                origin=semantics.origin,
                category=semantics.category,
                # `None` quand la mesure n'a pas pu être faite — jamais 0.0.
                fill_rate=None if rates is None else rates.get(column.name),
            )
        )
    return fields


# ---------------------------------------------------------------------------
# Construction de l'export
# ---------------------------------------------------------------------------


def build_export(
    client: ClickHouseQueryable,
    *,
    exporter_address: str,
    window: str,
    limit: int,
    fmt: str,
) -> FlowExport:
    """Construit le prélèvement complet : métadonnées, champs, lignes.

    Args:
        client: client ClickHouse INJECTÉ (jamais construit ici, pour que les
            tests fournissent un double sans infra).
        exporter_address: équipement à isoler ; chaîne vide = tous.
        window: fenêtre de l'UI (`WINDOW_CHOICES`), énumération fermée.
        limit: taille d'échantillon, plafonnée à `MAX_EXPORT_LIMIT`.
        fmt: format cible, énumération fermée `EXPORT_FORMATS`. Validé ICI même
            si le rendu vient plus tard : refuser tôt évite d'exécuter une
            requête coûteuse pour un format qu'on ne saura pas produire.

    Raises:
        ValueError: fenêtre ou format hors énumération fermée. Levée AVANT tout
            accès réseau.
        FlowExportUnavailableError: une des trois mesures (schéma, flux,
            remplissage) n'a pas abouti. Aucun fichier ne doit alors être
            produit.
    """
    _validate_format(fmt)
    # Refus AVANT tout accès réseau : une fenêtre invalide ne doit pas coûter
    # une requête, et surtout ne doit jamais atteindre le SQL.
    window_seconds = window_to_seconds(window)

    # 1. Le schéma RÉEL — jamais une liste recopiée (elle dériverait).
    try:
        columns = read_flow_columns(client)
    except Exception as exc:
        log.error("flow_export: schema de flux non lu", exc_info=True)
        raise FlowExportUnavailableError(f"schema de flux non lu: {exc}") from exc
    if not columns:
        raise FlowExportUnavailableError("schema de flux non lu: aucune colonne")

    # 2. Les flux.
    sql, parameters = build_flow_export_query(
        exporter_address=exporter_address, window=window, limit=limit
    )
    try:
        result = client.query(sql, parameters)
    except Exception as exc:
        log.error(
            "flow_export: echec extraction des flux exportateur=%s fenetre=%s",
            exporter_address or "tous",
            window,
            exc_info=True,
        )
        raise FlowExportUnavailableError(
            f"flux non extraits (exportateur={exporter_address or 'tous'}): {exc}"
        ) from exc

    column_names = list(result.column_names)
    rows: list[dict[str, Any]] = []
    for raw_row in result.result_rows:
        row = {
            name: _normalize_value(value)
            for name, value in zip(column_names, raw_row, strict=False)
        }
        # Tamis discriminant — voir `_matches_exporter()`.
        if _matches_exporter(row, exporter_address):
            rows.append(row)

    # 3. Le remplissage, sur le MÊME périmètre que l'export.
    rates = fetch_export_fill_rates(
        client,
        [column.name for column in columns],
        exporter_address=exporter_address,
        window=window,
    )
    fields = _build_fields(columns, rates)

    exporter_name = ""
    if exporter_address and rows:
        exporter_name = str(rows[0].get("ExporterName") or "")

    applied_limit = _clamp_limit(limit)
    empty = not rows
    # ZÉRO SILENCIEUX : l'export vide s'EXPLIQUE, il ne se devine pas d'un
    # fichier sans lignes.
    empty_reason = ""
    if empty:
        cible = exporter_address or "aucun exportateur"
        empty_reason = (
            f"aucun flux recu de {cible} sur la fenetre {window} — la requete a "
            "abouti, c'est une mesure et non une panne de collecte"
        )

    metadata = ExportMetadata(
        schema_version=SCHEMA_VERSION,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        exporter_address=exporter_address,
        exporter_name=exporter_name,
        window=window,
        window_seconds=window_seconds,
        requested_limit=limit,
        applied_limit=applied_limit,
        flow_count=len(rows),
        field_count=len(fields),
        filled_field_count=sum(1 for item in fields if item.is_filled),
        fill_rates_available=rates is not None,
        empty=empty,
        empty_reason=empty_reason,
    )

    return FlowExport(
        metadata=metadata,
        fields=fields,
        rows=rows,
        fill_rates_available=rates is not None,
    )


# ---------------------------------------------------------------------------
# Rendus — l'en-tête accompagne le fichier dans LES DEUX formats
# ---------------------------------------------------------------------------


def render_json(export: FlowExport) -> str:
    """Rend l'export en JSON — le format qui préserve les types.

    Structure : `metadata` (l'en-tête auto-portant), `fields` (TOUS les champs
    avec leur taux, y compris ceux à 0 %), `flows` (les lignes). L'ordre est
    délibéré : celui qui ouvre le fichier lit d'abord DE QUOI il parle.
    """
    charge = {
        "metadata": export.metadata.as_dict(),
        "fields": [
            {
                "name": item.name,
                "label": item.label,
                "type": item.clickhouse_type,
                "origin": item.origin,
                "origin_label": item.origin_label,
                "category": item.category,
                "fill_rate": item.fill_rate,
                "filled": item.is_filled,
            }
            for item in export.fields
        ],
        "flows": export.rows,
    }
    return json.dumps(charge, ensure_ascii=False, indent=2, default=str)


def render_csv(export: FlowExport) -> str:
    """Rend l'export en CSV — pour trier/annoter en tableur pendant la qualif.

    L'en-tête de métadonnées est écrit en LIGNES DE COMMENTAIRE préfixées `#`,
    avant la ligne d'en-têtes de colonnes. C'est le seul moyen de rendre un CSV
    auto-portant sans casser sa lecture : tous les tableurs et `csv.reader`
    savent ignorer ces lignes, alors qu'un second tableau collé au-dessus
    décalerait toutes les colonnes.

    Le taux de remplissage par champ est inclus dans ce bloc de commentaires —
    y compris les champs à 0 %, qui sont l'information de qualification.
    """
    buffer = io.StringIO()
    meta = export.metadata

    buffer.write("# Okvorado — export de flux (qualification d'equipement)\n")
    buffer.write(f"# version du schema: {meta.schema_version}\n")
    buffer.write(f"# genere le: {meta.generated_at}\n")
    buffer.write(f"# exportateur: {meta.exporter_display}\n")
    buffer.write(f"# periode: {meta.window} ({meta.window_seconds} s)\n")
    buffer.write(f"# limite appliquee: {meta.applied_limit} (demandee: {meta.requested_limit})\n")
    buffer.write(f"# flux exportes: {meta.flow_count}\n")
    buffer.write(f"# champs du schema: {meta.field_count}\n")

    if meta.empty:
        # ZÉRO SILENCIEUX : un fichier sans lignes DIT pourquoi il n'en a pas.
        buffer.write("# ATTENTION: aucun flux dans cet export.\n")
        buffer.write(f"# {meta.empty_reason}\n")

    if export.fill_rates_available:
        buffer.write(f"# champs renseignes: {meta.filled_field_count} / {meta.field_count}\n")
        buffer.write(f"# taux de remplissage par champ ({FILL_RATE_WINDOW_NOTE}):\n")
        for item in export.fields:
            buffer.write(
                f"#   {item.name};{item.clickhouse_type};{item.origin_label};"
                f"{item.fill_rate_display}\n"
            )
    else:
        # Ne JAMAIS écrire « 0 % » ici : ce serait une mesure inventée.
        buffer.write(
            "# taux de remplissage: NON MESURE (aucun flux a mesurer sur ce "
            "perimetre) — a ne pas lire comme 0 %\n"
        )

    buffer.write("#\n")

    # Les colonnes viennent du schéma, pas des lignes : un export vide conserve
    # ainsi ses en-têtes, et un champ absent des lignes reste visible.
    entetes = [item.name for item in export.fields]
    writer = csv.writer(buffer, delimiter=";", lineterminator="\n")
    writer.writerow(entetes)
    for row in export.rows:
        writer.writerow([_csv_cell(row.get(nom)) for nom in entetes])

    return buffer.getvalue()


def _csv_cell(value: Any) -> str:
    """Aplati une valeur pour une cellule CSV.

    `None` devient une cellule VIDE et non « 0 » ni « null » : la cellule vide
    est la représentation honnête d'un champ non renseigné par l'équipement.
    """
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    return str(value)


def export_filename(export: FlowExport, fmt: str) -> str:
    """Nom de fichier PARLANT — le fichier sera reçu hors contexte.

    « export.csv » dans un dossier de téléchargements ne dit rien. Le nom porte
    donc l'équipement et la fenêtre, comme l'en-tête interne.
    """
    _validate_format(fmt)
    cible = export.metadata.exporter_address or "tous"
    cible = "".join(c if c.isalnum() or c in "-." else "-" for c in cible)
    horodatage = export.metadata.generated_at.replace(":", "").replace("-", "")[:15]
    return f"okvorado-flux-{cible}-{export.metadata.window}-{horodatage}.{fmt}"


def render_export(export: FlowExport, fmt: str) -> tuple[str, str]:
    """Rend l'export dans le format demandé.

    Returns:
        `(contenu, media_type)`.

    Raises:
        ValueError: format hors énumération fermée.
    """
    _validate_format(fmt)
    if fmt == "json":
        return render_json(export), "application/json; charset=utf-8"
    return render_csv(export), "text/csv; charset=utf-8"


__all__ = [
    "DEFAULT_EXPORT_LIMIT",
    "EXPORT_FORMATS",
    "LIMIT_CHOICES",
    "MAX_EXPORT_LIMIT",
    "SCHEMA_VERSION",
    "WINDOW_CHOICES",
    "ExportField",
    "ExportMetadata",
    "ExportableDevice",
    "FlowExport",
    "FlowExportUnavailableError",
    "build_export",
    "build_export_fill_rate_query",
    "build_exporters_query",
    "build_flow_export_query",
    "export_filename",
    "fetch_export_fill_rates",
    "list_exportable_devices",
    "normalize_exporter_address",
    "render_csv",
    "render_export",
    "render_json",
]
