"""Découverte des champs de flux disponibles, à partir d'un ÉCHANTILLON réel.

CONFIG_HARDCODE_OK: les IP/valeurs citées dans les docstrings ci-dessous sont des
illustrations de FORME de donnée (relevées le 2026-08-06 sur la vraie base), pas
des valeurs d'infra contactées par ce module. Le host ClickHouse vient du client
injecté, jamais d'ici.

À QUOI CE MODULE SERT : deux écrans (composition d'une vue Visualize, composition
d'un filtre façon Palo Alto) ont besoin de répondre à « quels champs puis-je
utiliser, et qu'y a-t-il DEDANS ? ». La liste des 61 colonnes seule n'aide
personne : un opérateur ne sait pas si `ExporterName` contient « proxy-frontal » sans
regarder. On lit donc un échantillon borné des derniers flux et on en dérive les
champs AVEC leurs valeurs réellement observées.

TROIS GARDES STRUCTURANTES :

1. **Requête bornée, toujours.** `default.flows` compte ~60 M de lignes (mesuré le
   2026-08-06 : 59 905 288). Un `SELECT` sans `LIMIT` sur cette table est un
   incident de production, pas une requête lente. Le `LIMIT` est obligatoire et
   plafonné à `MAX_SAMPLE_LIMIT`, et la fenêtre temporelle ne peut venir que de
   la table fermée `WINDOW_CHOICES` (via `window_to_seconds()`).

2. **Requête paramétrée exclusivement** (garde n°1 du projet, cf.
   `app/clients/clickhouse.py`). Les noms de colonnes sont des littéraux en dur
   construits depuis `FLOW_COLUMNS` — jamais dérivés d'une saisie. La fenêtre et
   la limite transitent en paramètres liés (`{p:UInt32}`).

3. **Pas de zéro silencieux.** `[]` ne doit JAMAIS signifier à la fois « aucun
   flux dans la fenêtre » et « la requête n'a pas abouti ». Le premier cas est une
   mesure (les exportateurs sont muets, information exploitable), le second est
   une absence de mesure. Les fusionner, c'est le défaut fondateur du projet
   (« RAS, 0 paquet » avec 56 MAJ en attente). Ici : `fetch_flow_sample()` LÈVE
   `FlowSampleUnavailableError` quand la requête échoue, et retourne `[]` — sans
   exception — quand la fenêtre est réellement vide. L'appelant est donc obligé
   syntaxiquement de distinguer les deux.
"""

from __future__ import annotations

import ipaddress
import logging
import unicodedata
from collections import Counter
from dataclasses import dataclass, field

from clickhouse_connect.driver.client import Client

from app.config import window_to_seconds

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Bornes de la requête
# ---------------------------------------------------------------------------

DEFAULT_SAMPLE_LIMIT = 200
"""Taille d'échantillon par défaut : assez pour voir les valeurs courantes de
chaque champ, assez petit pour que la requête reste instantanée."""

MAX_SAMPLE_LIMIT = 1000
"""Plafond DUR. Une valeur supérieure demandée par un appelant est ramenée à ce
plafond plutôt que refusée : le but est de rendre impossible la requête
non bornée, pas de faire échouer un écran pour un paramètre trop généreux."""

MAX_SAMPLE_VALUES = 12
"""Nombre de valeurs distinctes exposées par champ. Au-delà, une liste de valeurs
cesse d'aider à choisir et devient un mur de texte dans l'UI. `distinct_count`
reste, lui, le compte COMPLET observé dans l'échantillon — il ne faut pas que
l'utilisateur croie qu'il n'existe que 12 ports."""


class FlowSampleUnavailableError(RuntimeError):
    """La requête d'échantillonnage n'a pas abouti.

    Distincte d'un échantillon vide, DÉLIBÉRÉMENT : « la requête a échoué » et
    « aucun flux dans la dernière heure » sont deux états que l'opérateur doit
    pouvoir séparer. Le premier appelle un diagnostic technique, le second un
    diagnostic d'exportateur. Retourner `[]` pour les deux ferait passer une
    collecte en défaut pour un réseau calme.
    """


# ---------------------------------------------------------------------------
# Typologie des champs
# ---------------------------------------------------------------------------

FIELD_KIND_IP = "ip"
FIELD_KIND_PORT = "port"
FIELD_KIND_ASN = "asn"
FIELD_KIND_TEXT = "text"
FIELD_KIND_NUMBER = "number"
FIELD_KIND_TIME = "time"
FIELD_KIND_BOOL = "bool"
FIELD_KIND_LIST = "list"
"""`list` = colonne ClickHouse `Array(...)` (`DstASPath`, `DstCommunities`,
`DstLargeCommunities`). Ce n'est pas un `text` : une valeur multiple ne se compare
pas avec `=` et ne s'agrège pas comme une dimension (voir `dimensionable`)."""


@dataclass(frozen=True)
class FlowField:
    """Un champ de flux disponible, avec ce qu'on a réellement vu dedans.

    `sample_values` est ordonné par FRÉQUENCE DÉCROISSANTE dans l'échantillon, pas
    alphabétiquement : ce qui aide à composer une vue, c'est de voir d'abord ce qui
    domine le trafic. Il est tronqué à `MAX_SAMPLE_VALUES` alors que
    `distinct_count` compte tout l'échantillon — sinon un champ à 300 valeurs
    passerait pour un champ à 12 valeurs.
    """

    name: str
    label: str
    kind: str
    sample_values: list[str] = field(default_factory=list)
    distinct_count: int = 0
    filterable: bool = True
    dimensionable: bool = True
    searchable_values: tuple[str, ...] = ()
    """TOUTES les valeurs vues, pour la RECHERCHE — jamais pour l'affichage.

    DÉFAUT MESURÉ (2026-08-06) : `search_fields` cherchait dans
    `sample_values`, déjà tronqué à `MAX_SAMPLE_VALUES`. Sur `SrcAddr`, 12
    valeurs sur 26 étaient conservées, et une adresse RÉELLEMENT présente dans
    l'échantillon — hors du top 12 — était introuvable. L'écran répondait
    « Aucun champ ne correspond » pour une machine qui émettait des flux à cet
    instant précis.

    Chercher et afficher n'ont pas les mêmes contraintes : afficher 300 valeurs
    est illisible, ne pouvoir en chercher que 12 rend l'écran menteur. D'où
    deux listes, et non un compromis sur une seule.
    """

    @property
    def truncated(self) -> bool:
        """Vrai si l'échantillon contient plus de valeurs que celles exposées.

        Permet à l'UI d'afficher « … et N autres » au lieu de laisser croire que
        la liste est exhaustive.
        """
        return self.distinct_count > len(self.sample_values)


@dataclass(frozen=True)
class FlowColumn:
    """Descripteur STATIQUE d'une colonne de `default.flows`.

    Les types sont ceux MESURÉS le 2026-08-06 via `system.columns` sur la base
    réelle, pas ceux supposés depuis la documentation Akvorado. Cette table est la
    seule source des noms de colonnes injectés dans le SQL : ce sont donc toujours
    des littéraux du code, jamais une saisie utilisateur.
    """

    name: str
    label: str
    kind: str
    clickhouse_type: str
    dimensionable: bool = True
    filterable: bool = True


# Les 61 colonnes de `default.flows`, dans l'ordre de position réel.
#
# 61, PAS 60 : le compte a été vérifié contre `system.columns` le 2026-08-06
# (`SELECT count() FROM system.columns WHERE table = 'flows'` -> 61). La
# spécification initiale annonçait « 60 colonnes » tout en en énumérant 61 —
# recopier le chiffre annoncé plutôt que de compter la source de vérité aurait
# fait disparaître un champ légitime de l'UI. `EXPECTED_FLOW_COLUMN_COUNT` fige
# ce constat pour qu'un ajout/retrait de colonne casse un test au lieu de passer.
#
# Les libellés FR sont le CŒUR de l'utilité de cet écran : `InIfBoundary` ne dit
# rien à un opérateur, « Frontière interface entrante » si. Sans eux, la liste des
# champs n'est qu'une copie du schéma ClickHouse, que l'opérateur pouvait déjà lire
# ailleurs — l'écran n'apporterait rien.
FLOW_COLUMNS: tuple[FlowColumn, ...] = (
    FlowColumn("TimeReceived", "Date de réception", FIELD_KIND_TIME, "DateTime"),
    FlowColumn("SamplingRate", "Taux d'échantillonnage", FIELD_KIND_NUMBER, "UInt64"),
    FlowColumn(
        "ExporterAddress", "Adresse de l'exportateur", FIELD_KIND_IP, "LowCardinality(IPv6)"
    ),
    FlowColumn("ExporterName", "Nom de l'exportateur", FIELD_KIND_TEXT, "LowCardinality(String)"),
    FlowColumn("ExporterGroup", "Groupe d'exportateurs", FIELD_KIND_TEXT, "LowCardinality(String)"),
    FlowColumn("ExporterRole", "Rôle de l'exportateur", FIELD_KIND_TEXT, "LowCardinality(String)"),
    FlowColumn("ExporterSite", "Site de l'exportateur", FIELD_KIND_TEXT, "LowCardinality(String)"),
    FlowColumn(
        "ExporterRegion", "Région de l'exportateur", FIELD_KIND_TEXT, "LowCardinality(String)"
    ),
    FlowColumn(
        "ExporterTenant", "Locataire de l'exportateur", FIELD_KIND_TEXT, "LowCardinality(String)"
    ),
    FlowColumn("SrcAddr", "Adresse source", FIELD_KIND_IP, "IPv6"),
    FlowColumn("DstAddr", "Adresse destination", FIELD_KIND_IP, "IPv6"),
    FlowColumn("SrcNetMask", "Masque réseau source", FIELD_KIND_NUMBER, "UInt8"),
    FlowColumn("DstNetMask", "Masque réseau destination", FIELD_KIND_NUMBER, "UInt8"),
    FlowColumn("SrcNetPrefix", "Préfixe réseau source", FIELD_KIND_TEXT, "String"),
    FlowColumn("DstNetPrefix", "Préfixe réseau destination", FIELD_KIND_TEXT, "String"),
    FlowColumn("SrcAS", "AS source", FIELD_KIND_ASN, "UInt32"),
    FlowColumn("DstAS", "AS destination", FIELD_KIND_ASN, "UInt32"),
    FlowColumn("SrcNetName", "Nom du réseau source", FIELD_KIND_TEXT, "LowCardinality(String)"),
    FlowColumn(
        "DstNetName", "Nom du réseau destination", FIELD_KIND_TEXT, "LowCardinality(String)"
    ),
    FlowColumn("SrcNetRole", "Rôle du réseau source", FIELD_KIND_TEXT, "LowCardinality(String)"),
    FlowColumn(
        "DstNetRole", "Rôle du réseau destination", FIELD_KIND_TEXT, "LowCardinality(String)"
    ),
    FlowColumn("SrcNetSite", "Site du réseau source", FIELD_KIND_TEXT, "LowCardinality(String)"),
    FlowColumn(
        "DstNetSite", "Site du réseau destination", FIELD_KIND_TEXT, "LowCardinality(String)"
    ),
    FlowColumn(
        "SrcNetRegion", "Région du réseau source", FIELD_KIND_TEXT, "LowCardinality(String)"
    ),
    FlowColumn(
        "DstNetRegion", "Région du réseau destination", FIELD_KIND_TEXT, "LowCardinality(String)"
    ),
    FlowColumn(
        "SrcNetTenant", "Locataire du réseau source", FIELD_KIND_TEXT, "LowCardinality(String)"
    ),
    FlowColumn(
        "DstNetTenant", "Locataire du réseau destination", FIELD_KIND_TEXT, "LowCardinality(String)"
    ),
    FlowColumn("SrcCountry", "Pays source", FIELD_KIND_TEXT, "FixedString(2)"),
    FlowColumn("DstCountry", "Pays destination", FIELD_KIND_TEXT, "FixedString(2)"),
    FlowColumn("SrcGeoCity", "Ville source", FIELD_KIND_TEXT, "LowCardinality(String)"),
    FlowColumn("DstGeoCity", "Ville destination", FIELD_KIND_TEXT, "LowCardinality(String)"),
    FlowColumn(
        "SrcGeoState", "Région géographique source", FIELD_KIND_TEXT, "LowCardinality(String)"
    ),
    FlowColumn(
        "DstGeoState", "Région géographique destination", FIELD_KIND_TEXT, "LowCardinality(String)"
    ),
    # Array(UInt32) : chemin d'AS complet. Ni dimension ni filtre d'égalité.
    FlowColumn(
        "DstASPath",
        "Chemin d'AS destination",
        FIELD_KIND_LIST,
        "Array(UInt32)",
        dimensionable=False,
        filterable=False,
    ),
    FlowColumn("Dst1stAS", "1er AS du chemin destination", FIELD_KIND_ASN, "UInt32"),
    FlowColumn("Dst2ndAS", "2e AS du chemin destination", FIELD_KIND_ASN, "UInt32"),
    FlowColumn("Dst3rdAS", "3e AS du chemin destination", FIELD_KIND_ASN, "UInt32"),
    FlowColumn(
        "DstCommunities",
        "Communautés BGP destination",
        FIELD_KIND_LIST,
        "Array(UInt32)",
        dimensionable=False,
        filterable=False,
    ),
    FlowColumn(
        "DstLargeCommunities",
        "Grandes communautés BGP destination",
        FIELD_KIND_LIST,
        "Array(UInt128)",
        dimensionable=False,
        filterable=False,
    ),
    FlowColumn("InIfName", "Interface entrante", FIELD_KIND_TEXT, "LowCardinality(String)"),
    FlowColumn("OutIfName", "Interface sortante", FIELD_KIND_TEXT, "LowCardinality(String)"),
    FlowColumn(
        "InIfDescription",
        "Description interface entrante",
        FIELD_KIND_TEXT,
        "LowCardinality(String)",
    ),
    FlowColumn(
        "OutIfDescription",
        "Description interface sortante",
        FIELD_KIND_TEXT,
        "LowCardinality(String)",
    ),
    FlowColumn("InIfSpeed", "Débit interface entrante", FIELD_KIND_NUMBER, "UInt32"),
    FlowColumn("OutIfSpeed", "Débit interface sortante", FIELD_KIND_NUMBER, "UInt32"),
    FlowColumn(
        "InIfConnectivity",
        "Connectivité interface entrante",
        FIELD_KIND_TEXT,
        "LowCardinality(String)",
    ),
    FlowColumn(
        "OutIfConnectivity",
        "Connectivité interface sortante",
        FIELD_KIND_TEXT,
        "LowCardinality(String)",
    ),
    FlowColumn(
        "InIfProvider", "Opérateur interface entrante", FIELD_KIND_TEXT, "LowCardinality(String)"
    ),
    FlowColumn(
        "OutIfProvider", "Opérateur interface sortante", FIELD_KIND_TEXT, "LowCardinality(String)"
    ),
    FlowColumn("InIfBoundary", "Frontière interface entrante", FIELD_KIND_TEXT, "Enum8"),
    FlowColumn("OutIfBoundary", "Frontière interface sortante", FIELD_KIND_TEXT, "Enum8"),
    FlowColumn("EType", "Type Ethernet", FIELD_KIND_NUMBER, "UInt32"),
    FlowColumn("Proto", "Protocole", FIELD_KIND_NUMBER, "UInt32"),
    FlowColumn("SrcPort", "Port source", FIELD_KIND_PORT, "UInt16"),
    FlowColumn("DstPort", "Port destination", FIELD_KIND_PORT, "UInt16"),
    # Métriques : agrégées par Akvorado, pas des axes de découpage.
    FlowColumn("Bytes", "Octets", FIELD_KIND_NUMBER, "UInt64", dimensionable=False),
    FlowColumn("Packets", "Paquets", FIELD_KIND_NUMBER, "UInt64", dimensionable=False),
    FlowColumn("PacketSize", "Taille de paquet", FIELD_KIND_NUMBER, "UInt64", dimensionable=False),
    FlowColumn(
        "PacketSizeBucket",
        "Tranche de taille de paquet",
        FIELD_KIND_TEXT,
        "LowCardinality(String)",
    ),
    FlowColumn("ForwardingStatus", "Statut de transmission", FIELD_KIND_NUMBER, "UInt32"),
    FlowColumn("FlowDirection", "Sens du flux", FIELD_KIND_TEXT, "Enum8"),
)

EXPECTED_FLOW_COLUMN_COUNT = 61
"""Nombre de colonnes de `default.flows`, MESURÉ sur la base réelle le 2026-08-06.

Constante et non commentaire : un test l'oppose à `len(FLOW_COLUMNS)`, donc une
colonne oubliée à la recopie casse la CI au lieu de disparaître en silence de
l'UI. C'est exactement ce qui a failli arriver ici (spec annonçant 60 pour 61
colonnes réelles)."""

_COLUMNS_BY_NAME: dict[str, FlowColumn] = {column.name: column for column in FLOW_COLUMNS}

# `TimeReceived` est déclaré non-dimensionnable ici plutôt que dans la table, pour
# garder la table lisible colonne par colonne. C'est l'axe X de tout graphe de
# flux : l'offrir comme dimension de découpage n'a aucun sens métier.
_NON_DIMENSIONABLE_EXTRA: frozenset[str] = frozenset({"TimeReceived"})


def _column_dimensionable(column: FlowColumn) -> bool:
    """RÈGLE `dimensionable` — le champ peut-il être un axe de découpage d'un graphe ?

    Trois exclusions, toutes dérivées du TYPE ou du RÔLE réel de la colonne :

    1. **Les `Array(...)`** (`DstASPath`, `DstCommunities`, `DstLargeCommunities`).
       Un flux porte N valeurs : « grouper par chemin d'AS » n'a pas de sens, la
       même ligne appartiendrait à N groupes. Akvorado les traite d'ailleurs avec
       des opérateurs dédiés, pas comme des dimensions.
    2. **Les métriques** (`Bytes`, `Packets`, `PacketSize`). Ce sont les valeurs
       AGRÉGÉES du graphe (l'axe Y), pas des catégories. Grouper par `Bytes`
       produirait une série par taille de flux distincte.
    3. **L'axe temporel** (`TimeReceived`), qui est déjà l'axe X.

    Tout le reste est dimensionnable : y compris les champs à forte cardinalité
    comme `SrcAddr` ou `SrcPort` — Akvorado sait les tronquer en « top N », et les
    interdire priverait l'opérateur du cas d'usage le plus courant (« qui parle le
    plus »).
    """
    return column.dimensionable and column.name not in _NON_DIMENSIONABLE_EXTRA


def _column_filterable(column: FlowColumn) -> bool:
    """RÈGLE `filterable` — le champ peut-il apparaître dans une expression de filtre ?

    Une seule exclusion : les colonnes `Array(...)`. Une expression de filtre
    Akvorado compare une valeur scalaire (`SrcAS = 64501`, `InIfName IN (...)`) ;
    une colonne multivaluée ne se compare pas avec ces opérateurs et produirait une
    expression rejetée par Akvorado — donc un filtre proposé par l'UI qui échoue à
    l'exécution, le pire des deux mondes.

    `TimeReceived` reste filtrable, lui : borner une période est un filtre légitime
    (c'est seulement comme DIMENSION qu'il n'a pas de sens).
    """
    return column.filterable


# ---------------------------------------------------------------------------
# Requête d'échantillonnage
# ---------------------------------------------------------------------------


def _clamp_limit(limit: int) -> int:
    """Ramène la limite dans `[1, MAX_SAMPLE_LIMIT]`.

    Le plafond est la garde qui rend la requête non bornée IMPOSSIBLE, pas une
    simple valeur par défaut : `default.flows` compte ~60 M de lignes (mesuré le
    2026-08-06), un `LIMIT` absent ou démesuré n'est pas une requête lente mais un
    incident de production. Une limite <= 0 est ramenée à 1 plutôt que de produire
    un `LIMIT 0` : un échantillon vide serait indistinguable d'une fenêtre sans
    flux, exactement le zéro silencieux que ce module refuse.
    """
    if limit < 1:
        return 1
    return min(limit, MAX_SAMPLE_LIMIT)


def build_flow_sample_query(
    *, limit: int = DEFAULT_SAMPLE_LIMIT, window: str = "1h"
) -> tuple[str, dict[str, int]]:
    """Construit la requête d'échantillonnage des derniers flux.

    Args:
        limit: taille d'échantillon souhaitée, plafonnée par `_clamp_limit()`.
        window: fenêtre de l'UI (`WINDOW_CHOICES` : "1h", "6h", "24h", "7d").
            Toute autre valeur lève `ValueError` AVANT d'atteindre le SQL —
            garde plus forte qu'un simple échappement : la valeur est refusée.

    Returns:
        `(sql, parameters)`. Le SQL ne contient ni fenêtre ni limite interpolées :
        les deux transitent en paramètres liés. Les noms de colonnes viennent de
        `FLOW_COLUMNS`, littéraux du code, jamais d'une saisie.

    Raises:
        ValueError: fenêtre hors de la table fermée `WINDOW_CHOICES`.
    """
    window_seconds = window_to_seconds(window)
    columns = ",\n    ".join(column.name for column in FLOW_COLUMNS)
    # `toIntervalSecond({p:UInt32})` et non `INTERVAL {p:String}` : ClickHouse
    # refuse un paramètre lié dans une clause INTERVAL (SYNTAX_ERROR mesuré le
    # 2026-08-05, cf. app/clients/clickhouse.py). C'est la seule forme qui
    # conserve la garde anti-injection.
    #
    # `ORDER BY TimeReceived DESC` : l'échantillon doit être celui des flux les
    # plus RÉCENTS. Sans tri, ClickHouse rend les premières lignes lues, qui
    # peuvent venir d'un vieux bloc — on décrirait alors un trafic passé en
    # croyant décrire le trafic courant.
    sql = f"""
SELECT
    {columns}
FROM default.flows
WHERE TimeReceived >= now() - toIntervalSecond({{window_seconds:UInt32}})
ORDER BY TimeReceived DESC
LIMIT {{sample_limit:UInt32}}
"""
    return sql, {"window_seconds": window_seconds, "sample_limit": _clamp_limit(limit)}


def fetch_flow_sample(
    client: Client, *, limit: int = DEFAULT_SAMPLE_LIMIT, window: str = "1h"
) -> list[dict[str, object]]:
    """Lit un échantillon borné des derniers flux et le rend en dictionnaires.

    Args:
        client: client ClickHouse déjà connecté (injecté — jamais construit ici,
            pour que les tests puissent fournir un double sans infra).
        limit: taille d'échantillon, plafonnée à `MAX_SAMPLE_LIMIT`.
        window: fenêtre de l'UI (`WINDOW_CHOICES`).

    Returns:
        Une liste de lignes `{nom_de_colonne: valeur_brute}`. Une liste VIDE
        signifie sans ambiguïté « la requête a abouti et la fenêtre ne contient
        aucun flux » — c'est une mesure exploitable (les exportateurs sont muets),
        pas une panne.

    Raises:
        FlowSampleUnavailableError: la requête n'a pas pu aboutir (erreur de
            connexion, table absente, timeout). PAS de `[]` dans ce cas : « je
            n'ai pas pu mesurer » doit rester distinct de « j'ai mesuré zéro »,
            sinon une collecte en défaut s'affiche comme un réseau calme (défaut
            fondateur du projet, cf. docstring de module).
        ValueError: fenêtre invalide (rejetée avant tout accès au réseau).
    """
    sql, parameters = build_flow_sample_query(limit=limit, window=window)
    try:
        result = client.query(sql, parameters=parameters)
    except Exception as exc:
        log.error(
            "echec requete clickhouse fetch_flow_sample window=%s limit=%s",
            window,
            parameters["sample_limit"],
            exc_info=True,
        )
        raise FlowSampleUnavailableError(
            f"echantillon de flux non recupere (fenetre={window}): {exc}"
        ) from exc

    column_names = list(result.column_names)
    return [dict(zip(column_names, row, strict=False)) for row in result.result_rows]


# ---------------------------------------------------------------------------
# Normalisation des valeurs brutes
# ---------------------------------------------------------------------------


def format_display_address(value: object) -> str:
    """Rend une adresse IP lisible pour un exploitant réseau — fonction PARTAGÉE
    de formatage d'affichage, à utiliser PARTOUT où une adresse est rendue
    (convergence, drill-down, onglets Sources/Destinations/Conversations de
    l'écran exportateur — cf. `app/templating.py` où elle est exposée comme
    filtre Jinja `format_ip`).

    CONFIG_HARDCODE_OK: l'adresse `198.51.100.25` citée ci-dessous est un exemple
    illustratif de FORME de donnée (comme le reste des docstrings de ce
    fichier), pas une adresse d'infra contactée par ce module.

    DÉFAUT MESURÉ À L'ÉCRAN (2026-08-07) : chaque IPv4 s'affichait sous sa
    forme IPv6-mappée, illisible pour un opérateur qui attend la forme v4
    simple. Les colonnes `SrcAddr`/`DstAddr`/`ExporterAddress` sont typées
    `IPv6` : une IPv4 y est stockée mappée (`::ffff:198.51.100.25` — forme
    confirmée sur la vraie base le 2026-08-06).

    PIÈGE VÉRIFIÉ : `cutIPv6(addr, 0, 1)` ne fait PAS ça — mesuré, il TRONQUE
    l'adresse (perd le dernier octet) au lieu de la reformater. Cette fonction
    n'utilise aucune troncature de position : elle passe par `ipaddress` et son
    attribut `ipv4_mapped`, qui distingue correctement une IPv4 mappée d'une
    IPv6 native (il y a de l'IPv6 native dans les données réelles, qui doit
    rester affichée telle quelle).

    Le driver ClickHouse rend un objet `IPv6Address`, pas une chaîne : on passe
    par `ipaddress` plutôt que par un `str.startswith("::ffff:")`, qui
    manquerait les formes équivalentes écrites autrement (`::ffff:c0a8:119`).

    Aucune COMPARAISON entre familles n'est faite ici : Python refuse de comparer
    une IPv4Address à une IPv6Address (`TypeError`), piège déjà rencontré sur ce
    projet côté tri des CIDR. On ne fait que convertir en texte.

    Returns:
        `"—"` si `value` est `None` (cohérent avec `humanize_bytes`/
        `humanize_number` de `app/templating.py`) ; la valeur telle quelle,
        non modifiée, si elle n'est pas une IP parsable (la perdre en silence
        donnerait un champ qui paraît vide alors qu'il contient une donnée
        inattendue — précisément ce qu'il faut voir).
    """
    if value is None:
        return "—"
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return str(value)
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        return str(mapped)
    return str(address)


def _normalize_ip(value: object) -> str:
    """Rend une adresse lisible pour la liste de valeurs proposées à l'opérateur
    (composeur de vue / filtre) : une IPv4 mappée est ramenée à sa forme v4.

    Spécialisation de `format_display_address()` pour ce module : `value` n'est
    ici jamais `None` (les valeurs `None` sont déjà écartées avant l'appel dans
    `_normalize_scalar()`), donc pas besoin du cas `"—"`.
    """
    return format_display_address(value)


def _normalize_fixed_string(value: object) -> str:
    """Nettoie une `FixedString(N)` de son bourrage de NUL.

    MESURÉ le 2026-08-06 sur la vraie base : `SrcCountry`/`DstCountry` sont des
    `FixedString(2)` et un pays inconnu revient en `\\0\\0`, PAS en chaîne vide.
    Sans ce nettoyage, la liste des valeurs de « Pays source » proposait un code
    pays invisible mais non vide — l'opérateur aurait construit un filtre sur des
    octets nuls.

    Le décodage `bytes -> str` est indispensable et vient d'un second défaut,
    vu à l'écran le même jour : le driver ClickHouse rend une `FixedString`
    en **`bytes`**, et `str(b"FR")` produit la chaîne `"b'FR'"` — préfixe et
    guillemets compris. Le compositeur affichait donc des pays sous la forme
    `b'FR'`, `b'US'`, inutilisables dans un filtre : `SrcCountry = b'FR'` n'est
    pas une expression Akvorado valide. Un `str()` sur une valeur binaire est
    toujours suspect ; ici il transformait une donnée juste en donnée fausse,
    sans erreur.
    """
    if isinstance(value, (bytes, bytearray)):
        texte = value.decode("utf-8", errors="replace")
    else:
        texte = str(value)
    return texte.replace("\x00", "").strip()


def _normalize_scalar(value: object, column: FlowColumn) -> str | None:
    """Ramène une valeur brute à sa forme affichable, ou `None` si elle n'apporte rien.

    `None` (valeur absente/vide) est distinct de la chaîne `"0"` : un AS à 0 ou un
    port à 0 signifient « non renseigné » dans les flux Akvorado (constaté sur
    l'échantillon réel : `SrcAS = 0` pour tout le trafic RFC1918). Les proposer
    comme valeurs d'un filtre suggérerait qu'il existe un « AS numéro 0 » à
    filtrer, ce qui est faux.
    """
    if value is None:
        return None

    if column.kind == FIELD_KIND_IP:
        return _normalize_ip(value) or None

    if column.clickhouse_type.startswith("FixedString"):
        return _normalize_fixed_string(value) or None

    if column.kind in (FIELD_KIND_ASN, FIELD_KIND_PORT):
        # 0 = « non renseigné » pour un AS comme pour un port : à écarter, pas à
        # proposer comme valeur filtrable.
        text = str(value).strip()
        return None if text in ("", "0") else text

    return str(value).strip() or None


def _normalize_list(value: object) -> list[str]:
    """Aplatit une colonne `Array(...)` en valeurs individuelles.

    Un chemin d'AS `[3215, 64501]` est présenté comme deux valeurs, pas comme la
    chaîne « [3215, 64501] » : c'est un AS particulier que l'opérateur cherche
    dans le chemin, jamais le chemin complet littéral. Un tableau vide (le cas
    dominant dans l'échantillon réel : `[]` partout hors transit BGP) ne produit
    aucune valeur — et non une valeur « [] » qui polluerait la liste.
    """
    if not isinstance(value, (list, tuple)):
        text = str(value).strip()
        return [text] if text else []
    return [str(item).strip() for item in value if str(item).strip()]


# ---------------------------------------------------------------------------
# Synthèse des champs
# ---------------------------------------------------------------------------


def summarize_fields(rows: list[dict[str, object]]) -> list[FlowField]:
    """Dérive la liste des champs disponibles depuis un échantillon de flux.

    Les 60 champs sont TOUJOURS retournés, même quand l'échantillon est vide ou
    qu'une colonne n'y porte aucune valeur. Ne rendre que les champs « peuplés »
    ferait disparaître de l'UI un champ légitime dès que l'échantillon est calme
    (ex. `DstCommunities`, vide hors transit BGP) : l'opérateur conclurait que le
    champ n'existe pas, alors qu'il n'était qu'absent de 200 lignes. Un champ sans
    valeur observée se distingue par `sample_values == []` et `distinct_count == 0`.

    Args:
        rows: lignes issues de `fetch_flow_sample()`. Les clés inconnues de
            `FLOW_COLUMNS` sont ignorées (une colonne ajoutée par une future
            version d'Akvorado ne doit pas faire échouer l'écran).

    Returns:
        Les champs dans l'ordre des colonnes de la table, chacun portant ses
        valeurs les plus fréquentes d'abord.
    """
    counters: dict[str, Counter[str]] = {column.name: Counter() for column in FLOW_COLUMNS}

    for row in rows:
        for name, raw_value in row.items():
            column = _COLUMNS_BY_NAME.get(name)
            if column is None:
                continue
            if column.kind == FIELD_KIND_LIST:
                counters[name].update(_normalize_list(raw_value))
                continue
            normalized = _normalize_scalar(raw_value, column)
            if normalized is not None:
                counters[name][normalized] += 1

    fields: list[FlowField] = []
    for column in FLOW_COLUMNS:
        counter = counters[column.name]
        # `most_common` ordonne par fréquence décroissante ; à égalité, l'ordre
        # d'insertion (donc de première apparition dans l'échantillon) est
        # conservé — stable d'un appel à l'autre pour un même échantillon.
        top = [value for value, _count in counter.most_common(MAX_SAMPLE_VALUES)]
        fields.append(
            FlowField(
                name=column.name,
                label=column.label,
                kind=column.kind,
                sample_values=top,
                distinct_count=len(counter),
                # TOUTES les valeurs, pour la recherche seule (voir la
                # docstring de `searchable_values`).
                searchable_values=tuple(counter),
                filterable=_column_filterable(column),
                dimensionable=_column_dimensionable(column),
            )
        )
    return fields


# ---------------------------------------------------------------------------
# Recherche
# ---------------------------------------------------------------------------


def _fold(text: str) -> str:
    """Replie une chaîne pour une comparaison insensible à la casse ET aux accents.

    Sans dépliage des accents, chercher « region » ne trouverait pas « Région de
    l'exportateur » — or c'est exactement ce qu'un opérateur tape, un clavier ne
    produisant pas spontanément l'accent en cours de frappe. La forme NFD sépare
    le caractère de son diacritique, que la catégorie `Mn` permet ensuite de
    retirer.
    """
    decomposed = unicodedata.normalize("NFD", text.casefold())
    return "".join(char for char in decomposed if unicodedata.category(char) != "Mn")


def search_fields(fields: list[FlowField], query: str) -> list[FlowField]:
    """Filtre les champs sur le NOM, le LIBELLÉ FR et les VALEURS d'échantillon.

    Chercher dans les VALEURS est ce qui rend l'écran réellement utilisable :
    l'opérateur sait qu'il veut voir le trafic de « proxy-frontal », il ne sait pas que
    cette information vit dans la colonne `ExporterName`. Limiter la recherche aux
    noms de colonnes lui imposerait de connaître le schéma — c'est-à-dire de ne
    plus avoir besoin de l'écran.

    Une requête vide (ou uniquement des espaces) rend TOUS les champs, pas aucun :
    une zone de recherche vierge doit montrer le catalogue complet, pas une page
    blanche.

    L'ordre d'entrée est préservé : le tri des champs relève de la vue, pas d'un
    filtre. Un même champ n'est jamais rendu deux fois, même s'il correspond à la
    fois par son nom et par une de ses valeurs.
    """
    needle = _fold(query.strip())
    if not needle:
        return list(fields)

    matched: list[FlowField] = []
    for item in fields:
        # `searchable_values` et non `sample_values` : ce dernier est tronqué
        # au top 12 pour l'affichage, et chercher dedans rendait invisible
        # toute valeur pourtant présente dans l'échantillon (mesuré sur
        # `SrcAddr`, 12 valeurs gardées sur 26).
        haystack = [item.name, item.label, *item.searchable_values]
        if any(needle in _fold(part) for part in haystack):
            matched.append(item)
    return matched
