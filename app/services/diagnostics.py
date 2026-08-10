"""Diagnostics réseau — construit du SQL de convergence et d'analyse par exportateur.

PLAGES INTERNES = RÉGLAGE, PAS CONSTANTE (correction du 2026-08-10). Ce module
portait auparavant les plages « internes » en dur, sous un `CONFIG_HARDCODE_OK`
qui les justifiait comme « préfixes RFC universels ». L'utilisateur a tranché,
et il a raison : la RFC définit ce qui EST privé, elle ne dit pas ce que CE
déploiement utilise. Le homelab est en 192.168/16 + CGNAT 100.64/10 (adressage
Tailscale) ; un parc d'entreprise — la cible du produit, 350 routeurs — sera
typiquement en 10/8 sans aucun CGNAT. Écrites en dur, ces bornes rendaient le
filtre de convergence FAUX chez le client, sans le moindre message d'erreur.
Elles viennent désormais de `OKVORADO_INTERNAL_NETWORKS` (voir `build_internal_filter`
et `app.config.parse_internal_networks`), avec pour défaut le comportement
antérieur exact.

Reste en dur, et c'est justifié : `224.0.0.0/4` (multicast IPv4). Ce n'est pas
une plage « à soi » qu'un exploitant choisit — c'est une classe d'adresses dont
la SÉMANTIQUE est fixée par la RFC (un envoi multicast n'est pas un flux
unicast convergent, quel que soit le plan d'adressage du site).

CAS D'USAGE CIBLE (verbatim utilisateur) : « l'équipe windows a envoyé par GPO
l'installer d'un logiciel depuis 160 sites vers un datacenter » — on veut voir N
sources qui convergent en masse vers UNE destination, sans savoir à l'avance quoi
chercher. C'est `build_convergence_query()` qui répond à ce besoin.

Ce module ne fait AUCUNE I/O : chaque fonction publique CONSTRUIT une requête SQL
et ses paramètres, et les RENVOIE sous forme `(sql, parameters)`. C'est ce qui les
rend testables sans ClickHouse (cf. `tests/test_diagnostics.py`) — exactement le
contrat déjà en place dans `app/clients/clickhouse.py` et `app/routers/views.py`,
que ce module réutilise plutôt que réinvente.

GARDE SÉCU N°1 DU PROJET (non négociable — cf. CONTRACT.md et les modules cités
ci-dessus) : Okvorado devient une app de requêtage exposée en entreprise, donc une
nouvelle surface d'attaque. Trois règles tiennent tout ce fichier :

1. **Aucune valeur utilisateur n'est concaténée dans le SQL.** IP, ports, noms
   d'exportateur : tous passés en paramètre lié ClickHouse (`{nom:Type}`).
2. **Noms de colonnes/tables en dur.** Quand un écran doit choisir une dimension
   (ex. « top par quoi ? »), elle passe par `EXPORTER_DIMENSION_ALLOWLIST` : une
   valeur hors allowlist lève `ValueError`, jamais interpolée.
3. **Période bornée par une énumération fermée** (`DIAGNOSTIC_PERIOD_CHOICES`),
   `LIMIT` toujours présent et plafonné dur (`MAX_CONVERGENCE_LIMIT`). La table
   brute sert aussi la console Akvorado : une requête non bornée peut la faire
   tomber (cf. `app/services/flow_sample.py`, même garde).

MESURES DÉCISIVES (prod, 2026-08-07, à ne pas refaire ni contredire sans mesurer) :

- **n°1 — la vue naïve ne détecte pas le motif recherché.** Un simple
  `GROUP BY DstAddr ORDER BY uniqExact(SrcAddr) DESC` remonte en tête
  `198.51.100.9` avec 1071 sources… dont 1059 EXTERNES (scan de ports Internet),
  et `198.51.100.51` avec 217 sources sur le port 41641 (maillage P2P Tailscale).
  Le filtre suivant, mesuré comme discriminant, sépare le vrai motif du bruit :
  source INTERNE (RFC1918 + CGNAT 100.64/10), destination UNICAST (hors multicast
  224.0.0.0/4), `DstPort` hors ICMP/fragments et hors ports éphémères clients
  (`0 < DstPort < 32768`), `Proto IN (6, 17)` (TCP/UDP uniquement).
- **n°2 — les tables d'agrégat sont inutilisables ici.** `flows_1m0s`, `flows_5m0s`,
  `flows_1h0m0s` ne portent que `SamplingRate` et `Bytes`, PAS `SrcAddr`/`DstAddr`/
  `DstPort`. Toute requête de convergence ou de drill-down DOIT taper la table
  brute `default.flows`.
- **n°3 — coût mesuré sur la table brute** : 1h -> 0,112 s ; 24h -> 0,400 s ;
  7j -> 1,86 s ; 30j -> 2,55 s. C'est ce qui justifie une énumération de périodes
  allant jusqu'à 30j sans mettre la base en danger, contrairement à un nombre de
  jours libre.

`sum(Bytes * SamplingRate)`, JAMAIS `sum(Bytes)` seul : cf. la docstring de
`app/clients/clickhouse.py` et `tests/test_sampling_rate.py`, qui échoue
mécaniquement si cette règle est oubliée. `count()` n'est JAMAIS mis à l'échelle :
il mesure des flux observés, pas du trafic.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.config import parse_internal_networks, settings

# ---------------------------------------------------------------------------
# Bornes communes — énumération fermée de périodes, plafond dur de LIMIT
# ---------------------------------------------------------------------------

DIAGNOSTIC_PERIOD_CHOICES: tuple[str, ...] = ("1h", "6h", "24h", "7d", "30d")
"""Périodes proposées aux écrans de diagnostic — énumération FERMÉE.

Pas de nombre de jours libre venant de l'utilisateur : la table brute `flows`
sert aussi la console Akvorado, une requête non bornée peut la faire tomber.
Bornes mesurées le 2026-08-07 (jusqu'à 30j -> 2,55 s), cf. docstring de module."""

_PERIOD_TO_SECONDS: dict[str, int] = {
    "1h": 3600,
    "6h": 21600,
    "24h": 86400,
    "7d": 604800,
    "30d": 2592000,
}

MAX_CONVERGENCE_LIMIT = 500
"""Plafond DUR sur tout `LIMIT` de ce module. Un appelant qui demande plus est
ramené à ce plafond plutôt que refusé (même choix que `flow_sample._clamp_limit` :
le but est de rendre la requête non bornée IMPOSSIBLE, pas de faire échouer
l'écran pour un paramètre trop généreux)."""

DEFAULT_CONVERGENCE_LIMIT = 50
DEFAULT_MIN_SOURCES = 5
"""Seuil par défaut de sources distinctes pour qu'une destination soit retenue
comme motif de convergence — évite qu'un simple couple (1 source, 1 destination)
noie le classement."""


def _validate_period(period: str) -> int:
    """Valide la période contre l'énumération fermée et rend sa durée en secondes.

    Raises:
        ValueError: si `period` n'est pas dans `DIAGNOSTIC_PERIOD_CHOICES`.
    """
    try:
        return _PERIOD_TO_SECONDS[period]
    except KeyError:
        raise ValueError(
            f"periode invalide: {period!r} (attendu: {', '.join(DIAGNOSTIC_PERIOD_CHOICES)})"
        ) from None


def _clamp_limit(limit: int) -> int:
    """Ramène `limit` dans `[1, MAX_CONVERGENCE_LIMIT]`.

    Une valeur <= 0 est ramenée à 1 plutôt qu'à un `LIMIT 0` : un résultat vide
    doit rester une MESURE (aucune convergence dans la fenêtre), pas un artefact
    de requête mal bornée."""
    if limit < 1:
        return 1
    return min(limit, MAX_CONVERGENCE_LIMIT)


# ---------------------------------------------------------------------------
# Filtre de convergence — cf. mesure décisive n°1
# ---------------------------------------------------------------------------

def build_internal_filter(colonne: str, plages: Sequence[str] | None = None) -> str:
    """Construit le filtre « adresse dans le réseau INTERNE » pour une colonne.

    Les plages viennent de la CONFIGURATION (`OKVORADO_INTERNAL_NETWORKS`), plus
    du code — décision utilisateur du 2026-08-10 qui corrige une erreur de
    conception : ces bornes étaient écrites en dur ici sous prétexte que
    « ce sont des préfixes RFC, donc universels ». La RFC définit ce qui EST
    privé ; elle ne dit pas ce que CE déploiement utilise. Le homelab est en
    192.168/16 + CGNAT 100.64/10 (Tailscale) ; un parc d'entreprise sera
    typiquement en 10/8 sans aucun CGNAT. Codé en dur, ce filtre — celui qui
    sépare le vrai motif du bruit (mesure décisive n°1) — classerait mal le
    trafic du client, et l'écran afficherait un résultat FAUX sans le dire.

    `colonne` est un littéral choisi par l'appelant (`SrcAddr`/`DstAddr`),
    JAMAIS une valeur utilisateur : garde sécu n°1 du projet. Les plages sont
    validées puis rendues sous forme de bornes littérales — elles viennent de
    la configuration de l'exploitant, pas d'une requête HTTP, et un CIDR validé
    par `ipaddress` ne peut pas porter d'injection.

    Comparaison par bornes plutôt que `isIPAddressInRange()` : la colonne est
    `IPv6` avec les IPv4 mappées `::ffff:x.x.x.x` (cf. CONTRACT.md et
    `app/clients/clickhouse.py::normalize_exporter_address`), et une comparaison
    de bornes sur la forme mappée reste valide car l'ordre lexicographique des
    IPv6 mappées préserve l'ordre numérique des IPv4 qu'elles encodent.

    Lève `ValueError` sur une plage invalide ou une liste vide (voir
    `app.config.parse_internal_networks` : un filtre vide est un zéro
    silencieux).
    """
    if colonne not in ("SrcAddr", "DstAddr"):
        raise ValueError(f"colonne d'adresse inattendue : {colonne!r}")

    brut = ",".join(plages) if plages is not None else settings.internal_networks
    reseaux = parse_internal_networks(brut)

    conditions = [
        f"({colonne} >= toIPv6('::ffff:{reseau.network_address}')\n"
        f"                AND {colonne} <= toIPv6('::ffff:{reseau.broadcast_address}'))"
        for reseau in reseaux
    ]
    return "\n        (\n            " + "\n            OR ".join(conditions) + "\n        )\n"


_CONVERGENCE_SOURCE_INTERNAL_FILTER = build_internal_filter("SrcAddr")
"""Source INTERNE seulement, d'après `OKVORADO_INTERNAL_NETWORKS` (défaut :
RFC1918 + CGNAT 100.64/10, soit le comportement d'avant le paramétrage).

C'est le filtre mesuré comme discriminant le 2026-08-07 (mesure décisive n°1) :
sans lui, le scan de ports Internet et le maillage P2P dominent le classement
et masquent le vrai motif de convergence."""

_CONVERGENCE_DEST_UNICAST_FILTER = (
    "NOT (DstAddr >= toIPv6('::ffff:224.0.0.0') AND DstAddr <= toIPv6('::ffff:239.255.255.255'))"
)
"""Destination UNICAST : exclut 224.0.0.0/4 (multicast v4), mesuré comme
nécessaire le 2026-08-07 — sans ce filtre, du trafic de découverte/annonce
multicast pollue le classement des destinations convergentes.

Redondant depuis l'ajout de `_CONVERGENCE_DEST_INTERNAL_FILTER` (le multicast
n'est dans aucune plage privée, donc déjà exclu par lui) — gardé quand même :
il est explicite et sans coût, mais ne le documente plus comme discriminant
(voir la docstring de `_CONVERGENCE_DEST_INTERNAL_FILTER` pour la mesure qui
tranche réellement)."""

_CONVERGENCE_DEST_INTERNAL_FILTER = build_internal_filter("DstAddr")
"""Destination INTERNE seulement : RFC1918 (10/8, 172.16/12, 192.168/16) +
CGNAT (100.64/10) — MESURE DÉCISIVE DÉFAUT N°1 (2026-08-07, constat écran) :
sur 50 lignes affichées, 40 étaient du STUN Tailscale port 3478 (9 sources,
6,9 Ko, 104 flux chacune) vers des IP publiques différentes ; le vrai motif
(192.0.2.24, 17 sources) restait en tête mais noyé sous 84% de bruit.

Mesure de tranche (prod, fenêtre 1h, seuil 5 sources) : destination EXTERNE
-> 74 lignes, max 9 sources (bruit : STUN, services cloud) ; destination
INTERNE -> 14 lignes, max 17 sources (signal).

Justification métier : le motif cible est « N postes internes -> 1 serveur ».
Un serveur SCCM, un partage SMB, un datacenter d'entreprise sont TOUJOURS
internes ; une destination externe avec beaucoup de sources internes est du
trafic sortant normal (STUN, CDN, cloud), pas un déploiement de masse. Ce
filtre ne perd donc aucun cas d'usage réel."""

_CONVERGENCE_PORT_FILTER = "DstPort > 0 AND DstPort < 32768"
"""Exclut ICMP/fragments (port 0) et les ports éphémères clients (>= 32768,
plage IANA dynamique) : ni l'un ni l'autre ne porte de motif de service."""

_CONVERGENCE_PROTO_FILTER = "Proto IN (6, 17)"
"""TCP (6) et UDP (17) uniquement — les protocoles qui portent un motif de
service applicatif au sens de ce diagnostic."""

_CONVERGENCE_WHERE_CLAUSE = f"""
        {_CONVERGENCE_SOURCE_INTERNAL_FILTER.strip()}
        AND {_CONVERGENCE_DEST_INTERNAL_FILTER.strip()}
        AND {_CONVERGENCE_DEST_UNICAST_FILTER}
        AND {_CONVERGENCE_PORT_FILTER}
        AND {_CONVERGENCE_PROTO_FILTER}
"""


# ---------------------------------------------------------------------------
# 1. build_convergence_query — la vue qui rend le motif SCCM visible
# ---------------------------------------------------------------------------


PROTO_NUMBER_TO_LABEL: dict[int, str] = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
"""Table de résolution du numéro de protocole IP (`Proto`, colonne ClickHouse)
vers son nom lisible par un exploitant réseau — SOURCE UNIQUE de ce mécanisme
dans l'app (cf. `resolve_protocol_label()` ci-dessous, réutilisée par
`app/routers/views.py` plutôt que dupliquée : un concept, une source).

ClickHouse résout déjà ces numéros via son dictionnaire
(`dictGetOrDefault('protocols','name',toUInt64(6),'?')` -> `TCP`), mais une
table Python évite une dépendance au dictionnaire ClickHouse pour un simple
affichage, et reste alignée sur le mécanisme déjà en place côté `views.py`
avant ce défaut. Couvre au moins TCP/UDP/ICMP/ICMPv6 (défaut mesuré en
production le 2026-08-07 : colonne PROTOCOLE affichait "6"/"17" bruts)."""


def resolve_protocol_label(proto: int | Any) -> str:
    """Rend le nom lisible d'un protocole IP, ou son numéro brut en repli.

    Le repli numérique est INTENTIONNEL (pas un trou silencieux) : un
    protocole hors table connue (ex. SCTP=132) doit rester visible sous sa
    forme numérique plutôt que de disparaître ou lever une exception — cf.
    CLAUDE.md règle n°2 (zéro silencieux), appliquée ici à un protocole,
    pas à une valeur neutre."""
    if isinstance(proto, int):
        return PROTO_NUMBER_TO_LABEL.get(proto, str(proto))
    return str(proto)


def build_convergence_query(
    *,
    period: str,
    min_sources: int = DEFAULT_MIN_SOURCES,
    limit: int = DEFAULT_CONVERGENCE_LIMIT,
) -> tuple[str, dict[str, Any]]:
    """Classe (destination, port) par nombre de sources internes DISTINCTES.

    C'est LA vue de détection : elle répond à « N sources convergent en masse
    vers UNE destination », sans savoir à l'avance quoi chercher (cas d'usage
    GPO/SCCM cité dans le contexte métier). Le filtre de convergence (mesure
    décisive n°1) exclut le scan Internet et le maillage P2P qui, sans lui,
    dominent un simple `GROUP BY DstAddr ORDER BY uniqExact(SrcAddr) DESC`.

    Args:
        period: fenêtre, doit appartenir à `DIAGNOSTIC_PERIOD_CHOICES`.
        min_sources: seuil minimal de sources distinctes pour qu'une ligne soit
            retenue (clause HAVING) — transite en paramètre lié.
        limit: nombre de lignes rendues, plafonné à `MAX_CONVERGENCE_LIMIT`.

    Returns:
        `(sql, parameters)`. Le SQL ne contient ni IP ni nom ni saisie utilisateur
        interpolés : seuls la table `default.flows` et les noms de colonnes sont
        des littéraux en dur.

    Raises:
        ValueError: `period` hors de l'énumération fermée.
    """
    period_seconds = _validate_period(period)
    sql = f"""
SELECT
    DstAddr,
    DstPort,
    Proto,
    uniqExact(SrcAddr) AS source_count,
    sum(Bytes * SamplingRate) AS total_bytes,
    count() AS flow_count
FROM default.flows
WHERE TimeReceived >= now() - toIntervalSecond({{window_seconds:UInt32}})
    AND {_CONVERGENCE_WHERE_CLAUSE.strip()}
GROUP BY DstAddr, DstPort, Proto
HAVING source_count >= {{min_sources:UInt32}}
ORDER BY source_count DESC, total_bytes DESC
LIMIT {{limit:UInt32}}
"""
    return sql, {
        "window_seconds": period_seconds,
        "min_sources": max(min_sources, 1),
        "limit": _clamp_limit(limit),
    }


# ---------------------------------------------------------------------------
# 2. build_convergence_detail_query — drill-down sur une destination retenue
# ---------------------------------------------------------------------------


def build_convergence_detail_query(
    *,
    dst_addr: str,
    dst_port: int,
    period: str,
    limit: int = DEFAULT_CONVERGENCE_LIMIT,
) -> tuple[str, dict[str, Any]]:
    """Détaille les sources d'une destination retenue par `build_convergence_query`.

    Pour une (destination, port) déjà identifiée comme motif de convergence :
    liste des sources, leur volume, et leur exportateur/interface d'entrée — ce
    qui permet de localiser physiquement chaque site source (les 160 sites GPO
    du cas d'usage cible).

    Applique le MÊME filtre source-interne que `build_convergence_query` :
    le classement ne compte que les sources internes (mesure décisive n°1),
    donc le détail doit lister exactement ce sous-ensemble — sinon le nombre
    de lignes affichées au clic dépasserait le `source_count` annoncé dans le
    tableau, un défaut de cohérence entre classement et drill-down.

    Args:
        dst_addr: adresse destination retenue (paramétrée — jamais interpolée,
            même si elle provient d'un clic sur une ligne déjà affichée : elle
            reste une donnée externe tant qu'elle transite par une requête HTTP).
        dst_port: port destination retenu, paramétré.
        period: fenêtre, doit appartenir à `DIAGNOSTIC_PERIOD_CHOICES`.
        limit: nombre de sources rendues, plafonné à `MAX_CONVERGENCE_LIMIT`.

    Returns:
        `(sql, parameters)` — `dst_addr` et `dst_port` transitent exclusivement
        en paramètres liés ClickHouse.

    Raises:
        ValueError: `period` hors de l'énumération fermée.
    """
    period_seconds = _validate_period(period)
    sql = f"""
SELECT
    SrcAddr,
    ExporterName,
    InIfName,
    sum(Bytes * SamplingRate) AS total_bytes,
    count() AS flow_count
FROM default.flows
WHERE TimeReceived >= now() - toIntervalSecond({{window_seconds:UInt32}})
    AND DstAddr = toIPv6({{dst_addr:String}})
    AND DstPort = {{dst_port:UInt16}}
    AND {_CONVERGENCE_SOURCE_INTERNAL_FILTER.strip()}
GROUP BY SrcAddr, ExporterName, InIfName
ORDER BY total_bytes DESC
LIMIT {{limit:UInt32}}
"""
    return sql, {
        "window_seconds": period_seconds,
        "dst_addr": dst_addr,
        "dst_port": dst_port,
        "limit": _clamp_limit(limit),
    }


# ---------------------------------------------------------------------------
# 3. Écran par exportateur — allowlist de dimensions
# ---------------------------------------------------------------------------

EXPORTER_DIMENSION_ALLOWLIST: frozenset[str] = frozenset(
    {
        "SrcAddr",
        "DstAddr",
        "DstPort",
        "SrcPort",
        "Proto",
        "SrcCountry",
        "DstCountry",
        "SrcAS",
        "DstAS",
    }
)
"""Colonnes autorisées comme axe de « top N » sur l'écran exportateur. Littéraux
en dur, jamais dérivés d'une saisie : une valeur hors de cette liste lève
`ValueError` dans `build_exporter_top_dimension_query()`, elle n'est JAMAIS
interpolée dans le SQL."""


def _validate_dimension(dimension: str) -> str:
    """Valide `dimension` contre l'allowlist et la rend telle quelle.

    Raises:
        ValueError: `dimension` n'appartient pas à `EXPORTER_DIMENSION_ALLOWLIST`.
    """
    if dimension not in EXPORTER_DIMENSION_ALLOWLIST:
        raise ValueError(
            f"dimension hors allowlist: {dimension!r} "
            f"(attendu: {', '.join(sorted(EXPORTER_DIMENSION_ALLOWLIST))})"
        )
    return dimension


def build_exporter_top_dimension_query(
    *,
    exporter_name: str,
    dimension: str,
    period: str,
    limit: int = DEFAULT_CONVERGENCE_LIMIT,
) -> tuple[str, dict[str, Any]]:
    """Top N par une dimension choisie dans `EXPORTER_DIMENSION_ALLOWLIST`.

    Fonction générique dont `build_exporter_top_sources_query()` et
    `build_exporter_top_destinations_query()` sont des spécialisations : elle
    est exposée séparément pour un écran qui laisserait l'opérateur choisir
    l'axe de regroupement (ex. `SrcCountry`, `SrcAS`).

    Args:
        exporter_name: nom d'exportateur, paramétré — jamais interpolé.
        dimension: nom de colonne, validé contre l'allowlist AVANT toute
            construction de SQL (littéral en dur une fois validé).
        period: fenêtre, doit appartenir à `DIAGNOSTIC_PERIOD_CHOICES`.
        limit: nombre de lignes rendues, plafonné à `MAX_CONVERGENCE_LIMIT`.

    Raises:
        ValueError: `dimension` hors allowlist, ou `period` hors énumération.
    """
    validated_dimension = _validate_dimension(dimension)
    period_seconds = _validate_period(period)
    sql = f"""
SELECT
    {validated_dimension},
    sum(Bytes * SamplingRate) AS total_bytes,
    sum(Packets * SamplingRate) AS total_packets,
    count() AS flow_count
FROM default.flows
WHERE TimeReceived >= now() - toIntervalSecond({{window_seconds:UInt32}})
    AND ExporterName = {{exporter_name:String}}
GROUP BY {validated_dimension}
ORDER BY total_bytes DESC
LIMIT {{limit:UInt32}}
"""
    return sql, {
        "window_seconds": period_seconds,
        "exporter_name": exporter_name,
        "limit": _clamp_limit(limit),
    }


# ---------------------------------------------------------------------------
# 3bis. Écran par exportateur — fonctions dédiées (l'autre agent les appelle)
# ---------------------------------------------------------------------------

_TIME_SERIES_STEP: dict[str, str] = {
    "1h": "5 MINUTE",
    "6h": "15 MINUTE",
    "24h": "1 HOUR",
    "7d": "6 HOUR",
    "30d": "1 DAY",
}
"""Pas d'agrégation temporelle par période — littéral ClickHouse en dur, dérivé
uniquement de `DIAGNOSTIC_PERIOD_CHOICES` (jamais d'une saisie). Même table que
`app/routers/views.py::_TIME_SERIES_STEP` pour les 4 périodes communes, complétée
ici pour "30d" (période absente de l'écran vues)."""


def build_exporter_time_series_query(
    *, exporter_name: str, period: str
) -> tuple[str, dict[str, Any]]:
    """Trafic dans le temps pour un exportateur — série `sum(Bytes*SamplingRate)`.

    Le pas d'agrégation suit `_TIME_SERIES_STEP` (5 min à 1h, jusqu'à 1 jour
    pour 30d), pour rester cohérent avec l'écran vues déjà en place.

    Raises:
        ValueError: `period` hors de l'énumération fermée.
    """
    period_seconds = _validate_period(period)
    step = _TIME_SERIES_STEP[period]
    sql = f"""
SELECT
    toStartOfInterval(TimeReceived, INTERVAL {step}) AS bucket,
    sum(Bytes * SamplingRate) AS total_bytes,
    sum(Packets * SamplingRate) AS total_packets,
    count() AS flow_count
FROM default.flows
WHERE TimeReceived >= now() - toIntervalSecond({{window_seconds:UInt32}})
    AND ExporterName = {{exporter_name:String}}
GROUP BY bucket
ORDER BY bucket ASC
"""
    return sql, {"window_seconds": period_seconds, "exporter_name": exporter_name}


def build_exporter_top_interfaces_query(
    *, exporter_name: str, period: str, limit: int = DEFAULT_CONVERGENCE_LIMIT
) -> tuple[str, dict[str, Any]]:
    """Top interfaces (entrantes) d'un exportateur, par volume.

    Raises:
        ValueError: `period` hors de l'énumération fermée.
    """
    period_seconds = _validate_period(period)
    sql = """
SELECT
    InIfName,
    InIfSpeed,
    sum(Bytes * SamplingRate) AS total_bytes,
    sum(Packets * SamplingRate) AS total_packets,
    count() AS flow_count
FROM default.flows
WHERE TimeReceived >= now() - toIntervalSecond({window_seconds:UInt32})
    AND ExporterName = {exporter_name:String}
GROUP BY InIfName, InIfSpeed
ORDER BY total_bytes DESC
LIMIT {limit:UInt32}
"""
    return sql, {
        "window_seconds": period_seconds,
        "exporter_name": exporter_name,
        "limit": _clamp_limit(limit),
    }


def build_exporter_top_applications_query(
    *, exporter_name: str, period: str, limit: int = DEFAULT_CONVERGENCE_LIMIT
) -> tuple[str, dict[str, Any]]:
    """Top applications (par port + protocole) d'un exportateur, par volume.

    Rend `DstPort` et `Proto` bruts : la résolution en nom d'application lisible
    (portmap) est une responsabilité de la couche appelante — cf.
    `app/routers/views.py::_resolve_services_applications`, le même choix y est
    déjà fait pour la vue « services ».

    Raises:
        ValueError: `period` hors de l'énumération fermée.
    """
    period_seconds = _validate_period(period)
    sql = """
SELECT
    DstPort,
    Proto,
    sum(Bytes * SamplingRate) AS total_bytes,
    sum(Packets * SamplingRate) AS total_packets,
    count() AS flow_count
FROM default.flows
WHERE TimeReceived >= now() - toIntervalSecond({window_seconds:UInt32})
    AND ExporterName = {exporter_name:String}
GROUP BY DstPort, Proto
ORDER BY total_bytes DESC
LIMIT {limit:UInt32}
"""
    return sql, {
        "window_seconds": period_seconds,
        "exporter_name": exporter_name,
        "limit": _clamp_limit(limit),
    }


def build_exporter_top_sources_query(
    *, exporter_name: str, period: str, limit: int = DEFAULT_CONVERGENCE_LIMIT
) -> tuple[str, dict[str, Any]]:
    """Top sources (`SrcAddr`) d'un exportateur, par volume.

    Spécialisation de `build_exporter_top_dimension_query()` sur `SrcAddr`,
    exposée séparément pour un branchement direct sans que la couche appelante
    ait à connaître l'allowlist de dimensions.

    Raises:
        ValueError: `period` hors de l'énumération fermée.
    """
    return build_exporter_top_dimension_query(
        exporter_name=exporter_name, dimension="SrcAddr", period=period, limit=limit
    )


def build_exporter_top_destinations_query(
    *, exporter_name: str, period: str, limit: int = DEFAULT_CONVERGENCE_LIMIT
) -> tuple[str, dict[str, Any]]:
    """Top destinations (`DstAddr`) d'un exportateur, par volume.

    Spécialisation de `build_exporter_top_dimension_query()` sur `DstAddr`.

    Raises:
        ValueError: `period` hors de l'énumération fermée.
    """
    return build_exporter_top_dimension_query(
        exporter_name=exporter_name, dimension="DstAddr", period=period, limit=limit
    )


def build_exporter_top_conversations_query(
    *, exporter_name: str, period: str, limit: int = DEFAULT_CONVERGENCE_LIMIT
) -> tuple[str, dict[str, Any]]:
    """Top conversations (source, destination, port) d'un exportateur, par volume.

    Distinct du top sources/destinations pris séparément : une conversation est
    le triplet complet, ce qui distingue « beaucoup de trafic vers X » de
    « beaucoup de trafic vers X sur CE port précis ».

    Raises:
        ValueError: `period` hors de l'énumération fermée.
    """
    period_seconds = _validate_period(period)
    sql = """
SELECT
    SrcAddr,
    DstAddr,
    DstPort,
    Proto,
    sum(Bytes * SamplingRate) AS total_bytes,
    sum(Packets * SamplingRate) AS total_packets,
    count() AS flow_count
FROM default.flows
WHERE TimeReceived >= now() - toIntervalSecond({window_seconds:UInt32})
    AND ExporterName = {exporter_name:String}
GROUP BY SrcAddr, DstAddr, DstPort, Proto
ORDER BY total_bytes DESC
LIMIT {limit:UInt32}
"""
    return sql, {
        "window_seconds": period_seconds,
        "exporter_name": exporter_name,
        "limit": _clamp_limit(limit),
    }


def build_exporter_qos_query(*, exporter_name: str, period: str) -> tuple[str, dict[str, Any]]:
    """Répartition QoS (DSCP) du trafic d'un exportateur.

    `bitShiftRight(IPTos, 2)` extrait le DSCP (les 6 bits hauts de l'octet
    ToS/DiffServ, les 2 bits bas étant l'ECN — RFC 3168) : c'est la valeur
    qu'un administrateur réseau reconnaît, `IPTos` brut ne se lit pas
    directement.

    DÉFAUT MESURÉ EN PRODUCTION (2026-08-07) : cette fonction écrivait
    `IPTos >> 2`, l'opérateur de décalage C-like — que ClickHouse NE CONNAÎT
    PAS (`Code: 62 SYNTAX_ERROR`). L'onglet QoS de `/exporters/routeur-agence-03`
    affichait l'erreur ClickHouse brute au clic. `bitShiftRight(IPTos, 2)` est
    la fonction ClickHouse réelle pour ce même décalage de 2 bits — vérifié en
    prod. Cf. le garde-fou générique
    `test_aucune_fonction_du_module_ne_produit_un_operateur_de_decalage_c_like`
    dans `tests/test_diagnostics.py`, contre cette famille de défaut.

    Ne suppose PAS la présence de la colonne `IPTos` dans le schéma :
    `app/routers/views.py` détecte déjà cette absence dynamiquement
    (`_has_iptos_column`), même garde à reproduire côté appelant de cette
    fonction plutôt que de la dupliquer ici, ce module restant pur SQL sans
    I/O.

    Raises:
        ValueError: `period` hors de l'énumération fermée.
    """
    period_seconds = _validate_period(period)
    sql = """
SELECT
    bitShiftRight(IPTos, 2) AS dscp,
    sum(Bytes * SamplingRate) AS total_bytes,
    count() AS flow_count
FROM default.flows
WHERE TimeReceived >= now() - toIntervalSecond({window_seconds:UInt32})
    AND ExporterName = {exporter_name:String}
GROUP BY dscp
ORDER BY total_bytes DESC
"""
    return sql, {"window_seconds": period_seconds, "exporter_name": exporter_name}
