"""Import/export en masse de sections de configuration Akvorado via CSV.

CONFIG_HARDCODE_OK: les exemples d'IP/CIDR/AS dans les docstrings ci-dessous
sont des illustrations de format CSV, jamais des valeurs d'infra contactées par
ce module (logique pure, aucun appel réseau, aucun host en dur).

Logique pure, sans dépendance HTTP ni écriture disque : `app/routers/config_sections.py`
consomme ce module pour construire une prévisualisation, puis met le résultat en
file d'attente via `app.services.config_writer.stage_change` — jamais d'écriture
directe depuis ici.

UNE SEULE implémentation de parsing (`parse_csv`) et de sérialisation
(`export_csv`), paramétrées par un descripteur `CsvFormat`. Trois copies d'un
même parseur (une par section) auraient divergé dès le premier correctif de
tolérance appliqué à une seule d'entre elles — le socle rend cette dérive
impossible par construction. `parse_networks_csv` / `export_networks_csv`
subsistent comme cas particuliers pré-câblés, leur signature étant celle dont
dépendent les routes.

Trois FORMES de section, mesurées sur la configuration réelle :

1. `mapping` — clé -> valeur scalaire, CSV `cle;valeur`.
   - `networks` : CIDR -> désignation (`192.168.1.0/24;vlan-bureau`)
   - `asns`     : numéro d'AS -> nom (`64501;ACME Corporation`)
2. `pairs` — liste d'objets à 2 champs, CSV `champ1;champ2`.
   - `saved_filters` : `[{"description": ..., "content": ...}]`
3. `lines` — liste de chaînes, une expression par ligne, AUCUN séparateur.
   - `exporter_classifiers` : `['ClassifyRegion("homelab")', ...]`

Tolérances documentées (formes `mapping` et `pairs`) :
- séparateur `;` (celui demandé) ; on accepte aussi `,` sur une ligne qui ne
  contient PAS de `;` (le `;` gagne toujours s'il est présent, y compris si la
  valeur elle-même contient une virgule — cas réel : "bureau, annexe", ou une
  expression de filtre `SrcAS IN (64501, 64502)`).
- la forme `lines` ne découpe RIEN : la ligne entière est la valeur, sinon une
  expression contenant `;` ou `,` (fréquent : `ClassifyRegion("eu", "west")`)
  serait amputée et le classifieur produit serait faux sans aucune erreur.

Tolérances communes aux trois formes :
- lignes vides et lignes de commentaire (`#`) ignorées.
- une éventuelle 1re ligne d'en-tête est ignorée silencieusement, reconnue
  UNIQUEMENT sur un intitulé de colonne connu (`CsvFormat.header_keywords`).
- espaces en début/fin de champ, fins de ligne Windows (`\\r\\n`), BOM UTF-8
  en tête de fichier : tous tolérés.

GARDE SÉCURITÉ : ce module ne fait AUCUN échappement HTML — le contenu CSV
est une entrée utilisateur brute, stockée littéralement dans `CsvRow.name` /
`CsvParseResult`. L'échappement à l'affichage est la responsabilité du
template Jinja2 (autoescape, jamais de `|safe`), jamais de cette couche de
parsing.

**Tout ou rien** : `parse_csv` ne retourne JAMAIS un mélange de lignes valides
et d'erreurs. Dès qu'une seule ligne échoue (clé invalide, valeur vide/trop
longue) ou qu'un doublon est détecté, `rows` est vide et toutes les
erreurs/doublons rencontrés sont listés — l'appelant doit tout corriger et
relancer l'import, jamais appliquer un sous-ensemble.

**Pas de zéro silencieux** : `rows=[]` a deux causes que l'appelant DOIT
pouvoir distinguer — « CSV valide mais sans ligne de données » (`errors=[]`)
et « CSV refusé » (`errors` non vide). Les fusionner ferait passer un import
destructeur (`replace` sur un fichier mal enregistré) pour un import à vide
annoncé en succès — défaut vécu le 2026-08-06 côté routeur.
"""

from __future__ import annotations

import csv
import io
import ipaddress
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

_MAX_NAME_LENGTH = 128
_MAX_EXPRESSION_LENGTH = 1024

# Dernier numéro d'AS représentable sur 32 bits (RFC 6793). Au-delà, la valeur
# ne peut pas venir d'un routeur réel : c'est une faute de saisie, pas un AS.
_MAX_ASN = 4294967295


@dataclass(frozen=True)
class CsvRow:
    """Une ligne CSV valide, après normalisation de la clé.

    Les noms de champs `cidr`/`name` sont ceux du cas historique `networks`,
    dont dépendent les routes et les templates : ils sont conservés tels quels
    plutôt que renommés. Les propriétés `key`/`value` en donnent la lecture
    générique utilisée par le socle, sans participer à l'égalité du dataclass
    (donc sans casser les comparaisons `CsvRow(line=..., cidr=..., name=...)`
    existantes).

    Pour la forme `lines` (une expression par ligne), il n'y a pas de clé
    distincte de la valeur : `cidr` et `name` portent la même expression.
    """

    line: int
    cidr: str
    name: str

    @property
    def key(self) -> str:
        """Clé normalisée (CIDR, numéro d'AS, description...)."""
        return self.cidr

    @property
    def value(self) -> str:
        """Valeur associée (désignation, expression de filtre...)."""
        return self.name


@dataclass(frozen=True)
class CsvParseResult:
    """Résultat d'un `parse_csv`.

    `rows` n'est peuplé QUE si `errors` et `duplicates` sont tous deux vides
    (tout ou rien) : sinon, `rows` est une liste vide et l'appelant lit
    `errors`/`duplicates` pour afficher ce qu'il faut corriger.
    """

    rows: list[CsvRow]
    errors: list[str]
    duplicates: list[str]


# Un normalisateur de clé rend la clé canonique, ou `None` si la clé est
# invalide. Le `None` est délibérément distinct d'une chaîne vide : une clé
# refusée doit produire une ERREUR, jamais une clé vide acceptée en silence.
KeyParser = Callable[[str], "str | None"]

# Clé de tri d'export. Doit être TOTALE sur des clés hétérogènes : les clés
# viennent du YAML et arrivent aussi bien en `str` qu'en `int`, et un plan
# d'adressage mêle IPv4 et IPv6 (voir `_network_sort_key`).
SortKey = Callable[[str], "tuple[int, ...]"]


@dataclass(frozen=True)
class CsvFormat:
    """Descripteur de format CSV d'une section.

    C'est le seul point de variation entre les sections : `parse_csv` et
    `export_csv` sont écrits une fois et lisent ce descripteur.

    - `kind` : `"mapping"` (clé -> valeur scalaire), `"pairs"` (liste d'objets
      à 2 champs) ou `"lines"` (liste de chaînes, sans séparateur).
    - `key_parser` : valide/normalise la clé (CIDR, entier d'AS...). `None`
      pour une clé prise littéralement (description d'un filtre, expression).
    - `header_keywords` : intitulés de colonne reconnus comme en-tête. Un
      ensemble VIDE désactive la détection d'en-tête.
    - `sort_key` : `None` pour préserver l'ordre d'origine (les listes
      `saved_filters` / `exporter_classifiers` sont ordonnées et Akvorado
      applique les classifieurs en séquence : les trier changerait le
      comportement produit).
    - `pair_fields` : noms des deux clés du dict, pour la forme `pairs`.
    - `key_forbids_separator` : à l'EXPORT, remplace le `;` d'une clé par une
      virgule. La forme `pairs` découpe à la relecture sur la 1re occurrence du
      séparateur : écrire une clé qui en contient un produirait une ligne se
      relisant clé/valeur décalées, en silence (voir `_sanitize_pair_key`).
    """

    kind: str
    header_line: str
    key_label: str
    value_label: str
    header_keywords: frozenset[str] = frozenset()
    key_parser: KeyParser | None = None
    max_key_length: int = _MAX_NAME_LENGTH
    max_value_length: int = _MAX_NAME_LENGTH
    sort_key: SortKey | None = None
    pair_fields: tuple[str, str] = ("description", "content")
    key_forbids_separator: bool = False
    key_error_label: str = "cle"
    value_error_label: str = "valeur"
    duplicate_label: str = "cle"
    normalized_suffix: str = ""


# ---------------------------------------------------------------------------
# Normalisateurs de clé
# ---------------------------------------------------------------------------


def _normalize_cidr(raw: str) -> str | None:
    """Normalise un CIDR ou une IP nue. `None` si invalide.

    Une IP nue (sans `/`) est d'abord interprétée comme une adresse seule
    (`ip_address`) pour déterminer sa famille (IPv4 -> `/32`, IPv6 -> `/128`)
    AVANT d'ajouter le masque — coller `/32` en dur à une IPv6 nue produirait
    un CIDR IPv6 valide mais faux (interprété comme /32, pas /128).

    Un CIDR avec des bits hôte non nuls (ex. `10.0.0.1/24`) est ramené au
    réseau via `strict=False`, jamais rejeté.
    """
    if "/" not in raw:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            return None
        bare_mask = 32 if address.version == 4 else 128
        candidate = f"{raw}/{bare_mask}"
    else:
        candidate = raw

    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return None
    return str(network)


def _normalize_asn(raw: str) -> str | None:
    """Normalise un numéro d'AS. `None` si invalide.

    Passe par `int` plutôt que par la chaîne brute : « 064501 » et « 64501 »
    désignent le même AS, et sans cette normalisation le doublon échapperait à
    la détection pour ressortir en écrasement silencieux à l'application.

    `int()` accepterait aussi les formes exotiques `+64501` ou `1_000` : le
    filtre `isdigit` en amont les refuse, un numéro d'AS ne s'écrivant qu'en
    chiffres décimaux.
    """
    candidate = raw.strip()
    if not candidate.isdigit():
        return None
    asn = int(candidate)
    if asn <= 0 or asn > _MAX_ASN:
        return None
    return str(asn)


def _normalize_literal(raw: str) -> str | None:
    """Clé prise littéralement (description d'un filtre, expression).

    Retourne `None` sur une chaîne vide : c'est bien un refus, la validation de
    longueur en aval ne verrait sinon qu'une clé vide « valide ».
    """
    candidate = raw.strip()
    return candidate or None


# ---------------------------------------------------------------------------
# Clés de tri d'export
# ---------------------------------------------------------------------------


def _network_sort_key(cidr: str) -> tuple[int, ...]:
    """Ordonne un CIDR par `(version, adresse, préfixe)`.

    Le tri ne passe PAS directement par `ip_network` : Python refuse de
    comparer un réseau IPv4 à un réseau IPv6 (`TypeError: not of the same
    version`). Un plan mixte v4/v6 est un cas RÉEL — Tailscale distribue un
    préfixe IPv6 en plus du préfixe CGNAT. Sans cette clé composite, l'import
    acceptait l'IPv6 puis l'export plantait sur le plan que l'application
    venait elle-même d'accepter.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    return (network.version, int(network.network_address), network.prefixlen)


def _asn_sort_key(asn: str) -> tuple[int, ...]:
    """Ordonne les AS numériquement.

    Un tri lexicographique placerait « 100 » avant « 64501 » et « 3 » en
    dernier : un export illisible et surtout instable au diff dès qu'un AS
    change d'ordre de grandeur.
    """
    return (int(asn),)


# ---------------------------------------------------------------------------
# Découpage / pré-filtrage des lignes
# ---------------------------------------------------------------------------


def _strip_bom(content: str) -> str:
    return content.lstrip("﻿")


def _split_fields(line: str) -> list[str]:
    """Découpe une ligne selon `;` si présent, sinon `,` (tolérance documentée)."""
    separator = ";" if ";" in line else ","
    reader = csv.reader([line], delimiter=separator)
    try:
        fields = next(reader)
    except StopIteration:  # pragma: no cover - ligne déjà filtrée non-vide en amont
        return []
    return [f.strip() for f in fields]


def _split_once(line: str) -> list[str]:
    """Découpe sur la PREMIÈRE occurrence du séparateur, le reste littéral.

    DÉFAUT MESURÉ (2026-08-06) : `csv.reader` ne protège le séparateur que dans
    des guillemets DOUBLES, alors qu'une expression de filtre Akvorado cite en
    guillemets SIMPLES (`ExporterName = 'a;b'`). Un découpage complet rendait
    donc 3 champs, seuls les 2 premiers étaient lus, et l'expression était
    stockée amputée (`ExporterName = 'a`) — un filtre faux accepté avec
    `errors=[]`. Le contrat « tout ou rien » ne protège de rien quand la perte
    survient AVANT la validation.

    Le découpage en une seule fois est correct ici parce que la forme `pairs`
    n'a que deux champs et que le premier (une description) ne peut pas
    contenir le séparateur sans ambiguïté : tout ce qui suit appartient à
    l'expression.
    """
    separator = ";" if ";" in line else ","
    head, found, tail = line.partition(separator)
    if not found:
        return [head.strip()]
    return [head.strip(), tail.strip()]


def _data_lines(content: str, fmt: CsvFormat) -> list[tuple[int, str, list[str]]]:
    """Lignes non-vides/non-commentaire, avec leurs champs découpés.

    Trois découpages, un par forme :
    - `lines` ne découpe pas du tout (la ligne entière est la valeur) ;
    - `pairs` découpe sur la 1re occurrence seulement, une expression de filtre
      contenant un séparateur devant rester intacte (voir `_split_once`) ;
    - `mapping` garde le découpage `csv.reader` historique, qui gère les champs
      entre guillemets doubles produits par un tableur.
    """
    result: list[tuple[int, str, list[str]]] = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if fmt.kind == "lines":
            fields = [line]
        elif fmt.kind == "pairs":
            fields = _split_once(line)
        else:
            fields = _split_fields(line)
        result.append((line_number, raw_line, fields))
    return result


def _looks_like_header(raw: str, fmt: CsvFormat) -> bool:
    """Reconnaît une 1re ligne d'en-tête au sens STRICT : uniquement sur un
    intitulé de colonne connu (`cidr`, `numero`, `description`...).

    Une heuristique purement négative (« le 1er champ n'est pas une clé valide,
    donc c'est un en-tête ») avalerait silencieusement une vraie erreur sur un
    fichier à une seule ligne fautive — piège vécu en test. Le test positif sur
    mots-clés est la seule forme sûre : il ne peut jamais transformer une
    donnée refusée en « en-tête sans données ».
    """
    if not fmt.header_keywords:
        return False
    return raw.strip().lower() in fmt.header_keywords


# ---------------------------------------------------------------------------
# Parseur générique
# ---------------------------------------------------------------------------


def _parse_key(raw: str, fmt: CsvFormat) -> str | None:
    if fmt.key_parser is None:
        return _normalize_literal(raw)
    return fmt.key_parser(raw)


def parse_csv(content: str, fmt: CsvFormat) -> CsvParseResult:
    """Parse un CSV selon `fmt` en résultat tout-ou-rien.

    Voir la docstring de module pour les formes, le format exact et les
    tolérances. Aucun `rows` partiel n'est jamais retourné.
    """
    content = _strip_bom(content)
    errors: list[str] = []
    parsed_rows: list[CsvRow] = []
    seen_keys: dict[str, int] = {}
    duplicates: list[str] = []

    expected_fields = 1 if fmt.kind == "lines" else 2

    for index, (line_number, raw_line, fields) in enumerate(_data_lines(content, fmt)):
        if len(fields) < expected_fields:
            errors.append(
                f"ligne {line_number}: format invalide (attendu {fmt.header_line!r}): {raw_line!r}"
            )
            continue

        key_raw = fields[0]
        value_raw = fields[0] if fmt.kind == "lines" else fields[1]

        # En-tête reconnue : SEULEMENT la 1re ligne de données, ET seulement si
        # son 1er champ est un intitulé de colonne connu -> ignorée
        # silencieusement, pas une erreur. Une ligne dont le 1er champ n'est PAS
        # une clé valide mais ne ressemble pas non plus à un en-tête connu (ex.
        # faute de frappe) reste une ERREUR normale, jamais avalée.
        if index == 0 and _looks_like_header(key_raw, fmt):
            continue

        normalized = _parse_key(key_raw, fmt)
        if normalized is None:
            errors.append(f"ligne {line_number}: {fmt.key_error_label} invalide: {key_raw!r}")
            continue
        if len(normalized) > fmt.max_key_length:
            errors.append(
                f"ligne {line_number}: {fmt.key_error_label} trop long "
                f"({len(normalized)} caractères, max {fmt.max_key_length})"
            )
            continue

        value = value_raw.strip()
        if not value:
            errors.append(f"ligne {line_number}: {fmt.value_error_label} vide")
            continue
        if len(value) > fmt.max_value_length:
            errors.append(
                f"ligne {line_number}: {fmt.value_error_label} trop longue "
                f"({len(value)} caractères, max {fmt.max_value_length})"
            )
            continue

        if normalized in seen_keys:
            # Un doublon n'est PAS une erreur de format : il est remonté à part
            # pour que l'appelant puisse le libeller correctement (« déjà vu
            # ligne N ») au lieu d'un message de saisie invalide trompeur.
            duplicates.append(
                f"ligne {line_number}: {fmt.duplicate_label} en doublon (déjà vu ligne "
                f"{seen_keys[normalized]}{fmt.normalized_suffix}): {normalized}"
            )
            continue
        seen_keys[normalized] = line_number

        parsed_rows.append(CsvRow(line=line_number, cidr=normalized, name=value))

    if errors or duplicates:
        return CsvParseResult(rows=[], errors=errors, duplicates=duplicates)

    return CsvParseResult(rows=parsed_rows, errors=[], duplicates=[])


# ---------------------------------------------------------------------------
# Sérialiseur générique
# ---------------------------------------------------------------------------


def _iter_export_pairs(value: Any, fmt: CsvFormat) -> Iterable[tuple[str, str]]:
    """Ramène la valeur d'une section aux couples `(clé, valeur)` à écrire.

    La valeur vient du YAML : les clés d'un mapping y sont typées `int` pour
    `asns` et `str` pour `networks`. Elles sont ramenées en `str` ICI, avant
    tout tri — trier un mélange `int`/`str` lèverait un `TypeError` sur la
    configuration réelle.
    """
    if fmt.kind == "mapping":
        if not isinstance(value, Mapping):
            return []
        mapping = {str(key): str(item) for key, item in value.items()}
        keys = sorted(mapping, key=fmt.sort_key) if fmt.sort_key else list(mapping)
        return [(key, mapping[key]) for key in keys]

    if fmt.kind == "pairs":
        if not isinstance(value, Sequence) or isinstance(value, str):
            return []
        key_field, value_field = fmt.pair_fields
        pairs: list[tuple[str, str]] = []
        for entry in value:
            if not isinstance(entry, Mapping):
                continue
            pairs.append((str(entry.get(key_field, "")), str(entry.get(value_field, ""))))
        return pairs

    # kind == "lines"
    if not isinstance(value, Sequence) or isinstance(value, str):
        return []
    return [(str(entry), str(entry)) for entry in value]


def _sanitize_pair_key(key: str) -> str:
    """Neutralise le séparateur dans une clé de la forme `pairs`.

    DÉFAUT MESURÉ (2026-08-06) : la relecture découpant sur la 1re occurrence
    du séparateur, une description contenant un `;` produisait une ligne
    `desc;piegee;expression` relue comme clé=`desc` / valeur=`piegee;expression`
    — du texte migrait de la description vers l'expression à chaque
    aller-retour export/import, avec `errors=[]`.

    Le `;` est remplacé par une virgule dans la seule DESCRIPTION (un libellé
    lisible, dont la ponctuation n'a aucune portée fonctionnelle). L'expression,
    elle, n'est jamais touchée : c'est elle qui porte la sémantique du filtre.
    """
    return key.replace(";", ",")


def export_csv(value: Any, fmt: CsvFormat) -> str:
    """Sérialise la valeur courante d'une section au format décrit par `fmt`.

    Une section vide produit un CSV valide (en-tête seule), jamais une erreur :
    l'export d'une configuration légitimement vide ne doit pas ressembler à un
    échec.

    L'ordre est celui de `fmt.sort_key` quand il est défini (rendu stable et
    diffable), sinon celui d'origine — les listes ordonnées (`saved_filters`,
    `exporter_classifiers`) ne sont JAMAIS triées : Akvorado applique les
    classifieurs en séquence, un tri changerait la classification produite.
    """
    buffer = io.StringIO()
    buffer.write(f"{fmt.header_line}\r\n")
    writer = csv.writer(buffer, delimiter=";", lineterminator="\r\n")

    for key, item in _iter_export_pairs(value, fmt):
        if fmt.kind == "lines":
            # Pas de `csv.writer` ici : la forme `lines` n'a pas de séparateur,
            # donc rien à quoter. Le passer au writer ajouterait des guillemets
            # autour de toute expression contenant `;` ou `,` — l'expression
            # relue ne serait plus celle écrite dans la configuration.
            buffer.write(f"{item}\r\n")
        elif fmt.kind == "pairs":
            if fmt.key_forbids_separator:
                key = _sanitize_pair_key(key)
            # Idem : le lecteur de cette forme découpe sur la 1re occurrence du
            # séparateur et prend le reste littéralement (`_split_once`), donc
            # il n'interprète AUCUN guillemet. Laisser `csv.writer` en ajouter
            # autour d'une expression contenant `;` les ferait relire comme des
            # caractères de l'expression — l'aller-retour export/import
            # corromprait le filtre à chaque passage.
            buffer.write(f"{key};{item}\r\n")
        else:
            writer.writerow([key, item])
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Descripteurs des sections réelles
# ---------------------------------------------------------------------------

NETWORKS_CSV_FORMAT = CsvFormat(
    kind="mapping",
    header_line="ip/cidr;designation",
    key_label="ip/cidr",
    value_label="designation",
    header_keywords=frozenset({"cidr", "ip", "ip/cidr", "network", "reseau", "réseau", "subnet"}),
    key_parser=_normalize_cidr,
    # Un CIDR normalisé ne dépasse jamais cette longueur : la borne ne sert
    # qu'à empêcher qu'un format futur laisse passer une clé démesurée.
    max_key_length=_MAX_NAME_LENGTH,
    max_value_length=_MAX_NAME_LENGTH,
    sort_key=_network_sort_key,
    key_error_label="CIDR",
    value_error_label="désignation",
    duplicate_label="CIDR",
    normalized_suffix=", après normalisation",
)

ASNS_CSV_FORMAT = CsvFormat(
    kind="mapping",
    header_line="numero;nom",
    key_label="numero",
    value_label="nom",
    header_keywords=frozenset({"numero", "numéro", "as", "asn", "as number", "numero d'as"}),
    key_parser=_normalize_asn,
    max_key_length=_MAX_NAME_LENGTH,
    max_value_length=_MAX_NAME_LENGTH,
    sort_key=_asn_sort_key,
    key_error_label="numero d'AS",
    value_error_label="nom",
    duplicate_label="numero d'AS",
    normalized_suffix=", après normalisation",
)

SAVED_FILTERS_CSV_FORMAT = CsvFormat(
    kind="pairs",
    header_line="description;expression",
    key_label="description",
    value_label="expression",
    header_keywords=frozenset({"description", "libelle", "libellé", "nom"}),
    key_parser=None,
    max_key_length=_MAX_NAME_LENGTH,
    # Une expression de filtre Akvorado est longue par nature : la borne des
    # 128 caractères d'une désignation la refuserait à tort.
    max_value_length=_MAX_EXPRESSION_LENGTH,
    sort_key=None,
    pair_fields=("description", "content"),
    key_forbids_separator=True,
    key_error_label="description",
    value_error_label="expression",
    duplicate_label="description",
)

EXPORTER_CLASSIFIERS_CSV_FORMAT = CsvFormat(
    kind="lines",
    header_line="expression",
    key_label="expression",
    value_label="expression",
    header_keywords=frozenset({"expression", "classifieur", "classifier"}),
    key_parser=None,
    max_key_length=_MAX_EXPRESSION_LENGTH,
    max_value_length=_MAX_EXPRESSION_LENGTH,
    sort_key=None,
    key_error_label="expression",
    value_error_label="expression",
    duplicate_label="expression",
)

INTERFACE_CLASSIFIERS_CSV_FORMAT = CsvFormat(
    kind="lines",
    header_line="expression",
    key_label="expression",
    value_label="expression",
    header_keywords=frozenset({"expression", "classifieur", "classifier"}),
    key_parser=None,
    max_key_length=_MAX_EXPRESSION_LENGTH,
    max_value_length=_MAX_EXPRESSION_LENGTH,
    sort_key=None,
    key_error_label="expression",
    value_error_label="expression",
    duplicate_label="expression",
)


# ---------------------------------------------------------------------------
# Cas particuliers pré-câblés (signatures dont dépendent les routes)
# ---------------------------------------------------------------------------


def parse_networks_csv(content: str) -> CsvParseResult:
    """Parse un CSV `ip/cidr;designation` en résultat tout-ou-rien.

    Simple pré-câblage de `parse_csv` sur `NETWORKS_CSV_FORMAT` : aucune
    logique propre, pour que toute correction de tolérance profite d'office à
    toutes les sections.
    """
    return parse_csv(content, NETWORKS_CSV_FORMAT)


def export_networks_csv(networks: dict[str, str]) -> str:
    """Sérialise le plan d'adressage courant en CSV `ip/cidr;designation`.

    Pré-câblage de `export_csv` sur `NETWORKS_CSV_FORMAT` (tri v4 puis v6, voir
    `_network_sort_key`).
    """
    return export_csv(networks, NETWORKS_CSV_FORMAT)
