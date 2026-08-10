"""Catalogue déclaratif des sections de configuration éditables d'Akvorado.

Chaque `ConfigSection` décrit où une section vit (fichier + chemin pointillé),
comment la valider, et quel(s) service(s) redémarrer après modification.

GARDE SÉCURITÉ (voir CONTRACT.md) : `key` et `file` viennent TOUJOURS d'un
littéral en dur dans CE module, JAMAIS d'une saisie utilisateur. Un appelant
choisit une `key` parmi celles du catalogue via `get_section()` ; il n'existe
aucun chemin de code qui laisse une saisie externe influencer le `dotted_key`
ou le `file` réellement utilisés pour lire/écrire sur disque.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

Validator = Callable[[Any], list[str]]

_MAX_NAME_LENGTH = 128
_MAX_PORT = 65535
_VALID_DECODERS = {"netflow", "sflow"}

# Fournisseurs de métadonnées d'interface acceptés par Akvorado.
#
# Les flux NetFlow ne transportent QUE des index d'interface (ifIndex). Le nom
# et la description de l'interface sont récupérés séparément, auprès de l'un de
# ces fournisseurs. Allowlist FERMÉE : un `type` inconnu fait refuser le
# document entier par l'outlet au démarrage — une faute de frappe à l'écran
# deviendrait un outlet qui ne redémarre plus, donc plus aucune collecte.
VALID_METADATA_PROVIDER_TYPES: frozenset[str] = frozenset({"snmp", "gnmi", "static", "bioris"})

# Ordre de la CASCADE — contre-intuitif, et c'est tout l'enjeu de cette section.
#
# Akvorado interroge les fournisseurs DANS L'ORDRE DE LA LISTE et « s'arrête au
# premier qui accepte la requête ». Or SEUL `static` sait IGNORER une requête
# qu'il ne connaît pas et laisser la main au suivant. `snmp`, lui, accepte
# TOUTES les requêtes.
#
# Conséquence : mettre `snmp` avant `static` n'est pas un détail d'ordre, c'est
# la SUPPRESSION du repli statique — `static` ne serait plus jamais consulté,
# sans la moindre erreur ni dans les logs ni à l'écran. L'ordre est donc une
# donnée SÉMANTIQUE, pas cosmétique : il est affiché et vérifié.
_FALLTHROUGH_PROVIDER = "static"

# Marqueur d'une communauté fournie par référence d'environnement plutôt qu'en
# clair : `${SNMP_COMMUNITY}`. C'est le MODE PAR DÉFAUT proposé à l'écran.
_ENV_REF_PREFIX = "${"
_ENV_REF_SUFFIX = "}"

# Bornes des leviers de réglage SNMP. Ce sont des GARDE-FOUS de saisie, pas des
# limites d'Akvorado : 10 000 workers ne feraient pas tomber l'outlet, mais une
# faute de frappe (un zéro de trop) sur un réglage de performance se voit
# rarement à l'œil. Un refus explicite vaut mieux qu'un outlet qui rame.
_MAX_SNMP_WORKERS = 1000
_MAX_SNMP_RETRIES = 10

# Durée au format Go (`1s`, `500ms`, `2m`, `1m30s`) — le seul que parse
# Akvorado. Voir `_is_duration` pour le défaut que cette forme évite.
_DURATION_RE = re.compile(r"(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))+", re.ASCII)
_DURATION_AMOUNT_RE = re.compile(r"(\d+(?:\.\d+)?)(?:ns|us|µs|ms|s|m|h)", re.ASCII)
_VALID_HOMEPAGE_WIDGETS = {
    "exporter",
    "src-as",
    "dst-as",
    "src-country",
    "dst-country",
    "protocol",
    "etype",
    "src-port",
    "dst-port",
}

# Colonnes optionnelles du schéma ClickHouse d'Akvorado.
#
# SOURCE DE VÉRITÉ (mesurée le 2026-08-07) : `akvorado version -d` exécuté sur
# le BINAIRE déployé (v2.4.1-44-g42e151bb) — pas la documentation, qui n'en
# donne que des exemples et n'est donc pas exhaustive. Toute colonne hors de
# cette liste est refusée par l'orchestrateur au démarrage : l'allowlist doit
# rester FERMÉE, sinon une faute de frappe à l'écran devient un orchestrateur
# qui ne redémarre plus.
SCHEMA_COLUMN_CHOICES = (
    "SrcVlan",
    "DstVlan",
    "SrcCommunities",
    "SrcLargeCommunities",
    "SrcAddrNAT",
    "DstAddrNAT",
    "SrcPortNAT",
    "DstPortNAT",
    "SrcMAC",
    "DstMAC",
    "IPTTL",
    "IPTos",
    "IPFragmentID",
    "IPFragmentOffset",
    "IPv6FlowLabel",
    "TCPFlags",
    "ICMPv4",
    "ICMPv4Type",
    "ICMPv4Code",
    "ICMPv6",
    "ICMPv6Type",
    "ICMPv6Code",
    "NextHop",
    "MPLSLabels",
    "MPLS1stLabel",
    "MPLS2ndLabel",
    "MPLS3rdLabel",
    "MPLS4thLabel",
    "IngressVRFID",
    "EgressVRFID",
)
VALID_SCHEMA_COLUMNS: frozenset[str] = frozenset(SCHEMA_COLUMN_CHOICES)

# Colonnes qui n'existent QUE dans la table principale (`flows`), absentes des
# tables d'agrégation. Conséquence concrète à dire à l'écran : une vue qui
# remonte sur une plage longue tape une table d'agrégation, et ces colonnes y
# sont introuvables — la dimension paraît alors vide sans qu'aucune erreur ne
# soit affichée. Le taire produirait exactement le « zéro silencieux » que ce
# projet combat ailleurs.
MAIN_TABLE_ONLY_COLUMNS: frozenset[str] = frozenset(
    {
        "SrcCommunities",
        "SrcLargeCommunities",
        "SrcAddrNAT",
        "DstAddrNAT",
        "SrcPortNAT",
        "DstPortNAT",
    }
)


def _validate_networks(value: Any) -> list[str]:
    """CIDR valides, noms non vides, pas de doublon (après normalisation)."""
    if not isinstance(value, dict):
        type_name = type(value).__name__
        return [f"'networks.networks' doit etre une map cidr -> declaration (obtenu: {type_name})"]

    errors: list[str] = []
    seen_networks: set[str] = set()
    for cidr, spec in value.items():
        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            errors.append(f"cidr invalide: {cidr!r}")
            continue
        normalized = str(network)
        if normalized in seen_networks:
            errors.append(f"cidr en doublon (apres normalisation): {cidr!r}")
        seen_networks.add(normalized)

        if not isinstance(spec, dict):
            errors.append(f"declaration malformee pour cidr={cidr!r} (attendu un mapping)")
            continue
        name = spec.get("name")
        if not name or not str(name).strip():
            errors.append(f"name vide pour cidr={cidr!r}")

    return errors


def _validate_asns(value: Any) -> list[str]:
    """Clés = entiers positifs (numéros d'AS), valeurs = chaînes non vides."""
    if not isinstance(value, dict):
        return [f"'clickhouse.asns' doit etre une map as -> nom (obtenu: {type(value).__name__})"]

    errors: list[str] = []
    for raw_asn, raw_name in value.items():
        try:
            asn = int(raw_asn)
        except (TypeError, ValueError):
            errors.append(f"numero d'AS non entier: {raw_asn!r}")
            continue
        if asn <= 0:
            errors.append(f"numero d'AS invalide (doit etre positif): {raw_asn!r}")
        if not raw_name or not str(raw_name).strip():
            errors.append(f"nom vide pour l'AS {raw_asn!r}")

    return errors


def _validate_homepage_widgets(value: Any) -> list[str]:
    """Uniquement des valeurs de l'allowlist des widgets connus de la home."""
    if not isinstance(value, list):
        return [f"'homepage-top-widgets' doit etre une liste (obtenu: {type(value).__name__})"]

    errors: list[str] = []
    for widget in value:
        if widget not in _VALID_HOMEPAGE_WIDGETS:
            errors.append(
                f"widget inconnu: {widget!r} (autorises: {sorted(_VALID_HOMEPAGE_WIDGETS)})"
            )
    return errors


def _validate_schema_columns(value: Any) -> list[str]:
    """Uniquement des colonnes de l'allowlist fermée du schéma Akvorado."""
    if not isinstance(value, list):
        return [f"'schema.enabled' doit etre une liste (obtenu: {type(value).__name__})"]

    errors: list[str] = []
    seen: set[str] = set()
    for column in value:
        if column not in VALID_SCHEMA_COLUMNS:
            errors.append(f"colonne inconnue: {column!r} (non acceptee par Akvorado)")
            continue
        if column in seen:
            errors.append(f"colonne en doublon: {column!r}")
        seen.add(str(column))
    return errors


def is_env_reference(raw: Any) -> bool:
    """Vrai si la valeur est une RÉFÉRENCE d'environnement (`${SNMP_COMMUNITY}`)
    et non une communauté en clair.

    C'est la distinction qui décide de TOUT le reste : une référence peut être
    affichée telle quelle (elle ne révèle rien), une valeur en clair ne le peut
    jamais. Voir `mask_community`.
    """
    text = str(raw).strip()
    return text.startswith(_ENV_REF_PREFIX) and text.endswith(_ENV_REF_SUFFIX) and len(text) > 3


def mask_community(raw: Any) -> str:
    """Rend une communauté SNMP AFFICHABLE, jamais en clair.

    Une communauté SNMPv2c est un secret d'authentification : quiconque la
    connaît peut interroger l'équipement. Elle ne doit donc apparaître ni à
    l'écran (capture, partage d'écran, épaule), ni dans les logs, ni dans une
    page mise en cache par le navigateur.

    Une RÉFÉRENCE d'environnement (`${SNMP_COMMUNITY}`) est rendue telle quelle :
    elle ne révèle rien, et la masquer priverait l'opérateur de la seule
    information dont il a besoin à l'écran — savoir QUELLE variable est
    attendue. C'est précisément ce qui rend le mode par référence lisible, donc
    adoptable.
    """
    if raw is None or not str(raw).strip():
        return ""
    if is_env_reference(raw):
        return str(raw).strip()
    return "••••••"


def _validate_snmp_credentials(index: int, credentials: Any) -> list[str]:
    """Valide la table `credentials` d'un fournisseur `snmp` : `sous-réseau ->
    {communities: [...]}`.

    ⚠️ Les messages d'erreur ne contiennent JAMAIS la communauté elle-même : ce
    module ne loggue rien, mais ses retours sont journalisés par l'appelant
    (`log.error(... erreurs=%s ...)` dans le routeur). Une communauté citée dans
    un message de validation serait donc écrite en clair dans les logs — le
    secret fuirait par le chemin d'ERREUR, celui qu'on regarde le moins.
    """
    if not isinstance(credentials, dict):
        return [
            f"fournisseur #{index} (snmp) : 'credentials' doit etre une map "
            f"sous-reseau -> communautes (obtenu: {type(credentials).__name__})"
        ]

    errors: list[str] = []
    if not credentials:
        errors.append(f"fournisseur #{index} (snmp) : aucun sous-reseau declare")

    for subnet, spec in credentials.items():
        try:
            ipaddress.ip_network(str(subnet), strict=False)
        except ValueError:
            errors.append(f"fournisseur #{index} (snmp) : sous-reseau invalide: {subnet!r}")
            continue

        if not isinstance(spec, dict):
            errors.append(
                f"fournisseur #{index} (snmp) : declaration malformee pour {subnet!r} "
                "(attendu un mapping avec 'communities')"
            )
            continue

        # DEUX versions coexistent, et c'est le cas NORMAL pendant une migration :
        #   v2c -> `communities: [...]`
        #   v3  -> `user-name` + protocoles et phrases secrètes
        # Sur un parc de 350 routeurs, la bascule v2c -> v3 s'étale sur des mois :
        # refuser une table mixte rendrait l'écran de configuration inutilisable
        # pendant toute la transition.
        #
        # DÉFAUT MESURÉ (2026-08-08) : ce validateur n'acceptait QUE `communities`.
        # Reproduit — une entrée v3 seule ET une table mixte v2c+v3 étaient toutes
        # deux rejetées. L'opérateur qui aurait migré un sous-réseau en v3 n'aurait
        # plus pu toucher à sa configuration depuis l'écran.
        if "user-name" in spec:
            errors.extend(_validate_snmp_v3_entry(index, subnet, spec))
            continue

        communities = spec.get("communities")
        if not isinstance(communities, list) or not communities:
            errors.append(
                f"fournisseur #{index} (snmp) : {subnet!r} doit declarer soit "
                "'communities' (SNMPv2c, liste non vide) soit 'user-name' (SNMPv3)"
            )
            continue

        for community in communities:
            if not str(community).strip():
                # Le sous-réseau est cité, jamais la communauté (secret).
                errors.append(f"fournisseur #{index} (snmp) : communaute vide pour {subnet!r}")

    return errors


def _validate_snmp_v3_entry(index: int, subnet: Any, spec: dict[str, Any]) -> list[str]:
    """Valide une entrée SNMPv3 (modèle utilisateur USM).

    ⚠️ Même règle que pour les communautés, et elle compte DAVANTAGE ici : les
    phrases secrètes v3 ne sont JAMAIS citées dans un message d'erreur. Ces
    retours sont journalisés par le routeur appelant — un secret cité fuirait
    par le chemin d'ERREUR, celui qu'on surveille le moins.

    Les trois niveaux de sécurité de la RFC 3414 sont acceptés :
      noAuthNoPriv  — `user-name` seul
      authNoPriv    — + protocole et phrase d'authentification
      authPriv      — + protocole et phrase de chiffrement
    Une phrase sans son protocole (ou l'inverse) est un défaut de configuration
    qui se traduirait par un échec d'authentification silencieux côté agent.
    """
    errors: list[str] = []

    if not str(spec.get("user-name", "")).strip():
        errors.append(f"fournisseur #{index} (snmp v3) : 'user-name' vide pour {subnet!r}")

    for protocole, phrase, niveau in (
        ("authentication-protocol", "authentication-passphrase", "authentification"),
        ("privacy-protocol", "privacy-passphrase", "chiffrement"),
    ):
        a_protocole = bool(str(spec.get(protocole, "")).strip())
        a_phrase = bool(str(spec.get(phrase, "")).strip())
        if a_protocole != a_phrase:
            manquant = phrase if a_protocole else protocole
            errors.append(
                f"fournisseur #{index} (snmp v3) : {subnet!r} declare un {niveau} "
                f"incomplet — '{manquant}' manque"
            )

    # Le chiffrement sans authentification n'existe pas dans la RFC 3414 : il
    # serait accepte par la config et rejete par l'agent, sans explication.
    if (
        str(spec.get("privacy-protocol", "")).strip()
        and not str(spec.get("authentication-protocol", "")).strip()
    ):
        errors.append(
            f"fournisseur #{index} (snmp v3) : {subnet!r} declare un chiffrement sans "
            "authentification — ce niveau n'existe pas (RFC 3414)"
        )

    return errors


def _validate_metadata_providers(value: Any) -> list[str]:
    """Valide la CASCADE de découverte des interfaces (`metadata.providers`).

    Trois garanties, dans cet ordre d'importance :

    1. `type` dans l'allowlist fermée. Un type inconnu fait refuser tout le
       document par l'outlet au démarrage : plus aucune collecte.
    2. Ordre de la cascade : `static` doit précéder `snmp` (voir la constante
       `_FALLTHROUGH_PROVIDER`). Un ordre inversé n'est PAS refusé — c'est un
       choix légitime pour qui veut que l'équipement fasse foi sans repli — mais
       il est SIGNALÉ, parce que le repli statique devient alors inatteignable
       en silence.
    3. Réglages SNMP (`workers`, `poller-retries`, `poller-timeout`,
       `credentials`) bornés et typés.

    Aucun message d'erreur ne contient de communauté SNMP (voir
    `_validate_snmp_credentials`).
    """
    if not isinstance(value, list):
        return [f"'metadata.providers' doit etre une liste (obtenu: {type(value).__name__})"]

    if not value:
        # Une cascade VIDE n'est pas une cascade neutre : Akvorado n'a alors
        # aucune source de métadonnées et TOUS les flux retombent en
        # `unknown` — exactement le défaut vécu (76 000 flux, 2026-08-05).
        return [
            "'metadata.providers' ne peut pas etre vide : sans aucun fournisseur, "
            "toutes les interfaces seraient inconnues et les flux classes 'unknown'"
        ]

    errors: list[str] = []
    types_in_order: list[str] = []

    for index, provider in enumerate(value):
        if not isinstance(provider, dict):
            errors.append(f"fournisseur #{index} malforme (attendu un mapping)")
            continue

        provider_type = provider.get("type")
        if provider_type is None:
            errors.append(f"fournisseur #{index} : 'type' manquant")
            continue

        provider_type = str(provider_type)
        types_in_order.append(provider_type)
        if provider_type not in VALID_METADATA_PROVIDER_TYPES:
            errors.append(
                f"fournisseur #{index} : type inconnu {provider_type!r} "
                f"(autorises: {sorted(VALID_METADATA_PROVIDER_TYPES)})"
            )
            continue

        if provider_type != "snmp":
            # `static`, `gnmi` et `bioris` ne sont PAS édités par cet écran :
            # ils sont relus et réécrits tels quels. Les valider en profondeur
            # reviendrait à refuser un `static` existant, pourtant en
            # production, sur un champ que cet écran ne sait pas construire.
            continue

        errors.extend(_validate_snmp_settings(index, provider))

    errors.extend(check_cascade_order(types_in_order))
    return errors


def _validate_snmp_settings(index: int, provider: dict[str, Any]) -> list[str]:
    """Bornes des leviers de réglage SNMP — ceux qu'on touche quand SNMP est lent."""
    errors: list[str] = []

    for field_name, maximum in (
        ("workers", _MAX_SNMP_WORKERS),
        ("poller-retries", _MAX_SNMP_RETRIES),
    ):
        raw = provider.get(field_name)
        if raw is None:
            continue
        if not isinstance(raw, int) or isinstance(raw, bool) or raw < 1 or raw > maximum:
            errors.append(
                f"fournisseur #{index} (snmp) : '{field_name}' doit etre un entier "
                f"entre 1 et {maximum} (obtenu: {raw!r})"
            )

    timeout = provider.get("poller-timeout")
    if timeout is not None and not _is_duration(timeout):
        errors.append(
            f"fournisseur #{index} (snmp) : 'poller-timeout' doit etre une duree "
            f"(ex. '1s', '500ms', '2m'), obtenu: {timeout!r}"
        )

    errors.extend(_validate_snmp_credentials(index, provider.get("credentials")))
    return errors


def _is_duration(raw: Any) -> bool:
    """Forme d'une durée Go NON NULLE (`1s`, `500ms`, `2m`) — celle qu'attend
    Akvorado.

    Un entier nu (`5`) est refusé : Go le lirait comme 5 NANOSECONDES, soit un
    délai d'attente qui expire avant toute réponse. Un réglage censé rendre SNMP
    plus tolérant le rendrait totalement inopérant, sans erreur de parsing.

    `0s` est refusé pour la MÊME raison, et c'est le piège le plus vicieux des
    deux : il a la forme d'une durée valide, il passe tout contrôle syntaxique,
    et il produit exactement le même effet qu'un entier nu — un délai qui expire
    immédiatement, donc plus aucune interface résolue par SNMP. Accepter la
    forme tout en refusant l'entier nu aurait laissé grande ouverte la porte
    qu'on croyait fermer. (Mesuré le 2026-08-07.)

    `re.ASCII` est explicite : sans lui, `\\d` accepte les chiffres Unicode
    (`٣s`), que Go refuse — l'écran validerait une durée que l'outlet rejette au
    démarrage.
    """
    text = str(raw).strip()
    if not _DURATION_RE.fullmatch(text):
        return False
    # Au moins un composant non nul : `0s`, `0ms`, `0s0ms` sont des délais nuls.
    return any(float(amount) > 0 for amount in _DURATION_AMOUNT_RE.findall(text))


def check_cascade_order(types_in_order: list[str]) -> list[str]:
    """Signale TOUT `static` placé après un `snmp` — repli devenu inatteignable.

    La comparaison porte sur le PREMIER `snmp` et sur CHAQUE `static` situé
    après lui, et non sur les seules premières occurrences des deux types : une
    cascade `['static', 'snmp', 'static']` a bien un repli consulté (le
    premier), mais le SECOND est mort — `snmp` accepte toutes les requêtes et
    arrête le parcours avant lui. Ne comparer que les premières occurrences
    aurait déclaré cette cascade saine, alors qu'un opérateur y a écrit des
    ifIndex qui ne seront jamais lus. (Relevé à la revue, 2026-08-07.)
    """
    if "snmp" not in types_in_order:
        return []

    first_snmp = types_in_order.index("snmp")
    unreachable = [
        position
        for position, provider_type in enumerate(types_in_order)
        if provider_type == _FALLTHROUGH_PROVIDER and position > first_snmp
    ]
    if not unreachable:
        return []

    ranks = ", ".join(f"#{position + 1}" for position in unreachable)
    return [
        f"ordre de cascade : le(s) fournisseur(s) 'static' {ranks} sont places APRES "
        "'snmp'. Akvorado s'arrete au premier fournisseur qui accepte la requete, et "
        "'snmp' les accepte toutes : ce repli statique ne serait plus JAMAIS consulte. "
        "Remontez 'static' avant 'snmp'."
    ]


def _validate_saved_filters(value: Any) -> list[str]:
    """Chaque entrée a `description` et `content` non vides."""
    if not isinstance(value, list):
        return [f"'database.saved-filters' doit etre une liste (obtenu: {type(value).__name__})"]

    errors: list[str] = []
    for index, entry in enumerate(value):
        if not isinstance(entry, dict):
            errors.append(f"filtre #{index} malforme (attendu un mapping)")
            continue
        description = entry.get("description")
        if not description or not str(description).strip():
            errors.append(f"filtre #{index}: 'description' vide")
        content = entry.get("content")
        if not content or not str(content).strip():
            errors.append(f"filtre #{index}: 'content' vide")
    return errors


def _validate_flow_inputs(value: Any) -> list[str]:
    """Chaque entrée a `type`, `decoder`, `listen` ; port dans 1..65535 ;
    décodeur dans {netflow, sflow}."""
    if not isinstance(value, list):
        return [f"'flow.inputs' doit etre une liste (obtenu: {type(value).__name__})"]

    errors: list[str] = []
    for index, entry in enumerate(value):
        if not isinstance(entry, dict):
            errors.append(f"entree flow input #{index} malformee (attendu un mapping)")
            continue

        for field_name in ("type", "decoder", "listen"):
            if not entry.get(field_name):
                errors.append(f"entree flow input #{index}: '{field_name}' manquant")

        decoder = entry.get("decoder")
        if decoder is not None and decoder not in _VALID_DECODERS:
            errors.append(
                f"entree flow input #{index}: decodeur inconnu {decoder!r} "
                f"(autorises: {sorted(_VALID_DECODERS)})"
            )

        listen = entry.get("listen")
        if listen:
            port_part = str(listen).rsplit(":", 1)[-1]
            try:
                port = int(port_part)
            except ValueError:
                errors.append(f"entree flow input #{index}: port illisible dans listen={listen!r}")
            else:
                if not (1 <= port <= _MAX_PORT):
                    errors.append(
                        f"entree flow input #{index}: port hors bornes "
                        f"({port}, attendu 1..{_MAX_PORT})"
                    )
    return errors


def _validate_visualize_defaults(value: Any) -> list[str]:
    """`limit` entier > 0, `dimensions` = liste non vide."""
    if not isinstance(value, dict):
        return [
            f"'default-visualize-options' doit etre un mapping (obtenu: {type(value).__name__})"
        ]

    errors: list[str] = []
    limit = value.get("limit")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        errors.append(f"'limit' doit etre un entier positif (obtenu: {limit!r})")

    dimensions = value.get("dimensions")
    if not isinstance(dimensions, list) or not dimensions:
        errors.append(f"'dimensions' doit etre une liste non vide (obtenu: {dimensions!r})")

    return errors


def _validate_list_structure(value: Any, label: str) -> list[str]:
    """Validation structurelle minimale : la valeur doit être une liste."""
    if not isinstance(value, list):
        return [f"'{label}' doit etre une liste (obtenu: {type(value).__name__})"]
    return []


def _validate_exporter_classifiers(value: Any) -> list[str]:
    return _validate_list_structure(value, "core.exporter-classifiers")


def _validate_interface_classifiers(value: Any) -> list[str]:
    return _validate_list_structure(value, "core.interface-classifiers")


def _validate_kafka_retention(value: Any) -> list[str]:
    """Validation structurelle minimale : doit être un mapping."""
    if not isinstance(value, dict):
        return [
            f"'kafka.topic-configuration' doit etre un mapping (obtenu: {type(value).__name__})"
        ]
    return []


@dataclass(frozen=True)
class ConfigSection:
    """Description déclarative d'une section de configuration éditable."""

    key: str
    label: str
    description: str
    file: str
    dotted_key: str
    kind: str
    restart_services: tuple[str, ...]
    validator: Validator
    doc_url: str = ""
    integer_keys: bool = False
    """Les clés de ce mapping sont des ENTIERS dans le YAML.

    DÉFAUT MESURÉ (2026-08-06) : la file d'attente stocke chaque changement en
    JSON, or **JSON n'a pas de clé entière** — `{64501: "ACME"}` en ressort en
    `{"64501": "ACME"}`. Écrite telle quelle, la table des noms d'AS aurait
    porté des clés chaînes qu'Akvorado ne rapproche d'aucun AS observé : les
    noms n'auraient simplement jamais été appliqués, sans la moindre erreur ni
    dans les logs ni à l'écran.

    Ce drapeau permet de restaurer le type au moment de l'écriture YAML. Il est
    déclaré ICI, dans le catalogue, parce que c'est une propriété du FORMAT de
    la section — pas du chemin qui l'écrit.
    """


SECTIONS: dict[str, ConfigSection] = {
    "networks": ConfigSection(
        key="networks",
        label="Plan d'adressage",
        description=(
            "Nomme les sous-réseaux (CIDR) du homelab pour afficher des noms "
            "lisibles dans les vues au lieu d'IP brutes."
        ),
        file="outlet.yaml",
        dotted_key="networks.networks",
        kind="mapping",
        restart_services=("akvorado-outlet",),
        validator=_validate_networks,
    ),
    "asns": ConfigSection(
        key="asns",
        label="Noms d'AS maison",
        description=(
            "Associe un nom lisible aux numéros d'AS internes (RFC 6996). "
            "Fort levier : 87% du top AS affiche « 0 : ??? » sans cette table."
        ),
        file="akvorado.yaml",
        dotted_key="clickhouse.asns",
        kind="mapping",
        restart_services=(),  # orchestrator : pris en compte automatiquement, pas de restart
        validator=_validate_asns,
        # Un numéro d'AS est un entier dans `akvorado.yaml`. Sans ce drapeau, le
        # passage par le JSON de la file d'attente le transformerait en chaîne
        # (voir la docstring de `integer_keys`) et la table resterait sans effet.
        integer_keys=True,
    ),
    "exporter_classifiers": ConfigSection(
        key="exporter_classifiers",
        label="Règles de classification des exportateurs",
        description=(
            "Mini-langage d'expressions qui classe automatiquement les "
            "exportateurs (site, région, rôle) à l'ingestion."
        ),
        file="outlet.yaml",
        dotted_key="core.exporter-classifiers",
        kind="list",
        restart_services=("akvorado-outlet",),
        validator=_validate_exporter_classifiers,
    ),
    "interface_classifiers": ConfigSection(
        key="interface_classifiers",
        label="Règles de classification des interfaces",
        description="Mini-langage d'expressions qui classe les interfaces observées.",
        file="outlet.yaml",
        dotted_key="core.interface-classifiers",
        kind="list",
        restart_services=("akvorado-outlet",),
        validator=_validate_interface_classifiers,
    ),
    "visualize_defaults": ConfigSection(
        key="visualize_defaults",
        label="Vue par défaut de Visualize",
        description="Ce qu'on voit en ouvrant Visualize : période, dimensions, limite.",
        file="console.yaml",
        dotted_key="default-visualize-options",
        kind="mapping",
        restart_services=("akvorado-console",),
        validator=_validate_visualize_defaults,
    ),
    "homepage_widgets": ConfigSection(
        key="homepage_widgets",
        label="Widgets de la page d'accueil",
        description="Les dimensions affichées en widgets sur la page d'accueil de la console.",
        file="console.yaml",
        dotted_key="homepage-top-widgets",
        kind="list",
        restart_services=("akvorado-console",),
        validator=_validate_homepage_widgets,
    ),
    "saved_filters": ConfigSection(
        key="saved_filters",
        label="Filtres enregistrés",
        description=(
            "Filtres système proposés dans la console. Attention : "
            "resynchronisés DESTRUCTIVEMENT au démarrage — ce YAML est la "
            "seule source de vérité pour ces filtres."
        ),
        file="console.yaml",
        dotted_key="database.saved-filters",
        kind="list",
        restart_services=("akvorado-console",),
        validator=_validate_saved_filters,
    ),
    "flow_inputs": ConfigSection(
        key="flow_inputs",
        label="Ports d'écoute des flux",
        description="Ports et décodeurs sur lesquels l'inlet écoute (NetFlow, sFlow).",
        file="inlet.yaml",
        dotted_key="flow.inputs",
        kind="list",
        restart_services=("akvorado-inlet",),
        validator=_validate_flow_inputs,
    ),
    "schema_columns": ConfigSection(
        key="schema_columns",
        label="Colonnes du schéma",
        description=(
            "Champs optionnels stockés pour chaque flux (QoS/DSCP, VLAN, MAC, "
            "MPLS, ICMP…). Activer « IPTos » débloque le widget Top N QoS. "
            "Chaque colonne activée alourdit la table et le stockage."
        ),
        file="akvorado.yaml",
        dotted_key="schema.enabled",
        kind="list",
        # DEUX services, et l'omission de l'outlet a été MESURÉE (2026-08-07) :
        # l'orchestrateur porte les migrations — il crée bien la colonne dans
        # ClickHouse — mais c'est l'OUTLET qui décode les flux Kafka et remplit
        # les colonnes. Redémarrer le seul orchestrateur donnait une colonne
        # `IPTos` existante et TOUJOURS À ZÉRO : l'outlet continuait de tourner
        # avec l'ancien schéma, ignorant le champ que softflowd lui envoyait.
        #
        # Symptôme exact : 1320 paquets marqués AF21 côté iptables, colonne
        # créée en base, et `SELECT IPTos, count()` rendant `0  16367`. Aucune
        # erreur nulle part — le pire profil de défaut, celui où tout paraît
        # fonctionner.
        restart_services=("orchestrator", "akvorado-outlet"),
        validator=_validate_schema_columns,
    ),
    "metadata_providers": ConfigSection(
        key="metadata_providers",
        label="Découverte des interfaces (SNMP)",
        description=(
            "Comment Akvorado retrouve le NOM d'une interface à partir de son "
            "seul index (ifIndex) : en interrogeant l'équipement en SNMP, ou "
            "depuis une table écrite à la main. Les fournisseurs sont "
            "interrogés DANS L'ORDRE, jusqu'au premier qui répond."
        ),
        file="outlet.yaml",
        dotted_key="metadata.providers",
        kind="list",
        restart_services=("akvorado-outlet",),
        validator=_validate_metadata_providers,
        # ⚠️ LIMITE CONNUE ET MESURÉE (2026-08-07) — les clés d'ifIndex du
        # fournisseur `static` sont des ENTIERS dans le YAML
        # (`ifindexes: {219: {...}}`), or la file d'attente sérialise chaque
        # changement en JSON, qui n'a pas de clé entière : elles en ressortent
        # en `{"219": {...}}`.
        #
        # Le mécanisme qui corrige exactement ce défaut existe déjà :
        # `config_writer._restore_key_types`, appliqué au DÉSÉRIALISATION (donc
        # au bon moment), piloté par le drapeau `integer_keys` ci-dessous. Mais
        # il ne convertit que les clés de PREMIER NIVEAU d'un mapping
        # (`clickhouse.asns`) : ici la valeur est une LISTE de fournisseurs et
        # les clés à restaurer sont imbriquées trois niveaux plus bas.
        # `integer_keys=True` serait donc inopérant — il est laissé à False
        # plutôt que posé pour la forme.
        #
        # POURQUOI LA CORRECTION N'EST PAS ICI : la conversion doit avoir lieu à
        # la DÉSÉRIALISATION, juste avant l'écriture YAML — c'est ce que fait
        # `_restore_key_types`, appelé par `apply_pending_changes`. La tenter au
        # moment de la mise en file serait sans effet : la sérialisation JSON
        # qui suit re-transformerait immédiatement les clés en chaînes.
        # Vérifié par mesure le 2026-08-07 : un correctif posé côté routeur
        # produisait bien `{219: ...}` en mémoire et `{"219": ...}` en base.
        # Un correctif qui a l'air juste et ne fait rien est pire que pas de
        # correctif — il a donc été retiré plutôt que gardé pour la forme.
        #
        # Portée réelle du défaut : cet écran ne CONSTRUIT que le fournisseur
        # `snmp`, dont aucune clé n'est entière (les `credentials` sont indexés
        # par CIDR). Le `static` est relu et reposé tel quel, jamais reconstruit
        # (voir `_apply_metadata_providers_form`) — et sa suppression est
        # bloquée par `guard_static_provider_survives`. La conversion ne mord
        # donc qu'au moment où `apply_pending_changes` réécrira le document.
        # Correction à porter dans `config_writer` (hors périmètre de ce lot) :
        # généraliser `_restore_key_types` aux clés imbriquées sous une liste.
        # Fixé par `test_la_limite_des_cles_entieres_est_connue_et_documentee`,
        # qui échouera le jour où ce sera corrigé — donc jamais oublié.
    ),
    "kafka_retention": ConfigSection(
        key="kafka_retention",
        label="Rétention du buffer Kafka",
        description="Durée de rétention du buffer de flux avant ingestion ClickHouse.",
        file="akvorado.yaml",
        dotted_key="kafka.topic-configuration",
        kind="mapping",
        restart_services=("orchestrator",),
        validator=_validate_kafka_retention,
    ),
}


def get_section(key: str) -> ConfigSection:
    """Retourne la `ConfigSection` correspondant à `key`.

    Raises:
        ValueError: si `key` n'existe pas dans le catalogue. C'est la SEULE
            porte d'entrée : une `key` inconnue (y compris une tentative de
            forger un chemin arbitraire) est refusée avant tout accès disque.
    """
    try:
        return SECTIONS[key]
    except KeyError:
        raise ValueError(
            f"section de configuration inconnue: {key!r} (disponibles: {sorted(SECTIONS)})"
        ) from None


def list_sections() -> list[ConfigSection]:
    """Liste toutes les sections du catalogue."""
    return list(SECTIONS.values())
