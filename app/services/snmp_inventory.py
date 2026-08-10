"""Inventaire équipement — collecte SNMP de la MIB-II système par exportateur.

CE QUE CE MODULE AJOUTE (mesuré, cf. tâche) : la table ClickHouse
`default.exporters` d'Akvorado ne porte QUE des champs d'INTERFACE (`IfName`,
`IfSpeed`, `IfBoundary`...) — rien au niveau ÉQUIPEMENT (nom système,
description, localisation, uptime). C'est l'écran « Device Summary » de
ManageEngine NetFlow Analyzer que ce module reproduit, en interrogeant les 5
objets scalaires standard de la MIB-II système (RFC 1213) :

    1.3.6.1.2.1.1.1.0  sysDescr
    1.3.6.1.2.1.1.3.0  sysUpTime
    1.3.6.1.2.1.1.4.0  sysContact
    1.3.6.1.2.1.1.5.0  sysName
    1.3.6.1.2.1.1.6.0  sysLocation

BIBLIOTHÈQUE RETENUE — `pysnmp` (pur Python, `pysnmp.hlapi.v3arch.asyncio`) :
mesuré le 2026-08-08 que `snmpget`/`snmpwalk` (net-snmp) ne sont PAS installés
dans l'image `okvorado` (`python:3.13-slim`, aucun paquet apt ajouté) — passer
par un sous-processus aurait exigé d'ajouter net-snmp au Dockerfile en plus
d'une dépendance Python. `pysnmp` évite entièrement cette dépendance système
ET tout usage de sous-processus (donc aucun risque `shell=True`/injection de
commande par construction).

DÉPENDANCE `cryptography` — NON NÉGOCIABLE pour SNMPv3 `authPriv` (root cause
mesurée le 2026-08-08 contre un agent SNMP réel, cf. `_PRIV_PROTOCOL_MAP`
ci-dessous) : `pysnmp` ne déclare AUCUN backend de chiffrement comme
dépendance obligatoire (`cryptography` n'apparaît que dans son extra `dev`)
— sans lui installé, tout sondage `authPriv` (AES/DES) échoue avec un
`error_indication` de classe `pysnmp.proto.errind.EncryptionError`
("Ciphering services not available"). Cette classe n'étant PAS dans
`_AUTHENTICATION_FAILURE_INDICATIONS` (ce n'est pas un refus
d'authentification de l'agent, c'est l'incapacité LOCALE à chiffrer),
`_snmp_get_scalars_async` la traite comme un échec générique et rend `None`
-> `status='no_response'` : un zéro silencieux qui fait passer un paquet
Python manquant pour une panne réseau/agent (piège vécu : la mesure de
preuve v3 en `authPriv` rendait `None` pour un bon ET un mauvais mot de
passe, alors que `snmpget` en CLI répondait correctement — CLI net-snmp et
`pysnmp` ne partagent pas leurs dépendances). `cryptography` est donc
déclarée en dépendance de base (pas `dev`) dans `pyproject.toml`.

SÉCURITÉ (non négociable, cf. tâche) :
  - la communauté SNMP vient TOUJOURS de `settings.snmp_community` (variable
    d'environnement `OKVORADO_SNMP_COMMUNITY`) ou d'un paramètre explicite —
    jamais une valeur en dur, jamais logguée, jamais rendue en clair (même
    convention que `mask_community` dans `app.services.config_sections`) ;
  - aucun sous-processus : `pysnmp` fait tout en Python, il n'y a donc
    structurellement AUCUNE commande shell construite depuis une valeur
    utilisateur (pas de `shell=True`, pas de concaténation) ;
  - l'adresse interrogée est fournie par l'appelant à partir de la liste des
    exportateurs CONNUS (observés/déclarés par Akvorado, cf.
    `app.routers.exporters.load_exporter_statuses`) — ce module ne résout
    JAMAIS une adresse depuis une saisie libre.

ZÉRO SILENCIEUX (CLAUDE.md règle n°2) : un agent qui ne répond pas produit
`status='no_response'`, jamais des champs `sys_*` vides qu'on confondrait
avec un équipement réellement sans nom (piège déjà vécu ici : un nom de
repli pris pour un nom légitime). `sys_name` reste `NULL` en base tant
qu'aucune collecte n'a réussi — jamais une chaîne vide ni l'adresse IP en
repli silencieux.

COEXISTENCE SNMPv2c / SNMPv3 (migration progressive du parc, 350 routeurs
SFR) : `status` porte désormais TROIS valeurs — `'ok'`, `'no_response'`,
`'auth_failure'`. `'auth_failure'` est DISTINCT de `'no_response'` : un
mauvais mot de passe/niveau de sécurité SNMPv3 (l'agent RÉPOND mais refuse
l'authentification) n'est pas le même cas qu'un agent qui ne répond pas du
tout (timeout, silence sur le fil) — la distinction compte pour le
diagnostic, ces deux causes se corrigent différemment (config Okvorado côté
credentials vs. panne côté équipement/réseau). Mélanger les deux sous un
seul état serait un zéro silencieux au sens de CLAUDE.md règle n°2.

CREDENTIALS SNMPv3 — DÉCISION DE CONCEPTION (sécurité, non négociable) : les
mots de passe SNMPv3 (`auth_password`, `priv_password`) ne sont JAMAIS
stockés par device dans une table SQLite, même chiffrée applicativement. Le
fichier `data/okvorado.db` n'est pas un coffre-fort au même sens qu'un
secret manager (contrôle d'accès, rotation, audit) : il pourrait être
copié/exfiltré sans que cette protection s'applique. Design retenu : UN SEUL
couple de mots de passe v3 « par défaut global » vit dans `app.config`
(variables d'environnement `OKVORADO_SNMP_V3_*`, jamais en base). Par
device, SEULE la version choisie (`'v2c'` ou `'v3'`) est persistée
(colonne `snmp_inventory.snmp_version`) — un device en v3 utilise TOUJOURS
les credentials v3 globaux de `settings`. Un futur lecteur qui s'attendrait
à une table de credentials par device : c'est un choix délibéré, pas un
oubli.
"""

from __future__ import annotations

import ipaddress
import logging
import sqlite3
from typing import Any

from pydantic import BaseModel

from app.config import settings

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OID standard MIB-II système (RFC 1213) — littéraux en dur, jamais dérivés
# d'une saisie utilisateur.
# ---------------------------------------------------------------------------

_OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
_OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
_OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
_OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
_OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

# ---------------------------------------------------------------------------
# OID de la TABLE d'interfaces (IF-MIB, RFC 2863) — littéraux figés, jamais
# dérivés d'une saisie utilisateur (même règle que les scalaires ci-dessus).
# ---------------------------------------------------------------------------

_OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
"""IF-MIB::ifName — le nom COURT de l'interface, celui qu'Akvorado attend
dans `if-indexes[N].name` (`eth0`, `tailscale0`, `Gi0/1`).

MESURÉ le 2026-08-10 sur un exportateur du parc : un walk de cet OID rend la
table COMPLÈTE et EXACTE (ifName.1=lo, ifName.2=eth0, ifName.3=tailscale0,
ifName.4=br-780869fa3032) — c'est littéralement ce que l'exploitant recopiait
à la main dans `outlet.yaml`, à ceci près qu'à la main il se trompait."""

_OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
"""IF-MIB::ifDescr — REPLI quand `ifName` est vide.

`ifName` est une extension (ifXTable, RFC 2863) : tous les agents ne la
peuplent pas. Les agents anciens ou minimalistes ne remplissent QUE `ifDescr`
(MIB-II d'origine, RFC 1213). Sans ce repli, ces équipements-là rendraient
une table vide et retomberaient dans le geste manuel que ce module supprime.
Le repli n'est tenté QUE si `ifName` n'a rien rendu : un walk coûte un
aller-retour réseau par ligne, à 350 routeurs le doubler systématiquement
serait payé pour rien."""

_SCALAR_OIDS: tuple[tuple[str, str], ...] = (
    ("sys_descr", _OID_SYS_DESCR),
    ("sys_uptime_ticks", _OID_SYS_UPTIME),
    ("sys_contact", _OID_SYS_CONTACT),
    ("sys_name", _OID_SYS_NAME),
    ("sys_location", _OID_SYS_LOCATION),
)


class InventoryItem(BaseModel):
    """Un équipement inventorié — jamais la communauté SNMP dans ce modèle,
    elle ne transite nulle part au-delà de la fonction de sondage."""

    address: str
    sys_name: str | None = None
    sys_descr: str | None = None
    sys_location: str | None = None
    sys_contact: str | None = None
    sys_uptime_ticks: int | None = None
    status: str
    """`'ok'` (dernière collecte réussie), `'no_response'` (agent muet ou
    sans réponse exploitable sur la dernière tentative — timeout inclus) ou
    `'auth_failure'` (l'agent a répondu mais a refusé l'authentification
    SNMPv3 : mauvais username/mot de passe/niveau de sécurité). ZÉRO
    SILENCIEUX : ces trois causes sont distinctes et ne doivent jamais être
    confondues, un mauvais mot de passe ne se corrige pas comme un agent qui
    ne répond pas — jamais une quatrième valeur implicite."""

    snmp_version: str = "v2c"
    """`'v2c'` ou `'v3'` — version SNMP effective utilisée pour la dernière
    tentative de collecte de cet équipement."""

    first_seen_at: str
    last_attempt_at: str
    last_success_at: str | None = None

    @property
    def uptime_label(self) -> str:
        if self.sys_uptime_ticks is None:
            return "—"
        return format_uptime(self.sys_uptime_ticks)

    @property
    def is_responding(self) -> bool:
        return self.status == "ok"

    @property
    def has_auth_failure(self) -> bool:
        """Distinction visuelle dédiée : un `auth_failure` est un problème de
        CONFIGURATION (credentials v3), pas une panne réseau/agent — l'écran
        ne doit jamais l'afficher comme un simple `no_response`."""
        return self.status == "auth_failure"


# ---------------------------------------------------------------------------
# Conversion sysUpTime (centièmes de seconde, TimeTicks RFC 1213) -> durée lisible
# ---------------------------------------------------------------------------


def format_uptime(ticks: int) -> str:
    """Convertit un `sysUpTime` (centièmes de seconde) en durée lisible.

    Reproduit le format de la capture de référence : « 80 days, 9 hours, 3
    minutes, 30 seconds. » Une valeur négative ou aberrante ne lève JAMAIS
    d'exception (zéro silencieux appliqué à l'inverse : ne jamais transformer
    une valeur mesurable en 500 nu) — elle dégrade vers un repli explicite.
    """
    if not isinstance(ticks, int) or ticks < 0:
        log.error("sysUpTime hors domaine, repli affiche: ticks=%r", ticks)
        return "durée inconnue"

    total_seconds = ticks // 100
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts: list[str] = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours or days:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes or hours or days:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")

    return ", ".join(parts) + "."


# ---------------------------------------------------------------------------
# SNMPv3 — credentials USM et erreur d'authentification dédiée
# ---------------------------------------------------------------------------


class SnmpAuthenticationError(Exception):
    """Levée quand l'agent RÉPOND mais refuse l'authentification SNMPv3.

    DISTINCT de `None` (retour de `_snmp_get_scalars`) : `None` reste
    strictement réservé à "pas de réponse exploitable, cause indéterminée ou
    timeout" (`status='no_response'`). Cette exception signale un problème de
    CONFIGURATION (mauvais username/mot de passe/niveau de sécurité côté
    Okvorado), pas une panne côté équipement — `collect_one` la capture
    spécifiquement pour écrire `status='auth_failure'`. Ne contient JAMAIS le
    mot de passe utilisé (seulement l'adresse et le nom de la classe
    d'erreur pysnmp), pour rester sûre à logger si besoin."""


class SnmpV3Credentials(BaseModel):
    """Credentials USM (User-based Security Model) SNMPv3 pour un sondage.

    Pas de valeur en dur : ce modèle est construit par l'appelant depuis
    `settings.snmp_v3_*` (credentials v3 globaux, cf. docstring de module) —
    jamais stocké tel quel en base."""

    username: str
    security_level: str
    """`"noAuthNoPriv"` | `"authNoPriv"` | `"authPriv"`."""

    auth_protocol: str | None = None
    """`"MD5"` | `"SHA"` | `"SHA224"` | `"SHA256"` | `"SHA384"` | `"SHA512"`,
    ou `None` si `security_level="noAuthNoPriv"`."""

    auth_password: str | None = None
    priv_protocol: str | None = None
    """`"DES"` | `"AES"` | `"AES192"` | `"AES256"` | `"3DES"`, ou `None`."""

    priv_password: str | None = None


_AUTH_PROTOCOL_MAP: dict[str, str] = {
    "MD5": "usmHMACMD5AuthProtocol",
    "SHA": "usmHMACSHAAuthProtocol",
    "SHA224": "usmHMAC128SHA224AuthProtocol",
    "SHA256": "usmHMAC192SHA256AuthProtocol",
    "SHA384": "usmHMAC256SHA384AuthProtocol",
    "SHA512": "usmHMAC384SHA512AuthProtocol",
}
"""Mapping nom lisible -> nom de constante `pysnmp.hlapi.v3arch.asyncio`.
Table figée : jamais dérivée d'une saisie utilisateur, un protocole absent
de cette table lève `ValueError` (jamais un repli silencieux)."""

_PRIV_PROTOCOL_MAP: dict[str, str] = {
    "DES": "usmDESPrivProtocol",
    "AES": "usmAesCfb128Protocol",
    "AES192": "usmAesCfb192Protocol",
    "AES256": "usmAesCfb256Protocol",
    "3DES": "usm3DESEDEPrivProtocol",
}

_AUTHENTICATION_FAILURE_INDICATIONS: tuple[str, ...] = (
    "AuthenticationFailure",
    "WrongDigest",
    "UnknownUserName",
    "UnsupportedSecurityLevel",
    "NotInTimeWindow",
    "UnsupportedAuthProtocol",
    "UnsupportedPrivProtocol",
    "UnknownSecurityName",
)
"""Noms de classes `pysnmp.proto.errind` qui signalent un échec
d'AUTHENTIFICATION (agent qui répond mais refuse) — à distinguer d'un
`RequestTimedOut` (agent muet). Comparé par nom de classe plutôt que par
import direct des classes : évite d'alourdir l'import différé de
`_build_usm_user_data` (appelée hors contexte réseau, ex. en test) avec les
symboles `errind`, tout en gardant `isinstance` côté site d'usage réel."""


def _build_usm_user_data(creds: SnmpV3Credentials) -> Any:
    """Traduit `SnmpV3Credentials` en `UsmUserData` pysnmp.

    Lève `ValueError` — jamais une exception opaque, jamais un repli
    silencieux vers `noAuthNoPriv` — si `security_level="authPriv"` mais
    `priv_protocol` est `None`, ou si un protocole demandé n'est pas dans la
    table supportée ci-dessus.
    """
    from pysnmp.hlapi import v3arch  # noqa: PLC0415 - import différé volontaire

    asyncio_ns = v3arch.asyncio

    if creds.security_level not in ("noAuthNoPriv", "authNoPriv", "authPriv"):
        raise ValueError(
            f"security_level SNMPv3 invalide: {creds.security_level!r} "
            "(attendu: noAuthNoPriv, authNoPriv, authPriv)"
        )

    auth_protocol_obj = asyncio_ns.usmNoAuthProtocol
    if creds.security_level in ("authNoPriv", "authPriv"):
        if creds.auth_protocol is None:
            raise ValueError(
                f"security_level={creds.security_level!r} exige un auth_protocol, "
                "aucun repli silencieux vers noAuthNoPriv"
            )
        if creds.auth_protocol not in _AUTH_PROTOCOL_MAP:
            raise ValueError(
                f"auth_protocol SNMPv3 non supporté: {creds.auth_protocol!r} "
                f"(attendu: {', '.join(_AUTH_PROTOCOL_MAP)})"
            )
        auth_protocol_obj = getattr(asyncio_ns, _AUTH_PROTOCOL_MAP[creds.auth_protocol])

    priv_protocol_obj = asyncio_ns.usmNoPrivProtocol
    if creds.security_level == "authPriv":
        if creds.priv_protocol is None:
            raise ValueError(
                "security_level='authPriv' exige un priv_protocol, "
                "aucun repli silencieux vers noPriv"
            )
        if creds.priv_protocol not in _PRIV_PROTOCOL_MAP:
            raise ValueError(
                f"priv_protocol SNMPv3 non supporté: {creds.priv_protocol!r} "
                f"(attendu: {', '.join(_PRIV_PROTOCOL_MAP)})"
            )
        priv_protocol_obj = getattr(asyncio_ns, _PRIV_PROTOCOL_MAP[creds.priv_protocol])

    return asyncio_ns.UsmUserData(
        creds.username,
        authKey=creds.auth_password if creds.security_level != "noAuthNoPriv" else None,
        privKey=creds.priv_password if creds.security_level == "authPriv" else None,
        authProtocol=auth_protocol_obj,
        privProtocol=priv_protocol_obj,
    )


# ---------------------------------------------------------------------------
# Sondage SNMP bas niveau — point d'extension pour les tests (monkeypatch)
# ---------------------------------------------------------------------------


async def _snmp_get_scalars_async(
    address: str,
    timeout_seconds: float,
    *,
    community: str | None = None,
    v3_credentials: SnmpV3Credentials | None = None,
) -> dict[str, Any] | None:
    """Interroge les 5 scalaires MIB-II système, en SNMPv2c ou SNMPv3.

    Fournir `community` (v2c) OU `v3_credentials` (v3) — jamais aucun des
    deux : `ValueError` immédiate, aucun sondage silencieux sans
    authentification. Fournir les deux est également refusé (ambiguïté sur
    la version effectivement utilisée).

    Retour à TROIS issues (contrat, cf. `_snmp_get_scalars` pour le pont
    synchrone qui le propage tel quel) :
      - `dict[str, Any]` : succès, les 5 scalaires.
      - `None` : agent muet ou erreur SNMP générique (cause indéterminée ou
        timeout) — `status='no_response'` côté appelant.
      - lève `SnmpAuthenticationError` : agent qui a répondu mais a refusé
        l'authentification SNMPv3 — `status='auth_failure'` côté appelant.

    Import de `pysnmp` DIFFÉRÉ dans la fonction (pas au module) : les tests
    unitaires du reste du module ne doivent jamais dépendre du binding réseau
    de `pysnmp`, seule cette fonction — systématiquement mockée en test — en
    a besoin. Aucun sous-processus : `pysnmp` est pur Python (hlapi asyncio).
    """
    if community and v3_credentials is not None:
        raise ValueError("fournir soit community (v2c) soit v3_credentials (v3), pas les deux")
    if not community and v3_credentials is None:
        raise ValueError("aucune authentification fournie (ni community ni v3_credentials)")

    from pysnmp.hlapi.v3arch.asyncio import (  # noqa: PLC0415 - import différé volontaire
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
    )

    engine = SnmpEngine()
    transport = await UdpTransportTarget.create((address, 161), timeout=timeout_seconds, retries=0)
    auth: Any
    if community:
        auth = CommunityData(community, mpModel=1)  # mpModel=1 -> SNMPv2c
    else:
        assert v3_credentials is not None  # narrowing pour mypy, garanti par la garde ci-dessus
        auth = _build_usm_user_data(v3_credentials)

    values: dict[str, Any] = {}
    for field_name, oid in _SCALAR_OIDS:
        error_indication, error_status, _error_index, var_binds = await get_cmd(
            engine,
            auth,
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        if error_indication is not None:
            indication_class_name = type(error_indication).__name__
            if indication_class_name in _AUTHENTICATION_FAILURE_INDICATIONS:
                # Agent qui a répondu mais refuse l'authentification :
                # DISTINCT d'un agent muet, jamais mélangé avec `None`. Le
                # message ne contient aucun mot de passe (seulement l'adresse
                # et le nom de la classe d'erreur pysnmp).
                log.error(
                    "echec authentification snmpv3: address=%s indication=%s",
                    address,
                    indication_class_name,
                )
                raise SnmpAuthenticationError(
                    f"authentification SNMPv3 refusee pour {address}: {indication_class_name}"
                )
        if error_indication is not None or error_status:
            # Agent muet ou erreur SNMP générique (OID refusé, timeout...) :
            # échec de CETTE tentative dans son ensemble, jamais un mélange de
            # champs partiellement remplis qui masquerait l'échec.
            log.error(
                "sondage snmp sans reponse exploitable: address=%s oid=%s indication=%s",
                address,
                oid,
                error_indication,
            )
            return None
        _oid_obj, value = var_binds[0]
        values[field_name] = int(value) if field_name == "sys_uptime_ticks" else str(value)

    return values


def _snmp_get_scalars(
    address: str,
    timeout_seconds: float,
    *,
    community: str | None = None,
    v3_credentials: SnmpV3Credentials | None = None,
) -> dict[str, Any] | None:
    """Pont synchrone vers `_snmp_get_scalars_async` — point mocké par les tests.

    Contrat à TROIS issues, propagé tel quel depuis `_snmp_get_scalars_async` :
      - retourne un `dict[str, Any]` : succès.
      - retourne `None` : agent muet, timeout, ou toute autre erreur réseau
        générique (cause indéterminée) — `status='no_response'` côté appelant.
      - lève `SnmpAuthenticationError` (PROPAGÉE, pas capturée ici) : mauvais
        credentials SNMPv3 — `status='auth_failure'` côté appelant
        (`collect_one` capture spécifiquement cette exception).

    `collect_one`/`collect_all` restent synchrones (même contrat que le reste
    du module SQLite d'Okvorado, cf. `app/services/portmap.py`) : la tâche de
    fond périodique (LOT app/main.py) les exécute dans un thread plutôt que de
    propager l'async jusqu'aux appelants synchrones existants.
    """
    import asyncio  # noqa: PLC0415 - colocalisé avec l'appel qu'il sert

    try:
        return asyncio.run(
            _snmp_get_scalars_async(
                address,
                timeout_seconds,
                community=community,
                v3_credentials=v3_credentials,
            )
        )
    except SnmpAuthenticationError:
        # Propagée telle quelle : DISTINCTE d'un agent muet, ne doit jamais
        # être avalée par le `except Exception` générique ci-dessous (sinon
        # 'auth_failure' et 'no_response' redeviendraient indiscernables).
        raise
    except Exception as exc:  # noqa: BLE001 - toute autre erreur réseau = agent muet, jamais un 500
        log.error("echec sondage snmp: address=%s erreur=%s", address, exc)
        return None


# ---------------------------------------------------------------------------
# Résolution AUTOMATIQUE de la table ifIndex -> ifName (IF-MIB)
#
# LE DÉFAUT QUE CE BLOC SUPPRIME (mesuré le 2026-08-10)
# -----------------------------------------------------
# `outlet.yaml` portait, pour CHAQUE exportateur, une liste `if-indexes`
# ÉCRITE À LA MAIN et différente machine par machine : serveur-fichiers=[2,152],
# routeur-agence-01=[2,2932], routeur-agence-02=[2,999], clm=[2,1222],
# routeur-agence-21=[2,235], routeur-agence-03=[2,39], serveur-media=[5]. Vérification par SSH
# sur 4 machines : les ifIndex RÉELS sont 1=lo, 2=eth0/ens18, 3=tailscale0,
# 4+=bridges Docker. Les nombres 2932/999/235/1222/39 n'existaient NULLE PART.
#
# Conséquence en chaîne : un flux arrivant avec ifIndex 3 (tailscale0) ne
# matchait aucune déclaration -> Akvorado appliquait le bloc `default:` ->
# écrivait `unknown` dans InIfName/OutIfName -> l'écran /exporters affichait
# « Interface inconnue » sur 4 exportateurs sur 11.
#
# POURQUOI L'AUTOMATISER EST LA SEULE RÉPONSE TENABLE : la cible est un parc
# de 350 routeurs (cf. CLAUDE.md). Une liste nominative par machine croît
# linéairement avec le parc — c'est le geste que ce projet existe pour
# supprimer, pas un confort. L'équipement CONNAÎT sa propre table
# d'interfaces et sait la rendre : la lui demander est à la fois plus juste
# (aucune recopie) et plus court (un walk contre N éditions manuelles).
#
# À NOTER pour un futur lecteur : il n'existe PAS de colonne `InIfIndex` dans
# ClickHouse (vérifié : seules InIfName/OutIfName/InIfDescription/InIfSpeed/
# InIfBoundary/InIfConnectivity/InIfProvider existent). Akvorado ne stocke que
# le NOM résolu — on ne peut donc pas déduire l'ifIndex réel des flux déjà
# ingérés, il faut le demander à l'équipement. D'où SNMP.
# ---------------------------------------------------------------------------


class InterfaceTableResult(BaseModel):
    """Résultat d'une résolution de table d'interfaces — ZÉRO SILENCIEUX.

    Ne porte JAMAIS de credential (ni communauté, ni mot de passe v3) : ce
    modèle est destiné à traverser la frontière service -> routeur -> gabarit
    HTML, même garde que `InventoryItem`.

    Le point CENTRAL de ce modèle est que `interfaces == {}` n'est JAMAIS
    suffisant pour décider quoi que ce soit : il faut lire `status`. Un
    dictionnaire vide accompagne aussi bien « l'agent ne répond pas » que
    « l'agent a refusé l'authentification » ou « l'adresse était invalide » —
    trois causes qui se corrigent différemment (installer snmpd / corriger les
    credentials Okvorado / corriger l'appelant). Les fondre dans un `{}`
    indifférencié serait exactement le zéro silencieux proscrit par CLAUDE.md.
    """

    address: str
    status: str
    """État DISTINCT et exhaustif de la tentative :
      - `'ok'`            : table résolue, `interfaces` est exploitable ;
      - `'no_response'`   : agent muet (pas de snmpd, timeout, filtrage) ;
      - `'auth_failure'`  : l'agent RÉPOND mais refuse l'authentification v3 ;
      - `'not_configured'`: SNMP pas configuré côté Okvorado (aucun sondage
                            n'a été tenté — l'équipement n'est pas en cause) ;
      - `'invalid_address'`: l'adresse fournie n'est pas une IP (refus AVANT
                            tout accès réseau) ;
      - `'empty_table'`   : l'agent a répondu mais ne déclare aucune interface
                            (anormal : ne jamais écrire une config vide)."""

    interfaces: dict[int, str] = {}
    """ifIndex -> nom d'interface. Vide sur TOUT statut autre que `'ok'`."""

    source_oid: str | None = None
    """OID qui a effectivement rendu la table (`ifName` ou, en repli,
    `ifDescr`) — permet à l'écran de dire d'où vient le nom affiché."""

    message: str = ""
    """Message destiné à l'EXPLOITANT, en clair et ORIENTÉ ACTION. Ne
    contient jamais de credential. C'est ce message qui garantit le zéro
    silencieux à l'écran : « pas de réponse » doit se lire, pas se deviner
    d'un tableau vide."""

    @property
    def is_usable(self) -> bool:
        """Vrai UNIQUEMENT si la table peut servir à écrire une config.

        Volontairement plus strict que `status == 'ok'` sur la forme : un
        appelant qui lit cette propriété ne peut pas, par distraction, écrire
        un `outlet.yaml` depuis un résultat d'échec."""
        return self.status == "ok" and bool(self.interfaces)


#: Messages par statut d'échec — centralisés pour rester cohérents entre le
#: service, les fragments HTML et les tests. Chacun dit CE QU'IL FAUT FAIRE,
#: pas seulement ce qui s'est passé : un message qui constate sans orienter
#: laisse l'exploitant chercher au mauvais endroit (c'est comme ça qu'on va
#: chercher une panne réseau pour un paquet Python manquant, cf. l'incident
#: `cryptography` documenté en tête de module).
_INTERFACE_TABLE_MESSAGES: dict[str, str] = {
    "no_response": (
        "L'agent SNMP de cet équipement ne répond pas : vérifier que snmpd "
        "écoute bien sur 161/udp sur cette machine et que la communauté "
        "configurée dans Okvorado est la bonne."
    ),
    "auth_failure": (
        "L'équipement a répondu mais a refusé l'authentification SNMPv3 : "
        "vérifier l'utilisateur, le niveau de sécurité et les mots de passe "
        "v3 configurés dans Okvorado (l'équipement, lui, est joignable)."
    ),
    "not_configured": (
        "SNMP n'est pas configuré dans Okvorado (ni communauté v2c, ni "
        "utilisateur v3) : aucun équipement n'a été interrogé. Renseigner "
        "OKVORADO_SNMP_COMMUNITY ou OKVORADO_SNMP_V3_USERNAME."
    ),
    "invalid_address": (
        "L'adresse fournie n'est pas une adresse IP valide : aucune requête réseau n'a été émise."
    ),
    "empty_table": (
        "L'agent SNMP a répondu mais ne déclare aucune interface, ni via "
        "ifName ni via ifDescr : la configuration n'a PAS été modifiée "
        "(écrire une liste d'interfaces vide ferait rejeter tous les flux)."
    ),
}


async def _snmp_walk_interfaces_async(
    address: str,
    oid: str,
    timeout_seconds: float,
    *,
    community: str | None = None,
    v3_credentials: SnmpV3Credentials | None = None,
) -> dict[int, str] | None:
    """Parcourt (walk) une colonne de la table d'interfaces IF-MIB.

    `oid` est TOUJOURS un littéral de ce module (`_OID_IF_NAME` ou
    `_OID_IF_DESCR`), jamais une valeur d'origine utilisateur — c'est la
    même garde que pour les scalaires système.

    Contrat à trois issues, identique à `_snmp_get_scalars_async` (cohérence
    volontaire : deux contrats différents pour deux sondages du même module
    seraient une source d'erreur) :
      - `dict[int, str]` : succès (éventuellement vide si l'agent ne peuple
        pas cette colonne — c'est l'appelant qui décidera du repli) ;
      - `None` : agent muet / erreur SNMP générique ;
      - lève `SnmpAuthenticationError` : refus d'authentification v3.

    L'index rendu est le DERNIER sous-identifiant de l'OID de la réponse :
    pour `1.3.6.1.2.1.31.1.1.1.1.3`, l'ifIndex est `3`. C'est la structure
    standard d'une table indexée par ifIndex (RFC 2863).

    Import de `pysnmp` DIFFÉRÉ dans la fonction, comme `_snmp_get_scalars_async` :
    les tests du reste du module ne doivent jamais dépendre du binding réseau.
    Aucun sous-processus (pysnmp est pur Python) : aucune commande shell n'est
    construite, donc aucune injection possible par construction.
    """
    if community and v3_credentials is not None:
        raise ValueError("fournir soit community (v2c) soit v3_credentials (v3), pas les deux")
    if not community and v3_credentials is None:
        raise ValueError("aucune authentification fournie (ni community ni v3_credentials)")

    from pysnmp.hlapi.v3arch.asyncio import (  # noqa: PLC0415 - import différé volontaire
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        next_cmd,
    )

    engine = SnmpEngine()
    transport = await UdpTransportTarget.create((address, 161), timeout=timeout_seconds, retries=0)
    auth: Any
    if community:
        auth = CommunityData(community, mpModel=1)  # mpModel=1 -> SNMPv2c
    else:
        assert v3_credentials is not None  # narrowing mypy, garanti par la garde ci-dessus
        auth = _build_usm_user_data(v3_credentials)

    interfaces: dict[int, str] = {}
    current = ObjectType(ObjectIdentity(oid))

    while True:
        error_indication, error_status, _error_index, var_binds = await next_cmd(
            engine,
            auth,
            transport,
            ContextData(),
            current,
            lexicographicMode=False,
        )

        if error_indication is not None:
            indication_class_name = type(error_indication).__name__
            if indication_class_name in _AUTHENTICATION_FAILURE_INDICATIONS:
                # DISTINCT d'un agent muet — jamais fondu dans `None`. Le
                # message ne porte que l'adresse et le nom de la classe
                # d'erreur pysnmp : aucun mot de passe.
                log.error(
                    "echec authentification snmpv3 pendant le walk d'interfaces: "
                    "address=%s oid=%s indication=%s",
                    address,
                    oid,
                    indication_class_name,
                )
                raise SnmpAuthenticationError(
                    f"authentification SNMPv3 refusee pour {address}: {indication_class_name}"
                )
            log.error(
                "walk d'interfaces sans reponse exploitable: address=%s oid=%s indication=%s",
                address,
                oid,
                error_indication,
            )
            return None

        if error_status:
            log.error(
                "walk d'interfaces en erreur snmp: address=%s oid=%s status=%s",
                address,
                oid,
                error_status,
            )
            return None

        if not var_binds:
            break

        fin_de_table = False
        for var_oid, value in var_binds:
            oid_text = str(var_oid)
            # `lexicographicMode=False` borne déjà le walk au sous-arbre, mais
            # on revérifie : une implémentation d'agent laxiste peut renvoyer
            # au-delà, et écrire des interfaces d'une AUTRE table serait pire
            # que ne rien écrire.
            if not oid_text.startswith(f"{oid}."):
                fin_de_table = True
                break
            suffixe = oid_text[len(oid) + 1 :]
            try:
                if_index = int(suffixe.split(".", 1)[0])
            except ValueError:
                # Un index non entier n'est pas exploitable comme ifIndex :
                # on l'IGNORE explicitement plutôt que de fabriquer une clé.
                log.error(
                    "index d'interface non entier ignore: address=%s oid=%s suffixe=%r",
                    address,
                    oid,
                    suffixe,
                )
                continue
            nom = str(value).strip()
            if not nom:
                # Une ligne présente mais au nom VIDE ne doit pas produire une
                # interface anonyme dans outlet.yaml : c'est précisément le
                # cas qui justifie le repli sur ifDescr, décidé par l'appelant.
                continue
            interfaces[if_index] = nom
            current = ObjectType(ObjectIdentity(oid_text))

        if fin_de_table:
            break

    return interfaces


def _snmp_walk_interfaces(
    address: str,
    oid: str,
    timeout_seconds: float,
    *,
    community: str | None = None,
    v3_credentials: SnmpV3Credentials | None = None,
) -> dict[int, str] | None:
    """Pont synchrone vers `_snmp_walk_interfaces_async` — point mocké par les
    tests, exactement comme `_snmp_get_scalars` l'est pour les scalaires.

    Contrat propagé tel quel : `dict` (succès, possiblement vide), `None`
    (agent muet / erreur générique), ou `SnmpAuthenticationError` PROPAGÉE
    (refus d'authentification, à ne jamais confondre avec un agent muet).
    """
    import asyncio  # noqa: PLC0415 - colocalisé avec l'appel qu'il sert

    try:
        return asyncio.run(
            _snmp_walk_interfaces_async(
                address,
                oid,
                timeout_seconds,
                community=community,
                v3_credentials=v3_credentials,
            )
        )
    except SnmpAuthenticationError:
        # Propagée telle quelle : sinon 'auth_failure' et 'no_response'
        # redeviendraient indiscernables (zéro silencieux).
        raise
    except Exception as exc:  # noqa: BLE001 - toute autre erreur = agent muet, jamais un 500
        log.error("echec walk d'interfaces: address=%s oid=%s erreur=%s", address, oid, exc)
        return None


def resolve_interface_table(
    *,
    address: str,
    community: str = "",
    timeout_seconds: float | None = None,
    snmp_version: str = "v2c",
    v3_credentials: SnmpV3Credentials | None = None,
) -> InterfaceTableResult:
    """Résout la table `ifIndex -> nom d'interface` d'UN équipement.

    C'est le remplaçant AUTOMATIQUE de la liste `if-indexes` écrite à la main
    dans `outlet.yaml` (cf. le bloc de commentaires en tête de section).

    Séquence :
      1. Refuse une adresse qui n'est pas une IP — AVANT tout accès réseau
         (l'adresse peut venir d'un chemin d'URL, donc d'une saisie).
      2. Refuse un sondage sans credentials (SNMP non configuré) — l'agent
         n'est PAS en cause, l'état doit le dire.
      3. Walk de `ifName`. S'il ne rend rien (agent qui ne peuple pas
         l'ifXTable), REPLI sur `ifDescr` — et c'est le résultat du repli qui
         compte.
      4. Rend un état DISTINCT dans tous les cas, jamais une table vide muette.

    Ne lève JAMAIS : toute anomalie devient un `status` lisible. Une exception
    remontée jusqu'au routeur produirait un 500, et un 500 n'est pas swappé
    par htmx — le message serait INVISIBLE à l'écran (défaut déjà mesuré, cf.
    tests/test_htmx_error_visibility.py).
    """

    def _echec(status: str) -> InterfaceTableResult:
        return InterfaceTableResult(
            address=address,
            status=status,
            interfaces={},
            message=_INTERFACE_TABLE_MESSAGES[status],
        )

    try:
        ipaddress.ip_address(address)
    except ValueError:
        # On ne logue PAS la valeur brute telle quelle sans la marquer : elle
        # vient d'une saisie. `%r` la rend inambiguë dans le journal.
        log.error("resolution d'interfaces refusee, adresse invalide: address=%r", address)
        return _echec("invalid_address")

    if snmp_version not in ("v2c", "v3"):
        raise ValueError(f"snmp_version invalide: {snmp_version!r} (attendu: v2c, v3)")

    if snmp_version == "v2c":
        if not community:
            log.error(
                "resolution d'interfaces impossible, communaute v2c absente: address=%s", address
            )
            return _echec("not_configured")
        walk_kwargs: dict[str, Any] = {"community": community}
    else:
        if v3_credentials is None:
            log.error(
                "resolution d'interfaces impossible, credentials v3 absents: address=%s", address
            )
            return _echec("not_configured")
        walk_kwargs = {"v3_credentials": v3_credentials}

    effective_timeout = (
        timeout_seconds if timeout_seconds is not None else settings.snmp_timeout_seconds
    )

    # `ifName` d'abord (le nom court, celui qu'attend Akvorado), `ifDescr` en
    # repli UNIQUEMENT si `ifName` n'a rien rendu. Un `None` (agent muet) ne
    # déclenche PAS le repli : inutile de refaire un aller-retour vers un
    # agent qui ne répond pas — et le distinguer d'une table vide est
    # justement ce qui préserve le zéro silencieux.
    for oid in (_OID_IF_NAME, _OID_IF_DESCR):
        try:
            table = _snmp_walk_interfaces(address, oid, effective_timeout, **walk_kwargs)
        except SnmpAuthenticationError:
            return _echec("auth_failure")

        if table is None:
            return _echec("no_response")

        if table:
            log.info(
                "table d'interfaces resolue par snmp: address=%s oid=%s interfaces=%d",
                address,
                oid,
                len(table),
            )
            return InterfaceTableResult(
                address=address,
                status="ok",
                interfaces=table,
                source_oid=oid,
                message=f"{len(table)} interface(s) résolue(s) par SNMP.",
            )

    log.error(
        "agent snmp sans aucune interface declaree (ifName et ifDescr vides): address=%s", address
    )
    return _echec("empty_table")


# ---------------------------------------------------------------------------
# Collecte + persistance
# ---------------------------------------------------------------------------


def collect_one(
    conn: sqlite3.Connection,
    *,
    address: str,
    community: str = "",
    timeout_seconds: float | None = None,
    snmp_version: str = "v2c",
    v3_credentials: SnmpV3Credentials | None = None,
) -> InventoryItem:
    """Sonde un exportateur et persiste le résultat (upsert par `address`).

    `snmp_version` sélectionne la bifurcation v2c/v3 :
      - `"v2c"` (défaut, rétro-compatible) : utilise `community`. Vide
        (SNMP non configuré) est un refus EXPLICITE avant tout sondage
        réseau — jamais une communauté vide envoyée sur le fil.
      - `"v3"` : utilise `v3_credentials`, `community` est IGNORÉ. Si
        `v3_credentials` est `None` (config Okvorado incomplète), c'est
        aussi un refus EXPLICITE avant sondage — mais ce n'est PAS un échec
        d'authentification CONTRE l'agent (celui-ci n'a jamais été
        contacté), donc `status='no_response'` comme le cas `community`
        vide, pas `'auth_failure'` (réservé au refus DE L'AGENT).

    Dans les deux cas, du point de vue de l'écran, « pas configuré » et
    « pas de réponse » sont tous deux « pas de mesure disponible », jamais un
    tableau vide silencieux.

    Un échec d'authentification SNMPv3 CONTRE l'agent (mauvais
    username/mot de passe/niveau de sécurité — `SnmpAuthenticationError`
    levée par `_snmp_get_scalars`) est capturé ici et produit
    `status='auth_failure'`, DISTINCT de `no_response`.
    """
    if snmp_version not in ("v2c", "v3"):
        raise ValueError(f"snmp_version invalide: {snmp_version!r} (attendu: v2c, v3)")

    effective_timeout = (
        timeout_seconds if timeout_seconds is not None else settings.snmp_timeout_seconds
    )

    scalars: dict[str, Any] | None = None
    auth_failed = False

    if snmp_version == "v2c":
        should_probe = bool(community)
    else:
        should_probe = v3_credentials is not None

    if should_probe:
        try:
            if snmp_version == "v2c":
                scalars = _snmp_get_scalars(address, effective_timeout, community=community)
            else:
                scalars = _snmp_get_scalars(
                    address, effective_timeout, v3_credentials=v3_credentials
                )
        except SnmpAuthenticationError:
            auth_failed = True

    existing = conn.execute(
        "SELECT first_seen_at FROM snmp_inventory WHERE address = ?", (address,)
    ).fetchone()

    if auth_failed:
        if existing is None:
            conn.execute(
                "INSERT INTO snmp_inventory (address, status, last_attempt_at, snmp_version) "
                "VALUES (?, 'auth_failure', datetime('now'), ?)",
                (address, snmp_version),
            )
        else:
            conn.execute(
                "UPDATE snmp_inventory SET status = 'auth_failure', "
                "last_attempt_at = datetime('now'), snmp_version = ? WHERE address = ?",
                (snmp_version, address),
            )
        conn.commit()
        row = conn.execute("SELECT * FROM snmp_inventory WHERE address = ?", (address,)).fetchone()
        return _row_to_item(row)

    if scalars is None:
        if existing is None:
            conn.execute(
                "INSERT INTO snmp_inventory (address, status, last_attempt_at, snmp_version) "
                "VALUES (?, 'no_response', datetime('now'), ?)",
                (address, snmp_version),
            )
        else:
            conn.execute(
                "UPDATE snmp_inventory SET status = 'no_response', "
                "last_attempt_at = datetime('now'), snmp_version = ? WHERE address = ?",
                (snmp_version, address),
            )
        conn.commit()
        row = conn.execute("SELECT * FROM snmp_inventory WHERE address = ?", (address,)).fetchone()
        return _row_to_item(row)

    if existing is None:
        conn.execute(
            "INSERT INTO snmp_inventory "
            "(address, sys_name, sys_descr, sys_location, sys_contact, sys_uptime_ticks, "
            " status, last_attempt_at, last_success_at, snmp_version) "
            "VALUES (?, ?, ?, ?, ?, ?, 'ok', datetime('now'), datetime('now'), ?)",
            (
                address,
                scalars.get("sys_name"),
                scalars.get("sys_descr"),
                scalars.get("sys_location"),
                scalars.get("sys_contact"),
                scalars.get("sys_uptime_ticks"),
                snmp_version,
            ),
        )
    else:
        conn.execute(
            "UPDATE snmp_inventory SET sys_name = ?, sys_descr = ?, sys_location = ?, "
            "sys_contact = ?, sys_uptime_ticks = ?, status = 'ok', "
            "last_attempt_at = datetime('now'), last_success_at = datetime('now'), "
            "snmp_version = ? WHERE address = ?",
            (
                scalars.get("sys_name"),
                scalars.get("sys_descr"),
                scalars.get("sys_location"),
                scalars.get("sys_contact"),
                scalars.get("sys_uptime_ticks"),
                snmp_version,
                address,
            ),
        )
    conn.commit()
    row = conn.execute("SELECT * FROM snmp_inventory WHERE address = ?", (address,)).fetchone()
    return _row_to_item(row)


def collect_all(
    conn: sqlite3.Connection,
    *,
    addresses: list[str],
    community: str = "",
    timeout_seconds: float | None = None,
    snmp_version: str = "v2c",
    v3_credentials: SnmpV3Credentials | None = None,
    overrides: dict[str, tuple[str, SnmpV3Credentials | None]] | None = None,
) -> list[InventoryItem]:
    """Sonde une liste d'adresses CONNUES (jamais une saisie libre).

    `addresses` est fourni par l'appelant à partir des exportateurs
    observés/déclarés (`load_exporter_statuses`) — ce module ne construit
    jamais lui-même la liste des cibles.

    DESIGN RETENU pour « version configurable par exportateur, défaut
    global, exception par device » (le parc SFR migre progressivement) :
    `snmp_version`/`community`/`v3_credentials` sont le TRIPLET PAR DÉFAUT
    appliqué à toute adresse absente d' `overrides` ; `overrides` est une
    table d'EXCEPTIONS `address -> (snmp_version, v3_credentials)` pour les
    devices déjà migrés en v3 (ou explicitement forcés en v2c) alors que le
    reste du parc suit encore le défaut. Choisi plutôt qu'un mapping
    OBLIGATOIRE par adresse : la majorité du parc reste sur un même réglage
    à un instant donné, un défaut + table d'exceptions clairsemée évite à
    l'appelant de dupliquer le même triplet pour 350 adresses.
    """
    overrides = overrides or {}
    results: list[InventoryItem] = []
    for address in addresses:
        if address in overrides:
            address_version, address_v3_credentials = overrides[address]
            results.append(
                collect_one(
                    conn,
                    address=address,
                    community=community,
                    timeout_seconds=timeout_seconds,
                    snmp_version=address_version,
                    v3_credentials=address_v3_credentials,
                )
            )
        else:
            results.append(
                collect_one(
                    conn,
                    address=address,
                    community=community,
                    timeout_seconds=timeout_seconds,
                    snmp_version=snmp_version,
                    v3_credentials=v3_credentials,
                )
            )
    return results


def list_inventory(conn: sqlite3.Connection) -> list[InventoryItem]:
    """Liste l'inventaire déjà collecté, trié par nom (équipements muets en fin)."""
    rows = conn.execute(
        "SELECT * FROM snmp_inventory ORDER BY (status = 'ok') DESC, sys_name IS NULL, "
        "sys_name ASC, address ASC"
    ).fetchall()
    return [_row_to_item(row) for row in rows]


def get_inventory_item(conn: sqlite3.Connection, address: str) -> InventoryItem | None:
    row = conn.execute("SELECT * FROM snmp_inventory WHERE address = ?", (address,)).fetchone()
    return _row_to_item(row) if row is not None else None


def _row_to_item(row: sqlite3.Row) -> InventoryItem:
    row_keys = row.keys()
    return InventoryItem(
        address=row["address"],
        sys_name=row["sys_name"],
        sys_descr=row["sys_descr"],
        sys_location=row["sys_location"],
        sys_contact=row["sys_contact"],
        sys_uptime_ticks=row["sys_uptime_ticks"],
        status=row["status"],
        snmp_version=row["snmp_version"] if "snmp_version" in row_keys else "v2c",
        first_seen_at=row["first_seen_at"],
        last_attempt_at=row["last_attempt_at"],
        last_success_at=row["last_success_at"],
    )
