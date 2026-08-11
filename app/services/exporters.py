"""Logique métier du module Exportateurs : croise déclaré x observé x ingéré.

C'est le cœur du LOT 1 : ni Akvorado ni ClickHouse seuls ne savent produire
cette vue. Un exportateur peut émettre des flux et être 100% rejeté à
l'ingestion (motif `input and output interfaces missing`) sans que cela
n'apparaisse nulle part ailleurs — ce module le rend visible.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess  # noqa: S404 - liste d'arguments uniquement, jamais shell=True (cf. plus bas)
from dataclasses import dataclass
from datetime import datetime

from app.config import settings
from app.models import (
    Boundary,
    DeclaredExporter,
    ExporterHealth,
    ExporterStatus,
    InterfaceSpec,
    ObservedExporter,
)
from app.services.snmp_inventory import InterfaceTableResult

log = logging.getLogger(__name__)

#: Débit par défaut (Mbit/s) affecté à une interface DÉCOUVERTE par SNMP dont
#: rien n'était déclaré. Même valeur que le défaut de lecture d'`outlet.yaml`
#: (`app.clients.akvorado_yaml._parse_interface_spec`) : la cohérence importe
#: plus que la justesse ici, `speed` ne sert qu'au calcul du taux de
#: saturation d'interface et l'exploitant l'ajuste à l'écran. Ce qui est
#: interdit, c'est 0 — `validate_exporters` refuse un `speed <= 0`.
_DEFAULT_INTERFACE_SPEED = 1000


@dataclass
class InterfaceFiltrageResult:
    """Résultat de `filtrer_interfaces_exploitables` — ZÉRO SILENCIEUX.

    Ne rend jamais une simple liste raccourcie : `retenues` ET `ecartees`
    sont toutes deux exposées, avec leurs compteurs, pour qu'un appelant
    puisse toujours dire « N interfaces vues, M écartées, K retenues » — et
    JAMAIS deviner ce qui a disparu.
    """

    retenues: dict[int, InterfaceSpec]
    """Interfaces conservées : ifIndex -> spec, prêtes pour la suite de la
    résolution (ex. `build_if_indexes_from_snmp`)."""

    ecartees: dict[int, InterfaceSpec]
    """Interfaces écartées par le filtre — jamais perdues silencieusement,
    consultables pour diagnostic/audit."""

    @property
    def total_vues(self) -> int:
        return len(self.retenues) + len(self.ecartees)

    @property
    def total_retenues(self) -> int:
        return len(self.retenues)

    @property
    def total_ecartees(self) -> int:
        return len(self.ecartees)

    @property
    def tout_ecarte(self) -> bool:
        """SIGNAL D'ALARME, pas un résultat anodin : `True` uniquement quand
        au moins une interface a été VUE et qu'AUCUNE n'a survécu au filtre.
        Une table vide en entrée (rien à filtrer) n'est PAS ce cas — ne pas
        confondre absence d'entrée et filtre destructeur."""
        return self.total_vues > 0 and self.total_retenues == 0


def _nom_matche_motif(nom: str, motif: str) -> bool:
    """Teste un motif d'exclusion contre un nom d'interface.

    Deux formes seulement, volontairement simples (le projet cible un parc
    de 350 routeurs hétérogènes, pas un moteur de regex à maintenir) :
      - motif se terminant par `*` : préfixe (`br-*` matche `br-780869fa3032`) ;
      - motif sans `*` : égalité EXACTE (`lo` ne matche PAS `lo0`, un nom
        Cisco/BSD distinct — un matching par sous-chaîne mordrait à tort).
    """
    if motif.endswith("*"):
        return nom.startswith(motif[:-1])
    return nom == motif


def filtrer_interfaces_exploitables(
    snmp_table: dict[int, str],
    *,
    declared_names: set[str],
    motifs_exclus: list[str] | None = None,
) -> InterfaceFiltrageResult:
    """Écarte les interfaces SANS VALEUR NetFlow d'une table SNMP brute.

    MESURE QUI MOTIVE CETTE FONCTION (2026-08-11) : `outlet.yaml` en
    production déclarait pour un seul exportateur Docker 40 interfaces sans
    aucune valeur NetFlow (`lo`, `docker0`, 12 `br-*`, ~26 `veth*`) — noyant
    les 3 interfaces réellement utiles. `resolve_interface_table` et
    `build_if_indexes_from_snmp` acceptaient jusqu'ici TOUTE interface rendue
    par le walk, sans exclusion : c'est le trou que cette fonction comble, en
    amont de `build_if_indexes_from_snmp`.

    FILTRAGE PAR MOTIF, jamais par liste nominative — seule approche qui
    tienne à l'échelle visée (350 routeurs SFR, cf. CLAUDE.md
    « L'auto-découverte n'est pas un confort, c'est la condition de
    déployabilité »). Les motifs par défaut viennent de
    `settings.interface_exclude_patterns_list()`, ajustables SANS toucher au
    code (`OKVORADO_INTERFACE_EXCLUDE_PATTERNS`) — voir sa docstring pour la
    distinction homelab/entreprise.

    PRÉSERVATION D'UNE DÉCISION D'EXPLOITANT : une interface déjà présente
    dans `declared_names` (donc déjà déclarée dans `outlet.yaml`, cf.
    `_declared_interface_names`) n'est JAMAIS écartée, quel que soit le
    motif — le filtre sert à ne pas AJOUTER du bruit, pas à effacer un choix
    humain déjà fait (même logique de préservation par NOM que
    `build_if_indexes_from_snmp`).

    ZÉRO SILENCIEUX : le résultat expose `retenues` ET `ecartees` avec leurs
    comptes (`InterfaceFiltrageResult`), jamais une liste raccourcie muette.
    `tout_ecarte` signale explicitement le cas où le filtre ne laisse RIEN —
    un signal d'alarme à traiter par l'appelant, pas un résultat silencieux.

    Args:
        snmp_table: `ifIndex -> nom`, tel que rendu par l'équipement (même
            forme d'entrée que `build_if_indexes_from_snmp`).
        declared_names: noms d'interfaces déjà déclarés pour cet exportateur
            (ex. `_declared_interface_names(declared)`) — jamais écartés.
        motifs_exclus: motifs à appliquer ; `None` = défaut projet
            (`settings.interface_exclude_patterns_list()`). Passer une liste
            vide désactive tout filtrage par motif (seule `declared_names`
            reste sans effet dans ce cas, puisque rien n'est filtré).

    Returns:
        `InterfaceFiltrageResult` avec `retenues`/`ecartees` en `ifIndex ->
        nom` et les compteurs dérivés.
    """
    motifs = (
        settings.interface_exclude_patterns_list() if motifs_exclus is None else motifs_exclus
    )

    retenues: dict[int, str] = {}
    ecartees: dict[int, str] = {}
    for if_index, name in snmp_table.items():
        if name in declared_names:
            retenues[if_index] = name
            continue
        if any(_nom_matche_motif(name, motif) for motif in motifs):
            ecartees[if_index] = name
        else:
            retenues[if_index] = name

    if not retenues and ecartees:
        log.error(
            "filtrage interfaces : TOUTES les interfaces vues ont ete ecartees, "
            "aucune retenue — signal d'alarme, verifier les motifs d'exclusion "
            "(OKVORADO_INTERFACE_EXCLUDE_PATTERNS) ou l'equipement: "
            "total_vues=%s motifs=%s",
            len(ecartees),
            motifs,
        )

    def _to_specs(table: dict[int, str]) -> dict[int, InterfaceSpec]:
        return {
            if_index: InterfaceSpec(if_index=if_index, name=name)
            for if_index, name in table.items()
        }

    return InterfaceFiltrageResult(retenues=_to_specs(retenues), ecartees=_to_specs(ecartees))


def build_if_indexes_from_snmp(
    snmp_table: dict[int, str],
    *,
    existing: dict[int, InterfaceSpec],
) -> dict[int, InterfaceSpec]:
    """Traduit une table SNMP `ifIndex -> nom` en `if-indexes` pour outlet.yaml.

    C'EST LE CŒUR DU CORRECTIF (défaut mesuré le 2026-08-10, cf.
    `app.services.snmp_inventory.resolve_interface_table`) : les ifIndex
    déclarés à la main (999, 2932, 1222, 235, 39...) n'existaient sur AUCUN
    équipement, donc aucun flux ne matchait et Akvorado écrivait `unknown`.
    La table rendue ici REMPLACE intégralement l'ancienne indexation par
    celle que l'équipement déclare lui-même.

    PRÉSERVATION DES RÉGLAGES D'EXPLOITANT — le point délicat. SNMP rend le
    NOM de l'interface, pas son sens métier : `boundary` (interne/externe) et
    `description` sont des décisions humaines qu'aucun agent SNMP ne connaît.
    Ré-indexer `tailscale0` de 999 vers 3 ne doit donc PAS effacer son
    `boundary: internal` — sinon la correction d'un défaut de classement en
    créerait un autre, silencieusement (tout le trafic reclassé `undefined`).
    Le rapprochement se fait donc PAR NOM d'interface, la seule clé stable
    entre l'ancienne déclaration et la nouvelle table : l'ifIndex, lui, est
    précisément ce qui était faux.

    Une interface DÉCOUVERTE (présente sur l'équipement, absente de la
    configuration) reçoit `boundary=undefined` — l'état honnête. Deviner
    `internal` ou `external` d'après un nom d'interface fabriquerait une
    classification indiscernable d'une vraie décision d'exploitant : c'est la
    famille de défaut « valeur fabriquée » proscrite par CLAUDE.md.

    Args:
        snmp_table: `ifIndex -> nom`, tel que rendu par l'équipement.
        existing: les `if-indexes` actuellement déclarés pour cet
            exportateur, dont on récupère les réglages métier par nom.

    Returns:
        La map `ifIndex -> InterfaceSpec` prête à écrire. Les ifIndex
        fantômes ont disparu, puisque seuls ceux de `snmp_table` subsistent.
    """
    reglages_par_nom = {spec.name: spec for spec in existing.values()}

    resolved: dict[int, InterfaceSpec] = {}
    for if_index, name in snmp_table.items():
        if if_index <= 0:
            # Un ifIndex <= 0 fait rejeter les flux par Akvorado
            # (enricher.go:83) et serait de toute façon refusé par
            # `validate_exporters`. On l'écarte ICI, avec une trace : le
            # laisser passer produirait un échec d'écriture opaque plus loin.
            log.error(
                "ifindex non strictement positif rendu par snmp, interface ignoree: "
                "if_index=%s interface=%s",
                if_index,
                name,
            )
            continue

        ancien = reglages_par_nom.get(name)
        if ancien is not None:
            resolved[if_index] = ancien.model_copy(update={"if_index": if_index, "name": name})
        else:
            resolved[if_index] = InterfaceSpec(
                if_index=if_index,
                name=name,
                description="",
                speed=_DEFAULT_INTERFACE_SPEED,
                boundary=Boundary.UNDEFINED,
            )

    return resolved


def _find_declared_match(
    address: str, declared: list[DeclaredExporter]
) -> tuple[DeclaredExporter | None, bool]:
    """Cherche la déclaration correspondant à `address`.

    Retourne (déclaration, matched_nominally) :
    - une correspondance nominative (CIDR non-catchall, généralement /32)
      est préférée à une correspondance catchall ;
    - `matched_nominally` distingue "déclaré par son nom propre" de "couvert
      par un filet CIDR large" (nécessaire pour UNDECLARED vs SILENT/HEALTHY).
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        log.error("adresse d'exportateur invalide, correspondance ignoree: address=%s", address)
        return None, False

    nominal_match: DeclaredExporter | None = None
    catchall_match: DeclaredExporter | None = None
    for entry in declared:
        try:
            network = ipaddress.ip_network(entry.cidr, strict=False)
        except ValueError:
            log.error("cidr declare invalide, ignore: cidr=%s", entry.cidr)
            continue
        if ip not in network:
            continue
        if entry.is_catchall:
            if catchall_match is None:
                catchall_match = entry
        else:
            nominal_match = entry

    if nominal_match is not None:
        return nominal_match, True
    if catchall_match is not None:
        return catchall_match, False
    return None, False


def _declared_interface_names(declared: DeclaredExporter) -> set[str]:
    return {spec.name for spec in declared.if_indexes.values()}


def _build_explanation(
    health: ExporterHealth,
    address: str,
    rejection_reasons: dict[str, int],
    unknown_interfaces: list[str],
) -> str:
    """Rédige une explication en clair, sans jargon, pour un collègue non expert."""
    if health == ExporterHealth.REJECTED:
        top_reason = (
            max(rejection_reasons, key=lambda reason: rejection_reasons[reason])
            if rejection_reasons
            else "motif inconnu"
        )
        return (
            f"Cet exportateur ({address}) envoie des flux mais Akvorado les rejette tous "
            f"(motif : {top_reason}). "
            "Vérifier la version de softflowd (1.1.1 minimum) sur cette machine."
        )
    if health == ExporterHealth.SILENT:
        return (
            f"Cet exportateur ({address}) est déclaré dans la configuration mais n'a envoyé "
            "aucun flux sur la période observée. Vérifier qu'il est toujours en service et que "
            "le réseau entre lui et Akvorado fonctionne. Une fenêtre courte peut aussi masquer "
            "un exportateur à flux longs peu fréquents : réessayer avec une fenêtre plus large "
            "avant de conclure à une panne."
        )
    if health == ExporterHealth.UNDECLARED:
        return (
            f"Cet exportateur ({address}) envoie des flux mais n'a pas de déclaration "
            "nominative dans la configuration : il n'est couvert que par un filet générique. "
            "Ajouter une entrée dédiée dans outlet.yaml pour lui donner un nom et des "
            "interfaces connues."
        )
    if health == ExporterHealth.UNKNOWN_INTERFACE:
        joined = ", ".join(unknown_interfaces) if unknown_interfaces else "inconnue(s)"
        return (
            f"Cet exportateur ({address}) envoie des flux sur une ou plusieurs interfaces "
            f"non déclarées ({joined}). Mettre à jour outlet.yaml pour déclarer ces "
            "interfaces, sinon leur volume et leur boundary restent mal classés."
        )
    return f"Cet exportateur ({address}) fonctionne normalement."


def _is_massively_rejected(
    rejected_total: int, forwarded_total: int, observed: ObservedExporter | None
) -> bool:
    """REJECTED : rejets > 0 ET (aucun flux transmis OU aucun flux observé récent)."""
    if rejected_total <= 0:
        return False
    return forwarded_total == 0 or observed is None


def _determine_health(
    declared: DeclaredExporter | None,
    declared_nominally: bool,
    observed: ObservedExporter | None,
    rejected_total: int,
    forwarded_total: int,
) -> tuple[ExporterHealth, list[str]]:
    if _is_massively_rejected(rejected_total, forwarded_total, observed):
        return ExporterHealth.REJECTED, []

    if declared is None:
        # Observé sans aucune déclaration correspondante.
        return ExporterHealth.UNDECLARED, []

    if not declared_nominally:
        # Couvert seulement par un CIDR catchall : jamais nommé explicitement.
        return ExporterHealth.UNDECLARED, []

    if observed is None:
        return ExporterHealth.SILENT, []

    declared_interfaces = _declared_interface_names(declared)
    if declared_interfaces:
        unknown_interfaces = sorted(set(observed.interfaces) - declared_interfaces)
        if unknown_interfaces:
            return ExporterHealth.UNKNOWN_INTERFACE, unknown_interfaces

    return ExporterHealth.HEALTHY, []


def build_exporter_statuses(
    declared: list[DeclaredExporter],
    observed: list[ObservedExporter],
    forwarded_by_exporter: dict[str, int],
    rejected_by_exporter: dict[str, int],
    rejection_reasons: dict[str, dict[str, int]],
    now: datetime,
) -> list[ExporterStatus]:
    """Croise déclaré x observé x ingéré et retourne le statut de chaque exportateur.

    Args:
        declared: exportateurs déclarés dans outlet.yaml (LOT 1, akvorado_yaml).
        observed: exportateurs observés dans ClickHouse sur la fenêtre courante.
        forwarded_by_exporter: compteurs Prometheus `forwarded_total` par IP en
            clair (LOT 4, fourni en paramètre — jamais importé directement).
        rejected_by_exporter: idem pour `rejected_total`.
        rejection_reasons: motifs de rejet par IP puis par motif.
        now: horodatage de référence, injecté pour rendre le calcul testable.

    Returns:
        La liste triée avec les problèmes en premier (severity décroissante,
        puis volume de flux décroissant).
    """
    observed_by_address = {item.address: item for item in observed}
    declared_by_nominal_address = {
        item.cidr.split("/", 1)[0]: item for item in declared if not item.is_catchall
    }

    addresses = set(observed_by_address) | set(declared_by_nominal_address)
    statuses: list[ExporterStatus] = []

    for address in addresses:
        observed_exporter = observed_by_address.get(address)
        forwarded_total = forwarded_by_exporter.get(address, 0)
        rejected_total = rejected_by_exporter.get(address, 0)
        reasons = rejection_reasons.get(address, {})

        matched_declared, declared_nominally = _find_declared_match(address, declared)

        health, unknown_interfaces = _determine_health(
            declared=matched_declared,
            declared_nominally=declared_nominally,
            observed=observed_exporter,
            rejected_total=rejected_total,
            forwarded_total=forwarded_total,
        )

        name = (
            observed_exporter.name
            if observed_exporter is not None
            else (matched_declared.name if matched_declared is not None else address)
        )

        statuses.append(
            ExporterStatus(
                address=address,
                name=name,
                health=health,
                declared=matched_declared,
                observed=observed_exporter,
                forwarded_total=forwarded_total,
                rejected_total=rejected_total,
                rejection_reasons=reasons,
                explanation=_build_explanation(health, address, reasons, unknown_interfaces),
            )
        )

    statuses.sort(
        key=lambda status: (
            -status.health.severity,
            -(status.observed.flows if status.observed is not None else 0),
        )
    )
    return statuses


# ---------------------------------------------------------------------------
# Résolution des ifIndex par SSH — COMPLÉMENT de secours à la résolution SNMP
# ---------------------------------------------------------------------------
#
# BLOCAGE MESURÉ (2026-08-11) : `snmpd` n'est pas déployé sur une partie du
# parc homelab où l'ifIndex de `tailscale0` a dérivé (vérifié sur .23, .3,
# .21 : binaire absent, rien en écoute sur 161/udp). Le bouton « Résoudre par
# SNMP » (cf. `build_if_indexes_from_snmp` ci-dessus et `app.routers.exporters`)
# n'a donc aucun agent à interroger sur ces hôtes-là — pas cassé, juste sans
# cible. Il reste nécessaire pour la cible entreprise (Palo Alto, routeurs SFR
# répondent en SNMP, cf. CLAUDE.md) : rien n'y est modifié.
#
# Ce qui suit ajoute une SECONDE source, disponible en repli quand SNMP rend
# `no_response` : interroger l'équipement par SSH (`ip -o link show`), qui
# donne la même information (ifIndex -> nom d'interface) directement depuis
# le noyau Linux de la cible. Le résultat emprunte EXACTEMENT le même modèle
# (`snmp_inventory.InterfaceTableResult`, même contrat à 3 issues) pour rester
# interchangeable avec la voie SNMP côté appelant (`build_if_indexes_from_snmp`
# -> `stage_change` -> file d'attente -> `apply_pending_changes`).

#: Regex d'une ligne `ip -o link show` : "<ifIndex>: <nom>: <FLAGS> ...".
#: Le nom peut porter un suffixe `@parent` (interface empilée, ex. VLAN
#: `eth0.100@eth0`) : seul ce qui précède `@` est le nom de l'interface.
#: Ancrée en DÉBUT de ligne pour ignorer tout bruit qui ne commence pas par
#: un ifIndex numérique (zéro faux-positif plutôt qu'un parsing permissif).
_IP_LINK_LINE_RE = re.compile(r"^(?P<if_index>\d+):\s+(?P<name>[^:@\s]+)(?:@\S+)?:\s")

#: Messages par statut d'échec — même convention que
#: `snmp_inventory._INTERFACE_TABLE_MESSAGES`, pour que l'écran affiche un
#: message orienté action plutôt qu'un simple constat.
_SSH_INTERFACE_TABLE_MESSAGES: dict[str, str] = {
    "no_response": (
        "L'hôte n'a pas répondu en SSH : vérifier qu'il est joignable sur le "
        "port 22 et que la clé SSH d'Okvorado y est autorisée."
    ),
    "auth_failure": (
        "L'hôte a répondu mais a refusé l'authentification SSH : vérifier "
        "que la clé publique d'Okvorado est bien déployée pour l'utilisateur "
        "configuré (OKVORADO_SSH_IFINDEX_USER)."
    ),
    "invalid_address": (
        "L'adresse fournie n'est pas une adresse IP valide : aucune connexion SSH n'a été tentée."
    ),
    "empty_table": (
        "L'hôte a répondu mais `ip -o link show` n'a rendu aucune interface "
        "exploitable : la configuration n'a PAS été modifiée (écrire une "
        "liste d'interfaces vide ferait rejeter tous les flux)."
    ),
}


def parse_ip_link_show(output: str) -> dict[int, str]:
    """Traduit la sortie de `ip -o link show` en table `ifIndex -> nom`.

    Format réel (iproute2, une interface par ligne avec `-o`) :
        "3: tailscale0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 ..."

    Une ligne qui ne correspond pas au motif attendu est IGNORÉE plutôt que de
    faire échouer tout le parsing : `ip -o link show` ne produit normalement
    que des lignes conformes, mais un parseur qui lève sur un octet inattendu
    transformerait un détail cosmétique en `no_response` trompeur.

    Ne fait AUCUNE hypothèse sur les flags présents (`BROADCAST` notamment) :
    une interface TUN comme `tailscale0` porte `POINTOPOINT`, pas
    `BROADCAST` — c'est précisément l'interface au cœur du défaut mesuré en
    prod, elle doit être reconnue au même titre que les autres.
    """
    table: dict[int, str] = {}
    for line in output.splitlines():
        match = _IP_LINK_LINE_RE.match(line.strip())
        if match is None:
            continue
        table[int(match.group("if_index"))] = match.group("name")
    return table


def _classify_ssh_failure(stderr: str) -> str:
    """Distingue `auth_failure` (l'hôte répond, l'authentification échoue) de
    `no_response` (tout le reste : hôte non joint, port fermé, timeout côté
    ssh lui-même) — même distinction que le contrat SNMPv3, cf.
    `snmp_inventory.InterfaceTableResult.status`.

    Repose sur le message que le client `ssh` OpenSSH écrit sur stderr en cas
    de refus d'authentification (`Permission denied`) : c'est le signal le
    plus fiable disponible sans parser des codes de sortie non documentés
    (`ssh` rend 255 pour toute erreur de connexion ET d'authentification)."""
    if "permission denied" in stderr.lower():
        return "auth_failure"
    return "no_response"


def resolve_interface_table_ssh(
    *,
    address: str,
    ssh_user: str,
    timeout_seconds: float,
) -> InterfaceTableResult:
    """Résout la table `ifIndex -> nom d'interface` d'UN équipement par SSH.

    REPLI de `snmp_inventory.resolve_interface_table` quand SNMP est muet
    (`snmpd` absent) : SNMP reste la voie PRINCIPALE, cette fonction n'est
    appelée qu'en complément (cf. docstring de section, `app.config` et
    `app.routers.exporters`).

    Séquence, MÊME FORME que la résolution SNMP :
      1. Refuse une adresse qui n'est pas une IP — AVANT tout accès réseau.
      2. Exécute `ssh` avec une LISTE d'arguments (jamais `shell=True`, jamais
         de commande assemblée en chaîne) : l'adresse vient de la base des
         exportateurs, un shell l'exposerait à l'injection de commande.
      3. Rend un état DISTINCT dans tous les cas, jamais une table vide muette.

    Args:
        address: adresse IP de l'exportateur, VALIDÉE avant tout usage.
        ssh_user: utilisateur SSH (`settings.ssh_ifindex_user`, jamais en dur).
        timeout_seconds: délai de connexion (`settings.ssh_ifindex_timeout_seconds`).

    Returns:
        `InterfaceTableResult` — même modèle que la voie SNMP, avec
        `source_oid` portant la commande exécutée (pas un OID, mais le même
        champ sert à dire à l'écran D'OÙ vient la table).

    Ne lève JAMAIS : toute anomalie devient un `status` lisible, même
    contrainte que `resolve_interface_table` (un 500 ne serait pas swappé par
    htmx, cf. tests/test_htmx_error_visibility.py).
    """

    def _echec(status: str) -> InterfaceTableResult:
        return InterfaceTableResult(
            address=address,
            status=status,
            interfaces={},
            message=_SSH_INTERFACE_TABLE_MESSAGES[status],
        )

    try:
        ipaddress.ip_address(address)
    except ValueError:
        log.error("resolution ssh refusee, adresse invalide: address=%r", address)
        return _echec("invalid_address")

    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"ConnectTimeout={int(timeout_seconds)}",
        f"{ssh_user}@{address}",
        "ip",
        "-o",
        "link",
        "show",
    ]

    try:
        completed = subprocess.run(  # noqa: S603 - argv liste fixe, aucun shell, cf. docstring
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        log.error(
            "resolution ssh: hote sans reponse (timeout): address=%s timeout_seconds=%s",
            address,
            timeout_seconds,
        )
        return _echec("no_response")
    except OSError as exc:
        # Binaire `ssh` absent ou non exécutable : l'hôte n'est pas en cause,
        # mais l'exploitant doit quand même voir un état DISTINCT plutôt
        # qu'une table vide qui se lirait comme "aucune interface".
        log.error("resolution ssh: echec de lancement du client ssh: %s", exc)
        return _echec("no_response")

    if completed.returncode != 0:
        classification = _classify_ssh_failure(completed.stderr or "")
        log.error(
            "resolution ssh: echec address=%s returncode=%s classement=%s",
            address,
            completed.returncode,
            classification,
        )
        return _echec(classification)

    table = parse_ip_link_show(completed.stdout or "")
    if not table:
        log.error(
            "resolution ssh: sortie sans aucune interface exploitable: address=%s",
            address,
        )
        return _echec("empty_table")

    log.info(
        "resolution ssh reussie: address=%s interfaces=%d",
        address,
        len(table),
    )
    return InterfaceTableResult(
        address=address,
        status="ok",
        interfaces=table,
        source_oid="ip -o link show",
        message="",
    )
