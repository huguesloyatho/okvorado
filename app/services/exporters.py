"""Logique métier du module Exportateurs : croise déclaré x observé x ingéré.

C'est le cœur du LOT 1 : ni Akvorado ni ClickHouse seuls ne savent produire
cette vue. Un exportateur peut émettre des flux et être 100% rejeté à
l'ingestion (motif `input and output interfaces missing`) sans que cela
n'apparaisse nulle part ailleurs — ce module le rend visible.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime

from app.models import (
    Boundary,
    DeclaredExporter,
    ExporterHealth,
    ExporterStatus,
    InterfaceSpec,
    ObservedExporter,
)

log = logging.getLogger(__name__)

#: Débit par défaut (Mbit/s) affecté à une interface DÉCOUVERTE par SNMP dont
#: rien n'était déclaré. Même valeur que le défaut de lecture d'`outlet.yaml`
#: (`app.clients.akvorado_yaml._parse_interface_spec`) : la cohérence importe
#: plus que la justesse ici, `speed` ne sert qu'au calcul du taux de
#: saturation d'interface et l'exploitant l'ajuste à l'écran. Ce qui est
#: interdit, c'est 0 — `validate_exporters` refuse un `speed <= 0`.
_DEFAULT_INTERFACE_SPEED = 1000


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
