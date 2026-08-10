"""Lecture ET écriture de la configuration `outlet.yaml` d'Akvorado.

Parse `metadata.providers[].exporters` : une map de CIDR -> déclaration
d'exportateur (`name`, `if-indexes`, `default`). Utilise `ruamel.yaml` en mode
round-trip pour préserver commentaires/mise en forme — aussi bien en lecture
qu'en écriture (LOT B, v2).

Robustesse en lecture : un fichier absent, un YAML malformé, une section
manquante ou vide ne doivent JAMAIS lever d'exception non gérée — on logue
l'erreur avec contexte puis on dégrade proprement vers une liste vide.

Robustesse en écriture (LOT B) : c'est l'inverse — toute anomalie DOIT lever
une exception explicite, jamais de dégradation silencieuse. Écrire un YAML
tronqué ou incohérent empêcherait Akvorado de redémarrer. Voir
`write_declared_exporters` pour la séquence verrou optimiste + backup +
écriture atomique + validation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from app.models import Boundary, DeclaredExporter, InterfaceSpec

log = logging.getLogger(__name__)

_IPV4_MAX_PREFIX = 32
# Longueur de préfixe d'un hôte UNIQUE, par famille d'adressage. En deçà, le
# CIDR désigne une plage (catchall). Voir `_is_catchall_cidr` : l'absence du
# pendant IPv6 a produit un exportateur fantôme à l'écran (2026-08-09).
_IPV6_MAX_PREFIX = 128
_VALID_BOUNDARIES = {Boundary.INTERNAL.value, Boundary.EXTERNAL.value, Boundary.UNDEFINED.value}
_MAX_NAME_LENGTH = 128


class ConcurrentModificationError(Exception):
    """Le fichier a été modifié depuis le hash attendu (verrou optimiste).

    Motif : quelqu'un a édité `outlet.yaml` à la main (SSH) pendant que l'UI
    affichait un état devenu périmé. Un `flock` ne couvre PAS ce cas — seule
    une comparaison de hash avant écriture le détecte.
    """


def _is_catchall_cidr(cidr: str) -> bool:
    """Un CIDR est catchall s'il couvre un réseau entier plutôt qu'une machine.

    Le critère est le même dans les deux familles d'adressage : un préfixe
    plus court que l'adresse complète (< 32 en IPv4, < 128 en IPv6) désigne
    une PLAGE, donc un filet de repli — pas un routeur déclaré nommément.

    DÉFAUT MESURÉ À L'ÉCRAN (2026-08-09), sur un déploiement NEUF du paquet
    `stack/` sur machine nue : l'écran Exportateurs affichait « 1 exportateur »
    — ligne `exportateur-non-resolu`, adresse `::` — alors que ClickHouse
    contenait ZÉRO flux. Cette fonction ne traitait alors que l'IPv4 et rendait
    `False` pour TOUTE adresse IPv6, `::/0` (l'Internet entier) compris. Ce
    `::/0` était donc lu comme la déclaration NOMINATIVE d'un routeur réel par
    `_find_declared_match`, qui préfère une correspondance nominative à un
    catchall.

    Ce n'était pas un cas particulier : Akvorado écoute en IPv6 par défaut et
    le template du paquet écrit `::/0` pour le repli SNMP, donc TOUTE
    installation neuve affichait un routeur fantôme et envoyait l'exploitant
    chercher une panne sur un équipement inexistant. Famille du « zéro
    silencieux » proscrite par CLAUDE.md : une valeur FABRIQUÉE rendue
    indiscernable d'une vraie mesure.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        log.error("cidr invalide dans outlet.yaml, ignore comme non-catchall: cidr=%s", cidr)
        return False
    hote_unique = _IPV4_MAX_PREFIX if network.version == 4 else _IPV6_MAX_PREFIX
    return network.prefixlen < hote_unique


def _parse_boundary(raw: Any) -> Boundary:
    if raw is None:
        return Boundary.UNDEFINED
    try:
        return Boundary(str(raw))
    except ValueError:
        log.error("valeur boundary inconnue dans outlet.yaml, defaut undefined: valeur=%s", raw)
        return Boundary.UNDEFINED


def _parse_interface_spec(if_index: int, raw: Any) -> InterfaceSpec | None:
    if not isinstance(raw, dict):
        log.error(
            "entree if-indexes malformee dans outlet.yaml, ignoree: if_index=%s valeur=%r",
            if_index,
            raw,
        )
        return None
    name = raw.get("name")
    if not name:
        log.error(
            "interface sans 'name' dans outlet.yaml, ignoree: if_index=%s",
            if_index,
        )
        return None
    return InterfaceSpec(
        if_index=if_index,
        name=str(name),
        description=str(raw.get("description", "")),
        speed=int(raw.get("speed", 1000)),
        boundary=_parse_boundary(raw.get("boundary")),
    )


def _parse_if_indexes(raw: Any, exporter_name: str) -> dict[int, InterfaceSpec]:
    if not raw:
        return {}
    if not isinstance(raw, dict):
        log.error(
            "if-indexes n'est pas une map dans outlet.yaml, ignore: exportateur=%s",
            exporter_name,
        )
        return {}

    if_indexes: dict[int, InterfaceSpec] = {}
    for raw_index, raw_spec in raw.items():
        try:
            if_index = int(raw_index)
        except (TypeError, ValueError):
            log.error(
                "if-index non entier dans outlet.yaml, ignore: exportateur=%s if_index=%r",
                exporter_name,
                raw_index,
            )
            continue
        spec = _parse_interface_spec(if_index, raw_spec)
        if spec is not None:
            if_indexes[if_index] = spec
    return if_indexes


def _parse_default_interface(raw: Any, exporter_name: str) -> InterfaceSpec | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        log.error(
            "'default' malforme dans outlet.yaml, ignore: exportateur=%s",
            exporter_name,
        )
        return None
    return InterfaceSpec(
        if_index=0,
        name=str(raw.get("name", "default")),
        description=str(raw.get("description", "")),
        speed=int(raw.get("speed", 1000)),
        boundary=_parse_boundary(raw.get("boundary")),
    )


def _parse_exporters_map(exporters_raw: Any) -> list[DeclaredExporter]:
    if not exporters_raw:
        return []
    if not isinstance(exporters_raw, dict):
        log.error("section 'exporters' n'est pas une map dans outlet.yaml, ignoree")
        return []

    declared: list[DeclaredExporter] = []
    for cidr, spec in exporters_raw.items():
        if not isinstance(spec, dict):
            log.error(
                "declaration d'exportateur malformee dans outlet.yaml, ignoree: cidr=%s", cidr
            )
            continue
        name = spec.get("name")
        if not name:
            log.error("exportateur sans 'name' dans outlet.yaml, ignore: cidr=%s", cidr)
            continue
        declared.append(
            DeclaredExporter(
                cidr=str(cidr),
                name=str(name),
                if_indexes=_parse_if_indexes(spec.get("if-indexes"), str(name)),
                default=_parse_default_interface(spec.get("default"), str(name)),
                is_catchall=_is_catchall_cidr(str(cidr)),
            )
        )
    return declared


def load_declared_exporters(path: str) -> list[DeclaredExporter]:
    """Charge et parse les exportateurs déclarés depuis `outlet.yaml`.

    Ne lève jamais d'exception : toute anomalie (fichier absent, YAML
    invalide, section manquante/vide/malformée) est loguée avec contexte puis
    dégradée vers une liste vide.
    """
    yaml_path = Path(path)
    if not yaml_path.is_file():
        log.error("outlet.yaml introuvable, degradation vers liste vide: path=%s", path)
        return []

    yaml_loader = YAML(typ="rt")
    try:
        with yaml_path.open("r", encoding="utf-8") as handle:
            document = yaml_loader.load(handle)
    except YAMLError:
        log.error("outlet.yaml malforme (erreur de parsing YAML): path=%s", path, exc_info=True)
        return []
    except OSError:
        log.error("outlet.yaml illisible (erreur I/O): path=%s", path, exc_info=True)
        return []

    if not isinstance(document, dict):
        log.error("outlet.yaml ne contient pas un document mapping valide: path=%s", path)
        return []

    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        log.error("section 'metadata' absente ou invalide dans outlet.yaml: path=%s", path)
        return []

    providers = metadata.get("providers")
    if not isinstance(providers, list):
        log.error(
            "section 'metadata.providers' absente ou invalide dans outlet.yaml: path=%s", path
        )
        return []

    declared: list[DeclaredExporter] = []
    for provider in providers:
        if not isinstance(provider, dict):
            log.error("entree 'providers' malformee dans outlet.yaml, ignoree: path=%s", path)
            continue
        declared.extend(_parse_exporters_map(provider.get("exporters")))

    return declared


# ---------------------------------------------------------------------------
# Écriture (LOT B) — verrou optimiste, backup, écriture atomique, validation
# ---------------------------------------------------------------------------


def compute_config_hash(path: str) -> str:
    """Sha256 du contenu actuel de `outlet.yaml`, utilisé comme ETag pour le
    verrouillage optimiste (voir `write_declared_exporters`)."""
    with Path(path).open("rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def validate_exporters(exporters: list[DeclaredExporter]) -> list[str]:
    """Valide un jeu d'exportateurs déclarés. Retourne la liste des erreurs
    (vide si tout est correct). Ne lève jamais : c'est un pur contrôle.
    """
    errors: list[str] = []
    seen_cidrs: set[str] = set()
    has_catchall = False

    for exporter in exporters:
        try:
            network = ipaddress.ip_network(exporter.cidr, strict=False)
        except ValueError:
            errors.append(f"cidr invalide: {exporter.cidr!r}")
        else:
            normalized = str(network)
            if normalized in seen_cidrs:
                errors.append(f"cidr en doublon: {exporter.cidr!r}")
            seen_cidrs.add(normalized)
            if exporter.is_catchall:
                has_catchall = True

        if not exporter.name or not exporter.name.strip():
            errors.append(f"name vide pour l'exportateur cidr={exporter.cidr!r}")
        elif len(exporter.name) > _MAX_NAME_LENGTH:
            errors.append(
                f"name trop long ({len(exporter.name)} caracteres) pour cidr={exporter.cidr!r}"
            )

        # Les entrees `if-indexes` exigent un ifIndex STRICTEMENT positif : un
        # ifIndex a 0 (ou negatif) est precisement ce qui fait rejeter les
        # flux par Akvorado (enricher.go:83). `default` fait exception : par
        # convention de lecture (`_parse_default_interface`), il porte
        # toujours if_index=0 et ne represente pas une interface indexee.
        for spec in exporter.if_indexes.values():
            if spec.if_index <= 0:
                errors.append(
                    f"if_index invalide ({spec.if_index}) pour exportateur "
                    f"cidr={exporter.cidr!r} interface={spec.name!r} "
                    "(un ifIndex <= 0 fait rejeter les flux par Akvorado)"
                )

        all_specs = list(exporter.if_indexes.values())
        if exporter.default is not None:
            all_specs.append(exporter.default)

        for spec in all_specs:
            if spec.speed <= 0:
                errors.append(
                    f"speed invalide ({spec.speed}) pour exportateur "
                    f"cidr={exporter.cidr!r} interface={spec.name!r}"
                )
            if spec.boundary.value not in _VALID_BOUNDARIES:
                errors.append(
                    f"boundary invalide ({spec.boundary!r}) pour exportateur "
                    f"cidr={exporter.cidr!r} interface={spec.name!r}"
                )

    if not has_catchall:
        errors.append(
            "aucun exportateur catchall present : les nouveaux noeuds "
            "disparaitraient silencieusement des flux classes"
        )

    return errors


def _interface_spec_to_yaml(spec: InterfaceSpec) -> dict[str, Any]:
    entry: dict[str, Any] = {"name": spec.name}
    if spec.description:
        entry["description"] = spec.description
    entry["speed"] = spec.speed
    entry["boundary"] = spec.boundary.value
    return entry


def _exporter_to_yaml_entry(exporter: DeclaredExporter) -> dict[str, Any]:
    """Construit la représentation YAML (dict brut) d'un exportateur, dans
    l'ordre attendu par la structure documentée de outlet.yaml."""
    entry: dict[str, Any] = {"name": exporter.name}
    if exporter.if_indexes:
        entry["if-indexes"] = {
            if_index: _interface_spec_to_yaml(spec)
            for if_index, spec in sorted(exporter.if_indexes.items())
        }
    if exporter.default is not None:
        entry["default"] = _interface_spec_to_yaml(exporter.default)
    return entry


def _resync_exporters_map(exporters_map: Any, exporters: list[DeclaredExporter]) -> None:
    """Resynchronise en place une CommentedMap ruamel `exporters` avec la
    liste cible : supprime les clés disparues, met à jour les existantes
    (préservant leurs commentaires), ajoute les nouvelles à la fin.
    """
    target_cidrs = {exporter.cidr for exporter in exporters}

    for existing_cidr in list(exporters_map.keys()):
        if str(existing_cidr) not in target_cidrs:
            del exporters_map[existing_cidr]

    for exporter in exporters:
        new_entry = _exporter_to_yaml_entry(exporter)
        if exporter.cidr in exporters_map and isinstance(exporters_map[exporter.cidr], dict):
            existing_entry = exporters_map[exporter.cidr]
            for key in list(existing_entry.keys()):
                if key not in new_entry:
                    del existing_entry[key]
            for key, value in new_entry.items():
                existing_entry[key] = value
        else:
            exporters_map[exporter.cidr] = new_entry


def _find_first_exporters_map(document: Any) -> Any:
    """Localise la première section `metadata.providers[].exporters` d'un
    document round-trip déjà chargé et validé comme structurellement correct.
    """
    metadata = document["metadata"]
    providers = metadata["providers"]
    for provider in providers:
        if isinstance(provider, dict) and "exporters" in provider:
            return provider["exporters"]
    raise ValueError("aucune section 'metadata.providers[].exporters' trouvee dans le document")


def write_declared_exporters(
    path: str, exporters: list[DeclaredExporter], expected_hash: str
) -> None:
    """Écrit les exportateurs déclarés dans `outlet.yaml`, en toute sécurité.

    Séquence stricte :
    1. Vérifie le hash actuel du fichier == `expected_hash` (verrou optimiste :
       ConcurrentModificationError sinon, quelqu'un a édité le fichier entre
       temps).
    2. Valide `exporters` (`validate_exporters`) : ValueError si erreur, AVANT
       tout backup ou écriture.
    3. Backup horodaté `outlet.yaml.bak-YYYYmmddHHMMSS`.
    4. Charge le document ruamel round-trip, resynchronise la section
       `exporters` en place (préserve commentaires/formatage), écrit dans un
       fichier temporaire du même répertoire puis `os.replace()` (atomique).
    5. Re-parse le fichier écrit pour valider qu'il est bien reformé et
       contient tous les exportateurs attendus.

    Ne dégrade JAMAIS silencieusement : toute anomalie lève une exception.
    """
    yaml_path = Path(path)
    if not yaml_path.is_file():
        log.error("ecriture impossible, outlet.yaml introuvable: path=%s", path)
        raise FileNotFoundError(f"outlet.yaml introuvable: {path}")

    current_hash = compute_config_hash(path)
    if current_hash != expected_hash:
        log.error(
            "verrou optimiste: hash actuel differe du hash attendu, "
            "fichier modifie depuis: path=%s attendu=%s actuel=%s",
            path,
            expected_hash,
            current_hash,
        )
        raise ConcurrentModificationError(
            f"outlet.yaml a ete modifie depuis la derniere lecture (hash attendu={expected_hash}, "
            f"actuel={current_hash})"
        )

    errors = validate_exporters(exporters)
    if errors:
        log.error(
            "validation des exportateurs echouee, ecriture annulee: path=%s erreurs=%s",
            path,
            errors,
        )
        raise ValueError("validation des exportateurs echouee: " + "; ".join(errors))

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = yaml_path.with_name(f"{yaml_path.name}.bak-{timestamp}")
    shutil.copy2(yaml_path, backup_path)
    log.info("backup de outlet.yaml cree: path=%s", backup_path)

    yaml_rw = YAML(typ="rt")
    yaml_rw.preserve_quotes = True
    try:
        with yaml_path.open("r", encoding="utf-8") as handle:
            document = yaml_rw.load(handle)
    except (YAMLError, OSError) as exc:
        log.error("relecture de outlet.yaml impossible avant ecriture: path=%s", path)
        raise ValueError(f"impossible de relire outlet.yaml avant ecriture: {exc}") from exc

    exporters_map = _find_first_exporters_map(document)
    _resync_exporters_map(exporters_map, exporters)

    tmp_path = yaml_path.with_name(f"{yaml_path.name}.tmp-{timestamp}")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            yaml_rw.dump(document, handle)
        os.replace(tmp_path, yaml_path)
    except OSError:
        log.error(
            "echec de l'ecriture atomique de outlet.yaml, fichier original preserve: path=%s",
            path,
            exc_info=True,
        )
        if tmp_path.exists():
            tmp_path.unlink()
        raise
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    reloaded = load_declared_exporters(path)
    reloaded_cidrs = {exporter.cidr for exporter in reloaded}
    expected_cidrs = {exporter.cidr for exporter in exporters}
    if reloaded_cidrs != expected_cidrs:
        log.error(
            "validation post-ecriture echouee: cidrs attendus=%s obtenus=%s path=%s",
            expected_cidrs,
            reloaded_cidrs,
            path,
        )
        raise ValueError(
            "le fichier ecrit ne contient pas tous les exportateurs attendus "
            f"(attendus={expected_cidrs}, obtenus={reloaded_cidrs})"
        )

    log.info("outlet.yaml ecrit avec succes: path=%s exportateurs=%d", path, len(exporters))
