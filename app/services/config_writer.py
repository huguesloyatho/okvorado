"""Orchestration de l'écriture de `outlet.yaml` — file d'attente + application.

C'est la couche qui enchaîne en toute sécurité : relecture, application des
changements en attente au modèle en mémoire, validation, backup, écriture
atomique avec verrou optimiste, puis redémarrage avec rollback automatique en
cas d'échec.

La file d'attente de changements est stockée en SQLite. Ce module ne crée
JAMAIS le schéma lui-même : il prend la connexion en paramètre (câblée dans
`app/db.py` par LOT 0). Voir `SCHEMA` ci-dessous pour la définition exacte de
la table attendue par ce module (à intégrer telle quelle dans `app/db.py`).
"""

from __future__ import annotations

import json
import logging
import shutil
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from app.clients.akvorado_yaml import (
    ConcurrentModificationError,
    load_declared_exporters,
    validate_exporters,
    write_declared_exporters,
)
from app.clients.yaml_editor import (
    ConcurrentModificationError as SectionConcurrentModificationError,
)
from app.clients.yaml_editor import compute_file_hash, write_section
from app.models import Boundary, DeclaredExporter, InterfaceSpec
from app.services.config_sections import ConfigSection, get_section

log = logging.getLogger(__name__)

__all__ = [
    "SCHEMA",
    "ApplyResult",
    "PendingChange",
    "apply_pending_changes",
    "build_ifindex_fix",
    "discard_change",
    "list_pending_changes",
    "stage_change",
    # Re-export EXPLICITE : les tests monkeypatchent cette reference pour simuler
    # un echec d'ecriture. Sans __all__, mypy --strict refuse l'acces via ce module.
    "write_declared_exporters",
    "write_section",
]

ChangeType = Literal[
    "add_exporter", "update_exporter", "delete_exporter", "fix_ifindex", "update_section"
]

#: Nom logique du fichier des exportateurs dans la map `config_files`. Tous
#: les `change_type` hérités de LOT B (add/update/delete_exporter, fix_ifindex)
#: opèrent historiquement sur ce seul fichier.
_EXPORTERS_FILE_KEY = "outlet.yaml"

#: Schéma SQLite attendu par ce module. À câbler dans `app/db.py::SCHEMA`
#: (LOT 0) — ce module ne l'exécute jamais lui-même, il prend la connexion en
#: paramètre déjà initialisée.
SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_config_changes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    change_type TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    author      TEXT    NOT NULL DEFAULT 'anonymous',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
"""


@dataclass
class PendingChange:
    """Un changement en attente d'application sur `outlet.yaml`."""

    id: int
    change_type: ChangeType
    payload: dict[str, Any]
    author: str
    created_at: str


@dataclass
class ApplyResult:
    """Résultat détaillé d'un `apply_pending_changes`."""

    success: bool
    message: str
    steps_completed: list[str] = field(default_factory=list)
    rolled_back: bool = False
    errors: list[str] = field(default_factory=list)


@runtime_checkable
class RestartOutcome(Protocol):
    """Forme attendue de la valeur retournée par la fonction de restart
    injectée (fournie par LOT A, jamais importée directement par ce module).
    """

    success: bool
    message: str


#: Signature élargie (LOT D) : un `apply_pending_changes` peut désormais
#: toucher plusieurs sections déclarant chacune leur propre
#: `restart_services`. Le restart doit donc connaître l'UNION exacte des
#: services à redémarrer plutôt qu'une liste figée décidée par l'appelant.
#: BREAKING CHANGE côté appelants (`app/main.py`, `app/routers/config.py`,
#: hors périmètre de ce lot) : `RestartFn` prenait `()` , elle prend
#: maintenant `(tuple[str, ...])` — voir rapport final pour le câblage exact.
RestartFn = Callable[[tuple[str, ...]], RestartOutcome]


def stage_change(
    conn: sqlite3.Connection,
    change_type: ChangeType,
    payload: dict[str, Any],
    author: str,
) -> int:
    """Ajoute un changement à la file d'attente. Retourne son id."""
    cursor = conn.execute(
        "INSERT INTO pending_config_changes (change_type, payload, author) VALUES (?, ?, ?)",
        (change_type, json.dumps(payload), author),
    )
    conn.commit()
    change_id = cursor.lastrowid
    if change_id is None:  # pragma: no cover - ne devrait jamais arriver avec AUTOINCREMENT
        log.error(
            "insertion de changement en attente sans id retourne: change_type=%s", change_type
        )
        raise RuntimeError("echec insertion pending_config_changes: aucun id retourne")
    log.info(
        "changement mis en attente: id=%d change_type=%s author=%s", change_id, change_type, author
    )
    return change_id


def list_pending_changes(conn: sqlite3.Connection) -> list[PendingChange]:
    """Liste les changements en attente, dans l'ordre d'ajout (id croissant)."""
    rows = conn.execute(
        "SELECT id, change_type, payload, author, created_at "
        "FROM pending_config_changes ORDER BY id ASC"
    ).fetchall()
    return [
        PendingChange(
            id=row["id"],
            change_type=row["change_type"],
            payload=json.loads(row["payload"]),
            author=row["author"],
            created_at=row["created_at"],
        )
        for row in rows
    ]


def discard_change(conn: sqlite3.Connection, change_id: int) -> None:
    """Retire un changement de la file d'attente sans l'appliquer."""
    conn.execute("DELETE FROM pending_config_changes WHERE id = ?", (change_id,))
    conn.commit()
    log.info("changement en attente ecarte: id=%d", change_id)


def build_ifindex_fix(
    cidr: str,
    interface_name: str,
    old_if_index: int,
    new_if_index: int,
    author: str,
) -> PendingChange:
    """Construit (sans le stager) le changement corrigeant un ifIndex périmé.

    Contexte métier : l'ifIndex d'une interface TUN (`tailscale0`) change à
    chaque redémarrage du démon tailscale. Incident réel corrigé : `.17`
    déclaré à 219 au lieu de 409, `.21` à 3 au lieu de 235 -> ~76 000 flux mal
    classés. Cette fonction rend la correction faisable en un clic.
    """
    return PendingChange(
        id=0,
        change_type="fix_ifindex",
        payload={
            "cidr": cidr,
            "interface_name": interface_name,
            "old_if_index": old_if_index,
            "new_if_index": new_if_index,
        },
        author=author,
        created_at="",
    )


def _interface_spec_from_payload(raw: dict[str, Any], if_index: int) -> InterfaceSpec:
    return InterfaceSpec(
        if_index=if_index,
        name=str(raw.get("name", "")),
        description=str(raw.get("description", "")),
        speed=int(raw.get("speed", 1000)),
        boundary=Boundary(str(raw.get("boundary", Boundary.UNDEFINED.value))),
    )


def _declared_exporter_from_payload(payload: dict[str, Any]) -> DeclaredExporter:
    cidr = str(payload["cidr"])
    if_indexes_raw = payload.get("if_indexes", {}) or {}
    if_indexes = {
        int(if_index): _interface_spec_from_payload(raw, int(if_index))
        for if_index, raw in if_indexes_raw.items()
    }
    default_raw = payload.get("default")
    default = _interface_spec_from_payload(default_raw, 0) if default_raw else None
    return DeclaredExporter(
        cidr=cidr,
        name=str(payload.get("name", "")),
        if_indexes=if_indexes,
        default=default,
        is_catchall=bool(payload.get("is_catchall", False)),
    )


def _apply_add_exporter(exporters: list[DeclaredExporter], payload: dict[str, Any]) -> None:
    new_exporter = _declared_exporter_from_payload(payload)
    exporters[:] = [e for e in exporters if e.cidr != new_exporter.cidr]
    exporters.append(new_exporter)


def _apply_update_exporter(exporters: list[DeclaredExporter], payload: dict[str, Any]) -> None:
    updated = _declared_exporter_from_payload(payload)
    for index, existing in enumerate(exporters):
        if existing.cidr == updated.cidr:
            exporters[index] = updated
            return
    exporters.append(updated)


def _apply_delete_exporter(exporters: list[DeclaredExporter], payload: dict[str, Any]) -> None:
    cidr = str(payload["cidr"])
    exporters[:] = [e for e in exporters if e.cidr != cidr]


def _apply_fix_ifindex(exporters: list[DeclaredExporter], payload: dict[str, Any]) -> None:
    cidr = str(payload["cidr"])
    interface_name = str(payload["interface_name"])
    old_if_index = int(payload["old_if_index"])
    new_if_index = int(payload["new_if_index"])

    for exporter in exporters:
        if exporter.cidr != cidr:
            continue
        existing = exporter.if_indexes.pop(old_if_index, None)
        if existing is None:
            log.error(
                "fix_ifindex: ancien if_index introuvable, creation d'une nouvelle entree: "
                "cidr=%s interface=%s old_if_index=%d",
                cidr,
                interface_name,
                old_if_index,
            )
            exporter.if_indexes[new_if_index] = InterfaceSpec(
                if_index=new_if_index, name=interface_name
            )
        else:
            exporter.if_indexes[new_if_index] = existing.model_copy(
                update={"if_index": new_if_index}
            )
        return

    log.error(
        "fix_ifindex: aucun exportateur ne correspond au cidr, changement ignore: cidr=%s", cidr
    )


_APPLIERS = {
    "add_exporter": _apply_add_exporter,
    "update_exporter": _apply_update_exporter,
    "delete_exporter": _apply_delete_exporter,
    "fix_ifindex": _apply_fix_ifindex,
}


def _apply_changes_to_model(
    exporters: list[DeclaredExporter], changes: list[PendingChange]
) -> list[DeclaredExporter]:
    working = [exporter.model_copy(deep=True) for exporter in exporters]
    for change in changes:
        applier = _APPLIERS.get(change.change_type)
        if applier is None:  # pragma: no cover - change_type est un Literal ferme
            log.error("type de changement inconnu, ignore: change_type=%s", change.change_type)
            continue
        applier(working, change.payload)
    return working


_EXPORTER_CHANGE_TYPES: frozenset[str] = frozenset(
    {"add_exporter", "update_exporter", "delete_exporter", "fix_ifindex"}
)


SectionValidator = Callable[[Any], list[str]]


def _restore_key_types(value: Any, section: ConfigSection) -> Any:
    """Restaure le type des clés perdu par la sérialisation JSON de la file.

    DÉFAUT MESURÉ (2026-08-06) : la file d'attente stocke chaque changement en
    JSON, et **JSON n'a pas de clé entière**. Un mapping `{64501: "ACME"}` mis
    en attente en ressort en `{"64501": "ACME"}`. Écrit tel quel dans
    `akvorado.yaml`, la table des noms d'AS aurait porté des clés CHAÎNES
    qu'Akvorado ne rapproche d'aucun AS observé : les noms n'auraient jamais
    été appliqués — sans erreur dans les logs, sans rien à l'écran, et avec un
    « changement appliqué » affiché en succès.

    La conversion a lieu ICI, au dernier moment avant l'écriture : c'est le
    seul endroit traversé par TOUS les chemins (ajout unitaire, import CSV,
    suppression de masse), donc le seul où le défaut ne peut pas se rejouer
    parce qu'un nouveau chemin aurait oublié de convertir.

    Une clé non convertible est laissée telle quelle plutôt que rejetée : la
    validation de section, qui suit, produira un message précis. Convertir en
    silence ce qui n'est pas un entier serait exactement le zéro silencieux
    que cette fonction existe pour empêcher.
    """
    if not section.integer_keys or not isinstance(value, dict):
        return value

    restored: dict[Any, Any] = {}
    for key, item in value.items():
        if isinstance(key, str):
            try:
                restored[int(key)] = item
                continue
            except ValueError:
                pass
        restored[key] = item
    return restored


@dataclass
class _SectionWrite:
    """Une écriture `update_section` résolue : section du catalogue + valeur
    finale à écrire (le dernier changement en attente pour cette `section_key`
    gagne, chaque payload transportant la valeur complète — pas un diff)."""

    dotted_key: str
    value: Any
    validator: SectionValidator
    change_ids: list[int]


@dataclass
class _FileWrite:
    """Tout ce qu'il faut écrire dans UN fichier YAML pour ce batch."""

    file_key: str
    path: str
    exporter_changes: list[PendingChange] = field(default_factory=list)
    section_writes: dict[str, _SectionWrite] = field(default_factory=dict)  # dotted_key -> write


def _resolve_config_files(config_files: str | dict[str, str]) -> dict[str, str]:
    """Normalise le paramètre `config_files` : un `str` seul est le raccourci
    historique `{"outlet.yaml": <path>}` (compat LOT B, exportateurs)."""
    if isinstance(config_files, str):
        return {_EXPORTERS_FILE_KEY: config_files}
    return dict(config_files)


def _group_pending_by_file(
    pending: list[PendingChange], resolved_files: dict[str, str]
) -> tuple[dict[str, _FileWrite], list[str]]:
    """Regroupe les changements en attente par fichier cible.

    Retourne (groupes par `file_key`, erreurs). Une erreur (section_key
    inconnue, ou fichier non fourni dans `config_files` pour une section
    concernée) interrompt tout : aucune écriture ne doit avoir lieu.
    """
    groups: dict[str, _FileWrite] = {}
    errors: list[str] = []

    def _group_for(file_key: str) -> _FileWrite | None:
        if file_key not in groups:
            path = resolved_files.get(file_key)
            if path is None:
                errors.append(
                    f"fichier de configuration '{file_key}' requis par la file d'attente "
                    "mais absent de config_files"
                )
                return None
            groups[file_key] = _FileWrite(file_key=file_key, path=path)
        return groups[file_key]

    for change in pending:
        if change.change_type in _EXPORTER_CHANGE_TYPES:
            group = _group_for(_EXPORTERS_FILE_KEY)
            if group is not None:
                group.exporter_changes.append(change)
            continue

        if change.change_type == "update_section":
            section_key = change.payload.get("section_key")
            if not isinstance(section_key, str):
                errors.append(
                    f"changement id={change.id}: payload update_section sans 'section_key' valide"
                )
                continue
            try:
                section = get_section(section_key)
            except ValueError as exc:
                errors.append(f"changement id={change.id}: {exc}")
                continue
            if "value" not in change.payload:
                errors.append(f"changement id={change.id}: payload update_section sans 'value'")
                continue

            group = _group_for(section.file)
            if group is None:
                continue
            section_value = _restore_key_types(change.payload["value"], section)
            existing = group.section_writes.get(section.dotted_key)
            if existing is None:
                group.section_writes[section.dotted_key] = _SectionWrite(
                    dotted_key=section.dotted_key,
                    value=section_value,
                    validator=section.validator,
                    change_ids=[change.id],
                )
            else:
                existing.value = section_value
                existing.change_ids.append(change.id)
            continue

        # pragma: no cover - change_type est un Literal ferme, jamais atteint
        errors.append(
            f"changement id={change.id}: type de changement inconnu {change.change_type!r}"
        )

    return groups, errors


def _restart_services_for(pending: list[PendingChange]) -> tuple[str, ...]:
    """Union déterministe (triée) des `restart_services` de toutes les
    sections `update_section` touchées. Les changements exportateurs
    redémarrent toujours `akvorado-outlet` (comportement LOT B inchangé)."""
    services: set[str] = set()
    for change in pending:
        if change.change_type in _EXPORTER_CHANGE_TYPES:
            services.add("akvorado-outlet")
            continue
        if change.change_type == "update_section":
            section_key = change.payload.get("section_key")
            if not isinstance(section_key, str):
                continue
            try:
                section = get_section(section_key)
            except ValueError:
                continue
            services.update(section.restart_services)
    return tuple(sorted(services))


def apply_pending_changes(
    conn: sqlite3.Connection,
    config_files: str | dict[str, str],
    restart_fn: RestartFn,
) -> ApplyResult:
    """Applique tous les changements en attente, sur un ou plusieurs fichiers.

    `config_files` : soit un `str` (raccourci historique, équivalent à
    `{"outlet.yaml": <path>}`, pour les seuls `change_type` exportateurs),
    soit un mapping `{nom_logique_de_fichier: chemin}` — ex.
    `{"outlet.yaml": ..., "console.yaml": ..., "akvorado.yaml": ...,
    "inlet.yaml": ...}`. Le nom logique est celui porté par
    `ConfigSection.file` (catalogue `app.services.config_sections`).

    Séquence stricte :
    1. Groupe les changements en attente par fichier cible (exportateurs ->
       toujours `outlet.yaml` ; `update_section` -> `get_section(key).file`).
       Une `section_key` inconnue ou un fichier manquant dans `config_files`
       arrête tout, AVANT toute lecture/écriture.
    2. Pour chaque fichier : relit son contenu actuel + hash, applique les
       changements en attente au modèle en mémoire.
    3. Valide CHAQUE fichier (`validate_exporters` pour les exportateurs,
       `section.validator` pour chaque section) -> si UNE SEULE validation
       échoue, AUCUN fichier n'est écrit (tout ou rien).
    4. Écrit chaque fichier (atomique, verrou optimiste, backup horodaté —
       `write_declared_exporters`/`write_section` gèrent ça nativement). Si
       l'écriture du Nème fichier échoue, restaure IMMÉDIATEMENT tous les
       fichiers déjà écrits (N-1 précédents).
    5. Calcule l'UNION des `restart_services` de toutes les sections
       touchées (les exportateurs redémarrent toujours `akvorado-outlet`).
       Si l'union est vide, `restart_fn` n'est PAS appelée. Sinon, appelée
       UNE fois avec cette union (signature : `(tuple[str, ...]) ->
       RestartOutcome`, fournie par LOT A, jamais importée ici).
    6. Si le restart échoue -> ROLLBACK : restaure TOUS les fichiers écrits,
       relance `restart_fn` avec la même union pour tenter une remise en
       cohérence, le signale clairement dans `ApplyResult`.
    7. Vide la file d'attente seulement en cas de succès complet.
    """
    steps: list[str] = []
    pending = list_pending_changes(conn)
    if not pending:
        return ApplyResult(
            success=True,
            message="aucun changement en attente",
            steps_completed=["list_pending_changes"],
        )
    steps.append("list_pending_changes")

    resolved_files = _resolve_config_files(config_files)
    groups, grouping_errors = _group_pending_by_file(pending, resolved_files)
    if grouping_errors:
        log.error(
            "apply_pending_changes: regroupement par fichier echoue, aucune ecriture: erreurs=%s",
            grouping_errors,
        )
        return ApplyResult(
            success=False,
            message="changement(s) invalide(s) en file d'attente: " + "; ".join(grouping_errors),
            steps_completed=steps,
            errors=grouping_errors,
        )
    steps.append("group_pending_by_file")

    written_paths: list[str] = []

    try:
        # Passe 1 — validation SEULE, aucune écriture. Une seule erreur sur
        # un seul fichier doit interrompre tout le batch (tout ou rien).
        for group in groups.values():
            if group.exporter_changes:
                current_declared = load_declared_exporters(group.path)
                candidate_exporters = _apply_changes_to_model(
                    current_declared, group.exporter_changes
                )
                errors = validate_exporters(candidate_exporters)
                if errors:
                    log.error(
                        "apply_pending_changes: validation exportateurs echouee "
                        "(file=%s), aucune ecriture: erreurs=%s",
                        group.file_key,
                        errors,
                    )
                    return ApplyResult(
                        success=False,
                        message=(
                            f"validation des changements en attente echouee sur {group.file_key}: "
                            + "; ".join(errors)
                        ),
                        steps_completed=steps,
                        errors=errors,
                    )

            for write in group.section_writes.values():
                errors = write.validator(write.value)
                if errors:
                    log.error(
                        "apply_pending_changes: validation section echouee "
                        "(file=%s cle=%s), aucune ecriture: erreurs=%s",
                        group.file_key,
                        write.dotted_key,
                        errors,
                    )
                    return ApplyResult(
                        success=False,
                        message=(
                            f"validation des changements en attente echouee sur "
                            f"{group.file_key}#{write.dotted_key}: " + "; ".join(errors)
                        ),
                        steps_completed=steps,
                        errors=errors,
                    )
            steps.append(f"validate:{group.file_key}")

        steps.append("validate_all_files")

        # Passe 2 — toutes les validations sont passées : on écrit pour de
        # vrai. `current_hash` est réévalué après CHAQUE écriture réussie sur
        # un même fichier (write_section/write_declared_exporters ré-écrivent
        # le fichier -> le hash du verrou optimiste change à chaque écriture).
        for group in groups.values():
            current_hash = compute_file_hash(group.path)

            if group.exporter_changes:
                current_declared = load_declared_exporters(group.path)
                candidate_exporters = _apply_changes_to_model(
                    current_declared, group.exporter_changes
                )
                write_declared_exporters(
                    group.path, candidate_exporters, expected_hash=current_hash
                )
                written_paths.append(group.path)
                steps.append(f"write_declared_exporters:{group.file_key}")
                current_hash = compute_file_hash(group.path)

            for write in group.section_writes.values():
                write_section(group.path, write.dotted_key, write.value, expected_hash=current_hash)
                if group.path not in written_paths:
                    written_paths.append(group.path)
                steps.append(f"write_section:{group.file_key}:{write.dotted_key}")
                current_hash = compute_file_hash(group.path)
    except (ConcurrentModificationError, SectionConcurrentModificationError) as exc:
        log.error("apply_pending_changes: verrou optimiste echoue: %s", exc)
        return ApplyResult(
            success=False,
            message=f"un fichier a ete modifie entre-temps: {exc}",
            steps_completed=steps,
            errors=[str(exc)],
        )
    except (ValueError, OSError) as exc:
        log.error("apply_pending_changes: echec avant/pendant l'ecriture: %s", exc, exc_info=True)
        if written_paths:
            _rollback_all(written_paths)
            steps.append("rollback")
        return ApplyResult(
            success=False,
            message=f"echec lors de l'ecriture de la configuration: {exc}",
            steps_completed=steps,
            rolled_back=bool(written_paths),
            errors=[str(exc)],
        )

    restart_services = _restart_services_for(pending)
    if restart_services:
        restart_outcome = restart_fn(restart_services)
        steps.append("restart_fn")
    else:
        restart_outcome = None
        steps.append("no_restart_needed")

    if restart_outcome is None or restart_outcome.success:
        for change in pending:
            discard_change(conn, change.id)
        steps.append("clear_pending_changes")
        log.info(
            "apply_pending_changes: succes complet, %d changement(s) applique(s)", len(pending)
        )
        return ApplyResult(
            success=True,
            message=f"{len(pending)} changement(s) applique(s) avec succes",
            steps_completed=steps,
            rolled_back=False,
        )

    log.error(
        "apply_pending_changes: restart echoue, rollback en cours: %s", restart_outcome.message
    )
    rollback_error = _rollback_all(written_paths)
    steps.append("rollback")
    restart_after_rollback = restart_fn(restart_services)
    steps.append("restart_after_rollback")

    if rollback_error:
        message = (
            f"restart echoue ({restart_outcome.message}) ET rollback en erreur: {rollback_error}. "
            "INTERVENTION MANUELLE REQUISE."
        )
    else:
        post_rollback_status = (
            "ok" if restart_after_rollback.success else f"ECHEC — {restart_after_rollback.message}"
        )
        message = (
            f"restart echoue ({restart_outcome.message}) : rollback effectue, "
            f"fichier(s) restaure(s). Redemarrage post-rollback: {post_rollback_status}"
        )

    log.error("apply_pending_changes: resultat final: %s", message)
    return ApplyResult(
        success=False,
        message=message,
        steps_completed=steps,
        rolled_back=rollback_error is None,
        errors=[restart_outcome.message] + ([rollback_error] if rollback_error else []),
    )


def _rollback_all(paths: list[str]) -> str | None:
    """Restaure le backup le plus récent de CHAQUE fichier de `paths`.

    Retourne un message d'erreur agrégé si UNE SEULE restauration échoue,
    `None` si tout a été restauré. Les fichiers de backup sont conservés
    (copie, pas déplacement) pour garder une trace de l'incident.
    """
    errors: list[str] = []
    for path in paths:
        error = _rollback(path)
        if error:
            errors.append(error)
    if errors:
        return "; ".join(errors)
    return None


def _rollback(yaml_path: str) -> str | None:
    """Restaure le backup le plus récent de `yaml_path`. Retourne un message
    d'erreur si le rollback échoue, `None` sinon. Le fichier de backup est
    conservé (copie, pas déplacement) pour garder une trace de l'incident."""
    path = Path(yaml_path)
    backups = sorted(path.parent.glob(f"{path.name}.bak-*"))
    if not backups:
        log.error("rollback impossible: aucun backup trouve pour path=%s", yaml_path)
        return f"aucun backup disponible pour restaurer {path.name}"

    latest_backup = backups[-1]
    try:
        shutil.copy2(latest_backup, path)
    except OSError as exc:
        log.error("rollback: echec de restauration du backup: path=%s erreur=%s", yaml_path, exc)
        return f"echec de restauration du backup {latest_backup}: {exc}"

    log.info("rollback: %s restaure depuis %s", yaml_path, latest_backup)
    return None
