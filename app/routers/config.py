"""Router LOT C — routes d'écriture de la configuration Akvorado.

C'est le lot qui rend l'écriture faisable À LA SOURIS : mise en file
d'attente des changements (ajout d'exportateur, ajout/modification
d'interface, correction d'ifIndex périmé), consultation de la file, retrait,
et application groupée (redémarrage réel via l'agent, rollback automatique
en cas d'échec).

Toute la logique d'orchestration (validation, verrou optimiste, backup,
écriture atomique, rollback) vit dans `app.services.config_writer` et
`app.clients.akvorado_yaml` — ce module ne fait que traduire des requêtes
HTTP (formulaires HTML `application/x-www-form-urlencoded` ou JSON) en
appels à cette couche, et rendre des fragments HTMX lisibles.

Dépendances (à câbler dans `app/main.py`, LOT 0) :
  - `get_db_connection` : connexion SQLite réelle (déjà utilisée par
    `app/routers/views.py`, même pattern).
  - `get_akvorado_config_path` : chemin de `outlet.yaml`
    (`settings.akvorado_config_path`).
  - `get_restart_fn` : callable `() -> RestartOutcome` qui appelle
    `app.clients.restart.restart_akvorado([...])` de façon synchrone pour le
    contrat `RestartFn` attendu par `apply_pending_changes` (celui-ci est
    synchrone, `restart_akvorado` est une coroutine — le câblage LOT 0 doit
    fournir un wrapper, ex. `lambda: asyncio.run(restart_akvorado([...]))`
    ou équivalent basé sur l'event loop de l'app).
"""

from __future__ import annotations

import ipaddress
import logging
import sqlite3
from html import escape
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.clients.akvorado_yaml import ConcurrentModificationError, load_declared_exporters
from app.clients.restart import AkvoradoStatus, fetch_akvorado_status
from app.config import settings as default_settings
from app.models import Boundary
from app.services.config_writer import (
    ApplyResult,
    PendingChange,
    RestartFn,
    apply_pending_changes,
    build_ifindex_fix,
    discard_change,
    list_pending_changes,
    stage_change,
)
from app.templating import build_templates

log = logging.getLogger(__name__)

router = APIRouter(tags=["config"])

_MAX_NAME_LENGTH = 128
_VALID_BOUNDARIES = {b.value for b in Boundary}
_DEFAULT_AUTHOR = "ui"


# ---------------------------------------------------------------------------
# Dépendances — placeholders câblés par app/main.py (LOT 0)
# ---------------------------------------------------------------------------


def get_db_connection() -> sqlite3.Connection:
    """Placeholder — LOT 0 fournit la vraie connexion via app/db.py.

    Jamais appelée telle quelle en test (toujours surchargée par
    `app.dependency_overrides`), comme dans `app/routers/views.py`.
    """
    raise RuntimeError(
        "get_db_connection non câblée : app/main.py (LOT 0) doit surcharger "
        "cette dépendance avec la connexion SQLite réelle."
    )


def get_akvorado_config_path() -> str:
    """Placeholder — LOT 0 câble `settings.akvorado_config_path`."""
    raise RuntimeError(
        "get_akvorado_config_path non câblée : app/main.py (LOT 0) doit "
        "surcharger cette dépendance avec settings.akvorado_config_path."
    )


def get_restart_fn() -> RestartFn:
    """Placeholder — LOT 0 câble un wrapper synchrone autour de
    `app.clients.restart.restart_akvorado(services)`.
    """
    raise RuntimeError(
        "get_restart_fn non câblée : app/main.py (LOT 0) doit surcharger "
        "cette dépendance avec un appelant synchrone de restart_akvorado()."
    )


def get_templates() -> Jinja2Templates:
    return build_templates()


def get_config_files(path: str = Depends(get_akvorado_config_path)) -> dict[str, str]:
    """Map `nom logique -> chemin` des 4 fichiers de configuration Akvorado.

    DÉFAUT MESURÉ (2026-08-07), et il rendait TOUTE la partie management
    inopérante à l'application : le routeur passait à `apply_pending_changes`
    le seul chemin d'`outlet.yaml`, ce que la fonction interprète — c'est son
    raccourci historique — comme `{"outlet.yaml": <path>}`.

    Conséquence : un changement visant une section d'un AUTRE fichier n'avait
    aucun fichier cible. Constaté en activant la colonne QoS depuis l'écran :
    changement mis en file, bouton « Appliquer » cliqué, rapport rendu — et
    `akvorado.yaml` INCHANGÉ, hash identique à la baseline, orchestrateur
    jamais redémarré. Aucune erreur nulle part.

    Neuf sections sur onze vivent hors d'`outlet.yaml` : `asns` et
    `kafka_retention` dans `akvorado.yaml`, `saved_filters`,
    `visualize_defaults` et `homepage_widgets` dans `console.yaml`,
    `flow_inputs` dans `inlet.yaml`, `schema_columns` dans `akvorado.yaml`.
    Toutes étaient concernées.

    Les quatre fichiers sont VOISINS sur disque — le catalogue les résout déjà
    ainsi (`Path(config_dir) / section.file`). On dérive donc la map du chemin
    d'`outlet.yaml` plutôt que d'ajouter quatre dépendances à câbler, dont
    l'oubli d'une seule reproduirait ce défaut.
    """
    repertoire = Path(path).parent
    return {
        "outlet.yaml": path,
        "akvorado.yaml": str(repertoire / "akvorado.yaml"),
        "console.yaml": str(repertoire / "console.yaml"),
        "inlet.yaml": str(repertoire / "inlet.yaml"),
    }


DbConnection = Annotated[sqlite3.Connection, Depends(get_db_connection)]
ConfigPath = Annotated[str, Depends(get_akvorado_config_path)]
ConfigFiles = Annotated[dict[str, str], Depends(get_config_files)]
RestartCallable = Annotated[RestartFn, Depends(get_restart_fn)]
Templates = Annotated[Jinja2Templates, Depends(get_templates)]


# ---------------------------------------------------------------------------
# Validation des formulaires — messages lisibles, jamais de 500
# ---------------------------------------------------------------------------


def _validate_cidr(cidr: str) -> str | None:
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return f"CIDR invalide : {cidr!r}"
    return None


def _validate_name(name: str) -> str | None:
    if not name or not name.strip():
        return "le nom ne peut pas être vide"
    if len(name) > _MAX_NAME_LENGTH:
        return f"nom trop long ({len(name)} caractères, max {_MAX_NAME_LENGTH})"
    return None


def _validate_if_index(if_index: int) -> str | None:
    if if_index <= 0:
        return f"ifIndex invalide ({if_index}) : doit être strictement positif"
    return None


def _validate_speed(speed: int) -> str | None:
    if speed <= 0:
        return f"vitesse invalide ({speed}) : doit être strictement positive"
    return None


def _validate_boundary(boundary: str) -> str | None:
    if boundary not in _VALID_BOUNDARIES:
        return (
            f"boundary invalide ({boundary!r}) : attendu l'une de "
            f"{', '.join(sorted(_VALID_BOUNDARIES))}"
        )
    return None


def _error_response(errors: list[str]) -> HTMLResponse:
    items = "".join(f"<li>{escape(err)}</li>" for err in errors)
    return HTMLResponse(
        f'<div class="notice notice-crit"><strong>Changement refusé</strong><ul>{items}</ul></div>',
        status_code=422,
    )


# ---------------------------------------------------------------------------
# Consultation
# ---------------------------------------------------------------------------


def _pending_change_to_dict(change: PendingChange) -> dict[str, Any]:
    return {
        "id": change.id,
        "change_type": change.change_type,
        "payload": change.payload,
        "author": change.author,
        "created_at": change.created_at,
    }


_CHANGE_TYPE_LABELS: dict[str, str] = {
    "add_exporter": "Ajout d'exportateur",
    "update_exporter": "Modification d'exportateur",
    "delete_exporter": "Suppression d'exportateur",
    "fix_ifindex": "Correction d'ifIndex",
}


def describe_pending_change(change: PendingChange) -> str:
    """Phrase en clair décrivant un changement en attente, pour l'UI."""
    label = _CHANGE_TYPE_LABELS.get(change.change_type, change.change_type)
    payload = change.payload
    if change.change_type == "add_exporter":
        return f"{label} : {payload.get('cidr', '?')} ({payload.get('name', '?')})"
    if change.change_type == "update_exporter":
        return f"{label} : {payload.get('cidr', '?')} ({payload.get('name', '?')})"
    if change.change_type == "delete_exporter":
        return f"{label} : {payload.get('cidr', '?')}"
    if change.change_type == "fix_ifindex":
        return (
            f"{label} : {payload.get('cidr', '?')} / {payload.get('interface_name', '?')} "
            f"({payload.get('old_if_index', '?')} → {payload.get('new_if_index', '?')})"
        )
    # Type de changement inconnu : on affiche au moins son libelle plutot que rien.
    return label


@router.get("/api/config/pending")
def get_pending_changes(conn: DbConnection) -> JSONResponse:
    """Retourne la file d'attente au format `{"items": [...], "total": N}`."""
    pending = list_pending_changes(conn)
    return JSONResponse(
        content={
            "items": [_pending_change_to_dict(change) for change in pending],
            "total": len(pending),
        }
    )


@router.get("/config")
def get_config_page(
    request: Request,
    conn: DbConnection,
    config_path: ConfigPath,
    templates: Templates,
) -> HTMLResponse:
    """Rend l'écran de gestion : file d'attente + formulaires + état des containers.

    Si le backend (YAML/agent de restart) est indisponible, la page s'affiche
    quand même avec un message d'erreur clair — jamais une stacktrace.
    """
    error: str | None = None
    pending = list_pending_changes(conn)

    try:
        declared = load_declared_exporters(config_path)
    except Exception as exc:  # noqa: BLE001 - dégradation visible, jamais de 500 nu
        log.error("get_config_page: echec chargement outlet.yaml: %s", exc, exc_info=True)
        declared = []
        error = f"Impossible de charger la configuration actuelle : {exc}"

    return templates.TemplateResponse(
        request,
        "config.html",
        {
            "pending_changes": pending,
            "pending_total": len(pending),
            "describe_pending_change": describe_pending_change,
            "declared_exporters": declared,
            "boundary_choices": list(Boundary),
            "error": error,
            "active_page": "config",
            "akvorado_url": default_settings.akvorado_console_url,
        },
    )


@router.get("/config/status", response_class=HTMLResponse)
async def get_config_status_fragment() -> HTMLResponse:
    """Fragment HTMX : état des containers Akvorado, rafraîchi toutes les 30s."""
    try:
        status: AkvoradoStatus = await fetch_akvorado_status()
    except Exception as exc:  # noqa: BLE001 - dégradation visible, jamais de 500 nu
        log.error("get_config_status_fragment: echec recuperation statut: %s", exc)
        return HTMLResponse(
            '<p class="notice notice-warn">État des containers indisponible pour le moment '
            f"({escape(str(exc))}).</p>"
        )

    if not status.items:
        return HTMLResponse('<p class="empty">Aucun container Akvorado connu de l\'agent.</p>')

    rows = "".join(
        "<tr>"
        f"<td>{escape(entry.service)}</td>"
        f"<td>{escape(entry.name or '—')}</td>"
        f'<td><span class="badge badge-{"healthy" if entry.health == "healthy" else "rejected"}">'
        f"{escape(entry.health or 'inconnu')}</span></td>"
        f"<td>{escape(entry.status or '—')}</td>"
        "</tr>"
        for entry in status.items
    )
    return HTMLResponse(
        "<table><thead><tr><th>Service</th><th>Container</th><th>Santé</th>"
        f"<th>Statut</th></tr></thead><tbody>{rows}</tbody></table>"
    )


@router.get("/config/pending", response_class=HTMLResponse)
def get_pending_fragment(
    request: Request,
    conn: DbConnection,
    config_path: ConfigPath,
    templates: Templates,
) -> HTMLResponse:
    """Fragment HTMX : bandeau + liste des changements en attente, auto-refresh.

    Rend le template complet et laisse HTMX extraire `#pending-changes-panel`
    via `hx-select` (même pattern que `exporters.html`) : un seul template à
    maintenir, pas de duplication de markup entre page complète et fragment.
    """
    pending = list_pending_changes(conn)
    try:
        declared = load_declared_exporters(config_path)
    except Exception as exc:  # noqa: BLE001 - dégradation visible, jamais de 500 nu
        log.error("get_pending_fragment: echec chargement outlet.yaml: %s", exc, exc_info=True)
        declared = []

    return templates.TemplateResponse(
        request,
        "config.html",
        {
            "pending_changes": pending,
            "pending_total": len(pending),
            "describe_pending_change": describe_pending_change,
            "declared_exporters": declared,
            "boundary_choices": list(Boundary),
            "error": None,
            "active_page": "config",
            "akvorado_url": default_settings.akvorado_console_url,
        },
    )


# ---------------------------------------------------------------------------
# Mise en file d'attente
# ---------------------------------------------------------------------------


@router.post("/config/exporters")
def create_pending_exporter(
    conn: DbConnection,
    cidr: Annotated[str, Form()],
    name: Annotated[str, Form()],
) -> HTMLResponse:
    """Ajoute un exportateur à la file d'attente (formulaire HTML)."""
    errors = [err for err in (_validate_cidr(cidr), _validate_name(name)) if err is not None]
    if errors:
        log.error("create_pending_exporter: validation echouee: cidr=%s erreurs=%s", cidr, errors)
        return _error_response(errors)

    change_id = stage_change(
        conn,
        "add_exporter",
        {"cidr": cidr, "name": name.strip(), "if_indexes": {}, "default": None},
        _DEFAULT_AUTHOR,
    )
    log.info("create_pending_exporter: change_id=%d cidr=%s name=%s", change_id, cidr, name)
    return HTMLResponse(
        f'<li class="pending-item">Ajout en attente : {escape(cidr)} ({escape(name)})</li>',
        status_code=201,
    )


@router.post("/config/exporters/{cidr:path}/interfaces")
def create_pending_interface(
    conn: DbConnection,
    config_path: ConfigPath,
    cidr: str,
    if_index: Annotated[int, Form()],
    name: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    speed: Annotated[int, Form()] = 1000,
    boundary: Annotated[str, Form()] = Boundary.UNDEFINED.value,
) -> HTMLResponse:
    """Ajoute/modifie une interface d'un exportateur DÉJÀ déclaré.

    Repart de l'état déclaré actuel (`outlet.yaml`) pour construire le
    payload `update_exporter` complet : le modèle appliqué par
    `config_writer._apply_update_exporter` REMPLACE l'exportateur, il ne le
    fusionne pas — il faut donc lui fournir toutes les interfaces connues,
    pas seulement la nouvelle.
    """
    errors = [
        err
        for err in (
            _validate_if_index(if_index),
            _validate_name(name),
            _validate_speed(speed),
            _validate_boundary(boundary),
        )
        if err is not None
    ]
    if errors:
        log.error("create_pending_interface: validation echouee: cidr=%s erreurs=%s", cidr, errors)
        return _error_response(errors)

    declared = load_declared_exporters(config_path)
    matching = next((exporter for exporter in declared if exporter.cidr == cidr), None)
    if matching is None:
        log.error("create_pending_interface: exportateur inconnu: cidr=%s", cidr)
        return _error_response([f"exportateur inconnu (non déclaré) : {cidr!r}"])

    if_indexes_payload = {
        str(existing_index): {
            "name": spec.name,
            "description": spec.description,
            "speed": spec.speed,
            "boundary": spec.boundary.value,
        }
        for existing_index, spec in matching.if_indexes.items()
    }
    if_indexes_payload[str(if_index)] = {
        "name": name.strip(),
        "description": description,
        "speed": speed,
        "boundary": boundary,
    }
    default_payload = (
        {
            "name": matching.default.name,
            "description": matching.default.description,
            "speed": matching.default.speed,
            "boundary": matching.default.boundary.value,
        }
        if matching.default is not None
        else None
    )

    change_id = stage_change(
        conn,
        "update_exporter",
        {
            "cidr": cidr,
            "name": matching.name,
            "if_indexes": if_indexes_payload,
            "default": default_payload,
            "is_catchall": matching.is_catchall,
        },
        _DEFAULT_AUTHOR,
    )
    log.info(
        "create_pending_interface: change_id=%d cidr=%s if_index=%d", change_id, cidr, if_index
    )
    return HTMLResponse(
        f'<li class="pending-item">Interface en attente : {escape(cidr)} '
        f"ifIndex={if_index} ({escape(name)})</li>",
        status_code=201,
    )


@router.post("/config/exporters/{cidr:path}/fix-ifindex")
def create_pending_ifindex_fix(
    conn: DbConnection,
    cidr: str,
    interface_name: Annotated[str, Form()],
    old_if_index: Annotated[int, Form()],
    new_if_index: Annotated[int, Form()],
) -> HTMLResponse:
    """Le bouton en un clic qui corrige un ifIndex périmé (`build_ifindex_fix`).

    Contexte réel : l'ifIndex d'une interface TUN (`tailscale0`) change à
    chaque redémarrage du démon tailscale.
    """
    errors = [
        err
        for err in (
            _validate_name(interface_name),
            _validate_if_index(new_if_index),
        )
        if err is not None
    ]
    if old_if_index <= 0:
        errors.append(f"ancien ifIndex invalide ({old_if_index})")
    if errors:
        log.error(
            "create_pending_ifindex_fix: validation echouee: cidr=%s erreurs=%s", cidr, errors
        )
        return _error_response(errors)

    change = build_ifindex_fix(cidr, interface_name, old_if_index, new_if_index, _DEFAULT_AUTHOR)
    change_id = stage_change(conn, change.change_type, change.payload, change.author)
    log.info(
        "create_pending_ifindex_fix: change_id=%d cidr=%s interface=%s %d->%d",
        change_id,
        cidr,
        interface_name,
        old_if_index,
        new_if_index,
    )
    return HTMLResponse(
        f'<li class="pending-item">Correction ifIndex en attente : {escape(cidr)} '
        f"{escape(interface_name)} ({old_if_index} → {new_if_index})</li>",
        status_code=201,
    )


@router.delete("/config/pending/{change_id}")
def remove_pending_change(conn: DbConnection, change_id: int) -> HTMLResponse:
    """Retire un changement de la file d'attente sans l'appliquer."""
    discard_change(conn, change_id)
    log.info("remove_pending_change: change_id=%d", change_id)
    return HTMLResponse("")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------


def _render_apply_report(result: ApplyResult) -> HTMLResponse:
    status_class = "notice-ok" if result.success else "notice-crit"
    title = "Application réussie" if result.success else "Application échouée"

    steps_html = "".join(f"<li>{escape(step)}</li>" for step in result.steps_completed)
    errors_html = (
        "".join(f"<li>{escape(err)}</li>" for err in result.errors) if result.errors else ""
    )
    rollback_html = (
        '<p class="apply-report__rollback"><strong>Rollback effectué</strong> : '
        "outlet.yaml a été restauré à son état précédent.</p>"
        if result.rolled_back
        else ""
    )
    rollback_failed_html = (
        '<p class="apply-report__rollback notice-crit"><strong>Rollback NON effectué ou en '
        "échec</strong> : intervention manuelle requise sur outlet.yaml.</p>"
        if not result.success and not result.rolled_back and result.errors
        else ""
    )

    body = (
        f'<div class="apply-report {status_class}">'
        f"<strong>{escape(title)}</strong>"
        f"<p>{escape(result.message)}</p>"
        f"<h3>Étapes franchies</h3><ul>{steps_html}</ul>"
        f"{f'<h3>Erreurs</h3><ul>{errors_html}</ul>' if errors_html else ''}"
        f"{rollback_html}{rollback_failed_html}"
        "</div>"
    )
    return HTMLResponse(body, status_code=200)


@router.post("/config/apply", response_class=HTMLResponse)
def apply_config_changes(
    conn: DbConnection,
    config_files: ConfigFiles,
    restart_fn: RestartCallable,
) -> HTMLResponse:
    """Applique tous les changements en attente sur les 4 fichiers Akvorado.

    ⚠️ `config_files` et non `config_path` : passer un simple chemin active le
    raccourci historique de `apply_pending_changes`, qui le comprend comme
    `{"outlet.yaml": <path>}` SEUL. Un changement visant une section d'un autre
    fichier n'avait alors aucune cible — mesuré le 2026-08-07 en activant la
    colonne QoS depuis l'écran : rapport rendu, `akvorado.yaml` inchangé,
    orchestrateur jamais redémarré, aucune erreur. Neuf sections sur onze
    étaient concernées.

    Rend un rapport lisible : étapes franchies, succès/échec, rollback
    effectué ou non. Jamais de 500 nu — `ConcurrentModificationError` et
    les erreurs de validation/écriture sont déjà traduites en `ApplyResult`
    par `apply_pending_changes`, ce wrapper ne fait qu'attraper l'imprévu.
    """
    try:
        result = apply_pending_changes(conn, config_files, restart_fn)
    except ConcurrentModificationError as exc:
        log.error("apply_config_changes: verrou optimiste echoue: %s", exc)
        return HTMLResponse(
            '<div class="apply-report notice-crit"><strong>Application échouée</strong>'
            "<p>Quelqu'un a modifié le fichier de configuration entre-temps. "
            "Rechargez la page pour repartir d'un état à jour.</p></div>",
            status_code=200,
        )
    except Exception as exc:  # noqa: BLE001 - dégradation visible, jamais de 500 nu
        log.error("apply_config_changes: echec inattendu: %s", exc, exc_info=True)
        return HTMLResponse(
            '<div class="apply-report notice-crit"><strong>Application échouée</strong>'
            f"<p>Erreur inattendue : {escape(str(exc))}. L'incident est journalisé.</p></div>",
            status_code=200,
        )

    log.info("apply_config_changes: success=%s message=%s", result.success, result.message)
    return _render_apply_report(result)
