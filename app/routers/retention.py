"""Router Rétention (LOT 2) — page HTML + API JSON de pilotage du TTL ClickHouse.

Le client ClickHouse est injecté via la dépendance `get_clickhouse_client`
(FastAPI `Depends`), jamais importé directement depuis `app.clients.clickhouse`
(LOT 1) : cela découple les deux lots et permet un override propre dans les
tests (`app.dependency_overrides`).
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator

from app.services.purge import (
    PURGEABLE_TABLES,
    BackupPurgePreview,
    TablePurgePreview,
    execute_backup_purge,
    execute_table_purge,
    preview_backup_purge,
    preview_table_purge,
)
from app.services.retention import (
    ALLOWED_TABLES,
    MAX_TTL_DAYS,
    MIN_TTL_DAYS,
    ClickHouseQueryable,
    apply_ttl,
    build_ttl_alter_statement,
    compute_growth_rate,
    estimate_purge_impact,
    format_bytes,
    load_retention_status,
    project_disk_usage,
)
from app.templating import build_templates

log = logging.getLogger(__name__)

router = APIRouter()

templates = build_templates()

_PROJECTION_DAYS = 180
"""Horizon de la projection « occupation à 6 mois » affichée sur la page."""

_DEFAULT_DOCKER_LOG_MAX_SIZE = "10m"
_DEFAULT_DOCKER_LOG_MAX_FILE = "3"

# Clés connues de `retention_settings` (table SQLite posée par Lot B dans
# `app/db.py`) que ce routeur sait lire/écrire. Toute autre clé présente en
# base (réglage futur d'un autre lot) est ignorée par `GET /api/retention/settings`
# sans erreur — l'allowlist ne restreint que l'ÉCRITURE.
_SETTINGS_KEYS: tuple[str, ...] = (
    "docker_log_max_size_mb",
    "docker_log_max_file",
    "backup_keep_n",
    "audit_log_max_age_days",
    "pending_config_changes_max_age_days",
    "snmp_inventory_max_age_days",
    "purge_auto_enabled",
)


def get_clickhouse_client() -> ClickHouseQueryable:
    """Dépendance par défaut — DOIT être surchargée par l'app (LOT 0/deps.py).

    Ce module ne construit volontairement PAS de connexion ClickHouse réelle
    ici : le cycle de vie du client (connexion, pool, fermeture) appartient à
    `app/deps.py` [LOT 0], qui l'injectera via
    `app.include_router(retention.router, dependencies=...)` ou un
    `app.dependency_overrides[get_clickhouse_client]` au montage. Les tests de
    ce module font de même via `app.dependency_overrides`.

    Raises:
        RuntimeError: si appelée sans override — signale un défaut de câblage
            plutôt que d'échouer silencieusement ou de deviner l'API du LOT 1.
    """
    raise RuntimeError(
        "get_clickhouse_client n'est pas cablee : l'application doit fournir "
        "app.dependency_overrides[get_clickhouse_client] (voir app/deps.py, LOT 0) "
        "avec une instance compatible ClickHouseQueryable (ex: app.clients.clickhouse.connect())."
    )


def get_db_connection() -> sqlite3.Connection:
    """Placeholder — `app/main.py` (orchestrateur) doit surcharger cette
    dépendance avec la connexion SQLite réelle (`app/db.py::_open_db`),
    exactement comme le font déjà `app/routers/views.py`,
    `app/routers/config.py` et `app/routers/config_sections.py` (même nom de
    dépendance `get_db_connection`, mêmes conventions).

    Jamais appelée telle quelle en test (toujours surchargée par
    `app.dependency_overrides`).
    """
    raise RuntimeError(
        "get_db_connection non câblée : app/main.py doit surcharger cette "
        "dépendance avec la connexion SQLite réelle."
    )


def get_backup_directory() -> Path:
    """Placeholder — répertoire contenant les fichiers `.bak-*` d'`outlet.yaml`
    (celui produit par `app.clients.akvorado_yaml`, hors périmètre de ce lot).

    En prod, c'est le répertoire parent de `settings.akvorado_config_path`
    (même résolution que `app/routers/config_sections.py::get_config_dir`).
    """
    raise RuntimeError(
        "get_backup_directory non câblée : app/main.py doit surcharger cette "
        "dépendance avec le répertoire contenant les fichiers outlet.yaml.bak-*."
    )


DbConnection = Annotated[sqlite3.Connection, Depends(get_db_connection)]
BackupDirectory = Annotated[Path, Depends(get_backup_directory)]


def _record_audit(conn: sqlite3.Connection, action: str, detail: str) -> None:
    """Insère une ligne dans `audit_log` — même schéma que `app/db.py::SCHEMA`.

    Échec d'écriture d'audit journalisé mais jamais fatal pour la requête
    métier qui l'a déclenché : un audit manquant est un défaut de traçabilité,
    pas une raison de faire échouer une opération déjà réussie côté
    ClickHouse/SQLite.
    """
    try:
        conn.execute(
            "INSERT INTO audit_log (actor, action, detail) VALUES (?, ?, ?)",
            ("ui", action, detail),
        )
        conn.commit()
    except sqlite3.Error:
        log.error("retention: echec ecriture audit_log", exc_info=True, extra={"action": action})


class RetentionPreviewRequest(BaseModel):
    """Entrée validée pour la prévisualisation d'un changement de TTL."""

    table: str
    ttl_days: int = Field(ge=MIN_TTL_DAYS, le=MAX_TTL_DAYS)

    @field_validator("table")
    @classmethod
    def table_must_be_allowed(cls, value: str) -> str:
        if value not in ALLOWED_TABLES:
            raise ValueError(f"table hors allowlist: {value!r}")
        return value


def _error_response(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": message})


def _projection_rows(items: list[Any]) -> list[dict[str, Any]]:
    """Projection à `_PROJECTION_DAYS` jours par table, dérivée de la même
    croissance quotidienne que `/api/retention/preview` (`compute_growth_rate`
    + `project_disk_usage`) — jamais une constante recopiée dans le template.
    """
    rows: list[dict[str, Any]] = []
    for item in items:
        growth_per_day = compute_growth_rate(item.bytes_on_disk, item.ttl_seconds)
        projected = (
            project_disk_usage(item.table, _PROJECTION_DAYS, growth_per_day)
            if growth_per_day is not None
            else None
        )
        rows.append(
            {
                "table": item.table,
                "current_bytes": item.bytes_on_disk,
                "projected_bytes": projected,
            }
        )
    return rows


def _read_settings(conn: sqlite3.Connection) -> dict[str, str]:
    """Lit tous les réglages connus de `retention_settings`, sous forme `{clé: valeur}`.

    Table posée par Lot B (`app/db.py`) — une clé absente en base signifie
    simplement qu'elle n'a jamais été modifiée, pas une erreur.
    """
    try:
        rows = conn.execute("SELECT setting_key, setting_value FROM retention_settings").fetchall()
    except sqlite3.Error:
        log.error("retention: echec lecture retention_settings", exc_info=True)
        return {}
    return {row[0]: row[1] for row in rows}


@router.get("/retention", response_class=HTMLResponse)
def get_retention(
    request: Request,
    client: Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)],
    conn: DbConnection,
) -> Any:
    """Page HTML de pilotage de la rétention ClickHouse."""
    try:
        items = load_retention_status(client)
    except Exception:
        log.error("retention: echec chargement statut pour la page HTML", exc_info=True)
        items = []

    disk_total_bytes = 125 * 1024**3
    disk_used_bytes = sum(item.bytes_on_disk for item in items) if items else int(3.5 * 1024**3)

    settings_map = _read_settings(conn)

    return templates.TemplateResponse(
        request,
        "retention.html",
        {
            "items": items,
            "disk_used_bytes": disk_used_bytes,
            "disk_total_bytes": disk_total_bytes,
            "format_bytes": format_bytes,
            "projection_days": _PROJECTION_DAYS,
            "projection_rows": _projection_rows(items),
            "settings": settings_map,
            "docker_log_max_size": settings_map.get(
                "docker_log_max_size_mb", _DEFAULT_DOCKER_LOG_MAX_SIZE
            ),
            "docker_log_max_file": settings_map.get(
                "docker_log_max_file", _DEFAULT_DOCKER_LOG_MAX_FILE
            ),
            "purgeable_tables": sorted(PURGEABLE_TABLES),
        },
    )


@router.get("/api/retention")
def list_retention(
    client: Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)],
) -> JSONResponse:
    """Retourne l'état de rétention de toutes les tables suivies, en JSON."""
    try:
        items = load_retention_status(client)
    except Exception as exc:
        log.error(
            "retention: echec lecture system.tables/system.parts",
            exc_info=True,
        )
        return _error_response(
            502, f"Erreur ClickHouse lors de la lecture de l'etat de retention: {exc}"
        )

    payload = {
        "items": [item.model_dump(mode="json") for item in items],
        "total": len(items),
    }
    return JSONResponse(content=payload)


@router.post("/api/retention/preview", response_model=None)
def preview_retention(
    request: Request,
    body: RetentionPreviewRequest,
    client: Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)],
) -> JSONResponse | HTMLResponse:
    """Prévisualise un changement de TTL — NE MODIFIE RIEN.

    Malgré la méthode POST, cet endpoint est un CALCUL PUR côté ClickHouse :
    il lit l'état courant (lecture seule), construit l'ordre SQL
    correspondant pour affichage, projette l'occupation disque au nouveau
    TTL et estime l'impact d'une éventuelle purge. Aucun ALTER n'est exécuté
    (`build_ttl_alter_statement` ne fait que retourner une chaîne).

    DÉFAUT MESURÉ (2026-08-09) : cette route est appelée par un formulaire
    HTMX (`retention.html`, section « Prévisualiser puis appliquer un
    changement de TTL ») qui insérait le JSON brut dans `#preview-result`.
    Même double format HTMX/API que `preview_purge` ci-dessous (voir sa
    docstring) : un appel HTMX (header `HX-Request`) reçoit un fragment HTML
    lisible, un appel API direct reçoit le JSON inchangé.
    """
    try:
        items = load_retention_status(client)
    except Exception as exc:
        log.error(
            "retention: echec lecture statut pour preview",
            exc_info=True,
            extra={"table": body.table, "ttl_days": body.ttl_days},
        )
        return _error_response(
            502, f"Erreur ClickHouse lors de la lecture de l'etat de retention: {exc}"
        )

    current = next((item for item in items if item.table == body.table), None)
    bytes_on_disk = current.bytes_on_disk if current else 0
    current_ttl_seconds = current.ttl_seconds if current else None
    current_ttl_days = current.ttl_days if current else None

    growth_per_day = compute_growth_rate(bytes_on_disk, current_ttl_seconds) or 0.0

    try:
        sql_statement = build_ttl_alter_statement(body.table, body.ttl_days)
    except ValueError as exc:
        log.error(
            "retention: table/ttl_days refuses par la garde securite",
            extra={"table": body.table, "ttl_days": body.ttl_days},
        )
        return _error_response(400, str(exc))

    projected_bytes = project_disk_usage(body.table, body.ttl_days, growth_per_day)
    purged_bytes = estimate_purge_impact(
        current_ttl_days=current_ttl_days,
        new_ttl_days=body.ttl_days,
        bytes_on_disk=bytes_on_disk,
        growth_per_day=growth_per_day,
    )

    payload = {
        "status": "ok",
        "table": body.table,
        "ttl_days": body.ttl_days,
        "current_ttl_days": current_ttl_days,
        "current_bytes_on_disk": bytes_on_disk,
        "growth_per_day_bytes": growth_per_day,
        "sql_statement": sql_statement,
        "projected_bytes": projected_bytes,
        "purged_bytes": purged_bytes,
        "executed": False,
        "note": "Previsualisation uniquement — aucun ordre SQL n'est execute en v1.",
    }

    if request.headers.get("HX-Request") == "true":
        return templates.TemplateResponse(
            request, "_retention_preview_fragment.html", {"preview": payload}
        )

    return JSONResponse(content=payload)


# ---------------------------------------------------------------------------
# Application réelle du TTL — v2, geste en DEUX temps (preview déjà ci-dessus)
# ---------------------------------------------------------------------------


class RetentionApplyRequest(BaseModel):
    """Entrée validée pour l'application réelle d'un changement de TTL.

    Même validation que `RetentionPreviewRequest` (allowlist + bornes) — la
    garde sécu vraiment critique reste néanmoins celle d'`apply_ttl`
    (`app.services.retention`), exécutée AVANT tout accès ClickHouse : ce
    Pydantic-ci ne fait que refuser tôt, au niveau HTTP, avec un message clair.
    """

    table: str
    ttl_days: int = Field(ge=MIN_TTL_DAYS, le=MAX_TTL_DAYS)

    @field_validator("table")
    @classmethod
    def table_must_be_allowed(cls, value: str) -> str:
        if value not in ALLOWED_TABLES:
            raise ValueError(f"table hors allowlist: {value!r}")
        return value


@router.post("/api/retention/apply", response_model=None)
def apply_retention(
    request: Request,
    body: RetentionApplyRequest,
    client: Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)],
    conn: DbConnection,
) -> JSONResponse | HTMLResponse:
    """Exécute réellement l'ordre `ALTER TABLE ... MODIFY TTL ...` — DÉTRUIT

    potentiellement des données si le TTL baisse. Le geste en deux temps
    (preview obligatoire avant apply) est appliqué côté template
    (`retention.html`), pas ici : cet endpoint fait confiance à l'appelant
    HTTP, comme `apply_ttl` fait confiance à ses propres gardes internes
    (allowlist + bornes, revalidées AVANT tout accès ClickHouse).

    Même double format HTMX/API que `preview_retention` — défaut mesuré
    identique (2026-08-09) : le formulaire « Appliquer le TTL » insérait le
    JSON brut dans `#apply-result`.
    """
    try:
        result = apply_ttl(client, body.table, body.ttl_days)
    except ValueError as exc:
        log.error(
            "retention: apply refuse par la garde securite",
            extra={"table": body.table, "ttl_days": body.ttl_days},
        )
        return _error_response(400, str(exc))
    except Exception as exc:
        log.error(
            "retention: echec execution ALTER TTL",
            exc_info=True,
            extra={"table": body.table, "ttl_days": body.ttl_days},
        )
        return _error_response(502, f"Erreur ClickHouse lors de l'application du TTL: {exc}")

    _record_audit(
        conn,
        "retention_apply_ttl",
        f"table={result.table} ttl_days={result.ttl_days} sql={result.sql_statement}",
    )

    payload = {
        "status": "ok",
        "table": result.table,
        "ttl_days": result.ttl_days,
        "applied_at": result.applied_at.isoformat(),
        "sql_statement": result.sql_statement,
    }

    if request.headers.get("HX-Request") == "true":
        return templates.TemplateResponse(
            request, "_retention_apply_fragment.html", {"result": payload}
        )

    return JSONResponse(content=payload)


# ---------------------------------------------------------------------------
# Réglages de rétention/purge — table SQLite `retention_settings` (Lot B)
# ---------------------------------------------------------------------------


@router.get("/api/retention/settings")
def get_retention_settings(conn: DbConnection) -> JSONResponse:
    """Retourne tous les réglages connus de `retention_settings`, en JSON."""
    return JSONResponse(content={"items": _read_settings(conn)})


class RetentionSettingsRequest(BaseModel):
    """Entrée d'écriture des réglages — tous les champs sont optionnels,

    seuls les champs fournis (non `None`) sont mis à jour (upsert). Un champ
    absent du payload JSON ou explicitement `null` n'écrase rien.
    """

    docker_log_max_size_mb: int | None = None
    docker_log_max_file: int | None = None
    backup_keep_n: int | None = None
    audit_log_max_age_days: int | None = None
    pending_config_changes_max_age_days: int | None = None
    snmp_inventory_max_age_days: int | None = None
    purge_auto_enabled: bool | None = None


def _upsert_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        """
        INSERT INTO retention_settings (setting_key, setting_value, modified_by, modified_at)
        VALUES (?, ?, 'ui', datetime('now'))
        ON CONFLICT(setting_key) DO UPDATE SET
            setting_value = excluded.setting_value,
            modified_by = excluded.modified_by,
            modified_at = excluded.modified_at
        """,
        (key, value),
    )


@router.post("/api/retention/settings", response_model=None)
def update_retention_settings(
    request: Request,
    body: RetentionSettingsRequest,
    conn: DbConnection,
) -> JSONResponse | HTMLResponse:
    """Met à jour un ou plusieurs réglages — upsert, champs fournis uniquement.

    Même double format HTMX/API que `preview_retention` — défaut mesuré
    identique (2026-08-09) : le formulaire « Logs Docker » insérait le JSON
    brut dans `#docker-logs-result`.
    """
    updated: dict[str, str] = {}
    for field_name in RetentionSettingsRequest.model_fields:
        value = getattr(body, field_name)
        if value is None:
            continue
        text_value = "true" if value is True else "false" if value is False else str(value)
        updated[field_name] = text_value

    if not updated:
        return _error_response(400, "aucun réglage fourni")

    try:
        for key, text_value in updated.items():
            _upsert_setting(conn, key, text_value)
        conn.commit()
    except sqlite3.Error as exc:
        log.error(
            "retention: echec ecriture retention_settings",
            exc_info=True,
            extra={"keys": list(updated)},
        )
        return _error_response(502, f"Erreur SQLite lors de l'ecriture des reglages: {exc}")

    _record_audit(conn, "retention_update_settings", f"champs={sorted(updated)}")

    if request.headers.get("HX-Request") == "true":
        return templates.TemplateResponse(
            request, "_retention_settings_fragment.html", {"updated": updated}
        )

    return JSONResponse(content={"status": "ok", "updated": updated})


# ---------------------------------------------------------------------------
# Purges (backups .bak-* et tables SQLite internes) — preview puis execute
# ---------------------------------------------------------------------------

_PurgeTarget = Literal["backups", "audit_log", "pending_config_changes", "snmp_inventory"]


class PurgePreviewRequest(BaseModel):
    """Entrée d'une prévisualisation de purge — NE SUPPRIME RIEN.

    `target == "backups"` route vers `preview_backup_purge` (nécessite
    `keep_n`) ; toute autre valeur route vers `preview_table_purge` (table =
    `target`, nécessite `max_age_days`, refusé si `target` hors
    `PURGEABLE_TABLES` — laissé remonter en 400 depuis `app.services.purge`).
    """

    target: _PurgeTarget
    keep_n: int | None = None
    max_age_days: int | None = None


def _run_preview(
    body: PurgePreviewRequest, backup_directory: Path, conn: sqlite3.Connection
) -> BackupPurgePreview | TablePurgePreview:
    if body.target == "backups":
        if body.keep_n is None:
            raise ValueError("keep_n est requis pour une purge de backups")
        return preview_backup_purge(backup_directory, body.keep_n)

    if body.max_age_days is None:
        raise ValueError("max_age_days est requis pour une purge de table")
    return preview_table_purge(conn, body.target, body.max_age_days)


@router.post("/api/retention/purge/preview", response_model=None)
def preview_purge(
    request: Request,
    body: PurgePreviewRequest,
    conn: DbConnection,
    backup_directory: BackupDirectory,
) -> JSONResponse | HTMLResponse:
    """Prévisualise une purge (backups ou table SQLite interne) — NE SUPPRIME RIEN.

    Deux formats de réponse selon l'appelant :
    - Appel HTMX (header `HX-Request`, posé automatiquement par htmx sur
      chaque requête déclenchée par un `hx-post`) : retourne un FRAGMENT HTML
      qui affiche le résultat ET un bouton "Confirmer la purge" — ce bouton
      embarque le JSON du preview dans un champ caché, c'est la SEULE façon
      pour `/purge/execute` de recevoir "exactement ce que l'utilisateur a
      vu" sans JavaScript custom (CSP `script-src 'self'` sans
      `unsafe-eval` interdit `hx-vals="js:..."`). Défaut constaté à l'écran
      (2026-08-08) : sans ce fragment, l'écran affichait le preview mais
      n'offrait AUCUN moyen de confirmer la purge — la fonctionnalité était
      invisible malgré un backend fonctionnel et testé.
    - Appel API direct (pas de header `HX-Request`, ex. script/curl/test) :
      retourne le JSON brut, comme avant — l'API reste utilisable
      programmatiquement.
    """
    try:
        preview = _run_preview(body, backup_directory, conn)
    except ValueError as exc:
        log.error(
            "retention: purge preview refusee",
            extra={"target": body.target},
        )
        return _error_response(400, str(exc))
    except Exception as exc:
        log.error(
            "retention: echec calcul purge preview", exc_info=True, extra={"target": body.target}
        )
        return _error_response(502, f"Erreur lors du calcul de la prévisualisation: {exc}")

    preview_dump = preview.model_dump(mode="json")

    if request.headers.get("HX-Request") == "true":
        return templates.TemplateResponse(
            request,
            "_purge_preview_fragment.html",
            {
                "target": body.target,
                "preview": preview_dump,
                "preview_json": json.dumps(preview_dump),
            },
        )

    payload = {"status": "ok", "target": body.target, "preview": preview_dump}
    return JSONResponse(content=payload)


class PurgeExecuteRequest(BaseModel):
    """Entrée d'exécution d'une purge — reçoit le PREVIEW COMPLET calculé côté

    client par `/purge/preview`, jamais de nouveaux paramètres bruts.

    CHOIX ANTI-TOCTOU (documenté à la demande du brief) : plutôt que de
    re-scanner le répertoire/la table avec `target`/`keep_n`/`max_age_days` au
    moment de l'exécution — ce qui pourrait diverger de ce que l'utilisateur a
    vu et confirmé si le disque ou la table ont changé entre les deux appels —
    ce endpoint repasse tel quel l'objet `preview` reçu à
    `execute_backup_purge`/`execute_table_purge`. Ce que l'utilisateur a
    confirmé à l'écran est exactement ce qui part, jamais un nouvel état.
    """

    target: _PurgeTarget
    preview: dict[str, Any]

    @field_validator("preview", mode="before")
    @classmethod
    def preview_may_be_json_string(cls, value: Any) -> Any:
        """Accepte `preview` en chaîne JSON, pas seulement en objet.

        Le formulaire HTML de confirmation (`_purge_preview_fragment.html`)
        transporte le preview dans un `<input type="hidden">` : sérialisé par
        l'extension `json-enc`, TOUT le formulaire devient un objet JSON dont
        les valeurs sont les chaînes des champs — `preview` arrive donc comme
        une chaîne contenant du JSON, pas comme un objet imbriqué. Un appel
        API direct (script/test) continue de passer un objet, accepté tel
        quel (`isinstance(value, str)` ne matche pas).
        """
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError as exc:
                raise ValueError(f"preview n'est pas un JSON valide: {exc}") from exc
        return value


@router.post("/api/retention/purge/execute", response_model=None)
def execute_purge(
    request: Request,
    body: PurgeExecuteRequest,
    conn: DbConnection,
) -> JSONResponse | HTMLResponse:
    """Exécute réellement la purge décrite par `preview` — DÉTRUIT des données.

    DÉFAUT MESURÉ (2026-08-09) : le formulaire de confirmation
    (`_purge_preview_fragment.html`) cible `hx-target="this"` — avant ce
    correctif, le bouton « Confirmer la purge » se remplaçait par le JSON
    brut de la réponse au lieu d'un résultat lisible. Même double format
    HTMX/API que `preview_purge` (voir sa docstring).
    """
    try:
        if body.target == "backups":
            backup_preview = BackupPurgePreview.model_validate(body.preview)
            backup_result = execute_backup_purge(backup_preview)
            detail = (
                f"target=backups keep_n={backup_preview.keep_n} "
                f"supprimes={backup_result.deleted_count} octets={backup_result.deleted_bytes} "
                f"erreurs={len(backup_result.errors)}"
            )
            _record_audit(conn, "retention_purge_execute", detail)
            payload: dict[str, Any] = {
                "status": "ok",
                "target": body.target,
                "deleted_count": backup_result.deleted_count,
                "deleted_bytes": backup_result.deleted_bytes,
                "errors": backup_result.errors,
            }
        else:
            table_preview = TablePurgePreview.model_validate(body.preview)
            if table_preview.table != body.target:
                return _error_response(
                    400,
                    f"incohérence entre target={body.target!r} et "
                    f"preview.table={table_preview.table!r}",
                )
            table_result = execute_table_purge(conn, table_preview)
            detail = (
                f"target={body.target} max_age_days={table_preview.max_age_days} "
                f"supprimes={table_result.deleted_count}"
            )
            _record_audit(conn, "retention_purge_execute", detail)
            payload = {
                "status": "ok",
                "target": body.target,
                "deleted_count": table_result.deleted_count,
                "errors": [],
            }
    except ValueError as exc:
        log.error("retention: purge execute refusee", extra={"target": body.target})
        return _error_response(400, str(exc))
    except Exception as exc:
        log.error("retention: echec execution purge", exc_info=True, extra={"target": body.target})
        return _error_response(502, f"Erreur lors de l'exécution de la purge: {exc}")

    if request.headers.get("HX-Request") == "true":
        return templates.TemplateResponse(
            request,
            "_purge_execute_fragment.html",
            {"target": body.target, "result": payload},
        )

    return JSONResponse(content=payload)
