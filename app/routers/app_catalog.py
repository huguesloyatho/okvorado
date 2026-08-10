"""Router — écran de gestion du catalogue applicatif (port -> application).

CONTEXTE : `app.services.app_catalog` étend `app.services.portmap` de ~73
entrées à ~11 600 (registre IANA officiel) + un catalogue métier pré-chargé
(SCCM, Tailscale, RDP...). Cet écran donne à l'exploitant SFR (350 routeurs) :
liste paginée + recherche + filtre par source, édition à la souris,
import/export CSV en masse, bouton de rechargement IANA.

Routeur DÉDIÉ (pas une extension de `config_sections.py`, déjà ~1800 lignes
et centré sur un domaine différent — la config Akvorado, pas le catalogue
applicatif local) ni de `views.py` (qui garde son CRUD simple existant sur
`portmap.py`, inchangé, pour ses propres appelants).

GARDE SÉCU N°1 DU PROJET : toute requête SQLite passe par
`app.services.app_catalog`/`app.services.portmap`, jamais d'interpolation de
chaîne ici.
"""

from __future__ import annotations

import logging
import sqlite3
from html import escape
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Query, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.models import PortMapping
from app.services import app_catalog, portmap
from app.templating import build_templates

log = logging.getLogger(__name__)

router = APIRouter(tags=["app-catalog"])

_MAX_CSV_UPLOAD_BYTES = (
    5_242_880  # 5 Mo — le catalogue complet exporté pèse quelques Mo, jamais un timeout silencieux
)


# ---------------------------------------------------------------------------
# Dépendances — placeholders câblés par app/main.py, même mécanisme que
# app/routers/views.py et app/routers/config_sections.py
# ---------------------------------------------------------------------------


def get_db_connection() -> sqlite3.Connection:
    """Placeholder — app/main.py doit surcharger cette dépendance.

    Jamais appelée telle quelle en test (toujours surchargée par
    `app.dependency_overrides`), comme les autres routers de ce dépôt.
    """
    raise RuntimeError(
        "get_db_connection non câblée : app/main.py doit surcharger cette "
        "dépendance avec la connexion SQLite réelle."
    )


def get_templates() -> Jinja2Templates:
    return build_templates()


DbConnection = Annotated[sqlite3.Connection, Depends(get_db_connection)]
Templates = Annotated[Jinja2Templates, Depends(get_templates)]


# ---------------------------------------------------------------------------
# Écran principal — liste paginée, recherche, filtre
# ---------------------------------------------------------------------------


@router.get("/app-catalog", response_class=HTMLResponse)
def get_app_catalog_page(
    request: Request,
    conn: DbConnection,
    templates: Templates,
    page: int = Query(default=1, ge=1),
    search: str = Query(default=""),
    source: str = Query(default=""),
) -> HTMLResponse:
    """Écran complet : compteurs par source, statut du dernier rechargement
    IANA, table paginée avec recherche/filtre, formulaire d'ajout, blocs
    import/export CSV."""
    result = app_catalog.list_catalog_page(conn, page=page, search=search, source=source)
    reload_status = app_catalog.get_reload_status(conn)
    counts = app_catalog.count_by_source(conn)

    return templates.TemplateResponse(
        request,
        "app_catalog.html",
        {
            "active_page": "app_catalog",
            "result": result,
            "reload_status": reload_status,
            "counts": counts,
            "search": search,
            "source_filter": source,
            "valid_sources": app_catalog.VALID_SOURCES,
        },
    )


@router.get("/app-catalog/rows", response_class=HTMLResponse)
def get_app_catalog_rows_fragment(
    request: Request,
    conn: DbConnection,
    templates: Templates,
    page: int = Query(default=1, ge=1),
    search: str = Query(default=""),
    source: str = Query(default=""),
) -> HTMLResponse:
    """Fragment HTMX : uniquement la table + pagination, pour la recherche
    incrémentale sans recharger l'écran entier (compteurs, formulaires)."""
    result = app_catalog.list_catalog_page(conn, page=page, search=search, source=source)
    return templates.TemplateResponse(
        request,
        "app_catalog_rows.html",
        {
            "result": result,
            "search": search,
            "source_filter": source,
        },
    )


# ---------------------------------------------------------------------------
# CRUD à la souris — ajout / suppression (édition = suppression + ajout,
# même geste que la table existante de views.html)
# ---------------------------------------------------------------------------


def _row_html(mapping: PortMapping) -> str:
    row_id = f"app-catalog-row-{mapping.port}-{mapping.proto}"
    delete_disabled = ""
    return (
        f'<tr id="{row_id}">'
        f'<td class="num">{escape(mapping.port_label)}</td>'
        f"<td>{escape(mapping.proto)}</td>"
        f"<td>{escape(mapping.application)}</td>"
        f'<td><span class="badge badge-{escape(mapping.source)}">'
        f"{escape(mapping.source)}</span></td>"
        f"<td>"
        f'<button type="button" class="danger" {delete_disabled} '
        f'hx-delete="/app-catalog/{mapping.port}/{escape(mapping.proto)}" '
        f'hx-target="#{row_id}" hx-swap="outerHTML" '
        f'hx-confirm="Supprimer cette correspondance du catalogue ?">'
        f"Supprimer</button>"
        f"</td>"
        f"</tr>"
    )


@router.post("/app-catalog", response_class=HTMLResponse)
def create_app_catalog_entry(
    conn: DbConnection,
    port: Annotated[int, Form()],
    proto: Annotated[str, Form()],
    application: Annotated[str, Form()],
    port_end: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Ajout/édition à la souris — TOUJOURS `source='custom'` (saisie
    manuelle par l'exploitant, jamais écrasée par un rechargement IANA ou un
    reseed métier, cf. `app_catalog.reload_from_iana`/`seed_metier_defaults`)."""
    port_end_value: int | None = None
    if port_end.strip():
        try:
            port_end_value = int(port_end.strip())
        except ValueError:
            log.error("ajout catalogue refuse: port_end non entier: %r", port_end)
            return HTMLResponse(
                f'<tr><td colspan="5" class="notice notice-crit">'
                f"Fin de plage invalide : {escape(port_end)}</td></tr>",
                status_code=422,
            )

    if proto not in portmap.VALID_PROTOS:
        log.error("ajout catalogue refuse: proto invalide %r", proto)
        return HTMLResponse(
            f'<tr><td colspan="5" class="notice notice-crit">Protocole invalide : '
            f"{escape(proto)}</td></tr>",
            status_code=422,
        )
    try:
        mapping = portmap.create_mapping(
            conn,
            port=port,
            proto=proto,
            application=application,
            source="custom",
            port_end=port_end_value,
        )
    except portmap.ValidationError as exc:
        log.error("ajout catalogue refuse: %s", exc)
        return HTMLResponse(
            f'<tr><td colspan="5" class="notice notice-crit">{escape(str(exc))}</td></tr>',
            status_code=422,
        )

    return HTMLResponse(_row_html(mapping), status_code=201)


@router.delete("/app-catalog/{port}/{proto}", response_class=HTMLResponse)
def delete_app_catalog_entry(port: int, proto: str, conn: DbConnection) -> HTMLResponse:
    if not (portmap.MIN_PORT <= port <= portmap.MAX_PORT) or proto not in portmap.VALID_PROTOS:
        log.error("suppression catalogue refusee: port=%s proto=%r hors bornes", port, proto)
        return HTMLResponse("", status_code=422)
    portmap.delete_mapping(conn, port=port, proto=proto)
    return HTMLResponse("")


# ---------------------------------------------------------------------------
# Rechargement IANA — déclenchable à la souris
# ---------------------------------------------------------------------------


@router.post("/app-catalog/reload-iana", response_class=HTMLResponse)
def reload_app_catalog_from_iana(
    conn: DbConnection, templates: Templates, request: Request
) -> HTMLResponse:
    """Déclenche un rechargement réseau du registre IANA. Idempotent : peut
    être cliqué autant de fois que voulu sans dupliquer ni régresser une
    correspondance custom/métier.

    Retourne le fragment de statut (jamais un HTTP 500 : `reload_from_iana`
    dégrade déjà en interne réseau -> repli -> erreur, tous trois rendus
    ici avec un état VISIBLE distinct)."""
    status = app_catalog.reload_from_iana(conn)
    counts = app_catalog.count_by_source(conn)
    return templates.TemplateResponse(
        request,
        "app_catalog_reload_status.html",
        {"reload_status": status, "counts": counts},
    )


@router.get("/app-catalog/reload-status", response_class=HTMLResponse)
def get_app_catalog_reload_status_fragment(
    conn: DbConnection, templates: Templates, request: Request
) -> HTMLResponse:
    status = app_catalog.get_reload_status(conn)
    counts = app_catalog.count_by_source(conn)
    return templates.TemplateResponse(
        request,
        "app_catalog_reload_status.html",
        {"reload_status": status, "counts": counts},
    )


# ---------------------------------------------------------------------------
# Import/export CSV en masse — catalogue métier (350 routeurs)
# ---------------------------------------------------------------------------


@router.get("/app-catalog/export.csv")
def export_app_catalog_csv(conn: DbConnection, source: str = Query(default="")) -> HTMLResponse:
    csv_text = app_catalog.export_catalog_csv(conn, source=source)
    filename = f"catalogue-applicatif{'-' + source if source else ''}.csv"
    return HTMLResponse(
        csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _import_error_response(errors: list[str]) -> HTMLResponse:
    items = "".join(f"<li>{escape(err)}</li>" for err in errors)
    return HTMLResponse(
        f'<div class="notice notice-crit"><strong>Import refusé</strong><ul>{items}</ul></div>',
        status_code=422,
    )


@router.post("/app-catalog/import", response_class=HTMLResponse)
async def import_app_catalog_csv(
    conn: DbConnection,
    templates: Templates,
    request: Request,
    file: UploadFile | None = None,
    content: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Import CSV en masse (upload de fichier OU collage direct dans un
    textarea — les deux chemins existants dans `config_sections.html` pour
    les autres sections, repris ici à l'identique).

    TOUT OU RIEN : une seule ligne malformée refuse l'import entier et le DIT
    (message par ligne) — jamais un sous-ensemble appliqué en silence.
    Marque les entrées importées `source='metier'` : c'est le geste attendu
    à cette échelle (350 routeurs, saisie manuelle exclue), jamais 'custom'
    (réservé à l'ajout unitaire à la souris) ni 'iana' (réservé au registre
    officiel).
    """
    raw_text = content
    if file is not None:
        body = await file.read()
        if len(body) > _MAX_CSV_UPLOAD_BYTES:
            log.error("import catalogue refuse: fichier trop volumineux (%d octets)", len(body))
            return _import_error_response(
                [f"fichier trop volumineux ({len(body)} octets, max {_MAX_CSV_UPLOAD_BYTES})"]
            )
        try:
            raw_text = body.decode("utf-8")
        except UnicodeDecodeError as exc:
            log.error("import catalogue refuse: encodage invalide: %s", exc)
            return _import_error_response([f"encodage du fichier invalide (attendu UTF-8) : {exc}"])

    if not raw_text.strip():
        return _import_error_response(["aucun contenu à importer (fichier vide ou champ vide)"])

    parsed = app_catalog.parse_catalog_csv(raw_text)
    if parsed.errors:
        log.error("import catalogue refuse: %d erreur(s)", len(parsed.errors))
        return _import_error_response(parsed.errors)

    written = app_catalog.apply_catalog_csv_import(conn, parsed.rows, source="metier")
    log.info("import catalogue: %d ligne(s) appliquee(s) sous source='metier'", written)

    counts = app_catalog.count_by_source(conn)
    return templates.TemplateResponse(
        request,
        "app_catalog_import_result.html",
        {"written": written, "total_parsed": len(parsed.rows), "counts": counts},
    )
