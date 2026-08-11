"""Écran « Champs disponibles » — ce que le stack expose face à ce qu'on exploite.

POURQUOI CET ÉCRAN (demande utilisateur 2026-08-11) : soutenir une présentation
commerciale. Il doit retourner l'objection « vos dashboards sont légers » en
montrant le ratio réel de potentiel inexploité, et permettre de désigner les
champs à ajouter — puis d'emporter le tout en CSV pour l'annoter en réunion.

Le client ClickHouse et le dossier des dashboards sont INJECTÉS (jamais
construits ici) : c'est ce qui permet aux tests de fournir un double sans infra,
et c'est la convention de tous les routers du projet.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from app.services.field_catalog import (
    CATEGORY_ORDER,
    ORIGIN_DESCRIPTIONS,
    ORIGIN_LABELS,
    ORIGIN_ORDER,
    USAGE_CHOICES,
    ClickHouseQueryable,
    FieldCatalog,
    build_catalog,
    export_catalog_csv,
)
from app.templating import build_templates

log = logging.getLogger(__name__)

router = APIRouter()

templates = build_templates()


def get_clickhouse_client() -> ClickHouseQueryable:
    """Placeholder — surchargé par `app/main.py` (voir `_wire_dependencies`).

    Raises:
        RuntimeError: si appelée sans override — un câblage manquant doit
            échouer BRUYAMMENT. Sans ce garde-fou, les tests passent et la prod
            échoue au premier clic.
    """
    raise RuntimeError(
        "get_clickhouse_client n'est pas cablee : app/main.py doit fournir "
        "app.dependency_overrides[get_clickhouse_client]."
    )


def get_dashboards_dir() -> Path:
    """Placeholder — surchargé par `app/main.py` avec le dossier réel des
    dashboards Grafana provisionnés."""
    raise RuntimeError(
        "get_dashboards_dir n'est pas cablee : app/main.py doit fournir "
        "app.dependency_overrides[get_dashboards_dir]."
    )


ClickHouseDep = Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)]
DashboardsDirDep = Annotated[Path, Depends(get_dashboards_dir)]


def _validate_filters(usage: str, origin: str, category: str) -> str:
    """Valide les filtres contre des énumérations FERMÉES.

    Une valeur hors liste est REFUSÉE (400), jamais interpolée ni silencieusement
    ignorée. Ignorer rendrait l'écran complet là où l'utilisateur croit avoir
    filtré ; rendre une liste vide se confondrait avec « aucun champ ne
    correspond ». Les deux sont des mensonges d'affichage.

    Returns:
        Un message d'erreur, ou `""` si tout est valide.
    """
    if usage not in USAGE_CHOICES:
        return f"filtre d'exploitation inconnu: {usage!r}"
    if origin and origin not in ORIGIN_LABELS:
        return f"origine inconnue: {origin!r}"
    if category and category not in CATEGORY_ORDER:
        return f"categorie inconnue: {category!r}"
    return ""


def _context(catalog: FieldCatalog, usage: str, origin: str, category: str) -> dict[str, Any]:
    """Contexte commun à la page complète et au fragment de lignes."""
    return {
        "catalog": catalog,
        "entries": catalog.filtered(usage=usage, origin=origin, category=category),
        "usage": usage,
        "origin": origin,
        "category": category,
        "origin_order": ORIGIN_ORDER,
        "origin_labels": ORIGIN_LABELS,
        "origin_descriptions": ORIGIN_DESCRIPTIONS,
        "categories": [
            name for name in CATEGORY_ORDER if any(e.category == name for e in catalog.entries)
        ],
        "active_page": "field_catalog",
    }


@router.get("/field-catalog", response_class=HTMLResponse)
def get_field_catalog(
    request: Request,
    client: ClickHouseDep,
    dashboards_dir: DashboardsDirDep,
    usage: str = Query(default="all"),
    origin: str = Query(default=""),
    category: str = Query(default=""),
) -> Any:
    """Page complète du catalogue des champs."""
    error = _validate_filters(usage, origin, category)
    if error:
        return JSONResponse(status_code=400, content={"error": error})

    catalog = build_catalog(client, dashboards_dir)
    return templates.TemplateResponse(
        request, "field_catalog.html", _context(catalog, usage, origin, category)
    )


@router.get("/field-catalog/rows", response_class=HTMLResponse)
def get_field_catalog_rows(
    request: Request,
    client: ClickHouseDep,
    dashboards_dir: DashboardsDirDep,
    usage: str = Query(default="all"),
    origin: str = Query(default=""),
    category: str = Query(default=""),
) -> Any:
    """Fragment HTMX : uniquement le tableau, pour les filtres à la souris."""
    error = _validate_filters(usage, origin, category)
    if error:
        return JSONResponse(status_code=400, content={"error": error})

    catalog = build_catalog(client, dashboards_dir)
    return templates.TemplateResponse(
        request, "_field_catalog_rows.html", _context(catalog, usage, origin, category)
    )


@router.get("/field-catalog/export.csv")
def export_field_catalog_csv(
    client: ClickHouseDep, dashboards_dir: DashboardsDirDep
) -> Response:
    """Catalogue COMPLET en CSV — à ouvrir dans un tableur et annoter en réunion.

    Toujours complet, jamais filtré : le fichier sert de support de discussion,
    et un export amputé par un filtre laissé actif à l'écran serait un piège.
    """
    catalog = build_catalog(client, dashboards_dir)
    return Response(
        content=export_catalog_csv(catalog),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="champs-disponibles.csv"'},
    )
