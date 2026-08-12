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


_USAGE_LABELS: dict[str, str] = {
    "used": "Exploités",
    "unused": "Inexploités",
}
"""Libellés FR des jetons de filtre d'exploitation. `all` n'a pas de jeton :
c'est l'état neutre, pas une restriction à annoncer."""


def _active_filter_tokens(
    usage: str, origin: str, category: str
) -> list[dict[str, str]]:
    """Construit les jetons de la barre de filtre actif.

    Chaque jeton porte son libellé (groupe + valeur, en clair) et les
    paramètres URL à conserver une fois CE filtre retiré — c'est ce qui
    permet un retrait « jeton par jeton » sans jamais toucher aux deux autres
    filtres. Les valeurs de catégorie (accents, espaces, `/`) passent telles
    quelles : c'est Jinja/Starlette qui les urlencode à l'affichage.
    """
    tokens: list[dict[str, str]] = []
    if usage != "all":
        tokens.append(
            {
                "group": "Exploitation",
                "value": _USAGE_LABELS.get(usage, usage),
                "usage": "all",
                "origin": origin,
                "category": category,
            }
        )
    if origin:
        tokens.append(
            {
                "group": "Origine",
                "value": ORIGIN_LABELS.get(origin, origin),
                "usage": usage,
                "origin": "",
                "category": category,
            }
        )
    if category:
        tokens.append(
            {
                "group": "Catégorie",
                "value": category,
                "usage": usage,
                "origin": origin,
                "category": "",
            }
        )
    return tokens


def _empty_result_reason(usage: str, origin: str, category: str) -> str:
    """Message qui NOMME le ou les filtres responsables d'un résultat vide.

    Zéro silencieux appliqué à l'UI : un tableau vide légitime (résultat de
    filtrage) doit rester distinguable d'une panne, ET dire comment en sortir.
    Un croisement de PLUSIEURS filtres emploie le mot « croisement » ; un seul
    filtre actif reste un message simple — le vocabulaire ne doit pas laisser
    croire à un croisement là où un seul filtre suffit à tout exclure.
    """
    parts: list[str] = []
    if usage != "all":
        parts.append(f"Exploitation : {_USAGE_LABELS.get(usage, usage)}")
    if origin:
        parts.append(f"Origine : {ORIGIN_LABELS.get(origin, origin)}")
    if category:
        parts.append(f"Catégorie : {category}")

    if not parts:
        return ""
    if len(parts) == 1:
        return f"Le filtre {parts[0]} n'a aucune correspondance."
    liste = ", ".join(parts[:-1]) + " et " + parts[-1]
    return (
        f"Le croisement de {len(parts)} filtres ({liste}) n'a aucune "
        "correspondance : retirez-en un pour revoir des champs."
    )


def _context(catalog: FieldCatalog, usage: str, origin: str, category: str) -> dict[str, Any]:
    """Contexte commun à la page complète et au fragment de lignes."""
    entries = catalog.filtered(usage=usage, origin=origin, category=category)
    return {
        "catalog": catalog,
        "entries": entries,
        "filtered_count": len(entries),
        "usage": usage,
        "origin": origin,
        "category": category,
        "origin_order": ORIGIN_ORDER,
        "origin_labels": ORIGIN_LABELS,
        "origin_descriptions": ORIGIN_DESCRIPTIONS,
        "categories": [
            name for name in CATEGORY_ORDER if any(e.category == name for e in catalog.entries)
        ],
        "active_filters": _active_filter_tokens(usage, origin, category),
        "empty_result_reason": _empty_result_reason(usage, origin, category),
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
    """Page complète du catalogue des champs.

    Seul point d'entrée autorisé à MESURER le remplissage (cache froid ou
    expiré) — cadrage utilisateur 2026-08-12 : le filtrage ne doit jamais le
    faire, cf. `get_field_catalog_rows`."""
    error = _validate_filters(usage, origin, category)
    if error:
        return JSONResponse(status_code=400, content={"error": error})

    catalog = build_catalog(client, dashboards_dir, allow_fill_rate_refresh=True)
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
    """Fragment HTMX : uniquement le tableau, pour les filtres à la souris.

    CADRAGE UTILISATEUR (2026-08-12), mot pour mot : « pourquoi tu fais
    recherche clickhouse au moment du filtre ?????? [...] fait le au
    changement de la page ou a un autre moment ». Ce chemin ne mesure JAMAIS
    le remplissage (`allow_fill_rate_refresh=False`) : il sert le cache tel
    quel, y compris périmé (marqué comme tel), jamais une nouvelle requête
    ClickHouse — le filtrage porte sur des lignes déjà en mémoire."""
    error = _validate_filters(usage, origin, category)
    if error:
        return JSONResponse(status_code=400, content={"error": error})

    catalog = build_catalog(client, dashboards_dir, allow_fill_rate_refresh=False)
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
