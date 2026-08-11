"""Écran « Export de flux » — prélever un échantillon pour qualifier un équipement.

POURQUOI CET ÉCRAN (demande utilisateur 2026-08-11) : « quand je serai en qualif,
je voudrai exporter des flux avec les données des palo et des routeurs SFR à te
donner en exemple pour affiner l'intégration auto des bonnes interfaces + ajuster
les dashboards ».

L'écran sert donc un geste précis, en environnement client : choisir UN
équipement, regarder ce qu'il remplit VRAIMENT, puis emporter le fichier. D'où la
séquence imposée par les routes ci-dessous — on APERÇOIT avant de télécharger.

POURQUOI L'APERÇU EST OBLIGATOIRE ET NON UN CONFORT : sans lui, on télécharge à
l'aveugle et on ne découvre qu'après coup — parfois de retour au bureau, hors du
site client — que le pare-feu ne renseignait pas les champs attendus, ou que la
fenêtre était vide. L'aperçu montre les premières lignes ET le taux de
remplissage par champ, y compris les champs à 0 % : c'est ce qui rend le
prélèvement décidable sur place.

Le client ClickHouse est INJECTÉ (jamais construit ici) : c'est ce qui permet aux
tests de fournir un double sans infra, et c'est la convention de tous les routers
du projet.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from app.config import WINDOW_CHOICES
from app.services.field_catalog import read_flow_columns
from app.services.flow_export import (
    DEFAULT_EXPORT_LIMIT,
    EXPORT_FORMATS,
    LIMIT_CHOICES,
    MAX_EXPORT_LIMIT,
    ClickHouseQueryable,
    ExportableDevice,
    FlowExportUnavailableError,
    build_export,
    export_filename,
    list_exportable_devices,
    render_export,
)
from app.templating import build_templates

log = logging.getLogger(__name__)

router = APIRouter()

templates = build_templates()

PREVIEW_ROW_COUNT = 20
"""Lignes rendues dans l'aperçu. Assez pour juger de la forme des données, assez
peu pour que la page reste lisible et légère."""

PREVIEW_COLUMN_COUNT = 12
"""Colonnes rendues dans le tableau d'aperçu.

Les ~62 colonnes ne tiennent pas à l'écran. Ce n'est PAS une perte
d'information : le tableau des taux de remplissage juste au-dessus porte, lui,
TOUS les champs — c'est là qu'on lit ce que l'équipement renseigne. Le tableau de
lignes ne sert qu'à voir la tête des valeurs."""

DEVICE_LIST_WINDOW = "24h"
"""Fenêtre de découverte des exportateurs proposables.

Plus large que la fenêtre d'export par défaut, et c'est délibéré : un équipement
qu'on vient de brancher peut n'avoir émis qu'une rafale il y a trois heures. Le
proposer quand même est correct — c'est justement celui qu'on veut qualifier.
Une fenêtre d'une heure le ferait disparaître du sélecteur, et l'écran semblerait
ne pas le voir alors qu'il a bien reçu ses flux."""


def get_clickhouse_client() -> ClickHouseQueryable:
    """Placeholder — surchargé par `app/main.py` (voir `_wire_dependencies`).

    Raises:
        RuntimeError: si appelée sans override — un câblage manquant doit
            échouer BRUYAMMENT. Sans ce garde-fou, les tests passent et la prod
            échoue au premier clic (défaut mesuré 2026-08-10).
    """
    raise RuntimeError(
        "get_clickhouse_client n'est pas cablee : app/main.py doit fournir "
        "app.dependency_overrides[get_clickhouse_client]."
    )


ClickHouseDep = Annotated[ClickHouseQueryable, Depends(get_clickhouse_client)]


def _validate_selection(window: str, fmt: str) -> str:
    """Valide fenêtre et format contre des énumérations FERMÉES.

    Une valeur hors liste est REFUSÉE (400), jamais interpolée ni silencieusement
    remplacée par un défaut. Remplacer en silence produirait un fichier dont la
    période ne serait pas celle demandée — et ce fichier partirait en analyse,
    porteur d'une métadonnée fausse.

    Returns:
        Un message d'erreur, ou `""` si tout est valide.
    """
    if window not in WINDOW_CHOICES:
        return f"periode inconnue: {window!r}"
    if fmt not in EXPORT_FORMATS:
        return f"format inconnu: {fmt!r}"
    return ""


def _load_devices(client: ClickHouseQueryable) -> tuple[list[ExportableDevice], str]:
    """Charge la liste des équipements sélectionnables.

    Returns:
        `(devices, erreur)`. ZÉRO SILENCIEUX : une liste vide accompagnée d'une
        erreur NON VIDE signifie « je n'ai pas pu lire » ; une liste vide avec
        une erreur vide signifie « aucun exportateur n'émet ». L'écran doit dire
        laquelle des deux — un sélecteur vide sans explication ferait croire que
        l'équipement n'est pas branché alors que c'est la base qui est muette.
    """
    try:
        return list_exportable_devices(client, window=DEVICE_LIST_WINDOW), ""
    except (FlowExportUnavailableError, ValueError) as exc:
        log.error("flow_export: liste des exportateurs indisponible: %s", exc)
        return [], str(exc)


def _base_context(
    devices: list[ExportableDevice],
    devices_error: str,
    *,
    exporter: str,
    window: str,
    limit: int,
    fmt: str,
) -> dict[str, Any]:
    """Contexte commun à la page et au fragment d'aperçu."""
    return {
        "devices": devices,
        "devices_error": devices_error,
        "devices_available": not devices_error,
        "exporter": exporter,
        "window": window,
        "limit": limit,
        "fmt": fmt,
        "window_choices": WINDOW_CHOICES,
        "limit_choices": LIMIT_CHOICES,
        "format_choices": EXPORT_FORMATS,
        "max_limit": MAX_EXPORT_LIMIT,
        "device_list_window": DEVICE_LIST_WINDOW,
        "active_page": "flow_export",
    }


@router.get("/flow-export", response_class=HTMLResponse)
def get_flow_export(
    request: Request,
    client: ClickHouseDep,
    exporter: str = Query(default=""),
    window: str = Query(default="1h"),
    limit: int = Query(default=DEFAULT_EXPORT_LIMIT),
    fmt: str = Query(default="json"),
) -> Any:
    """Page de composition du prélèvement.

    Ne lance AUCUNE extraction : elle propose les équipements réellement observés
    et attend un geste. Extraire d'office ferait payer une requête sur ~60 M de
    lignes à chaque ouverture de l'onglet, pour un périmètre que l'utilisateur
    n'a pas encore choisi.
    """
    error = _validate_selection(window, fmt)
    if error:
        return JSONResponse(status_code=400, content={"error": error})

    devices, devices_error = _load_devices(client)
    context = _base_context(
        devices, devices_error, exporter=exporter, window=window, limit=limit, fmt=fmt
    )

    # ZÉRO SILENCIEUX — DÉFAUT MESURÉ PAR LE TEST AVANT LIVRAISON (2026-08-11) :
    # la liste des équipements et le schéma des champs sont DEUX mesures
    # indépendantes. Quand `system.columns` était illisible mais que la liste
    # passait, la page s'affichait NORMALEMENT, sélecteur peuplé, sans le
    # moindre avertissement — et l'utilisateur ne découvrait la panne qu'après
    # avoir choisi son équipement et cliqué sur « Aperçu ». En qualification, sur
    # site client, c'est le pire moment pour l'apprendre.
    #
    # La page vérifie donc elle-même que le schéma est lisible. C'est une
    # requête sur `system.columns` (métadonnées, pas la table de 60 M de
    # lignes) : son coût est négligeable et elle rend l'écran honnête dès son
    # ouverture.
    schema_error = ""
    try:
        read_flow_columns(client)
    except Exception as exc:  # noqa: BLE001 - toute panne de lecture vaut avertissement
        log.error("flow_export: schema de flux illisible: %s", exc)
        schema_error = f"schema de flux non lu: {exc}"
    context["schema_error"] = schema_error
    context["schema_available"] = not schema_error

    return templates.TemplateResponse(request, "flow_export.html", context)


@router.get("/flow-export/preview", response_class=HTMLResponse)
def get_flow_export_preview(
    request: Request,
    client: ClickHouseDep,
    exporter: str = Query(default=""),
    window: str = Query(default="1h"),
    limit: int = Query(default=DEFAULT_EXPORT_LIMIT),
    fmt: str = Query(default="json"),
) -> Any:
    """Fragment HTMX : l'aperçu AVANT téléchargement.

    Montre les premières lignes et le taux de remplissage par champ. C'est ce qui
    rend l'écran utile en qualification : on voit tout de suite si l'équipement
    renseigne `SrcNetMask` ou non, sans avoir à ouvrir le fichier.

    L'aperçu est borné indépendamment de la limite d'export : afficher 50 000
    lignes dans une page est un incident de navigateur, pas un aperçu.
    """
    error = _validate_selection(window, fmt)
    if error:
        return JSONResponse(status_code=400, content={"error": error})

    devices, devices_error = _load_devices(client)
    context = _base_context(
        devices, devices_error, exporter=exporter, window=window, limit=limit, fmt=fmt
    )

    try:
        export = build_export(
            client, exporter_address=exporter, window=window, limit=limit, fmt=fmt
        )
    except FlowExportUnavailableError as exc:
        # ZÉRO SILENCIEUX : « je n'ai pas pu mesurer » n'est PAS « 0 flux ».
        log.error("flow_export: apercu indisponible: %s", exc)
        context.update({"export": None, "export_error": str(exc)})
        return templates.TemplateResponse(request, "_flow_export_preview.html", context)
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})

    context.update(
        {
            "export": export,
            "export_error": "",
            # Seules les premières lignes sont RENDUES — le fichier téléchargé,
            # lui, porte l'échantillon complet.
            "preview_rows": export.rows[:PREVIEW_ROW_COUNT],
            "preview_row_count": PREVIEW_ROW_COUNT,
            "preview_columns": [item.name for item in export.fields][:PREVIEW_COLUMN_COUNT],
        }
    )
    return templates.TemplateResponse(request, "_flow_export_preview.html", context)


@router.get("/flow-export/download")
def download_flow_export(
    client: ClickHouseDep,
    exporter: str = Query(default=""),
    window: str = Query(default="1h"),
    limit: int = Query(default=DEFAULT_EXPORT_LIMIT),
    fmt: str = Query(default="json"),
) -> Response:
    """Produit le fichier à transmettre.

    Le fichier est AUTO-PORTANT : son en-tête de métadonnées dit quel équipement,
    quelle période, combien de flux et quels champs sont remplis, dans les deux
    formats. C'est l'exigence explicite de la demande — celui qui le reçoit ne
    doit pas avoir à poser de question.

    En cas d'indisponibilité, AUCUN fichier n'est produit (502) : un fichier vide
    issu d'une panne serait lu comme « cet équipement n'émet rien », soit une
    conclusion fausse tirée d'une absence de mesure.
    """
    error = _validate_selection(window, fmt)
    if error:
        return JSONResponse(status_code=400, content={"error": error})

    try:
        export = build_export(
            client, exporter_address=exporter, window=window, limit=limit, fmt=fmt
        )
    except FlowExportUnavailableError as exc:
        log.error("flow_export: telechargement impossible: %s", exc)
        return JSONResponse(status_code=502, content={"error": str(exc)})
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})

    contenu, media_type = render_export(export, fmt)
    nom = export_filename(export, fmt)
    return Response(
        content=contenu,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{nom}"'},
    )
