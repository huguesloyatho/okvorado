"""Compositeur de filtres Akvorado — à la manière d'un Palo Alto.

Jusqu'ici, enregistrer un filtre demandait de connaître par cœur la syntaxe
d'Akvorado ET le nom exact de ses 61 colonnes, puis de taper l'expression dans
un champ texte nu. Aucune aide, aucune vérification avant enregistrement : une
faute de frappe ne se découvrait qu'en ouvrant la console.

Cet écran renverse le geste. On part de ce qui EXISTE — un échantillon des
derniers flux — on clique sur un champ, on choisit une valeur réellement
observée, et l'expression se construit toute seule. La validation se fait au
fil de la frappe, par Akvorado lui-même.

TROIS SOURCES, chacune la seule autorité sur son sujet :

- `app.services.flow_sample` : l'échantillon lu dans ClickHouse. C'est lui qui
  dit quels champs portent des valeurs, et lesquelles.
- `app.clients.akvorado_console` : l'autocomplétion et la validation. La
  console interroge ClickHouse pour proposer les valeurs réelles, et c'est elle
  qui tranche sur sa propre grammaire — jamais une regex maison, qui
  divergerait de la version d'Akvorado déployée.
- `app.services.config_sections` : le YAML des filtres, seule source de vérité
  pour ce qui est enregistré (la console les resynchronise destructivement à
  son démarrage).

DÉGRADATION VISIBLE : ClickHouse ou la console peuvent ne pas répondre. Chaque
route rend alors un état DISTINCT — « je n'ai pas pu interroger » — et jamais
une liste vide, qui serait indistinguable de « aucun champ ne correspond ».
"""

from __future__ import annotations

import logging
from html import escape
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form
from fastapi.responses import HTMLResponse

from app.clients.akvorado_console import ConsoleUnavailable, complete_filter, validate_filter
from app.services.flow_sample import (
    FlowField,
    FlowSampleUnavailableError,
    fetch_flow_sample,
    search_fields,
    summarize_fields,
)

log = logging.getLogger(__name__)

router = APIRouter(tags=["filter-composer"])

_MAX_FIELDS_RENDUS = 40
"""Au-delà, la liste cesse d'être parcourable à l'œil. La recherche est là pour
réduire — afficher 61 champs d'un coup ne rend service à personne."""

_MAX_VALEURS_PAR_CHAMP = 8


def get_clickhouse_client() -> Any:
    """Placeholder — câblé par `app/main.py`, comme les autres routers."""
    raise RuntimeError(
        "get_clickhouse_client non câblée : app/main.py doit surcharger cette "
        "dépendance avec le client ClickHouse réel."
    )


ClickHouseClient = Annotated[Any, Depends(get_clickhouse_client)]


def _degrade(message: str, detail: str = "") -> HTMLResponse:
    """Rend un état INDÉTERMINÉ, distinct d'un résultat vide.

    « Aucun champ ne correspond à votre recherche » et « je n'ai pas pu lire
    les flux » produiraient sinon le même écran, et l'opérateur conclurait à
    tort que son infrastructure n'émet rien.
    """
    suffixe = f"<p class='composer-degraded__detail'>{escape(detail)}</p>" if detail else ""
    return HTMLResponse(
        f'<div class="notice notice-warn composer-degraded" data-composer-degraded>'
        f"<strong>{escape(message)}</strong>{suffixe}</div>"
    )


def _render_field(field: FlowField) -> str:
    """Une carte de champ, cliquable, avec ses valeurs réellement observées."""
    valeurs = field.sample_values[:_MAX_VALEURS_PAR_CHAMP]
    puces = "".join(
        f'<button type="button" class="composer-value" '
        f'data-composer-field="{escape(field.name)}" '
        f'data-composer-value="{escape(valeur)}">{escape(valeur)}</button>'
        for valeur in valeurs
    )
    if not puces:
        # Champ présent au catalogue mais sans aucune valeur dans l'échantillon :
        # le dire, plutôt que de rendre une carte muette qui laisse croire à un
        # défaut d'affichage.
        puces = (
            '<span class="composer-value composer-value--empty">'
            "aucune valeur dans l'échantillon</span>"
        )

    reste = field.distinct_count - len(valeurs)
    surplus = f'<span class="composer-field__more">+{reste} autre(s)</span>' if reste > 0 else ""

    return (
        f'<li class="composer-field" data-composer-field-card="{escape(field.name)}">'
        f'<button type="button" class="composer-field__head" '
        f'data-composer-field="{escape(field.name)}">'
        f'<span class="composer-field__label">{escape(field.label)}</span>'
        f'<code class="composer-field__name">{escape(field.name)}</code>'
        f"</button>"
        f'<div class="composer-field__values">{puces}{surplus}</div>'
        f"</li>"
    )


@router.get("/config/filters/fields", response_class=HTMLResponse)
def get_filter_fields(client: ClickHouseClient, q: str = "") -> HTMLResponse:
    """Champs de l'échantillon, filtrés par la barre de recherche.

    La recherche porte sur le nom TECHNIQUE, le libellé FRANÇAIS **et les
    valeurs observées** : taper « proxy-frontal » remonte le champ `ExporterName`,
    sans qu'il faille deviner qu'on cherche « exportateur ». C'est ce qui rend
    l'écran utilisable par quelqu'un qui connaît son infrastructure mais pas le
    schéma d'Akvorado.
    """
    try:
        rows = fetch_flow_sample(client)
    except FlowSampleUnavailableError as exc:
        log.error("get_filter_fields: echantillon indisponible: %s", exc)
        return _degrade(
            "Échantillon de flux indisponible.",
            "La lecture des derniers flux n'a pas abouti — la composition par "
            "clic est momentanément hors service. La saisie manuelle reste "
            "possible ci-dessous.",
        )

    if not rows:
        return _degrade(
            "Aucun flux sur la dernière heure.",
            "L'échantillon est vide : il n'y a rien à proposer. Ce n'est pas "
            "une erreur de lecture — la fenêtre observée ne contient aucun flux.",
        )

    fields = summarize_fields(rows)
    if q.strip():
        fields = search_fields(fields, q)

    # Les champs non filtrables n'ont rien à faire dans un compositeur de
    # filtres : les proposer produirait des expressions qu'Akvorado refuse.
    fields = [f for f in fields if f.filterable]

    if not fields:
        return HTMLResponse(
            '<p class="empty" data-composer-no-match>Aucun champ ne correspond à '
            f"« {escape(q)} ». Essayez un nom de machine, un port, un pays…</p>"
        )

    cartes = "".join(_render_field(f) for f in fields[:_MAX_FIELDS_RENDUS])
    reste = len(fields) - _MAX_FIELDS_RENDUS
    note = (
        f'<p class="composer-fields__note">{reste} champ(s) supplémentaire(s) — '
        "affinez la recherche.</p>"
        if reste > 0
        else ""
    )
    return HTMLResponse(f'<ul class="composer-fields">{cartes}</ul>{note}')


@router.post("/config/filters/values", response_class=HTMLResponse)
async def get_filter_values(
    column: Annotated[str, Form()],
    prefix: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Valeurs proposées pour une colonne, par la console Akvorado.

    Ces valeurs sont lues dans ClickHouse par la console : ce sont donc celles
    RÉELLEMENT observées, pas une liste figée qui dériverait. La console
    indique aussi si la valeur doit être entourée de guillemets — deviner cette
    règle côté client produirait des filtres syntaxiquement faux.
    """
    try:
        completions = await complete_filter("value", column=column, prefix=prefix)
    except ConsoleUnavailable as exc:
        log.error("get_filter_values: console indisponible: colonne=%s: %s", column, exc)
        return _degrade(
            "Suggestions indisponibles.",
            "La console Akvorado n'a pas répondu : les valeurs proposées ne "
            "peuvent pas être listées. La saisie manuelle reste possible.",
        )

    if not completions:
        return HTMLResponse(
            '<p class="empty">Aucune valeur connue pour ce champ dans les flux récents.</p>'
        )

    puces = "".join(
        f'<button type="button" class="composer-value" '
        f'data-composer-field="{escape(column)}" '
        f'data-composer-value="{escape(c.label)}" '
        f'data-composer-quoted="{"1" if c.quoted else "0"}">{escape(c.label)}</button>'
        for c in completions
    )
    return HTMLResponse(f'<div class="composer-field__values">{puces}</div>')


@router.post("/config/filters/validate", response_class=HTMLResponse)
async def post_validate_filter(
    expression: Annotated[str, Form()] = "",
    content: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Valide une expression AU FIL DE LA FRAPPE, par Akvorado lui-même.

    Le verdict vient de la console, seule autorité sur sa propre grammaire.
    Quand elle refuse, elle indique la POSITION du caractère fautif — c'est ce
    qui distingue un message utile d'un « filtre invalide » qui laisse
    chercher.

    DEUX noms acceptés, et ce n'est pas de la complaisance. La zone de saisie
    est le `<textarea name="content">` du formulaire d'ajout — nom imposé par
    le contrat d'écriture des filtres, qu'on ne peut pas changer. htmx poste
    donc `content`, alors que cette route attendait `expression`.

    DÉFAUT MESURÉ AU NAVIGATEUR (2026-08-06) : le champ arrivait vide, la route
    répondait « filtre vide : aucun filtrage appliqué »… et l'affichait comme
    un SUCCÈS. Une expression fautive aurait donc été annoncée valide, et
    enregistrée telle quelle. Le pire cas d'un validateur : dire oui sans avoir
    rien lu.
    """
    valeur = expression or content
    try:
        result = await validate_filter(valeur)
    except ConsoleUnavailable as exc:
        log.error("post_validate_filter: console indisponible: %s", exc)
        return _degrade(
            "Validation indisponible.",
            "La console Akvorado n'a pas répondu : l'expression n'a PAS été "
            "vérifiée. Elle peut être enregistrée, mais sans garantie de "
            "syntaxe.",
        )

    if result.ok:
        return HTMLResponse(
            '<p class="notice notice-ok composer-verdict" data-composer-valid="1">'
            f"<strong>Expression valide.</strong> {escape(result.message)}</p>"
        )

    return HTMLResponse(
        '<p class="notice notice-crit composer-verdict" data-composer-valid="0">'
        f"<strong>Expression refusée par Akvorado.</strong> {escape(result.message)}</p>"
    )
