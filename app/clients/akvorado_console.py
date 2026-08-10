"""Client de l'API de filtres de la console Akvorado.

Akvorado expose déjà TOUT ce qu'il faut pour composer un filtre correctement,
et Okvorado ne s'en servait pas — il proposait une zone de texte libre où
l'opérateur devait connaître par cœur la syntaxe et les noms de colonnes :

- `POST /api/v0/console/filter/complete` — autocomplétion des **colonnes**,
  des **opérateurs** et surtout des **valeurs réelles** lues dans ClickHouse.
  C'est ce qui permet de proposer « proxy-frontal » quand on compose sur
  `ExporterName`, au lieu d'exiger que l'utilisateur le sache.
- `POST /api/v0/console/filter/validate` — validation d'une expression, avec
  la position de l'erreur.

Contrat vérifié à la SOURCE (console/filter.go du dépôt akvorado/akvorado) et
non deviné. Disponibilité vérifiée en production le 2026-08-06 : les trois
chemins répondent 405 en GET, ce qui confirme qu'ils sont montés et attendent
un POST.

RÉSEAU : la console n'est pas publiée sur l'hôte. Okvorado tourne sur le
réseau docker `akvorado_default` et la joint par NOM de service
(`akvorado-console`, résolution vérifiée) — jamais par IP, qui change à chaque
recréation du conteneur.

DÉGRADATION VISIBLE : un appel peut échouer (timeout, console redémarrée
pendant un apply). Les fonctions lèvent alors `ConsoleUnavailable` plutôt que
de rendre une liste vide. Sans cette distinction, « cette colonne n'a aucune
valeur » et « la requête n'a pas abouti » produiraient le même écran — aucune
suggestion — et l'opérateur conclurait à tort que sa colonne est vide. C'est
le zéro silencieux que ce projet traque.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

from app.config import settings

log = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 5.0
"""Court volontairement : ces appels servent une frappe au clavier. Au-delà,
l'utilisateur a déjà tapé la suite et la suggestion arrive trop tard — mieux
vaut échouer vite et le dire."""

_MAX_COMPLETIONS = 50


class ConsoleUnavailable(RuntimeError):
    """L'appel à la console Akvorado n'a pas abouti.

    Distincte d'un résultat vide : « la colonne n'a aucune valeur » et « la
    requête a échoué » doivent produire deux écrans différents.
    """


@dataclass(frozen=True)
class Completion:
    """Une suggestion d'autocomplétion renvoyée par la console."""

    label: str
    detail: str = ""
    quoted: bool = False
    """La valeur doit être entourée de guillemets dans l'expression finale.

    C'est la console qui le dit, pas nous : `ExporterName = 'proxy-frontal'` a
    besoin des quotes, `SrcPort = 443` non. Deviner cette règle côté client
    produirait des filtres syntaxiquement faux — acceptés à la saisie, rejetés
    par Akvorado ensuite.
    """


@dataclass(frozen=True)
class ValidationResult:
    """Verdict de la console sur une expression de filtre."""

    ok: bool
    message: str
    parsed: str = ""
    errors: list[dict[str, Any]] | None = None
    """Erreurs détaillées, avec position quand la console la fournit — c'est ce
    qui permet de pointer le caractère fautif plutôt que d'afficher « filtre
    invalide » et de laisser chercher."""


def _console_url(path: str) -> str:
    # `akvorado_console_url` existe déjà dans la config et résout l'hôte de la
    # console (le sien s'il est précisé, sinon l'hôte partagé). En recréer une
    # variante ici ferait deux sources pour la même adresse, qui divergeraient
    # au premier changement de port.
    return f"{settings.akvorado_console_url}/api/v0/console{path}"


async def _post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST vers la console, en traduisant tout échec en `ConsoleUnavailable`.

    Ces appels sont en LECTURE malgré le verbe POST : la console attend un
    corps JSON pour compléter et valider. Aucun d'eux ne modifie quoi que ce
    soit. `/filter/saved/add` et `/filter/saved/{id}` en DELETE, eux, écrivent
    et ne sont volontairement PAS exposés ici : Okvorado gère les filtres par
    son propre YAML, seule source de vérité — la console les resynchronise
    destructivement à son démarrage.
    """
    url = _console_url(path)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.error("appel console akvorado en echec: url=%s erreur=%s", url, exc)
        raise ConsoleUnavailable(f"la console Akvorado n'a pas répondu : {exc}") from exc

    if not isinstance(data, dict):
        log.error("console akvorado: reponse inattendue sur %s: %r", url, data)
        raise ConsoleUnavailable("réponse inattendue de la console Akvorado")
    return data


async def complete_filter(
    what: str,
    *,
    column: str = "",
    operator: str = "",
    prefix: str = "",
    limit: int = 20,
) -> list[Completion]:
    """Autocomplète une partie d'expression de filtre.

    `what` vaut `"column"`, `"operator"` ou `"value"` — le contrat de la
    console. Pour `"value"`, elle interroge ClickHouse : les suggestions sont
    donc les valeurs RÉELLEMENT observées dans les flux, pas une liste figée
    qui dériverait de la réalité.
    """
    payload: dict[str, Any] = {
        "what": what,
        "prefix": prefix,
        "limit": min(limit, _MAX_COMPLETIONS),
    }
    if column:
        payload["column"] = column
    if operator:
        payload["operator"] = operator

    data = await _post("/filter/complete", payload)
    raw = data.get("completions") or []
    if not isinstance(raw, list):
        return []

    completions: list[Completion] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        label = item.get("label")
        if not label:
            continue
        completions.append(
            Completion(
                label=str(label),
                detail=str(item.get("detail") or ""),
                quoted=bool(item.get("quoted")),
            )
        )
    return completions


async def validate_filter(expression: str) -> ValidationResult:
    """Fait valider une expression PAR AKVORADO, jamais par une regex maison.

    Réimplémenter la grammaire côté Okvorado garantirait de diverger de la
    version d'Akvorado déployée : un filtre accepté ici et refusé là-bas, ou
    l'inverse. La console est la seule autorité sur sa propre syntaxe.
    """
    if not expression.strip():
        # Un filtre vide est légitime (« tout le trafic ») : ne pas déranger la
        # console pour ça, et surtout ne pas le présenter comme une erreur.
        return ValidationResult(ok=True, message="filtre vide : aucun filtrage appliqué")

    data = await _post("/filter/validate", {"filter": expression})
    message = str(data.get("message") or "")
    errors = data.get("errors")
    return ValidationResult(
        ok=message.lower() == "ok",
        message=message or "réponse sans message",
        parsed=str(data.get("parsed") or ""),
        errors=errors if isinstance(errors, list) else None,
    )
