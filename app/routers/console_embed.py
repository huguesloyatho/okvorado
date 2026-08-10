"""Écran d'INTÉGRATION de la console Akvorado dans Okvorado.

DEMANDE UTILISATEUR (2026-08-10) : « il manque l'intégration de l'interface
web d'akvorado dans okvorado pour le laisser juste dans l'internal network et
plus accessible a distance ».

CE QUI EXISTAIT DÉJÀ, ET CE QUI MANQUAIT. Le reverse proxy
(`app/routers/proxy_akvorado.py`) fonctionnait, et la console ne publie plus
aucun port sur l'hôte (`stack/docker-compose.yml`) : la partie « plus
accessible à distance » était donc acquise. Ce qui manquait est
l'INTÉGRATION : le menu portait `target="_blank"`, donc cliquer « Akvorado »
faisait SORTIR d'Okvorado vers un onglet séparé. Cet écran encadre la console
sous la barre de navigation d'Okvorado — l'exploitant reste chez lui.

POURQUOI UN IFRAME PLUTÔT QU'UN RENDU DIRECT DU HTML PROXIFIÉ (décidé par la
mesure du 2026-08-10, pas par intuition — les deux options étaient ouvertes) :
la console est une SPA Vue dont le routage est côté client et dont tous les
chemins se résolvent contre une balise `<base href>` que le proxy réécrit
précisément pour qu'elle fonctionne sous préfixe. L'injecter dans un gabarit
Jinja mettrait DEUX balises `<base>` et deux racines de document concurrentes
dans une seule page : les chemins de la console se résoudraient contre la base
d'Okvorado, et ses scripts entreraient en conflit avec htmx. L'iframe, lui,
laisse à la console son PROPRE document — donc sa balise `<base>`, son routeur
et ses appels d'API intacts, sans aucune réécriture supplémentaire.

DEUX BLOCAGES D'ENCADREMENT MESURÉS, tous deux corrigés hors de ce module
(l'iframe ne « marche » pas d'office — le brief prévenait, la mesure l'a
confirmé) :

1. `X-Frame-Options` de l'amont était relayé VERBATIM par le proxy (mesuré :
   une console posant `SAMEORIGIN` le rendait tel quel, et un `DENY` aurait
   rendu le cadre définitivement blanc). Corrigé en l'ajoutant aux en-têtes
   non relayés — voir `proxy_akvorado._HOP_BY_HOP_RESPONSE_HEADERS`.
2. La CSP du proxy portait `frame-ancestors http://localhost:3000` (origine
   Grafana) SANS `'self'`. L'encadrant étant Okvorado lui-même — même origine
   — le navigateur refusait le rendu bien que le proxy réponde 200. Corrigé
   en ajoutant `'self'` sur la seule branche proxy, voir
   `app/main.py::add_security_headers`.

ZÉRO SILENCIEUX (règle dure du projet) : un `<iframe>` dont la source ne
répond pas rend un CADRE BLANC, indiscernable à l'œil d'une page qui charge
encore. C'est très exactement la valeur neutre que la règle interdit. Cet
écran SONDE donc la console AVANT de rendre le cadre (`_sonder_console`) et,
en cas d'échec, rend un état explicite portant LA CAUSE — jamais un iframe
vide.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.config import settings
from app.routers.proxy_akvorado import PROXY_PREFIX
from app.templating import templates

log = logging.getLogger(__name__)

router = APIRouter(tags=["console_embed"])

EMBED_PATH = "/akvorado"
"""Chemin de CET écran. DISTINCT de `PROXY_PREFIX` (`/akvorado-console`) :
l'un est une page Okvorado avec sa barre de navigation, l'autre est le flux
relayé de la console. Les confondre ferait que l'écran s'encadrerait
lui-même à l'infini — garde-fou explicite dans
`tests/test_console_embed.py::test_l_ecran_ne_s_encadre_pas_lui_meme`."""

ACTIVE_PAGE = "akvorado_console"
"""Identifiant d'onglet actif, consommé par `base.html`. L'entrée de menu se
comporte désormais comme les autres (état actif), au lieu du lien externe
`target="_blank"` qui faisait sortir de l'application."""

_SONDE_TIMEOUT = httpx.Timeout(connect=3.0, read=5.0, write=5.0, pool=3.0)
"""Budget de la SONDE seulement — délibérément bien plus court que les 30 s de
lecture du proxy (`proxy_akvorado._TIMEOUT_SECONDS`). Ce n'est pas la même
opération : le proxy peut servir un gros payload légitimement lent, alors que
la sonde ne fait que répondre « la console est-elle là ? » avant de rendre la
page. Un budget long ici ferait attendre l'exploitant devant une page vide
pour, au final, lui rendre un état d'échec."""


@dataclass(frozen=True)
class EtatConsole:
    """État de la console tel qu'il sera RENDU — jamais un booléen nu.

    `disponible=False` s'accompagne TOUJOURS d'une `cause` non vide : c'est
    le tuple `(valeur, ok)` de la règle zéro silencieux, sous une forme que
    l'appelant ne peut pas lire à moitié. Un état d'échec sans cause
    afficherait « indisponible » sans donner la moindre prise à l'exploitant
    pour distinguer un service arrêté d'une erreur de configuration.
    """

    disponible: bool
    cause: str = ""


async def _sonder_console() -> EtatConsole:
    """Vérifie que la console répond, AVANT de rendre l'iframe.

    Interroge l'amont DIRECTEMENT (`settings.akvorado_console_url`) plutôt que
    de repasser par le proxy : la sonde tourne dans le même processus que le
    proxy, une requête HTTP vers soi-même dépendrait de la boucle d'événements
    en train de traiter CETTE requête. La cible reste la configuration serveur,
    jamais une entrée utilisateur (même garde anti-SSRF que le proxy).

    TOUTE réponse d'ERREUR (>= 400) est traitée comme un échec de la sonde :
    une console qui rend un 404 ou un 503 n'est pas une page à cadrer —
    l'encadrer montrerait la page d'erreur de l'amont dans un cadre, sans que
    l'exploitant sache que c'est le service et non Okvorado qui a échoué.

    ⚠️ LE SEUIL EST À 400, PAS À 500 — défaut mesuré le 2026-08-10 par une
    relecture à contexte vierge, alors que la suite de tests était VERTE (le
    test ne couvrait que 503). Avec un seuil à 500, un 4xx passait la sonde et
    l'écran rendait le cadre : la console qui démarre sans que son
    orchestrateur ait poussé la config répond 404 sur `/`, et l'exploitant
    voyait un cadre quasi-blanc portant l'erreur brute de l'amont. Sur un
    401/403 c'est pire encore : il en conclurait qu'Okvorado l'a mal
    authentifié alors que le défaut est à l'autre bout. Un 4xx amont est
    exactement aussi inexploitable qu'un 5xx pour qui veut voir la console.
    """
    try:
        async with httpx.AsyncClient(timeout=_SONDE_TIMEOUT) as client:
            # `GET` et non `HEAD`, alors que seul le CODE DE STATUT nous
            # intéresse : un `HEAD` économiserait le corps de l'`index.html`
            # (que le navigateur redemandera de toute façon via l'iframe),
            # mais beaucoup de serveurs de fichiers statiques répondent 405 à
            # un `HEAD`. Avec le seuil à 400 ci-dessous, ce 405 ferait
            # DÉCLARER LA CONSOLE INDISPONIBLE alors qu'elle fonctionne — un
            # faux négatif, exactement le symétrique du défaut qu'on vient de
            # corriger. Le surcoût (un index.html, quelques Ko) est le prix
            # d'une sonde qui ne se trompe pas.
            response = await client.get(settings.akvorado_console_url)
    except httpx.HTTPError as exc:
        log.error("ecran akvorado: la console n'a pas repondu a la sonde: %s", exc)
        # `str(exc)` peut être vide sur certaines exceptions httpx : on retombe
        # alors sur le nom de la classe plutôt que sur une cause VIDE, qui
        # afficherait « indisponible » sans rien expliquer (zéro silencieux).
        return EtatConsole(disponible=False, cause=str(exc) or type(exc).__name__)

    if response.status_code >= 400:
        log.error("ecran akvorado: console en erreur, statut=%d", response.status_code)
        return EtatConsole(
            disponible=False,
            cause=f"la console a répondu avec le statut HTTP {response.status_code}",
        )

    return EtatConsole(disponible=True)


@router.get(EMBED_PATH, include_in_schema=False)
async def get_console_embed(request: Request) -> HTMLResponse:
    """Rend la console Akvorado DANS Okvorado, sous la barre de navigation.

    Monté DERRIÈRE `require_authentication` (`app/main.py`) comme le proxy
    qu'il encadre : la console n'a jamais porté d'authentification propre,
    c'est Okvorado qui la lui apporte.
    """
    etat = await _sonder_console()
    return templates.TemplateResponse(
        request,
        "console_embed.html",
        {
            "active_page": ACTIVE_PAGE,
            "console_disponible": etat.disponible,
            "console_cause": etat.cause,
            # Passé au gabarit plutôt qu'écrit en dur dans le HTML : le préfixe
            # du proxy a UNE seule source de vérité (`proxy_akvorado.PROXY_PREFIX`).
            "console_src": PROXY_PREFIX,
        },
    )
