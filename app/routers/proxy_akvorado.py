"""Reverse proxy vers la console Akvorado — DEMANDE UTILISATEUR (2026-08-09) :

    « pour résoudre l'accès a akvorado, on peut juste y acceder via okvorado
      et le proxyfier vu que c'est un dev perso, on peut le modifier sans
      difficulté »

CONTEXTE (voir `stack/docker-compose.yml`, service `akvorado-console`) : la
console Akvorado ne publie AUCUN port sur l'hôte — elle ne tourne que sur le
réseau docker interne. Sans ce routeur, aucun exploitant ne peut l'atteindre
depuis un navigateur.

CONFIG_HARDCODE_OK: l'adresse réelle de la console (`settings.akvorado_console_url`,
voir `app/config.py`) est résolue depuis l'environnement (`OKVORADO_CONSOLE_HOST`
/ `OKVORADO_CONSOLE_PORT`, avec repli sur `OKVORADO_AKVORADO_HOST`) — ce module
ne code EN DUR aucune adresse de service, il consomme uniquement cette
propriété déjà paramétrable.

POURQUOI PAS LE PROXY GRAFANA (tenté puis ABANDONNÉ, voir docker-compose.yml
et .env.example) : Grafana pose en DUR un en-tête
`Content-Security-Policy: sandbox` sur TOUTES ses réponses de proxy — CSS et
JavaScript inertes, aucun contournement trouvé (même en faisant poser une CSP
permissive par un plugin, Grafana l'écrase). Okvorado, lui, est NOTRE code :
rien ne nous empêche d'ajouter une exception CSP ciblée UNIQUEMENT sur les
réponses de ce proxy (voir `app/main.py::add_security_headers`).

PRÉFIXE RETENU : `/akvorado-console`. Choix explicite (pas `/akvorado`, pas
`/console`) : le nom porte à la fois le produit et le composant, sans
ambiguïté avec un futur proxy vers l'inlet/outlet, et sans collision avec les
routes déjà montées (`/config`, `/inventory`, ...). Passe par `| prefixed`
comme tout chemin absolu du gabarit (voir `app/templating.py::prefixed`) :
sous `OKVORADO_URL_PREFIX`, le lien de menu reste correct.

LA CONSOLE EST UNE SPA (voir mesure du 2026-08-09) : son HTML porte
`<base href="/" />` et ses assets/API sont en chemins RELATIFS
(`./assets/index-*.js`, `api/v0/console/...`). Servie sous un préfixe, ces
chemins relatifs se résolvent CORRECTEMENT tout seuls (résolution URL
standard) — mesuré : assets ET API répondent 200 sous préfixe. La SEULE
correction nécessaire est la balise `<base href="/">`, qui doit pointer vers
le préfixe du proxy plutôt que vers la racine du document (qui serait alors
Okvorado, pas la console). On ne réécrit QUE cette balise : réécrire tout le
corps HTML pour un unique attribut serait fragile (dépendrait du HTML exact
généré par le build Vite de la console, qui peut changer à chaque version
d'Akvorado) et coûteux (charger tout le corps en mémoire alors que le
streaming est justement ce qu'on veut éviter pour les gros payloads/assets).

SÉCURITÉ — ANTI-SSRF : ce proxy ne relaie JAMAIS vers une URL fournie par le
client. La cible est TOUJOURS `settings.akvorado_console_url` (configuration
serveur, jamais une entrée utilisateur) concaténée avec le chemin capturé par
la route. ATTENTION au piège classique : `{path:path}` de Starlette matche
un chemin déjà normalisé par le ROUTAGE (un `..` littéral dans l'URL ne
traverse pas le préfixe de route côté Starlette), mais ce module refait
explicitement sa propre normalisation avant de forger l'URL amont — défense
en profondeur, on ne fait jamais confiance à un seul niveau de validation
pour une primitive SSRF. Voir `_safe_upstream_path()`.
"""

from __future__ import annotations

import logging
import posixpath

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse

from app.config import settings

log = logging.getLogger(__name__)

router = APIRouter(tags=["proxy_akvorado"])

PROXY_PREFIX = "/akvorado-console"
"""Préfixe de montage — RÉFÉRENCÉ depuis `app/templating.py` (lien de menu)
et `tests/`. Un seul endroit source de vérité, jamais recopié en dur ailleurs."""

_TIMEOUT_SECONDS = httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=5.0)
"""Lecture à 30 s (pas les 5 s des appels de complétion `akvorado_console.py`) :
la console peut servir des payloads volumineux (widgets avec beaucoup de
lignes) — un budget serré ferait échouer des requêtes légitimes."""

# En-têtes de la requête ENTRANTE qui ne doivent JAMAIS être relayés tels
# quels vers l'amont : `host` désignerait Okvorado et non la console (la
# plupart des serveurs HTTP se moquent de Host, mais autant rester correct) ;
# les en-têtes de connexion sont gérés par httpx lui-même, les relayer
# créerait une contradiction avec ce qu'httpx pose pour SA PROPRE connexion
# amont (RFC 7230 §6.1 : hop-by-hop headers, ne se relaient jamais tels quels
# entre deux sauts distincts).
_HOP_BY_HOP_REQUEST_HEADERS = frozenset(
    {"host", "connection", "content-length", "transfer-encoding", "keep-alive"}
)
_HOP_BY_HOP_RESPONSE_HEADERS = frozenset(
    {
        "content-length",  # recalculé par le serveur ASGI selon ce qu'on stream réellement
        "transfer-encoding",
        "connection",
        "keep-alive",
        "content-security-policy",  # posée nous-mêmes, voir app/main.py::add_security_headers
        # X-Frame-Options — DÉFAUT MESURÉ le 2026-08-10 en implémentant l'écran
        # d'intégration (`/akvorado`, gabarit `console_embed.html`) : cet
        # en-tête n'était PAS filtré, donc relayé VERBATIM depuis l'amont
        # (mesuré : une console posant `SAMEORIGIN` le rendait tel quel). Or
        # l'écran d'intégration encadre ces réponses dans un `<iframe>` servi
        # par Okvorado : un `DENY` amont rendrait le cadre définitivement
        # BLANC, et le navigateur applique TOUJOURS le plus restrictif entre
        # `X-Frame-Options` et `frame-ancestors` — garder l'en-tête amont
        # annulerait donc l'allowlist que la CSP exprime juste à côté.
        #
        # Le retirer n'ouvre RIEN : la politique de cadrage effective reste
        # posée par Okvorado lui-même via `frame-ancestors` (voir
        # `app/main.py::add_security_headers`), qui est le mécanisme MODERNE
        # et le seul capable d'exprimer une allowlist de plusieurs origines.
        # C'est la même décision, et pour la même raison, que le retrait de
        # `X-Frame-Options` sur les pages normales documenté dans main.py.
        # L'amont ne sait rien du proxy devant lui : ce n'est pas à lui de
        # décider qui peut encadrer ce qu'Okvorado sert.
        "x-frame-options",
    }
)

_BASE_HREF_NEEDLE = b'<base href="/" />'
"""Forme EXACTE mesurée le 2026-08-09 dans le HTML servi par la console
Akvorado (build Vite). Une correspondance stricte plutôt qu'une regex
tolérante : si le build change cette forme (espace, guillemets, self-closing),
on préfère ne RIEN réécrire et laisser le défaut visible à l'écran (assets en
404) plutôt que de risquer de corrompre un autre `<base>` par accident."""


def _safe_upstream_path(raw_path: str) -> str:
    """Normalise le chemin capturé et refuse toute tentative de sortie du préfixe.

    Défense en profondeur (voir docstring de tête) : `posixpath.normpath`
    résout `.`/`..`, puis on vérifie explicitement que le résultat ne
    commence pas par `..` (sortie vers le parent) et n'est pas absolu vers un
    autre arbre. Un chemin vide ou `.` après normalisation retombe sur `""`
    (racine de la console) plutôt que sur `.` littéral.
    """
    normalized = posixpath.normpath("/" + raw_path).lstrip("/")
    if normalized == ".":
        return ""
    if normalized.startswith("..") or normalized.startswith("/"):
        raise HTTPException(status_code=400, detail="chemin invalide")
    return normalized


def _rewrite_base_href(body: bytes, prefix: str) -> bytes:
    """Réécrit UNIQUEMENT `<base href="/" />` vers `<base href="{prefix}/" />`.

    C'est LE point technique central (voir docstring de tête) : la console
    est une SPA dont tous les chemins relatifs se résolvent contre cette
    balise. Ne touche à rien d'autre dans le corps — un `replace` ciblé sur
    une aiguille exacte, pas une réécriture générale du HTML.
    """
    target = f'<base href="{prefix}/" />'.encode()
    return body.replace(_BASE_HREF_NEEDLE, target)


def _filtered_request_headers(request: Request) -> dict[str, str]:
    return {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in _HOP_BY_HOP_REQUEST_HEADERS
    }


def _filtered_response_headers(response: httpx.Response) -> dict[str, str]:
    return {
        key: value
        for key, value in response.headers.items()
        if key.lower() not in _HOP_BY_HOP_RESPONSE_HEADERS
    }


async def _proxy(request: Request, raw_path: str) -> HTMLResponse | StreamingResponse:
    upstream_path = _safe_upstream_path(raw_path)
    # Cible TOUJOURS dérivée de la configuration serveur — jamais d'entrée
    # utilisateur dans le choix de l'hôte/port (anti-SSRF, voir docstring de
    # tête). Seul le CHEMIN (déjà validé ci-dessus) et la query varient.
    upstream_url = f"{settings.akvorado_console_url}/{upstream_path}"

    body = await request.body()
    client = httpx.AsyncClient(timeout=_TIMEOUT_SECONDS)
    try:
        upstream_request = client.build_request(
            request.method,
            upstream_url,
            params=request.query_params,
            content=body,
            headers=_filtered_request_headers(request),
        )
        upstream_response = await client.send(upstream_request, stream=True)
    except httpx.HTTPError as exc:
        await client.aclose()
        # Dégradation VISIBLE (règle zéro silencieux du projet) : un 502
        # explicite plutôt qu'une page blanche ou un swap HTMX silencieux —
        # l'exploitant doit comprendre que c'est la console, pas Okvorado,
        # qui n'a pas répondu à CETTE requête précise.
        log.error("proxy akvorado-console: echec de requete vers %s: %s", upstream_url, exc)
        raise HTTPException(
            status_code=502, detail="la console Akvorado n'a pas répondu à cette requête"
        ) from exc

    content_type = upstream_response.headers.get("content-type", "")
    headers = _filtered_response_headers(upstream_response)

    if content_type.startswith("text/html"):
        # Corps HTML : lu en entier (ce sont des pages, pas des flux volumineux —
        # contrairement aux assets/API ci-dessous, qui restent en streaming) pour
        # pouvoir y réécrire la balise <base>. `PROXY_PREFIX` et pas `raw_path` :
        # la balise doit toujours pointer la RACINE du proxy, quelle que soit la
        # sous-page HTML demandée (la console est une SPA à route unique côté
        # serveur : `index.html` sert toutes les routes front).
        raw_body = await upstream_response.aread()
        await upstream_response.aclose()
        await client.aclose()
        rewritten = _rewrite_base_href(raw_body, PROXY_PREFIX)
        return HTMLResponse(
            content=rewritten,
            status_code=upstream_response.status_code,
            headers=headers,
        )

    # Assets (JS/CSS/images) et API JSON : STREAMÉS sans charger tout le corps
    # en mémoire — un asset applicatif ou un export volumineux ne doit pas
    # être bufferisé intégralement côté Okvorado.
    async def _stream() -> object:
        try:
            async for chunk in upstream_response.aiter_raw():
                yield chunk
        finally:
            await upstream_response.aclose()
            await client.aclose()

    return StreamingResponse(
        _stream(),
        status_code=upstream_response.status_code,
        headers=headers,
        # Content-Type relayé via `headers` (non filtré ci-dessus) — c'est
        # PRÉCISÉMENT le point exigé par le brief : sans lui, CSS et JS ne
        # s'exécutent jamais (le navigateur les ignore hors `text/css` /
        # `.../javascript` déclaré).
    )


@router.api_route(
    PROXY_PREFIX,
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    include_in_schema=False,
    # Réponse à type UNION (HTML pour la page, streaming pour assets/API) :
    # FastAPI tente sinon de construire un modèle Pydantic de réponse à partir
    # de l'annotation et échoue à la définition de la route (`FastAPIError:
    # Invalid args for response field`) — désactivé, ce routeur ne documente
    # de toute façon aucun schéma (`include_in_schema=False` ci-dessus).
    response_model=None,
)
async def proxy_akvorado_console_root(request: Request) -> HTMLResponse | StreamingResponse:
    """Racine de la console (`/akvorado-console` sans slash final)."""
    return await _proxy(request, "")


@router.api_route(
    PROXY_PREFIX + "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    include_in_schema=False,
    response_model=None,  # même raison que proxy_akvorado_console_root ci-dessus
)
async def proxy_akvorado_console(request: Request, path: str) -> HTMLResponse | StreamingResponse:
    """Relaie toute méthode vers la console Akvorado, sous `PROXY_PREFIX`.

    Monté DERRIÈRE `require_authentication` (`app/main.py`) comme toute autre
    route de l'application — cette route ne fait PARTIE d'aucune allowlist
    publique, donc une session valide est exigée avant d'atteindre `_proxy`.
    C'est tout l'intérêt du proxy : la console hérite de la protection
    qu'elle n'a jamais eue elle-même.
    """
    return await _proxy(request, path)
