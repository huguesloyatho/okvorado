"""Tests du reverse proxy vers la console Akvorado (`app/routers/proxy_akvorado.py`).

CONTEXTE — voir la docstring de tête de `app/routers/proxy_akvorado.py` :
la console Akvorado ne publie aucun port sur l'hôte (réseau docker interne
uniquement), le proxy est le SEUL chemin d'accès pour un exploitant, monté
DERRIÈRE l'authentification d'Okvorado.

Comme `tests/test_akvorado_console.py` (même convention), aucun test ici ne
touche un vrai réseau : `httpx.AsyncClient` est intercepté par un
`httpx.MockTransport` qui simule la console.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.routers.proxy_akvorado import PROXY_PREFIX
from tests.conftest import authenticated_test_client


def _streamed(
    status_code: int, *, content: bytes, headers: dict[str, str]
) -> httpx.Response:
    """Construit une réponse `httpx` dont le corps N'EST PAS pré-consommé.

    PIÈGE MESURÉ EN ÉCRIVANT CES TESTS : `httpx.Response(200, json=...)` (ou
    `content=`/`text=`) marque le corps comme DÉJÀ LU au moment même de la
    construction — `.aiter_raw()` lève alors `StreamConsumed`, alors que ce
    même appel réussit face à un VRAI serveur réseau (le corps y est
    réellement en cours de réception). Le code du proxy (`stream=True` +
    `aiter_raw()`, voir `app/routers/proxy_akvorado.py::_proxy`) est le
    pattern httpx standard pour ne jamais bufferiser un gros payload — c'est
    la fixture de test qui doit reproduire fidèlement un flux non consommé,
    via `httpx.ByteStream`, plutôt que le code proxy qui doit changer."""
    return httpx.Response(status_code, headers=headers, stream=httpx.ByteStream(content))


def _install_upstream(monkeypatch: pytest.MonkeyPatch, handler: Callable) -> list[httpx.Request]:
    """Intercepte tout `httpx.AsyncClient` créé par le proxy et route vers `handler`.

    Même mécanisme que `tests/test_akvorado_console.py::_install` : un
    `httpx.MockTransport` simule la console SANS toucher au réseau, et
    enregistre chaque requête reçue pour permettre d'asserter dessus (méthode,
    corps, en-têtes, chemin demandé côté amont).
    """
    received: list[httpx.Request] = []
    original = httpx.AsyncClient

    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs.pop("transport", None)

        def _wrapped(request: httpx.Request) -> httpx.Response:
            received.append(request)
            return handler(request)

        return original(*args, transport=httpx.MockTransport(_wrapped), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return received


class TestMethodesRelayees:
    def test_get_est_relaye_et_le_corps_amont_est_rendu(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "GET"
            return _streamed(
                200,
                content=b'{"widget": "flow-last", "value": 42}',
                headers={"content-type": "application/json"},
            )

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.get(f"{PROXY_PREFIX}/api/v0/console/widget/flow-last")

        assert response.status_code == 200
        assert response.json() == {"widget": "flow-last", "value": 42}

    def test_post_est_relaye_avec_son_corps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """La console interroge sa propre API en POST (filtres, complétion) :
        le proxy doit transmettre le corps, pas seulement la méthode."""
        received_bodies: list[bytes] = []

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.method == "POST"
            received_bodies.append(request.content)
            return _streamed(
                200, content=b'{"message": "ok"}', headers={"content-type": "application/json"}
            )

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.post(
            f"{PROXY_PREFIX}/api/v0/console/filter/validate",
            json={"filter": "InIfBoundary = external"},
        )

        assert response.status_code == 200
        assert response.json() == {"message": "ok"}
        assert received_bodies == [b'{"filter":"InIfBoundary = external"}']


class TestContentTypePreserve:
    @pytest.mark.parametrize(
        "content_type",
        [
            "application/javascript",
            "text/css; charset=utf-8",
            "application/json",
        ],
    )
    def test_le_content_type_amont_est_transmis_tel_quel(
        self, monkeypatch: pytest.MonkeyPatch, content_type: str
    ) -> None:
        """Sans ce relais, CSS et JS ne s'exécutent jamais côté navigateur —
        c'est le point exigé explicitement par le brief."""

        def handler(request: httpx.Request) -> httpx.Response:
            return _streamed(200, content=b"body", headers={"content-type": content_type})

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.get(f"{PROXY_PREFIX}/assets/index-abc123.js")

        assert response.headers["content-type"].startswith(content_type.split(";")[0])


class TestReecritureBaseHref:
    def test_la_balise_base_href_est_reecrite_vers_le_prefixe(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """LE point technique central (voir docstring du module) : la SPA
        résout tous ses chemins relatifs contre cette balise."""

        def handler(request: httpx.Request) -> httpx.Response:
            html = (
                "<!doctype html><html><head>"
                '<base href="/" />'
                '<script src="./assets/index-abc.js"></script>'
                "</head><body></body></html>"
            )
            return httpx.Response(
                200, text=html, headers={"content-type": "text/html; charset=utf-8"}
            )

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.get(PROXY_PREFIX)

        assert response.status_code == 200
        assert f'<base href="{PROXY_PREFIX}/" />' in response.text
        # Le reste du corps est INTACT : seule la balise <base> est réécrite,
        # jamais une réécriture générale du HTML (voir docstring de tête).
        assert '<script src="./assets/index-abc.js"></script>' in response.text

    def test_un_html_sans_la_balise_exacte_est_rendu_sans_modification(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Si le build change la forme de `<base>`, on préfère ne RIEN
        réécrire plutôt que de risquer une correspondance approximative."""

        def handler(request: httpx.Request) -> httpx.Response:
            html = "<!doctype html><html><head><base href='/'></head><body></body></html>"
            return httpx.Response(
                200, text=html, headers={"content-type": "text/html; charset=utf-8"}
            )

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.get(PROXY_PREFIX)

        assert response.status_code == 200
        assert "<base href='/'>" in response.text


class TestLaSpaResteUtilisable:
    """EXIGENCE 5 du brief (2026-08-10) : une fois encadrée, la console doit
    rester UTILISABLE — c'est une SPA Vue avec son routage interne.

    Le point vérifié ici est celui que la réécriture de `<base href>` sert :
    les chemins de la console (assets, appels d'API) doivent arriver à l'amont
    DÉBARRASSÉS du préfixe du proxy. Si le préfixe fuyait vers l'amont, la
    console recevrait `/akvorado-console/api/v0/...` et répondrait 404 — les
    tests de relais ci-dessus resteraient pourtant verts, puisqu'ils
    n'inspectent pas le chemin RÉELLEMENT demandé côté console.
    """

    @pytest.mark.parametrize(
        "chemin_demande",
        [
            "assets/index-abc123.js",
            "assets/index-def456.css",
            "api/v0/console/widget/flow-last",
        ],
    )
    def test_le_prefixe_du_proxy_n_atteint_jamais_la_console(
        self, monkeypatch: pytest.MonkeyPatch, chemin_demande: str
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return _streamed(
                200, content=b"ok", headers={"content-type": "application/octet-stream"}
            )

        recues = _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        client.get(f"{PROXY_PREFIX}/{chemin_demande}")

        assert len(recues) == 1
        assert recues[0].url.path == f"/{chemin_demande}", (
            f"la console a reçu {recues[0].url.path!r} : le préfixe du proxy a "
            "fui vers l'amont, elle répondrait 404 sur ses propres actifs"
        )


class TestAntiSSRF:
    def test_un_chemin_qui_tente_de_sortir_du_prefixe_est_refuse(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`../` ne doit jamais permettre de sortir de l'arbre de la console."""
        called: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            called.append(str(request.url))
            return httpx.Response(200, text="ne devrait jamais etre atteint")

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        # Starlette normalise déjà `..` au routage pour la plupart des cas ;
        # ce test vérifie la défense EXPLICITE de `_safe_upstream_path` en
        # forçant un chemin dont la normalisation posixpath sort du préfixe.
        response = client.get(f"{PROXY_PREFIX}/../../etc/passwd")

        assert response.status_code in (400, 404)
        assert called == [], "la console amont ne doit jamais recevoir cette requete"

    def test_la_cible_amont_vient_toujours_de_la_configuration_serveur(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Aucune entrée utilisateur (query, header, corps) ne doit pouvoir
        changer l'hôte/port cible — seul `settings.akvorado_console_url` le peut."""
        received_hosts: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            received_hosts.append(request.url.host)
            return _streamed(
                200, content=b'{"ok": true}', headers={"content-type": "application/json"}
            )

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        # Un client hostile tente d'injecter une cible différente via un
        # en-tête ou un paramètre de requête : sans effet, l'hôte amont reste
        # celui de la configuration.
        client.get(
            f"{PROXY_PREFIX}/api/v0/console/widget/flow-last",
            headers={"Host": "attacker.example", "X-Forwarded-Host": "attacker.example"},
            params={"target": "http://attacker.example"},
        )

        assert received_hosts == [settings.effective_console_host]


class TestProtectionParSession:
    def test_le_proxy_exige_une_session_valide(self) -> None:
        """Le proxy est monté comme toute autre route : DERRIÈRE
        `require_authentication` — c'est tout l'intérêt du proxy."""
        client = TestClient(app)  # PAS authenticated_test_client : aucune session

        response = client.get(
            f"{PROXY_PREFIX}/api/v0/console/widget/flow-last", follow_redirects=False
        )

        assert response.status_code in (303, 401)


class TestCspNonAffaiblie:
    def test_une_page_normale_okvorado_garde_la_csp_stricte(self) -> None:
        """La CSP des pages normales (`script-src 'self'` SANS unsafe-inline)
        ne doit JAMAIS être affaiblie par l'ajout de l'exception proxy."""
        client = authenticated_test_client(app)

        response = client.get("/exporters")

        csp = response.headers.get("content-security-policy", "")
        script_src_segment = csp.split("style-src")[0]
        assert "script-src 'self'" in csp
        assert "unsafe-inline" not in script_src_segment

    def test_les_reponses_du_proxy_recoivent_la_csp_permissive_ciblee(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """La console (Vue/Vite) a besoin de `unsafe-inline` pour ses styles —
        cette exception ne doit s'appliquer QU'À ce préfixe (voir test ci-dessus)."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html></html>", headers={"content-type": "text/html"})

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.get(PROXY_PREFIX)

        csp = response.headers.get("content-security-policy", "")
        assert "script-src 'self' 'unsafe-inline'" in csp


class TestCadrageDeLaConsole:
    """L'INTÉGRATION de la console DANS Okvorado — demande utilisateur
    (2026-08-10) : « il manque l'intégration de l'interface web d'akvorado dans
    okvorado ».

    DEUX BLOCAGES MESURÉS le 2026-08-10 avant d'écrire ces tests (mesure, pas
    supposition — le brief prévenait explicitement du piège) :

    1. `X-Frame-Options` de l'AMONT était relayé TEL QUEL (mesuré : la console
       simulée pose `SAMEORIGIN`, le proxy le rendait verbatim). Il n'était
       PAS dans `_HOP_BY_HOP_RESPONSE_HEADERS`. Une console qui poserait
       `DENY` rendrait le cadre définitivement vide — et `X-Frame-Options` est
       l'ancêtre non-négociable : le navigateur applique TOUJOURS le plus
       restrictif entre lui et `frame-ancestors`.
    2. `frame-ancestors` valait `http://localhost:3000` (l'origine Grafana)
       SANS `'self'`. Or l'encadrant ici est Okvorado LUI-MÊME : même origine.
       Sans `'self'`, le navigateur refuse le rendu de son propre iframe.

    Les deux se corrigent UNIQUEMENT pour les réponses du proxy — la CSP des
    pages normales d'Okvorado reste strictement inchangée (couvert par
    `TestCspNonAffaiblie` ci-dessus, qui doit rester vert).
    """

    def test_x_frame_options_de_l_amont_n_est_jamais_relaye(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """BLOCAGE 1 MESURÉ : un `X-Frame-Options` amont casse l'encadrement.

        Le proxy doit le NEUTRALISER pour sa propre origine — c'est Okvorado
        qui décide qui peut encadrer les réponses qu'il sert, pas un en-tête
        hérité d'un service qui ignore tout du proxy devant lui.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                text='<!doctype html><html><head><base href="/" /></head><body></body></html>',
                headers={
                    "content-type": "text/html; charset=utf-8",
                    "x-frame-options": "DENY",
                },
            )

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.get(PROXY_PREFIX)

        assert "x-frame-options" not in {k.lower() for k in response.headers}, (
            "X-Frame-Options relayé depuis l'amont : le navigateur refusera "
            "d'afficher la console dans l'iframe d'Okvorado, cadre vide."
        )

    def test_x_frame_options_est_aussi_neutralise_sur_les_assets(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """La neutralisation ne doit pas dépendre du Content-Type.

        Le corps HTML et les assets empruntent DEUX chemins de code distincts
        dans `_proxy` (lecture complète vs streaming) : un filtre posé sur le
        seul chemin HTML laisserait passer l'en-tête sur l'autre.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return _streamed(
                200,
                content=b"console.log(1)",
                headers={
                    "content-type": "application/javascript",
                    "x-frame-options": "SAMEORIGIN",
                },
            )

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.get(f"{PROXY_PREFIX}/assets/index-abc.js")

        assert "x-frame-options" not in {k.lower() for k in response.headers}

    def test_la_csp_du_proxy_autorise_l_encadrement_par_okvorado_lui_meme(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """BLOCAGE 2 MESURÉ : `frame-ancestors` sans `'self'`.

        L'écran d'intégration est servi par Okvorado et encadre une réponse
        servie par Okvorado : c'est la MÊME origine, donc `'self'`. Sans lui,
        l'iframe reste vide alors que le proxy répond 200.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text="<html></html>", headers={"content-type": "text/html"}
            )

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.get(PROXY_PREFIX)

        csp = response.headers.get("content-security-policy", "")
        ancetres = csp.split("frame-ancestors")[1]
        assert "'self'" in ancetres, (
            f"frame-ancestors={ancetres.strip()!r} n'autorise pas 'self' : "
            "Okvorado ne peut pas encadrer sa propre réponse de proxy."
        )

    def test_les_origines_configurees_restent_autorisees_a_encadrer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ajouter `'self'` ne doit RIEN retirer : Grafana (porte d'entrée
        unique, cf. `Settings.frame_ancestors`) doit continuer d'encadrer."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text="<html></html>", headers={"content-type": "text/html"}
            )

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.get(PROXY_PREFIX)

        csp = response.headers.get("content-security-policy", "")
        assert settings.frame_ancestors in csp, (
            "les origines configurées ont disparu de frame-ancestors"
        )

    def test_frame_ancestors_n_est_jamais_ouvert_a_toutes_les_origines(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Garde-fou anti-clickjacking : corriger l'encadrement ne doit jamais
        se faire en ouvrant `*` — l'ajustement reste AU PLUS ÉTROIT."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, text="<html></html>", headers={"content-type": "text/html"}
            )

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.get(PROXY_PREFIX)

        csp = response.headers.get("content-security-policy", "")
        ancetres = csp.split("frame-ancestors")[1]
        assert "*" not in ancetres, "frame-ancestors ouvert à toute origine"
