"""Tests de l'ÉCRAN D'INTÉGRATION de la console Akvorado dans Okvorado.

DEMANDE UTILISATEUR (2026-08-10) : « il manque l'intégration de l'interface
web d'akvorado dans okvorado pour le laisser juste dans l'internal network et
plus accessible a distance ».

Le reverse proxy (`app/routers/proxy_akvorado.py`) existait déjà et la console
ne publie plus aucun port sur l'hôte — la moitié « plus accessible à distance »
était donc acquise. Ce qui MANQUAIT est l'intégration proprement dite : le
menu portait `target="_blank"`, donc cliquer « Akvorado » SORTAIT d'Okvorado
pour ouvrir un onglet séparé. L'exploitant quittait l'application.

Cet écran (`GET /akvorado`, gabarit `console_embed.html`) encadre la console
DANS Okvorado, sous la barre de navigation, via un `<iframe>` MÊME ORIGINE
pointant sur le proxy.

POURQUOI L'IFRAME ET PAS UN RENDU DIRECT DU HTML PROXIFIÉ (décidé par la
mesure du 2026-08-10, pas par intuition) : la console est une SPA Vue dont
tout le routage est côté client et dont les chemins se résolvent contre une
balise `<base href>`. L'injecter dans un gabarit Jinja mettrait DEUX `<base>`
et deux racines de document concurrentes dans une même page — le proxy
réécrit justement `<base>` pour que la SPA fonctionne, ce que le rendu direct
casserait. L'iframe conserve à la console son propre document, donc sa
balise `<base>`, son routeur et ses appels d'API intacts.

Les DEUX blocages d'encadrement mesurés (X-Frame-Options relayé, et
`frame-ancestors` sans `'self'`) sont couverts par
`tests/test_proxy_akvorado.py::TestCadrageDeLaConsole` — ils portent sur les
en-têtes du proxy, pas sur cet écran.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers.proxy_akvorado import PROXY_PREFIX
from tests.conftest import authenticated_test_client

EMBED_PATH = "/akvorado"
"""Chemin de l'écran d'intégration. DISTINCT de `PROXY_PREFIX`
(`/akvorado-console`) : l'un est une page Okvorado avec sa barre de
navigation, l'autre est le flux relayé de la console. Les confondre ferait
que l'écran s'encadrerait lui-même à l'infini."""


def _install_upstream(monkeypatch: pytest.MonkeyPatch, handler: Callable) -> list[httpx.Request]:
    """Intercepte les `httpx.AsyncClient` — même mécanisme que
    `tests/test_proxy_akvorado.py::_install_upstream` (aucun accès réseau)."""
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


def _console_disponible(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, text="OK", headers={"content-type": "text/html"})


class TestEcranIntegre:
    def test_l_ecran_rend_une_page_okvorado_complete(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """La console doit s'afficher SOUS la barre de navigation d'Okvorado.

        C'est l'exigence même de la demande : l'exploitant « reste chez lui ».
        Une page qui n'hériterait pas de `base.html` serait un onglet déguisé.
        """
        _install_upstream(monkeypatch, _console_disponible)
        client = authenticated_test_client(app)

        response = client.get(EMBED_PATH)

        assert response.status_code == 200
        assert '<nav class="nav">' in response.text, (
            "l'écran ne porte pas la barre de navigation d'Okvorado : "
            "l'exploitant a quitté l'application"
        )

    def test_l_ecran_encadre_la_console_via_le_proxy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """L'iframe doit viser le PROXY (même origine), jamais l'URL directe
        de la console — qui ne publie plus aucun port et ne répondrait pas."""
        _install_upstream(monkeypatch, _console_disponible)
        client = authenticated_test_client(app)

        response = client.get(EMBED_PATH)

        assert "<iframe" in response.text, "aucun iframe : la console n'est pas intégrée"
        assert f'src="{PROXY_PREFIX}' in response.text, (
            f"l'iframe ne pointe pas sur {PROXY_PREFIX} — une URL directe vers "
            "la console ne répondrait pas (port non publié)"
        )

    def test_l_ecran_ne_s_encadre_pas_lui_meme(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Garde-fou : `src` visant `/akvorado` (l'écran) au lieu de
        `/akvorado-console` (le proxy) produirait une récursion infinie
        d'iframes. Les deux chemins se ressemblent — d'où ce test."""
        _install_upstream(monkeypatch, _console_disponible)
        client = authenticated_test_client(app)

        response = client.get(EMBED_PATH)

        assert f'src="{EMBED_PATH}"' not in response.text
        assert f"src=\"{EMBED_PATH}'" not in response.text


class TestZeroSilencieux:
    """RÈGLE DURE DU PROJET : un échec rend un état DISTINCT et VISIBLE.

    Le piège précis ici : un `<iframe>` dont la source ne répond pas rend un
    CADRE BLANC. Rien ne distingue à l'œil « la console est morte » de « la
    page charge encore » — exactement la valeur neutre que la règle interdit.
    L'écran doit donc SONDER la console avant de rendre le cadre, et afficher
    un état explicite avec sa cause quand elle ne répond pas.
    """

    def test_console_injoignable_affiche_un_etat_explicite_pas_un_cadre_vide(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connexion refusee")

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.get(EMBED_PATH)

        assert response.status_code == 200, (
            "l'écran doit rendre la page Okvorado avec un message, pas une "
            "erreur brute qui ferait perdre la navigation"
        )
        assert "indisponible" in response.text.lower(), (
            "aucun état explicite : l'exploitant verrait un cadre blanc "
            "indiscernable d'un chargement en cours"
        )
        assert "<iframe" not in response.text, (
            "un iframe est rendu alors que la console ne répond pas : "
            "c'est précisément le cadre blanc que la règle interdit"
        )

    def test_la_cause_de_l_indisponibilite_est_affichee(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """« indisponible » sans la cause laisse l'exploitant sans prise :
        le brief exige « + la cause »."""

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connexion refusee vers akvorado-console")

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.get(EMBED_PATH)

        assert "connexion refusee" in response.text, (
            "la cause technique n'est pas rendue : l'exploitant ne peut pas "
            "distinguer un service arrêté d'une erreur de configuration"
        )

    @pytest.mark.parametrize("statut", [403, 404, 500, 502, 503])
    def test_un_code_d_erreur_amont_est_signale_et_non_encadre(
        self, monkeypatch: pytest.MonkeyPatch, statut: int
    ) -> None:
        """Toute réponse d'ERREUR amont est un ÉCHEC, pas une page à cadrer.

        Sans ce contrôle, l'iframe afficherait la page d'erreur de l'amont
        dans un cadre — visuellement proche d'une console cassée sans qu'on
        sache que c'est le service, pas Okvorado, qui a échoué.

        ⚠️ DÉFAUT MESURÉ le 2026-08-10 par une relecture à contexte vierge,
        alors que cette suite était VERTE : le seuil ne couvrait que `>= 500`,
        et ce test ne vérifiait QUE 503. Un 4xx passait donc la sonde et
        l'écran rendait le cadre. Cas concret : la console démarre mais son
        orchestrateur n'a pas encore poussé la config, elle répond 404 sur
        `/` — l'exploitant voyait un cadre quasi-blanc portant l'erreur brute
        de l'amont. Pire sur un 401/403 : il en conclurait qu'Okvorado l'a mal
        authentifié. D'où la PARAMÉTRISATION : tester un seul code laissait
        précisément passer le défaut que ce test existe pour attraper.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(statut, text="erreur amont")

        _install_upstream(monkeypatch, handler)
        client = authenticated_test_client(app)

        response = client.get(EMBED_PATH)

        assert "indisponible" in response.text.lower()
        assert str(statut) in response.text, "le code de statut amont n'est pas rendu"
        assert "<iframe" not in response.text, (
            f"un cadre est rendu alors que la console répond {statut} : "
            "l'exploitant verrait la page d'erreur de l'amont dans un iframe"
        )


class TestProtectionParSession:
    def test_l_ecran_exige_une_session_valide(self) -> None:
        """Même exigence que le proxy : la console n'a jamais eu
        d'authentification propre, c'est Okvorado qui la porte."""
        client = TestClient(app)  # aucune session

        response = client.get(EMBED_PATH, follow_redirects=False)

        assert response.status_code in (303, 401)


class TestNavigationCoherente:
    def test_le_menu_marque_l_onglet_actif_sur_cet_ecran(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Exigence 4 du brief : l'entrée « Akvorado » se comporte comme les
        autres onglets. Sans `active`, l'exploitant ne sait pas où il est."""
        _install_upstream(monkeypatch, _console_disponible)
        client = authenticated_test_client(app)

        response = client.get(EMBED_PATH)

        marqueur = f'href="{EMBED_PATH}" class="active"'
        assert marqueur in response.text, (
            f"l'onglet Akvorado n'est pas marqué actif ({marqueur!r} absent) : "
            "le menu ne reflète pas la page courante"
        )
