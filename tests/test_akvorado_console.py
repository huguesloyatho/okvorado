"""Client de l'API de filtres de la console Akvorado.

Akvorado sait déjà compléter et valider ses propres filtres — Okvorado ne s'en
servait pas et offrait une zone de texte libre où l'opérateur devait connaître
la syntaxe et les noms de colonnes par cœur.

Le contrat testé ici a été vérifié À LA SOURCE (console/filter.go du dépôt
akvorado/akvorado) PUIS contre la console de production le 2026-08-06 :

    complete(what=column, prefix=Exporter)  -> ExporterAddress, ExporterGroup…
    complete(what=value, column=ExporterName) -> proxy-frontal, clm, routeur-agence-13…
                                                 (valeurs RÉELLES, quoted=True)
    validate("InIfBoundary = external")     -> "ok"
    validate("InIfBoundary === bidon")      -> "at line 1, position 15: …"

Les tests ci-dessous rejouent ces formes exactes sur un transport simulé : ils
ne dépendent pas de la disponibilité de la console, mais ils décrivent son
comportement réel et non un contrat inventé.
"""

from __future__ import annotations

import httpx
import pytest

from app.clients.akvorado_console import (
    Completion,
    ConsoleUnavailable,
    complete_filter,
    validate_filter,
)


def _transport(handler: object) -> httpx.MockTransport:
    return httpx.MockTransport(handler)  # type: ignore[arg-type]


@pytest.fixture
def console_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """Console répondant comme celle de production (payloads réels)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/filter/complete"):
            return httpx.Response(
                200,
                json={
                    "completions": [
                        {"label": "proxy-frontal", "detail": "exporter name", "quoted": True},
                        {"label": "clm", "detail": "exporter name", "quoted": True},
                    ]
                },
            )
        return httpx.Response(200, json={"message": "ok", "parsed": "InIfBoundary = 2"})

    _install(monkeypatch, handler)


def _install(monkeypatch: pytest.MonkeyPatch, handler: object) -> None:
    original = httpx.AsyncClient

    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs.pop("transport", None)
        return original(*args, transport=_transport(handler), **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "AsyncClient", factory)


class TestAutocompletion:
    @pytest.mark.anyio
    async def test_les_valeurs_reelles_sont_remontees_avec_leur_besoin_de_quotes(
        self, console_ok: None
    ) -> None:
        """`quoted` vient de la CONSOLE, jamais d'une règle devinée côté client.

        `ExporterName = 'proxy-frontal'` a besoin des guillemets, `SrcPort = 443`
        non. Deviner cette règle produirait des filtres syntaxiquement faux —
        acceptés à la saisie, rejetés par Akvorado ensuite.
        """
        completions = await complete_filter("value", column="ExporterName")

        assert completions == [
            Completion(label="proxy-frontal", detail="exporter name", quoted=True),
            Completion(label="clm", detail="exporter name", quoted=True),
        ]

    @pytest.mark.anyio
    async def test_une_entree_sans_label_est_ignoree_sans_casser_la_liste(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Une suggestion malformée ne doit pas faire disparaître les autres."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"completions": [{"detail": "sans label"}, {"label": "clm"}]},
            )

        _install(monkeypatch, handler)
        completions = await complete_filter("value", column="ExporterName")

        assert [c.label for c in completions] == ["clm"]


class TestValidation:
    @pytest.mark.anyio
    async def test_un_filtre_valide_est_accepte(self, console_ok: None) -> None:
        result = await validate_filter("InIfBoundary = external")
        assert result.ok is True

    @pytest.mark.anyio
    async def test_l_erreur_conserve_la_position_renvoyee_par_la_console(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Message réel de la console, pas un « filtre invalide » générique.

        Pointer le caractère fautif est ce qui distingue un message utile d'un
        message qui laisse chercher.
        """
        message = (
            'at line 1, position 15: no match found, expected: "--", "/*", '
            '"external"i, "internal"i, "undefined"i or [ \\n\\r\\t]'
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"message": message})

        _install(monkeypatch, handler)
        result = await validate_filter("InIfBoundary === bidon")

        assert result.ok is False
        assert "position 15" in result.message

    @pytest.mark.anyio
    async def test_filtre_vide_est_legitime_et_n_appelle_pas_la_console(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """« Tout le trafic » est un filtre valide, pas une erreur à signaler."""
        appels: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            appels.append(str(request.url))
            return httpx.Response(200, json={"message": "ok"})

        _install(monkeypatch, handler)
        result = await validate_filter("   ")

        assert result.ok is True
        assert appels == [], "un filtre vide ne doit pas déranger la console"


class TestDegradationVisible:
    @pytest.mark.anyio
    async def test_un_appel_en_echec_leve_plutot_que_de_rendre_une_liste_vide(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ZÉRO SILENCIEUX : « aucune valeur » et « échec » sont deux états.

        Rendre `[]` dans les deux cas afficherait le même écran — aucune
        suggestion — et l'opérateur conclurait à tort que sa colonne est vide.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connexion refusée")

        _install(monkeypatch, handler)

        with pytest.raises(ConsoleUnavailable):
            await complete_filter("value", column="ExporterName")

    @pytest.mark.anyio
    async def test_une_reponse_non_json_leve_aussi(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>erreur</html>")

        _install(monkeypatch, handler)

        with pytest.raises(ConsoleUnavailable):
            await validate_filter("InIfBoundary = external")

    @pytest.mark.anyio
    async def test_un_statut_http_d_erreur_leve(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"message": "boom"})

        _install(monkeypatch, handler)

        with pytest.raises(ConsoleUnavailable):
            await validate_filter("InIfBoundary = external")
