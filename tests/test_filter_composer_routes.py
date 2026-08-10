"""Routes du compositeur de filtres — contrat de nommage et dégradation.

DÉFAUT MESURÉ AU NAVIGATEUR (2026-08-06), le plus grave de ce lot : la route
de validation attendait un champ `expression`, alors que la zone de saisie est
le `<textarea name="content">` du formulaire d'ajout — nom imposé par le
contrat d'écriture des filtres.

htmx postait donc `content`, la route recevait du vide, et répondait
« filtre vide : aucun filtrage appliqué »… **en l'affichant comme un SUCCÈS**.
Une expression fautive aurait été annoncée valide puis enregistrée telle
quelle. C'est le pire cas d'un validateur : dire oui sans avoir rien lu.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.clients.akvorado_console import ValidationResult


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    from app.routers import filter_composer

    vues: list[str] = []

    async def faux_validate(expression: str) -> ValidationResult:
        vues.append(expression)
        if not expression.strip():
            return ValidationResult(ok=True, message="filtre vide : aucun filtrage appliqué")
        if "===" in expression:
            return ValidationResult(ok=False, message="at line 1, position 15: no match found")
        return ValidationResult(ok=True, message="ok")

    monkeypatch.setattr(filter_composer, "validate_filter", faux_validate)
    app = FastAPI()
    app.include_router(filter_composer.router)
    testeur = TestClient(app)
    testeur.expressions_vues = vues  # type: ignore[attr-defined]
    yield testeur


class TestNommageDuChamp:
    def test_le_champ_content_du_formulaire_est_bien_lu(self, client: TestClient) -> None:
        """C'est le nom RÉELLEMENT posté par la page.

        Le textarea s'appelle `content` (contrat du formulaire d'ajout, non
        modifiable). Si la route ne lit que `expression`, elle valide du vide.
        """
        response = client.post(
            "/config/filters/validate",
            data={"content": "InIfBoundary = external AND DstPort = 443"},
        )

        assert response.status_code == 200
        assert "InIfBoundary = external AND DstPort = 443" in client.expressions_vues  # type: ignore[attr-defined]
        assert "filtre vide" not in response.text, (
            "la route a validé du VIDE alors qu'une expression était fournie — "
            "elle annoncerait « valide » sans avoir rien lu"
        )

    def test_le_champ_expression_reste_accepte(self, client: TestClient) -> None:
        """Compatibilité : un appel direct à l'API garde son nom naturel."""
        response = client.post("/config/filters/validate", data={"expression": "DstPort = 443"})
        assert response.status_code == 200
        assert "DstPort = 443" in client.expressions_vues  # type: ignore[attr-defined]

    def test_une_expression_fautive_est_refusee_avec_sa_position(self, client: TestClient) -> None:
        """Le message d'Akvorado porte la position : elle doit survivre au rendu."""
        response = client.post(
            "/config/filters/validate", data={"content": "InIfBoundary === bidon"}
        )

        assert 'data-composer-valid="0"' in response.text
        assert "position 15" in response.text, (
            "la position du caractère fautif est ce qui distingue un message "
            "utile d'un « filtre invalide » qui laisse chercher"
        )

    def test_un_filtre_reellement_vide_reste_un_etat_legitime(self, client: TestClient) -> None:
        """« Tout le trafic » n'est pas une erreur."""
        response = client.post("/config/filters/validate", data={"content": "   "})
        assert 'data-composer-valid="1"' in response.text
