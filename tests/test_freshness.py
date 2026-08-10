"""Garde-fou : l'écran de configuration est MONITORABLE sans rechargement.

EXIGENCE (utilisateur, 2026-06-24) : une UI dont on constate le fonctionnement
EN LIVE, sans enchaîner les rechargements. Okvorado vise explicitement l'usage
à PLUSIEURS — « que l'application soit utilisable par mes collègues » — donc un
changement appliqué par quelqu'un d'autre doit se savoir.

MAIS le panneau d'édition porte 24 champs de saisie et une zone de collage CSV.
Un rafraîchissement périodique du CONTENU effacerait un CSV à moitié collé ou
une sélection de cases en cours : le remède serait pire que le mal.

D'où une SONDE : elle interroge l'empreinte de la section toutes les 15 s,
n'affiche rien tant que rien n'a bougé, et signale un changement extérieur sans
jamais l'imposer. Recharger reste une décision de l'utilisateur — lui seul sait
s'il a une saisie en cours.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.db import SCHEMA

TEMPLATE = Path(__file__).resolve().parent.parent / "app" / "templates" / "config_sections.html"
FRESHNESS_JS = Path(__file__).resolve().parent.parent / "app" / "static" / "freshness.js"

_OUTLET = (
    "networks:\n"
    "  networks:\n"
    "    100.64.0.0/10:\n"
    "      name: mesh\n"
    "      role: internal\n"
    "core:\n"
    "  exporter-classifiers:\n"
    '    - ClassifyRegion("homelab")\n'
    "  interface-classifiers: []\n"
)


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    (tmp_path / "outlet.yaml").write_text(_OUTLET)
    (tmp_path / "akvorado.yaml").write_text(
        "clickhouse:\n  asns:\n    64501: ACME\nkafka:\n  topic-configuration:\n    retention: 1\n"
    )
    (tmp_path / "console.yaml").write_text(
        "database:\n  saved-filters: []\n"
        "default-visualize-options:\n  limit: 10\nhomepage-top-widgets: []\n"
    )
    (tmp_path / "inlet.yaml").write_text("flow:\n  inputs: []\n")
    return tmp_path


@pytest.fixture
def client(config_dir: Path) -> Generator[TestClient]:
    from app.routers import config_sections as sections_router

    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    app = FastAPI()
    app.include_router(sections_router.router)
    app.dependency_overrides[sections_router.get_db_connection] = lambda: conn
    app.dependency_overrides[sections_router.get_config_dir] = lambda: str(config_dir)
    yield TestClient(app)
    conn.close()


def _empreinte(html: str) -> str:
    found = re.search(r'data-fingerprint="([^"]+)"', html)
    assert found, f"aucune empreinte dans la réponse : {html[:200]!r}"
    return found.group(1)


class TestSonde:
    def test_premier_appel_ne_signale_rien_mais_rend_une_empreinte(
        self, client: TestClient
    ) -> None:
        """Sans référence connue, il n'y a rien à comparer — donc rien à dire."""
        response = client.get("/config/sections/networks/freshness")

        assert response.status_code == 200
        assert "modifiée ailleurs" not in response.text
        assert _empreinte(response.text)

    def test_section_inchangee_reste_silencieuse(self, client: TestClient) -> None:
        """Une bannière qui se déclenche pour rien apprend à ignorer les bannières."""
        vue = _empreinte(client.get("/config/sections/networks/freshness").text)

        response = client.get("/config/sections/networks/freshness", params={"seen": vue})

        assert "modifiée ailleurs" not in response.text

    def test_modification_exterieure_est_signalee_avec_un_lien_de_rechargement(
        self, client: TestClient, config_dir: Path
    ) -> None:
        """Le cas d'usage réel : un collègue applique un changement."""
        vue = _empreinte(client.get("/config/sections/networks/freshness").text)
        chemin = config_dir / "outlet.yaml"
        chemin.write_text(chemin.read_text().replace("name: mesh", "name: mesh-renomme"))

        response = client.get("/config/sections/networks/freshness", params={"seen": vue})

        assert "modifiée ailleurs" in response.text
        assert 'href="/config/sections/networks"' in response.text

    def test_une_autre_section_du_meme_fichier_ne_declenche_pas_de_fausse_alerte(
        self, client: TestClient, config_dir: Path
    ) -> None:
        """L'empreinte porte sur la SECTION, pas sur le fichier.

        `outlet.yaml` porte trois sections. Hacher le fichier entier ferait
        signaler un changement du plan d'adressage à chaque modification des
        classifieurs — une alerte qui se déclenche pour rien.
        """
        vue = _empreinte(client.get("/config/sections/networks/freshness").text)
        chemin = config_dir / "outlet.yaml"
        chemin.write_text(
            chemin.read_text().replace(
                '    - ClassifyRegion("homelab")',
                '    - ClassifyRegion("homelab")\n    - ClassifyRole("vm")',
            )
        )

        plan = client.get("/config/sections/networks/freshness", params={"seen": vue})
        classifiers = client.get(
            "/config/sections/exporter_classifiers/freshness",
            params={"seen": "empreinte-perimee"},
        )

        assert "modifiée ailleurs" not in plan.text, (
            "le plan d'adressage n'a pas changé : le signaler serait une fausse alerte"
        )
        assert "modifiée ailleurs" in classifiers.text

    def test_section_inconnue_repond_404_pas_un_silence(self, client: TestClient) -> None:
        response = client.get("/config/sections/section-imaginaire/freshness")
        assert response.status_code == 404


class TestCablageEtCsp:
    def test_la_zone_de_sonde_est_rafraichie_periodiquement(self) -> None:
        """Sans `every`, la sonde ne serait interrogée qu'au chargement."""
        html = TEMPLATE.read_text(encoding="utf-8")
        bloc = re.search(r'<div id="section-freshness".*?>', html, re.DOTALL)

        assert bloc, "zone #section-freshness absente du template"
        assert re.search(r'hx-trigger="[^"]*every \d+s', bloc.group(0)), (
            "la sonde doit être interrogée périodiquement, sinon l'écran n'est "
            "monitorable qu'au rechargement — l'exigence exacte qu'elle satisfait"
        )

    def test_le_champ_d_empreinte_est_hors_de_la_zone_rafraichie(self) -> None:
        """Placé dedans, il serait détruit à chaque swap.

        L'empreinte connue repartirait alors à vide à chaque cycle et la sonde
        ne signalerait JAMAIS rien — en silence.
        """
        html = TEMPLATE.read_text(encoding="utf-8")
        position_champ = html.find('id="section-freshness-seen"')
        position_zone = html.find('<div id="section-freshness"')

        assert position_champ != -1, "champ d'empreinte absent"
        assert position_zone != -1, "zone de sonde absente"
        assert position_champ < position_zone, (
            "le champ d'empreinte doit précéder la zone rafraîchie, donc vivre "
            "en dehors d'elle : sinon le premier innerHTML le détruit"
        )

    def test_aucun_hx_vals_js_incompatible_avec_la_csp(self, client: TestClient) -> None:
        """`hx-vals="js:..."` serait évalué par `Function()`, que la CSP bloque.

        L'application sert `script-src 'self'` SANS `unsafe-eval` : la valeur
        partirait vide, sans le moindre avertissement, et la sonde ne
        signalerait jamais rien. Même famille de piège que `hx-target-error`.

        L'inspection porte sur le HTML RENDU et non sur le template : les
        commentaires Jinja citent volontairement `hx-vals="js:"` pour
        documenter le piège, et un test lisant la source les prendrait pour
        des occurrences réelles. Même faux positif que celui rencontré sur le
        garde-fou des couleurs en dur.
        """
        rendu = client.get("/config/sections/networks").text
        offenders = re.findall(r'hx-vals=[\'"]js:', rendu)

        assert not offenders, (
            'hx-vals="js:..." est incompatible avec la CSP de l\'application '
            "(pas d'unsafe-eval) : il serait ignoré en SILENCE. Passe par un "
            "champ inclus via hx-include, alimenté par un fichier statique."
        )

    def test_le_report_d_empreinte_vit_dans_un_fichier_statique(self, client: TestClient) -> None:
        """CSP : aucun script inline, et le report doit exister quelque part."""
        assert FRESHNESS_JS.exists(), (
            "app/static/freshness.js absent : sans report de l'empreinte, "
            "chaque cycle repart de zéro et la sonde ne signale jamais rien"
        )
        rendu = client.get("/config/sections/networks").text
        assert "freshness.js" in rendu, "freshness.js n'est pas chargé par la page"

        # Un `<script>` sans attribut `src` est un script inline.
        inlines = [
            tag for tag in re.findall(r"<script\b[^>]*>", rendu) if not re.search(r"\bsrc\s*=", tag)
        ]
        assert not inlines, (
            f"scripts inline détectés ({inlines!r}) : la CSP de l'application "
            "(`script-src 'self'`) les bloque — ils seraient sans effet."
        )

    def test_l_empreinte_de_reference_est_figee_au_premier_cycle(self) -> None:
        """La référence ne doit PAS suivre le fichier, sinon la sonde se tait.

        DÉFAUT MESURÉ au navigateur (2026-08-06) : `freshness.js` réécrivait le
        champ à chaque réponse. La sonde détectait bien le changement — un
        cycle voyait l'empreinte passer de `47c2a882` à `39f80964` — puis
        enregistrait la NOUVELLE valeur. Le cycle suivant comparait donc la
        nouvelle empreinte à elle-même : plus aucun écart, plus aucune
        bannière. **La sonde se taisait exactement quand elle aurait dû
        parler**, et rien ne le laissait voir : la zone se rafraîchissait, la
        requête partait, la réponse arrivait.

        La référence est ce que le navigateur AFFICHE, figée au chargement.
        Elle ne change que par un vrai rechargement, décidé par l'utilisateur.
        """
        source = FRESHNESS_JS.read_text(encoding="utf-8")

        assert re.search(r"if\s*\(\s*champ\.value\s*\)\s*\{\s*return", source), (
            "freshness.js doit sortir SANS réécrire quand une empreinte de "
            "référence existe déjà. Sans ce garde, la référence suit le "
            "fichier et la sonde ne signale jamais rien."
        )
