"""Bandeau GLOBAL « changements en attente » — visible sur TOUTES les pages.

DÉFAUT MESURÉ EN PRODUCTION (2026-08-11), verbatim de l'utilisateur : « il faut
surtout soit mettre un bouton pour appliquer ce qui est en attente, quelque
chose du genre ».

Ce qui s'est passé : l'écran MET EN ATTENTE (`stage_change`) sans rien écrire.
L'utilisateur a déclaré son pare-feu DEUX FOIS en croyant que ça échouait —
21 changements s'étaient accumulés dans `pending_config_changes` sans qu'AUCUN
écran ne le signale. Seul `/config` portait le bouton « Appliquer » ; les
routeurs `exporters.py` et `config_sections.py` mettent en attente sans offrir
aucun moyen d'appliquer.

POURQUOI UN BANDEAU GLOBAL PLUTÔT QUE DEUX BOUTONS DE PLUS : ajouter le bouton
aux deux écrans manquants corrigerait le symptôme du jour et rien d'autre — le
prochain écran qui mettra en attente l'oubliera à son tour, exactement le
défaut qu'on corrige. Le bandeau est rendu par `base.html` à partir d'un
context processor (`app.templating._pending_changes_context`), donc par
CONSTRUCTION sur toute page qui hérite du gabarit : aucun routeur n'a rien à
passer, aucun ne peut l'oublier.

ZÉRO SILENCIEUX (CLAUDE.md) : si la lecture du compte échoue, on n'affiche
JAMAIS « 0 en attente » — ce serait un mensonge rassurant, précisément la
famille de défauts que le projet proscrit. Le compte vaut alors `None` et le
bandeau ne s'affiche pas du tout.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password, new_session_cookie
from app.db import SCHEMA
from app.main import app
from app.services.config_writer import stage_change


@pytest.fixture
def fichier_sqlite_reel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Base SQLite RÉELLE (fichier), pointée par `settings.sqlite_path`.

    Le bandeau est alimenté par un context processor, qui n'a que le `Request`
    et ne peut donc pas recevoir la connexion par injection FastAPI : il ouvre
    lui-même `settings.sqlite_path`. Un `:memory:` ne conviendrait pas — le
    processeur ouvrirait une base VIDE distincte de celle du test.
    """
    from app import main as main_module
    from app.config import settings

    db_path = str(tmp_path / "banner-okvorado.db")
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT INTO auth_users (username, password_hash, is_default_password, role) "
        "VALUES (?, ?, 0, 'admin')",
        ("test-user", hash_password("peu-importe-ici")),
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(settings, "sqlite_path", db_path)
    monkeypatch.setattr(main_module.settings, "sqlite_path", db_path)
    return db_path


def _client_authentifie() -> TestClient:
    client = TestClient(app, follow_redirects=False)
    cookie = new_session_cookie("test-user", app.state.auth_session_secret)
    client.cookies.set("okvorado_session", cookie)
    return client


def _empiler_changements(db_path: str, combien: int) -> None:
    """Met `combien` changements dans la file, comme le ferait l'écran."""
    conn = sqlite3.connect(db_path)
    try:
        for index in range(combien):
            stage_change(
                conn,
                "add_exporter",
                {
                    "cidr": f"192.0.2.{index + 1}/32",
                    "name": f"equipement-{index}",
                    "if_indexes": {},
                    "default": None,
                },
                "ui",
            )
        conn.commit()
    finally:
        conn.close()


class TestBandeauVisibleSurToutesLesPages:
    """LE CŒUR DE LA DEMANDE : le bandeau ne doit PAS être réservé à /config."""

    # Pages retenues : celles qui rendent de bout en bout dans l'environnement
    # de test, sans dépendance que d'autres modules de test dé-câblent.
    #
    # Écartées pour des raisons ÉTRANGÈRES au bandeau — leur couverture est
    # assurée par la garde structurelle `TestBandeauRenduParLeGabaritCommun`,
    # qui prouve que le bandeau vit dans `base.html` donc sur TOUTE page qui en
    # hérite :
    #   - `/retention`, `/db-health`, `/diagnostics/convergence`,
    #     `/field-catalog` : ces routes ouvrent une connexion ClickHouse, que la
    #     suite ne fournit pas (règle du projet : aucun test ne touche
    #     d'infrastructure réelle) ;
    #   - `/app-catalog`, `/settings/security` : `tests/test_app_catalog.py` et
    #     `tests/test_accounts.py` font un `dependency_overrides.pop(...)` sans
    #     jamais restaurer le câblage, ce qui dé-câble ces routes pour tout test
    #     s'exécutant après eux. MESURÉ ici : elles passent en isolation et
    #     échouent en suite complète — défaut d'isolation préexistant, sans
    #     rapport avec ce lot, qu'on se garde d'aggraver en s'appuyant dessus.
    @pytest.mark.parametrize(
        "chemin",
        [
            "/exporters",
            "/inventory",
            "/ingestion",
        ],
    )
    def test_le_bandeau_apparait_sur_une_page_qui_n_est_pas_config(
        self, fichier_sqlite_reel: str, chemin: str
    ) -> None:
        """C'est LE cas vécu : 21 changements en attente, et l'exploitant qui
        travaille sur l'écran Exportateurs n'en voit AUCUNE trace."""
        _empiler_changements(fichier_sqlite_reel, 3)

        response = _client_authentifie().get(chemin)

        assert response.status_code == 200
        assert "pending-global-banner" in response.text, (
            f"aucun bandeau de changements en attente sur {chemin} : "
            "un exploitant peut y accumuler des changements sans jamais "
            "savoir qu'ils l'attendent (défaut mesuré le 2026-08-11)"
        )
        assert "3" in response.text

    def test_le_bandeau_porte_le_bouton_appliquer(self, fichier_sqlite_reel: str) -> None:
        """Signaler sans offrir le geste ne corrige rien : l'utilisateur
        demande « un bouton pour appliquer ce qui est en attente »."""
        _empiler_changements(fichier_sqlite_reel, 2)

        response = _client_authentifie().get("/exporters")

        assert response.status_code == 200
        debut = response.text.index("pending-global-banner")
        fin = response.text.index("</main>")
        bandeau = response.text[debut:fin]
        assert "/config/apply" in bandeau, (
            "le bandeau doit porter le bouton qui APPLIQUE, pas seulement le compte"
        )

    def test_le_bandeau_disparait_quand_la_file_est_vide(
        self, fichier_sqlite_reel: str
    ) -> None:
        """Aucun changement en attente -> aucun bandeau. Un bandeau permanent
        deviendrait du bruit qu'on cesse de lire."""
        response = _client_authentifie().get("/exporters")

        assert response.status_code == 200
        assert "pending-global-banner" not in response.text

    def test_le_compte_affiche_est_le_compte_reel(self, fichier_sqlite_reel: str) -> None:
        """Le nombre montré doit être MESURÉ, pas approximé : c'est ce nombre
        qui a manqué à l'exploitant (21 accumulés, aucun affiché)."""
        _empiler_changements(fichier_sqlite_reel, 21)

        response = _client_authentifie().get("/exporters")

        assert response.status_code == 200
        assert "pending-global-banner" in response.text
        assert "21" in response.text


class TestZeroSilencieuxSurLeCompte:
    """Un échec de lecture ne doit JAMAIS produire « 0 en attente »."""

    def test_echec_de_lecture_n_affiche_pas_zero(
        self, fichier_sqlite_reel: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Base illisible (verrou, corruption, table absente) : le bandeau
        s'efface, mais on n'écrit JAMAIS un « 0 changement en attente » qui
        laisserait croire que la file est vide alors qu'on n'en sait rien.

        La table est SUPPRIMÉE plutôt que `sqlite3.connect` patché : le
        middleware d'authentification (`app.main`) ouvre la MÊME base sur le
        même module `sqlite3`, un patch global le ferait tomber avant tout
        rendu et ne prouverait rien sur le bandeau. Supprimer la table cible
        casse la seule lecture qui nous intéresse, en laissant le reste de la
        requête intact — c'est le vrai cas d'un schéma incomplet."""
        conn = sqlite3.connect(fichier_sqlite_reel)
        try:
            conn.execute("DROP TABLE pending_config_changes")
            conn.commit()
        finally:
            conn.close()

        response = _client_authentifie().get("/exporters")

        assert response.status_code == 200
        assert "pending-global-banner" not in response.text
        assert "0 changement" not in response.text
        assert "changement en attente" not in response.text

    def test_le_compte_vaut_none_et_non_zero_quand_la_lecture_echoue(
        self, fichier_sqlite_reel: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Garde au niveau du context processor lui-même : `None` (état
        DISTINCT « indéterminé ») et jamais `0` (une vraie mesure)."""
        from app import templating

        def _explose(*_args: Any, **_kwargs: Any) -> Any:
            raise sqlite3.OperationalError("base verrouillee (simule)")

        monkeypatch.setattr(templating.sqlite3, "connect", _explose)

        contexte = templating._pending_changes_context(_request_factice())

        assert contexte["pending_changes_count"] is None, (
            "un echec de lecture doit rendre un etat DISTINCT (None), "
            "jamais 0 — un 0 est indiscernable d'une file reellement vide"
        )

    def test_le_compte_est_un_entier_quand_la_lecture_reussit(
        self, fichier_sqlite_reel: str
    ) -> None:
        _empiler_changements(fichier_sqlite_reel, 4)

        contexte = __import__(
            "app.templating", fromlist=["_pending_changes_context"]
        )._pending_changes_context(_request_factice())

        assert contexte["pending_changes_count"] == 4


class TestBandeauRenduParLeGabaritCommun:
    """Garde STRUCTURELLE : le bandeau vit dans base.html, pas dans un écran.

    Sans cette garde, rien n'empêcherait une correction future de le
    redéplacer dans un gabarit particulier — et de réintroduire exactement le
    défaut corrigé (un écran qui l'oublie).
    """

    def test_le_bandeau_est_dans_base_html(self) -> None:
        base_html = Path("app/templates/base.html").read_text(encoding="utf-8")
        assert "pending-global-banner" in base_html

    def test_le_bandeau_est_hors_du_bloc_nav(self) -> None:
        """Même garde de mise en page que le bandeau mot de passe : frère du
        `<nav>`, jamais enfant (sinon il hérite de son `flex-wrap`)."""
        base_html = Path("app/templates/base.html").read_text(encoding="utf-8")
        nav_start = base_html.index('<nav class="nav">')
        nav_end = base_html.index("</nav>") + len("</nav>")
        assert "pending-global-banner" not in base_html[nav_start:nav_end]
        assert base_html.index("pending-global-banner") > nav_end

    def test_la_classe_existe_dans_le_css(self) -> None:
        css = Path("app/static/style.css").read_text(encoding="utf-8")
        assert ".pending-global-banner" in css

    def test_aucun_gabarit_de_page_ne_redefinit_le_bandeau(self) -> None:
        """UNE SEULE source du bandeau : `base.html`.

        Si un écran redéfinissait sa propre version du bandeau, on retomberait
        dans le défaut corrigé — deux implémentations qui divergent, et des
        écrans qui restent sans. Le bandeau de `config.html` (`pending-banner`,
        avec le détail des changements) est une SURFACE DIFFÉRENTE et
        légitime : il liste les changements un par un, ce que le bandeau global
        ne fait pas. Seule la classe `pending-global-banner` doit être unique.
        """
        gabarits = list(Path("app/templates").glob("*.html"))
        assert gabarits, "aucun gabarit trouvé : le test ne prouverait rien"

        porteurs = [
            chemin.name
            for chemin in gabarits
            if "pending-global-banner" in chemin.read_text(encoding="utf-8")
        ]
        assert porteurs == ["base.html"], (
            f"le bandeau global doit n'exister QUE dans base.html, trouvé dans {porteurs}"
        )

    def test_toute_page_heritant_de_base_recoit_le_bandeau(self) -> None:
        """La propriété RÉELLE que cette correction doit garantir.

        Les tests HTTP ci-dessus ne couvrent que les écrans qui rendent sans
        dépendance externe. Ce test-ci prouve la propriété pour TOUS les
        gabarits de page : ils étendent `base.html`, donc ils reçoivent le
        bandeau — c'est précisément ce qui rend impossible qu'un écran l'oublie.
        """
        # Les FRAGMENTS HTMX sont des morceaux insérés dans une page DÉJÀ
        # rendue : ils n'étendent rien et n'ont pas à porter le bandeau, déjà
        # présent dans la page hôte. La convention du projet est le préfixe `_`,
        # mais trois fragments du LOT app_catalog la précèdent
        # (`app_catalog_rows.html`, `..._reload_status.html`,
        # `..._import_result.html`) — ils se déclarent tels quels en tête de
        # fichier. On détecte donc le fragment par son CONTENU (« Fragment »
        # dans le commentaire d'en-tête) plutôt que par son seul nom : une
        # règle basée sur le nom laisserait passer un vrai écran mal nommé,
        # c'est-à-dire exactement le cas que ce test doit attraper.
        #
        # `login*.html` sont hors périmètre : ce sont les seules pages servies
        # SANS session, où aucun changement en attente ne peut être appliqué.
        exclus = {"base.html", "login.html", "login_totp.html"}
        gabarits_de_page = [
            chemin
            for chemin in Path("app/templates").glob("*.html")
            if not chemin.name.startswith("_")
            and chemin.name not in exclus
            and "Fragment" not in chemin.read_text(encoding="utf-8")[:400]
        ]
        assert gabarits_de_page, "aucun gabarit de page trouvé"

        sans_heritage = [
            chemin.name
            for chemin in gabarits_de_page
            if '{% extends "base.html" %}' not in chemin.read_text(encoding="utf-8")
        ]
        assert sans_heritage == [], (
            f"ces gabarits n'héritent pas de base.html et n'auraient donc PAS le "
            f"bandeau de changements en attente : {sans_heritage}"
        )

    def test_le_context_processor_est_branche_sur_le_moteur(self) -> None:
        """SERVICE EXISTANT NON BRANCHÉ — l'une des 4 familles de défauts
        invisibles aux tests recensées dans CLAUDE.md. Le processeur peut
        exister, être testé unitairement, et n'être câblé nulle part : le
        bandeau serait alors absent de TOUTES les pages sans qu'aucun test
        unitaire ne bronche."""
        from app import templating

        moteur = templating.build_templates()
        assert templating._pending_changes_context in _context_processors(moteur), (
            "le context processor n'est pas branché sur le moteur Jinja : "
            "le bandeau n'apparaîtrait sur AUCUNE page"
        )


def _context_processors(moteur: Any) -> list[Any]:
    """Récupère la liste des context processors d'un `Jinja2Templates`.

    L'attribut est privé côté Starlette (`context_processors`) : on le lit ici
    plutôt que dans chaque test, pour n'avoir qu'un seul endroit à corriger si
    Starlette le renomme.
    """
    return list(getattr(moteur, "context_processors", []))


def _request_factice() -> Any:
    """`Request` minimal : le context processor n'en lit rien, il n'a besoin
    que de la signature. Construit à la main plutôt que via TestClient pour
    tester le processeur SEUL, sans traverser tout le rendu."""
    from starlette.requests import Request

    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
        }
    )
