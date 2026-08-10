"""Garde-fous du composeur d'étiquettes et de la liste exhaustive des widgets.

Ces tests portent sur la STRUCTURE du HTML rendu — pas sur le rendu visuel, qui
se vérifie au navigateur, ni sur le traitement serveur (inchangé par ce lot).

DÉFAUTS QU'ILS EMPÊCHENT DE REVENIR :

1. `visualize_defaults` rendait ses 6 dimensions dans UN SEUL
   `<input type="text">` étroit, séparées par des virgules (valeur de prod
   mesurée le 2026-08-06 : `ExporterName, SrcAddr, DstAddr, DstPort, Proto,
   InIfBoundary`). Verbatim utilisateur : « c'est dégueu ». Illisible, et
   l'ordre — qui porte du sens, la 1re dimension étant l'axe principal du
   graphe Akvorado — n'était modifiable qu'en retapant la chaîne entière.

2. `homepage_widgets` rendait 9 codes techniques bruts en cases à cocher, sans
   dire ce que chaque widget affiche ni que la liste est close. La liste EST
   exhaustive (vérifiée contre l'API Akvorado : les 9 répondent 200, 8 autres
   candidats répondent 400) — le défaut était d'AFFICHAGE.

3. Une classe CSS posée sans règle dans `style.css` (`.view-card__akvorado-link`,
   puis `.secondary`) : l'élément se rend avec le style par défaut du navigateur,
   hors charte, sans la moindre erreur.

4. Du JavaScript inline sous une CSP `script-src 'self'` : bloqué par le
   navigateur, page affichée mais inerte au clic.

5. Une commande accessible à la SEULE souris : une liste réordonnable
   uniquement au glisser-déposer est inutilisable pour qui ne peut pas glisser.
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

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = PROJECT_ROOT / "app" / "templates" / "config_sections.html"
STYLE_CSS = PROJECT_ROOT / "app" / "static" / "style.css"
COMPOSER_JS = PROJECT_ROOT / "app" / "static" / "field-composer.js"

# Valeur de PRODUCTION mesurée le 2026-08-06 sur `default-visualize-options`.
# Les fixtures reprennent cette valeur exacte : un test qui passerait sur une
# seule dimension ne prouverait rien du défaut signalé, qui n'apparaît qu'à
# partir de plusieurs dimensions dans un champ étroit.
PROD_DIMENSIONS = [
    "ExporterName",
    "SrcAddr",
    "DstAddr",
    "DstPort",
    "Proto",
    "InIfBoundary",
]

# Les 9 widgets acceptés par l'API Akvorado (`/api/v0/console/widget/top/<w>`
# -> 200). C'est l'allowlist `_HOMEPAGE_WIDGET_CHOICES` du routeur.
ALL_WIDGETS = [
    "exporter",
    "src-as",
    "dst-as",
    "src-country",
    "dst-country",
    "protocol",
    "etype",
    "src-port",
    "dst-port",
]

# Widgets cochés dans la fixture : 6 sur 9, comme en production.
CHECKED_WIDGETS = [
    "exporter",
    "src-as",
    "dst-as",
    "src-country",
    "dst-country",
    "protocol",
]


# ---------------------------------------------------------------------------
# Fixtures — mêmes YAML de travail que les autres suites, jamais la prod :
# SQLite en mémoire, fichiers en tmp_path.
# ---------------------------------------------------------------------------

_OUTLET_YAML = """\
networks:
  networks:
    100.64.0.0/10:
      name: tailscale-mesh
core:
  exporter-classifiers:
    - ClassifyRegion("homelab")
  interface-classifiers: []
"""

_AKVORADO_YAML = """\
clickhouse:
  asns:
    64512: homelab-as
kafka:
  topic-configuration:
    num-partitions: 4
"""

_CONSOLE_YAML = """\
default-visualize-options:
  limit: 10
  dimensions:
    - ExporterName
    - SrcAddr
    - DstAddr
    - DstPort
    - Proto
    - InIfBoundary
homepage-top-widgets:
  - exporter
  - src-as
  - dst-as
  - src-country
  - dst-country
  - protocol
database:
  saved-filters:
    - description: filtre 0
      content: "DstPort = 8000"
"""

_INLET_YAML = """\
flow:
  inputs:
    - type: udp
      decoder: netflow
      listen: 0.0.0.0:2055
"""


@pytest.fixture
def memory_conn() -> Generator[sqlite3.Connection]:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    (tmp_path / "outlet.yaml").write_text(_OUTLET_YAML)
    (tmp_path / "akvorado.yaml").write_text(_AKVORADO_YAML)
    (tmp_path / "console.yaml").write_text(_CONSOLE_YAML)
    (tmp_path / "inlet.yaml").write_text(_INLET_YAML)
    return tmp_path


@pytest.fixture
def client(memory_conn: sqlite3.Connection, config_dir: Path) -> TestClient:
    from app.routers import config_sections as sections_router

    app = FastAPI()
    app.include_router(sections_router.router)
    app.dependency_overrides[sections_router.get_db_connection] = lambda: memory_conn
    app.dependency_overrides[sections_router.get_config_dir] = lambda: str(config_dir)
    return TestClient(app)


def _render(client: TestClient, key: str) -> str:
    response = client.get(f"/config/sections/{key}")
    assert response.status_code == 200, f"section={key} n'a pas rendu"
    return response.text


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# Les commentaires Jinja documentent les pièges en CITANT le balisage concerné
# (« un `<script>` inline », « `onclick=` »). Ce balisage cité ne part JAMAIS au
# navigateur : l'analyser ferait échouer les garde-fous sur leur propre
# documentation. Même précaution que dans test_bulk_selection.py.
_JINJA_COMMENT_RE = re.compile(r"\{#.*?#\}", re.DOTALL)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def _strip_comments(html: str) -> str:
    html = _JINJA_COMMENT_RE.sub("", html)
    return _HTML_COMMENT_RE.sub("", html)


# Même précaution pour le JS et le CSS : leurs commentaires CITENT les pièges
# évités (`setTimeout`, `var(--accent-bg)`, `position: sticky`). Analyser le
# fichier commentaires compris ferait échouer les garde-fous sur leur propre
# documentation — exactement le motif que ces tests dénoncent.
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"^\s*//.*$", re.MULTILINE)


def _strip_js_comments(source: str) -> str:
    return _LINE_COMMENT_RE.sub("", _BLOCK_COMMENT_RE.sub("", source))


def _strip_css_comments(source: str) -> str:
    return _BLOCK_COMMENT_RE.sub("", source)


def _tags(html: str) -> list[str]:
    """Les `<li>` d'étiquette du composeur, dans l'ordre du document."""
    return re.findall(r"<li[^>]*data-field-composer-tag[^>]*>", html)


# ---------------------------------------------------------------------------
# A — Les dimensions sont des ÉTIQUETTES, plus un champ texte unique
# ---------------------------------------------------------------------------


class TestEtiquettesDeDimensions:
    def test_une_etiquette_par_dimension(self, client: TestClient) -> None:
        """Le cœur de la demande : une étiquette PAR dimension.

        Sur la valeur de production (6 dimensions), on attend 6 étiquettes
        distinctes — pas une chaîne de 6 termes dans un seul champ.
        """
        html = _render(client, "visualize_defaults")
        tags = _tags(html)
        assert len(tags) == len(PROD_DIMENSIONS), (
            f"{len(PROD_DIMENSIONS)} étiquettes attendues (une par dimension), trouvé {len(tags)}"
        )

    def test_chaque_dimension_est_portee_par_son_etiquette(self, client: TestClient) -> None:
        """Chaque dimension configurée a bien SON étiquette, dans l'ordre du YAML.

        L'ordre est vérifié et non seulement la présence : la 1re dimension est
        l'axe principal du graphe Akvorado. Un composeur qui reordonnerait
        (par exemple alphabétiquement) à l'affichage changerait silencieusement
        la signification de la configuration.
        """
        html = _render(client, "visualize_defaults")
        values = [
            m.group(1)
            for tag in _tags(html)
            if (m := re.search(r'data-field-value="([^"]*)"', tag))
        ]
        assert values == PROD_DIMENSIONS, (
            "les étiquettes doivent reprendre les dimensions DANS L'ORDRE de la "
            f"configuration : attendu {PROD_DIMENSIONS}, obtenu {values}"
        )

    def test_plus_aucun_champ_texte_visible_porte_les_dimensions(self, client: TestClient) -> None:
        """TEST DE NON-RETOUR — c'est lui qui interdit le défaut d'origine.

        Sans ce test, ajouter des étiquettes À CÔTÉ du champ texte d'origine
        passerait tous les autres, et l'écran resterait « dégueu ».

        Le champ qui porte `name="dimensions"` doit être un champ CACHÉ (il
        transporte l'ordre au submit), jamais un `type="text"` que l'on éditerait
        à la virgule près.
        """
        html = _render(client, "visualize_defaults")
        fields = re.findall(r'<input[^>]*name="dimensions"[^>]*>', html)
        assert fields, 'aucun champ name="dimensions" rendu'
        for field in fields:
            assert 'type="hidden"' in field, (
                'le champ des dimensions doit être caché — un `type="text"` '
                "réintroduit exactement le défaut signalé (« c'est dégueu ») :\n"
                f"  {field}"
            )

    def test_le_rang_de_chaque_etiquette_est_affiche(self, client: TestClient) -> None:
        """L'ordre compte : le rang est VISIBLE, pas seulement implicite.

        Une liste ordonnée sans numéro laisse deviner quelle dimension est
        l'axe principal du graphe — au moment précis où on la réordonne.
        """
        html = _render(client, "visualize_defaults")
        ranks = re.findall(r"data-field-composer-rank[^>]*>\s*(\d+)\s*<", html)
        assert ranks == [str(i) for i in range(1, len(PROD_DIMENSIONS) + 1)], (
            f"rangs 1..{len(PROD_DIMENSIONS)} attendus, obtenu {ranks}"
        )

    def test_chaque_etiquette_porte_un_libelle_francais(self, client: TestClient) -> None:
        """Le code technique seul ne dit pas ce que la dimension représente.

        `InIfBoundary` ne se lit pas ; « Frontière d'entrée » se lit. Les deux
        sont affichés : le code reste visible parce que c'est lui qui part dans
        le YAML et qu'on le retrouve dans la doc Akvorado.
        """
        html = _render(client, "visualize_defaults")
        labels = re.findall(r'class="field-composer__tag-label"[^>]*>([^<]*)<', html)
        # Au moins une étiquette par dimension retenue, chacune non vide et
        # DIFFÉRENTE du code technique.
        retained = labels[: len(PROD_DIMENSIONS)]
        assert len(retained) == len(PROD_DIMENSIONS)
        for code, label in zip(PROD_DIMENSIONS, retained, strict=True):
            assert label.strip(), f"libellé vide pour {code}"
            assert label.strip() != code, (
                f"{code}: le libellé doit être un intitulé lisible, pas le code technique"
            )


# ---------------------------------------------------------------------------
# B — Réordonnancement : souris ET clavier
# ---------------------------------------------------------------------------


class TestReordonnancement:
    def test_chaque_etiquette_est_deplacable_a_la_souris(self, client: TestClient) -> None:
        """`draggable="true"` sur chaque étiquette — le glisser-déposer demandé."""
        html = _render(client, "visualize_defaults")
        tags = _tags(html)
        assert tags, "aucune étiquette rendue"
        for tag in tags:
            assert 'draggable="true"' in tag, f"étiquette non déplaçable à la souris : {tag}"

    def test_chaque_etiquette_a_une_commande_clavier(self, client: TestClient) -> None:
        """TEST D'ACCESSIBILITÉ — une liste ordonnable À LA SEULE SOURIS est
        inutilisable pour qui ne peut pas glisser (clavier seul, tremblement,
        lecteur d'écran, tactile sans DnD HTML5).

        Chaque étiquette doit porter une commande « monter » ET une commande
        « descendre », atteignables au clavier (des `<button>`, donc focusables).
        """
        html = _render(client, "visualize_defaults")
        ups = re.findall(r'<button[^>]*data-field-composer-move="up"', html)
        downs = re.findall(r'<button[^>]*data-field-composer-move="down"', html)
        n = len(PROD_DIMENSIONS)
        assert len(ups) == n, f"{n} commandes « monter » attendues, trouvé {len(ups)}"
        assert len(downs) == n, f"{n} commandes « descendre » attendues, trouvé {len(downs)}"

    def test_les_boutons_du_composeur_ne_soumettent_pas_le_formulaire(
        self, client: TestClient
    ) -> None:
        """Un `<button>` sans `type` vaut `submit` DANS un formulaire.

        Sans `type="button"`, monter une étiquette d'un rang ENVERRAIT le
        formulaire et mettrait en file un changement que personne n'a demandé.
        Le seul bouton qui a le droit de soumettre est « Mettre en attente ».
        """
        html = _strip_comments(_render(client, "visualize_defaults"))
        composer = re.search(
            r'<div class="field-composer"[^>]*>(.*?)<label for="visualize-limit"',
            html,
            re.DOTALL,
        )
        assert composer, "bloc du composeur introuvable dans le rendu"
        for button in re.findall(r"<button[^>]*>", composer.group(1)):
            assert 'type="button"' in button, (
                'tout bouton du composeur doit être `type="button"` — sinon il '
                f"soumet le formulaire :\n  {button}"
            )

    def test_chaque_commande_est_nommee_pour_un_lecteur_decran(self, client: TestClient) -> None:
        """Les boutons portent des glyphes (↑ ↓ ✕) : sans `aria-label`, un
        lecteur d'écran annonce un bouton anonyme, donc une commande dont on ne
        peut pas savoir ce qu'elle fait avant de l'avoir déclenchée."""
        html = _strip_comments(_render(client, "visualize_defaults"))
        for attr in (
            'data-field-composer-move="up"',
            'data-field-composer-move="down"',
            "data-field-composer-remove",
            "data-field-composer-add",
        ):
            buttons = re.findall(r"<button[^>]*" + re.escape(attr) + r"[^>]*>", html)
            assert buttons, f"aucun bouton portant {attr}"
            for button in buttons:
                assert "aria-label=" in button, f"bouton sans aria-label : {button}"


# ---------------------------------------------------------------------------
# C — Le contrat de formulaire : l'ordre part au serveur, inchangé
# ---------------------------------------------------------------------------


class TestContratDeFormulaire:
    def test_un_champ_cache_transporte_lordre_sous_le_nom_dimensions(
        self, client: TestClient
    ) -> None:
        """Le contrat serveur est INCHANGÉ : un unique champ `dimensions`.

        Le routeur lit `form_dict["dimensions"]` et le découpe sur les virgules.
        Les étiquettes ne sont qu'une façon de COMPOSER cette chaîne — aucune
        ligne de `app/routers/` n'a besoin de changer.
        """
        html = _render(client, "visualize_defaults")
        fields = re.findall(r'<input[^>]*name="dimensions"[^>]*>', html)
        assert len(fields) == 1, (
            "un seul champ `dimensions` doit être posté : deux champs de même "
            "nom postent deux valeurs et le serveur n'en garde qu'une, laquelle "
            f"dépend de l'ordre du DOM. Trouvé {len(fields)}."
        )

    def test_le_champ_cache_est_deja_rempli_par_le_serveur(self, client: TestClient) -> None:
        """PROTECTION CONTRE LE ZÉRO SILENCIEUX — le cas le plus grave du lot.

        Si le champ caché était laissé VIDE en attendant que le JS le peuple,
        alors le jour où `field-composer.js` ne s'exécute pas (erreur, CSP
        durcie, fichier non servi), enregistrer POSTERAIT une liste vide et
        EFFACERAIT les 6 dimensions de production — sans le moindre message.

        Prérempli côté serveur, le pire cas est un enregistrement à l'identique.
        """
        html = _render(client, "visualize_defaults")
        field = re.search(r'<input[^>]*name="dimensions"[^>]*>', html)
        assert field, 'champ name="dimensions" introuvable'
        value = re.search(r'value="([^"]*)"', field.group(0))
        assert value, "le champ des dimensions n'a pas d'attribut `value`"
        posted = [d.strip() for d in value.group(1).split(",") if d.strip()]
        assert posted == PROD_DIMENSIONS, (
            "le champ caché doit porter la valeur COURANTE dès le rendu serveur "
            f"(sinon un JS muet efface la configuration) : attendu "
            f"{PROD_DIMENSIONS}, obtenu {posted}"
        )

    def test_le_format_serialise_est_celui_que_le_routeur_sait_lire(
        self, client: TestClient
    ) -> None:
        """Le format posté doit survivre au découpage du routeur.

        Le routeur fait `[d.strip() for d in form["dimensions"].split(",") if
        d.strip()]`. On rejoue EXACTEMENT ce traitement sur la valeur rendue :
        c'est ce qui prouve que le contrat tient, et non une ressemblance de
        forme.
        """
        html = _render(client, "visualize_defaults")
        field = re.search(r'<input[^>]*name="dimensions"[^>]*value="([^"]*)"', html)
        assert field
        raw = field.group(1)
        parsed = [d.strip() for d in raw.split(",") if d.strip()]
        assert parsed == PROD_DIMENSIONS

    def test_le_champ_de_recherche_ne_poste_rien(self, client: TestClient) -> None:
        """La barre de recherche est une commande d'INTERFACE.

        Nommée, elle partirait au serveur et `form_dict` recevrait une clé
        parasite que personne n'attend.
        """
        html = _strip_comments(_render(client, "visualize_defaults"))
        search = re.search(r"<input[^>]*data-field-composer-search[^>]*>", html)
        assert search, "champ de recherche introuvable"
        assert "name=" not in search.group(0), (
            f"le champ de recherche ne doit pas porter de `name` : {search.group(0)}"
        )

    def test_la_limite_reste_editable(self, client: TestClient) -> None:
        """Non-régression : `limit` est l'autre réglage de la section, il ne
        doit pas avoir été emporté par la refonte des dimensions."""
        html = _render(client, "visualize_defaults")
        limit = re.search(r'<input[^>]*name="limit"[^>]*>', html)
        assert limit, 'champ name="limit" disparu de visualize_defaults'
        assert 'value="10"' in limit.group(0)


# ---------------------------------------------------------------------------
# D — Robustesse : les mauvaises manips, pas seulement le chemin heureux
# ---------------------------------------------------------------------------


class TestRobustesse:
    def test_etat_vide_explicite_quand_aucune_dimension(
        self, client: TestClient, config_dir: Path
    ) -> None:
        """Retirer TOUTES les dimensions : la zone ne reste jamais muette.

        Un vide sans explication est indistinguable d'un écran qui n'a pas fini
        de charger. Le message doit nommer la CONSÉQUENCE, pas seulement le fait.
        """
        (config_dir / "console.yaml").write_text(
            "default-visualize-options:\n  limit: 10\n  dimensions: []\n"
        )
        html = _render(client, "visualize_defaults")
        assert _tags(html) == [], "aucune étiquette attendue sur une liste vide"

        empty = re.search(r"<p[^>]*data-field-composer-empty[^>]*>(.*?)</p>", html, re.DOTALL)
        assert empty, "message d'état vide absent"
        assert "hidden" not in empty.group(0), (
            "sur une liste VIDE, le message d'état vide doit être VISIBLE dès le "
            "rendu serveur — masqué, il ne s'afficherait pas si le JS ne tourne pas"
        )
        assert "graphe" in empty.group(1).lower(), (
            "le message doit nommer la conséquence (le graphe n'affichera rien), "
            f"pas seulement constater le vide : {empty.group(1)!r}"
        )

    def test_message_vide_masque_quand_des_dimensions_existent(self, client: TestClient) -> None:
        """Le pendant du test précédent : pas d'alerte sur un état sain.

        Un avertissement affiché en permanence cesse d'être lu — y compris le
        jour où il est vrai.
        """
        html = _render(client, "visualize_defaults")
        empty = re.search(r"<p[^>]*data-field-composer-empty[^>]*>", html)
        assert empty, "message d'état vide absent du DOM"
        assert "hidden" in empty.group(0), (
            "avec 6 dimensions retenues, le message d'état vide doit être masqué"
        )

    def test_aucun_doublon_possible_une_dimension_deja_retenue_nest_pas_proposee(
        self, client: TestClient
    ) -> None:
        """Double-clic sur « ajouter » : une dimension DEUX FOIS casse le graphe.

        Première ligne de défense, côté serveur : le catalogue des champs
        disponibles est déjà filtré des dimensions retenues. Le JS pose la
        seconde (contrôle de l'état réel du DOM avant insertion).
        """
        html = _render(client, "visualize_defaults")
        options = re.findall(r'data-field-composer-option[^>]*data-field-value="([^"]*)"', html)
        for dim in PROD_DIMENSIONS:
            assert dim not in options, (
                f"{dim} est déjà retenue et ne doit PAS être proposée à l'ajout "
                "(une dimension en double casse le graphe Akvorado)"
            )
        assert options, "aucun champ disponible proposé — le catalogue est vide"
        assert len(options) == len(set(options)), (
            f"doublons dans le catalogue des champs disponibles : {options}"
        )

    def test_le_javascript_garde_contre_le_doublon_sur_letat_reel(self) -> None:
        """La protection anti-doublon du JS porte sur l'ÉTAT du DOM.

        Un anti-rebond temporel (`setTimeout`) laisserait passer le doublon dès
        que la machine rame — ce qui est précisément le moment où l'on
        double-clique.
        """
        js = _strip_js_comments(_read(COMPOSER_JS))
        assert "already" in js and "return" in js, (
            "field-composer.js doit refuser l'ajout d'une valeur déjà présente"
        )
        assert "setTimeout" not in js, (
            "aucun anti-rebond temporel : la protection anti-doublon doit porter "
            "sur l'état réel du DOM, pas sur un délai"
        )

    def test_recherche_sans_resultat_a_un_message_explicite(self, client: TestClient) -> None:
        """Une liste qui se vide sans rien dire est indistinguable d'un écran
        cassé : l'utilisateur conclut que le champ ne sert à rien au lieu de
        corriger sa saisie."""
        html = _strip_comments(_render(client, "visualize_defaults"))
        no_match = re.search(r"<p[^>]*data-field-composer-no-match[^>]*>(.*?)</p>", html, re.DOTALL)
        assert no_match, "message « aucun résultat » absent du DOM"
        assert "hidden" in no_match.group(0), (
            "le message « aucun résultat » doit être masqué tant qu'aucune recherche n'a été saisie"
        )
        assert no_match.group(1).strip(), "message « aucun résultat » vide"

    def test_le_javascript_nettoie_un_glisser_relache_hors_zone(self) -> None:
        """Glisser une étiquette HORS de la zone puis relâcher.

        `dragend` se déclenche TOUJOURS, y compris quand le dépôt a été refusé
        (hors zone, Échap, relâchement sur la barre du navigateur). Sans
        écouteur `dragend`, l'étiquette resterait figée en état « en cours de
        déplacement » — à moitié transparente et non cliquable — pour le reste
        de la session.
        """
        js = _read(COMPOSER_JS)
        assert '"dragend"' in js, (
            "field-composer.js doit écouter `dragend` : c'est le SEUL événement "
            "qui se déclenche quand le dépôt est refusé (glisser hors zone)"
        )
        dragend = js[js.index('addEventListener("dragend"') :]
        assert "is-dragging" in dragend or "DRAGGING_CLASS" in dragend, (
            "`dragend` doit retirer la classe d'état « en cours de déplacement »"
        )

    def test_le_javascript_autorise_explicitement_le_depot(self) -> None:
        """Piège classique du DnD HTML5 : sans `preventDefault` sur `dragover`,
        le navigateur REFUSE la zone et l'étiquette « revient » à sa place au
        relâchement, sans le moindre message."""
        js = _read(COMPOSER_JS)
        dragover = js[js.index('addEventListener("dragover"') :]
        dragover = dragover[: dragover.index('addEventListener("drop"')]
        assert "preventDefault" in dragover, (
            "`dragover` doit appeler preventDefault(), sinon le dépôt est refusé en silence"
        )

    def test_le_javascript_neutralise_entree_dans_la_recherche(self) -> None:
        """Un champ de saisie unique visible déclenche l'ENVOI IMPLICITE du
        formulaire à la touche Entrée. Mettre un changement en file parce qu'on
        a validé une recherche est exactement la mauvaise manip à empêcher."""
        js = _read(COMPOSER_JS)
        assert '"keydown"' in js and "preventDefault" in js, (
            "field-composer.js doit neutraliser Entrée dans le champ de recherche"
        )


# ---------------------------------------------------------------------------
# E — Mode dégradé : le formulaire reste utilisable sans JavaScript
# ---------------------------------------------------------------------------


class TestModeDegrade:
    def test_le_bandeau_degrade_est_visible_par_defaut(self, client: TestClient) -> None:
        """Le bandeau est retiré PAR le JS, jamais révélé par lui.

        Un bandeau caché par défaut que le JS devrait révéler ne s'afficherait
        justement PAS le jour où le JS ne tourne pas — c'est-à-dire le seul jour
        où il sert à quelque chose.
        """
        html = _render(client, "visualize_defaults")
        banner = re.search(r"<p[^>]*data-field-composer-degraded[^>]*>", html)
        assert banner, "bandeau de mode dégradé absent du DOM"
        assert "hidden" not in banner.group(0), (
            "le bandeau de mode dégradé doit être présent SANS `hidden` : c'est "
            "le CSS, conditionné au marqueur posé par le JS, qui le masque"
        )

    def test_le_marqueur_ready_nest_pose_que_par_le_javascript(self, client: TestClient) -> None:
        """Le HTML servi ne porte PAS `data-field-composer-ready`.

        S'il était rendu par Jinja, le bandeau serait masqué même quand le JS
        ne tourne pas, et l'utilisateur cliquerait dans le vide sans comprendre.
        """
        html = _strip_comments(_render(client, "visualize_defaults"))
        assert "data-field-composer-ready" not in html, (
            "le marqueur `ready` ne doit JAMAIS être rendu par le serveur : il "
            "atteste que le JS s'est exécuté"
        )
        assert "data-field-composer-ready" in _read(COMPOSER_JS), (
            "field-composer.js doit poser le marqueur `ready`"
        )

    def test_le_css_masque_les_commandes_inertes_sans_javascript(self) -> None:
        """Sans JS, les boutons ↑ / ↓ / ✕ / + sont inertes : ils sont MASQUÉS.

        Des commandes présentes mais mortes invitent à cliquer, puis à
        recliquer. Les ÉTIQUETTES, elles, restent visibles — elles sont rendues
        par Jinja, et c'est ce qui corrige le défaut de lisibilité même JS
        éteint.
        """
        css = _read(STYLE_CSS)
        assert ":not([data-field-composer-ready])" in css, (
            "style.css doit masquer les commandes tant que le JS n'a pas pris la "
            "main (règle `:not([data-field-composer-ready])`)"
        )
        assert "[data-field-composer-ready] .field-composer__degraded" in css, (
            "style.css doit masquer le bandeau dégradé une fois le JS actif"
        )

    def test_les_etiquettes_restent_lisibles_sans_javascript(self) -> None:
        """Contre-test du précédent : les étiquettes ne sont PAS masquées.

        Sans lui, « tout masquer sans JS » passerait le test précédent et
        laisserait un écran vide — pire que le champ texte d'origine.
        """
        css = _strip_css_comments(_read(STYLE_CSS))

        # On n'inspecte QUE les règles qui masquent réellement (`display: none`),
        # pas toutes celles qui ciblent l'état « sans JS » : le curseur des
        # étiquettes y est légitimement repassé en `default`, puisque rien n'est
        # déplaçable. Un test qui confondrait « sélectionné » et « masqué »
        # interdirait tout ajustement de cet état.
        hidden: set[str] = set()
        for selectors, body in re.findall(r"([^{}]+)\{([^}]*)\}", css):
            if "display: none" not in body:
                continue
            if "data-field-composer-ready" not in selectors:
                continue
            if "[data-field-composer-ready]" in selectors.replace(
                ":not([data-field-composer-ready])", ""
            ):
                continue  # règle du cas AVEC JS (bandeau dégradé)
            hidden.update(re.findall(r"(\.field-composer__[a-zA-Z0-9_-]+)", selectors))

        assert hidden, "aucune règle de masquage du mode dégradé trouvée"
        for visible in (
            ".field-composer__tag",
            ".field-composer__rank",
            ".field-composer__tag-label",
            ".field-composer__tag-code",
        ):
            assert visible not in hidden, (
                f"{visible} ne doit PAS être masquée sans JS : les étiquettes "
                "lisibles sont précisément ce qui corrige le défaut signalé"
            )


# ---------------------------------------------------------------------------
# F — Widgets de la page d'accueil : la liste exhaustive, LISIBLE
# ---------------------------------------------------------------------------


class TestWidgetsPageAccueil:
    def test_les_neuf_widgets_sont_rendus(self, client: TestClient) -> None:
        """La liste exhaustive : les 9 widgets acceptés par l'API Akvorado.

        Vérifié le 2026-08-06 contre `/api/v0/console/widget/top/<w>` : ces 9
        répondent 200, 8 autres candidats répondent 400.
        """
        html = _render(client, "homepage_widgets")
        values = re.findall(r'<input[^>]*name="widgets"[^>]*value="([^"]*)"', html)
        assert values == ALL_WIDGETS, (
            f"les {len(ALL_WIDGETS)} widgets doivent être rendus : attendu "
            f"{ALL_WIDGETS}, obtenu {values}"
        )

    def test_chaque_widget_a_un_libelle_francais_distinct_du_code(self, client: TestClient) -> None:
        """« afficher la liste exhaustive à jour » : le contenu était déjà
        complet, c'est l'AFFICHAGE qui ne l'était pas.

        `etype` ne dit rien ; « Type Ethernet » se lit. Le code technique reste
        affiché à côté parce que c'est lui qui part dans le YAML.
        """
        html = _render(client, "homepage_widgets")
        labels = re.findall(r'class="widget-checklist__label"[^>]*>([^<]*)<', html)
        assert len(labels) == len(ALL_WIDGETS), (
            f"un libellé par widget attendu, trouvé {len(labels)}"
        )
        for code, label in zip(ALL_WIDGETS, labels, strict=True):
            assert label.strip(), f"libellé vide pour {code}"
            assert label.strip() != code, (
                f"{code}: le libellé doit être un intitulé lisible, pas le code"
            )
        assert len(set(labels)) == len(labels), f"deux widgets partagent le même libellé : {labels}"

    def test_chaque_widget_dit_ce_quil_affiche(self, client: TestClient) -> None:
        """Un libellé nomme, une description explique. Les deux sont nécessaires
        pour qu'un collègue sache ce que la case va mettre sur la page d'accueil.
        """
        html = _render(client, "homepage_widgets")
        descs = re.findall(r'class="widget-checklist__desc"[^>]*>([^<]*)<', html)
        assert len(descs) == len(ALL_WIDGETS), (
            f"une description par widget attendue, trouvé {len(descs)}"
        )
        for code, desc in zip(ALL_WIDGETS, descs, strict=True):
            assert len(desc.strip()) > 10, (
                f"{code}: description trop courte pour expliquer quoi que ce soit ({desc!r})"
            )

    def test_les_widgets_coches_correspondent_a_la_valeur_reelle(self, client: TestClient) -> None:
        """Les cases cochées reflètent la configuration, ni plus ni moins.

        6 sur 9 dans la fixture, comme en production.
        """
        html = _render(client, "homepage_widgets")
        checked = re.findall(r'<input[^>]*name="widgets"[^>]*value="([^"]*)"[^>]*checked', html)
        assert checked == CHECKED_WIDGETS, (
            f"widgets cochés attendus {CHECKED_WIDGETS}, obtenu {checked}"
        )

    def test_le_distinguo_coche_non_coche_porte_sur_la_ligne_entiere(
        self, client: TestClient
    ) -> None:
        """DÉFAUT VÉCU (2026-08-06) — une case visuellement détachée de son
        libellé n'a été vue qu'à la CAPTURE D'ÉCRAN : le DOM était correct.

        La distinction doit donc porter sur la ligne entière (classe sur le
        `<label>`), pas sur la seule case à cocher.
        """
        html = _render(client, "homepage_widgets")
        items = re.findall(r'<label class="widget-checklist__item([^"]*)"', html)
        assert len(items) == len(ALL_WIDGETS)
        marked = [i for i, suffix in enumerate(items) if "is-checked" in suffix]
        expected = [ALL_WIDGETS.index(w) for w in CHECKED_WIDGETS]
        assert marked == expected, (
            "la classe `is-checked` doit être portée par le <label> de chaque "
            f"widget coché : lignes marquées {marked}, attendu {expected}"
        )

    def test_le_compte_coches_sur_total_est_affiche(self, client: TestClient) -> None:
        """« liste exhaustive » : le total doit être VISIBLE, pour qu'on sache
        qu'on a tout vu et combien est retenu — sans compter les cases à l'œil.
        """
        html = _strip_comments(_render(client, "homepage_widgets"))
        intro = re.search(r'<p class="widget-checklist__intro">(.*?)</p>', html, re.DOTALL)
        assert intro, "phrase d'introduction du catalogue absente"
        text = re.sub(r"<[^>]+>", " ", intro.group(1))
        assert str(len(ALL_WIDGETS)) in text, (
            f"le total ({len(ALL_WIDGETS)}) doit apparaître : {text!r}"
        )
        assert str(len(CHECKED_WIDGETS)) in text, (
            f"le nombre de cochés ({len(CHECKED_WIDGETS)}) doit apparaître : {text!r}"
        )


# ---------------------------------------------------------------------------
# G — Garde-fous transverses : CSP, CSS, périmètre
# ---------------------------------------------------------------------------


class TestGardeFousTransverses:
    @pytest.mark.parametrize("key", ["visualize_defaults", "homepage_widgets"])
    def test_aucun_script_inline(self, client: TestClient, key: str) -> None:
        """CSP `script-src 'self'` SANS `unsafe-eval`.

        Un `<script>` inline ou un `onclick=` est bloqué par le navigateur, et
        il l'est en SILENCE du point de vue de l'application : la page
        s'affiche, les étiquettes sont là, et rien ne bouge au clic.
        """
        html = _render(client, key)
        for script in re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL):
            assert not script.strip(), (
                f"{key}: script inline détecté — bloqué par la CSP :\n{script[:200]}"
            )
        # Gestionnaires DOM inline (`onclick=`, `onchange=`…) : bloqués par la
        # même CSP. `hx-on::after-request` n'en est pas un — c'est un attribut
        # htmx, évalué par htmx lui-même — d'où le `\s` initial qui l'exclut
        # (il est précédé d'un tiret, pas d'une espace).
        handlers = re.findall(r'\son[a-z]+\s*=\s*"[^"]*"', html)
        assert not handlers, f"{key}: gestionnaire inline détecté : {handlers}"

    def test_le_javascript_est_charge_depuis_un_fichier_statique(self, client: TestClient) -> None:
        """Chargé comme bulk-select.js : `?v=` (empreinte) et `defer`.

        Sans l'empreinte, le navigateur reconduit sa copie en cache après un
        déploiement et sert un JS antérieur — défaut vécu sur le CSS le
        2026-08-05.
        """
        html = _render(client, "visualize_defaults")
        tag = re.search(r'<script[^>]*src="/static/field-composer\.js[^"]*"[^>]*>', html)
        assert tag, "field-composer.js n'est pas chargé sur la page"
        assert "?v=" in tag.group(0), f"empreinte de version absente : {tag.group(0)}"
        assert "defer" in tag.group(0), f"`defer` absent : {tag.group(0)}"

    def test_toute_classe_du_composeur_existe_dans_le_css(self, client: TestClient) -> None:
        """DÉFAUT VÉCU, deux fois plutôt qu'une (`.view-card__akvorado-link`
        puis `.secondary`) : une classe posée sans règle CSS se rend avec le
        style par défaut du navigateur, sans la moindre erreur.

        La vérification porte sur TOUTES les classes rencontrées dans le rendu
        des deux sections du lot — un garde-fou qui n'inspecte que ce qu'il
        connaît déjà ne garde rien.
        """
        css = _read(STYLE_CSS)
        seen: set[str] = set()
        for key in ("visualize_defaults", "homepage_widgets"):
            html = _strip_comments(_render(client, key))
            for attr in re.findall(r'class="([^"]*)"', html):
                for cls in attr.split():
                    if cls.startswith(("field-composer", "widget-checklist")):
                        seen.add(cls)

        assert seen, "aucune classe du lot détectée dans le rendu"
        orphelines = sorted(cls for cls in seen if not re.search(rf"\.{re.escape(cls)}\b", css))
        assert not orphelines, (
            "Classes posées dans le template mais ABSENTES de style.css — ces "
            "éléments s'affichent hors charte, sans erreur :\n  " + "\n  ".join(orphelines)
        )

    def test_les_classes_detat_du_javascript_existent_dans_le_css(self) -> None:
        """Même piège, appliqué aux classes que seul le JS pose.

        `is-dragging` et `is-drop-target` ne figurent jamais dans le HTML servi :
        aucun test de rendu ne peut les attraper. Sans règle CSS, le
        glisser-déposer n'aurait AUCUN retour visuel — on déplacerait à
        l'aveugle.
        """
        css = _read(STYLE_CSS)
        for cls in ("is-dragging", "is-drop-target"):
            assert re.search(rf"\.{re.escape(cls)}\b", css), (
                f".{cls} est posée par field-composer.js mais absente de "
                "style.css — le glisser-déposer serait sans retour visuel"
            )

    def test_aucune_variable_css_inexistante_dans_les_regles_ajoutees(self) -> None:
        """PIÈGE VÉCU (2026-08-06) : `var(--accent-bg)` — variable inexistante —
        est ignorée par le navigateur SANS avertissement. Le hover ne faisait
        simplement rien.

        `test_design_system.py` couvre déjà tout le fichier ; ce test cible les
        règles du lot pour que l'échec DÉSIGNE ce composant.
        """
        css = _read(STYLE_CSS)
        root = re.search(r":root\s*\{([^}]*)\}", css)
        assert root, ":root introuvable"
        defined = set(re.findall(r"(--[a-zA-Z0-9-]+)\s*:", root.group(1)))

        # Commentaires retirés AVANT l'analyse : le commentaire d'en-tête du
        # composeur cite `var(--accent-bg)` comme exemple du piège évité. Le
        # lire comme du code ferait échouer ce test sur sa propre documentation.
        rules = _strip_css_comments(css)
        start = rules.index(".field-composer {")
        used = set(re.findall(r"var\(\s*(--[a-zA-Z0-9-]+)", rules[start:]))
        orphelines = sorted(used - defined)
        assert not orphelines, (
            "variables CSS utilisées par le lot mais jamais définies dans :root "
            f"(ignorées en silence par le navigateur) : {orphelines}"
        )

    def test_aucun_position_sticky_dans_une_zone_defilante_du_composeur(self) -> None:
        """PIÈGE MESURÉ cette semaine : `position: sticky` s'ancre au conteneur
        de DÉFILEMENT le plus proche, pas à la fenêtre. Un parent en
        `overflow: auto` — comme la liste des champs disponibles, qui l'est —
        l'envoie hors écran.
        """
        css = _strip_css_comments(_read(STYLE_CSS))
        block = css[css.index(".field-composer {") :]
        for match in re.finditer(r"position:\s*sticky", block):
            context = block[max(0, match.start() - 400) : match.start()]
            assert "overflow" not in context, (
                "`position: sticky` déclaré à proximité d'un conteneur défilant "
                "du composeur : il serait ancré à ce conteneur, pas à la fenêtre"
            )

    def test_les_autres_sections_ne_sont_pas_touchees(self, client: TestClient) -> None:
        """TEST DE PÉRIMÈTRE — le composeur ne doit exister que sur
        `visualize_defaults`.

        Une étiquette réordonnable posée sur une section qui n'est pas une liste
        ordonnée serait une commande sans objet.
        """
        for key in (
            "networks",
            "asns",
            "saved_filters",
            "exporter_classifiers",
            "interface_classifiers",
            "flow_inputs",
            "homepage_widgets",
        ):
            html = _strip_comments(_render(client, key))
            assert "data-field-composer" not in html, (
                f"{key}: le composeur d'étiquettes n'a rien à faire sur cette section"
            )
