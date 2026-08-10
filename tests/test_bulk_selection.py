"""Garde-fous de la sélection de masse des entrées de configuration.

Ces tests portent sur la STRUCTURE du template rendu — pas sur le rendu
visuel, qui se vérifie au navigateur, ni sur le traitement serveur de
`action=remove_selected`, développé en parallèle.

Ce qu'ils empêchent de revenir, tous des défauts déjà vécus sur ce projet :

1. Une classe CSS posée dans un template sans règle correspondante dans
   `style.css` (`.view-card__akvorado-link`, puis `.secondary`) : l'élément se
   rend avec le style par défaut du navigateur, hors charte, sans erreur.
2. Un attribut `hx-*` issu d'une extension htmx NON embarquée
   (`hx-target-error`) : ignoré en SILENCE. Faire reposer une suppression de
   masse sur un `hx-confirm` non gréé donnerait un bouton qui supprime sans
   jamais demander confirmation.
3. Du JavaScript inline sous une CSP `script-src 'self'` : bloqué par le
   navigateur, page affichée mais inerte au clic.
4. Une commande qui ment : case maîtresse ou barre d'actions sur une section
   vide, ou cases posées sur des sections qui ne sont pas des collections.
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
BULK_JS = PROJECT_ROOT / "app" / "static" / "bulk-select.js"
HTMX_MIN_JS = PROJECT_ROOT / "app" / "static" / "htmx.min.js"

# Sections qui sont des COLLECTIONS d'entrées : la sélection de masse y a un
# sens. Volumétrie de production mesurée en commentaire.
BULK_SECTIONS = [
    "networks",  # 2 entrées
    "asns",  # 1 entrée
    "saved_filters",  # 36 entrées — c'est le cas qui motive la fonctionnalité
    "exporter_classifiers",  # 3 entrées
    "interface_classifiers",  # 0 entrée — cas vide, doit rester propre
]

# Sections à clés FIXES : ce sont des réglages, pas des collections. Une case à
# cocher y serait une commande sans objet. C'est le test négatif sur ces
# sections qui prouve que la pertinence est respectée — sans lui, « ajouter des
# cases partout » passerait le reste de la suite.
NON_BULK_SECTIONS = [
    "visualize_defaults",
    "homepage_widgets",
    "flow_inputs",
    "kafka_retention",
]


# ---------------------------------------------------------------------------
# Fixtures — mêmes YAML de travail que test_config_sections_router.py, jamais
# la prod : SQLite en mémoire, fichiers en tmp_path.
# ---------------------------------------------------------------------------

_OUTLET_YAML = """\
networks:
  networks:
    100.64.0.0/10:
      name: tailscale-mesh
    192.168.1.0/24:
      name: lan-maison
core:
  exporter-classifiers:
    - ClassifyRegion("homelab")
    - ClassifyRole("edge")
    - ClassifySite("lab")
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
    - src-as
homepage-top-widgets:
  - src-as
database:
  saved-filters:
    - description: filtre 0
      content: "DstPort = 8000"
    - description: filtre 1
      content: "DstPort = 8001"
    - description: filtre 2
      content: "DstPort = 8002"
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


# Les commentaires Jinja documentent les pièges en citant le balisage concerné
# (« un `<form>` de suppression unitaire », « jamais en `<script>` inline »).
# Ce balisage cité ne part JAMAIS au navigateur : l'analyser reviendrait à
# faire échouer les garde-fous sur leur propre documentation.
_JINJA_COMMENT_RE = re.compile(r"\{#.*?#\}", re.DOTALL)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def _read_template_markup() -> str:
    """Template privé de ses commentaires — le balisage réellement rendu."""
    html = _read(TEMPLATE)
    html = _JINJA_COMMENT_RE.sub("", html)
    return _HTML_COMMENT_RE.sub("", html)


# ---------------------------------------------------------------------------
# Périmètre : qui porte des cases, qui n'en porte pas
# ---------------------------------------------------------------------------


class TestPerimetreDesCases:
    @pytest.mark.parametrize("key", BULK_SECTIONS)
    def test_section_de_collection_porte_une_case_maitresse(
        self, client: TestClient, key: str
    ) -> None:
        """Chaque section-collection NON VIDE porte une case « tout sélectionner »."""
        html = _render(client, key)
        masters = re.findall(
            r'<input[^>]*class="bulk-select__master"[^>]*data-bulk-scope="' + re.escape(key) + r'"',
            html,
        )
        if key == "interface_classifiers":
            # Section vide en prod comme dans ces fixtures : voir le test dédié
            # plus bas — pas de case maîtresse orpheline.
            assert masters == []
            return
        assert len(masters) == 1, (
            f"{key}: une case maîtresse et une seule est attendue, trouvé {len(masters)}"
        )

    @pytest.mark.parametrize(
        ("key", "expected_rows"),
        [
            ("networks", 2),
            ("asns", 1),
            ("saved_filters", 3),
            ("exporter_classifiers", 3),
            ("interface_classifiers", 0),
        ],
    )
    def test_une_case_par_entree(self, client: TestClient, key: str, expected_rows: int) -> None:
        """Autant de cases de ligne que d'entrées rendues, ni plus ni moins."""
        html = _render(client, key)
        rows = re.findall(
            r'<input[^>]*class="bulk-select__row"[^>]*data-bulk-scope="' + re.escape(key) + r'"',
            html,
        )
        assert len(rows) == expected_rows, (
            f"{key}: {expected_rows} cases de ligne attendues, trouvé {len(rows)}"
        )

    @pytest.mark.parametrize("key", NON_BULK_SECTIONS)
    def test_section_a_cles_fixes_ne_porte_aucune_case(self, client: TestClient, key: str) -> None:
        """TEST NÉGATIF — c'est lui qui prouve que la pertinence est respectée.

        Une section de réglages à clés fixes n'est pas une collection : y poser
        une case à cocher et un bouton « Supprimer la sélection » proposerait de
        supprimer un réglage qui doit exister. Sans ce test, « ajouter des cases
        partout » passerait tout le reste de la suite.
        """
        html = _render(client, key)
        for marker in ("bulk-select__row", "bulk-select__master", "bulk-actions"):
            assert marker not in html, (
                f"{key} est une section à clés fixes (un réglage, pas une "
                f"collection) : elle ne doit porter aucun marqueur de sélection "
                f"de masse, or `{marker}` y est présent"
            )


# ---------------------------------------------------------------------------
# Contrat du formulaire groupé
# ---------------------------------------------------------------------------


class TestContratDuFormulaireGroupe:
    @pytest.mark.parametrize("key", [k for k in BULK_SECTIONS if k != "interface_classifiers"])
    def test_formulaire_groupe_poste_remove_selected_sur_la_bonne_route(
        self, client: TestClient, key: str
    ) -> None:
        """Contrat serveur : POST /config/sections/{key} avec action=remove_selected."""
        html = _render(client, key)
        form = re.search(
            r'<form\b[^>]*id="bulk-form-' + re.escape(key) + r'"[^>]*>(.*?)</form>',
            html,
            re.DOTALL,
        )
        assert form, f"{key}: formulaire de masse `bulk-form-{key}` introuvable"
        tag = form.group(0)
        assert f'hx-post="/config/sections/{key}"' in tag, (
            f"{key}: le formulaire de masse doit poster sur sa propre section"
        )
        assert '<input type="hidden" name="action" value="remove_selected">' in tag, (
            f"{key}: le champ caché action=remove_selected est le contrat convenu "
            "avec le traitement serveur"
        )

    @pytest.mark.parametrize("key", [k for k in BULK_SECTIONS if k != "interface_classifiers"])
    def test_les_cases_sont_rattachees_au_formulaire_groupe(
        self, client: TestClient, key: str
    ) -> None:
        """Chaque case poste `selected` DANS le formulaire de masse.

        Les cases vivent dans le tableau, le formulaire de masse est son voisin :
        c'est l'attribut HTML5 `form="…"` qui les relie. Sans lui, les cases
        seraient hors formulaire et la requête partirait avec zéro `selected` —
        un « supprimer la sélection » qui ne supprime rien, ou pire, que le
        serveur interprète comme une sélection vide.
        """
        html = _render(client, key)
        rows = re.findall(r"<input[^>]*bulk-select__row[^>]*>", html)
        assert rows, f"{key}: aucune case de ligne rendue"
        for row in rows:
            assert f'form="bulk-form-{key}"' in row, (
                f"{key}: case non rattachée au formulaire de masse -> {row!r}"
            )
            assert 'name="selected"' in row, (
                f"{key}: la case doit poster sous le nom `selected` -> {row!r}"
            )
            assert re.search(r'value="[^"]+"', row), (
                f"{key}: la case doit porter la clé/l'index de son entrée -> {row!r}"
            )

    def test_les_formulaires_de_masse_ne_sont_pas_imbriques_dans_un_autre_formulaire(
        self,
    ) -> None:
        """Aucun `<form>` imbriqué dans un autre — HTML invalide, réparé en silence.

        Chaque ligne porte déjà son formulaire de suppression unitaire. Un
        formulaire de masse qui envelopperait le tableau imbriquerait des
        formulaires : le navigateur supprime alors le formulaire intérieur sans
        avertir, et les boutons « Supprimer » unitaires cessent de poster. D'où
        le rattachement par `form="…"` plutôt que par imbrication.
        """
        html = _read_template_markup()
        depth = 0
        for token in re.findall(r"</?form\b", html):
            if token == "<form":
                depth += 1
                assert depth <= 1, (
                    "formulaire imbriqué détecté dans config_sections.html — "
                    "le navigateur supprimerait le formulaire intérieur en silence"
                )
            else:
                depth -= 1
        assert depth == 0, "balises <form> déséquilibrées dans config_sections.html"


# ---------------------------------------------------------------------------
# Action destructive
# ---------------------------------------------------------------------------


class TestActionDestructive:
    @pytest.mark.parametrize("key", [k for k in BULK_SECTIONS if k != "interface_classifiers"])
    def test_bouton_groupe_est_marque_destructif(self, client: TestClient, key: str) -> None:
        """Classe `danger` : jamais l'accent turquoise sur une action destructive."""
        html = _render(client, key)
        button = re.search(r"<button[^>]*bulk-actions__submit[^>]*>", html)
        assert button, f"{key}: bouton de suppression groupée introuvable"
        assert "danger" in button.group(0), (
            f"{key}: le bouton supprime N entrées de configuration — il doit porter "
            "la classe `danger`, jamais le registre visuel d'une action anodine"
        )

    @pytest.mark.parametrize("key", [k for k in BULK_SECTIONS if k != "interface_classifiers"])
    def test_hx_confirm_est_porte_par_le_formulaire_pas_par_le_bouton(
        self, client: TestClient, key: str
    ) -> None:
        """`hx-confirm` doit être posé LÀ OÙ HTMX LE CHERCHE.

        DÉFAUT TROUVÉ EN ÉCRIVANT CE LOT, et invisible autrement : htmx résout
        la confirmation par `re(requestElt, "hx-confirm")` — lu dans le bundle
        servi — c'est-à-dire depuis l'élément portant `hx-post` (le formulaire),
        en remontant ses ANCÊTRES. Un `hx-confirm` écrit sur le bouton est un
        DESCENDANT du formulaire : htmx ne l'y cherche jamais.

        Conséquence concrète du placement fautif : le compte exact réinjecté par
        bulk-select.js n'apparaissait jamais dans la confirmation, sans erreur
        ni avertissement. Même famille que `hx-target-error` — un attribut posé
        là où le framework ne regarde pas est ignoré en silence.
        """
        html = _render(client, key)
        form = re.search(
            r'<form\b[^>]*id="bulk-form-' + re.escape(key) + r'"[^>]*>', html, re.DOTALL
        )
        assert form, f"{key}: formulaire de masse introuvable"
        assert "hx-confirm=" in form.group(0), (
            f"{key}: `hx-confirm` absent du FORMULAIRE. Posé sur le bouton, il "
            "serait ignoré en silence : la suppression de masse partirait sans "
            "aucune confirmation."
        )

        # Et le JS doit réécrire le compte sur le formulaire, pas sur le bouton.
        js = _read(BULK_JS)
        assert re.search(r'form\.setAttribute\(\s*\n?\s*"hx-confirm"', js), (
            "bulk-select.js doit poser le compte dynamique sur le FORMULAIRE "
            '(`form.setAttribute("hx-confirm", …)`) : sur le bouton, htmx ne '
            "le lirait jamais et la confirmation resterait sans chiffre"
        )

    def test_hx_confirm_est_bien_embarque_dans_htmx(self) -> None:
        """`hx-confirm` doit exister dans le htmx SERVI, pas seulement dans la doc.

        PIÈGE VÉCU (2026-08-06) : `hx-target-error` a été posé sur un formulaire
        alors qu'il vient d'une EXTENSION htmx non embarquée. L'attribut a été
        ignoré en SILENCE — un garde-fou qui ne garde rien. Faire reposer une
        suppression de masse sur un `hx-confirm` absent du bundle donnerait un
        bouton qui supprime sans jamais demander confirmation.
        """
        htmx = _read(HTMX_MIN_JS)
        assert "hx-confirm" in htmx, (
            "hx-confirm est absent de app/static/htmx.min.js : l'attribut serait "
            "ignoré en silence et la confirmation n'aurait jamais lieu"
        )
        assert "hx-disabled-elt" in htmx, (
            "hx-disabled-elt est absent du bundle : la protection contre le "
            "double-submit ne s'appliquerait pas"
        )

    @pytest.mark.parametrize("key", [k for k in BULK_SECTIONS if k != "interface_classifiers"])
    def test_formulaire_groupe_protege_du_double_submit(self, client: TestClient, key: str) -> None:
        """Motif du projet : hx-sync=this:replace + hx-disabled-elt=find button.

        Un double-clic sur une suppression de masse enverrait deux requêtes de
        suppression : la seconde porterait sur des index déjà décalés par la
        première.
        """
        html = _render(client, key)
        form = re.search(
            r'<form\b[^>]*id="bulk-form-' + re.escape(key) + r'"[^>]*>', html, re.DOTALL
        )
        assert form, f"{key}: formulaire de masse introuvable"
        tag = form.group(0)
        assert 'hx-sync="this:replace"' in tag, f"{key}: hx-sync manquant"
        assert 'hx-disabled-elt="find button"' in tag, f"{key}: hx-disabled-elt manquant"

    @pytest.mark.parametrize("key", [k for k in BULK_SECTIONS if k != "interface_classifiers"])
    def test_barre_est_masquee_tant_que_rien_n_est_coche(
        self, client: TestClient, key: str
    ) -> None:
        """Au rendu initial, aucune case n'est cochée : la barre doit être `hidden`.

        Un bouton « Supprimer la sélection » cliquable avec 0 case cochée invite
        à cliquer, puis à recliquer, sur une action destructive sans objet.
        """
        html = _render(client, key)
        form = re.search(
            r'<form\b[^>]*id="bulk-form-' + re.escape(key) + r'"[^>]*>', html, re.DOTALL
        )
        assert form, f"{key}: formulaire de masse introuvable"
        assert "hidden" in form.group(0), (
            f"{key}: la barre d'actions doit être `hidden` au rendu initial (aucune case cochée)"
        )
        # Et le CSS ne doit pas écraser `hidden` avec son `display: flex`.
        css = _read(STYLE_CSS)
        assert re.search(r"\.bulk-actions\[hidden\]\s*\{[^}]*display:\s*none", css), (
            "`.bulk-actions` déclare `display: flex`, de spécificité supérieure au "
            "`display: none` que le navigateur associe à `hidden` : sans la règle "
            "`.bulk-actions[hidden] { display: none }`, la barre resterait visible "
            "en permanence"
        )


# ---------------------------------------------------------------------------
# Section vide et cases orphelines
# ---------------------------------------------------------------------------


class TestSectionVide:
    def test_section_vide_n_a_ni_case_maitresse_ni_barre_d_actions(
        self, client: TestClient
    ) -> None:
        """`interface_classifiers` compte 0 entrée en prod — cas nominal, pas un bord.

        Une case « tout sélectionner » sans aucune ligne à sélectionner, et une
        barre d'actions qui ne peut agir sur rien, sont des commandes qui mentent.
        """
        html = _render(client, "interface_classifiers")
        assert "bulk-select__master" not in html, "case maîtresse orpheline sur une section vide"
        assert "bulk-select__row" not in html, "case de ligne sur une section vide"
        assert 'id="bulk-form-interface_classifiers"' not in html, (
            "barre d'actions fantôme sur une section vide"
        )

    def test_toutes_les_sections_de_collection_deviennent_vides_proprement(
        self, memory_conn: sqlite3.Connection, tmp_path: Path
    ) -> None:
        """Le cas vide vaut pour TOUTES les sections, pas seulement celle qui l'est en prod.

        `saved_filters` compte 36 entrées aujourd'hui ; il en comptera 0 le jour
        où on les aura toutes supprimées — précisément via cette fonctionnalité.
        """
        from app.routers import config_sections as sections_router

        (tmp_path / "outlet.yaml").write_text("networks: {}\ncore: {}\n")
        (tmp_path / "akvorado.yaml").write_text("clickhouse: {}\n")
        (tmp_path / "console.yaml").write_text("database: {}\n")
        (tmp_path / "inlet.yaml").write_text("flow: {}\n")

        app = FastAPI()
        app.include_router(sections_router.router)
        app.dependency_overrides[sections_router.get_db_connection] = lambda: memory_conn
        app.dependency_overrides[sections_router.get_config_dir] = lambda: str(tmp_path)
        client = TestClient(app)

        for key in BULK_SECTIONS:
            html = _render(client, key)
            assert "bulk-select__master" not in html, f"{key} vide : case maîtresse orpheline"
            assert f'id="bulk-form-{key}"' not in html, f"{key} vide : barre d'actions fantôme"


# ---------------------------------------------------------------------------
# CSP, JS et charte visuelle
# ---------------------------------------------------------------------------


class TestCspEtCharte:
    def test_aucun_javascript_inline_dans_le_template(self) -> None:
        """CSP `script-src 'self'` : un `<script>` inline ou un `onclick=` est BLOQUÉ.

        Et il l'est de façon invisible pour l'application : la page s'affiche,
        les cases sont là, rien ne réagit au clic.
        """
        html = _read_template_markup()
        for tag in re.findall(r"<script\b[^>]*>", html):
            assert "src=" in tag, (
                f"script inline détecté (bloqué par la CSP) -> {tag!r} — "
                "tout JS doit vivre dans un fichier de app/static/"
            )
        assert not re.search(r"\bon(click|change|input|submit)\s*=", html), (
            "gestionnaire d'événement inline (onclick=…) détecté : bloqué par la CSP"
        )

    def test_le_script_de_selection_est_charge_depuis_un_fichier_statique(
        self, client: TestClient
    ) -> None:
        """Chargé en `src` + empreinte `?v=` comme htmx-config.js.

        Sans l'empreinte, le navigateur reconduit sa copie en cache après
        déploiement et sert un JS antérieur — défaut vécu le 2026-08-05 sur le
        CSS, dont l'écran de configuration s'affichait entièrement sans style.
        """
        assert BULK_JS.exists(), "app/static/bulk-select.js est absent"
        html = _render(client, "networks")
        script = re.search(r'<script[^>]*src="/static/bulk-select\.js[^"]*"[^>]*>', html)
        assert script, "bulk-select.js n'est pas chargé par la page"
        tag = script.group(0)
        assert "?v=" in tag, (
            "empreinte de cache manquante sur bulk-select.js (motif `?v={{ static_version }}`)"
        )
        # `static_version` doit avoir été RÉSOLU par Jinja, pas rendu tel quel.
        assert "{{" not in tag and "static_version" not in tag, (
            f"la variable de version n'a pas été interpolée -> {tag!r}"
        )

    def test_le_script_gere_l_etat_partiel_de_la_case_maitresse(self) -> None:
        """`indeterminate` : après « tout cocher » puis un décochage, la case ne ment pas.

        Une case maîtresse simplement décochée AFFIRME que rien n'est
        sélectionné alors que N-1 entrées le sont. Sur une suppression de masse,
        c'est le pire défaut possible.
        """
        js = _read(BULK_JS)
        assert "indeterminate" in js, (
            "bulk-select.js ne gère pas l'état partiel de la case maîtresse"
        )

    def test_le_script_recalcule_apres_un_swap_htmx(self) -> None:
        """Les tableaux sont réinjectés par HTMX : la sélection doit se recalculer.

        Sans cela, la barre resterait affichée avec l'ancien compte après une
        suppression — désignant une sélection qui n'existe plus.
        """
        js = _read(BULK_JS)
        assert "htmx:afterSwap" in js, "bulk-select.js ne se recalcule pas après un swap HTMX"

    @pytest.mark.parametrize("key", BULK_SECTIONS)
    def test_toutes_les_classes_de_selection_existent_dans_le_css(
        self, client: TestClient, key: str
    ) -> None:
        """Une classe posée sans règle CSS se rend au style par défaut du navigateur.

        DÉFAUT VÉCU deux fois (2026-08-06) : `.view-card__akvorado-link`, puis
        `.secondary` — cette dernière introduite par le lot même qui corrigeait
        la première. Le garde-fou de `test_design_system` n'avait pas vu la
        seconde parce qu'il ne vérifiait que les classes d'une liste connue.

        On énumère donc la SOURCE : les attributs `class` de la page RÉELLEMENT
        rendue, pas une liste de noms attendus, et pas le template brut (dont
        les commentaires citent du balisage qui ne part jamais au navigateur).
        """
        css = _read(STYLE_CSS)
        html = _render(client, key)

        classes: set[str] = set()
        for attr in re.findall(r'class="([^"]*)"', html):
            classes.update(attr.split())

        # Seules les classes introduites par ce lot sont de son ressort ; les
        # autres relèvent de test_design_system.
        introduced = sorted(c for c in classes if c.startswith("bulk-"))
        if key == "interface_classifiers":
            # Section vide : aucune classe de sélection n'a lieu d'être rendue.
            assert introduced == []
            return
        assert introduced, f"{key}: aucune classe de sélection rendue"

        orphelines = [c for c in introduced if not re.search(rf"\.{re.escape(c)}\b", css)]
        assert not orphelines, (
            "classes rendues mais ABSENTES de style.css — ces éléments "
            f"s'affichent au style par défaut du navigateur : {orphelines}"
        )

    def test_le_css_de_selection_n_utilise_aucune_couleur_en_dur(self) -> None:
        """Tout dérive des variables de `:root` — aucun hexadécimal hors de ce bloc."""
        css = _read(STYLE_CSS)
        start = css.find("/* ---------- Sélection de masse")
        assert start != -1, "bloc CSS de la sélection de masse introuvable"
        block = css[start:]
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b", block), (
            "couleur hexadécimale en dur dans le CSS de la sélection de masse"
        )

    def test_les_variables_css_utilisees_existent_dans_root(self) -> None:
        """Une `var(--xxx)` inexistante est ignorée en SILENCE par le navigateur.

        PIÈGE VÉCU (2026-08-06) : `var(--accent-bg)` — variable jamais définie.
        La déclaration est ignorée sans le moindre avertissement.

        Les COMMENTAIRES sont retirés avant l'analyse : ce test lisait le CSS
        brut et prenait pour une utilisation réelle la mention `var(--accent-bg)`
        d'un commentaire qui documente précisément ce piège. Il échouait donc
        sur la documentation du défaut qu'il protège — un faux positif qui,
        laissé en place, apprend à ignorer le garde-fou. Même motif que celui
        rencontré sur le contrôle des couleurs en dur.
        """
        css = _read(STYLE_CSS)
        root = re.search(r":root\s*\{([^}]*)\}", css)
        assert root, ":root introuvable"
        defined = set(re.findall(r"(--[a-zA-Z0-9-]+)\s*:", root.group(1)))

        effective = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
        used = set(re.findall(r"var\(\s*(--[a-zA-Z0-9-]+)", effective))
        orphelines = sorted(used - defined)
        assert not orphelines, f"variables utilisées mais non définies dans :root : {orphelines}"

    def test_la_barre_d_actions_reste_atteignable_sur_une_longue_liste(self) -> None:
        """36 entrées (`saved_filters` en prod) : la barre reste à l'écran.

        Cocher une case en bas de liste puis remonter chercher le bouton fait
        perdre la sélection de vue — et un bouton qu'on cherche est un bouton
        sur lequel on finit par cliquer sans relire.

        Ce test vérifiait initialement `position: sticky`, c'est-à-dire le
        MOYEN et non l'intention. Or `sticky` s'ancre au plus proche ancêtre
        créant un contexte de défilement, pas à la fenêtre : le parent
        `#section-editor-panel` portant `overflow: auto`, la barre collait au
        bas d'un conteneur de 2848 px et se retrouvait HORS ÉCRAN
        (`top: -204`, mesuré au navigateur le 2026-08-06). Le test était vert
        avec le défaut en place — il garantissait la présence d'une propriété,
        pas le comportement qu'elle était censée produire.

        L'assertion porte donc sur ce qui compte : la barre est ancrée à la
        FENÊTRE, quel que soit le conteneur qui la porte.
        """
        css = _read(STYLE_CSS)
        block = re.search(r"\.bulk-actions\s*\{([^}]*)\}", css)
        assert block, "règle .bulk-actions introuvable"
        rules = block.group(1)

        assert "position: fixed" in rules, (
            ".bulk-actions doit être ancrée à la FENÊTRE (`position: fixed`). "
            "`sticky` s'ancre au conteneur de défilement le plus proche : avec "
            "un parent en `overflow: auto`, la barre sort de l'écran."
        )
        assert re.search(r"bottom:\s*\d", rules), (
            ".bulk-actions doit déclarer un `bottom` : sans lui, `fixed` la "
            "laisse à sa position de flux, donc hors écran après défilement."
        )
        assert re.search(r"z-index:\s*\d", rules), (
            ".bulk-actions doit passer AU-DESSUS du contenu qu'elle recouvre, "
            "sinon elle est masquée par les panneaux qui suivent."
        )
