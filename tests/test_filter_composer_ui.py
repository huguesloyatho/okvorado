"""Garde-fous de l'écran de composition des filtres enregistrés.

CE QUE CE FICHIER EMPÊCHE DE REVENIR.

Le défaut d'origine, signalé par l'utilisateur : la section « filtres
enregistrés » rendait DEUX CHAMPS TEXTE NUS (`description`, `content`). Pour
enregistrer un filtre il fallait connaître par cœur la syntaxe d'Akvorado ET le
nom exact de ses 61 colonnes. Les routes serveur du compositeur
(`/config/filters/fields`, `/values`, `/validate`) existaient et étaient
montées — mais AUCUN écran ne les appelait. Du code livré que personne ne
pouvait atteindre.

Le garde-fou central est donc celui-ci : **la section CÂBLE réellement les
routes**. Un compositeur qui n'interroge rien serait exactement le défaut
d'origine, avec plus de balisage.

S'y ajoutent les quatre pièges déjà vécus sur ce projet, tous de la même
famille — une référence à quelque chose qui n'existe pas, avalée en SILENCE :

1. Une classe CSS posée sans règle dans `style.css` : l'élément se rend avec le
   style par défaut du navigateur (`.view-card__akvorado-link`, `.secondary`).
2. Une variable `var(--xxx)` inexistante : la déclaration est ignorée sans le
   moindre avertissement.
3. Un attribut `hx-*` d'une extension htmx NON embarquée (`hx-target-error`).
4. Du JavaScript inline sous une CSP `script-src 'self'` : page affichée, écran
   inerte au clic.

Ces tests portent sur la STRUCTURE du HTML rendu. Le rendu visuel se vérifie au
navigateur, ce qui est le rôle de l'utilisateur.
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
COMPOSER_JS = PROJECT_ROOT / "app" / "static" / "filter-composer.js"
HTMX_MIN_JS = PROJECT_ROOT / "app" / "static" / "htmx.min.js"

SECTION = "saved_filters"


# ---------------------------------------------------------------------------
# Fixtures — mêmes YAML de travail que test_bulk_selection.py, jamais la prod.
# ---------------------------------------------------------------------------

_OUTLET_YAML = """\
networks:
  networks:
    100.64.0.0/10:
      name: tailscale-mesh
core:
  exporter-classifiers: []
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


@pytest.fixture
def html(client: TestClient) -> str:
    response = client.get(f"/config/sections/{SECTION}")
    assert response.status_code == 200, "la section des filtres enregistrés n'a pas rendu"
    return response.text


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# Les commentaires Jinja de ce projet CITENT volontairement le balisage piégeux
# qu'ils documentent (`onclick=`, `hx-target-error`). Ce balisage cité ne part
# jamais au navigateur : l'analyser ferait échouer les garde-fous sur leur
# propre documentation — faux positif déjà rencontré trois fois ici.
_JINJA_COMMENT_RE = re.compile(r"\{#.*?#\}", re.DOTALL)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def _markup(html: str) -> str:
    """HTML privé de ses commentaires — le balisage réellement rendu."""
    return _HTML_COMMENT_RE.sub("", _JINJA_COMMENT_RE.sub("", html))


def _tag_containing(html: str, needle: str) -> str:
    """Retourne la balise ouvrante qui contient `needle`."""
    idx = html.find(needle)
    assert idx != -1, f"{needle!r} introuvable dans le rendu"
    start = html.rfind("<", 0, idx)
    end = html.find(">", idx)
    assert start != -1 and end != -1
    return html[start : end + 1]


# ---------------------------------------------------------------------------
# 1. Le compositeur EXISTE et CÂBLE les routes serveur
#    — c'est le garde-fou qui répond au défaut signalé.
# ---------------------------------------------------------------------------


class TestCablageDesRoutes:
    def test_la_section_rend_un_compositeur(self, html: str) -> None:
        """Sans racine `data-filter-composer`, le script n'a aucun point d'accroche."""
        assert "data-filter-composer" in html, (
            "La section ne rend aucun compositeur : on retombe sur les deux "
            "champs texte nus, le défaut exact signalé par l'utilisateur."
        )

    def test_une_barre_de_recherche_interroge_la_route_des_champs(self, html: str) -> None:
        """DÉFAUT D'ORIGINE : les routes existaient, aucun écran ne les appelait.

        C'est le test central de ce fichier. Un compositeur qui n'interroge
        jamais `/config/filters/fields` n'a rien à proposer au clic — il faut
        donc toujours connaître les 61 colonnes par cœur.
        """
        markup = _markup(html)
        tag = _tag_containing(markup, 'hx-get="/config/filters/fields"')

        assert 'type="search"' in tag or 'name="q"' in tag, (
            "la recherche n'est pas câblée sur un champ de saisie"
        )
        assert "hx-trigger=" in tag, "sans hx-trigger, la recherche ne part jamais"
        assert "hx-target=" in tag, (
            "sans hx-target, la réponse remplacerait le champ de recherche lui-même"
        )

    def test_la_recherche_se_declenche_au_fil_de_la_frappe(self, html: str) -> None:
        """`input changed delay:` — et pas seulement au `submit`.

        Sans `changed`, chaque flèche du clavier relance une requête identique ;
        sans `delay`, taper « proxy-frontal » en produit neuf.
        """
        tag = _tag_containing(_markup(html), 'hx-get="/config/filters/fields"')
        trigger = re.search(r'hx-trigger="([^"]*)"', tag)
        assert trigger, "hx-trigger absent de la barre de recherche"
        valeur = trigger.group(1)

        assert "input" in valeur, f"la recherche ne réagit pas à la frappe : {valeur!r}"
        assert "changed" in valeur, (
            f"sans `changed`, une touche sans effet relance la requête : {valeur!r}"
        )
        assert "delay:" in valeur, (
            f"sans `delay`, chaque caractère déclenche une requête : {valeur!r}"
        )

    def test_la_zone_d_expression_est_validee_par_akvorado(self, html: str) -> None:
        """La validation doit être câblée sur la route, pas sur une regex maison.

        Une grammaire réimplémentée côté client divergerait de la version
        d'Akvorado déployée : elle accepterait des filtres que la console
        refuse, et l'erreur ne se découvrirait qu'après enregistrement.
        """
        markup = _markup(html)
        tag = _tag_containing(markup, 'hx-post="/config/filters/validate"')

        assert "data-composer-expression" in tag, (
            "la validation n'est pas posée sur le champ d'expression"
        )
        assert 'name="content"' in tag, (
            "le champ validé n'est pas celui qui sera enregistré : on validerait "
            "une expression différente de celle qui part au serveur"
        )
        assert "hx-target=" in tag, "sans hx-target, le verdict remplacerait le champ de saisie"

    def test_la_validation_se_declenche_au_fil_de_la_frappe(self, html: str) -> None:
        tag = _tag_containing(_markup(html), 'hx-post="/config/filters/validate"')
        trigger = re.search(r'hx-trigger="([^"]*)"', tag)
        assert trigger, "hx-trigger absent du champ d'expression"
        valeur = trigger.group(1)

        assert "input" in valeur, f"l'expression n'est pas validée à la frappe : {valeur!r}"
        assert "changed" in valeur and "delay:" in valeur, (
            f"validation non amortie : une requête par caractère : {valeur!r}"
        )

    def test_une_zone_de_verdict_est_rendue_avant_toute_frappe(self, html: str) -> None:
        """Le verdict a une place RÉSERVÉE dès l'ouverture.

        Une zone qui n'apparaît qu'après la première validation laisse croire,
        tant qu'elle est absente, que rien ne vérifie l'expression. Elle ferait
        aussi sauter le bouton « Ajouter » sous le curseur au moment du clic.
        """
        markup = _markup(html)
        tag = _tag_containing(_markup(html), 'hx-post="/config/filters/validate"')
        cible = re.search(r'hx-target="#([^"]+)"', tag)
        assert cible, "hx-target du champ d'expression illisible"

        assert f'id="{cible.group(1)}"' in markup, (
            f"la cible #{cible.group(1)} du verdict n'existe pas dans la page : "
            "htmx n'aurait nulle part où écrire le verdict, en silence"
        )


# ---------------------------------------------------------------------------
# 2. Les opérateurs — un compositeur qui n'offre que `=` ne compose rien
# ---------------------------------------------------------------------------


class TestOperateurs:
    #  `=` seul ne permet ni d'exclure, ni de combiner, ni de grouper.
    ATTENDUS = ["=", "!=", "AND", "OR", "IN", "NOT", "(", ")"]

    @pytest.mark.parametrize("operateur", ATTENDUS)
    def test_l_operateur_est_present_et_cliquable(self, html: str, operateur: str) -> None:
        markup = _markup(html)
        assert f'data-composer-operator="{operateur}"' in markup, (
            f"opérateur {operateur!r} absent — sans lui, l'expression doit être "
            "complétée à la main, ce que le compositeur est censé éviter"
        )

        tag = _tag_containing(markup, f'data-composer-operator="{operateur}"')
        assert tag.startswith("<button"), (
            f"{operateur!r} n'est pas un <button> : un élément non focalisable "
            "est inatteignable au clavier"
        )
        assert 'type="button"' in tag, (
            f"{operateur!r} sans type=button : dans un <form>, un bouton par "
            "défaut SOUMET le formulaire — cliquer un opérateur enregistrerait "
            "le filtre à moitié composé"
        )

    def test_les_parentheses_sont_bien_les_deux(self, html: str) -> None:
        """Une parenthèse ouvrante sans fermante ne groupe rien."""
        markup = _markup(html)
        assert 'data-composer-operator="("' in markup
        assert 'data-composer-operator=")"' in markup

    def test_une_commande_vide_l_expression(self, html: str) -> None:
        """Reprendre de zéro est un geste courant sur une expression composée."""
        assert "data-composer-clear" in _markup(html)

    def test_les_boutons_du_compositeur_ne_soumettent_jamais_le_formulaire(self, html: str) -> None:
        """TOUT bouton du compositeur porte `type="button"`.

        Un `<button>` sans `type` vaut `type="submit"`. Ces boutons vivent dans
        (ou à côté de) le formulaire d'ajout : sans cet attribut, cliquer un
        opérateur enregistrerait le filtre en cours de composition.
        """
        markup = _markup(html)
        for attribut in ("data-composer-operator", "data-composer-clear"):
            for tag in re.findall(r"<button[^>]*" + attribut + r"[^>]*>", markup):
                assert 'type="button"' in tag, f"bouton sans type=button : {tag!r}"


# ---------------------------------------------------------------------------
# 3. Le contrat serveur du formulaire d'ajout — INCHANGÉ
# ---------------------------------------------------------------------------


class TestContratDuFormulaireDAjout:
    def _form(self, html: str) -> str:
        """Le formulaire d'ajout, du <form> à son </form>."""
        markup = _markup(html)
        forms = re.findall(r"<form[^>]*>.*?</form>", markup, re.DOTALL)
        candidats = [f for f in forms if 'name="action" value="add"' in f]
        assert candidats, "aucun formulaire d'ajout trouvé dans la section"
        return candidats[0]

    def test_le_formulaire_poste_toujours_vers_la_meme_route(self, html: str) -> None:
        """Le compositeur ne doit RIEN changer au contrat du routeur."""
        form = self._form(html)
        assert 'hx-post="/config/sections/saved_filters"' in form, (
            "la cible du formulaire d'ajout a changé : le routeur ne recevrait "
            "plus l'enregistrement"
        )

    def test_le_formulaire_poste_action_add(self, html: str) -> None:
        form = self._form(html)
        assert '<input type="hidden" name="action" value="add">' in form

    @pytest.mark.parametrize("champ", ["description", "content"])
    def test_le_formulaire_poste_les_deux_champs_attendus(self, html: str, champ: str) -> None:
        """`description` et `content` : les deux seuls champs que le routeur lit.

        Le compositeur écrit DANS `content`, il n'ajoute aucun champ à l'envoi.
        Renommer `content` en `expression` casserait le routeur sans qu'aucune
        erreur ne s'affiche — le serveur verrait simplement un champ manquant.
        """
        form = self._form(html)
        assert f'name="{champ}"' in form, (
            f"le champ `{champ}` a disparu du formulaire : contrat serveur rompu"
        )

    def test_l_expression_est_un_champ_de_formulaire_ordinaire(self, html: str) -> None:
        """REPLI SANS JS : le champ d'expression doit être soumissible tel quel.

        S'il devenait un `<div contenteditable>` piloté par le script, un JS non
        exécuté rendrait l'enregistrement IMPOSSIBLE — le compositeur, qui est
        une aide, deviendrait un passage obligé.
        """
        form = self._form(html)
        champ = _tag_containing(form, 'name="content"')
        assert champ.startswith("<textarea") or champ.startswith("<input"), (
            f"le champ d'expression n'est pas un champ de formulaire : {champ!r}"
        )

    def test_le_formulaire_reste_utilisable_sans_le_compositeur(self, html: str) -> None:
        """Les deux champs vivent DANS le formulaire, pas dans le compositeur.

        Un champ posé hors du `<form>` ne serait pas envoyé à la soumission.
        """
        form = self._form(html)
        assert 'id="filters-description"' in form
        assert 'id="filters-content"' in form

    def test_le_motif_htmx_du_projet_est_respecte(self, html: str) -> None:
        """`hx-sync` + `hx-disabled-elt` : protection contre le double envoi."""
        tag = _tag_containing(_markup(html), 'hx-post="/config/sections/saved_filters"')
        assert 'hx-sync="this:replace"' in tag
        assert 'hx-disabled-elt="find button"' in tag


# ---------------------------------------------------------------------------
# 4. Paires label/champ enveloppées — défaut signalé par capture le 2026-08-06
# ---------------------------------------------------------------------------


class TestPairesLabelChamp:
    def test_chaque_label_du_formulaire_est_dans_un_field(self, html: str) -> None:
        """Dans `.config-form`, label et champ sont des cases de grille SÉPARÉES.

        DÉFAUT VÉCU (2026-08-06, capture à l'appui) : la grille étant en
        `auto-fit`, le retour à la ligne tombait AU MILIEU d'une paire. Le label
        se retrouvait seul en fin de ligne et paraissait annoncer le champ
        SUIVANT au lieu du sien. `.field` emballe la paire et devient l'unique
        case de grille, indivisible par construction.
        """
        markup = _markup(html)
        forms = re.findall(r"<form[^>]*>.*?</form>", markup, re.DOTALL)
        form = next(f for f in forms if 'name="action" value="add"' in f)

        for label_id in ("filters-description", "filters-content"):
            label = f'<label for="{label_id}">'
            idx = form.find(label)
            assert idx != -1, f"label de {label_id} introuvable"

            # Le `.field` doit OUVRIR avant le label et se refermer après le
            # champ : on vérifie qu'un `<div class="field">` précède le label
            # sans qu'un `</div>` ne s'intercale.
            avant = form[:idx]
            ouverture = avant.rfind('class="field"')
            assert ouverture != -1, (
                f"{label_id} : label hors de tout `.field` — sur fenêtre étroite "
                "il deviendra orphelin de son champ (défaut 2026-08-06)"
            )
            assert "</div>" not in avant[ouverture:], (
                f"{label_id} : le `.field` est refermé avant le label"
            )

    def test_la_recherche_a_aussi_son_field(self, html: str) -> None:
        """Même règle pour la barre de recherche du compositeur."""
        markup = _markup(html)
        idx = markup.find('<label for="composer-search">')
        assert idx != -1, "la barre de recherche n'a pas de label"
        avant = markup[:idx]
        ouverture = avant.rfind('class="field"')
        assert ouverture != -1 and "</div>" not in avant[ouverture:], (
            "le label de recherche n'est pas emballé avec son champ"
        )

    def test_chaque_champ_a_un_label_associe(self, html: str) -> None:
        """Un champ sans `<label for>` n'est pas annoncé aux lecteurs d'écran."""
        markup = _markup(html)
        for champ_id in ("filters-description", "filters-content", "composer-search"):
            assert f'<label for="{champ_id}">' in markup, f"aucun label associé à #{champ_id}"


# ---------------------------------------------------------------------------
# 5. Les quatre pièges du « avalé en silence »
# ---------------------------------------------------------------------------


class TestReferencesQuiExistentVraiment:
    """Une référence à quelque chose d'inexistant est ignorée SANS avertissement."""

    def test_aucun_script_inline_dans_la_section(self, html: str) -> None:
        """CSP `script-src 'self'` : un `onclick=` est BLOQUÉ en silence.

        L'écran s'afficherait normalement — barre de recherche, cartes,
        opérateurs — et resterait totalement inerte au clic.
        """
        markup = _markup(html)
        offenders = []
        for match in re.finditer(r'\bon[a-z]+\s*=\s*["\']', markup, re.IGNORECASE):
            fragment = markup[max(0, match.start() - 60) : match.end() + 20]
            # `hx-on::` est évalué par htmx, pas par le navigateur : hors CSP.
            if "hx-on" in fragment:
                continue
            offenders.append(match.group(0))

        assert not offenders, (
            f"gestionnaires inline détectés — la CSP les bloque en silence : {offenders}"
        )

    def test_aucune_balise_script_inline(self, html: str) -> None:
        markup = _markup(html)
        for tag in re.findall(r"<script[^>]*>", markup):
            assert "src=" in tag, (
                f"bloc <script> inline détecté : {tag!r} — bloqué par la CSP, "
                "le compositeur serait entièrement inerte"
            )

    def test_le_script_du_compositeur_existe_et_est_charge(self, html: str) -> None:
        """Vérifié sur la BALISE, pas sur une occurrence du nom de fichier.

        PIÈGE VÉCU : les commentaires du projet mentionnent les noms de scripts,
        et un premier contrôle avait pris ces mentions pour un chargement
        effectif — le script n'était en réalité chargé nulle part.
        """
        assert COMPOSER_JS.exists(), "app/static/filter-composer.js absent"
        assert re.search(r'<script[^>]+src="/static/filter-composer\.js', _markup(html)), (
            "filter-composer.js n'est pas chargé par une vraie balise <script>"
        )

    def test_le_script_est_charge_avec_l_empreinte_de_version(self, html: str) -> None:
        """Sans `?v=`, le navigateur reconduit sa copie en cache après déploiement."""
        tag = _tag_containing(_markup(html), "/static/filter-composer.js")
        assert "?v=" in tag, f"empreinte de version absente : {tag!r}"
        assert "defer" in tag, f"`defer` absent : {tag!r}"

    def test_toute_classe_du_compositeur_existe_dans_le_css(self, html: str) -> None:
        """Une classe sans règle se rend avec le style par défaut du navigateur.

        DÉFAUT VÉCU TROIS FOIS ici (`.view-card__akvorado-link`, `.secondary`,
        `.field-composer__zone--available`). Le test énumère la SOURCE — les
        classes réellement écrites — au lieu de se fier à une liste connue : un
        garde-fou qui n'inspecte que ce qu'il connaît déjà ne garde rien.
        """
        css = _read(STYLE_CSS)
        markup = _markup(html)

        # Périmètre : le bloc du compositeur et le formulaire d'ajout.
        debut = markup.find("data-filter-composer")
        assert debut != -1
        fin = markup.find("</form>", markup.find('name="action" value="add"'))
        bloc = markup[markup.rfind("<", 0, debut) : fin]

        utilisees: set[str] = set()
        for attr in re.findall(r'class="([^"]*)"', bloc):
            for cls in attr.split():
                if cls and "{" not in cls and "}" not in cls:
                    utilisees.add(cls)

        orphelines = sorted(c for c in utilisees if not re.search(rf"\.{re.escape(c)}\b", css))
        assert not orphelines, (
            "Classes posées dans le compositeur mais ABSENTES de style.css — "
            "ces éléments se rendent avec le style par défaut du navigateur :\n  "
            + "\n  ".join(orphelines)
        )

    def test_les_classes_rendues_par_le_serveur_sont_stylees(self) -> None:
        """Les classes `composer-*` viennent du ROUTEUR, pas du template.

        Elles échappent donc à toute inspection du template : c'est exactement
        le genre de balisage qu'on oublie de styler. Elles composent pourtant
        l'essentiel de l'écran (cartes de champs, puces de valeurs, verdicts).
        """
        css = _read(STYLE_CSS)
        rendues_par_le_serveur = [
            "composer-fields",
            "composer-field",
            "composer-field__head",
            "composer-field__label",
            "composer-field__name",
            "composer-field__values",
            "composer-field__more",
            "composer-value",
            "composer-value--empty",
            "composer-degraded__detail",
            "composer-verdict",
            "composer-fields__note",
        ]
        manquantes = [
            c for c in rendues_par_le_serveur if not re.search(rf"\.{re.escape(c)}\b", css)
        ]
        assert not manquantes, (
            f"Classes rendues par app/routers/filter_composer.py mais jamais stylées : {manquantes}"
        )

    def test_aucune_variable_css_inexistante(self) -> None:
        """`var(--xxx)` inconnue : la déclaration est ignorée SANS avertissement."""
        css = _read(STYLE_CSS)
        root = re.search(r":root\s*\{([^}]*)\}", css)
        assert root, ":root introuvable"
        definies = set(re.findall(r"(--[a-zA-Z0-9-]+)\s*:", root.group(1)))
        utilisees = set(re.findall(r"var\(\s*(--[a-zA-Z0-9-]+)", css))

        orphelines = sorted(utilisees - definies)
        assert not orphelines, f"variables CSS utilisées mais non définies : {orphelines}"

    @pytest.mark.parametrize(
        "attribut",
        ["hx-get", "hx-post", "hx-trigger", "hx-target", "hx-sync", "hx-indicator"],
    )
    def test_les_attributs_htmx_utilises_existent_dans_le_bundle(self, attribut: str) -> None:
        """PIÈGE VÉCU : `hx-target-error` (extension NON embarquée) était ignoré.

        htmx construit `hx-get` / `hx-post` dynamiquement (`"hx-"+verbe` sur
        `["get","post","put","delete","patch"]`) : une recherche littérale de
        `hx-get` dans le bundle minifié ne les trouve donc PAS, alors qu'ils
        fonctionnent. On vérifie chaque famille avec l'instrument adapté plutôt
        que de conclure d'un grep littéral qui ne peut structurellement pas
        voir ces deux-là.
        """
        htmx = _read(HTMX_MIN_JS)
        if attribut in ("hx-get", "hx-post"):
            verbe = attribut.split("-")[1]
            assert f'"{verbe}"' in htmx and '"hx-"+' in htmx.replace(" ", ""), (
                f"{attribut} n'est pas résolu par le bundle htmx servi"
            )
            return
        assert attribut in htmx, (
            f"{attribut} est absent de app/static/htmx.min.js : l'attribut serait "
            "ignoré en SILENCE, le câblage n'aurait aucun effet"
        )

    def test_aucun_attribut_htmx_d_extension_non_embarquee(self, html: str) -> None:
        """Filet large : tout `hx-*` posé doit exister dans le bundle."""
        htmx = _read(HTMX_MIN_JS)
        markup = _markup(html)
        dynamiques = {"hx-get", "hx-post", "hx-put", "hx-delete", "hx-patch"}

        inconnus = set()
        for attr in set(re.findall(r"\b(hx-[a-z-]+)=", markup)):
            if attr in dynamiques or attr.startswith("hx-on"):
                continue
            if attr not in htmx:
                inconnus.add(attr)

        assert not inconnus, (
            f"attributs htmx absents du bundle servi (ignorés en silence) : {sorted(inconnus)}"
        )


# ---------------------------------------------------------------------------
# 6. Robustesse — les états dégradés ne doivent jamais se confondre
# ---------------------------------------------------------------------------


class TestRobustesse:
    def test_le_repli_sans_js_est_rendu_par_le_serveur(self, html: str) -> None:
        """Rendu puis MASQUÉ par le script, jamais posé masqué.

        Posé masqué et révélé par le script, l'avertissement resterait invisible
        le seul jour où il sert : celui où le script ne s'exécute pas. Même
        raisonnement que `.autosubmit-fallback` (mesuré 2026-08-06).
        """
        markup = _markup(html)
        assert "filter-composer__no-js" in markup, (
            "aucun repli : si le script échoue, les boutons du compositeur "
            "seraient inertes sans que rien ne l'explique"
        )

        tag = _tag_containing(markup, "filter-composer__no-js")
        assert "hidden" not in tag and "display:none" not in tag.replace(" ", ""), (
            "le repli est posé masqué : il ne s'afficherait jamais"
        )

    def test_le_repli_est_masque_par_le_css_quand_le_script_tourne(self) -> None:
        css = _read(STYLE_CSS)
        assert re.search(
            r"\[data-filter-composer-ready\][^{]*\.filter-composer__no-js\s*\{[^}]*display:\s*none",
            css,
        ), (
            "le repli n'est pas masqué quand le script a tourné : "
            "l'avertissement s'afficherait en permanence, à tort"
        )

    def test_le_script_pose_bien_la_marque_attendue_par_le_css(self) -> None:
        """Le CSS et le JS doivent s'accorder sur le NOM de la marque.

        Une marque posée sous un autre nom que celui attendu par le CSS ne
        masquerait rien — et c'est encore une référence avalée en silence.
        """
        js = _read(COMPOSER_JS)
        assert "data-filter-composer-ready" in js, (
            "le script ne pose pas `data-filter-composer-ready` : le repli "
            "resterait affiché même quand la composition fonctionne"
        )

    def test_le_conteneur_de_champs_ne_ment_pas_avant_chargement(self, html: str) -> None:
        """« Pas encore chargé » ne doit PAS se lire comme « aucun champ ».

        Ces deux états produiraient sinon le même écran, et l'opérateur
        conclurait à tort que son infrastructure n'émet rien.
        """
        markup = _markup(html)
        cible = re.search(
            r'hx-target="#([^"]+)"', _tag_containing(markup, "/config/filters/fields")
        )
        assert cible
        conteneur = cible.group(1)

        idx = markup.find(f'id="{conteneur}"')
        assert idx != -1, f"le conteneur #{conteneur} n'existe pas dans la page"
        bloc = markup[idx : idx + 400].lower()
        assert "chargement" in bloc, (
            "le conteneur des champs n'annonce pas son chargement : une zone "
            "vide serait indistinguable d'un échantillon sans aucun flux"
        )

    def test_la_recherche_se_charge_des_l_ouverture(self, html: str) -> None:
        """Sans déclencheur `load`, l'écran s'ouvrirait sur une zone vide.

        Il faudrait alors deviner qu'il faut taper quelque chose pour voir
        apparaître les champs — le compositeur ne proposerait rien de lui-même.
        """
        tag = _tag_containing(_markup(html), 'hx-get="/config/filters/fields"')
        trigger = re.search(r'hx-trigger="([^"]*)"', tag)
        assert trigger and "load" in trigger.group(1), (
            "aucun déclencheur `load` : les champs n'apparaissent qu'après une "
            f"première frappe : {trigger.group(1) if trigger else None!r}"
        )

    def test_l_expression_vide_est_annoncee_comme_legitime(self, html: str) -> None:
        """Une expression vide filtre tout le trafic — c'est un état, pas une erreur."""
        markup = _markup(html).lower()
        assert "vide" in markup, (
            "rien n'indique qu'une expression vide est un état légitime "
            "(aucun filtrage), ce qui la ferait prendre pour une erreur"
        )

    def test_le_js_protege_contre_la_double_insertion(self) -> None:
        """Un double-clic produit DEUX `click` : sans garde, `SrcAddr SrcAddr`."""
        js = _read(COMPOSER_JS)
        assert "estDoublon" in js, (
            "aucune protection contre le double-clic : l'expression recevrait "
            "deux fois le même fragment"
        )

    def test_le_js_insere_a_la_position_du_curseur(self) -> None:
        """Insérer en fin de champ écraserait l'ordre voulu par l'utilisateur."""
        js = _read(COMPOSER_JS)
        assert "selectionStart" in js and "setSelectionRange" in js, (
            "l'insertion ne respecte pas la position du curseur : cliquer une "
            "parenthèse ouvrante la collerait en fin d'expression"
        )

    def test_le_js_ne_devine_jamais_les_guillemets(self) -> None:
        """La console dit si la valeur se cite — jamais une règle maison.

        `ExporterName = 'proxy-frontal'` en a besoin, `SrcPort = 443` non. Une règle
        devinée ici divergerait de la version d'Akvorado déployée.
        """
        js = _read(COMPOSER_JS)
        assert "data-composer-quoted" in js, (
            "le script ne lit pas `data-composer-quoted` : il devine la règle "
            "de citation au lieu de la tenir de la console"
        )

    def test_le_js_notifie_htmx_apres_une_insertion(self) -> None:
        """Écrire `field.value` ne déclenche AUCUN événement `input`.

        Sans émission manuelle, la validation ne partirait jamais sur les
        fragments insérés au clic : le verdict resterait figé sur l'état
        précédent et MENTIRAIT sur l'expression affichée.
        """
        js = _read(COMPOSER_JS)
        assert "dispatchEvent" in js and 'Event("input"' in js, (
            "aucun événement `input` émis après insertion : le verdict affiché "
            "ne correspondrait plus à l'expression"
        )
