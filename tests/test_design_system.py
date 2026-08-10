"""Garde-fou : tout lien-action est stylé, jamais nu.

DÉFAUT VÉCU (2026-08-06) — capture à l'appui — le lien « ← Toutes les
sections » s'affichait en bleu souligné par défaut du navigateur, au milieu
d'une interface par ailleurs soignée. Cause : `<a href="...">` sans classe CSS,
alors que `.btn` existe dans style.css sans être jamais utilisé.

Ce fichier fait deux choses :
1. Interdit tout `<a href="/...">` sans attribut `class` dans les templates du
   périmètre (hors base.html, dont la nav fait déjà l'objet d'un garde-fou
   dédié dans test_navigation.py).
2. Vérifie que le CSS des liens-actions respecte la charte : pas de souligné
   par défaut, hover + focus-visible partout, aucune couleur en dur hors
   `:root` (tout dérive des variables de la salle de contrôle réseau).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "app" / "templates"
STYLE_CSS = Path(__file__).resolve().parent.parent / "app" / "static" / "style.css"

# base.html est hors périmètre : sa nav fait déjà l'objet d'un garde-fou dédié
# (test_navigation.py) et il est explicitement exclu de ce chantier.
TEMPLATES_IN_SCOPE = [
    "config.html",
    "config_sections.html",
    "views.html",
    "exporters.html",
    "retention.html",
    "ingestion.html",
]

# Classes du système de liens-actions attendues par le brief.
LINK_ACTION_CLASSES = {"link-back", "link-action", "link-external", "section-card"}

ANCHOR_TAG_RE = re.compile(r"<a\b[^>]*>", re.IGNORECASE)
HREF_RE = re.compile(r'href\s*=\s*"([^"]*)"')
CLASS_RE = re.compile(r'class\s*=\s*"([^"]*)"')
HEX_COLOR_RE = re.compile(r"#[0-9a-fA-F]{3,8}\b")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _anchors_with_local_href(html: str) -> list[str]:
    """Retourne les tags <a ...> dont le href pointe vers une route locale (/...).

    Les templates de ce périmètre passent désormais leurs chemins locaux par
    le filtre Jinja `prefixed` (app servie derrière le proxy Grafana) : la
    forme source est `href="{{ '/exporters/' | prefixed }}..."`, plus la
    forme brute `href="/exporters"`. Les deux comptent comme un lien local.
    """
    tags = []
    for tag in ANCHOR_TAG_RE.findall(html):
        m = HREF_RE.search(tag)
        if not m:
            continue
        valeur = m.group(1)
        if valeur.startswith("/") or valeur.startswith("{{ '/") or valeur.startswith('{{ "/'):
            tags.append(tag)
    return tags


@pytest.mark.parametrize("template_name", TEMPLATES_IN_SCOPE)
def test_no_anchor_without_class(template_name: str) -> None:
    """Garde-fou principal : tout <a href="/..."> a une classe CSS.

    C'est ce test qui empêche le défaut de revenir : un lien ajouté sans
    classe dans un futur template de ce périmètre le fait échouer.
    """
    html = _read(TEMPLATES_DIR / template_name)
    for tag in _anchors_with_local_href(html):
        assert CLASS_RE.search(tag), (
            f"{template_name}: lien sans classe CSS trouvé -> {tag!r} "
            '(tout <a href="/..."> doit porter une classe de lien-action)'
        )


def test_link_action_classes_used_exist_in_css() -> None:
    """TOUTE classe portée par un lien local doit exister dans le CSS.

    DÉFAUT VÉCU (2026-08-06), et deux fois plutôt qu'une :
    1. `.view-card__akvorado-link` était posée sur 4 liens sans exister en CSS.
    2. Le bouton « Exporter en CSV », ajouté par le lot qui corrigeait le
       point 1, portait `class="secondary"` — également inexistante. Rendu :
       bleu souligné, le défaut d'origine réintroduit.

    Le point 2 est passé parce que ce test filtrait d'abord les classes vues
    par une liste connue (`LINK_ACTION_CLASSES` + préfixe `view-card__`) puis
    ne vérifiait QUE celles-là. `secondary` n'appartenant à aucune des deux,
    elle était écartée AVANT l'assertion : le test restait vert avec le bug en
    place. Un garde-fou qui n'inspecte que ce qu'il connaît déjà ne garde rien.

    La vérification porte donc désormais sur TOUTES les classes rencontrées.
    """
    css = _read(STYLE_CSS)
    used_by_template: dict[str, set[str]] = {}
    for template_name in TEMPLATES_IN_SCOPE:
        html = _read(TEMPLATES_DIR / template_name)
        classes: set[str] = set()
        for tag in _anchors_with_local_href(html):
            m = CLASS_RE.search(tag)
            if m:
                classes.update(m.group(1).split())
        if classes:
            used_by_template[template_name] = classes

    assert used_by_template, "aucune classe de lien détectée dans les templates"

    orphelines: list[str] = []
    for template_name, classes in sorted(used_by_template.items()):
        for cls in sorted(classes):
            # Jinja peut produire une classe conditionnelle vide (`class="{{ ... }}"`).
            if not cls or "{" in cls or "}" in cls:
                continue
            if not re.search(rf"\.{re.escape(cls)}\b", css):
                orphelines.append(f"{template_name}: .{cls}")

    assert not orphelines, (
        "Classes portées par un lien mais ABSENTES de style.css — ces liens "
        "s'affichent avec le style par défaut du navigateur (bleu souligné) :\n  "
        + "\n  ".join(orphelines)
        + f"\nDéfinis-les dans {STYLE_CSS.name}, ou utilise une classe de la charte "
        f"({', '.join(sorted(LINK_ACTION_CLASSES))})."
    )


def test_css_link_action_rules_declare_no_text_decoration_underline() -> None:
    """Le CSS des liens-actions déclare text-decoration: none."""
    css = _read(STYLE_CSS)
    for cls in ("link-back", "link-action", "link-external"):
        block_match = re.search(rf"\.{re.escape(cls)}\s*{{([^}}]*)}}", css)
        assert block_match, f"règle .{cls} introuvable dans {STYLE_CSS.name}"
        block = block_match.group(1)
        assert "text-decoration: none" in block, (
            f".{cls} doit déclarer text-decoration: none (c'est précisément le "
            "défaut du navigateur que ce chantier corrige)"
        )


def test_css_has_no_hardcoded_hex_color_outside_root() -> None:
    """Aucune couleur hexadécimale en dur hors du bloc :root — tout passe par une variable."""
    css = _read(STYLE_CSS)
    root_match = re.search(r":root\s*{.*?}", css, re.DOTALL)
    assert root_match, "bloc :root introuvable"
    css_outside_root = css[: root_match.start()] + css[root_match.end() :]

    offenders = []
    for i, line in enumerate(css_outside_root.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        if HEX_COLOR_RE.search(line):
            offenders.append((i, line.strip()))

    assert not offenders, (
        "couleurs hexadécimales en dur hors :root (doivent dériver d'une "
        f"variable --xxx) : {offenders}"
    )


@pytest.mark.parametrize("cls", ["link-back", "link-action", "link-external", "section-card"])
def test_link_action_class_has_hover_and_focus_visible(cls: str) -> None:
    """Chaque classe de lien-action a une règle :hover ET une règle :focus-visible."""
    css = _read(STYLE_CSS)
    assert re.search(rf"\.{re.escape(cls)}:hover", css), (
        f".{cls}:hover manquant dans {STYLE_CSS.name}"
    )
    assert re.search(rf"\.{re.escape(cls)}:focus-visible", css), (
        f".{cls}:focus-visible manquant dans {STYLE_CSS.name} "
        "(l'accessibilité clavier ne doit pas régresser)"
    )


def test_no_browser_default_blue() -> None:
    """Aucune couleur bleue de navigateur par défaut (#0000EE) dans le CSS."""
    css = _read(STYLE_CSS)
    assert "#0000EE".lower() not in css.lower()
    assert "#00e".lower() not in css.lower()


def test_view_card_akvorado_link_is_styled() -> None:
    """Les 4 liens 'ouvrir dans Akvorado' de views.html ont bien une règle CSS.

    Trouvé au-delà de l'inventaire initial du brief : la classe
    view-card__akvorado-link était déjà posée dans le template mais jamais
    définie dans style.css — même défaut (lien nu) que celui signalé.
    """
    css = _read(STYLE_CSS)
    assert ".view-card__akvorado-link" in css
    assert re.search(r"\.view-card__akvorado-link\s*{[^}]*text-decoration:\s*none", css)


def test_all_css_variables_used_are_defined_in_root() -> None:
    """Une variable CSS inexistante est ignorée en SILENCE.

    PIÈGE VÉCU (2026-08-06) : en stylant le sélecteur de fichier, j'ai écrit
    `var(--accent-bg)` — variable qui n'existe pas. Le navigateur ignore la
    déclaration sans le moindre avertissement : le hover n'aurait tout
    simplement rien fait, et rien n'aurait cassé nulle part.

    C'est le même motif que la classe `.secondary` posée sans règle CSS, et que
    l'attribut `hx-target-error` d'une extension non embarquée : une référence
    à quelque chose qui n'existe pas, avalée en silence. Ce test énumère la
    SOURCE (les `var(...)` réellement écrits) au lieu de se fier à une liste.
    """
    css = _read(STYLE_CSS)

    root_block = re.search(r":root\s*\{([^}]*)\}", css)
    assert root_block, ":root introuvable dans style.css"
    defined = set(re.findall(r"(--[a-zA-Z0-9-]+)\s*:", root_block.group(1)))

    used = set(re.findall(r"var\(\s*(--[a-zA-Z0-9-]+)", css))
    orphelines = sorted(used - defined)

    assert not orphelines, (
        "Ces variables CSS sont utilisées mais jamais définies dans :root — "
        "le navigateur ignore la déclaration SANS avertissement :\n  "
        + "\n  ".join(orphelines)
        + f"\nDéfinis-les dans :root, ou utilise une variable existante "
        f"({', '.join(sorted(defined))})."
    )


def test_tout_type_de_champ_texte_utilise_est_style() -> None:
    """Un `type` absent de la règle globale rend le champ BLANC sur fond sombre.

    DÉFAUT VU PAR CAPTURE (2026-08-06) : la barre de recherche du compositeur
    de filtres est un `input type="search"`. La règle de charte n'énumérait que
    `text` et `number` : le champ échappait à tout le style et s'affichait en
    blanc, seul élément clair de l'écran. Le DOM était pourtant irréprochable —
    seul l'œil pouvait le voir.

    Ce test relie les types RÉELLEMENT employés dans les templates à ceux que
    la feuille de style couvre.
    """
    css = _read(STYLE_CSS)
    couverts = set(re.findall(r'input\[type="([a-z]+)"\]', css))
    # `textarea` n'est pas un `input` : vérifié séparément.
    assert "textarea" in css, "les zones de texte multi-lignes doivent être stylées"

    employes: dict[str, str] = {}
    for template in sorted(TEMPLATES_DIR.glob("*.html")):
        html = _read(template)
        for type_ in re.findall(r'<input[^>]*type="([a-z]+)"', html):
            employes.setdefault(type_, template.name)

    # Ces types n'ont pas d'apparence de champ texte : ils ont leurs propres règles.
    hors_charte_texte = {"checkbox", "radio", "hidden", "file", "submit", "button"}

    orphelins = [
        f"{type_} (dans {source})"
        for type_, source in sorted(employes.items())
        if type_ not in couverts and type_ not in hors_charte_texte
    ]

    assert not orphelins, (
        "Ces types de champ sont employés mais absents de la règle de charte — "
        "le navigateur les rendra avec son style par défaut, donc en clair sur "
        f"une interface sombre :\n  {orphelins}"
    )


def test_les_cases_a_cocher_restent_alignees_avec_leur_libelle() -> None:
    """Une case détachée de son texte invite à cocher sans lire.

    DÉFAUT VU TROIS FOIS SUR CE PROJET, toujours à la capture d'écran, jamais
    dans le DOM :
    1. l'option « Remplacer entièrement le plan d'adressage » (2026-08-06)
    2. le label « Port » orphelin des ports d'écoute (2026-08-06)
    3. les 30 colonnes du schéma (2026-08-07) — `display` effectif à `block`,
       label de 502 px, texte rendu AVANT la case (651 px contre 655)

    Cause commune : `.config-form label { display: block }` — règle générique
    des formulaires — l'emporte sur la règle de la checklist, à spécificité
    comparable et déclarée plus haut. Le dernier déclaré gagne.

    Ce test vérifie que les classes de case à cocher ont bien une règle plus
    spécifique que le sélecteur générique, dans une déclaration DÉCLARÉE APRÈS
    lui — les deux conditions comptent.
    """
    css = _read(STYLE_CSS)

    position_generique = css.find(".config-form label")
    assert position_generique != -1, "règle générique .config-form label introuvable"

    for classe in ("widget-checklist__item", "checkbox-field"):
        motif = re.compile(rf"\.config-form\s+\.{re.escape(classe)}\b")
        correspondance = motif.search(css)
        assert correspondance, (
            f"aucune règle `.config-form .{classe}` : le `display: block` "
            "générique l'emporterait et la case serait détachée de son libellé"
        )
        assert correspondance.start() > position_generique, (
            f"la règle `.config-form .{classe}` est déclarée AVANT le sélecteur "
            "générique : à spécificité comparable, c'est le dernier qui gagne"
        )
