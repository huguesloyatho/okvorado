"""Garde-fous de l'aide par l'exemple (classifieurs) et de l'agencement des
formulaires de ports d'écoute.

DEUX DÉFAUTS VÉCUS motivent ce fichier.

1. `interface_classifiers` compte 0 expression en production. Un collègue qui
   arrive sur cet écran voit un tableau vide et une zone de texte vide : aucun
   point de départ, aucune indication de ce que le mini-langage accepte ou
   refuse. L'aide doit donc montrer les DEUX versants — ce qui marche ET ce qui
   ne marche pas avec la raison — et être OUVERTE d'emblée sur cette section.

2. (2026-08-06, capture à l'appui) Sur « Ports d'écoute des flux », le label
   « Port » se retrouvait seul en fin de ligne, son champ `2055` reporté à la
   ligne suivante, chaque label paraissant annoncer le champ SUIVANT. Cause :
   dans la grille `.config-form` en `auto-fit`, chaque label et chaque champ
   étaient des cases INDÉPENDANTES ; le retour à la ligne tombait au milieu
   d'une paire. Le correctif emballe chaque paire dans un `.field`.

Les fonctions citées dans l'aide ne sont pas devinées : elles sont vérifiées
contre la liste en dur ci-dessous, elle-même relevée à la source (cf. commentaire
de `EXPORTER_FUNCTIONS` / `INTERFACE_FUNCTIONS`). Un test qui accepterait
n'importe quel nom `Classify…` laisserait passer une fonction inventée — le
motif exact du défaut « classe CSS posée sans règle », avalé en silence.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATE = Path(__file__).resolve().parent.parent / "app" / "templates" / "config_sections.html"
STYLE_CSS = Path(__file__).resolve().parent.parent / "app" / "static" / "style.css"

# ---------------------------------------------------------------------------
# Vocabulaire RÉELLEMENT documenté par Akvorado.
#
# SOURCE (vérifiée le 2026-08-06) :
#   - doc  : dépôt akvorado/akvorado, `console/data/docs/50-configuration.md`,
#            section « Classification ». Le chemin `docs/02-configuration.md`
#            fréquemment cité est un lien mort (404) : `docs` est un symlink.
#   - code : `outlet/core/classifier.go` — liste exhaustive des fonctions
#            enregistrées et des champs des structures `exporterInfo` /
#            `interfaceInfo` ; `outlet/core/enricher.go` pour l'ordre.
#
# Les deux tables sont compilées dans des environnements DISJOINTS : une
# fonction d'exportateur employée dans une règle d'interface (ou l'inverse)
# empêche Akvorado de démarrer. D'où deux jeux séparés, jamais fusionnés.
# ---------------------------------------------------------------------------

EXPORTER_FUNCTIONS = {
    "Classify",  # alias non documenté de ClassifyGroup, présent dans le code
    "ClassifyGroup",
    "ClassifyRole",
    "ClassifySite",
    "ClassifyRegion",
    "ClassifyTenant",
}
INTERFACE_FUNCTIONS = {
    "ClassifyConnectivity",
    "ClassifyProvider",
    "ClassifyExternal",
    "ClassifyInternal",
    "SetName",
    "SetDescription",
}
# Présentes dans les DEUX tables.
COMMON_FUNCTIONS = {"Reject", "Format"}

# `ClassifyExternal` et `ClassifyInternal` sont les seules à ne PAS avoir de
# variante `Regex` (elles ne prennent aucun argument) — doc, verbatim.
NO_REGEX_VARIANT = {"ClassifyExternal", "ClassifyInternal"}


def _with_regex_variants(names: set[str]) -> set[str]:
    out = set(names)
    for name in names:
        if name.startswith("Classify") and name not in NO_REGEX_VARIANT:
            out.add(f"{name}Regex")
    return out


EXPORTER_VOCABULARY = _with_regex_variants(EXPORTER_FUNCTIONS) | COMMON_FUNCTIONS
INTERFACE_VOCABULARY = _with_regex_variants(INTERFACE_FUNCTIONS) | COMMON_FUNCTIONS

# Champs de contexte réellement exposés (structures Go, exhaustives).
EXPORTER_VARIABLES = {"Exporter.IP", "Exporter.Name"}
INTERFACE_VARIABLES = {
    "Interface.Index",
    "Interface.Name",
    "Interface.Description",
    "Interface.Speed",
    "Interface.VLAN",
} | EXPORTER_VARIABLES  # les règles d'interface voient aussi l'exportateur


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _help_block(section_key: str) -> str:
    """Extrait le corps de l'aide propre à une table de classification.

    La macro `classifier_help` porte les deux jeux dans un `{% if %}` /
    `{% else %}` : on isole la branche pour vérifier qu'aucune fonction ne
    traverse d'une table à l'autre.
    """
    html = _read(TEMPLATE)
    start = html.index("{% macro classifier_help(")
    end = html.index("{% endmacro %}", start)
    macro = html[start:end]

    split = macro.index("{% else %}")
    branch_if = macro[macro.index("{% if section_key ==") : split]
    branch_else = macro[split:]
    return branch_if if section_key == "exporter_classifiers" else branch_else


# ---------------------------------------------------------------------------
# 1. Les deux sections portent une aide, avec exemple ET contre-exemple.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("section_key", ["exporter_classifiers", "interface_classifiers"])
def test_section_has_help_block(section_key: str) -> None:
    """La macro d'aide est réellement appelée pour les deux sections."""
    html = _read(TEMPLATE)
    assert "{% macro classifier_help(" in html, "macro classifier_help absente"
    assert "{{ classifier_help(detail.key) }}" in html, (
        "la macro d'aide n'est jamais appelée : le bloc n'apparaîtrait sur aucun écran"
    )
    # L'appel est bien dans la branche qui sert les deux tables de classification.
    branch = html.index("{% if detail.key in ('exporter_classifiers', 'interface_classifiers') %}")
    call = html.index("{{ classifier_help(detail.key) }}")
    assert call > branch, "l'aide doit être rendue dans la branche des classifieurs"


@pytest.mark.parametrize("section_key", ["exporter_classifiers", "interface_classifiers"])
def test_help_has_positive_and_negative_examples(section_key: str) -> None:
    """« Ce qui est faisable OU PAS » : les deux versants sont exigés.

    Un bloc qui ne montrerait que les exemples valides ne répondrait qu'à la
    moitié de la demande — et laisserait intacts les pièges (fonction de l'autre
    table, variante Regex inexistante) qui empêchent Akvorado de démarrer.
    """
    branch = _help_block(section_key)

    assert "lang-help__col--ok" in branch, f"{section_key}: aucun bloc d'exemples valides"
    assert "lang-help__col--ko" in branch, f"{section_key}: aucun contre-exemple"

    ok_part = branch[branch.index("lang-help__col--ok") : branch.index("lang-help__col--ko")]
    ko_part = branch[branch.index("lang-help__col--ko") :]

    ok_examples = re.findall(r'lang-help__code">(.*?)</code>', ok_part, re.DOTALL)
    ko_examples = re.findall(r'lang-help__code">(.*?)</code>', ko_part, re.DOTALL)

    assert len(ok_examples) >= 3, (
        f"{section_key}: {len(ok_examples)} exemple(s) valide(s), 3 attendus au minimum"
    )
    assert len(ko_examples) >= 2, (
        f"{section_key}: {len(ko_examples)} contre-exemple(s), 2 attendus au minimum "
        "(« ce qui est faisable OU PAS » est une demande en deux volets)"
    )


@pytest.mark.parametrize("section_key", ["exporter_classifiers", "interface_classifiers"])
def test_every_counter_example_states_a_reason(section_key: str) -> None:
    """Un contre-exemple sans la RAISON n'apprend rien : il interdit sans expliquer."""
    branch = _help_block(section_key)
    ko_part = branch[branch.index("lang-help__col--ko") :]
    ko_items = re.findall(r"<li>(.*?)</li>", ko_part, re.DOTALL)

    assert ko_items, f"{section_key}: aucun contre-exemple détecté"
    for item in ko_items:
        assert "lang-help__note" in item, (
            f"{section_key}: contre-exemple sans explication -> {item[:80]!r}"
        )
        note = item[item.index("lang-help__note") :]
        text = re.sub(r"<[^>]+>", " ", note)
        assert len(text.split()) >= 8, (
            f"{section_key}: explication trop courte pour être une raison -> {text[:80]!r}"
        )


# ---------------------------------------------------------------------------
# 2. Aucune fonction inventée, aucune fonction empruntée à l'autre table.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("section_key", "vocabulary"),
    [
        ("exporter_classifiers", EXPORTER_VOCABULARY),
        ("interface_classifiers", INTERFACE_VOCABULARY),
    ],
)
def test_only_documented_functions_are_cited(section_key: str, vocabulary: set[str]) -> None:
    """Toute fonction citée dans les EXEMPLES existe réellement.

    Les contre-exemples sont volontairement exclus de ce contrôle : leur rôle
    est précisément de montrer des appels invalides (fonction de l'autre table,
    variante Regex inexistante). Les y soumettre rendrait le test contradictoire.
    """
    branch = _help_block(section_key)
    ok_part = branch[branch.index("lang-help__col--ok") : branch.index("lang-help__col--ko")]

    called = set(re.findall(r"\b((?:Classify|Set)[A-Za-z]*)\s*\(", ok_part))
    assert called, f"{section_key}: aucun appel de fonction dans les exemples valides"

    unknown = sorted(called - vocabulary)
    assert not unknown, (
        f"{section_key}: fonctions citées en exemple mais INEXISTANTES dans "
        f"Akvorado : {unknown}\nVocabulaire vérifié à la source (classifier.go) : "
        f"{sorted(vocabulary)}"
    )


@pytest.mark.parametrize(
    ("section_key", "foreign"),
    [
        # Une fonction d'interface citée en exemple VALIDE côté exportateur (ou
        # l'inverse) ferait échouer le DÉMARRAGE d'Akvorado : les deux jeux sont
        # compilés dans des environnements disjoints.
        ("exporter_classifiers", INTERFACE_FUNCTIONS),
        ("interface_classifiers", EXPORTER_FUNCTIONS - {"Classify"}),
    ],
)
def test_no_function_borrowed_from_the_other_table(section_key: str, foreign: set[str]) -> None:
    branch = _help_block(section_key)
    ok_part = branch[branch.index("lang-help__col--ok") : branch.index("lang-help__col--ko")]
    called = set(re.findall(r"\b((?:Classify|Set)[A-Za-z]*)\s*\(", ok_part))

    borrowed = sorted(called & foreign)
    assert not borrowed, (
        f"{section_key}: exemple VALIDE citant une fonction de l'autre table "
        f"{borrowed} — Akvorado refuserait de démarrer"
    )


@pytest.mark.parametrize(
    ("section_key", "allowed"),
    [
        ("exporter_classifiers", EXPORTER_VARIABLES),
        ("interface_classifiers", INTERFACE_VARIABLES),
    ],
)
def test_context_variables_are_listed_and_real(section_key: str, allowed: set[str]) -> None:
    """Les variables du contexte sont annoncées, et aucune n'est inventée.

    `Exporter.Description` est le piège type : il n'existe NI dans la doc NI
    dans le code, alors qu'on l'attendrait par symétrie avec
    `Interface.Description`.
    """
    branch = _help_block(section_key)

    for variable in sorted(allowed):
        assert variable in branch, (
            f"{section_key}: la variable {variable} du contexte n'est pas annoncée"
        )

    cited = set(re.findall(r"\b(?:Exporter|Interface)\.[A-Za-z]+", branch))
    ok_part = branch[branch.index("lang-help__col--ok") : branch.index("lang-help__col--ko")]
    cited_in_examples = set(re.findall(r"\b(?:Exporter|Interface)\.[A-Za-z]+", ok_part))

    unknown = sorted(cited_in_examples - allowed)
    assert not unknown, (
        f"{section_key}: variables citées en exemple valide mais inexistantes : {unknown}"
    )
    assert cited, f"{section_key}: aucune variable de contexte citée"


def test_exporter_description_is_never_presented_as_valid() -> None:
    """`Exporter.Description` n'existe pas : jamais dans un exemple valide."""
    branch = _help_block("exporter_classifiers")
    ok_part = branch[branch.index("lang-help__col--ok") : branch.index("lang-help__col--ko")]
    assert "Exporter.Description" not in ok_part, (
        "Exporter.Description est cité comme utilisable alors que le champ "
        "n'existe ni dans la doc ni dans classifier.go"
    )


def test_undocumented_facts_are_flagged_as_such() -> None:
    """Ce qu'Akvorado ne documente pas est signalé, jamais présenté comme acquis.

    Le comportement de retour des fonctions `Classify…` (toujours `true` hors
    variantes `Regex`) n'est établi qu'en lisant le code source. L'aide doit le
    dire plutôt que de le faire passer pour une garantie documentée.
    """
    branch = _help_block("exporter_classifiers")
    assert "non documentée" in branch or "non documenté" in branch, (
        "aucune mention explicite de ce qui n'est PAS documenté par Akvorado — "
        "l'aide présenterait alors une lecture du code comme une garantie"
    )


# ---------------------------------------------------------------------------
# 3. Section vide -> aide ouverte d'emblée.
# ---------------------------------------------------------------------------


def test_interface_classifiers_help_is_open_by_default() -> None:
    """`interface_classifiers` compte 0 expression : l'aide y est déployée.

    Sur une section vide, un bloc replié demande à l'utilisateur de deviner
    qu'une aide existe avant même de savoir quoi taper.
    """
    html = _read(TEMPLATE)
    start = html.index("{% macro classifier_help(")
    end = html.index("{% endmacro %}", start)
    macro = html[start:end]

    details = re.search(r"<details[^>]*>", macro)
    assert details, "aucun <details> dans la macro d'aide"
    tag = details.group(0)

    assert "interface_classifiers" in tag and "open" in tag, (
        "l'attribut `open` doit être conditionné à interface_classifiers "
        f"(section vide en prod) -> {tag!r}"
    )
    # Et pas ouvert inconditionnellement : sur exporter_classifiers, 3 expressions
    # existent déjà et l'aide déployée repousserait l'éditeur hors de l'écran.
    assert not re.search(r"<details[^>]*\sopen(\s|>)", tag), (
        "l'aide est ouverte inconditionnellement : elle doit l'être uniquement sur la section vide"
    )


def test_help_uses_details_not_inline_script() -> None:
    """Le repli est natif (`<details>`), sans JS.

    La CSP du service est `script-src 'self'` : un `<script>` inline serait
    bloqué SANS erreur visible — page affichée, bloc inerte.
    """
    html = _read(TEMPLATE)
    start = html.index("{% macro classifier_help(")
    end = html.index("{% endmacro %}", start)
    macro = html[start:end]

    assert "<details" in macro and "<summary" in macro
    assert "<script" not in macro, "script inline dans l'aide : bloqué par la CSP"
    assert "onclick" not in macro, "gestionnaire inline : bloqué par la CSP"


# ---------------------------------------------------------------------------
# 4. Ports d'écoute : chaque label est collé à SON champ.
# ---------------------------------------------------------------------------


def _flow_inputs_form() -> str:
    html = _read(TEMPLATE)
    start = html.index("{% elif detail.key == 'flow_inputs' %}")
    # PIÈGE : découper sur le premier `{% else %}` rencontré tombe sur celui du
    # `{% if value %}` INTERNE (la ligne « Aucun port d'écoute déclaré »), donc
    # bien AVANT le formulaire d'ajout. Le repère fiable est l'indentation du
    # `{% else %}` de la chaîne `{% elif %}` de premier niveau, qui ferme la
    # branche entière.
    end_match = re.search(r"\n {4}\{% else %\}", html[start:])
    assert end_match, "fin de la branche flow_inputs introuvable"
    section = html[start : start + end_match.start()]
    # Le formulaire d'AJOUT est le dernier `<form class="config-form">` de la
    # branche : les formulaires précédents sont ceux, unitaires, de suppression
    # dans le tableau (ils ne portent pas cette classe). La recherche est faite
    # par expression régulière et non sur une chaîne littérale : un test qui
    # dépend de l'indentation exacte casse au premier reformatage du template
    # sans que rien ne soit réellement régressé.
    match = re.search(r'<form\s[^>]*class="config-form"', section)
    assert match, "formulaire d'ajout des ports d'écoute introuvable"
    return section[match.start() : section.index("</form>", match.start())]


def test_flow_inputs_labels_all_reference_an_existing_field() -> None:
    """Aucun label orphelin : chaque `for` pointe un `id` présent dans le formulaire."""
    form = _flow_inputs_form()

    labels = re.findall(r'<label\s+for="([^"]+)"', form)
    ids = set(re.findall(r'\sid="([^"]+)"', form))

    assert labels, "aucun label dans le formulaire des ports d'écoute"
    orphelins = sorted(set(labels) - ids)
    assert not orphelins, (
        f"labels dont le champ n'existe pas : {orphelins} — un label orphelin "
        "est exactement le symptôme signalé sur la capture (« Port » séparé de son champ)"
    )

    # Réciproque : tout champ saisissable est nommé.
    saisissables = set(
        re.findall(r'<(?:input|select)[^>]*\stype="(?!hidden)[^"]*"[^>]*\sid="([^"]+)"', form)
    ) | set(re.findall(r"<select[^>]*\sid=\"([^\"]+)\"", form))
    non_nommes = sorted(saisissables - set(labels))
    assert not non_nommes, f"champs sans label : {non_nommes}"


def test_flow_inputs_each_label_is_wrapped_with_its_own_field() -> None:
    """Le correctif est STRUCTUREL : label et champ dans un même `.field`.

    C'était la cause du défaut — label et champ étaient des cases de grille
    indépendantes, coupables d'être séparées par un retour à la ligne. Un
    correctif purement cosmétique (marges, ordre) laisserait le défaut revenir
    à la première largeur de fenêtre défavorable.
    """
    form = _flow_inputs_form()

    # Chaque bloc `.field` (hors conteneurs) porte exactement 1 label et 1 champ.
    blocs = re.findall(r'<div class="field(?:[^"]*)">(.*?)</div>', form, re.DOTALL)
    assert len(blocs) >= 4, (
        f"{len(blocs)} paires emballées, 4 attendues (type, décodeur, adresse, port)"
    )
    for bloc in blocs:
        n_labels = len(re.findall(r"<label\b", bloc))
        n_champs = len(re.findall(r"<(?:input|select)\b", bloc))
        assert n_labels == 1, f"bloc .field avec {n_labels} label(s) : {bloc[:70]!r}"
        assert n_champs == 1, f"bloc .field avec {n_champs} champ(s) : {bloc[:70]!r}"

    # Plus aucun label enfant DIRECT de la grille : c'est ce qui autorisait la
    # coupure au milieu d'une paire.
    sans_wrapper = re.findall(r'^\s{8}<label\s+for="', form, re.MULTILINE)
    assert not sans_wrapper, (
        "un label est encore enfant direct de .config-form : la grille peut le "
        "séparer de son champ au prochain retour à la ligne"
    )


def test_flow_inputs_host_and_port_are_grouped_as_one_value() -> None:
    """`host` et `port` forment UNE valeur YAML (`listen: 0.0.0.0:2055`).

    Les présenter comme deux réglages indépendants contredit le tableau du
    dessus, qui les affiche déjà fusionnés dans la colonne « Écoute ».
    """
    form = _flow_inputs_form()
    assert "field--group" in form, "adresse et port ne sont pas présentés comme un ensemble"

    groupe = form[form.index("field--group") :]
    groupe = groupe[: groupe.index("</fieldset>")]
    assert 'id="inputs-host"' in groupe and 'id="inputs-port"' in groupe, (
        "le groupe « adresse d'écoute » doit contenir les DEUX champs"
    )
    assert "<legend>" in groupe, "un fieldset sans legend n'annonce pas ce qu'il regroupe"


def test_flow_inputs_form_has_no_inline_handler() -> None:
    """Aucun `onclick=` : la CSP `script-src 'self'` les bloque en silence."""
    form = _flow_inputs_form()
    assert not re.search(r"\son[a-z]+\s*=", form.replace("hx-on::", "")), (
        "gestionnaire d'événement inline dans le formulaire des ports d'écoute"
    )


# ---------------------------------------------------------------------------
# 5. Toute classe CSS introduite existe réellement.
# ---------------------------------------------------------------------------


def test_all_classes_introduced_exist_in_css() -> None:
    """DÉFAUT VÉCU DEUX FOIS : une classe posée sans règle CSS s'affiche nue.

    `.view-card__akvorado-link` puis `.secondary` avaient été posées sans être
    définies — rendu en style par défaut du navigateur, sans le moindre
    avertissement. Ce test énumère les classes RÉELLEMENT écrites dans les blocs
    de ce lot plutôt que de se fier à une liste connue d'avance.
    """
    css = _read(STYLE_CSS)
    html = _read(TEMPLATE)

    start = html.index("{% macro classifier_help(")
    end = html.index("{% endmacro %}", start)
    portee = html[start:end] + _flow_inputs_form()

    classes: set[str] = set()
    for attr in re.findall(r'class="([^"]*)"', portee):
        for cls in attr.split():
            if cls and "{" not in cls and "}" not in cls:
                classes.add(cls)

    assert classes, "aucune classe détectée dans le périmètre du lot"

    orphelines = sorted(cls for cls in classes if not re.search(rf"\.{re.escape(cls)}\b", css))
    assert not orphelines, (
        "Classes posées dans le template mais ABSENTES de style.css — elles "
        "s'afficheraient avec le style par défaut du navigateur :\n  "
        + "\n  ".join(f".{c}" for c in orphelines)
    )


def test_new_css_uses_only_defined_variables() -> None:
    """Une `var(--xxx)` inexistante est ignorée SANS avertissement par le navigateur."""
    css = _read(STYLE_CSS)
    root = re.search(r":root\s*\{([^}]*)\}", css)
    assert root, ":root introuvable"
    definies = set(re.findall(r"(--[a-zA-Z0-9-]+)\s*:", root.group(1)))

    for bloc in ("lang-help", "field--group", "field__pair"):
        regles = re.findall(rf"\.{re.escape(bloc)}[^{{]*\{{([^}}]*)\}}", css)
        assert regles, f".{bloc} n'a aucune règle dans style.css"
        for regle in regles:
            for variable in re.findall(r"var\(\s*(--[a-zA-Z0-9-]+)", regle):
                assert variable in definies, (
                    f".{bloc} utilise {variable}, absente de :root — déclaration "
                    "ignorée en silence par le navigateur"
                )


def test_new_css_has_no_hardcoded_hex_color() -> None:
    """Toute couleur dérive d'une variable de la charte, jamais d'un hex en dur."""
    css = _read(STYLE_CSS)
    root = re.search(r":root\s*\{.*?\}", css, re.DOTALL)
    assert root
    hors_root = css[: root.start()] + css[root.end() :]

    for bloc in ("lang-help", "field"):
        for regle in re.findall(rf"\.{re.escape(bloc)}[^{{]*\{{([^}}]*)\}}", hors_root):
            assert not re.search(r"#[0-9a-fA-F]{3,8}\b", regle), (
                f".{bloc} contient une couleur hexadécimale en dur : {regle.strip()!r}"
            )


def test_summary_has_focus_visible_rule() -> None:
    """Le repliement est actionnable au clavier : l'état de focus doit être visible."""
    css = _read(STYLE_CSS)
    assert re.search(r"\.lang-help__summary:focus-visible", css), (
        ".lang-help__summary:focus-visible manquant — la navigation clavier "
        "n'indiquerait pas où se trouve le focus"
    )
    assert re.search(r"\.lang-help__summary:hover", css), (
        ".lang-help__summary:hover manquant — rien n'indiquerait que le bloc se déplie"
    )
