"""Garde-fou : un refus expliqué au serveur DOIT être affiché à l'utilisateur.

DÉFAUT VÉCU (2026-08-06), trouvé au navigateur et par aucun autre moyen.
Un import CSV contenant une ligne fautive était correctement refusé — la route
construisait un message précis (« ligne 3: CIDR invalide: '999.999.999.0/24' »),
le journal serveur le confirmait, et la garantie « tout ou rien » était bien
respectée. Mais la réponse partait en HTTP 422, et HTMX ne swappe QUE les 2xx
par défaut : le message n'était jamais inséré dans la page. L'utilisateur
cliquait, rien ne se passait, aucune explication.

Ce n'était pas un défaut local à l'import : 12 réponses d'erreur métier
réparties sur 4 routers rendent du HTML destiné à être lu, en 422. Toutes
étaient invisibles pour la même raison — d'où un fix à la source
(`app/static/htmx-config.js`) plutôt qu'un contournement route par route.

Ces tests échouent si quelqu'un retire la configuration, casse l'ordre de
chargement, ou ajoute une réponse d'erreur dans un statut que HTMX n'affiche
pas. La logique peut être juste ; si l'utilisateur ne la voit pas, elle n'existe
pas — c'est la même leçon que l'onglet de configuration sans lien de menu.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

APP_DIR = Path(__file__).resolve().parent.parent / "app"
HTMX_CONFIG = APP_DIR / "static" / "htmx-config.js"
BASE_TEMPLATE = APP_DIR / "templates" / "base.html"
ROUTERS_DIR = APP_DIR / "routers"

# Statuts d'erreur que le serveur utilise pour renvoyer du HTML À LIRE.
# Tout statut listé ici doit être déclaré swappable dans htmx-config.js.
SWAPPABLE_ERROR_CODES = ("404", "422")

# Réponses d'erreur servies par NAVIGATION DIRECTE et non par HTMX : le
# navigateur affiche leur corps lui-même, la config responseHandling ne les
# concerne pas. Chaque exemption nomme la fonction et sa raison — une entrée
# ajoutée sans justification est exactement la porte par laquelle un message
# invisible reviendrait.
DIRECT_NAVIGATION_RESPONSES = {
    # Route de TÉLÉCHARGEMENT : le bouton Export est un <a href download>
    # classique, sans attribut hx-*. En cas d'échec, le navigateur rend la page
    # d'erreur directement — vérifié par
    # test_exempted_routes_are_really_not_htmx_driven, qui échoue si le lien
    # gagne un jour un attribut htmx OU si cette fonction n'existe plus.
    #
    # Renommée de `export_networks_csv_route` le 2026-08-06, quand l'export est
    # devenu générique (paramétré par section au lieu d'être figé sur le plan
    # d'adressage). Le garde-fou a mordu sur le nom périmé : c'est précisément
    # ce qu'on lui demande — une exemption qui ne correspond plus à aucune
    # route est une exemption qui protège dans le vide.
    "export_section_csv_route",
}


def test_htmx_config_exists_and_is_loaded_after_htmx() -> None:
    """La config doit être chargée APRÈS htmx, sinon elle est écrasée.

    MESURÉ AU NAVIGATEUR (2026-08-06) : htmx REMPLACE `window.htmx` par sa
    propre instance à l'initialisation. Une config posée avant est donc perdue
    — la page affichait le `responseHandling` par défaut de htmx alors que le
    fichier de configuration était bien chargé, bien avant, et sans erreur.

    Ce test encodait initialement l'ordre INVERSE, c'est-à-dire mon hypothèse
    plutôt que le comportement réel de htmx. Il passait au vert avec le défaut
    en place. Un test qui affirme une hypothèse non vérifiée ne protège rien.
    """
    assert HTMX_CONFIG.exists(), (
        "app/static/htmx-config.js est absent : les messages d'erreur renvoyés "
        "en 4xx redeviendraient invisibles pour l'utilisateur."
    )

    html = BASE_TEMPLATE.read_text(encoding="utf-8")
    position_config = html.find("htmx-config.js")
    position_htmx = html.find("htmx.min.js")

    assert position_config != -1, "htmx-config.js n'est pas chargé dans base.html"
    assert position_htmx != -1, "htmx.min.js n'est pas chargé dans base.html"
    assert position_htmx < position_config, (
        "htmx-config.js doit être déclaré APRÈS htmx.min.js. Chargé avant, la "
        "configuration est écrasée quand htmx s'installe sur window.htmx, et "
        "les réponses 4xx redeviennent invisibles — sans qu'aucune erreur "
        "n'apparaisse nulle part."
    )


def test_error_codes_returning_html_are_declared_swappable() -> None:
    """Chaque statut d'erreur porteur de HTML doit être swappable."""
    config = HTMX_CONFIG.read_text(encoding="utf-8")

    for code in SWAPPABLE_ERROR_CODES:
        rule = re.search(
            rf'\{{[^}}]*code:\s*"{code}"[^}}]*\}}',
            config,
        )
        assert rule is not None, (
            f"Aucune règle responseHandling pour le statut {code}. "
            f"Les réponses {code} ne seraient pas affichées."
        )
        assert "swap: true" in rule.group(0), (
            f"La règle pour {code} ne fait pas `swap: true` : le message "
            f"d'erreur partirait sur le réseau sans jamais être affiché."
        )


def test_swappable_error_rule_precedes_the_generic_4xx_rule() -> None:
    """L'ordre des règles compte : la première qui matche gagne.

    Une règle générique `[45]..` placée AVANT la règle 422 la rendrait morte,
    et le défaut reviendrait en silence — sans que rien d'autre ne casse.
    """
    config = HTMX_CONFIG.read_text(encoding="utf-8")

    position_422 = config.find('code: "422"')
    generic = re.search(r'code:\s*"\[45\]\.\."', config)

    assert position_422 != -1, "règle 422 absente"
    if generic is not None:
        assert position_422 < generic.start(), (
            "La règle générique 4xx précède la règle 422 : elle matche en "
            "premier et annule l'affichage des erreurs métier."
        )


def test_error_rule_still_marks_the_response_as_an_error() -> None:
    """Afficher un refus ne doit pas le faire passer pour un succès.

    `error: true` conserve l'événement htmx:responseError et le marquage
    d'erreur : un 422 affiché reste un 422, jamais un 2xx déguisé.
    """
    config = HTMX_CONFIG.read_text(encoding="utf-8")
    rule = re.search(r'\{[^}]*code:\s*"422"[^}]*\}', config)

    assert rule is not None
    assert "error: true" in rule.group(0), (
        "La règle 422 doit garder `error: true`, sinon un refus serait traité "
        "comme une réussite par le reste du code HTMX."
    )


def test_no_router_returns_html_in_a_non_swappable_error_status() -> None:
    """Inventaire : aucun HTML d'erreur dans un statut jamais affiché.

    Ce test énumère la source réelle (les routers) plutôt que de se fier à une
    liste tenue à la main. Un nouveau `HTMLResponse(..., status_code=4xx)` dans
    un statut non déclaré swappable est un message condamné à l'invisibilité.
    """
    declared = set(SWAPPABLE_ERROR_CODES)
    offenders: list[str] = []

    function_def_re = re.compile(r"^(?:async\s+)?def\s+(\w+)", re.MULTILINE)

    for router in sorted(ROUTERS_DIR.glob("*.py")):
        source = router.read_text(encoding="utf-8")
        # HTMLResponse(...) portant un status_code 4xx/5xx, sur une ou plusieurs lignes.
        for match in re.finditer(
            r"HTMLResponse\((?:[^()]|\([^()]*\))*?status_code=(\d{3})",
            source,
            re.DOTALL,
        ):
            code = match.group(1)
            if not code.startswith(("4", "5")) or code in declared:
                continue

            # À quelle fonction appartient cette réponse ? (dernier `def` avant elle)
            enclosing = [m.group(1) for m in function_def_re.finditer(source[: match.start()])]
            owner = enclosing[-1] if enclosing else "?"
            if owner in DIRECT_NAVIGATION_RESPONSES:
                continue

            line = source[: match.start()].count("\n") + 1
            offenders.append(f"{router.name}:{line} ({owner}) -> HTTP {code}")

    assert not offenders, (
        "Ces réponses HTML d'erreur utilisent un statut non déclaré swappable "
        "dans htmx-config.js — leur contenu ne sera JAMAIS affiché :\n  "
        + "\n  ".join(offenders)
        + "\nAjoute le statut à SWAPPABLE_ERROR_CODES et à htmx-config.js, "
        "ou renvoie le message dans un statut déjà affiché."
    )


def test_exempted_routes_are_really_not_htmx_driven() -> None:
    """Une exemption doit être PROUVÉE, pas déclarée.

    `DIRECT_NAVIGATION_RESPONSES` autorise une route à renvoyer une erreur dans
    un statut non swappable, au motif que le navigateur l'affiche lui-même
    (navigation directe). Si un jour le lien qui l'appelle gagne un attribut
    `hx-*`, l'exemption devient fausse et le message redevient invisible — sans
    que rien ne casse. Ce test relie l'exemption au template : le lien pointant
    vers la route exemptée ne doit porter AUCUN attribut htmx.
    """
    templates_dir = APP_DIR / "templates"

    # Chemin d'URL de chaque route exemptée, extrait de son décorateur.
    exempted_paths: set[str] = set()
    for router in sorted(ROUTERS_DIR.glob("*.py")):
        source = router.read_text(encoding="utf-8")
        for match in re.finditer(
            r'@router\.\w+\(\s*"([^"]+)"[^)]*\)\s*(?:async\s+)?def\s+(\w+)',
            source,
        ):
            if match.group(2) in DIRECT_NAVIGATION_RESPONSES:
                exempted_paths.add(match.group(1))

    assert exempted_paths, (
        "Aucune route trouvée pour les exemptions déclarées "
        f"{sorted(DIRECT_NAVIGATION_RESPONSES)} — la liste est-elle périmée ?"
    )

    htmx_driven: list[str] = []
    for template in sorted(templates_dir.glob("*.html")):
        html = template.read_text(encoding="utf-8")
        for path in exempted_paths:
            for tag in re.findall(rf'<a\b[^>]*href="{re.escape(path)}"[^>]*>', html):
                if re.search(r"\bhx-[a-z-]+\s*=", tag):
                    htmx_driven.append(f"{template.name}: {tag[:90]}")

    assert not htmx_driven, (
        "Ces liens pointent vers une route exemptée MAIS sont pilotés par HTMX : "
        "leur réponse d'erreur ne sera pas affichée.\n  " + "\n  ".join(htmx_driven)
    )


def test_no_htmx_action_trigger_silently_inherits_a_foreign_hx_select() -> None:
    """Garde-fou — RÉGRESSION MESURÉE (2026-08-09) sur `/db-health`.

    CAUSE EXACTE, établie au navigateur (pas supposée) : `db_health.html` fait
    reposer TOUTE la page dans `<div id="db-health-page" hx-select=
    "#db-health-page" hx-trigger="every 60s" ...>` pour son auto-actualisation
    périodique — nécessaire puisque `/db-health` répond avec le document
    ENTIER et qu'il faut en extraire seulement ce conteneur.

    `hx-select` est un attribut HÉRITÉ par htmx (comme hx-target/hx-swap) :
    chaque bouton/formulaire d'action vivant SOUS ce conteneur (Prévisualiser,
    Exécuter OPTIMIZE, Prévisualiser tout...), sans son propre hx-select,
    héritait donc silencieusement `#db-health-page`. Leurs réponses sont de
    PETITS FRAGMENTS qui ne contiennent jamais cet id : dans htmx.min.js
    (fonction `$e`), `n.querySelectorAll(o.select)` trouvait 0 élément, le
    fragment à insérer devenait un DocumentFragment VIDE, et la boucle
    d'insertion DOM ne s'exécutait jamais. Tout le reste du cycle d'événements
    (beforeRequest/beforeSwap/afterSwap/afterSettle, tous avec shouldSwap
    true) se déroulait normalement — d'où un succès HTTP 200 + fragment
    correct + AUCUNE erreur console, mais rien n'apparaissait jamais à
    l'écran. Prouvé en traçant DOMParser.parseFromString (appelée, contenu
    correct) et Node.insertBefore/appendChild/removeChild/textContent=
    (JAMAIS appelés) pendant un clic réel.

    CE QUE CE TEST PROUVE : qu'aucun élément portant son propre déclencheur
    htmx (hx-get/hx-post à lui, pas hérité) ne vit sous un ancêtre hx-select
    sans neutraliser cet héritage (`hx-select="unset"` sur lui-même ou un
    ancêtre intermédiaire). C'est une analyse STATIQUE du HTML rendu par
    Jinja (avec des valeurs de contexte minimales) — elle ne clique sur
    rien et ne prouve donc PAS que le swap réussit réellement (un id
    hx-select valide mais absent du fragment de réponse, par exemple,
    passerait ce test sans problème). La preuve du swap réel reste le test
    navigateur (clic réel + lecture du DOM après swap), fait manuellement
    lors du fix — voir le rapport de la tâche du 2026-08-09.

    CE QU'IL NE PROUVE PAS non plus : que l'auto-actualisation périodique
    elle-même continue de fonctionner (elle a son propre hx-select légitime
    et n'est pas couverte ici, elle vise sa propre réponse qui EST le document
    complet).
    """
    import re as _re

    from app.templating import build_templates

    # Rendu minimal du template réel via le MÊME moteur que la production
    # (mêmes filtres custom : humanize_bytes, prefixed, ...) — mêmes noms de
    # variables que le router (app/routers/db_health.py), valeurs bidons
    # suffisantes pour que Jinja ne lève pas d'exception sur les
    # boucles/conditions du template.
    env = build_templates().env

    class _FakeState:
        value = "healthy"
        label = "Sain"

    class _FakeIndicator:
        state = _FakeState()
        label = "indicateur"
        value_text = "0"
        threshold_text = "-"

    class _FakeSnapshot:
        overall_state = _FakeState()
        checked_at = "2026-08-09T00:00:00"
        error_message = None
        indicators = [_FakeIndicator()]
        parts_by_table: list[Any] = []
        merge_backlog = None
        detached_parts_by_table: list[Any] = []
        errors_of_interest: list[Any] = []
        stuck_mutations: list[Any] = []
        memory = None
        replication_active = False

    template = env.get_template("db_health.html")
    html = template.render(
        snapshot=_FakeSnapshot(),
        history=[],
        monitored_tables=["flows"],
        system_log_tables=["query_log"],
        HealthState=_FakeState,
        active_page="db_health",
        auth_username="test",
        auth_role="admin",
        auth_default_password_warning=False,
        static_version="test",
    )

    # Trouver le conteneur racine hx-select (celui qui n'est PAS "unset") et
    # sa portée : tout ce qui suit jusqu'à la fermeture de son div, en
    # ignorant les sous-arbres qui neutralisent explicitement l'héritage.
    root_select_match = _re.search(r'hx-select="(?!unset)([^"]+)"', html)
    assert root_select_match is not None, (
        "Aucun hx-select trouvé dans db_health.html — ce test suppose "
        "l'auto-actualisation périodique du conteneur racine ; s'il a été "
        "retiré, ce test est devenu sans objet et doit être révisé."
    )

    # Repère chaque bloc "section/div" qui déclare hx-select="unset" — ses
    # DESCENDANTS sont couverts, on ne les vérifie pas individuellement.
    unset_scopes = [m.start() for m in _re.finditer(r'hx-select="unset"', html)]

    # Chaque déclencheur d'action (hx-get ou hx-post porté par le noeud
    # lui-même) situé APRÈS le hx-select racine et AVANT tout hx-select="unset"
    # protecteur hérite silencieusement de la sélection racine.
    offenders: list[str] = []
    for trigger_match in _re.finditer(r"<(?:form|button)\b[^>]*\bhx-(?:get|post)=", html):
        pos = trigger_match.start()
        if pos <= root_select_match.start():
            continue  # avant le conteneur racine : pas concerné
        protected = any(scope_pos < pos for scope_pos in unset_scopes)
        if protected:
            continue
        tag_snippet = html[pos : pos + 120].replace("\n", " ")
        offenders.append(tag_snippet)

    assert not offenders, (
        "Ces déclencheurs htmx héritent silencieusement du hx-select du "
        "conteneur racine (#db-health-page) sans neutralisation explicite : "
        "leur fragment de réponse ne contient jamais cet id, le swap "
        "insère un fragment vide, AUCUNE erreur ne remonte. Ajoute "
        'hx-select="unset" sur un ancêtre commun ou sur chacun.\n  '
        + "\n  ".join(offenders)
    )


def test_no_template_or_router_uses_an_unsupported_htmx_extension_attribute() -> None:
    """Un attribut htmx d'EXTENSION non embarquée est ignoré en silence.

    PIÈGE ÉVITÉ DE JUSTESSE (2026-08-06) : pour router les erreurs vers la zone
    d'import, `hx-target-error` semblait la réponse évidente. Il vient en
    réalité d'une extension htmx qui n'est PAS embarquée ici : posé sur le
    formulaire, il aurait été ignoré sans le moindre avertissement — le
    garde-fou qui ne garde rien, exactement le motif de tous les défauts de
    cette session (classe CSS inexistante, config écrasée, message invisible).

    Ce test refuse tout attribut `hx-*` absent du htmx réellement servi.
    """
    htmx_source = (APP_DIR / "static" / "htmx.min.js").read_text(encoding="utf-8")
    templates_dir = APP_DIR / "templates"

    attribute_re = re.compile(r'\bhx-[a-z0-9-]+(?=\s*=\s*["\'])')
    offenders: list[str] = []

    sources = list(templates_dir.glob("*.html")) + list(ROUTERS_DIR.glob("*.py"))
    for path in sorted(sources):
        content = path.read_text(encoding="utf-8")
        for attribute in sorted(set(attribute_re.findall(content))):
            # htmx référence ses attributs sans le préfixe dans son code minifié.
            bare = attribute[len("hx-") :]
            if attribute in htmx_source or f'"{bare}"' in htmx_source:
                continue
            offenders.append(f"{path.name}: {attribute}")

    assert not offenders, (
        "Ces attributs htmx ne sont pas reconnus par le htmx embarqué "
        f"({(APP_DIR / 'static' / 'htmx.min.js').name}) — ils sont ignorés "
        "SILENCIEUSEMENT, donc sans effet :\n  " + "\n  ".join(offenders)
    )
