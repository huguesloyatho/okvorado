"""Garde-fou : toute page servie doit être atteignable depuis le menu.

DÉFAUT VÉCU (2026-08-06) — c'est la raison d'être de ce fichier.
Les écrans de configuration (`/config`, `/config/sections`) étaient codés,
testés, déployés… et ABSENTS de la barre de navigation. L'utilisateur a fait un
rechargement forcé, exploré les 5 onglets, et n'a trouvé aucun endroit pour
configurer quoi que ce soit — à juste titre.

Les screenshots de validation avaient été pris en tapant l'URL à la main, ce qui
masquait complètement le problème : une page atteignable seulement par URL
n'existe pas pour la personne qui utilise l'application.

Ce test compare les pages HTML réellement servies aux liens du menu. Il échoue
si quelqu'un ajoute un écran sans l'y déclarer.
"""

from __future__ import annotations

import re
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent.parent / "app" / "templates"
BASE_TEMPLATE = TEMPLATES_DIR / "base.html"

PAGES_HORS_MENU: frozenset[str] = frozenset(
    {
        "/",  # redirige vers /exporters
        "/health",  # sonde technique (Kuma/Gatus), pas une page
        # Pages générées par FastAPI, destinées aux développeurs et non aux
        # utilisateurs de l'application :
        "/docs",
        "/redoc",
        "/openapi.json",
        "/docs/oauth2-redirect",
    }
)
"""Pages volontairement absentes du menu, avec la raison de leur exemption.

Toute entrée ici est un choix assumé. En ajouter une doit rester un acte
délibéré : c'est exactement par ce genre d'exemption tacite que les écrans de
configuration sont devenus invisibles.
"""


def _menu_hrefs() -> set[str]:
    """Extrait les liens INTERNES de la barre de navigation.

    Reconnaît DEUX formes : le chemin brut `href="/exporters"` et la forme
    passée au filtre Jinja `prefixed` (nécessaire depuis que l'app est servie
    derrière le proxy Grafana) `href="{{ '/exporters' | prefixed }}"`. Le
    préfixe par défaut est vide : à vide, `prefixed` rend le chemin identique
    à avant — seul le TEXTE SOURCE du template a changé de forme.
    """
    html = BASE_TEMPLATE.read_text(encoding="utf-8")
    nav = re.search(r"<nav class=\"nav\">(.*?)</nav>", html, re.DOTALL)
    assert nav is not None, "la barre de navigation est introuvable dans base.html"
    motif = r"""href="(?:(/[^"{]*)|\{\{\s*'(/[^']*)'\s*\|\s*prefixed\s*\}\})\""""
    hrefs = set()
    for brut, via_filtre in re.findall(motif, nav.group(1)):
        hrefs.add(brut or via_filtre)
    return hrefs


def _pages_avec_barre_de_navigation() -> set[str]:
    """Chemins des routes qui rendent une PAGE COMPLÈTE (héritant de `base.html`).

    DÉFAUT MESURÉ (2026-08-07) : le critère précédent définissait un fragment
    comme « une cible de `hx-get` ABSENTE DU MENU ». Il dépendait donc du menu
    — et s'auto-neutralisait exactement dans le cas qu'il devait détecter.

    Vérifié en retirant le lien « Convergence » de `base.html` : les 3 tests
    restaient VERTS. `convergence.html` porte `hx-get="/diagnostics/convergence"`
    pour son auto-rafraîchissement ; privée de son lien, la page se requalifiait
    toute seule en fragment et sortait du contrôle. Le garde-fou censé empêcher
    le retour du défaut du 2026-08-06 (écrans de configuration atteignables
    uniquement en tapant l'URL) laissait donc passer ce même défaut.

    Le critère retenu est STRUCTUREL et indépendant du menu : une page rend un
    document complet — elle hérite de `base.html`, donc son HTML porte la barre
    de navigation. Un fragment rend un morceau destiné à être inséré dans une
    page existante ; il n'a ni `<html>` ni `<nav>`.

    On interroge le GABARIT de la route, pas le nom du chemin : un suffixe
    (`/fragment`, `/list`) est une convention qui dérive.

    ⚠️ DEUX pièges mesurés en écrivant cette version, tous deux corrigés ici :

    1. Interroger la route en HTTP ne marche PAS. `/diagnostics/convergence`
       lève une exception quand la suite tourne ailleurs que sur le serveur
       applicatif : le conteneur ClickHouse tourne (healthy depuis 6 jours),
       mais il publie son port 8123 sur le seul réseau Docker de l'hôte —
       mesuré fermé sur 127.0.0.1, localhost et 192.0.2.6 depuis le poste de
       développement. La route était donc écartée, et son lien de menu passait
       pour MORT. Un garde-fou de navigation ne doit dépendre d'aucun service
       externe : il doit mordre y compris sur une machine de développement.
    2. Rendre `<nav>` ne suffit pas à faire une page : `/config/pending` est un
       fragment (chargé par `hx-get` depuis `config.html`) qui hérite pourtant
       de `base.html`.

    D'où le critère combiné, entièrement STATIQUE : une PAGE est une route dont
    le gabarit étend `base.html` ET qui n'est la cible d'aucun `hx-get` — sauf
    lorsqu'elle se rafraîchit elle-même, cas où le `hx-get` vise sa PROPRE URL.
    """
    cibles_hx_par_gabarit: dict[str, set[str]] = {}
    for template in TEMPLATES_DIR.glob("*.html"):
        html = template.read_text(encoding="utf-8")
        cibles_hx_par_gabarit[template.name] = {
            url.split("?")[0] for url in re.findall(r'hx-get="([^"{}]*)"', html)
        }

    pages: set[str] = set()
    for gabarit in TEMPLATES_DIR.glob("*.html"):
        html = gabarit.read_text(encoding="utf-8")
        if 'extends "base.html"' not in html and "extends 'base.html'" not in html:
            continue  # fragment : rend un morceau de page, pas un document
        chemin = _route_du_gabarit(gabarit.name)
        if chemin is None or chemin in PAGES_HORS_MENU:
            continue
        # Une page qui s'auto-rafraîchit vise sa PROPRE URL : ce `hx-get` ne la
        # disqualifie pas. Être visé par un AUTRE gabarit, si : c'est un fragment.
        vise_par_un_autre = any(
            chemin in cibles for nom, cibles in cibles_hx_par_gabarit.items() if nom != gabarit.name
        )
        if vise_par_un_autre:
            continue
        pages.add(chemin)
    return pages


def _route_du_gabarit(nom_gabarit: str) -> str | None:
    """Chemin de la route qui rend ce gabarit, lu dans le CODE des routeurs.

    Dérivé de la source (`@router.get` précédant l'usage du gabarit) plutôt que
    déduit du nom de fichier : une convention de nommage dérive, une
    correspondance lue dans le code suit le refactor.

    ⚠️ Piège mesuré : chercher la simple PRÉSENCE du nom de gabarit dans le
    module donne un faux couple. `exporters.html` résolvait vers
    `/config/pending`, parce que `config.py` — premier dans l'ordre
    alphabétique — mentionne ce nom ailleurs. On ancre donc sur l'APPEL DE
    RENDU (le gabarit entre guillemets), et on ignore les routes d'API, qui
    ne rendent pas de page.
    """
    routeurs = Path(__file__).parent.parent / "app" / "routers"
    motif_rendu = re.compile(rf'["\']{re.escape(nom_gabarit)}["\']')
    for module in sorted(routeurs.glob("*.py")):
        source = module.read_text(encoding="utf-8")
        rendu = motif_rendu.search(source)
        if rendu is None:
            continue
        chemins = [
            chemin
            for chemin in _chemins_get_declares(source[: rendu.start()])
            if not chemin.startswith("/api/")
        ]
        if chemins:
            prefixe = re.search(r'APIRouter\([^)]*prefix="([^"]*)"', source)
            return (prefixe.group(1) if prefixe else "") + chemins[-1]
    return None


def _chemins_get_declares(source: str) -> list[str]:
    """Chemins déclarés par `@router.get(...)`, littéraux OU via une CONSTANTE.

    ⚠️ DÉFAUT MESURÉ (2026-08-10), troisième variante du même angle mort que
    celles déjà documentées dans `_pages_avec_barre_de_navigation` : ce
    garde-fou ne reconnaissait QUE la forme littérale `@router.get("/x")`.

    L'écran d'intégration de la console (`app/routers/console_embed.py`)
    déclare sa route `@router.get(EMBED_PATH)` — une CONSTANTE de module,
    précisément pour que le chemin ait une source de vérité unique partagée
    avec les tests, au lieu d'être recopié en dur à plusieurs endroits. Bien
    écrite, cette route devenait INVISIBLE au garde-fou : la page n'était plus
    comptée comme servie, et son lien de menu était donc rapporté comme MORT.

    C'est le pire profil de faux positif — il PUNIT la bonne pratique et pousse
    à revenir au littéral dupliqué, ou pire, à exempter la page (ce qui
    rouvrirait le trou du 2026-08-06 que tout ce fichier existe pour fermer).
    On résout donc la constante dans le module plutôt que d'exiger un littéral.
    """
    chemins: list[str] = []
    for brut in re.findall(r"@router\.get\(\s*([^,)\s]+)", source):
        if brut.startswith(('"', "'")):
            valeur = brut.strip("\"'")
            if "{" not in valeur:  # exclut les chemins paramétrés, comme avant
                chemins.append(valeur)
            continue
        # Nom de constante : on lit son affectation littérale dans le module.
        affectation = re.search(rf'^{re.escape(brut)}\s*[:=][^=]*?"([^"{{}}]*)"', source, re.M)
        if affectation:
            chemins.append(affectation.group(1))
    return chemins


def _served_pages() -> set[str]:
    """Pages HTML complètes réellement servies, INDÉPENDAMMENT du menu.

    Le critère est la présence de la barre de navigation dans le rendu — un
    fait observable — et non plus « cible de `hx-get` absente du menu », qui
    faisait dépendre le contrôle de ce qu'il contrôle (cf. le défaut mesuré
    documenté dans `_pages_avec_barre_de_navigation`).
    """
    return _pages_avec_barre_de_navigation()


def test_configuration_est_dans_le_menu() -> None:
    """L'écran de configuration DOIT avoir son entrée de menu.

    C'est le défaut exact qui a été vécu : sans ce lien, l'utilisateur explore
    les onglets et conclut — correctement — que rien n'est configurable.
    """
    hrefs = _menu_hrefs()
    assert any(h.startswith("/config") for h in hrefs), (
        "Aucun lien vers la configuration dans le menu. Les écrans de config "
        "seraient invisibles pour l'utilisateur, atteignables seulement par URL."
    )


def test_toute_page_servie_est_atteignable_depuis_le_menu() -> None:
    """Aucune page HTML ne doit être orpheline de navigation."""
    hrefs = _menu_hrefs()
    orphelines = set()
    for page in _served_pages():
        if page in PAGES_HORS_MENU:
            continue
        # Une page est couverte si elle-même, ou une page dont elle dépend,
        # figure au menu (ex. /config couvert par /config/sections).
        if not any(page.startswith(h) or h.startswith(page) for h in hrefs):
            orphelines.add(page)

    assert not orphelines, (
        f"Pages servies mais absentes du menu : {sorted(orphelines)}. "
        "Une page atteignable seulement par URL n'existe pas pour l'utilisateur. "
        "Ajoute son lien dans base.html, ou déclare l'exemption dans PAGES_HORS_MENU."
    )


def test_les_liens_du_menu_pointent_vers_des_routes_reelles() -> None:
    """Le miroir du test précédent : pas de lien mort dans le menu.

    EXEMPTION SUPPRIMÉE le 2026-08-10. Ce contrôle portait un
    `_LIENS_PROXY = {"/akvorado-console"}`, parce que le menu pointait alors
    DIRECTEMENT vers le routeur de proxy — qui n'a aucun gabarit local, donc
    restait invisible au critère structurel de `_served_pages()`.

    Le menu pointe désormais vers l'écran d'intégration `/akvorado`
    (`app/routers/console_embed.py`), qui est une VRAIE page avec son gabarit
    `console_embed.html` étendant `base.html` : elle est donc détectée
    normalement, sans aucune exemption. Laisser l'exemption en place aurait
    été pire qu'inutile — elle ne couvrait plus rien, mais aurait dispensé de
    tout contrôle un futur lien direct vers le proxy remis dans le menu.
    Une exemption qui ne protège plus rien ne fait que creuser un trou.
    """
    served = _served_pages()
    morts = {
        href
        for href in _menu_hrefs()
        if not any(s == href or s.startswith(href) for s in served)
    }
    assert not morts, f"Liens de menu ne correspondant à aucune route servie : {sorted(morts)}"


def test_toute_variable_du_gabarit_commun_est_un_global_jinja() -> None:
    """Une variable utilisée par `base.html` doit être fournie GLOBALEMENT,
    jamais passée route par route.

    DÉFAUT MESURÉ À L'ÉCRAN (2026-08-09) : `akvorado_url` alimente le lien
    « Akvorado ↗ » de `base.html`, donc de TOUTES les pages — mais elle était
    passée à la main par chaque routeur (`config.py`, `views.py`...). Les
    écrans d'authentification, nouvellement ajoutés, ne la fournissaient pas :
    Jinja rend alors une chaîne VIDE, et `<a href="">` renvoie sur la page
    courante. Constaté sur `/settings/security`, où « Akvorado ↗ » pointait
    vers `/settings/security`.

    Le défaut est SILENCIEUX : aucune erreur, aucun test rouge, juste un lien
    qui ne mène nulle part. Et il revient à chaque nouvelle page dont l'auteur
    ignore qu'il doit passer cette variable — d'où ce garde-fou plutôt qu'une
    n-ième correction d'occurrence.
    """
    import re

    from app.templating import build_templates

    base = (Path(__file__).resolve().parent.parent / "app" / "templates" / "base.html").read_text(
        encoding="utf-8"
    )

    # Variables consommées directement par le gabarit commun, hors blocs et
    # hors constructions Jinja (boucles, conditions, filtres).
    consommees = set(re.findall(r"\{\{\s*([a-z_][a-z0-9_]*)\s*[}|]", base))
    fournies = set(build_templates().env.globals)

    # Ce que le contexte d'authentification injecte par processeur (donc
    # présent sur toute page rendue), à lire dans templating.py
    # (`_auth_context`, étendu LOT accounts avec `auth_username`/`auth_role`
    # pour l'état de connexion affiché dans base.html).
    contexte_auth = {
        "utilisateur_connecte",
        "mot_de_passe_par_defaut",
        "request",
        "auth_username",
        "auth_role",
        "auth_default_password_warning",
    }
    # Fournies par page, légitimement : elles décrivent la page elle-même.
    propres_a_la_page = {"active_page", "title"}

    manquantes = consommees - fournies - contexte_auth - propres_a_la_page
    assert not manquantes, (
        f"Variables utilisées par base.html mais non fournies globalement : "
        f"{sorted(manquantes)}. Une page qui oublierait de les passer rendrait "
        "une chaîne vide, sans erreur — lien mort, ressource introuvable. "
        "Déclare-les dans `build_templates()` (env.globals), comme "
        "`static_version` et `akvorado_url`."
    )


class TestToutRouterInjecteEstCableDansMain:
    """Tout router qui DÉCLARE une dépendance injectable doit la voir surchargée
    dans `app/main.py`, sinon la prod échoue là où les tests passent.

    DÉFAUT MESURÉ (2026-08-10) : le chantier « résolution SNMP des ifIndex » a
    ajouté deux routes POST à `app/routers/exporters.py`, lesquelles dépendent
    de `get_db_connection` / `get_templates`. Les 1885 tests passaient — parce
    que chaque test surcharge lui-même ces dépendances — mais `app/main.py` ne
    les câblait pas. En production, la définition par défaut lève
    délibérément « non câblée : app/main.py doit surcharger cette dépendance ».
    Le défaut n'apparaissait donc QU'AU CLIC, à l'écran.

    C'est la quatrième famille de défauts invisibles aux tests recensée sur ce
    projet : « service existant non branché » (cf. CLAUDE.md, section « Ce que
    les tests ne prouvent pas »). Un garde-fou vaut mieux qu'une n-ième
    correction d'occurrence.

    NOTE sur les routers ABSENTS de cet inventaire : `ingestion`, `retention`
    et `db_health` rendent leurs gabarits via le moteur partagé importé
    directement (`from app.templating import build_templates`), sans passer par
    une dépendance injectée — ils n'ont donc rien à câbler côté `get_templates`
    et ne sont pas concernés. Ce test ne regarde QUE ce qui est réellement
    déclaré comme injectable, jamais une liste écrite à la main (une liste
    figée serait exactement le garde-fou aveugle que ce projet a déjà corrigé).
    """

    _ROUTERS_DIR = Path(__file__).resolve().parent.parent / "app" / "routers"
    _MAIN = Path(__file__).resolve().parent.parent / "app" / "main.py"

    # Dépendances dont l'absence de câblage fait ÉCHOUER la requête en prod.
    _DEPENDANCES_CRITIQUES = ("get_db_connection", "get_templates")

    @classmethod
    def _declarations_par_router(cls) -> dict[str, set[str]]:
        """Ce que CHAQUE router déclare réellement comme dépendance injectable."""
        trouve: dict[str, set[str]] = {}
        for fichier in sorted(cls._ROUTERS_DIR.glob("*.py")):
            if fichier.name == "__init__.py":
                continue
            source = fichier.read_text(encoding="utf-8")
            declarees = {
                dep
                for dep in cls._DEPENDANCES_CRITIQUES
                if re.search(rf"^def {re.escape(dep)}\(", source, re.MULTILINE)
            }
            if declarees:
                trouve[fichier.stem] = declarees
        return trouve

    @classmethod
    def _cablages_dans_main(cls) -> set[tuple[str, str]]:
        """Les couples (router, dépendance) réellement surchargés dans main.py."""
        source = cls._MAIN.read_text(encoding="utf-8")
        return set(
            re.findall(
                r"app\.dependency_overrides\[\s*([a-z_]+)_router\.(get_db_connection|get_templates)\s*\]",
                source,
            )
        )

    def test_inventaire_non_vide(self) -> None:
        """Sans cette garde, une regex cassée rendrait le test vert à vide."""
        declarations = self._declarations_par_router()
        assert len(declarations) >= 10, (
            f"inventaire suspect ({len(declarations)} routers) — la détection "
            "des dépendances déclarées est probablement cassée"
        )
        assert self._cablages_dans_main(), "aucun câblage détecté dans main.py"

    def test_toute_dependance_declaree_est_cablee(self) -> None:
        declarations = self._declarations_par_router()
        cables = self._cablages_dans_main()

        # `config_sections` est monté sous l'alias `sections_router` dans main.py.
        alias = {"config_sections": "sections"}
        # Routers qui utilisent le moteur de templates PARTAGÉ (import direct)
        # plutôt qu'une dépendance injectée : rien à câbler pour eux.
        moteur_partage = {
            ("ingestion", "get_templates"),
            ("retention", "get_templates"),
            ("db_health", "get_templates"),
        }

        manquants: list[str] = []
        for router, deps in sorted(declarations.items()):
            for dep in sorted(deps):
                if (router, dep) in moteur_partage:
                    continue
                nom = alias.get(router, router)
                if (nom, dep) not in cables:
                    manquants.append(f"{router}.{dep}")

        assert not manquants, (
            "dépendance(s) DÉCLARÉE(S) par un router mais jamais surchargée(s) "
            "dans app/main.py — les tests passeront et la PROD échouera au "
            f"premier clic : {manquants}"
        )

    def test_le_garde_fou_mord(self) -> None:
        """PREUVE DE MORSURE : un test toujours vert ne prouve rien."""
        declarations = {"exporters": {"get_db_connection"}}
        cables: set[tuple[str, str]] = set()  # simule l'oubli réel du 2026-08-10

        manquants = [
            f"{r}.{d}"
            for r, deps in declarations.items()
            for d in deps
            if (r, d) not in cables
        ]
        assert manquants == ["exporters.get_db_connection"]
