"""Garde-fous du préfixe d'URL (`OKVORADO_URL_PREFIX` / `settings.url_prefix`).

CONTEXTE — Grafana peut proxifier Okvorado via une datasource de plugin :
l'URL servie devient alors `/api/datasources/proxy/uid/<uid>/exporters` au
lieu de `/exporters`. Les templates écrivent leurs chemins en dur
(`href="/exporters"`, `src="/static/style.css"`, `hx-get="/config/..."`) —
sous le proxy, le navigateur les résoudrait à la racine de Grafana, cassant
CSS/JS/navigation.

MESURÉ (pas supposé) avant d'implémenter : la balise `<base href>` NE
corrige PAS ce cas. Elle ne réécrit que les chemins RELATIFS ; un chemin
absolu (qui commence par `/`) ignore `<base>` et se résout toujours à la
racine du document (RFC 3986 §5.3 : une référence de chemin absolu remplace
entièrement le chemin de la base). D'où la solution retenue : un filtre
Jinja `prefixed` appliqué explicitement à chaque chemin absolu, plutôt
qu'une balise `<base>` qui ne réglerait rien pour l'écrasante majorité des
~100 chemins réels du projet (tous en forme absolue).

DÉFAUT RÉEL rencontré en écrivant ce filtre (documenté ici pour ne pas le
réintroduire) : Jinja2 REPLIE les filtres appliqués à un littéral constant
(`'/x' | prefixed`) à la COMPILATION du template, et fige le résultat dans
le bytecode mis en cache — `settings.url_prefix` changé après coup restait
invisible, en silence. Le filtre `prefixed` est décoré `@pass_context`
précisément pour désactiver ce repli (voir `app/templating.py`).
"""

from __future__ import annotations

import re

import pytest

from app.config import settings
from app.main import app
from app.templating import prefixed as _prefixed_with_context
from tests.conftest import authenticated_test_client


def prefixed(path: str) -> str:
    """Enveloppe de test : `prefixed` est décoré `@pass_context` (Jinja2 le
    charge automatiquement avec le contexte de rendu), donc son premier
    paramètre réel n'est pas `path` mais le contexte — inutilisé par
    l'implémentation (elle lit `settings` directement). Cette enveloppe
    appelle la fonction comme le fait Jinja2, sans dupliquer sa logique."""
    return _prefixed_with_context(None, path)


@pytest.fixture(autouse=True)
def _restore_url_prefix():
    """Chaque test repart d'un préfixe vide et le restaure après coup.

    `settings` est un singleton partagé par toute l'application (comme
    `frame_ancestors` ailleurs) : un test qui le modifie sans le restaurer
    contaminerait tous les tests suivants de la session — y compris ceux
    d'autres fichiers qui ne s'attendent PAS à un préfixe.
    """
    original = settings.url_prefix
    settings.url_prefix = ""
    yield
    settings.url_prefix = original


# ---------------------------------------------------------------------------
# 1. Le filtre `prefixed` lui-même — unité, sans passer par un rendu HTML
# ---------------------------------------------------------------------------


def test_prefixe_vide_laisse_le_chemin_inchange() -> None:
    """LE défaut à protéger : `url_prefix=""` (valeur de `Settings` par défaut)
    doit produire un comportement STRICTEMENT identique à aujourd'hui, pour
    ne casser aucun des tests existants qui vérifient des chemins bruts."""
    settings.url_prefix = ""
    assert prefixed("/exporters") == "/exporters"
    assert prefixed("/static/style.css?v=abc123") == "/static/style.css?v=abc123"


def test_prefixe_pose_prefixe_le_chemin_absolu() -> None:
    settings.url_prefix = "/api/datasources/proxy/uid/abc123"
    assert prefixed("/exporters") == "/api/datasources/proxy/uid/abc123/exporters"
    assert prefixed("/static/style.css") == "/api/datasources/proxy/uid/abc123/static/style.css"


def test_prefixe_sans_slash_final_ne_produit_pas_de_double_slash() -> None:
    """Cas limite documenté dans la docstring de `Settings.url_prefix` : le
    préfixe ne doit JAMAIS se terminer par `/` (concaténation directe avec un
    chemin qui commence toujours par `/`). Ce test prouve que le format
    attendu (sans `/` final) ne produit pas de double slash."""
    settings.url_prefix = "/proxy/uid/abc123"
    resultat = prefixed("/exporters")
    assert "//" not in resultat
    assert resultat == "/proxy/uid/abc123/exporters"


def test_prefixe_avec_slash_final_produit_un_double_slash_visible() -> None:
    """Contrôle négatif : si un déploiement pose PAR ERREUR un préfixe avec
    `/` final, le double slash doit être VISIBLE dans le résultat (pas
    absorbé en silence) — c'est la preuve que la docstring d'avertissement
    est fondée, pas un raccourci "on suppose que ça n'arrive pas"."""
    settings.url_prefix = "/proxy/uid/abc123/"
    resultat = prefixed("/exporters")
    assert resultat == "/proxy/uid/abc123//exporters"


def test_chemin_deja_relatif_ou_externe_traverse_sans_modification() -> None:
    """Seuls les chemins ABSOLUS-RACINE (commençant par `/`) sont concernés :
    une URL externe complète ne doit jamais être réécrite."""
    settings.url_prefix = "/proxy/uid/abc123"
    assert prefixed("http://localhost:3000") == "http://localhost:3000"
    assert prefixed("relative/path") == "relative/path"


def test_le_filtre_nest_pas_fige_a_la_compilation_du_template(tmp_path) -> None:
    """PREUVE DE MORSURE du défaut réel rencontré (voir docstring du module) :
    un même template Jinja rendu deux fois, avec `settings.url_prefix`
    changé ENTRE les deux rendus, doit refléter le changement à chaque
    rendu — sinon le filtre serait figé par le repli de constante Jinja2 et
    le préfixe resterait celui du PREMIER rendu, silencieusement."""
    from jinja2 import Environment

    env = Environment(autoescape=True)
    # Le VRAI filtre décoré (`_prefixed_with_context`, `@pass_context`), pas
    # l'enveloppe de test ci-dessus : c'est le décorateur qui désactive le
    # repli de constante Jinja2, et c'est justement ce mécanisme qu'on prouve.
    env.filters["prefixed"] = _prefixed_with_context
    template = env.from_string('<a href="{{ \'/exporters\' | prefixed }}">lien</a>')

    settings.url_prefix = ""
    premier_rendu = template.render()
    assert premier_rendu == '<a href="/exporters">lien</a>'

    settings.url_prefix = "/proxy/uid/abc123"
    second_rendu = template.render()
    assert second_rendu == '<a href="/proxy/uid/abc123/exporters">lien</a>', (
        "le second rendu ne reflète pas le nouveau url_prefix — le filtre "
        "serait figé par le repli de constante Jinja2 (mesuré, voir docstring "
        "de prefixed() dans app/templating.py)"
    )


# ---------------------------------------------------------------------------
# 2. Bout en bout — rendu HTML réel via TestClient
# ---------------------------------------------------------------------------


# Mêmes attributs que le rayon d'impact mesuré dans la demande : href, src,
# hx-get/post/delete, et les data-* qui portent un chemin consommé par le JS
# statique (tabs.js, form-targets.js) plutôt que par htmx directement.
_ATTRS_CHEMIN = re.compile(
    r'(?:href|src|hx-[a-z]+|data-tab-url|data-target-template)="(/[^"]*)"'
)


def _chemins_absolus(html: str) -> list[str]:
    return _ATTRS_CHEMIN.findall(html)


def test_page_rendue_sans_prefixe_a_des_chemins_inchanges() -> None:
    """Défaut protégé : le rendu réel d'une page (pas seulement le filtre en
    isolation) doit rester identique à l'existant quand `url_prefix=""`."""
    settings.url_prefix = ""
    client = authenticated_test_client(app)
    resp = client.get("/exporters")
    assert resp.status_code == 200

    chemins = _chemins_absolus(resp.text)
    assert chemins, "aucun chemin absolu trouvé — le test ne prouverait rien"
    for chemin in chemins:
        assert not chemin.startswith("//"), f"chemin déjà cassé sans préfixe : {chemin!r}"


def test_page_rendue_avec_prefixe_a_tous_les_chemins_prefixes() -> None:
    """LE cas nominal de la demande : sous le proxy Grafana, TOUS les chemins
    absolus rendus (nav, CSS, JS, htmx) doivent porter le préfixe — sinon le
    navigateur les résoudrait à la racine de Grafana (CSS/JS/navigation
    cassés), exactement le défaut mesuré dans la demande initiale."""
    prefix = "/api/datasources/proxy/uid/abc123"
    settings.url_prefix = prefix
    client = authenticated_test_client(app)
    resp = client.get("/exporters")
    assert resp.status_code == 200

    chemins = _chemins_absolus(resp.text)
    assert chemins, "aucun chemin absolu trouvé — le test ne prouverait rien"
    non_prefixes = [c for c in chemins if not c.startswith(prefix)]
    assert not non_prefixes, (
        f"chemins absolus non préfixés sous url_prefix={prefix!r} : "
        f"{non_prefixes} — ils se résoudraient à la racine du proxy Grafana, "
        "cassant CSS/JS/navigation (le défaut exact que ce réglage corrige)"
    )
    # Preuve positive que le préfixage a bien eu lieu (pas juste "rien à
    # préfixer") : au moins le CSS et un lien de nav le portent.
    assert any(prefix + "/static/style.css" in html_frag for html_frag in [resp.text])
    assert f'{prefix}/exporters"' in resp.text


def test_le_favicon_et_le_css_sont_prefixes_dans_le_head() -> None:
    """Cas concret cité dans la demande initiale : `src="/static/style.css"`
    et `href="/static/favicon.svg"` étaient explicitement pointés comme
    chemins qui casseraient sous le proxy."""
    prefix = "/grafana-proxy"
    settings.url_prefix = prefix
    client = authenticated_test_client(app)
    resp = client.get("/exporters")

    assert f'href="{prefix}/static/favicon.svg"' in resp.text
    assert f'{prefix}/static/style.css?v=' in resp.text
