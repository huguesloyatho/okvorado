"""Tests des routes de diagnostic réseau — vue convergence et écran exportateur.

Ces tests prouvent l'INTENTION, pas le moyen : ils n'imposent jamais un détail
de rendu (nom de classe CSS exact, texte pixel-perfect), mais vérifient des
comportements OBSERVABLES à l'écran :

- les deux écrans sont atteignables depuis le menu (piège vécu 2026-08-06,
  `tests/test_navigation.py`) ;
- une période hors énumération répond 422 avec un message lisible, jamais 500 ;
- quand le double ClickHouse SIMULE un échec de connexion (`ConnectionError`
  levée par un double de test, aucune infrastructure réelle sondée ici), l'écran
  rend un état DISTINCT et visible, jamais un tableau vide ou un zéro qui se
  confondrait avec une vraie mesure (garde dure du projet — CLAUDE.md, règle
  n°2 : zéro silencieux interdit) ;
- le drill-down convergence renvoie le détail d'une destination retenue ;
- les 8 onglets de l'écran exportateur existent et répondent chacun.

Le client ClickHouse est un double (`FakeClickHouseClient` de `conftest.py`) :
aucun test ne touche l'infrastructure réelle.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers import diagnostics as diagnostics_router
from app.services import portmap
from tests.conftest import FakeClickHouseClient, authenticated_test_client

# ---------------------------------------------------------------------------
# Doubles de test
# ---------------------------------------------------------------------------


class _ClickHouseClientDoubleEnEchec:
    """Double de test dont `.query()` lève systématiquement une exception,
    pour simuler côté application une connexion ClickHouse qui échoue — aucune
    infrastructure réelle n'est sollicitée par ce double."""

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> Any:
        raise ConnectionError("échec de connexion simulé par le double de test")


@pytest.fixture
def client_ok() -> TestClient:
    """Client HTTP avec un ClickHouse factice qui répond des lignes vides."""
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = (
        lambda: FakeClickHouseClient()
    )
    try:
        yield authenticated_test_client(app)
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)


@pytest.fixture
def client_echec() -> TestClient:
    """Client HTTP dont le double ClickHouse échoue systématiquement (cf.
    `_ClickHouseClientDoubleEnEchec` — simulation locale, pas d'infra réelle)."""
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = (
        lambda: _ClickHouseClientDoubleEnEchec()
    )
    try:
        yield authenticated_test_client(app)
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)


# ---------------------------------------------------------------------------
# Navigation — les deux écrans doivent être ATTEIGNABLES depuis le menu
# ---------------------------------------------------------------------------


def test_le_menu_contient_un_lien_vers_la_convergence() -> None:
    """Piège vécu (2026-08-06) : du code livré mais absent du menu n'existe pas
    pour l'utilisateur. cf. tests/test_navigation.py, même garde ici."""
    html = (
        __import__("pathlib").Path(__file__).parent.parent / "app" / "templates" / "base.html"
    ).read_text(encoding="utf-8")
    assert "/diagnostics/convergence" in html


def test_le_menu_contient_un_lien_vers_les_exportateurs() -> None:
    """L'écran exportateur se raccroche depuis la liste des exportateurs
    existante (`/exporters`), déjà présente au menu — pas d'entrée dédiée
    nécessaire pour l'écran de détail paramétré."""
    html = (
        __import__("pathlib").Path(__file__).parent.parent / "app" / "templates" / "base.html"
    ).read_text(encoding="utf-8")
    assert "/exporters" in html


# ---------------------------------------------------------------------------
# GET /diagnostics/convergence — la vue qui révèle le motif SCCM
# ---------------------------------------------------------------------------


def test_convergence_periode_par_defaut_repond_200(client_ok: TestClient) -> None:
    response = client_ok.get("/diagnostics/convergence")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_convergence_periode_invalide_repond_422_avec_message_lisible(
    client_ok: TestClient,
) -> None:
    """ValueError levée par le service doit devenir un 422 lisible, jamais 500."""
    response = client_ok.get("/diagnostics/convergence", params={"period": "42d"})
    assert response.status_code == 422
    assert "42d" in response.text or "periode" in response.text.lower()


@pytest.mark.parametrize("period", ("1h", "6h", "24h", "7d", "30d"))
def test_convergence_toutes_les_periodes_de_l_enumeration_repondent_200(
    client_ok: TestClient, period: str
) -> None:
    response = client_ok.get("/diagnostics/convergence", params={"period": period})
    assert response.status_code == 200


def test_convergence_echec_clickhouse_affiche_un_etat_distinct_et_visible(
    client_echec: TestClient,
) -> None:
    """Zéro silencieux interdit : quand le double ClickHouse échoue (simulation
    de test), l'écran doit produire un texte d'indisponibilité VISIBLE, jamais
    un tableau vide indiscernable d'une fenêtre sans convergence."""
    response = client_echec.get("/diagnostics/convergence")
    assert response.status_code == 200
    lowered = response.text.lower()
    assert any(mot in lowered for mot in ("indisponible", "impossible", "échec")), (
        "aucun état d'indisponibilité visible alors que le double ClickHouse échoue"
    )


def test_convergence_explique_la_vue_a_l_ecran(client_ok: TestClient) -> None:
    """L'utilisateur veut que ses collègues comprennent la vue sans être
    experts : le filtre source-interne / ports de service doit être EXPLIQUÉ,
    pas seulement appliqué en silence."""
    response = client_ok.get("/diagnostics/convergence")
    assert response.status_code == 200
    lowered = response.text.lower()
    assert "source" in lowered
    assert any(mot in lowered for mot in ("interne", "convergence", "convergent"))


def test_convergence_explique_maintenant_le_filtre_destination_interne(
    client_ok: TestClient,
) -> None:
    """Le texte doit être mis à jour avec le nouveau filtre (défaut n°1) : la
    vue ne retient que les destinations INTERNES — un serveur d'entreprise est
    interne, le trafic sortant vers Internet est du bruit ici. L'assertion
    porte sur la PHRASE (« destination(s) interne(s) »), pas sur la simple
    présence isolée des deux mots ailleurs sur la page (le mot « destination »
    apparaît déjà dans l'en-tête de colonne du tableau)."""
    response = client_ok.get("/diagnostics/convergence")
    assert response.status_code == 200

    debut = response.text.index('<p class="notice notice-info">')
    fin = response.text.index("</p>", debut)
    paragraphe = response.text[debut:fin].lower()

    assert re.search(r"destinations?\s+internes?", paragraphe), (
        "le paragraphe d'explication ne décrit pas le nouveau filtre "
        "destination-interne (défaut n°1)"
    )
    assert any(mot in paragraphe for mot in ("port", "service"))


def test_convergence_paragraphe_explicatif_nest_pas_casse_en_plein_milieu(
    client_ok: TestClient,
) -> None:
    """DÉFAUT MESURÉ (2026-08-07) : le paragraphe s'affichait coupé, avec des
    marqueurs markdown (`**`) et un retour à la ligne parasite (`\\n\\n`) au
    milieu d'une phrase — signe d'une balise mal fermée ou d'un gabarit
    corrompu. Le CONTENU du paragraphe (à l'intérieur de la balise `<p>`, pas
    l'espacement normal entre blocs HTML voisins) ne doit contenir NI
    astérisque markdown NI ligne vide parasite."""
    response = client_ok.get("/diagnostics/convergence")
    assert response.status_code == 200

    debut = response.text.index('<p class="notice notice-info">')
    fin = response.text.index("</p>", debut)
    paragraphe = response.text[debut : fin + len("</p>")]

    assert "**" not in paragraphe, (
        "des astérisques markdown fuient dans le HTML rendu — le paragraphe d'explication est cassé"
    )
    assert "\n\n" not in paragraphe.replace("\r\n", "\n"), (
        "une ligne vide coupe le paragraphe d'explication en plein milieu"
    )


def test_convergence_seuil_min_sources_est_un_champ_du_formulaire(
    client_ok: TestClient,
) -> None:
    response = client_ok.get("/diagnostics/convergence")
    assert response.status_code == 200
    assert "min_sources" in response.text


def test_convergence_accepte_un_seuil_min_sources_personnalise(
    client_ok: TestClient,
) -> None:
    response = client_ok.get(
        "/diagnostics/convergence", params={"period": "1h", "min_sources": 10, "limit": 20}
    )
    assert response.status_code == 200


def test_convergence_min_sources_zero_reaffiche_la_valeur_reellement_appliquee(
    client_ok: TestClient,
) -> None:
    """`build_convergence_query` remonte silencieusement `min_sources=0` à `1`
    via `max(min_sources, 1)` (clause HAVING) — c'est la requête RÉELLEMENT
    exécutée. Mais le gabarit réaffiche `{{ min_sources }}`, qui est la valeur
    BRUTE de la query string : l'utilisateur voit "0" dans le champ alors que
    la requête a utilisé "1". Il croit voir le résultat de sa saisie ; c'est
    faux (principe du projet : une valeur affichée doit correspondre à la
    mesure faite). Le champ doit réafficher 1, pas 0."""
    response = client_ok.get("/diagnostics/convergence", params={"period": "1h", "min_sources": 0})
    assert response.status_code == 200
    assert 'value="0"' not in response.text, (
        "le formulaire réaffiche min_sources=0 alors que la requête exécutée a "
        "utilisé 1 (max(min_sources, 1)) — l'écran ment sur ce qui a été appliqué"
    )
    assert 'value="1"' in response.text


def test_convergence_limit_hors_plafond_reaffiche_la_valeur_reellement_appliquee(
    client_ok: TestClient,
) -> None:
    """Même raisonnement pour `limit`, plafonné à `MAX_CONVERGENCE_LIMIT` (500)
    par `_clamp_limit`. Si l'utilisateur demande 10000, la requête exécutée
    utilise 500 : l'écran doit montrer 500, pas 10000."""
    response = client_ok.get("/diagnostics/convergence", params={"period": "1h", "limit": 10000})
    assert response.status_code == 200
    assert 'value="10000"' not in response.text, (
        "le formulaire réaffiche limit=10000 alors que la requête exécutée a "
        "plafonné à 500 (MAX_CONVERGENCE_LIMIT) — l'écran ment sur ce qui a été appliqué"
    )
    assert 'value="500"' in response.text


# ---------------------------------------------------------------------------
# GET /diagnostics/convergence/detail — drill-down HTMX
# ---------------------------------------------------------------------------


def test_convergence_detail_renvoie_le_detail_d_une_destination(
    client_ok: TestClient,
) -> None:
    response = client_ok.get(
        "/diagnostics/convergence/detail",
        params={"dst_addr": "10.0.0.5", "dst_port": 445, "period": "1h"},
    )
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_convergence_table_affiche_les_adresses_demappees_jamais_en_forme_ffff(
    client_ok: TestClient,
) -> None:
    """DÉFAUT MESURÉ À L'ÉCRAN (2026-08-07) : chaque IPv4 s'affichait sous sa
    forme IPv6-mappée (`::ffff:192.0.2.24`) dans le tableau de convergence —
    illisible pour un exploitant réseau, qui attend `192.0.2.24`.

    L'assertion porte sur la CELLULE visible (`<td>...</td>`), pas sur le HTML
    entier : l'attribut `hx-vals` du drill-down doit, lui, continuer de porter
    l'adresse dans sa forme ClickHouse-comparable (`toIPv6()`), ce n'est pas ce
    qu'un opérateur LIT à l'écran."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["DstAddr", "DstPort", "Proto", "source_count", "total_bytes", "flow_count"],
        rows=[("::ffff:192.0.2.24", 9995, 6, 17, 28564480, 210)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok.get("/diagnostics/convergence")
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
    assert response.status_code == 200
    assert "<td>::ffff:192.0.2.24</td>" not in response.text, (
        "la cellule visible affiche encore l'adresse sous sa forme IPv6-mappée"
    )
    assert "<td>192.0.2.24</td>" in response.text


def test_convergence_detail_affiche_les_sources_demappees(client_ok: TestClient) -> None:
    """Même défaut que le classement, sur le drill-down : les sources listées
    au clic doivent, elles aussi, être en forme IPv4 lisible."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["SrcAddr", "ExporterName", "InIfName", "total_bytes", "flow_count"],
        rows=[("::ffff:10.0.0.42", "clm", "eth0", 12345, 9)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok.get(
            "/diagnostics/convergence/detail",
            params={"dst_addr": "192.0.2.24", "dst_port": 9995, "period": "1h"},
        )
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
    assert response.status_code == 200
    assert "::ffff:" not in response.text
    assert "10.0.0.42" in response.text


def test_convergence_detail_periode_invalide_repond_422(client_ok: TestClient) -> None:
    response = client_ok.get(
        "/diagnostics/convergence/detail",
        params={"dst_addr": "10.0.0.5", "dst_port": 445, "period": "jamais"},
    )
    assert response.status_code == 422


def test_convergence_detail_echec_clickhouse_affiche_un_etat_distinct(
    client_echec: TestClient,
) -> None:
    response = client_echec.get(
        "/diagnostics/convergence/detail",
        params={"dst_addr": "10.0.0.5", "dst_port": 445, "period": "1h"},
    )
    assert response.status_code == 200
    lowered = response.text.lower()
    assert any(mot in lowered for mot in ("indisponible", "impossible", "échec"))


def test_convergence_detail_adresse_hostile_nest_jamais_interpolee_dans_une_erreur(
    client_ok: TestClient,
) -> None:
    """Même une adresse absurde doit transiter proprement (paramétrée côté
    service) — la route ne doit pas planter en 500."""
    response = client_ok.get(
        "/diagnostics/convergence/detail",
        params={"dst_addr": "'; DROP TABLE flows--", "dst_port": 445, "period": "1h"},
    )
    assert response.status_code in (200, 422)


def test_convergence_detail_port_hors_bornes_uint16_repond_422_explicite(
    client_ok: TestClient,
) -> None:
    """La colonne ClickHouse ciblée (`DstPort`) est un `UInt16` (0-65535). Sans
    borne côté FastAPI, une valeur hors plage (ex. 70000 ou -1) part jusqu'au
    driver et n'est rattrapée que par le `try` générique de `_run_query` — pas
    de 500, mais un message moins clair qu'un 422 de validation FastAPI. La
    validation doit se faire au bon endroit : `Query(ge=0, le=65535)`."""
    response = client_ok.get(
        "/diagnostics/convergence/detail",
        params={"dst_addr": "10.0.0.5", "dst_port": 70000, "period": "1h"},
    )
    assert response.status_code == 422


def test_convergence_detail_port_negatif_repond_422_explicite(
    client_ok: TestClient,
) -> None:
    response = client_ok.get(
        "/diagnostics/convergence/detail",
        params={"dst_addr": "10.0.0.5", "dst_port": -1, "period": "1h"},
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# GET /exporters/{nom} — écran à 8 onglets
# ---------------------------------------------------------------------------

_ONGLETS = (
    "resume",
    "trafic",
    "interfaces",
    "applications",
    "sources",
    "destinations",
    "conversations",
    "qos",
)


def test_page_exportateur_repond_200(client_ok: TestClient) -> None:
    response = client_ok.get("/exporters/clm")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_page_exportateur_periode_invalide_repond_422(client_ok: TestClient) -> None:
    response = client_ok.get("/exporters/clm", params={"period": "42d"})
    assert response.status_code == 422


def test_page_exportateur_liste_les_8_onglets_attendus(client_ok: TestClient) -> None:
    """L'utilisateur a explicitement choisi ces 8 onglets — tous doivent
    apparaître dans la page (comme cible de chargement HTMX ou libellé)."""
    response = client_ok.get("/exporters/clm")
    assert response.status_code == 200
    lowered = response.text.lower()
    libelles = (
        "résumé",
        "trafic",
        "interfaces",
        "applications",
        "sources",
        "destinations",
        "conversations",
        "qos",
    )
    for libelle in libelles:
        assert libelle in lowered, f"onglet {libelle!r} absent de la page exportateur"


@pytest.mark.parametrize("onglet", _ONGLETS)
def test_chaque_onglet_exportateur_repond_200(client_ok: TestClient, onglet: str) -> None:
    """Chaque onglet se charge en HTMX via sa propre requête (pas tout d'un
    coup) — c'est ce qui garde la page rapide."""
    response = client_ok.get(f"/exporters/clm/onglet/{onglet}", params={"period": "1h"})
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_onglet_inconnu_repond_422(client_ok: TestClient) -> None:
    response = client_ok.get("/exporters/clm/onglet/inexistant", params={"period": "1h"})
    assert response.status_code == 422


def test_onglet_periode_invalide_repond_422_avec_message_lisible(
    client_ok: TestClient,
) -> None:
    response = client_ok.get("/exporters/clm/onglet/trafic", params={"period": "jamais"})
    assert response.status_code == 422
    assert response.text.strip()


@pytest.mark.parametrize("onglet", _ONGLETS)
def test_chaque_onglet_echec_clickhouse_affiche_un_etat_distinct(
    client_echec: TestClient, onglet: str
) -> None:
    """Zéro silencieux : chaque onglet doit rester visible-erreur quand le
    double ClickHouse échoue, jamais un contenu vide."""
    response = client_echec.get(f"/exporters/clm/onglet/{onglet}", params={"period": "1h"})
    assert response.status_code == 200
    lowered = response.text.lower()
    assert any(mot in lowered for mot in ("indisponible", "impossible", "échec"))


class _ClickHouseClientDoubleAvecColonnes:
    """Double portant `column_names`, requis par le contrat `QueryResult` du
    router (`FakeClickHouseClient` de conftest.py n'expose que `result_rows`,
    suffisant pour les autres tests de ce fichier qui ne lisent pas les
    valeurs — celui-ci doit lire `dscp` pour vérifier la traduction)."""

    def __init__(self, column_names: list[str], rows: list[tuple[Any, ...]]) -> None:
        self._column_names = column_names
        self._rows = rows

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> Any:
        return _ResultatAvecColonnes(self._column_names, self._rows)


class _ResultatAvecColonnes:
    def __init__(self, column_names: list[str], rows: list[tuple[Any, ...]]) -> None:
        self.column_names = column_names
        self.result_rows = rows


def test_onglet_sources_affiche_les_adresses_demappees_et_preserve_ipv6_native(
    client_ok: TestClient,
) -> None:
    """Même défaut sur l'écran exportateur (onglets Sources/Destinations/
    Conversations) : une IPv4 mappée doit s'afficher dé-mappée, ET une IPv6
    NATIVE (il y en a dans les données réelles, ex. `2001:861:...`) ne doit
    JAMAIS être tronquée — piège `cutIPv6` vérifié dans le contexte métier."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["SrcAddr", "total_bytes", "total_packets", "flow_count"],
        rows=[
            ("::ffff:198.51.100.25", 5000, 40, 12),
            ("2001:861:3ac0:1234::1", 3000, 20, 6),
        ],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok.get("/exporters/clm/onglet/sources", params={"period": "1h"})
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
    assert response.status_code == 200
    assert "::ffff:" not in response.text
    assert "198.51.100.25" in response.text
    assert "2001:861:3ac0:1234::1" in response.text


def test_onglet_qos_traduit_le_dscp_en_nom_de_classe(client_ok: TestClient) -> None:
    """dscp est numérique (0-63) : l'écran doit afficher le nom de classe lisible
    (EF, AF21, CS6, CS1...), pas seulement le chiffre brut — mesuré en prod :
    7 classes réelles observées."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["dscp", "total_bytes", "flow_count"],
        rows=[(46, 1000, 5), (18, 2000, 8), (48, 500, 2), (8, 100, 1), (0, 50, 3)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok.get("/exporters/clm/onglet/qos", params={"period": "1h"})
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
    assert response.status_code == 200
    lowered = response.text.upper()
    assert "EF" in lowered
    assert "AF21" in lowered
    assert "CS6" in lowered
    assert "CS1" in lowered


def test_exporters_html_pointe_vers_l_ecran_de_detail() -> None:
    """La liste des exportateurs doit permettre de rejoindre l'écran détaillé
    (piège vécu : code livré sans point d'entrée navigable)."""
    html = (
        __import__("pathlib").Path(__file__).parent.parent / "app" / "templates" / "exporters.html"
    ).read_text(encoding="utf-8")
    assert "/exporters/" in html


# ---------------------------------------------------------------------------
# GET /exporters/{nom} — exporter_name doit être urlencodé dans les URLs
# générées, comme partout ailleurs dans le projet (exporters.html, config.html)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# DÉFAUT MESURÉ EN PRODUCTION (2026-08-07) : volumes en octets bruts
#
# Constat à l'écran :
#   - onglet Résumé : « Volume total sur la fenêtre : 8 601 326 326 octets »
#   - onglet Applications : colonne VOLUME = 4497709712, 2914185416...
#   - drill-down convergence : colonne VOLUME = 70236704912, 23188670296...
# Illisible pour un exploitant réseau. `humanize_bytes` (filtre Jinja de
# `app/templating.py`, DÉJÀ utilisé par convergence.html pour la colonne
# principale) doit être appliqué partout où un volume est affiché — pas une
# deuxième fonction de formatage : un concept = une source.
# ---------------------------------------------------------------------------


def test_onglet_resume_affiche_le_volume_en_unite_lisible_pas_en_octets_bruts(
    client_ok: TestClient,
) -> None:
    """DÉFAUT MESURÉ (2026-08-07) : l'onglet Résumé affichait « Volume total sur
    la fenêtre : 8 601 326 326 octets » — un exploitant lit « 8.0 Go »."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["bucket", "total_bytes", "total_packets", "flow_count"],
        rows=[("2026-08-07T10:00:00", 8_601_326_326, 4_671_045, 12)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok.get("/exporters/clm/onglet/resume", params={"period": "1h"})
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
    assert response.status_code == 200
    assert "8601326326" not in response.text, (
        "le volume brut en octets apparaît encore, non formaté"
    )
    assert "octets" not in response.text.lower(), (
        "le libellé « octets » brut ne doit plus apparaître : "
        "humanize_bytes rend une unité (Go/Mo/...)"
    )
    assert "Go" in response.text or "Mo" in response.text


def test_onglet_applications_affiche_le_volume_en_unite_lisible(client_ok: TestClient) -> None:
    """DÉFAUT MESURÉ (2026-08-07) : la colonne VOLUME de l'onglet Applications
    affichait 4497709712, 2914185416... au lieu de Go/Mo."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["DstPort", "Proto", "total_bytes", "total_packets", "flow_count"],
        rows=[(443, 6, 4_497_709_712, 4_671_045, 3_228_382)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok.get("/exporters/clm/onglet/applications", params={"period": "1h"})
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
    assert response.status_code == 200
    assert "4497709712" not in response.text
    assert "Go" in response.text or "Mo" in response.text


def test_onglet_qos_affiche_le_volume_en_unite_lisible(client_ok: TestClient) -> None:
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["dscp", "total_bytes", "flow_count"],
        rows=[(0, 3_228_382_000, 3_228_382)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok.get("/exporters/clm/onglet/qos", params={"period": "1h"})
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
    assert response.status_code == 200
    assert "3228382000" not in response.text
    assert "Go" in response.text or "Mo" in response.text


def test_convergence_detail_affiche_le_volume_en_unite_lisible(client_ok: TestClient) -> None:
    """DÉFAUT MESURÉ (2026-08-07) : le drill-down de convergence affichait la
    colonne VOLUME = 70236704912, 23188670296... en octets bruts."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["SrcAddr", "ExporterName", "InIfName", "total_bytes", "flow_count"],
        rows=[("::ffff:10.0.0.42", "clm", "eth0", 70_236_704_912, 12_345)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok.get(
            "/diagnostics/convergence/detail",
            params={"dst_addr": "192.0.2.24", "dst_port": 9995, "period": "1h"},
        )
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
    assert response.status_code == 200
    assert "70236704912" not in response.text
    assert "Go" in response.text or "Mo" in response.text


def test_onglet_applications_affiche_les_paquets_avec_separateur_de_milliers(
    client_ok: TestClient,
) -> None:
    """DÉFAUT MESURÉ (2026-08-07) : colonne PAQUETS = 4671045 brut, sans
    séparateur — humanize_number suffit ici (pas une conversion d'unité)."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["DstPort", "Proto", "total_bytes", "total_packets", "flow_count"],
        rows=[(443, 6, 4_497_709_712, 4_671_045, 3_228_382)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok.get("/exporters/clm/onglet/applications", params={"period": "1h"})
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
    assert response.status_code == 200
    assert "4671045" not in response.text, (
        "les paquets bruts apparaissent sans séparateur de milliers"
    )
    assert "4 671 045" in response.text


# ---------------------------------------------------------------------------
# DÉFAUT MESURÉ EN PRODUCTION (2026-08-07) : protocole affiché en numéro
#
# Constat à l'écran : colonne PROTOCOLE = 6, 17 — un exploitant réseau lit
# TCP/UDP. ClickHouse résout déjà les numéros via son dictionnaire
# (dictGetOrDefault('protocols','name',toUInt64(6),'?') -> TCP), mais l'app
# préfère une table Python pour rester cohérente avec le mécanisme déjà en
# place dans app/routers/views.py (_PROTO_NUMBER_TO_NAME) — un seul mécanisme
# de résolution protocole dans toute l'app, pas deux.
# ---------------------------------------------------------------------------


def test_onglet_applications_affiche_le_protocole_en_nom_lisible(client_ok: TestClient) -> None:
    """DÉFAUT MESURÉ (2026-08-07) : colonne PROTOCOLE = 6 / 17 brut."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["DstPort", "Proto", "total_bytes", "total_packets", "flow_count"],
        rows=[(443, 6, 1000, 10, 5), (53, 17, 2000, 20, 8)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok.get("/exporters/clm/onglet/applications", params={"period": "1h"})
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
    assert response.status_code == 200
    assert "TCP" in response.text
    assert "UDP" in response.text


def test_onglet_conversations_affiche_le_protocole_en_nom_lisible(client_ok: TestClient) -> None:
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=[
            "SrcAddr",
            "DstAddr",
            "DstPort",
            "Proto",
            "total_bytes",
            "total_packets",
            "flow_count",
        ],
        rows=[("::ffff:10.0.0.1", "::ffff:10.0.0.2", 443, 6, 1000, 10, 5)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok.get("/exporters/clm/onglet/conversations", params={"period": "1h"})
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
    assert response.status_code == 200
    assert "TCP" in response.text


def test_onglet_applications_protocole_icmp_et_icmpv6_resolus(client_ok: TestClient) -> None:
    """Couvre au moins TCP (6), UDP (17), ICMP (1), ICMPv6 (58), avec repli
    numérique pour un protocole inconnu (pas de trou silencieux)."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["DstPort", "Proto", "total_bytes", "total_packets", "flow_count"],
        rows=[
            (0, 1, 100, 1, 1),
            (0, 58, 200, 2, 2),
            (0, 132, 300, 3, 3),  # protocole inconnu (SCTP) — repli numérique
        ],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok.get("/exporters/clm/onglet/applications", params={"period": "1h"})
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
    assert response.status_code == 200
    assert "ICMPv6" in response.text
    assert "ICMP" in response.text
    assert "132" in response.text, "un protocole hors table connue doit garder son numéro en repli"


def test_convergence_page_affiche_le_protocole_en_nom_lisible(client_ok: TestClient) -> None:
    """Même défaut sur le tableau principal de convergence (`convergence.html`,
    colonne Protocole) : `{{ item.Proto }}` affichait le numéro brut."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["DstAddr", "DstPort", "Proto", "source_count", "total_bytes", "flow_count"],
        rows=[("::ffff:192.0.2.24", 9995, 6, 17, 28564480, 210)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok.get("/diagnostics/convergence")
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
    assert response.status_code == 200
    assert "TCP" in response.text


def test_exporter_detail_avec_nom_contenant_un_point_dinterrogation_ne_casse_pas_les_urls() -> None:
    """Scénario concret (relevé par la revue) : un exportateur nommé SNMP ou
    via la config de l'équipement peut porter un `?` (ex. "foo?bar=baz") — c'est
    une donnée EXTERNE, pas une constante de confiance. Rendu direct du gabarit
    avec ce nom (le router transmet `exporter_name` déjà décodé par Starlette,
    donc c'est bien au moment du RENDU que le `?` doit être ré-encodé). Sans
    `| urlencode`, `data-tab-url="/exporters/foo?bar=baz/onglet/resume?period=1h"`
    contient DEUX `?` : le navigateur/HTMX tronque l'URL au premier, envoyant
    une requête vers une ressource totalement différente de celle voulue — les
    8 onglets et le sélecteur de période deviennent inopérants, SANS message
    d'erreur. Le nom doit donc apparaître urlencodé (`?` -> `%3F`), jamais brut,
    dans les attributs qui portent une URL (`hx-get`, `data-tab-url`)."""
    from app.templating import build_templates

    templates = build_templates()
    html = templates.get_template("exporter_detail.html").render(
        exporter_name="foo?bar=baz",
        period_choices=("1h", "6h", "24h", "7d", "30d"),
        current_period="1h",
        onglets=(
            "resume",
            "trafic",
            "interfaces",
            "applications",
            "sources",
            "destinations",
            "conversations",
            "qos",
        ),
    )

    # Aucune URL générée ne doit contenir le `?` brut du nom : seul le premier
    # `?` (séparateur légitime devant `period=`) doit subsister par URL.
    for ligne in html.splitlines():
        if "hx-get=" in ligne or "data-tab-url=" in ligne:
            assert ligne.count("?") <= 1, (
                f"URL avec plus d'un `?` — nom d'exportateur non urlencodé : {ligne.strip()!r}"
            )
    assert "foo%3Fbar%3Dbaz" in html, (
        "le nom d'exportateur hostile devrait apparaître urlencodé dans les URLs générées"
    )


# ---------------------------------------------------------------------------
# DÉFAUT MESURÉ EN PRODUCTION (2026-08-07) : port affiché brut, pas le nom
# de l'application
#
# Constat à l'écran : onglet Applications de /exporters/{nom} et vue
# Convergence affichent des numéros de port bruts (41641, 2049, 711, 5080)
# au lieu du nom de l'application. `app/services/portmap.py::resolve_application`
# existe déjà (table `port_mappings` éditable depuis l'écran) mais
# `app/routers/diagnostics.py` ne la référence nulle part (0 occurrence
# vérifiée avant ce correctif).
#
# Mesuré à l'instant sur la base de prod (/data/okvorado.db) :
#    2049/tcp  -> NFS
#     443/tcp  -> HTTPS
#      22/tcp  -> SSH
#     445/tcp  -> SMB
#     137/udp  -> NetBIOS-NS
#   41641/udp  -> udp/41641      (inconnu : repli propre, pas de trou silencieux)
#     711/tcp  -> tcp/711        (idem)
#
# Cas d'usage cible (déploiement SCCM de masse, signature SMB) : voir "SMB"
# au lieu de "445" est ce qui rend la vue lisible par un collègue non expert.
# ---------------------------------------------------------------------------


@pytest.fixture
def db_avec_portmap() -> sqlite3.Connection:
    """Base SQLite en mémoire, schéma applicatif + mappings port_mappings
    reproduisant la mesure de prod (2026-08-07) : quelques ports connus (NFS,
    HTTPS, SSH, SMB, NetBIOS-NS) et deux ports volontairement ABSENTS de la
    table (41641/udp, 711/tcp) pour vérifier le repli `proto/port` propre."""
    # `check_same_thread=False` : TestClient exécute les routes synchrones
    # dans un pool de threads (même besoin que `_open_db` de `app/main.py`).
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    from app.db import SCHEMA

    conn.executescript(SCHEMA)
    portmap.create_mapping(conn, port=2049, proto="tcp", application="NFS", source="iana")
    portmap.create_mapping(conn, port=443, proto="tcp", application="HTTPS", source="iana")
    portmap.create_mapping(conn, port=22, proto="tcp", application="SSH", source="iana")
    portmap.create_mapping(conn, port=445, proto="tcp", application="SMB", source="iana")
    portmap.create_mapping(conn, port=137, proto="udp", application="NetBIOS-NS", source="iana")
    # 41641/udp et 711/tcp restent volontairement absents de la table.
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def client_ok_avec_portmap(db_avec_portmap: sqlite3.Connection) -> TestClient:
    """Client HTTP avec ClickHouse factice ET connexion SQLite portmap câblées.

    Même mécanisme de dépendance que `app/routers/views.py` (dependency
    override de `get_db_connection`) — pas un second câblage."""
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = (
        lambda: FakeClickHouseClient()
    )
    app.dependency_overrides[diagnostics_router.get_db_connection] = lambda: db_avec_portmap
    try:
        yield authenticated_test_client(app)
    finally:
        app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)
        app.dependency_overrides.pop(diagnostics_router.get_db_connection, None)


def test_onglet_applications_affiche_le_nom_d_application_et_garde_le_port_visible(
    client_ok_avec_portmap: TestClient,
) -> None:
    """DÉFAUT MESURÉ (2026-08-07) : colonne port de l'onglet Applications
    affichait `445` brut. Le nom (SMB) doit apparaître ET le numéro de port
    doit rester visible — un exploitant réseau a besoin des deux."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["DstPort", "Proto", "total_bytes", "total_packets", "flow_count"],
        rows=[(445, 6, 1_000_000, 100, 10)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok_avec_portmap.get(
            "/exporters/clm/onglet/applications", params={"period": "1h"}
        )
    finally:
        app.dependency_overrides[diagnostics_router.get_clickhouse_client] = (
            lambda: FakeClickHouseClient()
        )
    assert response.status_code == 200
    assert "SMB" in response.text, "le nom de l'application (SMB) doit être affiché"
    assert "445" in response.text, "le numéro de port doit rester visible en complément du nom"


def test_onglet_applications_port_inconnu_replie_proprement_sans_vide_ni_inconnu(
    client_ok_avec_portmap: TestClient,
) -> None:
    """Port absent de `port_mappings` (711/tcp, mesuré en prod) : repli lisible
    `tcp/711`, jamais un vide ni un texte « inconnu » qui masquerait la mesure."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["DstPort", "Proto", "total_bytes", "total_packets", "flow_count"],
        rows=[(711, 6, 500, 5, 1)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok_avec_portmap.get(
            "/exporters/clm/onglet/applications", params={"period": "1h"}
        )
    finally:
        app.dependency_overrides[diagnostics_router.get_clickhouse_client] = (
            lambda: FakeClickHouseClient()
        )
    assert response.status_code == 200
    assert "tcp/711" in response.text, "repli attendu : proto/port, lisible"
    assert "inconnu" not in response.text.lower()
    assert "711" in response.text, "le numéro de port doit rester visible"


def test_onglet_conversations_affiche_le_nom_d_application_et_garde_le_port_visible(
    client_ok_avec_portmap: TestClient,
) -> None:
    """Même défaut sur l'onglet Conversations : il montre aussi un port de
    destination, qui doit être résolu en nom d'application (NFS ici)."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=[
            "SrcAddr",
            "DstAddr",
            "DstPort",
            "Proto",
            "total_bytes",
            "total_packets",
            "flow_count",
        ],
        rows=[("::ffff:10.0.0.1", "::ffff:10.0.0.2", 2049, 6, 1000, 10, 5)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok_avec_portmap.get(
            "/exporters/clm/onglet/conversations", params={"period": "1h"}
        )
    finally:
        app.dependency_overrides[diagnostics_router.get_clickhouse_client] = (
            lambda: FakeClickHouseClient()
        )
    assert response.status_code == 200
    assert "NFS" in response.text
    assert "2049" in response.text


def test_convergence_affiche_le_nom_d_application_et_garde_le_port_visible(
    client_ok_avec_portmap: TestClient,
) -> None:
    """Même défaut sur la vue Convergence : le tableau principal affiche le
    port destination brut au lieu du nom d'application (cas d'usage cible
    SCCM/SMB — voir "SMB" plutôt que "445" est l'objectif produit)."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["DstAddr", "DstPort", "Proto", "source_count", "total_bytes", "flow_count"],
        rows=[("::ffff:192.0.2.24", 445, 6, 17, 28564480, 210)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok_avec_portmap.get("/diagnostics/convergence")
    finally:
        app.dependency_overrides[diagnostics_router.get_clickhouse_client] = (
            lambda: FakeClickHouseClient()
        )
    assert response.status_code == 200
    assert "SMB" in response.text, "le nom de l'application (SMB) doit être affiché"
    assert '<td class="num">445</td>' in response.text, (
        "le numéro de port doit rester visible en complément du nom"
    )


def test_convergence_port_inconnu_replie_proprement_sans_vide_ni_inconnu(
    client_ok_avec_portmap: TestClient,
) -> None:
    """Port absent de `port_mappings` (41641/udp, mesuré en prod, maillage
    Tailscale) : repli lisible `udp/41641`, jamais un vide silencieux."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["DstAddr", "DstPort", "Proto", "source_count", "total_bytes", "flow_count"],
        rows=[("::ffff:192.0.2.24", 41641, 17, 5, 1000, 10)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok_avec_portmap.get("/diagnostics/convergence")
    finally:
        app.dependency_overrides[diagnostics_router.get_clickhouse_client] = (
            lambda: FakeClickHouseClient()
        )
    assert response.status_code == 200
    assert "udp/41641" in response.text
    assert "inconnu" not in response.text.lower()


def test_convergence_detail_affiche_le_nom_d_application_de_la_destination(
    client_ok_avec_portmap: TestClient,
) -> None:
    """Le drill-down convergence est ouvert sur une (destination, port) déjà
    retenue par le classement : le port cliqué doit lui aussi être résolu en
    nom d'application dans le fragment affiché, pas seulement dans le tableau
    parent."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["SrcAddr", "ExporterName", "InIfName", "total_bytes", "flow_count"],
        rows=[("::ffff:10.0.0.42", "clm", "eth0", 12345, 9)],
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
    try:
        response = client_ok_avec_portmap.get(
            "/diagnostics/convergence/detail",
            params={"dst_addr": "::ffff:192.0.2.24", "dst_port": 445, "period": "1h"},
        )
    finally:
        app.dependency_overrides[diagnostics_router.get_clickhouse_client] = (
            lambda: FakeClickHouseClient()
        )
    assert response.status_code == 200
    assert "SMB" in response.text
    assert "445" in response.text


def test_resolution_application_ne_fait_pas_une_requete_sqlite_par_ligne(
    client_ok_avec_portmap: TestClient, db_avec_portmap: sqlite3.Connection
) -> None:
    """Contrainte d'intégration : sur un tableau de 50 lignes, la résolution
    ne doit pas exploser en 50 requêtes SQLite distinctes si un mécanisme de
    cache/regroupement est possible sans le dupliquer. On vérifie ici que le
    nombre de lignes SQL exécutées reste borné (au plus 1 par port+proto
    DISTINCT présent dans le tableau, jamais 1 par ligne affichée) — 50 lignes
    du même port ne doivent pas déclencher 50 lectures de la table
    `port_mappings`."""
    lignes_dupliquees = [(445, 6, 1000, 10, 1) for _ in range(50)]
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["DstPort", "Proto", "total_bytes", "total_packets", "flow_count"],
        rows=lignes_dupliquees,
    )
    app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake

    # `set_trace_callback` : mécanisme natif sqlite3 pour observer chaque
    # requête réellement exécutée sur la connexion — pas de monkeypatch sur
    # `.execute` (attribut en lecture seule sur `sqlite3.Connection`).
    requetes_avant: list[str] = []
    db_avec_portmap.set_trace_callback(requetes_avant.append)

    try:
        response = client_ok_avec_portmap.get(
            "/exporters/clm/onglet/applications", params={"period": "1h"}
        )
    finally:
        db_avec_portmap.set_trace_callback(None)
        app.dependency_overrides[diagnostics_router.get_clickhouse_client] = (
            lambda: FakeClickHouseClient()
        )

    assert response.status_code == 200
    requetes_port_mappings = [sql for sql in requetes_avant if "port_mappings" in sql]
    assert len(requetes_port_mappings) <= 1, (
        f"{len(requetes_port_mappings)} requêtes SQLite pour 50 lignes du même "
        "port+proto : la résolution doit regrouper les couples (port, proto) "
        "DISTINCTS avant d'interroger SQLite, pas interroger une fois par ligne "
        "affichée."
    )
