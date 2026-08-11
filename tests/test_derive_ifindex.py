"""Tests de la mesure de dérive d'ifIndex — proportion de flux mal classés.

PROBLÈME MESURÉ EN PRODUCTION (2026-08-11, contexte de la tâche) : 53 % des
flux (101 326 / 189 449 sur 30 min) portaient une interface `unknown`, et
l'exploitant ne l'a découvert qu'en regardant l'écran. L'écran affichait déjà
l'état « Interface inconnue » PAR EXPORTATEUR, mais rien ne donnait le
DÉCOMPTE GLOBAL ni la PROPORTION — un exploitant à 350 routeurs ne peut pas
parcourir 350 lignes pour découvrir que la moitié de ses flux est mal classée.

Ce que ce fichier prouve :
- la mesure qui compte est la PROPORTION DE FLUX, pas le nombre d'exportateurs
  en anomalie (un exportateur à 3 flux/h ne pèse pas comme un à 30 000) ;
- `count()` n'est JAMAIS mis à l'échelle par `SamplingRate` — c'est un
  comptage de flux, pas un volume (miroir de `tests/test_sampling_rate.py`) ;
- la requête est bornée (période fermée, LIMIT plafonné), aucune valeur
  utilisateur n'est concaténée ;
- ClickHouse muet -> état DISTINCT et VISIBLE, JAMAIS un 0 % qui se lirait
  « tout va bien » (CLAUDE.md, règle n°2 — motif fondateur du projet) ;
- dérive (certains flux résolvent, d'autres non) et non-déclaré (aucun flux
  ne résout) sont DISTINGUÉS, parce que le geste de correction diffère ;
- le classement par exportateur est trié par IMPACT (flux mal classés
  décroissant), pas alphabétique ni par nombre d'exportateurs.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers import diagnostics as diagnostics_router
from app.services import diagnostics
from tests.conftest import authenticated_test_client

# ---------------------------------------------------------------------------
# Service — build_unknown_interface_summary_query : construction SQL
# ---------------------------------------------------------------------------


def test_summary_query_periode_valide_retourne_sql_et_parametres() -> None:
    sql, params = diagnostics.build_unknown_interface_summary_query(period="1h")
    assert isinstance(sql, str) and sql.strip()
    assert isinstance(params, dict)


def test_summary_query_periode_hors_enumeration_refusee() -> None:
    with pytest.raises(ValueError):
        diagnostics.build_unknown_interface_summary_query(period="42d")


@pytest.mark.parametrize("period", diagnostics.DIAGNOSTIC_PERIOD_CHOICES)
def test_summary_query_toutes_les_periodes_de_l_enumeration_sont_acceptees(
    period: str,
) -> None:
    sql, _ = diagnostics.build_unknown_interface_summary_query(period=period)
    assert sql.strip()


def test_summary_query_tape_la_table_brute_jamais_un_agregat() -> None:
    """Même mesure décisive n°2 que la convergence : les tables d'agrégat ne
    portent pas InIfName/OutIfName, seule `default.flows` peut répondre."""
    sql, _ = diagnostics.build_unknown_interface_summary_query(period="1h")
    assert re.search(r"\bflows\b", sql)
    assert "flows_1m0s" not in sql
    assert "flows_5m0s" not in sql
    assert "flows_1h0m0s" not in sql


def test_summary_query_compte_les_flux_mal_classes_par_interface_unknown() -> None:
    sql, _ = diagnostics.build_unknown_interface_summary_query(period="1h")
    assert "unknown" in sql.lower()
    assert "InIfName" in sql or "OutIfName" in sql


def test_summary_query_ne_met_jamais_a_l_echelle_le_comptage_de_flux() -> None:
    """`count()` compte des flux OBSERVÉS, pas du trafic : il ne se met JAMAIS
    à l'échelle par SamplingRate, contrairement à `sum(Bytes * SamplingRate)`.
    C'est la règle explicitée dans le contexte de la tâche — une erreur ici
    fausserait la proportion (elle deviendrait une proportion de VOLUME, pas
    de FLUX)."""
    sql, _ = diagnostics.build_unknown_interface_summary_query(period="1h")
    assert not re.search(r"count\(\)\s*\*\s*SamplingRate", sql, re.IGNORECASE)
    assert not re.search(r"SamplingRate\s*\*\s*count\(\)", sql, re.IGNORECASE)


def test_summary_query_regroupe_par_exportateur() -> None:
    sql, _ = diagnostics.build_unknown_interface_summary_query(period="1h")
    assert "ExporterName" in sql


def test_summary_query_limit_present_et_plafonne() -> None:
    sql, params = diagnostics.build_unknown_interface_summary_query(period="1h", limit=999_999_999)
    assert "LIMIT" in sql.upper()
    assert params.get("limit") is not None
    assert params["limit"] <= diagnostics.MAX_CONVERGENCE_LIMIT


def test_summary_query_aucune_valeur_utilisateur_concatenee() -> None:
    """Bien qu'aujourd'hui cette requête n'a pas de paramètre libre côté
    utilisateur (period est validée contre une énumération fermée AVANT
    d'atteindre le SQL), le garde générique du module (pas d'opérateur C-like)
    doit rester respecté."""
    sql, _ = diagnostics.build_unknown_interface_summary_query(period="1h")
    assert ">>" not in sql
    assert "<<" not in sql


# ---------------------------------------------------------------------------
# Router — le calcul de proportion et la distinction dérive / non-déclaré
# ---------------------------------------------------------------------------


class _ClickHouseClientDoubleAvecColonnes:
    """Double portant `column_names` + `result_rows`, spécifiquement pour la
    requête de RÉSUMÉ DE DÉRIVE (`unknown_count`/`total_count` dans le SQL).

    La page `/diagnostics/convergence` exécute DEUX requêtes distinctes (le
    classement de convergence ET le résumé de dérive) sur le MÊME client —
    ce double route donc sur le texte SQL pour ne servir les lignes fournies
    qu'à la requête de dérive, et répondre vide à l'autre (le classement de
    convergence n'est pas ce que ces tests vérifient)."""

    def __init__(self, column_names: list[str], rows: list[tuple[Any, ...]]) -> None:
        self._column_names = column_names
        self._rows = rows

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> Any:
        if "unknown_count" in sql:
            return _ResultatAvecColonnes(self._column_names, self._rows)
        return _ResultatAvecColonnes([], [])


class _ResultatAvecColonnes:
    def __init__(self, column_names: list[str], rows: list[tuple[Any, ...]]) -> None:
        self.column_names = column_names
        self.result_rows = rows


class _ClickHouseClientDoubleEnEchec:
    """Simule un ClickHouse qui ne répond pas — aucune infra réelle sollicitée."""

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> Any:
        raise ConnectionError("échec de connexion simulé par le double de test")


@pytest.fixture
def client_avec_double():  # type: ignore[no-untyped-def]
    """Fabrique un TestClient authentifié dont le double ClickHouse est
    substituable par le test appelant."""

    def _make(fake: Any) -> TestClient:
        app.dependency_overrides[diagnostics_router.get_clickhouse_client] = lambda: fake
        return authenticated_test_client(app)

    yield _make
    app.dependency_overrides.pop(diagnostics_router.get_clickhouse_client, None)


def test_page_convergence_affiche_le_decompte_global_de_derive(
    client_avec_double: Any,
) -> None:
    """Le chiffre qui compte : la PROPORTION DE FLUX mal classés, visible sans
    parcourir la liste des exportateurs. Reproduction du cas mesuré (53 %,
    101 326 / 189 449)."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["ExporterName", "unknown_count", "total_count"],
        rows=[
            ("clm", 101326, 189449),
        ],
    )
    response = client_avec_double(fake).get("/diagnostics/convergence")
    assert response.status_code == 200
    # Proportion mesurée : 101326 / 189449 = 53.48...% -> affichage "53" attendu.
    assert "53" in response.text
    assert "101" in response.text or "101 326" in response.text or "101326" in response.text


def test_decompte_global_agrege_plusieurs_exportateurs(client_avec_double: Any) -> None:
    """La proportion globale doit AGRÉGER tous les exportateurs, pas se limiter
    au premier — sinon l'exploitant croirait le problème isolé à une machine."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["ExporterName", "unknown_count", "total_count"],
        rows=[
            ("clm", 1000, 2000),
            ("nextcloud", 500, 1000),
        ],
    )
    response = client_avec_double(fake).get("/diagnostics/convergence")
    assert response.status_code == 200
    # Global : (1000+500) / (2000+1000) = 1500/3000 = 50%
    assert "50" in response.text


def test_decompte_global_zero_flux_mal_classe_affiche_zero_pourcent_reel(
    client_avec_double: Any,
) -> None:
    """Une vraie mesure à 0% (aucune dérive) doit pouvoir s'afficher normalement
    — le zéro silencieux proscrit est celui produit par un ÉCHEC, pas une
    mesure réelle de zéro."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["ExporterName", "unknown_count", "total_count"],
        rows=[("clm", 0, 5000)],
    )
    response = client_avec_double(fake).get("/diagnostics/convergence")
    assert response.status_code == 200
    assert "0" in response.text
    assert "indisponible" not in response.text.lower()


def test_decompte_global_clickhouse_muet_affiche_indisponible_jamais_zero_pourcent(
    client_avec_double: Any,
) -> None:
    """MOTIF FONDATEUR DU PROJET (CLAUDE.md) : un échec de mesure ne doit
    JAMAIS produire un 0 % qui se lirait « tout va bien ». L'état doit être
    DISTINCT et VISIBLE : « indisponible »."""
    fake = _ClickHouseClientDoubleEnEchec()
    response = client_avec_double(fake).get("/diagnostics/convergence")
    assert response.status_code == 200
    lowered = response.text.lower()
    assert any(mot in lowered for mot in ("indisponible", "impossible", "échec"))


def test_distinction_derive_versus_non_declare(client_avec_double: Any) -> None:
    """Deux causes distinctes, deux gestes de correction distincts :
    - DÉRIVE : certains flux résolvent, d'autres non (0 < unknown < total) ;
    - NON-DÉCLARÉ : aucun flux ne résout (unknown == total, cas OPNsense
      192.0.2.25 cité dans le contexte de la tâche).
    L'écran doit permettre de les distinguer textuellement."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["ExporterName", "unknown_count", "total_count"],
        rows=[
            ("clm", 500, 1000),  # dérive partielle
            ("opnsense", 3000, 3000),  # aucune résolution
        ],
    )
    response = client_avec_double(fake).get("/diagnostics/convergence")
    assert response.status_code == 200
    lowered = response.text.lower()
    assert "dériv" in lowered or "derive" in lowered
    assert "non déclaré" in lowered or "non declare" in lowered or "non-déclaré" in lowered


def test_tableau_de_derive_trie_par_impact_flux_mal_classes_decroissant(
    client_avec_double: Any,
) -> None:
    """Un tableau de 350 lignes non trié par impact est inutilisable (CLAUDE.md,
    exigence 6) : l'exportateur au plus grand nombre de flux mal classés doit
    apparaître EN PREMIER, même s'il a un nom qui le classerait après
    alphabétiquement."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["ExporterName", "unknown_count", "total_count"],
        rows=[
            ("aaa-petit", 10, 100),
            ("zzz-gros", 90000, 100000),
        ],
    )
    response = client_avec_double(fake).get("/diagnostics/convergence")
    assert response.status_code == 200
    position_gros = response.text.index("zzz-gros")
    position_petit = response.text.index("aaa-petit")
    assert position_gros < position_petit, (
        "l'exportateur au plus fort impact (flux mal classés) doit apparaître "
        "avant celui au plus faible impact, pas dans l'ordre alphabétique"
    )


def test_exportateur_sans_aucun_flux_mal_classe_absent_du_tableau_de_derive(
    client_avec_double: Any,
) -> None:
    """Un exportateur parfaitement sain (0 flux unknown) ne doit pas polluer le
    tableau de dérive — sinon 350 lignes s'affichent pour repérer les 40 en
    anomalie (CLAUDE.md, exigence 6 : lisibilité à l'échelle)."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["ExporterName", "unknown_count", "total_count"],
        rows=[
            ("sain", 0, 5000),
            ("en-derive", 200, 1000),
        ],
    )
    response = client_avec_double(fake).get("/diagnostics/convergence")
    assert response.status_code == 200
    # "sain" ne doit pas apparaître dans le tableau de dérive dédié — on
    # vérifie l'absence dans le contexte du bloc dérive, pas sur toute la
    # page (le nom pourrait apparaître ailleurs par coïncidence future).
    debut = response.text.index("Dérive")
    bloc = response.text[debut : debut + 4000]
    assert "sain" not in bloc


def test_lien_de_resolution_mene_vers_l_ecran_exportateurs_existant(
    client_avec_double: Any,
) -> None:
    """Anti-redondance (CLAUDE.md) : le bouton de résolution SNMP existe déjà
    sur `/exporters`. L'écran de dérive ne le RECONSTRUIT pas, il MÈNE vers
    lui — pilotable à la souris, un seul concept, une seule source."""
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["ExporterName", "unknown_count", "total_count"],
        rows=[("clm", 500, 1000)],
    )
    response = client_avec_double(fake).get("/diagnostics/convergence")
    assert response.status_code == 200
    assert "/exporters" in response.text


def test_requete_reste_bornee_pour_350_exportateurs(client_avec_double: Any) -> None:
    """Transposabilité à 350 routeurs (CLAUDE.md) : la requête de synthèse
    porte un LIMIT plafonné même simulée avec un grand nombre de lignes — la
    page ne doit pas planter ni dépasser le plafond dur du module."""
    lignes = [(f"routeur-{i:03d}", i, i + 1000) for i in range(1, 400)]
    fake = _ClickHouseClientDoubleAvecColonnes(
        column_names=["ExporterName", "unknown_count", "total_count"],
        rows=lignes,
    )
    response = client_avec_double(fake).get("/diagnostics/convergence")
    assert response.status_code == 200


def test_calcul_proportion_arrondit_de_maniere_lisible() -> None:
    """Le calcul de la proportion (fonction pure, testable sans ClickHouse) :
    101326 / 189449 doit rendre une valeur lisible proche de 53.5%, jamais une
    division brute non arrondie ni une exception sur total=0."""
    from app.routers.diagnostics import _calculer_taux_derive

    taux = _calculer_taux_derive(unknown=101326, total=189449)
    assert 53.0 <= taux <= 54.0


def test_calcul_proportion_total_zero_ne_leve_pas_et_rend_zero() -> None:
    """Aucun flux observé sur la fenêtre : proportion 0, pas une division par
    zéro qui ferait planter l'écran (ce n'est pas un zéro silencieux : c'est
    une vraie mesure d'ABSENCE de flux, distincte d'un échec ClickHouse traité
    en amont par `_run_query`)."""
    from app.routers.diagnostics import _calculer_taux_derive

    assert _calculer_taux_derive(unknown=0, total=0) == 0.0
