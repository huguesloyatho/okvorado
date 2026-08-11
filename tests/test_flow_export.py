"""Garde-fous de l'écran « Export de flux » — outil de QUALIFICATION d'équipement.

À QUOI CET ÉCRAN SERT (demande utilisateur 2026-08-11) : « quand je serai en
qualif, je voudrai exporter des flux avec les données des palo et des routeurs
SFR à te donner en exemple pour affiner l'intégration auto des bonnes interfaces
+ ajuster les dashboards ».

Ce n'est PAS un export de reporting. C'est un prélèvement d'échantillon destiné à
être TRANSMIS pour analyse. D'où trois exigences que ces tests verrouillent :

1. **Isoler UN équipement.** Un dump global noyé ne dit rien de ce que le Palo
   remplit. Le filtre par exportateur doit être discriminant — piège mesuré sur
   ce projet (« filtre juste mais non discriminant », cf. CLAUDE.md).

2. **Montrer les champs VIDES autant que les remplis.** C'est précisément
   l'information qui manque pour affiner l'intégration : savoir que le Palo ne
   renseigne PAS `SrcNetMask` vaut autant que de savoir qu'il renseigne `SrcAS`.

3. **Fichier AUTO-PORTANT.** Celui qui reçoit le fichier doit pouvoir dire quel
   équipement, quelle période, quels champs remplis, sans poser de question.

S'y ajoutent les gardes dures du projet : requête paramétrée exclusivement,
période en énumération fermée, LIMIT plafonné, et zéro silencieux (ClickHouse
muet ≠ export vide).
"""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services.flow_export import (
    EXPORT_FORMATS,
    MAX_EXPORT_LIMIT,
    ExportMetadata,
    FlowExport,
    FlowExportUnavailableError,
    build_export,
    build_flow_export_query,
    render_csv,
    render_json,
)

# ---------------------------------------------------------------------------
# Doubles de test
# ---------------------------------------------------------------------------

_SCHEMA_ROWS: list[tuple[str, str]] = [
    ("TimeReceived", "DateTime"),
    ("ExporterAddress", "IPv6"),
    ("ExporterName", "String"),
    ("SrcAddr", "IPv6"),
    ("DstAddr", "IPv6"),
    ("SrcNetMask", "UInt8"),
    ("SrcAS", "UInt32"),
    ("InIfName", "String"),
    ("Bytes", "UInt64"),
    ("SamplingRate", "UInt64"),
]


class _FakeResult:
    def __init__(self, rows: list[tuple[Any, ...]], column_names: list[str]) -> None:
        self.result_rows = rows
        self.column_names = column_names


class FakeClickHouseClient:
    """Double routé par sous-chaîne du SQL — convention des tests du projet.

    Enregistre CHAQUE (sql, parameters) pour que les tests puissent asserter
    qu'aucune valeur utilisateur n'a été interpolée dans le texte de la requête.
    """

    def __init__(
        self,
        *,
        schema: list[tuple[str, str]] | None = None,
        flow_rows: list[tuple[Any, ...]] | None = None,
        exporters: list[tuple[Any, ...]] | None = None,
        fill_total: int = 3,
        fill_counts: dict[str, int] | None = None,
    ) -> None:
        self.schema = schema if schema is not None else _SCHEMA_ROWS
        self.flow_rows = flow_rows if flow_rows is not None else []
        # Forme RÉELLE de `_EXPORTERS_SQL` : 4 colonnes. Un double à 2 colonnes
        # aurait rendu le test vert sur un service cassé en prod — c'est
        # exactement la famille de défauts « SQL invalide accepté par les
        # doubles de test » recensée dans CLAUDE.md.
        self.exporters = (
            exporters
            if exporters is not None
            else [
                ("::ffff:192.0.2.25", "opnsense", 1200, 4_500_000),
                ("::ffff:192.0.2.10", "proxy-frontal", 800, 2_100_000),
            ]
        )
        self.fill_total = fill_total
        self.fill_counts = fill_counts or {}
        self.queries: list[tuple[str, dict[str, Any]]] = []
        self.raise_on: set[str] = set()

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> Any:
        self.queries.append((sql, parameters or {}))
        for marker in self.raise_on:
            if marker in sql:
                raise RuntimeError(f"echec simule pour requete contenant {marker!r}")

        if "system.columns" in sql:
            return _FakeResult(list(self.schema), ["name", "type"])

        if "groupUniqArray" in sql or "GROUP BY ExporterAddress" in sql:
            return _FakeResult(
                list(self.exporters),
                ["exporter_address", "exporter_name", "flow_count", "byte_count"],
            )

        if "AS fill_" in sql:
            aliases = re.findall(r"AS fill_([A-Za-z0-9_]+)", sql)
            row: list[Any] = [self.fill_total]
            row.extend(self.fill_counts.get(name, 0) for name in aliases)
            return _FakeResult([tuple(row)], ["total", *[f"fill_{n}" for n in aliases]])

        # Requête d'extraction des flux.
        names = [name for name, _type in self.schema]
        return _FakeResult(list(self.flow_rows), names)

    @property
    def sql_texts(self) -> list[str]:
        return [sql for sql, _params in self.queries]


def _flow_row(exporter_address: str = "::ffff:192.0.2.25") -> tuple[Any, ...]:
    """Une ligne de flux alignée sur `_SCHEMA_ROWS`."""
    return (
        "2026-08-11 10:00:00",
        exporter_address,
        "opnsense",
        "::ffff:10.0.0.1",
        "::ffff:10.0.0.2",
        24,
        3215,
        "igb0",
        1500,
        1,
    )


def _build_app(client: FakeClickHouseClient) -> FastAPI:
    """Monte le routeur seul, avec ses dépendances surchargées."""
    from app.routers import flow_export as flow_export_router

    app = FastAPI()
    app.include_router(flow_export_router.router)
    app.dependency_overrides[flow_export_router.get_clickhouse_client] = lambda: client
    return app


# ---------------------------------------------------------------------------
# GARDE SÉCU N°1 — aucune valeur utilisateur dans le texte SQL
# ---------------------------------------------------------------------------


class TestAucuneValeurUtilisateurDansLeSql:
    """La garde n°1 du projet : tout ce qui vient de l'écran transite en
    PARAMÈTRE lié, jamais concaténé dans la chaîne SQL."""

    def test_l_adresse_d_exportateur_n_apparait_pas_dans_le_sql(self) -> None:
        sql, parameters = build_flow_export_query(
            exporter_address="192.0.2.25", window="1h", limit=50
        )
        assert "192.0.2.25" not in sql, (
            "l'adresse saisie a été interpolée dans le texte SQL — c'est "
            "exactement le chemin d'injection que le projet interdit"
        )
        assert parameters["exporter_address"] == "192.0.2.25"

    def test_la_limite_et_la_fenetre_transitent_en_parametres(self) -> None:
        sql, parameters = build_flow_export_query(
            exporter_address="", window="6h", limit=42
        )
        assert "{window_seconds:UInt32}" in sql
        assert "{export_limit:UInt32}" in sql
        assert parameters["window_seconds"] == 21600
        assert parameters["export_limit"] == 42
        # Ni la fenêtre ni la limite ne sont écrites en clair.
        assert "21600" not in sql
        assert "42" not in sql

    def test_une_tentative_d_injection_reste_une_valeur_liee(self) -> None:
        """Le payload ne doit JAMAIS atteindre le texte de la requête."""
        payload = "1.2.3.4' OR 1=1 --"
        sql, parameters = build_flow_export_query(
            exporter_address=payload, window="1h", limit=10
        )
        assert "OR 1=1" not in sql
        assert parameters["exporter_address"] == payload

    def test_le_service_n_interpole_rien_a_l_execution(self) -> None:
        """Preuve de bout en bout : on inspecte le SQL RÉELLEMENT exécuté."""
        client = FakeClickHouseClient(flow_rows=[_flow_row()])
        build_export(
            client, exporter_address="192.0.2.25", window="1h", limit=10, fmt="json"
        )
        for sql in client.sql_texts:
            assert "192.0.2.25" not in sql


# ---------------------------------------------------------------------------
# Énumérations fermées et plafonds
# ---------------------------------------------------------------------------


class TestPeriodeEtLimiteBornees:
    def test_periode_hors_enumeration_refusee(self) -> None:
        with pytest.raises(ValueError):
            build_flow_export_query(exporter_address="", window="99h", limit=10)

    def test_periode_hors_enumeration_refusee_avant_tout_acces_reseau(self) -> None:
        client = FakeClickHouseClient()
        with pytest.raises(ValueError):
            build_export(client, exporter_address="", window="1 OR 1=1", limit=10, fmt="csv")
        assert client.queries == [], (
            "la fenêtre invalide a été refusée APRÈS avoir interrogé ClickHouse — "
            "elle doit l'être avant tout accès réseau"
        )

    def test_la_limite_est_plafonnee_dur(self) -> None:
        _sql, parameters = build_flow_export_query(
            exporter_address="", window="1h", limit=10_000_000
        )
        assert parameters["export_limit"] == MAX_EXPORT_LIMIT

    def test_une_limite_nulle_ou_negative_ne_produit_pas_un_limit_zero(self) -> None:
        """`LIMIT 0` rendrait un export vide indistinguable d'une fenêtre calme."""
        for demandee in (0, -5):
            _sql, parameters = build_flow_export_query(
                exporter_address="", window="1h", limit=demandee
            )
            assert parameters["export_limit"] >= 1

    def test_le_limit_est_toujours_present(self) -> None:
        sql, _parameters = build_flow_export_query(
            exporter_address="", window="7d", limit=100
        )
        assert "LIMIT" in sql.upper()

    def test_format_hors_enumeration_refuse(self) -> None:
        client = FakeClickHouseClient(flow_rows=[_flow_row()])
        with pytest.raises(ValueError):
            build_export(client, exporter_address="", window="1h", limit=10, fmt="xlsx")

    def test_les_formats_offerts_sont_csv_et_json(self) -> None:
        assert set(EXPORT_FORMATS) == {"csv", "json"}


# ---------------------------------------------------------------------------
# Isoler UN équipement — le cœur du besoin de qualification
# ---------------------------------------------------------------------------


class TestIsolationDUnEquipement:
    def test_le_filtre_par_exportateur_est_pose_dans_le_sql(self) -> None:
        sql, _parameters = build_flow_export_query(
            exporter_address="192.0.2.25", window="1h", limit=10
        )
        assert "ExporterAddress" in sql
        assert "{exporter_address:String}" in sql

    def test_sans_exportateur_aucun_filtre_d_exportateur_n_est_pose(self) -> None:
        """« Tous » doit rester « tous » — pas un filtre sur la chaîne vide,
        qui ne remonterait AUCUN flux (défaut « filtre non discriminant »)."""
        sql, parameters = build_flow_export_query(
            exporter_address="", window="1h", limit=10
        )
        assert "{exporter_address:String}" not in sql
        assert "exporter_address" not in parameters

    def test_l_export_d_un_exportateur_ne_contient_que_lui(self) -> None:
        """Le filtre doit être DISCRIMINANT, pas seulement présent."""
        client = FakeClickHouseClient(
            flow_rows=[_flow_row("::ffff:192.0.2.25"), _flow_row("::ffff:192.0.2.25")]
        )
        export = build_export(
            client, exporter_address="192.0.2.25", window="1h", limit=100, fmt="json"
        )
        adresses = {row["ExporterAddress"] for row in export.rows}
        assert adresses == {"192.0.2.25"}, (
            "l'export porte des flux d'un autre exportateur que celui demandé"
        )

    def test_le_filtre_mord_sur_un_double_qui_rendrait_tout(self) -> None:
        """PREUVE DE MORSURE : si le service ne filtrait pas, ce test échouerait.

        Le double rend ici des lignes de DEUX exportateurs (il ignore
        volontairement le paramètre). Le service doit donc lui-même écarter ce
        qui ne correspond pas — sinon l'écran mentirait sur le périmètre.
        """
        client = FakeClickHouseClient(
            flow_rows=[_flow_row("::ffff:192.0.2.25"), _flow_row("::ffff:192.0.2.10")]
        )
        export = build_export(
            client, exporter_address="192.0.2.25", window="1h", limit=100, fmt="json"
        )
        adresses = {row["ExporterAddress"] for row in export.rows}
        assert adresses == {"192.0.2.25"}

    def test_la_liste_des_exportateurs_vient_de_clickhouse(self) -> None:
        from app.services.flow_export import list_exportable_devices

        client = FakeClickHouseClient()
        devices = list_exportable_devices(client, window="24h")
        adresses = [device.address for device in devices]
        assert "192.0.2.25" in adresses
        assert "192.0.2.10" in adresses

    def test_les_adresses_proposees_sont_normalisees(self) -> None:
        """`::ffff:` ne doit jamais atteindre l'écran ni le fichier."""
        from app.services.flow_export import list_exportable_devices

        client = FakeClickHouseClient()
        devices = list_exportable_devices(client, window="24h")
        for device in devices:
            assert not device.address.startswith("::ffff:")


# ---------------------------------------------------------------------------
# Taux de remplissage — y compris les champs VIDES
# ---------------------------------------------------------------------------


class TestTypesRendusParLeVraiDriver:
    """DÉFAUT MESURÉ CONTRE UN VRAI CLICKHOUSE (2026-08-11, avant livraison).

    Le driver `clickhouse_connect` rend les colonnes IPv6 en objets
    `ipaddress.IPv6Address`, PAS en `str`. Les doubles de test rendaient des
    `str` — donc tous les tests passaient pendant que CHAQUE adresse du fichier
    transmis serait partie sous sa forme IPv6-mapped brute, illisible pour qui
    analyse.

    Ces tests reproduisent les types RÉELS du driver. Ils mordent : sans la
    branche `IPv4Address/IPv6Address` de `_normalize_value`, ils échouent.
    """

    def test_une_adresse_ipv6_mapped_du_driver_est_normalisee(self) -> None:
        from ipaddress import IPv6Address

        from app.services.flow_export import _normalize_value

        assert _normalize_value(IPv6Address("::ffff:192.0.2.25")) == "192.0.2.25"

    def test_l_export_normalise_les_adresses_objets(self) -> None:
        from ipaddress import IPv6Address

        ligne = list(_flow_row())
        # Types RÉELS du driver, pas des chaînes de confort.
        ligne[1] = IPv6Address("::ffff:192.0.2.25")
        ligne[3] = IPv6Address("::ffff:10.0.0.1")

        client = FakeClickHouseClient(flow_rows=[tuple(ligne)])
        export = build_export(
            client, exporter_address="192.0.2.25", window="1h", limit=10, fmt="json"
        )
        assert export.rows, "le tamis a écarté la ligne : l'adresse objet n'est pas reconnue"
        assert export.rows[0]["ExporterAddress"] == "192.0.2.25"
        assert export.rows[0]["SrcAddr"] == "10.0.0.1"

    def test_aucune_forme_ipv6_mapped_ne_sort_dans_le_fichier(self) -> None:
        from ipaddress import IPv6Address

        ligne = list(_flow_row())
        ligne[1] = IPv6Address("::ffff:192.0.2.25")
        ligne[3] = IPv6Address("::ffff:10.0.0.1")

        client = FakeClickHouseClient(flow_rows=[tuple(ligne)])
        export = build_export(
            client, exporter_address="192.0.2.25", window="1h", limit=10, fmt="csv"
        )
        assert "::ffff:" not in render_csv(export)
        assert "::ffff:" not in render_json(export)

    def test_une_date_du_driver_est_serialisable_en_json(self) -> None:
        """`datetime` natif : `json.dumps` échouerait sans normalisation."""
        from datetime import datetime as _dt

        ligne = list(_flow_row())
        ligne[0] = _dt(2026, 8, 11, 10, 0, 0)
        client = FakeClickHouseClient(flow_rows=[tuple(ligne)])
        export = build_export(
            client, exporter_address="192.0.2.25", window="1h", limit=10, fmt="json"
        )
        charge = json.loads(render_json(export))
        assert charge["flows"][0]["TimeReceived"].startswith("2026-08-11T10:00:00")


class TestTauxDeRemplissage:
    def test_les_champs_vides_sont_presents_avec_zero_pour_cent(self) -> None:
        """C'est l'information qui manque pour affiner l'intégration : savoir
        qu'un champ est VIDE chez cet équipement, pas seulement l'omettre."""
        client = FakeClickHouseClient(
            flow_rows=[_flow_row()],
            fill_total=10,
            fill_counts={"SrcAS": 10, "SrcNetMask": 0},
        )
        export = build_export(
            client, exporter_address="192.0.2.25", window="1h", limit=10, fmt="json"
        )
        taux = {f.name: f.fill_rate for f in export.fields}
        assert taux["SrcNetMask"] == 0.0, "un champ vide doit être listé, pas omis"
        assert taux["SrcAS"] == 100.0

    def test_le_remplissage_est_mesure_sur_l_exportateur_demande(self) -> None:
        """Un taux mesuré sur TOUT le parc ne dirait rien du Palo en particulier."""
        client = FakeClickHouseClient(flow_rows=[_flow_row()])
        build_export(
            client, exporter_address="192.0.2.25", window="1h", limit=10, fmt="json"
        )
        fill_queries = [
            (sql, params) for sql, params in client.queries if "AS fill_" in sql
        ]
        assert fill_queries, "aucune requête de remplissage n'a été émise"
        _sql, params = fill_queries[0]
        assert params.get("exporter_address") == "192.0.2.25"

    def test_le_remplissage_couvre_tout_le_schema(self) -> None:
        client = FakeClickHouseClient(flow_rows=[_flow_row()])
        export = build_export(
            client, exporter_address="", window="1h", limit=10, fmt="json"
        )
        noms = {f.name for f in export.fields}
        assert noms == {name for name, _type in _SCHEMA_ROWS}

    def test_l_origine_du_champ_vient_du_catalogue_existant(self) -> None:
        """UN concept = UNE source : l'origine n'est pas redéfinie ici."""
        from app.services.field_catalog import ORIGIN_LABELS

        client = FakeClickHouseClient(flow_rows=[_flow_row()])
        export = build_export(
            client, exporter_address="", window="1h", limit=10, fmt="json"
        )
        for champ in export.fields:
            assert champ.origin in ORIGIN_LABELS


# ---------------------------------------------------------------------------
# En-tête de métadonnées — le fichier doit être AUTO-PORTANT
# ---------------------------------------------------------------------------


class TestEnTeteDeMetadonnees:
    """Celui qui reçoit le fichier doit pouvoir dire quel équipement, quelle
    période, quels champs remplis — sans poser de question."""

    def _export(self) -> FlowExport:
        client = FakeClickHouseClient(
            flow_rows=[_flow_row()], fill_total=10, fill_counts={"SrcAS": 5}
        )
        return build_export(
            client, exporter_address="192.0.2.25", window="1h", limit=10, fmt="json"
        )

    def test_les_metadonnees_portent_l_equipement_la_periode_et_le_compte(self) -> None:
        meta = self._export().metadata
        assert isinstance(meta, ExportMetadata)
        assert meta.exporter_address == "192.0.2.25"
        assert meta.window == "1h"
        assert meta.flow_count == 1
        assert meta.schema_version
        assert meta.generated_at

    def test_le_json_porte_l_en_tete_et_les_taux_de_remplissage(self) -> None:
        export = self._export()
        charge = json.loads(render_json(export))
        assert "metadata" in charge
        assert charge["metadata"]["exporter_address"] == "192.0.2.25"
        assert charge["metadata"]["window"] == "1h"
        assert charge["metadata"]["flow_count"] == 1
        assert "fields" in charge
        noms = {champ["name"] for champ in charge["fields"]}
        assert "SrcNetMask" in noms
        assert all("fill_rate" in champ for champ in charge["fields"])
        assert "flows" in charge

    def test_le_csv_porte_l_en_tete_en_commentaires(self) -> None:
        export = self._export()
        texte = render_csv(export)
        assert texte.startswith("#"), (
            "le CSV doit s'ouvrir sur son en-tête de métadonnées, sinon le "
            "fichier reçu ne dit pas de quel équipement il parle"
        )
        assert "192.0.2.25" in texte
        assert "1h" in texte

    def test_le_csv_reste_lisible_par_un_tableur(self) -> None:
        """Les commentaires ne doivent pas casser la lecture des colonnes."""
        export = self._export()
        lignes = [
            ligne
            for ligne in render_csv(export).splitlines()
            if ligne and not ligne.startswith("#")
        ]
        lecteur = csv.reader(io.StringIO("\n".join(lignes)), delimiter=";")
        entetes = next(lecteur)
        assert "ExporterAddress" in entetes
        assert "SrcNetMask" in entetes

    def test_le_csv_porte_les_taux_de_remplissage(self) -> None:
        texte = render_csv(self._export())
        assert "SrcNetMask" in texte
        assert "remplissage" in texte.lower()

    def test_l_en_tete_nomme_l_export_global_sans_ambiguite(self) -> None:
        """« Tous » doit être écrit, jamais une case vide qu'on interpréterait."""
        client = FakeClickHouseClient(flow_rows=[_flow_row()])
        export = build_export(
            client, exporter_address="", window="24h", limit=10, fmt="csv"
        )
        assert export.metadata.exporter_address == ""
        assert "tous" in render_csv(export).lower()


# ---------------------------------------------------------------------------
# ZÉRO SILENCIEUX — les trois états doivent rester DISTINCTS
# ---------------------------------------------------------------------------


class TestZeroSilencieux:
    def test_clickhouse_muet_leve_une_erreur_distincte(self) -> None:
        client = FakeClickHouseClient()
        client.raise_on = {"FROM default.flows"}
        with pytest.raises(FlowExportUnavailableError):
            build_export(client, exporter_address="", window="1h", limit=10, fmt="json")

    def test_schema_illisible_leve_une_erreur_distincte(self) -> None:
        client = FakeClickHouseClient()
        client.raise_on = {"system.columns"}
        with pytest.raises(FlowExportUnavailableError):
            build_export(client, exporter_address="", window="1h", limit=10, fmt="json")

    def test_un_export_vide_le_dit_explicitement(self) -> None:
        """0 flux est une MESURE — mais elle doit être ÉNONCÉE, pas devinée
        d'un fichier sans lignes."""
        client = FakeClickHouseClient(flow_rows=[])
        export = build_export(
            client, exporter_address="192.0.2.25", window="1h", limit=10, fmt="json"
        )
        assert export.is_empty is True
        assert export.metadata.flow_count == 0

        charge = json.loads(render_json(export))
        assert charge["metadata"]["flow_count"] == 0
        assert charge["metadata"]["empty"] is True
        assert charge["metadata"]["empty_reason"]

        texte = render_csv(export)
        assert "aucun flux" in texte.lower()

    def test_un_export_vide_n_est_pas_confondu_avec_une_panne(self) -> None:
        client = FakeClickHouseClient(flow_rows=[])
        export = build_export(
            client, exporter_address="", window="1h", limit=10, fmt="json"
        )
        assert export.is_empty is True
        assert export.fields, (
            "même sans flux, le schéma des champs doit rester affiché — sinon "
            "une fenêtre calme se confond avec un schéma vide"
        )

    def test_remplissage_non_mesurable_ne_rend_pas_zero_pour_cent(self) -> None:
        """0 % signifie « champ mesuré vide », l'exact contraire d'une mesure
        manquante — les confondre est le défaut fondateur du projet."""
        client = FakeClickHouseClient(flow_rows=[_flow_row()], fill_total=0)
        export = build_export(
            client, exporter_address="", window="1h", limit=10, fmt="json"
        )
        assert export.fill_rates_available is False
        for champ in export.fields:
            assert champ.fill_rate is None

        charge = json.loads(render_json(export))
        assert charge["metadata"]["fill_rates_available"] is False


# ---------------------------------------------------------------------------
# SamplingRate — l'erreur invisible au homelab
# ---------------------------------------------------------------------------


class TestSamplingRate:
    def test_tout_volume_agrege_est_mis_a_l_echelle(self) -> None:
        """`sum(Bytes)` seul vaudrait un facteur 1000 en entreprise."""
        sqls = [
            build_flow_export_query(exporter_address="", window="1h", limit=10)[0],
        ]
        from app.services.flow_export import build_exporters_query

        sqls.append(build_exporters_query(window="24h")[0])
        for sql in sqls:
            if "sum(Bytes" in sql:
                assert "sum(Bytes * SamplingRate)" in sql, (
                    "somme de volume sans SamplingRate — erreur invisible au "
                    "homelab (échantillonnage 1:1), facteur 1000 en entreprise"
                )

    def test_count_n_est_jamais_mis_a_l_echelle(self) -> None:
        sql, _p = build_flow_export_query(exporter_address="", window="1h", limit=10)
        assert "count() * SamplingRate" not in sql


# ---------------------------------------------------------------------------
# L'ÉCRAN — routes, aperçu, téléchargement
# ---------------------------------------------------------------------------


class TestEcranExportDeFlux:
    def test_la_page_repond(self) -> None:
        client = FakeClickHouseClient(flow_rows=[_flow_row()])
        with TestClient(_build_app(client)) as http:
            reponse = http.get("/flow-export")
        assert reponse.status_code == 200

    def test_la_page_propose_les_exportateurs_reellement_presents(self) -> None:
        client = FakeClickHouseClient(flow_rows=[_flow_row()])
        with TestClient(_build_app(client)) as http:
            corps = http.get("/flow-export").text
        assert "192.0.2.25" in corps
        assert "192.0.2.10" in corps

    def test_l_apercu_montre_le_taux_de_remplissage(self) -> None:
        client = FakeClickHouseClient(
            flow_rows=[_flow_row()], fill_total=10, fill_counts={"SrcAS": 10}
        )
        with TestClient(_build_app(client)) as http:
            reponse = http.get(
                "/flow-export/preview",
                params={"exporter": "192.0.2.25", "window": "1h", "limit": "10"},
            )
        assert reponse.status_code == 200
        assert "SrcNetMask" in reponse.text

    def test_l_apercu_refuse_une_periode_hors_enumeration(self) -> None:
        client = FakeClickHouseClient(flow_rows=[_flow_row()])
        with TestClient(_build_app(client)) as http:
            reponse = http.get(
                "/flow-export/preview",
                params={"exporter": "", "window": "99h", "limit": "10"},
            )
        assert reponse.status_code == 400

    def test_le_telechargement_csv_porte_un_nom_de_fichier(self) -> None:
        client = FakeClickHouseClient(flow_rows=[_flow_row()])
        with TestClient(_build_app(client)) as http:
            reponse = http.get(
                "/flow-export/download",
                params={
                    "exporter": "192.0.2.25",
                    "window": "1h",
                    "limit": "10",
                    "fmt": "csv",
                },
            )
        assert reponse.status_code == 200
        assert "attachment" in reponse.headers["content-disposition"]
        assert reponse.text.startswith("#")

    def test_le_telechargement_json_est_du_json_valide(self) -> None:
        client = FakeClickHouseClient(flow_rows=[_flow_row()])
        with TestClient(_build_app(client)) as http:
            reponse = http.get(
                "/flow-export/download",
                params={
                    "exporter": "192.0.2.25",
                    "window": "1h",
                    "limit": "10",
                    "fmt": "json",
                },
            )
        assert reponse.status_code == 200
        charge = json.loads(reponse.text)
        assert charge["metadata"]["exporter_address"] == "192.0.2.25"

    def test_le_telechargement_refuse_un_format_inconnu(self) -> None:
        client = FakeClickHouseClient(flow_rows=[_flow_row()])
        with TestClient(_build_app(client)) as http:
            reponse = http.get(
                "/flow-export/download",
                params={"exporter": "", "window": "1h", "limit": "10", "fmt": "xlsx"},
            )
        assert reponse.status_code == 400

    def test_clickhouse_muet_affiche_indisponible_et_non_un_tableau_vide(self) -> None:
        client = FakeClickHouseClient()
        client.raise_on = {"system.columns"}
        with TestClient(_build_app(client)) as http:
            reponse = http.get("/flow-export")
        assert reponse.status_code == 200
        assert "indisponible" in reponse.text.lower()

    def test_un_apercu_vide_le_dit_a_l_ecran(self) -> None:
        client = FakeClickHouseClient(flow_rows=[])
        with TestClient(_build_app(client)) as http:
            reponse = http.get(
                "/flow-export/preview",
                params={"exporter": "192.0.2.25", "window": "1h", "limit": "10"},
            )
        assert "aucun flux" in reponse.text.lower()


# ---------------------------------------------------------------------------
# Navigation, CSP et pièges HTMX du projet
# ---------------------------------------------------------------------------


class TestNavigationEtGardesHtmx:
    _BASE = Path(__file__).resolve().parent.parent / "app" / "templates" / "base.html"
    _TEMPLATE = (
        Path(__file__).resolve().parent.parent / "app" / "templates" / "flow_export.html"
    )
    _FRAGMENT = (
        Path(__file__).resolve().parent.parent
        / "app"
        / "templates"
        / "_flow_export_preview.html"
    )

    def test_l_onglet_est_dans_la_navigation(self) -> None:
        """Une page sans lien de menu n'existe pas pour qui l'utilise
        (défaut vécu 2026-08-06)."""
        source = self._BASE.read_text(encoding="utf-8")
        assert "/flow-export" in source
        assert "flow_export" in source

    def test_les_sections_d_action_portent_hx_select_unset(self) -> None:
        """PIÈGE MESURÉ 3 FOIS : `hx-select` est HÉRITÉ."""
        source = self._TEMPLATE.read_text(encoding="utf-8")
        assert 'hx-select="unset"' in source

    def test_aucun_gestionnaire_inline(self) -> None:
        """CSP `script-src 'self'` sans `unsafe-inline`."""
        source = self._TEMPLATE.read_text(encoding="utf-8") + self._FRAGMENT.read_text(
            encoding="utf-8"
        )
        assert "onclick=" not in source
        assert "onchange=" not in source
        assert "onsubmit=" not in source
        assert "<script>" not in source
        assert "javascript:" not in source

    def test_aucune_condition_htmx_evaluee_en_js(self) -> None:
        """`every Ns [ ... ]` lève un `EvalError` sous CSP stricte."""
        source = self._TEMPLATE.read_text(encoding="utf-8") + self._FRAGMENT.read_text(
            encoding="utf-8"
        )
        assert not re.search(r"hx-trigger=\"[^\"]*every[^\"]*\[", source)

    def test_la_selection_se_fait_a_la_souris(self) -> None:
        """Pas de saisie libre d'exportateur : une liste des équipements
        réellement présents (l'utilisateur ne doit jamais taper une adresse)."""
        source = self._TEMPLATE.read_text(encoding="utf-8")
        assert "<select" in source
        assert 'name="exporter"' in source
