"""Catalogue des champs de flux — ce que le stack expose vs ce qu'on en exploite.

POURQUOI CET ÉCRAN EXISTE (demande utilisateur 2026-08-11) : c'est un outil de
NÉGOCIATION, pas une documentation. Il doit répondre à l'objection « vos
dashboards sont légers » en montrant que la majorité du potentiel NetFlow est
inexploitée, et permettre de désigner à l'écran les champs à ajouter.

CE QUE CES TESTS PROTÈGENT, dans l'ordre d'importance commerciale :

1. **Aucun chiffre figé.** Le ratio « N exploités sur M » se recalcule à chaque
   affichage depuis le schéma ClickHouse réel et depuis les dashboards présents
   sur le disque. Un compte écrit en dur deviendrait faux le jour où le client
   active la géolocalisation ou le BGP — et c'est exactement l'évolution que
   l'écran doit rendre visible. Cf. `TestLeRatioEstCalculeJamaisFige`.

2. **Aucun faux positif de détection.** Annoncer « ce champ est déjà exploité »
   à tort décrédibiliserait toute la démonstration. La détection se fait à la
   frontière de mot : `SrcAddr` ne doit jamais matcher `SrcAddrX`, et un nom
   cité dans une `description` de panneau (prose, pas SQL) ne compte pas.
   Cf. `TestDetectionDesChampsUtilises`.

3. **Aucun contresens sur l'ORIGINE de la donnée.** Correction de cadrage de
   l'utilisateur (2026-08-11) : « attention quand même ça doit se baser sur les
   sources cibles. Là sur mon infra il n'y a pas de firewall donc des infos
   comme le routage et j'en passe ne seront pas visibles ».

   Les 11 exportateurs de cette maquette sont TOUS des serveurs Linux sous
   softflowd (confirmé par `README.md`, qui documente déjà que softflowd 1.1.0
   ne renseigne même pas les interfaces). Aucun routeur, aucun pare-feu. Un
   champ vide ICI peut donc être parfaitement rempli CHEZ LE CLIENT.

   La bonne question n'est pas « le champ est-il rempli ? » mais « QUELLE
   SOURCE le remplit ? ». Confondre les deux présenterait comme une limite du
   PRODUIT ce qui n'est qu'une limite de la MAQUETTE — le contresens commercial
   le plus coûteux de cette présentation. D'où un classement par ORIGINE :
   protocole / équipement réseau / enrichissement collecteur.
   Cf. `TestClassementParOrigineDeLaDonnee`.

4. **Zéro silencieux.** ClickHouse muet ou dossier de dashboards absent doivent
   produire un état DISTINCT et visible, jamais un catalogue vide ni « 0 % »
   partout — 0 % signifie « champ vide », l'exact contraire d'une mesure
   manquante. Cf. `TestZeroSilencieux`.
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

from app.services import field_catalog
from app.services.field_catalog import (
    CATEGORY_APPLICATION,
    CATEGORY_ROUTING,
    ORIGIN_COLLECTOR_ENRICHMENT,
    ORIGIN_LABELS,
    ORIGIN_NETWORK_EQUIPMENT,
    ORIGIN_PROTOCOL,
    build_catalog,
    build_fill_rate_query,
    columns_used_by_dashboards,
    export_catalog_csv,
    read_dashboard_usage,
    read_flow_columns,
)

# ---------------------------------------------------------------------------
# Doubles de test
# ---------------------------------------------------------------------------


class _Result:
    """Imite le `QueryResult` du driver ClickHouse (attributs lus par le code)."""

    def __init__(self, rows: list[tuple[Any, ...]], column_names: list[str] | None = None) -> None:
        self.result_rows = rows
        self.column_names = column_names or []


class FakeClickHouseClient:
    """Double routé par sous-chaîne du SQL — même convention que
    `tests/test_db_health.py::FakeClickHouseClient`.

    `raise_on` permet de simuler une panne PARTIELLE (le schéma répond, le
    remplissage échoue), qui est le cas le plus piégeux : c'est là qu'un
    « 0 % » silencieux pourrait s'afficher à la place d'une absence de mesure.
    """

    def __init__(
        self,
        columns: list[tuple[str, str]] | None = None,
        fill_counts: dict[str, int] | None = None,
        total_flows: int = 1000,
    ) -> None:
        self.columns = columns if columns is not None else _DEFAULT_COLUMNS
        self.fill_counts = fill_counts or {}
        self.total_flows = total_flows
        self.queries: list[tuple[str, dict[str, Any] | None]] = []
        self.raise_on: set[str] = set()

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> _Result:
        self.queries.append((sql, parameters))
        for marker in self.raise_on:
            if marker in sql:
                raise RuntimeError(f"echec simule pour requete contenant {marker!r}")

        if "system.columns" in sql:
            return _Result(list(self.columns), ["name", "type"])

        if "countIf" in sql or "count()" in sql:
            # Une seule ligne agrégée : total, puis un compteur par colonne dans
            # l'ordre des alias demandés par le service.
            names = field_catalog._fill_rate_aliases(sql)
            row: list[Any] = [self.total_flows]
            row.extend(self.fill_counts.get(name, 0) for name in names)
            return _Result([tuple(row)], ["total", *names])

        return _Result([], [])


_DEFAULT_COLUMNS: list[tuple[str, str]] = [
    ("TimeReceived", "DateTime"),
    ("SamplingRate", "UInt64"),
    ("ExporterName", "LowCardinality(String)"),
    ("SrcAddr", "IPv6"),
    ("DstAddr", "IPv6"),
    ("Bytes", "UInt64"),
    ("Packets", "UInt64"),
    ("DstCountry", "FixedString(2)"),
    ("SrcNetRole", "LowCardinality(String)"),
    ("DstASPath", "Array(UInt32)"),
    ("InIfBoundary", "Enum8"),
    ("IPTos", "UInt8"),
]


def _write_dashboard(directory: Path, name: str, title: str, sqls: list[str]) -> None:
    """Écrit un dashboard Grafana minimal mais RÉALISTE.

    Les requêtes vivent sous `panels[].targets[].rawSql`, exactement comme dans
    `stack/grafana/dashboards/` : un double trop simplifié (une clé `sql` à la
    racine) validerait un parseur incapable de lire les vrais fichiers — c'est
    la famille de défaut « SQL invalide accepté par les doubles de test »
    documentée dans le CLAUDE.md du projet.
    """
    payload = {
        "title": title,
        "panels": [
            {
                "title": f"panneau {index}",
                "targets": [{"rawSql": sql}],
            }
            for index, sql in enumerate(sqls)
        ],
    }
    (directory / name).write_text(json.dumps(payload), encoding="utf-8")


@pytest.fixture
def dashboards_dir(tmp_path: Path) -> Path:
    """Deux dashboards couvrant les cas de détection qui comptent."""
    directory = tmp_path / "dashboards"
    directory.mkdir()
    _write_dashboard(
        directory,
        "00-trafic.json",
        "Okvorado — Traffic Summary",
        [
            "SELECT sum(Bytes * SamplingRate) AS volume FROM flows "
            "WHERE $__timeFilter(TimeReceived) GROUP BY ExporterName",
        ],
    )
    _write_dashboard(
        directory,
        "01-exportateur.json",
        "Okvorado — Par exportateur",
        [
            "SELECT SrcAddr, DstAddr, count() FROM flows GROUP BY SrcAddr, DstAddr",
        ],
    )
    return directory


# ---------------------------------------------------------------------------
# 1. Détection des champs utilisés — le socle de l'argument
# ---------------------------------------------------------------------------


class TestDetectionDesChampsUtilises:
    def test_un_champ_cite_dans_le_sql_est_detecte(self, dashboards_dir: Path) -> None:
        usage = read_dashboard_usage(dashboards_dir)

        assert "Bytes" in usage.columns_by_name
        assert usage.columns_by_name["Bytes"] == ["Okvorado — Traffic Summary"]

    def test_un_champ_absent_n_est_pas_detecte(self, dashboards_dir: Path) -> None:
        usage = read_dashboard_usage(dashboards_dir)

        assert "DstASPath" not in usage.columns_by_name

    def test_le_meme_champ_dans_deux_dashboards_les_liste_tous(self, tmp_path: Path) -> None:
        directory = tmp_path / "d"
        directory.mkdir()
        _write_dashboard(directory, "a.json", "Dashboard A", ["SELECT Bytes FROM flows"])
        _write_dashboard(directory, "b.json", "Dashboard B", ["SELECT Bytes FROM flows"])

        usage = read_dashboard_usage(directory)

        assert usage.columns_by_name["Bytes"] == ["Dashboard A", "Dashboard B"]

    @pytest.mark.parametrize(
        ("sql", "attendu"),
        [
            # Le piège nommé dans le brief : `Bytes` est un préfixe/sous-chaîne
            # possible d'autres identifiants. Une détection par simple `in`
            # marquerait `Bytes` exploité alors que seul `BytesTotal` est cité.
            ("SELECT BytesTotal FROM flows", False),
            ("SELECT MyBytes FROM flows", False),
            ("SELECT sum(Bytes) FROM flows", True),
            ("SELECT Bytes*SamplingRate FROM flows", True),
            ("SELECT t.Bytes FROM flows AS t", True),
            ("SELECT Bytes AS volume FROM flows", True),
        ],
    )
    def test_la_detection_respecte_la_frontiere_de_mot(
        self, tmp_path: Path, sql: str, attendu: bool
    ) -> None:
        """Une détection par sous-chaîne ruinerait l'argument commercial : elle
        annoncerait « déjà exploité » sur un champ qui ne l'est pas."""
        directory = tmp_path / "d"
        directory.mkdir()
        _write_dashboard(directory, "a.json", "Dashboard A", [sql])

        usage = read_dashboard_usage(directory)

        assert ("Bytes" in usage.columns_by_name) is attendu

    def test_srcaddr_ne_matche_pas_srcaddrx(self, tmp_path: Path) -> None:
        """Cas de sous-chaîne explicitement cité dans le brief."""
        directory = tmp_path / "d"
        directory.mkdir()
        _write_dashboard(directory, "a.json", "Dashboard A", ["SELECT SrcAddrX FROM flows"])

        usage = read_dashboard_usage(directory)

        assert "SrcAddr" not in usage.columns_by_name

    def test_un_nom_cite_hors_sql_ne_compte_pas(self, tmp_path: Path) -> None:
        """DÉFAUT ÉVITÉ : les vrais dashboards portent des `description` en prose
        qui CITENT des noms de colonnes (« DSCP = bitShiftRight(IPTos, 2) »
        apparaît dans la description de plusieurs panneaux réels). Scanner le
        JSON entier au lieu des seules requêtes ferait passer pour exploité un
        champ seulement MENTIONNÉ — et l'écran mentirait dans le sens le plus
        coûteux : en sous-estimant le potentiel restant."""
        directory = tmp_path / "d"
        directory.mkdir()
        payload = {
            "title": "Dashboard A",
            "panels": [
                {
                    "description": "Le champ DstASPath serait utile ici",
                    "targets": [{"rawSql": "SELECT Bytes FROM flows"}],
                }
            ],
        }
        (directory / "a.json").write_text(json.dumps(payload), encoding="utf-8")

        usage = read_dashboard_usage(directory)

        assert "Bytes" in usage.columns_by_name
        assert "DstASPath" not in usage.columns_by_name

    def test_columns_used_by_dashboards_rend_un_ensemble_de_noms(
        self, dashboards_dir: Path
    ) -> None:
        noms = columns_used_by_dashboards(dashboards_dir)

        assert "Bytes" in noms
        assert "SrcAddr" in noms
        assert "DstASPath" not in noms


# ---------------------------------------------------------------------------
# 2. Le ratio — calculé, jamais figé
# ---------------------------------------------------------------------------


class TestLeRatioEstCalculeJamaisFige:
    def test_le_total_vient_du_schema_reel_pas_d_une_constante(
        self, dashboards_dir: Path
    ) -> None:
        """Le schéma décide du total. Ici 12 colonnes déclarées par le double :
        si le code lisait `FLOW_COLUMNS` (61 entrées statiques) au lieu de
        `system.columns`, ce test le verrait immédiatement."""
        client = FakeClickHouseClient()

        catalog = build_catalog(client, dashboards_dir)

        assert catalog.total_count == len(_DEFAULT_COLUMNS)

    def test_une_colonne_ajoutee_au_schema_augmente_le_total(
        self, dashboards_dir: Path
    ) -> None:
        """C'est le scénario réel : activer IPTos ou la géo AJOUTE des colonnes.
        Le ratio doit bouger tout seul."""
        base = FakeClickHouseClient()
        catalog_avant = build_catalog(base, dashboards_dir)

        enrichi = FakeClickHouseClient(columns=[*_DEFAULT_COLUMNS, ("SrcGeoCity", "String")])
        catalog_apres = build_catalog(enrichi, dashboards_dir)

        assert catalog_apres.total_count == catalog_avant.total_count + 1
        assert catalog_apres.unused_count == catalog_avant.unused_count + 1

    def test_un_dashboard_ajoute_augmente_le_compte_des_exploites(
        self, dashboards_dir: Path
    ) -> None:
        """Un dashboard livré en plus doit faire baisser le « potentiel
        inexploité » sans qu'on touche au code."""
        client = FakeClickHouseClient()
        avant = build_catalog(client, dashboards_dir)

        _write_dashboard(
            dashboards_dir, "02-geo.json", "Okvorado — Géo", ["SELECT DstCountry FROM flows"]
        )
        apres = build_catalog(FakeClickHouseClient(), dashboards_dir)

        assert apres.used_count == avant.used_count + 1
        assert apres.unused_count == avant.unused_count - 1

    def test_used_plus_unused_egale_le_total(self, dashboards_dir: Path) -> None:
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)

        assert catalog.used_count + catalog.unused_count == catalog.total_count

    def test_le_pourcentage_inexploite_est_coherent(self, dashboards_dir: Path) -> None:
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)

        attendu = round(catalog.unused_count * 100 / catalog.total_count)
        assert catalog.unused_percent == attendu

    def test_aucun_chiffre_du_brief_n_est_ecrit_en_dur_dans_le_service(self) -> None:
        """Garde-fou de non-régression sur l'intention : ni 62, ni 43, ni 69 ne
        doivent apparaître comme constantes de comptage dans le service. Ce sont
        les valeurs MESURÉES le jour du brief ; les recopier ferait un écran qui
        affiche fièrement un chiffre faux six mois plus tard."""
        source = Path(field_catalog.__file__).read_text(encoding="utf-8")
        code = "\n".join(
            ligne
            for ligne in source.splitlines()
            if not ligne.lstrip().startswith("#")
        )
        for interdit in ("= 62", "= 43", "= 69", "return 62", "return 43"):
            assert interdit not in code


# ---------------------------------------------------------------------------
# 3. Classification métier et disponibilité A/B/C
# ---------------------------------------------------------------------------


class TestDashboardsEnAvanceDePhase:
    """Un dashboard qui rend « No data » n'EXPLOITE rien — il PRÉPARE.

    DÉFAUT MESURÉ À L'ÉCRAN (2026-08-11, avant livraison) : les 3 dashboards
    « [Équipement réseau] », livrés en avance de phase sur des champs qu'aucun
    exportateur de la maquette n'émettait, faisaient passer le ratio de « 19
    exploités sur 62 » à « 42 sur 62 » — soit de 69 % à 32 % de potentiel
    inexploité. 23 champs comptaient comme exploités sans qu'une seule donnée
    s'affiche nulle part. L'écran aurait donc détruit l'argument même qu'il
    doit porter, avec un chiffre d'apparence rigoureuse. C'est la famille de
    défaut « filtre juste mais non discriminant » du CLAUDE.md, appliquée à un
    compteur.

    CES 3 DASHBOARDS ONT ÉTÉ RETIRÉS DU DÉPÔT le 2026-08-11 (non alimentés par
    la maquette). Les tests ci-dessous restent valides et NÉCESSAIRES : ils
    s'exécutent sur des DOUBLES construits en `tmp_path`, jamais sur les
    fichiers réels, et verrouillent un mécanisme GÉNÉRIQUE qui doit continuer
    de mordre le jour où un dashboard en avance de phase sera livré à nouveau.
    Seul `test_sur_les_VRAIS_dashboards_*` observe le dépôt réel.
    """

    @staticmethod
    def _dossier_mixte(tmp_path: Path) -> Path:
        directory = tmp_path / "d"
        directory.mkdir()
        _write_dashboard(
            directory, "00-live.json", "Okvorado — Traffic Summary", ["SELECT Bytes FROM flows"]
        )
        _write_dashboard(
            directory,
            "08-avance.json",
            "[Équipement réseau] Routage & transit",
            ["SELECT DstASPath FROM flows"],
        )
        return directory

    def test_un_champ_vu_seulement_en_avance_de_phase_n_est_pas_exploite(
        self, tmp_path: Path
    ) -> None:
        catalog = build_catalog(FakeClickHouseClient(), self._dossier_mixte(tmp_path))
        par_nom = {e.name: e for e in catalog.entries}

        assert par_nom["DstASPath"].used is False

    def test_ce_champ_est_signale_comme_PRET_et_non_comme_inexploite_nu(
        self, tmp_path: Path
    ) -> None:
        """L'argument « il ne manque que l'équipement » doit rester visible :
        ce n'est pas un champ à développer."""
        catalog = build_catalog(FakeClickHouseClient(), self._dossier_mixte(tmp_path))
        par_nom = {e.name: e for e in catalog.entries}

        assert par_nom["DstASPath"].prepared is True
        assert par_nom["DstASPath"].pending_dashboards == [
            "[Équipement réseau] Routage & transit"
        ]

    def test_un_champ_vu_par_un_dashboard_alimente_reste_exploite(
        self, tmp_path: Path
    ) -> None:
        catalog = build_catalog(FakeClickHouseClient(), self._dossier_mixte(tmp_path))
        par_nom = {e.name: e for e in catalog.entries}

        assert par_nom["Bytes"].used is True
        assert par_nom["Bytes"].prepared is False

    def test_les_dashboards_en_avance_ne_gonflent_pas_le_compte_des_exploites(
        self, tmp_path: Path
    ) -> None:
        """LE test qui mord : ajouter un dashboard en avance de phase ne doit
        RIEN changer au ratio exploités / inexploités."""
        directory = tmp_path / "d"
        directory.mkdir()
        _write_dashboard(
            directory, "00-live.json", "Okvorado — Traffic Summary", ["SELECT Bytes FROM flows"]
        )
        avant = build_catalog(FakeClickHouseClient(), directory)

        _write_dashboard(
            directory,
            "08-avance.json",
            "[Équipement réseau] Routage & transit",
            ["SELECT DstASPath, SrcAS, SrcNetMask FROM flows"],
        )
        apres = build_catalog(FakeClickHouseClient(), directory)

        assert apres.used_count == avant.used_count
        assert apres.unused_percent == avant.unused_percent

    def test_le_compte_des_champs_prets_est_expose(self, tmp_path: Path) -> None:
        catalog = build_catalog(FakeClickHouseClient(), self._dossier_mixte(tmp_path))

        assert catalog.prepared_count == 1

    def test_le_csv_distingue_le_dashboard_pret(self, tmp_path: Path) -> None:
        catalog = build_catalog(FakeClickHouseClient(), self._dossier_mixte(tmp_path))

        lignes = list(
            csv.DictReader(io.StringIO(export_catalog_csv(catalog)), delimiter=";")
        )
        par_nom = {ligne["champ"]: ligne for ligne in lignes}

        assert par_nom["DstASPath"]["exploite"] == "non"
        assert "[Équipement réseau]" in par_nom["DstASPath"]["dashboard_pret"]

    def test_sur_les_VRAIS_dashboards_le_ratio_reste_celui_de_la_demonstration(
        self,
    ) -> None:
        """Contrôle sur les fichiers RÉELS du dépôt, pas sur des doubles.

        Sentinelle de l'argument commercial, RÉAJUSTÉE le 2026-08-08 (lot
        « segmentation réseau ») : le constat qui a déclenché ce lot était
        l'INVERSE de celui qui a fixé le seuil précédent — « des champs
        remplis mais exploités par aucun dashboard affaiblissent l'argument
        commercial » (CLAUDE.md racine, section restitution). Exploiter
        SrcNetName/DstNetName/SrcNetRole/DstNetRole/SrcNetTenant/DstNetTenant/
        SrcNetPrefix/DstNetPrefix (8 champs, ~18 avec le lot parc/exportateur
        en parallèle) fait donc BAISSER unused_percent par construction — ce
        n'est pas une régression de ce garde-fou, c'est son but. Le
        MÉCANISME générique (avance de phase ne gonfle jamais le compte,
        cf. reste de la classe) continue de mordre : seul le SEUIL numérique,
        qui reflétait l'état d'AVANT ce lot, est réajusté à la baisse.

        ÉTAT VERROUILLÉ ICI (mesuré le 2026-08-08, après le lot segmentation
        réseau) : 39 % de potentiel encore inexploité sur le VRAI schéma
        (38/62 champs exploités). `prepared_count` reste à 0 (mesuré, jamais
        None) tant qu'aucun dashboard en avance de phase n'est livré."""
        reels = Path(__file__).resolve().parent.parent / "stack" / "grafana" / "dashboards"
        if not reels.is_dir():  # pragma: no cover - dépôt sans le stack
            pytest.skip("dossier des dashboards absent")

        # Schéma RÉEL de production : les colonnes de `flow_sample` + `IPTos`,
        # activée depuis (elle manque à la table statique, cf. docstring du
        # service). Le double à 12 colonnes du reste du fichier ne convient pas
        # ici : c'est le ratio SUR LE VRAI SCHÉMA qu'on verrouille.
        from app.services.flow_sample import FLOW_COLUMNS

        client = FakeClickHouseClient(
            columns=[(c.name, c.clickhouse_type) for c in FLOW_COLUMNS]
            + [("IPTos", "UInt8")]
        )

        catalog = build_catalog(client, reels)

        assert catalog.unused_percent is not None
        # Réajusté par le lot segmentation réseau (2026-08-08) : 60 -> 30.
        # Sous 30 % dirait que la quasi-totalité du catalogue est exploitée,
        # ce qui n'est mesuré ni vrai — 39 % est la mesure réelle post-lot.
        assert catalog.unused_percent >= 30
        # Le compte des « prêts » est MESURÉ (un entier), jamais None : les
        # dashboards ont bien été lus. Il vaut 0 depuis le retrait des écrans
        # en avance de phase — un zéro qui a été mesuré, et que l'écran ne
        # présente pas comme une tuile vide (cf. field_catalog.html).
        assert catalog.prepared_count is not None
        assert catalog.prepared_count == sum(
            1 for entry in catalog.entries if entry.prepared
        )


class TestCategoriesMetier:
    def test_chaque_champ_porte_une_categorie(self, dashboards_dir: Path) -> None:
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)

        assert all(entry.category for entry in catalog.entries)

    def test_les_champs_sont_regroupables_par_categorie(self, dashboards_dir: Path) -> None:
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)

        groupes = catalog.by_category()

        assert len(groupes) > 1
        total_groupe = sum(len(champs) for champs in groupes.values())
        assert total_groupe == catalog.total_count

    def test_une_colonne_inconnue_du_referentiel_reste_affichee(
        self, dashboards_dir: Path
    ) -> None:
        """Une colonne ajoutée par une future version d'Akvorado ne doit pas
        DISPARAÎTRE de l'écran : c'est précisément du potentiel à vendre. Elle
        est classée en « autres » plutôt qu'omise."""
        client = FakeClickHouseClient(columns=[*_DEFAULT_COLUMNS, ("ChampInedit", "String")])

        catalog = build_catalog(client, dashboards_dir)

        noms = [entry.name for entry in catalog.entries]
        assert "ChampInedit" in noms


class TestUsagePotentiel:
    def test_tout_champ_inexploite_porte_une_phrase_d_usage(
        self, dashboards_dir: Path
    ) -> None:
        """LA valeur de l'écran : « à quoi ça servirait ». Un champ inexploité
        sans argument est une ligne inutile en réunion."""
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)

        muets = [
            entry.name
            for entry in catalog.entries
            if not entry.used and not entry.potential_usage.strip()
        ]
        assert muets == []

    def test_la_phrase_d_usage_n_est_pas_une_paraphrase_du_nom(
        self, dashboards_dir: Path
    ) -> None:
        """Une phrase doit apporter un cas d'usage réseau, pas répéter le nom."""
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)
        par_nom = {entry.name: entry for entry in catalog.entries}

        phrase = par_nom["DstASPath"].potential_usage
        assert len(phrase) > 40
        assert phrase.lower() != "chemin d'as destination"

    def test_les_champs_exploites_listent_leurs_dashboards(
        self, dashboards_dir: Path
    ) -> None:
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)
        par_nom = {entry.name: entry for entry in catalog.entries}

        assert par_nom["Bytes"].used is True
        assert "Okvorado — Traffic Summary" in par_nom["Bytes"].dashboards
        assert par_nom["DstASPath"].used is False
        assert par_nom["DstASPath"].dashboards == []


class TestClassementParOrigineDeLaDonnee:
    """QUELLE SOURCE remplit ce champ — la dimension qui sauve la présentation.

    Sans elle, l'écran affiche « 0 % » sur tout le bloc routage et le décideur
    conclut « le produit ne sait pas faire », alors que la vraie phrase est
    « cette maquette n'a pas de routeur ; un SFR ou un Palo Alto l'émet
    nativement ».
    """

    def test_le_protocole_couvre_ce_qui_marche_partout(self, dashboards_dir: Path) -> None:
        """Catégorie 1 : porté par NetFlow/IPFIX quelle que soit la source."""
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)
        par_nom = {entry.name: entry for entry in catalog.entries}

        assert par_nom["Bytes"].origin == ORIGIN_PROTOCOL
        assert par_nom["SrcAddr"].origin == ORIGIN_PROTOCOL

    def test_le_bloc_bgp_vient_d_un_equipement_reseau(self, dashboards_dir: Path) -> None:
        """Catégorie 2 — LE message clé. Vide ici FAUTE DE SOURCE, pas faute de
        config : aucun serveur softflowd n'émet de chemin d'AS."""
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)
        par_nom = {entry.name: entry for entry in catalog.entries}

        assert par_nom["DstASPath"].origin == ORIGIN_NETWORK_EQUIPMENT

    def test_les_masques_reseau_viennent_d_un_equipement_reseau(
        self, dashboards_dir: Path
    ) -> None:
        client = FakeClickHouseClient(columns=[*_DEFAULT_COLUMNS, ("SrcNetMask", "UInt8")])

        catalog = build_catalog(client, dashboards_dir)
        par_nom = {entry.name: entry for entry in catalog.entries}

        assert par_nom["SrcNetMask"].origin == ORIGIN_NETWORK_EQUIPMENT

    def test_la_geo_vient_d_un_enrichissement_du_collecteur(
        self, dashboards_dir: Path
    ) -> None:
        """Catégorie 3 : la donnée n'est dans AUCUN flux, elle est ajoutée par
        Akvorado depuis une base GeoIP — indépendamment des équipements."""
        client = FakeClickHouseClient(
            columns=[*_DEFAULT_COLUMNS, ("SrcGeoCity", "LowCardinality(String)")]
        )

        catalog = build_catalog(client, dashboards_dir)
        par_nom = {entry.name: entry for entry in catalog.entries}

        assert par_nom["SrcGeoCity"].origin == ORIGIN_COLLECTOR_ENRICHMENT

    def test_les_declarations_statiques_sont_un_enrichissement(
        self, dashboards_dir: Path
    ) -> None:
        """`SrcNetRole` vient des `networks:` déclarés dans outlet.yaml, pas du
        flux — vérifié dans `stack/config/outlet.yaml.template`."""
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)
        par_nom = {entry.name: entry for entry in catalog.entries}

        assert par_nom["SrcNetRole"].origin == ORIGIN_COLLECTOR_ENRICHMENT

    def test_l_origine_ne_depend_PAS_du_remplissage_mesure(
        self, dashboards_dir: Path
    ) -> None:
        """RÉGRESSION À INTERDIRE : le taux ILLUSTRE le classement, il ne le
        DÉTERMINE pas. Un `DstASPath` qui se remplirait (client avec BGP) reste
        classé « équipement réseau » — c'est bien un routeur qui le fournit."""
        vide = build_catalog(FakeClickHouseClient(fill_counts={}), dashboards_dir)
        rempli = build_catalog(
            FakeClickHouseClient(fill_counts={"DstASPath": 900}, total_flows=1000),
            dashboards_dir,
        )

        origine_vide = {e.name: e.origin for e in vide.entries}["DstASPath"]
        origine_remplie = {e.name: e.origin for e in rempli.entries}["DstASPath"]

        assert origine_vide == origine_remplie == ORIGIN_NETWORK_EQUIPMENT

    def test_un_champ_d_equipement_explique_le_zero_de_la_maquette(
        self, dashboards_dir: Path
    ) -> None:
        """Sans cette phrase, le 0 % se lit comme un défaut du produit."""
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)
        par_nom = {entry.name: entry for entry in catalog.entries}

        action = par_nom["DstASPath"].required_action.lower()
        assert action.strip()
        assert "routeur" in action or "pare-feu" in action or "équipement" in action

    def test_un_champ_d_enrichissement_dit_quoi_configurer(
        self, dashboards_dir: Path
    ) -> None:
        client = FakeClickHouseClient(
            columns=[*_DEFAULT_COLUMNS, ("SrcGeoCity", "LowCardinality(String)")]
        )

        catalog = build_catalog(client, dashboards_dir)
        par_nom = {entry.name: entry for entry in catalog.entries}

        assert par_nom["SrcGeoCity"].required_action.strip()

    def test_le_catalogue_est_filtrable_par_origine(self, dashboards_dir: Path) -> None:
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)

        equipements = catalog.filtered(origin=ORIGIN_NETWORK_EQUIPMENT)

        assert equipements
        assert all(entry.origin == ORIGIN_NETWORK_EQUIPMENT for entry in equipements)

    def test_chaque_champ_porte_une_origine(self, dashboards_dir: Path) -> None:
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)

        assert all(entry.origin for entry in catalog.entries)


class TestTauxDeRemplissage:
    def test_le_taux_est_mesure_pas_suppose(self, dashboards_dir: Path) -> None:
        client = FakeClickHouseClient(fill_counts={"SrcNetRole": 840}, total_flows=1000)

        catalog = build_catalog(client, dashboards_dir)
        par_nom = {entry.name: entry for entry in catalog.entries}

        assert par_nom["SrcNetRole"].fill_rate == pytest.approx(84.0, abs=0.1)

    def test_un_champ_totalement_vide_rend_zero_et_non_none(
        self, dashboards_dir: Path
    ) -> None:
        """Distinction FONDAMENTALE : `0.0` = « mesuré, et le champ est vide »
        (information vendable : il faut activer quelque chose). `None` = « pas
        mesuré ». Les confondre est le zéro silencieux."""
        client = FakeClickHouseClient(fill_counts={}, total_flows=1000)

        catalog = build_catalog(client, dashboards_dir)
        par_nom = {entry.name: entry for entry in catalog.entries}

        assert par_nom["DstASPath"].fill_rate == 0.0
        assert par_nom["DstASPath"].fill_rate is not None

    def test_la_requete_de_remplissage_est_bornee_dans_le_temps(self) -> None:
        """La table brute sert aussi la console : une requête non bornée peut la
        faire tomber (garde du CLAUDE.md projet)."""
        sql, parameters = build_fill_rate_query(["SrcNetRole", "DstCountry"])

        assert "TimeReceived" in sql
        assert "window_seconds" in parameters

    def test_la_requete_de_remplissage_n_interpole_aucune_saisie(self) -> None:
        """Allowlist SQL : les noms de colonnes sont des littéraux issus du
        schéma, et une colonne hors schéma est REFUSÉE, jamais interpolée."""
        with pytest.raises(ValueError):
            build_fill_rate_query(["SrcNetRole; DROP TABLE flows"])

    def test_la_requete_refuse_un_nom_non_identifiant(self) -> None:
        with pytest.raises(ValueError):
            build_fill_rate_query(["'; SELECT 1 --"])

    def test_une_seule_requete_agregee_pour_tout_le_remplissage(
        self, dashboards_dir: Path
    ) -> None:
        """Un `countIf` par champ ferait 60 requêtes sur une table de 60 M de
        lignes à chaque affichage. Une seule passe agrégée."""
        client = FakeClickHouseClient()

        build_catalog(client, dashboards_dir)

        requetes_remplissage = [sql for sql, _ in client.queries if "countIf" in sql]
        assert len(requetes_remplissage) == 1


# ---------------------------------------------------------------------------
# 4. Zéro silencieux
# ---------------------------------------------------------------------------


class TestZeroSilencieux:
    def test_clickhouse_indisponible_rend_un_etat_distinct(
        self, dashboards_dir: Path
    ) -> None:
        client = FakeClickHouseClient()
        client.raise_on = {"system.columns"}

        catalog = build_catalog(client, dashboards_dir)

        assert catalog.schema_available is False
        assert catalog.error_message
        assert catalog.entries == []

    def test_clickhouse_indisponible_ne_rend_pas_un_ratio_trompeur(
        self, dashboards_dir: Path
    ) -> None:
        """Un « 0 sur 0 » ou « 0 % » afficherait une mesure là où il n'y en a
        pas. Le pourcentage doit être None quand le schéma est inconnu."""
        client = FakeClickHouseClient()
        client.raise_on = {"system.columns"}

        catalog = build_catalog(client, dashboards_dir)

        assert catalog.unused_percent is None

    def test_dossier_de_dashboards_absent_rend_un_etat_distinct(
        self, tmp_path: Path
    ) -> None:
        """Sans les dashboards, on ne sait pas ce qui est exploité : afficher
        « 100 % inexploité » serait un mensonge flatteur pour la démonstration,
        donc exactement ce qu'il faut interdire."""
        catalog = build_catalog(FakeClickHouseClient(), tmp_path / "absent")

        assert catalog.dashboards_available is False
        assert catalog.error_message

    def test_dossier_absent_n_annonce_pas_zero_exploite(self, tmp_path: Path) -> None:
        catalog = build_catalog(FakeClickHouseClient(), tmp_path / "absent")

        assert catalog.used_count is None
        assert catalog.unused_percent is None

    def test_echec_du_remplissage_seul_laisse_le_catalogue_utilisable(
        self, dashboards_dir: Path
    ) -> None:
        """Panne PARTIELLE : le schéma répond, la mesure de remplissage échoue.
        Le catalogue reste affichable (le ratio exploité/inexploité est valide),
        mais les taux passent à `None` — jamais à 0 %."""
        client = FakeClickHouseClient()
        client.raise_on = {"countIf"}

        catalog = build_catalog(client, dashboards_dir)

        assert catalog.schema_available is True
        assert catalog.fill_rates_available is False
        assert catalog.entries
        assert all(entry.fill_rate is None for entry in catalog.entries)

    def test_un_dashboard_illisible_est_signale_pas_ignore(
        self, dashboards_dir: Path
    ) -> None:
        """Un JSON corrompu ne doit pas silencieusement retirer ses champs du
        compte des exploités."""
        (dashboards_dir / "99-casse.json").write_text("{ ceci n'est pas du json", encoding="utf-8")

        usage = read_dashboard_usage(dashboards_dir)

        assert usage.unreadable_files


class TestLectureDuSchema:
    def test_read_flow_columns_lit_system_columns(self) -> None:
        client = FakeClickHouseClient()

        colonnes = read_flow_columns(client)

        assert [c.name for c in colonnes] == [nom for nom, _ in _DEFAULT_COLUMNS]
        assert any("system.columns" in sql for sql, _ in client.queries)

    def test_read_flow_columns_passe_la_table_en_parametre(self) -> None:
        """Aucune concaténation de nom de table dans le SQL."""
        client = FakeClickHouseClient()

        read_flow_columns(client)

        sql, parameters = next(
            (sql, params) for sql, params in client.queries if "system.columns" in sql
        )
        assert "{table:String}" in sql
        assert parameters and parameters.get("table") == "flows"

    def test_le_libelle_francais_vient_du_referentiel_partage(self) -> None:
        """UN concept = UNE source : les libellés FR restent ceux de
        `flow_sample.FLOW_COLUMNS`, jamais redéfinis ici."""
        client = FakeClickHouseClient()

        colonnes = read_flow_columns(client)
        par_nom = {c.name: c for c in colonnes}

        assert par_nom["SrcAddr"].label == "Adresse source"


# ---------------------------------------------------------------------------
# 5. Export CSV
# ---------------------------------------------------------------------------


class TestExportCsv:
    def test_le_csv_porte_toutes_les_colonnes_attendues(
        self, dashboards_dir: Path
    ) -> None:
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)

        contenu = export_catalog_csv(catalog)
        entete = next(csv.reader(io.StringIO(contenu), delimiter=";"))

        for colonne in (
            "champ",
            "type",
            "categorie",
            "exploite",
            "dashboards",
            "usage_possible",
            "origine",
            "taux_remplissage",
            "action_requise",
        ):
            assert colonne in entete

    def test_le_csv_contient_une_ligne_par_champ(self, dashboards_dir: Path) -> None:
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)

        contenu = export_catalog_csv(catalog)
        lignes = list(csv.reader(io.StringIO(contenu), delimiter=";"))

        assert len(lignes) == catalog.total_count + 1

    def test_le_csv_dit_oui_non_et_non_true_false(self, dashboards_dir: Path) -> None:
        """Le fichier s'ouvre dans un tableur pendant la réunion : `True` est du
        jargon de développeur."""
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)

        contenu = export_catalog_csv(catalog)
        lignes = list(csv.DictReader(io.StringIO(contenu), delimiter=";"))

        valeurs = {ligne["exploite"] for ligne in lignes}
        assert valeurs <= {"oui", "non"}

    def test_le_csv_est_relisible_sans_casse_sur_les_separateurs(
        self, dashboards_dir: Path
    ) -> None:
        """Les phrases d'usage contiennent des virgules et des points-virgules :
        elles doivent être échappées, sinon le tableur décale les colonnes."""
        catalog = build_catalog(FakeClickHouseClient(), dashboards_dir)

        contenu = export_catalog_csv(catalog)
        entete = next(csv.reader(io.StringIO(contenu), delimiter=";"))
        lignes = list(csv.DictReader(io.StringIO(contenu), delimiter=";"))

        # Chaque ligne doit porter EXACTEMENT autant de champs que l'en-tête :
        # une phrase d'usage mal échappée décalerait les colonnes du tableur.
        assert all(len(ligne) == len(entete) for ligne in lignes)
        assert all(ligne["champ"] for ligne in lignes)

    def test_le_taux_indisponible_ne_s_ecrit_pas_zero(self, dashboards_dir: Path) -> None:
        """Zéro silencieux jusque dans le fichier exporté."""
        client = FakeClickHouseClient()
        client.raise_on = {"countIf"}
        catalog = build_catalog(client, dashboards_dir)

        contenu = export_catalog_csv(catalog)
        lignes = list(csv.DictReader(io.StringIO(contenu), delimiter=";"))

        taux = {ligne["taux_remplissage"] for ligne in lignes}
        assert "0" not in taux
        assert "0.0" not in taux
        assert taux == {"indisponible"}


# ---------------------------------------------------------------------------
# 6. L'écran
# ---------------------------------------------------------------------------


def _build_app(client: FakeClickHouseClient, dashboards: Path) -> FastAPI:
    """Monte le routeur seul, avec ses dépendances surchargées — même
    convention que les autres tests d'écran du projet."""
    from app.routers import field_catalog as field_catalog_router

    app = FastAPI()
    app.include_router(field_catalog_router.router)
    app.dependency_overrides[field_catalog_router.get_clickhouse_client] = lambda: client
    app.dependency_overrides[field_catalog_router.get_dashboards_dir] = lambda: dashboards
    return app


class TestEcranCatalogue:
    def test_la_page_repond(self, dashboards_dir: Path) -> None:
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        reponse = TestClient(app).get("/field-catalog")

        assert reponse.status_code == 200

    def test_la_page_affiche_le_ratio_calcule(self, dashboards_dir: Path) -> None:
        client = FakeClickHouseClient()
        catalog = build_catalog(client, dashboards_dir)
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get("/field-catalog").text

        assert str(catalog.total_count) in corps
        assert str(catalog.unused_count) in corps

    def test_la_page_liste_les_champs(self, dashboards_dir: Path) -> None:
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get("/field-catalog").text

        assert "DstASPath" in corps
        assert "SrcNetRole" in corps

    def test_le_filtre_inexploites_ne_rend_que_les_inexploites(
        self, dashboards_dir: Path
    ) -> None:
        """Filtre DISCRIMINANT : un filtre qui rend la même chose que « tout »
        est un défaut mesuré sur ce projet (famille « filtre juste mais non
        discriminant »)."""
        app = _build_app(FakeClickHouseClient(), dashboards_dir)
        client = TestClient(app)

        tout = client.get("/field-catalog/rows").text
        inexploites = client.get("/field-catalog/rows", params={"usage": "unused"}).text

        assert "DstASPath" in inexploites
        assert "DstASPath" in tout
        # `Bytes` est exploité par le dashboard de test : il doit disparaître.
        assert tout.count("<tr") > inexploites.count("<tr")

    def test_le_filtre_exploites_ne_rend_que_les_exploites(
        self, dashboards_dir: Path
    ) -> None:
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get("/field-catalog/rows", params={"usage": "used"}).text

        assert "DstASPath" not in corps

    def test_le_filtre_par_origine_est_discriminant(self, dashboards_dir: Path) -> None:
        app = _build_app(FakeClickHouseClient(), dashboards_dir)
        client = TestClient(app)

        tout = client.get("/field-catalog/rows").text
        equipement = client.get(
            "/field-catalog/rows", params={"origin": ORIGIN_NETWORK_EQUIPMENT}
        ).text

        assert "DstASPath" in equipement
        assert tout.count("<tr") > equipement.count("<tr")

    def test_un_filtre_d_origine_inconnu_est_refuse(self, dashboards_dir: Path) -> None:
        """Allowlist : une valeur hors énumération ne doit pas être interpolée
        ni rendre un écran vide qu'on confondrait avec « aucun champ »."""
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        reponse = TestClient(app).get(
            "/field-catalog/rows", params={"origin": "n-importe-quoi"}
        )

        assert reponse.status_code == 400

    def test_la_page_indique_clickhouse_indisponible(self, dashboards_dir: Path) -> None:
        client = FakeClickHouseClient()
        client.raise_on = {"system.columns"}
        app = _build_app(client, dashboards_dir)

        corps = TestClient(app).get("/field-catalog").text.lower()

        assert "indisponible" in corps

    def test_la_page_indique_les_dashboards_absents(self, tmp_path: Path) -> None:
        app = _build_app(FakeClickHouseClient(), tmp_path / "absent")

        corps = TestClient(app).get("/field-catalog").text.lower()

        assert "indisponible" in corps or "introuvable" in corps

    def test_le_csv_est_telechargeable(self, dashboards_dir: Path) -> None:
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        reponse = TestClient(app).get("/field-catalog/export.csv")

        assert reponse.status_code == 200
        assert "attachment" in reponse.headers["content-disposition"]
        assert "csv" in reponse.headers["content-type"]


class TestGardesHtmxEtCsp:
    """Les trois défauts d'UI mesurés sur ce projet, rendus mécaniques."""

    _TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "app" / "templates"
    _TEMPLATE = _TEMPLATES_DIR / "field_catalog.html"
    _ROWS = _TEMPLATES_DIR / "_field_catalog_rows.html"

    @property
    def _both(self) -> str:
        """Les DEUX templates de l'écran.

        Le fragment de lignes est servi seul par HTMX : une faute de CSP qui n'y
        serait pas cherchée passerait inaperçue jusqu'au premier clic de filtre.
        """
        return self._TEMPLATE.read_text(encoding="utf-8") + self._ROWS.read_text(
            encoding="utf-8"
        )

    def test_les_sections_d_action_portent_hx_select_unset(self) -> None:
        """PIÈGE MESURÉ 3 FOIS : `hx-select` est HÉRITÉ. Un conteneur parent qui
        le porte fait insérer un fragment VIDE par les boutons enfants, en
        silence."""
        source = self._TEMPLATE.read_text(encoding="utf-8")

        assert 'hx-select="unset"' in source

    def test_aucun_gestionnaire_inline(self) -> None:
        """CSP `script-src 'self'` sans `unsafe-inline`."""
        source = self._both

        assert "onclick=" not in source
        assert "onchange=" not in source
        assert "<script>" not in source

    def test_aucune_condition_htmx_evaluee_en_js(self) -> None:
        """`every Ns [ ... ]` est évalué dynamiquement -> `EvalError` sous CSP
        stricte (défaut mesuré le 2026-08-10).

        On cible la FORME fautive (`every ... [`), pas la simple présence d'un
        crochet : un test qui interdirait tout `[` mordrait sur du Jinja
        légitime et serait désactivé au premier faux positif."""
        source = self._both

        assert not re.search(r"hx-trigger=\"[^\"]*every[^\"]*\[", source)

    def test_le_vert_vient_des_variables_css_existantes(self) -> None:
        """« VERT = exploité » est une demande explicite. La couleur doit venir
        de `--ok`/`--ok-bg`, pas d'une palette réinventée."""
        source = self._both
        css = (
            Path(__file__).resolve().parent.parent / "app" / "static" / "style.css"
        ).read_text(encoding="utf-8")

        # La classe existe côté template ET porte bien le vert côté CSS : les
        # deux moitiés doivent tenir, un template qui pose une classe sans style
        # est un défaut mesuré sur ce projet (« CSS cassant un HTML correct »).
        assert "field-used" in source
        assert ".field-used" in css
        assert "var(--ok-bg)" in css


class TestNavigation:
    def test_l_onglet_est_dans_la_navigation(self) -> None:
        """Défaut vécu (2026-08-06) : une page sans lien de menu n'existe pas
        pour qui l'utilise."""
        base = (
            Path(__file__).resolve().parent.parent / "app" / "templates" / "base.html"
        ).read_text(encoding="utf-8")

        assert "/field-catalog" in base

    def test_l_onglet_porte_un_etat_actif(self) -> None:
        base = (
            Path(__file__).resolve().parent.parent / "app" / "templates" / "base.html"
        ).read_text(encoding="utf-8")

        assert "field_catalog" in base

    def test_le_routeur_est_monte_dans_main(self) -> None:
        main = (
            Path(__file__).resolve().parent.parent / "app" / "main.py"
        ).read_text(encoding="utf-8")

        assert "app.routers.field_catalog" in main

    def test_les_dependances_du_routeur_sont_cablees_dans_main(self) -> None:
        """CÂBLAGE OBLIGATOIRE : sans override, les tests passent et la PROD
        échoue au premier clic."""
        main = (
            Path(__file__).resolve().parent.parent / "app" / "main.py"
        ).read_text(encoding="utf-8")

        assert "field_catalog_router.get_clickhouse_client" in main
        assert "field_catalog_router.get_dashboards_dir" in main


class TestDashboardPretDistingueDonneePresenteOuAbsente:
    """« Prêt » ne veut pas dire la même chose selon que la donnée est là ou non.

    DÉFAUT MESURÉ À L'ÉCRAN (2026-08-11), sur la plateforme réelle : trois
    champs affichaient « Prêt — en attente de la source » alors que leur taux
    de remplissage mesuré était non nul —
      - SrcNetPrefix : 100 %
      - InIfBoundary : 100 %
      - SrcNetRole   :  83 %

    Le libellé était donc FAUX pour eux : leur dashboard n'attend aucune
    source, il afficherait des données dès son ouverture. En présentation,
    cela revenait à réclamer un équipement pour des champs immédiatement
    exploitables — et à perdre l'argument le PLUS fort : « le panneau existe,
    la donnée est là, il suffit de l'ajouter au dashboard ».

    Le statut doit donc dépendre de la MESURE, pas de la seule existence du
    fichier de dashboard.
    """

    _GABARIT = (
        Path(__file__).resolve().parent.parent
        / "app"
        / "templates"
        / "_field_catalog_rows.html"
    )
    _CSS = Path(__file__).resolve().parent.parent / "app" / "static" / "style.css"

    def test_le_statut_depend_du_taux_de_remplissage_mesure(self) -> None:
        html = self._GABARIT.read_text(encoding="utf-8")
        # On ne se contente PAS de chercher « fill_rate » quelque part : il faut
        # que la CONDITION qui choisit le libellé le consulte réellement.
        # Sinon un `{% if false %}` laisserait le test vert avec le défaut en
        # place — vérifié par mutation, c'est exactement ce qui s'est produit.
        condition = re.search(
            r"\{%\s*if\s+([^%]*?)\s*%\}\s*\n\s*<span class=\"badge badge-ready-now\"",
            html,
        )
        assert condition, (
            "aucune condition ne gouverne le badge « donnée déjà présente » : "
            "le libellé serait figé, quel que soit le remplissage réel"
        )
        assert "fill_rate" in condition.group(1), (
            "la condition du badge n'interroge pas le taux de remplissage "
            f"MESURÉ — trouvé : {condition.group(1)!r}. Un champ déjà rempli "
            "serait présenté comme « en attente de la source »."
        )
        # Le nom de l'attribut compte : `fill_ratio` (inventé) rendrait la
        # condition toujours fausse et laisserait le défaut en place, en silence.
        assert "fill_ratio" not in html, (
            "attribut inexistant `fill_ratio` : la condition serait toujours "
            "fausse et le libellé resterait erroné sans qu'aucun test ne tombe"
        )

    def test_les_deux_libelles_existent_et_sont_distincts(self) -> None:
        html = self._GABARIT.read_text(encoding="utf-8")
        assert "donnée déjà présente" in html, (
            "il manque le libellé du cas « le dashboard fonctionnerait tout de "
            "suite » — c'est l'argument commercial le plus fort"
        )
        assert "en attente de la source" in html, (
            "le libellé du cas réellement en attente doit subsister"
        )

    def test_le_badge_donnee_presente_est_style(self) -> None:
        """Un badge sans style se rend sans couleur — défaut déjà vécu ici
        avec `notice-error`, employée 8 fois sans exister dans le CSS."""
        css = self._CSS.read_text(encoding="utf-8")
        assert ".badge-ready-now" in css, (
            "badge-ready-now employé dans le gabarit mais absent du CSS : il "
            "s'afficherait sans aucun style"
        )


# ---------------------------------------------------------------------------
# 7. Persistance du filtre (le reset au bout de ~5s, signalé par l'utilisateur)
# ---------------------------------------------------------------------------
#
# CAUSE MESURÉE : le conteneur de filtres ne remplace QUE `#field-catalog-rows`
# (`hx-target` + `hx-swap="innerHTML"`) et ne pousse JAMAIS l'URL. La page
# reste sur `/field-catalog` sans paramètre : tout nouveau rendu de la page
# (retour arrière, restauration d'onglet, rechargement) retombe sur l'état
# NON filtré, puisque l'état du filtre ne vit que dans le DOM.
#
# Le correctif : `hx-push-url` sur les boutons, avec une URL EXPLICITE
# (`/field-catalog?...`, jamais `/field-catalog/rows?...` qui rendrait un
# fragment nu si collé dans la barre d'adresse) + le routeur `/field-catalog`
# qui lit `usage`/`origin`/`category` de la query string et rend la page DÉJÀ
# filtrée, bouton actif compris.


class TestPersistanceDuFiltre:
    def test_la_page_complete_est_deja_filtree_depuis_la_query_string(
        self, dashboards_dir: Path
    ) -> None:
        """LE test qui compte : `/field-catalog?usage=unused` rend la page
        COMPLÈTE (pas un fragment), déjà filtrée — pas juste le paramètre
        accepté, le NOMBRE de lignes doit refléter le filtre."""
        app = _build_app(FakeClickHouseClient(), dashboards_dir)
        client = TestClient(app)

        tout = client.get("/field-catalog")
        filtre = client.get("/field-catalog", params={"usage": "unused"})

        assert tout.status_code == 200
        assert filtre.status_code == 200
        # Page COMPLÈTE : le fragment n'a pas de <h1>, la page si.
        assert "<h1>" in filtre.text
        # DISCRIMINANT : le rendu filtré contient strictement moins de lignes.
        assert filtre.text.count("<tr") < tout.text.count("<tr")

    def test_le_bouton_actif_reflete_le_filtre_de_la_query_string(
        self, dashboards_dir: Path
    ) -> None:
        """Après rechargement sur `?usage=unused`, le bouton « Inexploités »
        doit porter la classe active — sinon l'exploitant croit que rien
        n'est filtré alors que la liste, elle, l'est déjà."""
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get("/field-catalog", params={"usage": "unused"}).text

        bouton = re.search(
            r'<a class="btn[^"]*"\s+hx-get="[^"]*usage=unused[^"]*"[^>]*>Inexploités</a>',
            corps,
        )
        assert bouton, "bouton « Inexploités » introuvable dans le rendu filtré"
        assert "primary" in bouton.group(0), (
            "le bouton « Inexploités » ne porte pas la classe active alors que "
            "le filtre `usage=unused` est bien appliqué à l'écran — l'exploitant "
            "verrait une liste filtrée sans aucun bouton actif"
        )

    def test_les_boutons_de_filtre_poussent_l_url_de_la_page_complete(self) -> None:
        """`hx-push-url` doit pointer vers `/field-catalog?...`, JAMAIS vers
        `/field-catalog/rows?...` : une URL de fragment collée dans la barre
        d'adresse rendrait un tableau nu, sans mise en page ni CSS."""
        template = (
            Path(__file__).resolve().parent.parent
            / "app"
            / "templates"
            / "field_catalog.html"
        ).read_text(encoding="utf-8")

        boutons_filtre = re.findall(r"<a class=\"btn[^\"]*\"[^>]*>[^<]*</a>", template)
        boutons_filtre = [b for b in boutons_filtre if "hx-get" in b and "/rows" in b]
        assert boutons_filtre, "aucun bouton de filtre hx-get trouvé"

        for bouton in boutons_filtre:
            assert 'hx-push-url="' in bouton, (
                f"bouton sans hx-push-url, le filtre ne survivra pas à un "
                f"nouveau rendu de la page : {bouton!r}"
            )
            match = re.search(r'hx-push-url="([^"]*)"', bouton)
            assert match, bouton
            url_poussee = match.group(1)
            assert "/rows" not in url_poussee, (
                "l'URL poussée pointe vers le fragment de lignes "
                f"({url_poussee!r}) : rechargée telle quelle, elle rendrait un "
                "tableau nu sans mise en page"
            )
            # Comparaison sur le SOURCE Jinja (pas rendu) : la valeur littérale
            # passée à `prefixed` doit être la page complète, pas le fragment.
            assert "'/field-catalog'" in url_poussee, (
                f"l'URL poussée ne cible pas la page complète : {url_poussee!r}"
            )

    def test_le_fragment_de_lignes_reste_un_fragment_pour_htmx(
        self, dashboards_dir: Path
    ) -> None:
        """`/field-catalog/rows` doit continuer à rendre le fragment SEUL pour
        une requête HTMX (header `HX-Request`) : c'est ce que `hx-target`
        consomme au clic. Ne pas basculer cette route sur la page complète."""
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get(
            "/field-catalog/rows",
            params={"usage": "unused"},
            headers={"HX-Request": "true"},
        ).text

        assert "<h1>" not in corps
        assert "<table" in corps or "notice" in corps

    def test_un_usage_hors_allowlist_sur_la_page_complete_est_refuse(
        self, dashboards_dir: Path
    ) -> None:
        """Même garde d'allowlist sur `/field-catalog` que sur `/rows` : une
        valeur hors énumération ne doit jamais être interpolée."""
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        reponse = TestClient(app).get(
            "/field-catalog", params={"usage": "n-importe-quoi"}
        )

        assert reponse.status_code == 400


# ---------------------------------------------------------------------------
# 8. Barre de filtre actif (demande utilisateur 2026-08-12)
# ---------------------------------------------------------------------------
#
# CAPTURE À L'APPUI : le bouton « Applicatif / ports » est visiblement actif,
# 3 lignes seulement sont affichées (Proto, SrcPort, DstPort) — et le titre du
# tableau annonce « Les 62 champs ». Trois défauts distincts :
#   1. Le titre ment : `catalog.total_count` (le catalogue) au lieu du nombre
#      RÉELLEMENT affiché (`entries`, la liste filtrée).
#   2. Aucun récapitulatif du filtre actif : l'exploitant doit deviner l'état
#      courant en lisant 3 groupes de boutons.
#   3. Un croisement vide (`usage=unused&category=...`) rend 0 ligne sans dire
#      lequel des filtres croisés est en cause.


class TestLeTitreDitCeQuiEstReellementAffiche:
    """Le titre du tableau doit refléter `entries` (filtré), jamais
    `catalog.total_count` (le catalogue entier) — c'est le défaut mesuré en
    capture : bouton « Applicatif / ports » actif, 3 lignes rendues, titre
    annonçant quand même « Les 62 champs »."""

    def test_le_titre_reflete_le_nombre_de_lignes_filtrees_categorie(
        self, dashboards_dir: Path
    ) -> None:
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        reponse = TestClient(app).get(
            "/field-catalog", params={"category": CATEGORY_ROUTING}
        )
        corps = reponse.text
        nb_lignes = corps.count("<tr class=")

        assert nb_lignes > 0
        assert nb_lignes < len(_DEFAULT_COLUMNS), (
            "le filtre categorie doit etre discriminant sur ce jeu de test"
        )
        # Le titre du TABLEAU (dans le <h2> qui suit le panel-head après la
        # barre de filtre actif) doit citer le compte RÉEL affiché — pas
        # n'importe quel <h2> de la page (il y en a plusieurs : « D'où vient
        # la donnée », « Filtrer »...).
        ancre = corps.find('id="field-catalog-active-filters"')
        assert ancre != -1
        titre = corps[corps.find("<h2>", ancre) : corps.find("</h2>", ancre) + 5]
        assert f"{nb_lignes} champ" in titre, (
            f"le titre du tableau n'annonce pas {nb_lignes} (nombre de "
            f"lignes reellement rendues) — titre: {titre!r}"
        )

    def test_le_titre_ne_recite_jamais_le_total_catalogue_sous_filtre(
        self, dashboards_dir: Path
    ) -> None:
        """LE test qui aurait mordu sur `titre 62 | lignes 3` : sous un filtre
        strictement discriminant, le total catalogue ne doit PLUS apparaître
        seul comme le compte affiché dans le titre."""
        client = FakeClickHouseClient()
        catalog_complet = build_catalog(client, dashboards_dir)
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get(
            "/field-catalog", params={"category": CATEGORY_ROUTING}
        ).text
        nb_lignes = corps.count("<tr class=")

        assert nb_lignes != catalog_complet.total_count, (
            "jeu de test non discriminant : le filtre doit rendre moins de "
            "lignes que le catalogue complet pour que ce test soit probant"
        )
        assert nb_lignes > 0, (
            "jeu de test non probant : le filtre doit rendre au moins une "
            "ligne (categorie presente dans _DEFAULT_COLUMNS)"
        )
        ancre = corps.find('id="field-catalog-active-filters"')
        assert ancre != -1
        titre = corps[corps.find("<h2>", ancre) : corps.find("</h2>", ancre) + 5]
        assert str(catalog_complet.total_count) not in titre or (
            f"{nb_lignes} champ" in titre
        ), (
            f"le titre affiche encore le total catalogue "
            f"({catalog_complet.total_count}) sans mentionner le compte "
            f"filtre reel ({nb_lignes}) : {titre!r}"
        )

    def test_sans_filtre_le_titre_reste_coherent(self, dashboards_dir: Path) -> None:
        """Sans filtre, filtré == catalogue : le titre doit rester correct
        (comportement déjà correct par hasard, ne pas le casser)."""
        client = FakeClickHouseClient()
        catalog = build_catalog(client, dashboards_dir)
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get("/field-catalog").text

        assert f"{catalog.total_count} champ" in corps


class TestBarreDeFiltreActif:
    """« mettre une barre qui fixe le filtre en cours pour faciliter la
    gestion » — demande utilisateur mot pour mot. La barre doit : nommer
    chaque filtre actif en clair, le dire aussi quand il n'y en a aucun,
    permettre de retirer un filtre d'un clic (jeton + croix), et rester
    visible au défilement (sticky)."""

    def test_aucun_filtre_actif_est_dit_explicitement(self, dashboards_dir: Path) -> None:
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get("/field-catalog").text

        assert "field-catalog-active-filters" in corps
        assert "Aucun filtre actif" in corps

    def test_un_filtre_usage_actif_est_nomme_en_clair(self, dashboards_dir: Path) -> None:
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get(
            "/field-catalog", params={"usage": "unused"}
        ).text

        barre = corps[
            corps.find('id="field-catalog-active-filters"') :
            corps.find('id="field-catalog-active-filters"') + 2000
        ]
        assert "Exploitation" in barre
        assert "Inexploités" in barre
        assert "Aucun filtre actif" not in barre

    def test_un_filtre_categorie_avec_espace_et_accent_est_nomme(
        self, dashboards_dir: Path
    ) -> None:
        """Les catégories sont des libellés FR complets : « Applicatif /
        ports », espace + barre oblique. Doit s'afficher tel quel."""
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get(
            "/field-catalog", params={"category": CATEGORY_APPLICATION}
        ).text

        barre = corps[
            corps.find('id="field-catalog-active-filters"') :
            corps.find('id="field-catalog-active-filters"') + 2000
        ]
        assert CATEGORY_APPLICATION in barre

    def test_plusieurs_filtres_actifs_sont_tous_nommes(self, dashboards_dir: Path) -> None:
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get(
            "/field-catalog",
            params={"usage": "unused", "origin": ORIGIN_NETWORK_EQUIPMENT},
        ).text

        barre = corps[
            corps.find('id="field-catalog-active-filters"') :
            corps.find('id="field-catalog-active-filters"') + 2000
        ]
        assert "Inexploités" in barre
        assert ORIGIN_LABELS[ORIGIN_NETWORK_EQUIPMENT] in barre

    def test_le_compte_affiche_sur_total_est_dans_la_barre(
        self, dashboards_dir: Path
    ) -> None:
        """« 3 champs affichés sur 62 » : le compteur qui corrige le titre
        menteur doit aussi être lisible depuis la barre elle-même."""
        client = FakeClickHouseClient()
        catalog = build_catalog(client, dashboards_dir)
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get(
            "/field-catalog", params={"category": CATEGORY_APPLICATION}
        ).text
        nb_lignes = corps.count("<tr class=")

        barre = corps[
            corps.find('id="field-catalog-active-filters"') :
            corps.find('id="field-catalog-active-filters"') + 2000
        ]
        assert str(nb_lignes) in barre
        assert str(catalog.total_count) in barre

    def test_chaque_jeton_de_filtre_est_un_lien_retirant_ce_seul_filtre(
        self, dashboards_dir: Path
    ) -> None:
        """Retirer le jeton « Exploitation » doit produire l'URL SANS `usage`
        mais en conservant `origin` — geste à la souris, jamais l'URL tapée."""
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get(
            "/field-catalog",
            params={"usage": "unused", "origin": ORIGIN_NETWORK_EQUIPMENT},
        ).text

        barre = corps[
            corps.find('id="field-catalog-active-filters"') :
            corps.find('id="field-catalog-active-filters"') + 3000
        ]
        liens_retrait = re.findall(r'href="([^"]*field-catalog\?[^"]*)"', barre)
        assert liens_retrait, "aucun lien de retrait trouve dans la barre"

        # Un des liens doit retirer `usage` en gardant `origin`.
        cible_usage = [
            href for href in liens_retrait
            if "usage=all" in href and f"origin={ORIGIN_NETWORK_EQUIPMENT}" in href
        ]
        assert cible_usage, (
            f"aucun lien ne retire usage tout en gardant origin — liens "
            f"trouves: {liens_retrait!r}"
        )

        # Un des liens doit retirer `origin` en gardant `usage=unused`.
        cible_origin = [
            href for href in liens_retrait
            if "usage=unused" in href and "origin=" in href
            and f"origin={ORIGIN_NETWORK_EQUIPMENT}" not in href
        ]
        assert cible_origin, (
            f"aucun lien ne retire origin tout en gardant usage=unused — "
            f"liens trouves: {liens_retrait!r}"
        )

    def test_le_bouton_tout_reinitialiser_efface_tous_les_filtres(
        self, dashboards_dir: Path
    ) -> None:
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get(
            "/field-catalog",
            params={
                "usage": "unused",
                "origin": ORIGIN_NETWORK_EQUIPMENT,
                "category": CATEGORY_ROUTING,
            },
        ).text

        barre = corps[
            corps.find('id="field-catalog-active-filters"') :
            corps.find('id="field-catalog-active-filters"') + 3000
        ]
        assert "réinitialiser" in barre.lower() or "Réinitialiser" in barre

        reset = re.search(
            r'href="([^"]*field-catalog\?usage=all&(?:amp;)?origin=&(?:amp;)?'
            r'category=[^"]*)"',
            barre,
        )
        assert reset, f"pas de lien de reinitialisation complet trouve dans {barre!r}"

    def test_les_jetons_sont_des_liens_hx_get_avec_push_url_page_complete(
        self, dashboards_dir: Path
    ) -> None:
        """Même contrat que les boutons de filtre existants : `<a href>`
        fonctionnel sans JS, `hx-get` vers `/rows`, `hx-push-url` vers la page
        complète — jamais celle du fragment."""
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get(
            "/field-catalog", params={"usage": "unused"}
        ).text

        barre = corps[
            corps.find('id="field-catalog-active-filters"') :
            corps.find('id="field-catalog-active-filters"') + 3000
        ]
        # Un jeton = un <a>...</a> dont le contenu (potentiellement structuré
        # en <span>) porte la croix de retrait.
        jetons = re.findall(r"<a\b[^>]*>(?:(?!</a>).)*×(?:(?!</a>).)*</a>", barre, re.S)
        assert jetons, f"aucun jeton retirable (avec x) trouve dans {barre!r}"
        for jeton in jetons:
            assert "hx-get=" in jeton
            assert '/field-catalog/rows' in jeton
            assert 'hx-push-url="' in jeton
            match = re.search(r'hx-push-url="([^"]*)"', jeton)
            assert match
            assert "/rows" not in match.group(1)

    def test_la_barre_porte_hx_select_unset(self, dashboards_dir: Path) -> None:
        """Même piège que les autres conteneurs d'action de ce projet :
        `hx-select` hérité insérerait un fragment vide en silence."""
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        corps = TestClient(app).get("/field-catalog").text
        debut = corps.find('id="field-catalog-active-filters"')
        assert debut != -1
        bloc = corps[max(0, debut - 300) : debut]

        assert 'hx-select="unset"' in bloc or 'hx-select="unset"' in corps[debut:debut + 400]

    def test_la_barre_est_positionnee_sticky_en_css(self) -> None:
        """« une barre qui FIXE le filtre en cours » : `position: sticky` (pas
        `fixed`, qui casserait la mise en page dans le flux du panneau)."""
        css = (
            Path(__file__).resolve().parent.parent / "app" / "static" / "style.css"
        ).read_text(encoding="utf-8")

        bloc = re.search(
            r"\.field-catalog-active-filters\s*\{([^}]*)\}", css
        )
        assert bloc, "aucune regle CSS .field-catalog-active-filters trouvee"
        assert "sticky" in bloc.group(1)
        assert "top:" in bloc.group(1)

    def test_la_barre_est_dans_le_fragment_swap_able(self) -> None:
        """La barre doit vivre DANS `#field-catalog-rows` (le fragment
        HTMX swap-able), pas dans `field_catalog.html` en dehors de cette
        zone : sinon un clic de filtre remplacerait les lignes sans jamais
        mettre à jour la barre, qui continuerait d'afficher l'état PRÉCÉDENT.
        """
        rows_fragment = (
            Path(__file__).resolve().parent.parent
            / "app"
            / "templates"
            / "_field_catalog_rows.html"
        ).read_text(encoding="utf-8")
        page = (
            Path(__file__).resolve().parent.parent
            / "app"
            / "templates"
            / "field_catalog.html"
        ).read_text(encoding="utf-8")

        assert "field-catalog-active-filters" in rows_fragment
        # La zone swap doit englober le fragment entier (id sur le <div>
        # parent de l'`{% include %}`), pas seulement un sous-bloc statique.
        assert 'id="field-catalog-rows"' in page
        include_pos = page.find("{% include")
        div_pos = page.rfind('id="field-catalog-rows"', 0, include_pos)
        assert div_pos != -1, (
            "le div #field-catalog-rows doit envelopper l'include du "
            "fragment pour que la barre soit remplacee avec les lignes"
        )


class TestCroisementDeFiltresVide:
    """Défaut 3 : `?usage=unused&category=X` qui ne rend rien doit NOMMER les
    filtres en cause, pas afficher un message générique indiscernable d'une
    panne — règle zéro silencieux appliquée à l'UI."""

    @staticmethod
    def _client_avec_champs_applicatifs() -> FakeClickHouseClient:
        """`_DEFAULT_COLUMNS` ne porte aucun champ `Applicatif / ports` : on
        ajoute Proto/SrcPort/DstPort pour pouvoir vider ce croisement
        précisément (et pas un simple filtre catégorie déjà vide seul)."""
        return FakeClickHouseClient(
            columns=[
                *_DEFAULT_COLUMNS,
                ("Proto", "UInt8"),
                ("SrcPort", "UInt16"),
                ("DstPort", "UInt16"),
            ]
        )

    @staticmethod
    def _dossier_tout_exploite(tmp_path: Path) -> Path:
        """Dashboard qui exploite TOUS les champs `Applicatif / ports`
        ajoutés ci-dessus, pour forcer un croisement
        usage=unused × category=Applicatif vide."""
        directory = tmp_path / "d"
        directory.mkdir()
        _write_dashboard(
            directory,
            "00-app.json",
            "Dashboard applicatif complet",
            ["SELECT Proto, SrcPort, DstPort FROM flows"],
        )
        return directory

    def test_le_croisement_vide_nomme_les_deux_filtres_en_cause(
        self, tmp_path: Path
    ) -> None:
        directory = self._dossier_tout_exploite(tmp_path)
        app = _build_app(self._client_avec_champs_applicatifs(), directory)

        reponse = TestClient(app).get(
            "/field-catalog",
            params={"usage": "unused", "category": CATEGORY_APPLICATION},
        )
        corps = reponse.text.lower()

        assert "aucun champ" in corps
        assert "exploitation" in corps or "inexploités" in corps.lower() or (
            "inexploité" in corps
        )
        assert "catégorie" in corps or "categorie" in corps
        assert "applicatif" in corps

    def test_le_message_de_croisement_vide_propose_de_relacher(
        self, tmp_path: Path
    ) -> None:
        directory = self._dossier_tout_exploite(tmp_path)
        app = _build_app(self._client_avec_champs_applicatifs(), directory)

        corps = TestClient(app).get(
            "/field-catalog",
            params={"usage": "unused", "category": CATEGORY_APPLICATION},
        ).text.lower()

        assert "retirer" in corps or "relâcher" in corps or "relacher" in corps

    def test_un_seul_filtre_vide_garde_un_message_simple_pas_de_croisement(
        self, dashboards_dir: Path
    ) -> None:
        """Un SEUL filtre actif qui rend 0 ligne ne doit pas parler de
        « croisement » — ce vocabulaire est réservé à 2+ filtres actifs."""
        app = _build_app(FakeClickHouseClient(), dashboards_dir)

        # `_DEFAULT_COLUMNS` ne porte aucun champ « Applicatif / ports » :
        # un SEUL filtre catégorie suffit ici à vider le résultat.
        corps = TestClient(app).get(
            "/field-catalog", params={"category": CATEGORY_APPLICATION}
        ).text.lower()

        assert "aucun champ" in corps
        assert "croisement" not in corps
