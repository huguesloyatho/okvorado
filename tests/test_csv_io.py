"""Tests du CSV du plan d'adressage : parsing/sérialisation PUIS routes HTTP.

Deux parties :
1. `app/services/csv_io.py` (logique pure, aucun HTTP, aucune écriture de
   fichier) — la majorité des tests ci-dessous.
2. `POST/GET /config/sections/networks/{import,export}` (routes HTTP) via
   `TestClient`, en fin de fichier — le périmètre du lot CSV inclut les
   routes du router mais pas `tests/test_config_sections_router.py`
   (périmètre disjoint, verrouillé pour un autre agent), donc ces tests de
   routes vivent ici plutôt que là-bas.

Aucun test ici ne touche la prod : SQLite en mémoire, YAML en `tmp_path`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.db import SCHEMA
from app.services.config_writer import list_pending_changes
from app.services.csv_io import (
    ASNS_CSV_FORMAT,
    EXPORTER_CLASSIFIERS_CSV_FORMAT,
    NETWORKS_CSV_FORMAT,
    SAVED_FILTERS_CSV_FORMAT,
    CsvParseResult,
    CsvRow,
    export_csv,
    export_networks_csv,
    parse_csv,
    parse_networks_csv,
)

# ---------------------------------------------------------------------------
# Parsing nominal
# ---------------------------------------------------------------------------


class TestParseNominal:
    def test_three_valid_lines_produce_three_rows(self) -> None:
        content = (
            "192.168.10.0/24;vlan-bureau\n10.0.0.0/8;lan-interne\n100.64.0.0/10;tailscale-mesh\n"
        )

        result = parse_networks_csv(content)

        assert result.errors == []
        assert result.duplicates == []
        assert len(result.rows) == 3
        assert result.rows[0] == CsvRow(line=1, cidr="192.168.10.0/24", name="vlan-bureau")
        assert result.rows[1] == CsvRow(line=2, cidr="10.0.0.0/8", name="lan-interne")
        assert result.rows[2] == CsvRow(line=3, cidr="100.64.0.0/10", name="tailscale-mesh")

    def test_comma_separator_accepted_when_no_semicolon(self) -> None:
        content = "192.168.10.0/24,vlan-bureau\n10.0.0.0/8,lan-interne\n"

        result = parse_networks_csv(content)

        assert result.errors == []
        assert len(result.rows) == 2
        assert result.rows[0] == CsvRow(line=1, cidr="192.168.10.0/24", name="vlan-bureau")
        assert result.rows[1] == CsvRow(line=2, cidr="10.0.0.0/8", name="lan-interne")

    def test_semicolon_wins_over_comma_when_both_present_on_line(self) -> None:
        # Le séparateur demandé est `;` : une ligne qui en contient un l'utilise,
        # même si la désignation contient elle-même une virgule.
        content = "192.168.10.0/24;bureau, annexe\n"

        result = parse_networks_csv(content)

        assert result.errors == []
        assert result.rows == [CsvRow(line=1, cidr="192.168.10.0/24", name="bureau, annexe")]


# ---------------------------------------------------------------------------
# Tolérance de forme
# ---------------------------------------------------------------------------


class TestToleranceDeForme:
    def test_blank_lines_and_comments_are_ignored(self) -> None:
        content = (
            "# plan d'adressage homelab\n"
            "\n"
            "192.168.10.0/24;vlan-bureau\n"
            "   \n"
            "# commentaire au milieu\n"
            "10.0.0.0/8;lan-interne\n"
        )

        result = parse_networks_csv(content)

        assert result.errors == []
        assert len(result.rows) == 2

    def test_header_line_is_ignored_when_first_field_not_a_cidr(self) -> None:
        content = "ip/cidr;designation\n192.168.10.0/24;vlan-bureau\n"

        result = parse_networks_csv(content)

        assert result.errors == []
        assert result.rows == [CsvRow(line=2, cidr="192.168.10.0/24", name="vlan-bureau")]

    def test_surrounding_whitespace_is_stripped(self) -> None:
        content = "  192.168.10.0/24  ;   vlan-bureau  \n"

        result = parse_networks_csv(content)

        assert result.errors == []
        assert result.rows == [CsvRow(line=1, cidr="192.168.10.0/24", name="vlan-bureau")]

    def test_windows_line_endings_are_tolerated(self) -> None:
        content = "192.168.10.0/24;vlan-bureau\r\n10.0.0.0/8;lan-interne\r\n"

        result = parse_networks_csv(content)

        assert result.errors == []
        assert len(result.rows) == 2
        assert result.rows[0].cidr == "192.168.10.0/24"
        assert result.rows[1].cidr == "10.0.0.0/8"

    def test_utf8_bom_is_stripped(self) -> None:
        content = "﻿192.168.10.0/24;vlan-bureau\n"

        result = parse_networks_csv(content)

        assert result.errors == []
        assert result.rows == [CsvRow(line=1, cidr="192.168.10.0/24", name="vlan-bureau")]


# ---------------------------------------------------------------------------
# Normalisation CIDR
# ---------------------------------------------------------------------------


class TestNormalisationCidr:
    def test_bare_ip_is_normalized_to_slash_32(self) -> None:
        content = "192.168.1.5;poste-fixe\n"

        result = parse_networks_csv(content)

        assert result.errors == []
        assert result.rows == [CsvRow(line=1, cidr="192.168.1.5/32", name="poste-fixe")]

    def test_cidr_with_nonzero_host_bits_is_normalized_not_rejected(self) -> None:
        content = "192.168.1.1/24;vlan-bureau\n"

        result = parse_networks_csv(content)

        assert result.errors == []
        # ipaddress.ip_network(..., strict=False) ramène au réseau : 192.168.1.0/24
        assert result.rows == [CsvRow(line=1, cidr="192.168.1.0/24", name="vlan-bureau")]

    def test_ipv6_cidr_is_accepted(self) -> None:
        content = "2001:db8::/32;ipv6-lab\n"

        result = parse_networks_csv(content)

        assert result.errors == []
        assert result.rows == [CsvRow(line=1, cidr="2001:db8::/32", name="ipv6-lab")]

    def test_bare_ipv6_is_normalized_to_slash_128(self) -> None:
        content = "2001:db8::1;hote-v6\n"

        result = parse_networks_csv(content)

        assert result.errors == []
        assert result.rows == [CsvRow(line=1, cidr="2001:db8::1/128", name="hote-v6")]


# ---------------------------------------------------------------------------
# Validation — erreurs avec numéro de ligne
# ---------------------------------------------------------------------------


class TestValidationErreurs:
    def test_invalid_cidr_reports_line_number(self) -> None:
        content = "192.168.10.0/24;vlan-bureau\nnot-a-cidr;bad-line\n"

        result = parse_networks_csv(content)

        assert result.rows == []  # tout ou rien
        assert len(result.errors) == 1
        assert "2" in result.errors[0]
        assert "not-a-cidr" in result.errors[0]

    def test_empty_designation_reports_line_number(self) -> None:
        content = "192.168.10.0/24;\n"

        result = parse_networks_csv(content)

        assert result.rows == []
        assert len(result.errors) == 1
        assert "1" in result.errors[0]

    def test_designation_too_long_reports_line_number(self) -> None:
        long_name = "x" * 300
        content = f"192.168.10.0/24;{long_name}\n"

        result = parse_networks_csv(content)

        assert result.rows == []
        assert len(result.errors) == 1
        assert "1" in result.errors[0]

    def test_duplicate_cidr_within_file_is_reported(self) -> None:
        content = "192.168.10.0/24;vlan-bureau\n192.168.10.0/24;vlan-bureau-bis\n"

        result = parse_networks_csv(content)

        assert result.rows == []  # tout ou rien
        assert len(result.duplicates) == 1
        assert "192.168.10.0/24" in result.duplicates[0]

    def test_duplicate_after_normalization_is_detected(self) -> None:
        # 192.168.1.1/24 et 192.168.1.2/24 se normalisent tous deux en
        # 192.168.1.0/24 : c'est bien un doublon après normalisation.
        content = "192.168.1.1/24;a\n192.168.1.2/24;b\n"

        result = parse_networks_csv(content)

        assert result.rows == []
        assert len(result.duplicates) == 1


# ---------------------------------------------------------------------------
# Tout ou rien
# ---------------------------------------------------------------------------


class TestToutOuRien:
    def test_single_invalid_line_among_many_valid_imports_nothing(self) -> None:
        content = (
            "192.168.10.0/24;vlan-bureau\n"
            "10.0.0.0/8;lan-interne\n"
            "not-a-cidr;bad-line\n"
            "172.16.0.0/12;vlan-lab\n"
        )

        result = parse_networks_csv(content)

        assert result.rows == []
        assert len(result.errors) == 1

    def test_all_valid_lines_still_returned_when_only_error_is_a_duplicate(self) -> None:
        # Même un SEUL doublon bloque tout : aucune ligne valide n'est retournée.
        content = "192.168.10.0/24;a\n10.0.0.0/8;b\n192.168.10.0/24;c\n"

        result = parse_networks_csv(content)

        assert result.rows == []


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


class TestExport:
    def test_export_then_parse_round_trip_preserves_data(self) -> None:
        networks = {
            "100.64.0.0/10": "tailscale-mesh",
            "192.168.1.0/24": "lan-maison",
        }

        csv_content = export_networks_csv(networks)
        result = parse_networks_csv(csv_content)

        assert result.errors == []
        assert {(row.cidr, row.name) for row in result.rows} == {
            ("100.64.0.0/10", "tailscale-mesh"),
            ("192.168.1.0/24", "lan-maison"),
        }

    def test_export_empty_plan_produces_valid_non_error_csv(self) -> None:
        csv_content = export_networks_csv({})

        assert isinstance(csv_content, str)
        # Ré-analysable sans erreur : soit vide, soit uniquement un en-tête.
        result = parse_networks_csv(csv_content)
        assert isinstance(result, CsvParseResult)
        assert result.errors == []
        assert result.rows == []

    def test_export_uses_semicolon_separator(self) -> None:
        csv_content = export_networks_csv({"10.0.0.0/8": "lan"})

        # Le format demandé est `ip/cidr;designation`.
        assert any(";" in line for line in csv_content.splitlines() if line.strip())

    def test_export_supports_mixed_ipv4_and_ipv6_plan(self) -> None:
        """Un plan mêlant IPv4 et IPv6 doit s'exporter, pas planter.

        DÉFAUT VÉCU (2026-08-06) : le tri passait `ip_network` directement en
        clé de `sorted`, or Python refuse de comparer un réseau IPv4 à un
        réseau IPv6 (`TypeError: not of the same version`). Le défaut était
        ASYMÉTRIQUE et donc particulièrement traître : l'import ACCEPTAIT
        l'IPv6 sans broncher, puis l'export plantait en 500 sur le plan que
        l'application venait elle-même d'accepter. Cas réel : Tailscale
        distribue un préfixe IPv6 en plus du préfixe CGNAT IPv4.
        """
        networks = {
            "100.64.0.0/10": "tailscale-mesh",
            "fd7a:115c:a1e0::/48": "tailscale-mesh-v6",
            "192.168.1.0/24": "lan-maison",
        }

        csv_content = export_networks_csv(networks)

        # Aller-retour complet : ce qui sort doit se ré-importer à l'identique.
        result = parse_networks_csv(csv_content)
        assert result.errors == []
        assert {(row.cidr, row.name) for row in result.rows} == set(networks.items())

        # L'IPv4 précède l'IPv6, et l'ordre reste stable (rendu diffable).
        exported_cidrs = [row.cidr for row in result.rows]
        assert exported_cidrs == ["100.64.0.0/10", "192.168.1.0/24", "fd7a:115c:a1e0::/48"]


# ---------------------------------------------------------------------------
# Sécurité — injection
# ---------------------------------------------------------------------------


class TestInjection:
    def test_html_in_designation_is_stored_literally(self) -> None:
        content = "192.168.10.0/24;<script>alert(1)</script>\n"

        result = parse_networks_csv(content)

        assert result.errors == []
        assert result.rows == [
            CsvRow(line=1, cidr="192.168.10.0/24", name="<script>alert(1)</script>")
        ]
        # Le parsing lui-même ne doit JAMAIS échapper : c'est le rendu (Jinja2
        # autoescape) qui échappe à l'affichage, pas cette couche de parsing.


# ---------------------------------------------------------------------------
# Socle générique — le cas `networks` passe par le MÊME code que les autres
# ---------------------------------------------------------------------------


class TestSocleGenerique:
    """`parse_networks_csv` doit être un simple cas particulier de `parse_csv`.

    Si ces deux chemins divergeaient, on retomberait sur trois copies du
    parseur à maintenir en parallèle — la dérive que la généralisation vise
    précisément à empêcher.
    """

    def test_parse_networks_csv_equivaut_a_parse_csv_avec_le_format_networks(self) -> None:
        content = "192.168.10.0/24;vlan-bureau\n10.0.0.0/8;lan-interne\n"

        assert parse_networks_csv(content) == parse_csv(content, NETWORKS_CSV_FORMAT)

    def test_export_networks_csv_equivaut_a_export_csv_avec_le_format_networks(self) -> None:
        networks = {"100.64.0.0/10": "tailscale-mesh", "192.168.1.0/24": "lan-maison"}

        assert export_networks_csv(networks) == export_csv(networks, NETWORKS_CSV_FORMAT)

    def test_csvrow_expose_des_alias_generiques_key_et_value(self) -> None:
        """Le socle manipule (clé, valeur) ; `cidr`/`name` restent les noms
        historiques du cas `networks` dont dépendent routes et templates."""
        result = parse_csv("192.168.10.0/24;vlan-bureau\n", NETWORKS_CSV_FORMAT)

        row = result.rows[0]
        assert (row.key, row.value) == ("192.168.10.0/24", "vlan-bureau")
        assert (row.cidr, row.name) == ("192.168.10.0/24", "vlan-bureau")


# ---------------------------------------------------------------------------
# Forme 1 — mapping clé -> valeur scalaire (`asns` : numéro d'AS -> nom)
# ---------------------------------------------------------------------------


class TestFormeMappingAsns:
    def test_lignes_valides_donnent_des_rows_avec_asn_normalise(self) -> None:
        content = "64501;ACME Corporation\n64502;Beta Telecom\n"

        result = parse_csv(content, ASNS_CSV_FORMAT)

        assert result.errors == []
        assert result.duplicates == []
        assert [(row.line, row.key, row.value) for row in result.rows] == [
            (1, "64501", "ACME Corporation"),
            (2, "64502", "Beta Telecom"),
        ]

    def test_espaces_et_zeros_en_tete_sont_normalises(self) -> None:
        # « 064501 » et « 64501 » désignent le même AS : la normalisation doit
        # passer par l'entier, sinon le doublon ci-dessous échapperait.
        content = "  064501  ;  ACME Corporation  \n"

        result = parse_csv(content, ASNS_CSV_FORMAT)

        assert result.errors == []
        assert result.rows == [CsvRow(line=1, cidr="64501", name="ACME Corporation")]

    def test_entete_connue_est_ignoree(self) -> None:
        content = "numero;nom\n64501;ACME Corporation\n"

        result = parse_csv(content, ASNS_CSV_FORMAT)

        assert result.errors == []
        assert [row.key for row in result.rows] == ["64501"]

    def test_virgule_acceptee_si_pas_de_point_virgule(self) -> None:
        content = "64501,ACME Corporation\n"

        result = parse_csv(content, ASNS_CSV_FORMAT)

        assert result.errors == []
        assert result.rows == [CsvRow(line=1, cidr="64501", name="ACME Corporation")]

    @pytest.mark.parametrize("bad_asn", ["0", "-1", "not-a-number", "4294967296", "1.5"])
    def test_asn_invalide_est_rejete(self, bad_asn: str) -> None:
        content = f"{bad_asn};un nom\n"

        result = parse_csv(content, ASNS_CSV_FORMAT)

        assert result.rows == []
        assert len(result.errors) == 1
        assert bad_asn in result.errors[0]

    def test_borne_haute_32_bits_est_acceptee(self) -> None:
        # 4294967295 = dernier AS 32 bits valide (RFC 6793) : la borne exclut
        # ce qui la dépasse, jamais elle-même.
        result = parse_csv("4294967295;as-32-bits-max\n", ASNS_CSV_FORMAT)

        assert result.errors == []
        assert result.rows == [CsvRow(line=1, cidr="4294967295", name="as-32-bits-max")]

    def test_nom_vide_est_rejete(self) -> None:
        result = parse_csv("64501;\n", ASNS_CSV_FORMAT)

        assert result.rows == []
        assert len(result.errors) == 1
        assert "1" in result.errors[0]

    def test_nom_trop_long_est_rejete(self) -> None:
        result = parse_csv(f"64501;{'x' * 300}\n", ASNS_CSV_FORMAT)

        assert result.rows == []
        assert len(result.errors) == 1

    def test_doublon_apres_normalisation_est_remonte_separement(self) -> None:
        content = "64501;ACME Corporation\n064501;ACME bis\n"

        result = parse_csv(content, ASNS_CSV_FORMAT)

        assert result.rows == []  # tout ou rien
        assert result.errors == []  # un doublon n'est pas une erreur de format
        assert len(result.duplicates) == 1
        assert "64501" in result.duplicates[0]

    def test_une_seule_ligne_fautive_annule_tout_l_import(self) -> None:
        content = "64501;ACME Corporation\n0;as-invalide\n64502;Beta Telecom\n"

        result = parse_csv(content, ASNS_CSV_FORMAT)

        assert result.rows == []
        assert len(result.errors) == 1

    def test_export_trie_numeriquement_et_pas_lexicographiquement(self) -> None:
        """Un tri lexicographique placerait « 100 » avant « 64501 ».

        Les clés d'AS arrivent en `int` depuis le YAML : le tri doit être total
        sur des clés hétérogènes (`int` comme `str`), jamais un `sorted` naïf
        qui comparerait un `int` à un `str` (`TypeError`).
        """
        asns: dict[int | str, str] = {64501: "ACME", "100": "Cent", 3: "Trois"}

        exported = export_csv(asns, ASNS_CSV_FORMAT)

        result = parse_csv(exported, ASNS_CSV_FORMAT)
        assert result.errors == []
        assert [row.key for row in result.rows] == ["3", "100", "64501"]

    def test_aller_retour_export_puis_parse_preserve_les_donnees(self) -> None:
        asns = {64501: "ACME Corporation", 64502: "Beta Telecom"}

        result = parse_csv(export_csv(asns, ASNS_CSV_FORMAT), ASNS_CSV_FORMAT)

        assert result.errors == []
        assert {(row.key, row.value) for row in result.rows} == {
            ("64501", "ACME Corporation"),
            ("64502", "Beta Telecom"),
        }

    def test_export_vide_produit_un_csv_valide_sans_donnee(self) -> None:
        exported = export_csv({}, ASNS_CSV_FORMAT)

        result = parse_csv(exported, ASNS_CSV_FORMAT)
        assert result.errors == []
        assert result.rows == []


# ---------------------------------------------------------------------------
# Forme 2 — liste d'objets à 2 champs (`saved_filters`)
# ---------------------------------------------------------------------------


class TestFormePairsSavedFilters:
    def test_description_et_expression_sont_extraites(self) -> None:
        content = "Flux proxy-frontal;ExporterName = 'proxy-frontal'\n"

        result = parse_csv(content, SAVED_FILTERS_CSV_FORMAT)

        assert result.errors == []
        assert result.rows == [
            CsvRow(line=1, cidr="Flux proxy-frontal", name="ExporterName = 'proxy-frontal'")
        ]

    def test_expression_avec_egal_espaces_quotes_et_virgules_passe_litteralement(self) -> None:
        """Le `;` reste le séparateur ; tout le reste est du contenu.

        Une expression de filtre Akvorado contient couramment `=`, des espaces,
        des quotes simples et des virgules (`InIfBoundary = 'external'`,
        `SrcAS IN (64501, 64502)`) : découper sur la virgule tronquerait
        l'expression au milieu et produirait un filtre silencieusement faux.
        """
        content = "AS clients;SrcAS IN (64501, 64502) AND InIfBoundary = 'external'\n"

        result = parse_csv(content, SAVED_FILTERS_CSV_FORMAT)

        assert result.errors == []
        assert result.rows[0].value == "SrcAS IN (64501, 64502) AND InIfBoundary = 'external'"

    def test_expression_contenant_un_point_virgule_litteral_n_est_pas_tronquee(self) -> None:
        """DÉFAUT MESURÉ (2026-08-06) : une expression était amputée en silence.

        `csv.reader` ne protège le séparateur que dans des GUILLEMETS DOUBLES ;
        or une expression Akvorado cite en guillemets SIMPLES
        (`ExporterName = 'a;b'`). Le découpage produisait donc 3 champs, seuls
        les 2 premiers étaient lus, et l'expression `a = 'x;y'` était stockée
        comme `a = 'x` — un filtre syntaxiquement faux, accepté avec
        `errors=[]`. Le contrat « tout ou rien » ne protège de rien si la perte
        se produit AVANT la validation.

        La description ne pouvant pas contenir de séparateur sans ambiguïté,
        seule la PREMIÈRE occurrence sépare : tout ce qui suit est l'expression.
        """
        content = "Filtre quote;ExporterName = 'a;b' AND InIf = 2\n"

        result = parse_csv(content, SAVED_FILTERS_CSV_FORMAT)

        assert result.errors == []
        assert result.rows[0].key == "Filtre quote"
        assert result.rows[0].value == "ExporterName = 'a;b' AND InIf = 2"

    def test_aller_retour_preserve_une_expression_contenant_un_point_virgule(self) -> None:
        value = [{"description": "Filtre quote", "content": "ExporterName = 'a;b'"}]

        result = parse_csv(export_csv(value, SAVED_FILTERS_CSV_FORMAT), SAVED_FILTERS_CSV_FORMAT)

        assert result.errors == []
        assert result.rows[0].value == "ExporterName = 'a;b'"

    def test_export_neutralise_le_separateur_dans_la_description(self) -> None:
        """DÉFAUT MESURÉ (2026-08-06) : du texte migrait description -> expression.

        La relecture découpant sur la 1re occurrence du séparateur, une
        description contenant un `;` produisait `desc;piegee;expression`, relu
        comme description=`desc` et expression=`piegee;expression` — à chaque
        aller-retour export/import, et avec `errors=[]`.

        L'export neutralise le `;` de la DESCRIPTION (un libellé, sa ponctuation
        n'a aucune portée fonctionnelle) et ne touche JAMAIS à l'expression, qui
        porte la sémantique du filtre.
        """
        value = [{"description": "desc;piegee", "content": "a = 'x;y'"}]

        result = parse_csv(export_csv(value, SAVED_FILTERS_CSV_FORMAT), SAVED_FILTERS_CSV_FORMAT)

        assert result.errors == []
        assert result.rows[0].key == "desc,piegee"
        assert result.rows[0].value == "a = 'x;y'", "l'expression ne doit jamais être réécrite"

    def test_deux_descriptions_identiques_sont_un_doublon(self) -> None:
        content = "Flux proxy-frontal;ExporterName = 'a'\nFlux proxy-frontal;ExporterName = 'b'\n"

        result = parse_csv(content, SAVED_FILTERS_CSV_FORMAT)

        assert result.rows == []
        assert result.errors == []
        assert len(result.duplicates) == 1
        assert "Flux proxy-frontal" in result.duplicates[0]

    def test_entete_connue_est_ignoree(self) -> None:
        content = "description;expression\nFlux proxy-frontal;ExporterName = 'proxy-frontal'\n"

        result = parse_csv(content, SAVED_FILTERS_CSV_FORMAT)

        assert result.errors == []
        assert [row.key for row in result.rows] == ["Flux proxy-frontal"]

    def test_description_vide_est_rejetee(self) -> None:
        result = parse_csv(";ExporterName = 'proxy-frontal'\n", SAVED_FILTERS_CSV_FORMAT)

        assert result.rows == []
        assert len(result.errors) == 1

    def test_expression_vide_est_rejetee(self) -> None:
        result = parse_csv("Flux proxy-frontal;\n", SAVED_FILTERS_CSV_FORMAT)

        assert result.rows == []
        assert len(result.errors) == 1

    def test_expression_trop_longue_est_rejetee_au_dela_de_1024(self) -> None:
        result = parse_csv(f"Un filtre;{'x' * 1025}\n", SAVED_FILTERS_CSV_FORMAT)

        assert result.rows == []
        assert len(result.errors) == 1

    def test_expression_longue_mais_sous_la_borne_est_acceptee(self) -> None:
        """Une expression de filtre est longue par nature : la borne des 128
        caractères d'une désignation la refuserait à tort."""
        expression = "x" * 1024

        result = parse_csv(f"Un filtre;{expression}\n", SAVED_FILTERS_CSV_FORMAT)

        assert result.errors == []
        assert result.rows[0].value == expression

    def test_export_serialise_la_liste_d_objets(self) -> None:
        value = [
            {"description": "Flux proxy-frontal", "content": "ExporterName = 'proxy-frontal'"},
            {"description": "AS clients", "content": "SrcAS IN (64501, 64502)"},
        ]

        exported = export_csv(value, SAVED_FILTERS_CSV_FORMAT)

        result = parse_csv(exported, SAVED_FILTERS_CSV_FORMAT)
        assert result.errors == []
        assert [(row.key, row.value) for row in result.rows] == [
            ("Flux proxy-frontal", "ExporterName = 'proxy-frontal'"),
            ("AS clients", "SrcAS IN (64501, 64502)"),
        ]

    def test_export_preserve_l_ordre_de_la_liste(self) -> None:
        """Une liste ordonnée par l'utilisateur ne doit pas être triée : l'ordre
        des filtres enregistrés est significatif dans la console Akvorado."""
        value = [
            {"description": "zzz", "content": "a = 1"},
            {"description": "aaa", "content": "b = 2"},
        ]

        result = parse_csv(export_csv(value, SAVED_FILTERS_CSV_FORMAT), SAVED_FILTERS_CSV_FORMAT)

        assert [row.key for row in result.rows] == ["zzz", "aaa"]

    def test_export_vide_produit_un_csv_valide_sans_donnee(self) -> None:
        result = parse_csv(export_csv([], SAVED_FILTERS_CSV_FORMAT), SAVED_FILTERS_CSV_FORMAT)

        assert result.errors == []
        assert result.rows == []

    def test_html_dans_l_expression_est_stocke_litteralement(self) -> None:
        content = "Filtre piégé;<script>alert(1)</script>\n"

        result = parse_csv(content, SAVED_FILTERS_CSV_FORMAT)

        assert result.errors == []
        assert result.rows[0].value == "<script>alert(1)</script>"


# ---------------------------------------------------------------------------
# Forme 3 — liste de chaînes (`exporter_classifiers`)
# ---------------------------------------------------------------------------


class TestFormeLinesExporterClassifiers:
    def test_une_expression_par_ligne(self) -> None:
        content = 'ClassifyRegion("homelab")\nClassifyTenant("example")\n'

        result = parse_csv(content, EXPORTER_CLASSIFIERS_CSV_FORMAT)

        assert result.errors == []
        assert result.duplicates == []
        assert [(row.line, row.value) for row in result.rows] == [
            (1, 'ClassifyRegion("homelab")'),
            (2, 'ClassifyTenant("example")'),
        ]

    def test_point_virgule_dans_l_expression_n_est_pas_un_separateur(self) -> None:
        """Forme sans séparateur : la ligne ENTIÈRE est l'expression.

        Un découpage sur `;` (hérité du socle mapping) amputerait une
        expression qui en contient un et produirait un classifieur invalide
        accepté sans erreur — exactement le genre de perte silencieuse que le
        tout-ou-rien est censé empêcher.
        """
        content = 'ClassifyRegion("a;b")\n'

        result = parse_csv(content, EXPORTER_CLASSIFIERS_CSV_FORMAT)

        assert result.errors == []
        assert result.rows[0].value == 'ClassifyRegion("a;b")'

    def test_virgule_dans_l_expression_n_est_pas_un_separateur(self) -> None:
        content = 'ClassifyRegion("eu", "west")\n'

        result = parse_csv(content, EXPORTER_CLASSIFIERS_CSV_FORMAT)

        assert result.errors == []
        assert result.rows[0].value == 'ClassifyRegion("eu", "west")'

    def test_lignes_vides_et_commentaires_sont_ignores(self) -> None:
        content = '# classifieurs\n\nClassifyRegion("homelab")\n   \n'

        result = parse_csv(content, EXPORTER_CLASSIFIERS_CSV_FORMAT)

        assert result.errors == []
        assert [row.value for row in result.rows] == ['ClassifyRegion("homelab")']

    def test_entete_connue_est_ignoree(self) -> None:
        content = 'expression\nClassifyRegion("homelab")\n'

        result = parse_csv(content, EXPORTER_CLASSIFIERS_CSV_FORMAT)

        assert result.errors == []
        assert [row.value for row in result.rows] == ['ClassifyRegion("homelab")']

    def test_une_ligne_ressemblant_a_une_expression_n_est_jamais_prise_pour_un_entete(
        self,
    ) -> None:
        """Piège vécu : une heuristique négative avale une vraie donnée.

        Ici la 1re ligne est une expression légitime : elle doit être importée,
        pas ignorée comme « en-tête ».
        """
        result = parse_csv('ClassifyRegion("homelab")\n', EXPORTER_CLASSIFIERS_CSV_FORMAT)

        assert result.errors == []
        assert len(result.rows) == 1

    def test_doublon_d_expression_est_remonte(self) -> None:
        content = 'ClassifyRegion("homelab")\nClassifyRegion("homelab")\n'

        result = parse_csv(content, EXPORTER_CLASSIFIERS_CSV_FORMAT)

        assert result.rows == []
        assert result.errors == []
        assert len(result.duplicates) == 1

    def test_expression_trop_longue_est_rejetee(self) -> None:
        result = parse_csv("x" * 1025 + "\n", EXPORTER_CLASSIFIERS_CSV_FORMAT)

        assert result.rows == []
        assert len(result.errors) == 1

    def test_bom_et_crlf_sont_toleres(self) -> None:
        content = '﻿ClassifyRegion("homelab")\r\nClassifyTenant("example")\r\n'

        result = parse_csv(content, EXPORTER_CLASSIFIERS_CSV_FORMAT)

        assert result.errors == []
        assert [row.value for row in result.rows] == [
            'ClassifyRegion("homelab")',
            'ClassifyTenant("example")',
        ]

    def test_export_preserve_l_ordre_des_classifieurs(self) -> None:
        """L'ordre des classifieurs est significatif : Akvorado les applique en
        séquence, un tri alphabétique changerait la classification produite."""
        value = ['ClassifyTenant("example")', 'ClassifyRegion("homelab")']

        result = parse_csv(
            export_csv(value, EXPORTER_CLASSIFIERS_CSV_FORMAT), EXPORTER_CLASSIFIERS_CSV_FORMAT
        )

        assert result.errors == []
        assert [row.value for row in result.rows] == value

    def test_export_vide_produit_un_csv_valide_sans_donnee(self) -> None:
        result = parse_csv(
            export_csv([], EXPORTER_CLASSIFIERS_CSV_FORMAT), EXPORTER_CLASSIFIERS_CSV_FORMAT
        )

        assert result.errors == []
        assert result.rows == []


# ---------------------------------------------------------------------------
# Zéro silencieux — un CSV vide n'est pas un CSV en erreur
# ---------------------------------------------------------------------------


class TestZeroSilencieux:
    """`rows=[]` a DEUX causes distinctes que l'appelant doit pouvoir séparer :
    « CSV valide mais sans donnée » (errors=[]) et « CSV refusé » (errors≠[]).
    Les fusionner ferait passer un import destructeur pour un import à vide.
    """

    @pytest.mark.parametrize(
        "fmt",
        [
            NETWORKS_CSV_FORMAT,
            ASNS_CSV_FORMAT,
            SAVED_FILTERS_CSV_FORMAT,
            EXPORTER_CLASSIFIERS_CSV_FORMAT,
        ],
    )
    def test_csv_sans_donnee_est_un_succes_vide_pas_une_erreur(self, fmt: object) -> None:
        result = parse_csv("# rien que des commentaires\n\n", fmt)  # type: ignore[arg-type]

        assert isinstance(result, CsvParseResult)
        assert result.rows == []
        assert result.errors == []
        assert result.duplicates == []

    @pytest.mark.parametrize(
        ("fmt", "content"),
        [
            (NETWORKS_CSV_FORMAT, "pas-un-cidr;x\n"),
            (ASNS_CSV_FORMAT, "pas-un-as;x\n"),
            (SAVED_FILTERS_CSV_FORMAT, "description-sans-expression\n"),
            (EXPORTER_CLASSIFIERS_CSV_FORMAT, "x" * 2000 + "\n"),
        ],
    )
    def test_csv_refuse_a_des_erreurs_non_vides(self, fmt: object, content: str) -> None:
        result = parse_csv(content, fmt)  # type: ignore[arg-type]

        assert result.rows == []
        assert result.errors != [], "un refus doit être distinguable d'un CSV vide"


# ---------------------------------------------------------------------------
# Routes HTTP — import (preview + confirm) et export
# ---------------------------------------------------------------------------


@pytest.fixture
def memory_conn() -> Generator[sqlite3.Connection]:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    try:
        yield conn
    finally:
        conn.close()


_OUTLET_YAML = """\
networks:
  networks:
    100.64.0.0/10:
      name: tailscale-mesh
      role: internal
      tenant: homelab
    192.168.1.0/24:
      name: lan-maison
      role: lan
      tenant: homelab
core:
  exporter-classifiers:
    - ClassifyRegion("homelab")
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
  saved-filters: []
"""

_INLET_YAML = """\
flow:
  inputs:
    - type: udp
      decoder: netflow
      listen: 0.0.0.0:2055
"""


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    (tmp_path / "outlet.yaml").write_text(_OUTLET_YAML)
    (tmp_path / "akvorado.yaml").write_text(_AKVORADO_YAML)
    (tmp_path / "console.yaml").write_text(_CONSOLE_YAML)
    (tmp_path / "inlet.yaml").write_text(_INLET_YAML)
    return tmp_path


def _make_app(conn: sqlite3.Connection, config_dir_path: str) -> FastAPI:
    from app.routers import config_sections as sections_router

    app = FastAPI()
    app.include_router(sections_router.router)
    app.dependency_overrides[sections_router.get_db_connection] = lambda: conn
    app.dependency_overrides[sections_router.get_config_dir] = lambda: config_dir_path
    return app


def _client(conn: sqlite3.Connection, config_dir_path: str) -> TestClient:
    return TestClient(_make_app(conn, config_dir_path))


class TestImportRoutePreview:
    def test_valid_csv_pasted_returns_preview_without_staging_anything(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks/import",
            data={"csv_text": "10.42.0.0/16;labo\n192.168.10.0/24;vlan-bureau\n"},
        )

        assert response.status_code == 200
        assert "labo" in response.text
        assert "vlan-bureau" in response.text
        assert "2 ajout" in response.text
        # Aucune mise en file avant confirmation explicite.
        assert list_pending_changes(memory_conn) == []

    def test_preview_reports_updates_vs_unchanged(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks/import",
            data={
                "csv_text": (
                    "100.64.0.0/10;tailscale-mesh\n"  # inchangé
                    "192.168.1.0/24;lan-maison-renomme\n"  # mise à jour
                )
            },
        )

        assert response.status_code == 200
        assert "1 ajout" not in response.text or "0 ajout" in response.text
        assert "1 mise" in response.text
        assert "1 inchangé" in response.text
        assert list_pending_changes(memory_conn) == []

    def test_invalid_csv_returns_errors_with_line_number_and_stages_nothing(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks/import",
            data={"csv_text": "10.42.0.0/16;labo\nnot-a-cidr;bad\n"},
        )

        assert response.status_code == 422
        assert "2" in response.text
        assert list_pending_changes(memory_conn) == []

    def test_uploaded_file_takes_precedence_over_pasted_text(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks/import",
            data={"csv_text": "10.99.0.0/16;depuis-texte\n"},
            files={"csv_file": ("plan.csv", b"10.42.0.0/16;depuis-fichier\n", "text/csv")},
        )

        assert response.status_code == 200
        assert "depuis-fichier" in response.text
        assert "depuis-texte" not in response.text

    def test_html_in_designation_is_escaped_in_preview(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks/import",
            data={"csv_text": "10.42.0.0/16;<script>alert(1)</script>\n"},
        )

        assert response.status_code == 200
        assert "<script>alert(1)</script>" not in response.text
        assert "&lt;script&gt;" in response.text

    def test_file_over_size_limit_is_explicitly_refused(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))
        oversized = b"10.0.0.0/8;x\n" * 100_000  # bien au-dessus d'1 Mo

        response = client.post(
            "/config/sections/networks/import",
            files={"csv_file": ("big.csv", oversized, "text/csv")},
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []

    def test_empty_content_is_rejected(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post("/config/sections/networks/import", data={"csv_text": "   "})

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []


class TestImportRouteConfirm:
    def test_confirm_merges_with_existing_by_default(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks/import",
            data={
                "mode": "confirm",
                "csv_text": "10.42.0.0/16;labo\n",
            },
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        value = pending[0].payload["value"]
        assert "10.42.0.0/16" in value
        # Fusion : les 2 réseaux existants sont conservés.
        assert "100.64.0.0/10" in value
        assert "192.168.1.0/24" in value

    def test_confirm_with_replace_drops_networks_not_in_csv(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks/import",
            data={
                "mode": "confirm",
                "replace": "true",
                "csv_text": "10.42.0.0/16;labo\n",
            },
        )

        assert response.status_code in (200, 201)
        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        value = pending[0].payload["value"]
        assert list(value.keys()) == ["10.42.0.0/16"]

    def test_confirm_with_invalid_csv_stages_nothing(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks/import",
            data={"mode": "confirm", "csv_text": "not-a-cidr;bad\n"},
        )

        assert response.status_code == 422
        assert list_pending_changes(memory_conn) == []


class TestExportRoute:
    def test_export_returns_csv_content_type_and_disposition(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        response = client.get("/config/sections/networks/export")

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        disposition = response.headers["content-disposition"]
        assert 'attachment; filename="plan-adressage.csv"' in disposition
        assert "tailscale-mesh" in response.text
        assert "lan-maison" in response.text

    def test_export_then_reimport_preview_shows_everything_unchanged(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        client = _client(memory_conn, str(config_dir))

        exported = client.get("/config/sections/networks/export")
        assert exported.status_code == 200

        response = client.post(
            "/config/sections/networks/import",
            data={"csv_text": exported.text},
        )

        assert response.status_code == 200
        assert "2 inchangé" in response.text
        assert list_pending_changes(memory_conn) == []


class TestImportPertesSilencieuses:
    """Défauts trouvés à la revue de diff (2026-08-06), tous PROUVÉS par
    exécution avant correction. Chacun avait le même profil : l'application
    répondait « succès » en détruisant de la configuration, sans rien afficher.
    """

    def test_csv_sans_donnee_avec_replace_ne_vide_pas_le_plan(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        """Un CSV de commentaires + « remplacer » effaçait TOUT le plan.

        `parse_networks_csv` retourne `rows=[]` ET `errors=[]` pour un contenu
        sans ligne de données : un succès pour le parseur. Avec `replace=true`,
        la valeur mise en file était `{}` — plan d'adressage vide — répondu en
        HTTP 201 avec « 0 ajout(s), 0 mise(s) à jour », libellé qui ne mentionne
        aucune suppression. Chemin réel : exporter, ouvrir dans un tableur, mal
        enregistrer, réimporter avec la case cochée.
        """
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks/import",
            data={
                "csv_text": "# export vide\n#\n",
                "mode": "confirm",
                "replace": "true",
            },
        )

        assert response.status_code == 422
        assert "aucune ligne de données" in response.text
        assert list_pending_changes(memory_conn) == [], (
            "un CSV sans données ne doit RIEN mettre en file, a fortiori pas "
            "un plan d'adressage vide"
        )

    def test_import_refuse_si_un_changement_networks_est_deja_en_file(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        """Un import écrasait un changement déjà en attente, silencieusement.

        `apply_pending_changes` applique « le dernier gagne » par clé pointée,
        et l'import pousse la valeur ENTIÈRE du plan recalculée depuis le
        DISQUE — donc sans ce qui est en file. Séquence mesurée : ajout manuel
        mis en file, puis import CSV, puis Appliquer → l'ajout manuel avait
        disparu, avec un apply en succès et aucun avertissement.
        """
        client = _client(memory_conn, str(config_dir))

        # 1) Un premier changement de section est mis en file.
        first = client.post(
            "/config/sections/networks/import",
            data={"csv_text": "10.99.0.0/16;ajout-initial\n", "mode": "confirm"},
        )
        assert first.status_code == 201
        assert len(list_pending_changes(memory_conn)) == 1

        # 2) Un second import doit REFUSER plutôt qu'écraser le premier.
        second = client.post(
            "/config/sections/networks/import",
            data={"csv_text": "10.42.0.0/16;via-csv\n", "mode": "confirm"},
        )

        assert second.status_code == 422
        # L'apostrophe est échappée par le rendu HTML (`&#x27;`) : on assert sur
        # la partie stable du message plutôt que sur une chaîne qui dépend de
        # l'échappement.
        assert "déjà en file" in second.text
        assert "écraserait" in second.text
        assert len(list_pending_changes(memory_conn)) == 1, (
            "le second import ne doit rien ajouter tant que le premier est en file"
        )

    def test_replace_conserve_role_et_tenant_des_reseaux_presents_dans_le_csv(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        """Le CSV décrit une désignation, pas une politique de classification.

        En mode remplacement, un réseau POURTANT PRÉSENT dans le CSV était
        recréé avec le seul champ `name` : ses `role` et `tenant` disparaissaient
        — alors que `role` pilote la classification interne/externe des flux
        dans Akvorado. La prévisualisation le classait « inchangé », le nom
        n'ayant pas bougé : rien n'alertait l'utilisateur.
        """
        client = _client(memory_conn, str(config_dir))

        response = client.post(
            "/config/sections/networks/import",
            data={
                "csv_text": "100.64.0.0/10;tailscale-mesh\n",
                "mode": "confirm",
                "replace": "true",
            },
        )
        assert response.status_code == 201

        pending = list_pending_changes(memory_conn)
        assert len(pending) == 1
        value = pending[0].payload["value"]

        entry = value["100.64.0.0/10"]
        assert entry["name"] == "tailscale-mesh"
        assert entry.get("role") == "internal", (
            "role perdu : la classification des flux du mesh basculerait"
        )
        assert entry.get("tenant") == "homelab", "tenant perdu"
        # Le remplacement reste un remplacement : ce qui n'est pas dans le CSV part.
        assert "192.168.1.0/24" not in value

    def test_mode_non_reconnu_previsualise_et_n_ecrit_jamais(
        self, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        """Seul le mode exactement « confirm » écrit.

        Le test portait sur `!= "confirm"` APRÈS `.strip().lower()` : une
        valeur comme « CONFIRM » était normalisée puis écrivait, alors qu'elle
        ne venait d'aucun formulaire de l'application. Un mode non reconnu doit
        prévisualiser, jamais mettre en file.
        """
        client = _client(memory_conn, str(config_dir))

        for mode in ("CONFIRM", " confirm ", "Confirm", "n-importe-quoi"):
            response = client.post(
                "/config/sections/networks/import",
                data={"csv_text": "10.42.0.0/16;labo\n", "mode": mode},
            )
            assert response.status_code == 200, f"mode {mode!r} aurait dû prévisualiser"
            assert list_pending_changes(memory_conn) == [], (
                f"mode {mode!r} a mis un changement en file alors qu'il n'est pas « confirm »"
            )
