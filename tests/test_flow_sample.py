"""Tests de la découverte des champs de flux (`app/services/flow_sample.py`).

Aucun test ici n'exige d'infra : le client ClickHouse est un double injecté.

LES FIXTURES REPRODUISENT LES TYPES PYTHON RÉELS DU DRIVER, pas des chaînes
commodes — piège vécu sur ce projet (des fixtures inventées ont fait diagnostiquer
3 faux défauts). Formes relevées le 2026-08-06 sur `default.flows` via
`system.columns` + un `SELECT ... LIMIT 5` sur la vraie base :

- `SrcAddr`/`DstAddr`/`ExporterAddress` : `IPv6` -> le driver rend un objet
  `IPv6Address`, avec les IPv4 MAPPÉES (`::ffff:198.51.100.25`) ;
- `SrcCountry`/`DstCountry` : `FixedString(2)` -> un pays inconnu revient bourré
  de NUL (`"\\x00\\x00"`), PAS en chaîne vide ;
- `DstASPath`/`DstCommunities`/`DstLargeCommunities` : `Array(...)` -> `list`,
  vide (`[]`) sur la quasi-totalité du trafic (pas de transit BGP) ;
- `TimeReceived` : `DateTime` -> objet `datetime` ;
- entiers (`SrcAS`, `SrcPort`, `Bytes`...) : `int`, avec `0` = « non renseigné » ;
- `InIfBoundary`/`FlowDirection` : `Enum8` -> chaîne (`"external"`, `"ingress"`).
"""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv6Address
from typing import Any

import pytest

from app.services.flow_sample import (
    DEFAULT_SAMPLE_LIMIT,
    EXPECTED_FLOW_COLUMN_COUNT,
    FLOW_COLUMNS,
    MAX_SAMPLE_LIMIT,
    MAX_SAMPLE_VALUES,
    FlowField,
    FlowSampleUnavailableError,
    build_flow_sample_query,
    fetch_flow_sample,
    format_display_address,
    search_fields,
    summarize_fields,
)

# Les 61 colonnes attendues, dans l'ordre de position mesuré sur la vraie table.
# 61 et non 60 : compté sur `system.columns` le 2026-08-06 (la spec annonçait 60
# tout en énumérant 61 noms — c'est la base qui fait foi, pas l'annonce).
EXPECTED_COLUMN_NAMES: tuple[str, ...] = (
    "TimeReceived",
    "SamplingRate",
    "ExporterAddress",
    "ExporterName",
    "ExporterGroup",
    "ExporterRole",
    "ExporterSite",
    "ExporterRegion",
    "ExporterTenant",
    "SrcAddr",
    "DstAddr",
    "SrcNetMask",
    "DstNetMask",
    "SrcNetPrefix",
    "DstNetPrefix",
    "SrcAS",
    "DstAS",
    "SrcNetName",
    "DstNetName",
    "SrcNetRole",
    "DstNetRole",
    "SrcNetSite",
    "DstNetSite",
    "SrcNetRegion",
    "DstNetRegion",
    "SrcNetTenant",
    "DstNetTenant",
    "SrcCountry",
    "DstCountry",
    "SrcGeoCity",
    "DstGeoCity",
    "SrcGeoState",
    "DstGeoState",
    "DstASPath",
    "Dst1stAS",
    "Dst2ndAS",
    "Dst3rdAS",
    "DstCommunities",
    "DstLargeCommunities",
    "InIfName",
    "OutIfName",
    "InIfDescription",
    "OutIfDescription",
    "InIfSpeed",
    "OutIfSpeed",
    "InIfConnectivity",
    "OutIfConnectivity",
    "InIfProvider",
    "OutIfProvider",
    "InIfBoundary",
    "OutIfBoundary",
    "EType",
    "Proto",
    "SrcPort",
    "DstPort",
    "Bytes",
    "Packets",
    "PacketSize",
    "PacketSizeBucket",
    "ForwardingStatus",
    "FlowDirection",
)


# ---------------------------------------------------------------------------
# Doubles de test : mêmes types que le driver réel
# ---------------------------------------------------------------------------


class FakeQueryResult:
    """Reproduit la surface de `QueryResult` utilisée par le module."""

    def __init__(self, column_names: list[str], result_rows: list[list[Any]]) -> None:
        self.column_names = column_names
        self.result_rows = result_rows


class FakeClient:
    """Client ClickHouse factice : enregistre l'appel, rend des lignes figées."""

    def __init__(self, column_names: list[str], result_rows: list[list[Any]]) -> None:
        self._column_names = column_names
        self._result_rows = result_rows
        self.calls: list[tuple[str, dict[str, int]]] = []

    def query(self, sql: str, parameters: dict[str, int] | None = None) -> FakeQueryResult:
        self.calls.append((sql, dict(parameters or {})))
        return FakeQueryResult(self._column_names, [list(row) for row in self._result_rows])


class FailingClient:
    """Client dont la requête échoue — simule une source non interrogeable."""

    def __init__(self, error: Exception | None = None) -> None:
        self._error = error or OSError("connection refused (simule pour le test)")

    def query(self, sql: str, parameters: dict[str, int] | None = None) -> FakeQueryResult:
        raise self._error


def _real_shaped_row(
    *,
    exporter_name: str = "proxy-frontal",
    exporter_address: str = "::ffff:192.0.2.17",
    src_addr: str = "::ffff:198.51.100.25",
    dst_addr: str = "::ffff:92.138.254.190",
    src_as: int = 0,
    dst_as: int = 3215,
    src_country: str = "\x00\x00",
    dst_country: str = "FR",
    in_if_name: str = "ens3",
    src_port: int = 443,
    dst_port: int = 60282,
    dst_as_path: list[int] | None = None,
    received: datetime | None = None,
) -> dict[str, Any]:
    """Une ligne d'échantillon aux TYPES du driver réel.

    Les adresses sont des `IPv6Address` (IPv4 mappées), les pays des
    `FixedString(2)` bourrées de NUL quand inconnues, les `Array(...)` des listes
    Python — exactement ce que rend `clickhouse-connect` sur cette table.
    """
    return {
        "TimeReceived": received or datetime(2026, 8, 6, 14, 10, 59),
        "SamplingRate": 1,
        "ExporterAddress": IPv6Address(exporter_address),
        "ExporterName": exporter_name,
        "ExporterGroup": "",
        "ExporterRole": "",
        "ExporterSite": "",
        "ExporterRegion": "",
        "ExporterTenant": "",
        "SrcAddr": IPv6Address(src_addr),
        "DstAddr": IPv6Address(dst_addr),
        "SrcNetMask": 0,
        "DstNetMask": 0,
        "SrcNetPrefix": "",
        "DstNetPrefix": "",
        "SrcAS": src_as,
        "DstAS": dst_as,
        "SrcNetName": "",
        "DstNetName": "",
        "SrcNetRole": "",
        "DstNetRole": "",
        "SrcNetSite": "",
        "DstNetSite": "",
        "SrcNetRegion": "",
        "DstNetRegion": "",
        "SrcNetTenant": "",
        "DstNetTenant": "",
        "SrcCountry": src_country,
        "DstCountry": dst_country,
        "SrcGeoCity": "",
        "DstGeoCity": "",
        "SrcGeoState": "",
        "DstGeoState": "",
        "DstASPath": list(dst_as_path or []),
        "Dst1stAS": 0,
        "Dst2ndAS": 0,
        "Dst3rdAS": 0,
        "DstCommunities": [],
        "DstLargeCommunities": [],
        "InIfName": in_if_name,
        "OutIfName": "",
        "InIfDescription": "",
        "OutIfDescription": "",
        "InIfSpeed": 0,
        "OutIfSpeed": 0,
        "InIfConnectivity": "",
        "OutIfConnectivity": "",
        "InIfProvider": "",
        "OutIfProvider": "",
        "InIfBoundary": "external",
        "OutIfBoundary": "undefined",
        "EType": 2048,
        "Proto": 6,
        "SrcPort": src_port,
        "DstPort": dst_port,
        "Bytes": 8586,
        "Packets": 12,
        "PacketSize": 715,
        "PacketSizeBucket": "1024-1279",
        "ForwardingStatus": 0,
        "FlowDirection": "egress",
    }


def _client_from_rows(rows: list[dict[str, Any]]) -> FakeClient:
    """Construit un client factice à partir de lignes en dict (ordre des colonnes réel)."""
    names = list(EXPECTED_COLUMN_NAMES)
    return FakeClient(names, [[row[name] for name in names] for row in rows])


# ---------------------------------------------------------------------------
# format_display_address — formatage d'affichage des adresses IP
# ---------------------------------------------------------------------------


class TestFormatDisplayAddress:
    """DÉFAUT MESURÉ À L'ÉCRAN (2026-08-07) : chaque IPv4 s'affichait sous sa
    forme IPv6-mappée (`::ffff:192.0.2.24`) — illisible pour un exploitant
    réseau, qui attend `192.0.2.24`.

    PIÈGE VÉRIFIÉ : `cutIPv6(addr, 0, 1)` ne fait PAS ça — mesuré, il rend
    `::ffff:100.64.0.0` (il TRONQUE l'adresse au lieu de la reformater). La
    fonction ci-dessous ne s'appuie pas sur une troncature de position, mais
    sur le parsing `ipaddress` + `ipv4_mapped`, qui distingue correctement une
    IPv4 mappée d'une IPv6 native (il y a de l'IPv6 native dans les données
    réelles, ex. `2001:861:...`)."""

    def test_ipv4_mappee_affichee_sous_sa_forme_v4(self) -> None:
        assert format_display_address(IPv6Address("::ffff:192.0.2.24")) == "192.0.2.24"

    def test_ipv6_native_reste_affichee_telle_quelle(self) -> None:
        """Une vraie IPv6 (non mappée) ne doit JAMAIS être tronquée ou modifiée :
        c'est le mode d'échec de `cutIPv6`, qu'il faut éviter par construction."""
        adresse = IPv6Address("2001:861:3ac0:1234::1")
        assert format_display_address(adresse) == "2001:861:3ac0:1234::1"

    def test_valeur_limite_chaine_deja_ipv4_texte(self) -> None:
        """Valeur limite : une IPv4 déjà fournie en texte simple (pas mappée,
        pas un objet `IPv6Address`) doit rester lisible telle quelle — le
        formatage ne doit pas supposer un objet `IPv6Address` en entrée."""
        assert format_display_address("192.0.2.24") == "192.0.2.24"

    def test_valeur_non_parsable_rendue_telle_quelle_sans_lever(self) -> None:
        """Une valeur qui n'est pas une IP valide ne doit pas faire planter le
        rendu : elle est rendue telle quelle plutôt que masquée (même choix que
        `_normalize_ip` déjà en place dans ce module)."""
        assert format_display_address("valeur-invalide") == "valeur-invalide"

    def test_valeur_none_rendue_comme_tiret_cadratin(self) -> None:
        """Cohérence avec le reste de l'app (`humanize_bytes`/`humanize_number`
        dans `app/templating.py`) : une valeur absente s'affiche « — », jamais
        une chaîne vide ou « None »."""
        assert format_display_address(None) == "—"


class TestFlowColumnsCatalogue:
    def test_covers_every_measured_column_in_order(self) -> None:
        """Le catalogue doit refléter la table RÉELLE (61 colonnes, ordre de position).

        Mesuré le 2026-08-06 via `system.columns` sur `default.flows`.
        """
        assert tuple(column.name for column in FLOW_COLUMNS) == EXPECTED_COLUMN_NAMES

    def test_column_count_matches_the_measured_total(self) -> None:
        """Garde-fou contre la colonne oubliée à la recopie.

        La spécification initiale annonçait « 60 colonnes » alors que la base en
        compte 61 : suivre le chiffre annoncé aurait fait disparaître un champ
        légitime de l'UI, sans erreur. Le compte est donc vérifié, pas commenté.
        """
        assert len(FLOW_COLUMNS) == EXPECTED_FLOW_COLUMN_COUNT
        assert len(EXPECTED_COLUMN_NAMES) == EXPECTED_FLOW_COLUMN_COUNT

    def test_column_names_are_unique(self) -> None:
        """Un doublon écraserait silencieusement un champ dans `_COLUMNS_BY_NAME`."""
        names = [column.name for column in FLOW_COLUMNS]
        assert len(names) == len(set(names))

    def test_every_column_has_a_french_label_distinct_from_its_name(self) -> None:
        """Sans libellé FR, l'écran n'est qu'une copie du schéma ClickHouse.

        Un opérateur ne lit pas `InIfBoundary` ; c'est le libellé qui porte
        l'utilité du module.
        """
        for column in FLOW_COLUMNS:
            assert column.label, f"libelle manquant pour {column.name}"
            assert column.label != column.name, f"libelle non traduit pour {column.name}"

    def test_labels_are_unique(self) -> None:
        """Deux champs au même libellé seraient indiscernables dans une liste."""
        labels = [column.label for column in FLOW_COLUMNS]
        assert len(labels) == len(set(labels))

    def test_boundary_label_is_the_readable_one(self) -> None:
        by_name = {column.name: column for column in FLOW_COLUMNS}
        assert by_name["InIfBoundary"].label == "Frontière interface entrante"


# ---------------------------------------------------------------------------
# Construction de requête — bornage et paramétrage
# ---------------------------------------------------------------------------


class TestBuildFlowSampleQuery:
    def test_returns_sql_and_bound_parameters(self) -> None:
        sql, parameters = build_flow_sample_query()
        assert isinstance(sql, str)
        assert parameters == {"window_seconds": 3600, "sample_limit": DEFAULT_SAMPLE_LIMIT}

    def test_query_is_always_limited(self) -> None:
        """Un SELECT non borné sur ~60 M de lignes est un incident, pas une lenteur."""
        sql, _ = build_flow_sample_query()
        assert "LIMIT {sample_limit:UInt32}" in sql

    def test_limit_is_capped_at_max(self) -> None:
        _, parameters = build_flow_sample_query(limit=999_999)
        assert parameters["sample_limit"] == MAX_SAMPLE_LIMIT

    def test_zero_or_negative_limit_becomes_one_never_zero(self) -> None:
        """`LIMIT 0` rendrait un échantillon vide indistinguable d'une fenêtre calme."""
        for requested in (0, -1, -1000):
            _, parameters = build_flow_sample_query(limit=requested)
            assert parameters["sample_limit"] == 1

    def test_window_transits_as_bound_parameter_never_in_sql(self) -> None:
        sql, parameters = build_flow_sample_query(window="6h", limit=50)
        assert "21600" not in sql
        assert "50" not in sql.replace("UInt32", "")
        assert parameters == {"window_seconds": 21600, "sample_limit": 50}

    def test_malicious_window_is_rejected_before_reaching_sql(self) -> None:
        """La fenêtre vient d'une table FERMÉE : une valeur forgée est refusée, pas échappée."""
        with pytest.raises(ValueError):
            build_flow_sample_query(window="1h'); DROP TABLE flows; --")

    def test_uses_tointervalsecond_not_interval_literal(self) -> None:
        """`INTERVAL {p:String}` est refusé par ClickHouse (SYNTAX_ERROR, 2026-08-05)."""
        sql, _ = build_flow_sample_query()
        assert "toIntervalSecond({window_seconds:UInt32})" in sql
        assert "INTERVAL {" not in sql

    def test_selects_every_catalogued_column_from_the_fixed_table(self) -> None:
        sql, _ = build_flow_sample_query()
        assert "FROM default.flows" in sql
        for column in FLOW_COLUMNS:
            assert column.name in sql

    def test_orders_by_most_recent_flows(self) -> None:
        """Sans tri, l'échantillon peut venir d'un vieux bloc : on décrirait un trafic passé."""
        sql, _ = build_flow_sample_query()
        assert "ORDER BY TimeReceived DESC" in sql

    def test_all_supported_windows_are_accepted(self) -> None:
        for window, seconds in (("1h", 3600), ("6h", 21600), ("24h", 86400), ("7d", 604800)):
            _, parameters = build_flow_sample_query(window=window)
            assert parameters["window_seconds"] == seconds


# ---------------------------------------------------------------------------
# Lecture de l'échantillon — vide vs erreur
# ---------------------------------------------------------------------------


class TestFetchFlowSample:
    def test_returns_rows_as_dicts_keyed_by_column(self) -> None:
        client = _client_from_rows([_real_shaped_row()])

        rows = fetch_flow_sample(client)  # type: ignore[arg-type]

        assert len(rows) == 1
        assert rows[0]["ExporterName"] == "proxy-frontal"
        assert rows[0]["SrcAddr"] == IPv6Address("::ffff:198.51.100.25")

    def test_passes_bound_parameters_to_the_client(self) -> None:
        client = _client_from_rows([])

        fetch_flow_sample(client, limit=25, window="24h")  # type: ignore[arg-type]

        _sql, parameters = client.calls[0]
        assert parameters == {"window_seconds": 86400, "sample_limit": 25}

    def test_empty_window_returns_empty_list_without_raising(self) -> None:
        """« Aucun flux dans la fenêtre » est une MESURE : pas d'exception."""
        client = _client_from_rows([])

        rows = fetch_flow_sample(client)  # type: ignore[arg-type]

        assert rows == []

    def test_query_failure_raises_instead_of_returning_empty(self) -> None:
        """ZÉRO SILENCIEUX — le défaut fondateur du projet.

        Une requête qui échoue ne doit JAMAIS rendre `[]` : « je n'ai pas pu
        mesurer » deviendrait indistinguable de « j'ai mesuré zéro », et une
        collecte en défaut s'afficherait comme un réseau calme.
        """
        with pytest.raises(FlowSampleUnavailableError):
            fetch_flow_sample(FailingClient())  # type: ignore[arg-type]

    def test_failure_chains_the_original_cause(self) -> None:
        """Le diagnostic doit rester possible : la cause d'origine n'est pas perdue."""
        original = OSError("connection refused (simule pour le test)")

        with pytest.raises(FlowSampleUnavailableError) as excinfo:
            fetch_flow_sample(FailingClient(original))  # type: ignore[arg-type]

        assert excinfo.value.__cause__ is original

    def test_empty_and_failure_are_distinguishable_by_the_caller(self) -> None:
        """Le contrat central : deux états, deux comportements observables."""
        empty_rows = fetch_flow_sample(_client_from_rows([]))  # type: ignore[arg-type]
        assert empty_rows == []

        failed = False
        try:
            fetch_flow_sample(FailingClient())  # type: ignore[arg-type]
        except FlowSampleUnavailableError:
            failed = True
        assert failed

    def test_invalid_window_raises_before_touching_the_client(self) -> None:
        client = _client_from_rows([_real_shaped_row()])

        with pytest.raises(ValueError):
            fetch_flow_sample(client, window="5m")  # type: ignore[arg-type]

        assert client.calls == []


# ---------------------------------------------------------------------------
# Synthèse des champs
# ---------------------------------------------------------------------------


class TestSummarizeFields:
    def test_returns_every_field_even_on_empty_sample(self) -> None:
        """Un champ absent de l'échantillon reste PROPOSÉ, avec zéro valeur.

        Ne rendre que les champs peuplés ferait croire qu'un champ légitime
        n'existe pas dès que l'échantillon est calme.
        """
        fields = summarize_fields([])

        assert len(fields) == len(FLOW_COLUMNS)
        assert all(f.sample_values == [] for f in fields)
        assert all(f.distinct_count == 0 for f in fields)

    def test_field_order_follows_the_table(self) -> None:
        fields = summarize_fields([_real_shaped_row()])
        assert tuple(f.name for f in fields) == EXPECTED_COLUMN_NAMES

    def test_ipv4_mapped_addresses_are_rendered_readable(self) -> None:
        """`::ffff:198.51.100.25` doit s'afficher `198.51.100.25`, sinon illisible."""
        fields = {f.name: f for f in summarize_fields([_real_shaped_row()])}

        assert fields["SrcAddr"].sample_values == ["198.51.100.25"]
        assert fields["ExporterAddress"].sample_values == ["192.0.2.17"]

    def test_genuine_ipv6_is_preserved_not_mangled(self) -> None:
        """Une IPv6 native ne doit pas être tronquée ni comparée à une IPv4.

        Comparer les deux familles lève `TypeError` en Python — on ne fait que
        convertir en texte.
        """
        rows = [
            _real_shaped_row(src_addr="2001:db8::1"),
            _real_shaped_row(src_addr="::ffff:10.0.0.1"),
        ]

        fields = {f.name: f for f in summarize_fields(rows)}

        assert set(fields["SrcAddr"].sample_values) == {"2001:db8::1", "10.0.0.1"}

    def test_fixed_string_country_padding_is_stripped(self) -> None:
        """`FixedString(2)` revient en `\\x00\\x00` quand le pays est inconnu.

        Sans nettoyage, « Pays source » proposerait une valeur invisible mais non
        vide, sur laquelle un opérateur construirait un filtre absurde.
        """
        fields = {f.name: f for f in summarize_fields([_real_shaped_row()])}

        assert fields["SrcCountry"].sample_values == []
        assert fields["DstCountry"].sample_values == ["FR"]

    def test_zero_asn_and_port_are_not_offered_as_values(self) -> None:
        """`SrcAS = 0` signifie « non renseigné », pas « AS numéro 0 »."""
        fields = {f.name: f for f in summarize_fields([_real_shaped_row(src_as=0, dst_as=3215)])}

        assert fields["SrcAS"].sample_values == []
        assert fields["DstAS"].sample_values == ["3215"]

    def test_array_columns_are_flattened_into_individual_values(self) -> None:
        """Un chemin d'AS se cherche AS par AS, jamais comme chaîne littérale."""
        rows = [_real_shaped_row(dst_as_path=[3215, 64501])]

        fields = {f.name: f for f in summarize_fields(rows)}

        assert set(fields["DstASPath"].sample_values) == {"3215", "64501"}

    def test_empty_arrays_produce_no_value(self) -> None:
        """`[]` (le cas dominant hors transit BGP) ne doit pas devenir la valeur « [] »."""
        fields = {f.name: f for f in summarize_fields([_real_shaped_row(dst_as_path=[])])}

        assert fields["DstASPath"].sample_values == []
        assert fields["DstCommunities"].sample_values == []

    def test_values_are_ordered_by_frequency_descending(self) -> None:
        """Ce qui domine le trafic doit apparaître en premier."""
        rows = [
            *[_real_shaped_row(exporter_name="serveur-fichiers") for _ in range(5)],
            *[_real_shaped_row(exporter_name="proxy-frontal") for _ in range(2)],
            _real_shaped_row(exporter_name="poste-collecte"),
        ]

        fields = {f.name: f for f in summarize_fields(rows)}

        assert fields["ExporterName"].sample_values == ["serveur-fichiers", "proxy-frontal", "poste-collecte"]

    def test_distinct_count_counts_all_values_not_only_the_exposed_ones(self) -> None:
        """Tronquer les valeurs sans exposer le compte ferait croire à 12 ports en tout."""
        rows = [_real_shaped_row(src_port=1000 + index) for index in range(40)]

        fields = {f.name: f for f in summarize_fields(rows)}
        src_port = fields["SrcPort"]

        assert src_port.distinct_count == 40
        assert len(src_port.sample_values) == MAX_SAMPLE_VALUES
        assert src_port.truncated is True

    def test_not_truncated_when_all_values_are_exposed(self) -> None:
        fields = {f.name: f for f in summarize_fields([_real_shaped_row()])}
        assert fields["ExporterName"].truncated is False

    def test_unknown_columns_in_rows_are_ignored(self) -> None:
        """Une colonne ajoutée par une future version d'Akvorado ne doit rien casser."""
        row = _real_shaped_row()
        row["SomeFutureAkvoradoColumn"] = "valeur inattendue"

        fields = summarize_fields([row])

        assert len(fields) == len(FLOW_COLUMNS)
        assert all(f.name != "SomeFutureAkvoradoColumn" for f in fields)

    def test_missing_columns_in_rows_do_not_raise(self) -> None:
        """Un SELECT partiel (test, futur écran) ne doit pas faire échouer la synthèse."""
        fields = summarize_fields([{"ExporterName": "proxy-frontal"}])

        by_name = {f.name: f for f in fields}
        assert by_name["ExporterName"].sample_values == ["proxy-frontal"]
        assert by_name["SrcAddr"].sample_values == []

    def test_enum_values_are_kept_as_readable_strings(self) -> None:
        fields = {f.name: f for f in summarize_fields([_real_shaped_row()])}

        assert fields["InIfBoundary"].sample_values == ["external"]
        assert fields["FlowDirection"].sample_values == ["egress"]

    def test_empty_strings_are_not_offered_as_values(self) -> None:
        """Un champ non renseigné ne doit pas proposer la chaîne vide comme filtre."""
        fields = {f.name: f for f in summarize_fields([_real_shaped_row()])}

        assert fields["ExporterGroup"].sample_values == []
        assert fields["SrcNetName"].sample_values == []


# ---------------------------------------------------------------------------
# filterable / dimensionable
# ---------------------------------------------------------------------------


class TestFilterableAndDimensionable:
    def test_array_columns_are_neither_filterable_nor_dimensionable(self) -> None:
        """Une colonne multivaluée ne se compare pas avec `=` et n'est pas un axe."""
        fields = {f.name: f for f in summarize_fields([])}

        for name in ("DstASPath", "DstCommunities", "DstLargeCommunities"):
            assert fields[name].filterable is False, name
            assert fields[name].dimensionable is False, name

    def test_metrics_are_filterable_but_not_dimensionable(self) -> None:
        """`Bytes` est l'axe Y du graphe, pas une catégorie de découpage."""
        fields = {f.name: f for f in summarize_fields([])}

        for name in ("Bytes", "Packets", "PacketSize"):
            assert fields[name].dimensionable is False, name
            assert fields[name].filterable is True, name

    def test_time_is_filterable_but_not_dimensionable(self) -> None:
        """Borner une période est un filtre légitime ; grouper par instant ne l'est pas."""
        fields = {f.name: f for f in summarize_fields([])}

        assert fields["TimeReceived"].filterable is True
        assert fields["TimeReceived"].dimensionable is False

    def test_ordinary_fields_are_both(self) -> None:
        fields = {f.name: f for f in summarize_fields([])}

        for name in ("ExporterName", "SrcAddr", "SrcPort", "SrcAS", "InIfName", "SrcCountry"):
            assert fields[name].filterable is True, name
            assert fields[name].dimensionable is True, name

    def test_high_cardinality_fields_stay_dimensionable(self) -> None:
        """« Qui parle le plus » est le cas d'usage n°1 : ne pas l'interdire."""
        fields = {f.name: f for f in summarize_fields([])}

        assert fields["SrcAddr"].dimensionable is True
        assert fields["DstPort"].dimensionable is True


# ---------------------------------------------------------------------------
# Recherche
# ---------------------------------------------------------------------------


def _fields_from_real_sample() -> list[FlowField]:
    rows = [
        _real_shaped_row(exporter_name="proxy-frontal", in_if_name="ens3"),
        _real_shaped_row(exporter_name="serveur-fichiers", in_if_name="eth0", dst_country="GB"),
    ]
    return summarize_fields(rows)


class TestSearchFields:
    def test_matches_on_column_name(self) -> None:
        results = search_fields(_fields_from_real_sample(), "SrcAddr")
        assert [f.name for f in results] == ["SrcAddr"]

    def test_matches_on_french_label(self) -> None:
        """Un opérateur cherche « port », pas `DstPort`."""
        results = search_fields(_fields_from_real_sample(), "port destination")
        assert [f.name for f in results] == ["DstPort"]

    def test_matches_on_sample_value_not_only_on_name(self) -> None:
        """EXIGENCE CENTRALE : taper « proxy-frontal » doit remonter `ExporterName`.

        L'opérateur sait ce qu'il cherche (un nom de machine) ; il ne sait pas dans
        quelle colonne du schéma ça vit. Chercher uniquement dans les noms lui
        imposerait de connaître le schéma, donc de ne plus avoir besoin de l'écran.
        """
        results = search_fields(_fields_from_real_sample(), "proxy-frontal")

        names = [f.name for f in results]
        assert "ExporterName" in names

    def test_value_search_does_not_require_the_column_name(self) -> None:
        results = search_fields(_fields_from_real_sample(), "ens3")
        assert [f.name for f in results] == ["InIfName"]

    def test_search_is_case_insensitive(self) -> None:
        results = search_fields(_fields_from_real_sample(), "PROXY-FRONTAL")
        assert "ExporterName" in [f.name for f in results]

    def test_search_is_accent_insensitive(self) -> None:
        """« region » doit trouver « Région de l'exportateur » : on tape sans accent."""
        results = search_fields(_fields_from_real_sample(), "region")

        names = [f.name for f in results]
        assert "ExporterRegion" in names
        assert "SrcNetRegion" in names

    def test_accented_query_matches_unaccented_content(self) -> None:
        results = search_fields(_fields_from_real_sample(), "Frontière")
        assert [f.name for f in results] == ["InIfBoundary", "OutIfBoundary"]

    def test_empty_query_returns_all_fields(self) -> None:
        """Une zone de recherche vierge montre le catalogue, pas une page blanche."""
        fields = _fields_from_real_sample()

        assert len(search_fields(fields, "")) == len(fields)
        assert len(search_fields(fields, "   ")) == len(fields)

    def test_no_match_returns_empty_list(self) -> None:
        results = search_fields(_fields_from_real_sample(), "zzz-inexistant-zzz")
        assert results == []

    def test_field_matching_by_both_name_and_value_appears_once(self) -> None:
        """Pas de doublon quand nom ET valeur correspondent."""
        fields = summarize_fields([_real_shaped_row(in_if_name="InIfName")])

        results = search_fields(fields, "inifname")

        assert [f.name for f in results].count("InIfName") == 1

    def test_result_order_follows_input_order(self) -> None:
        """Le tri relève de la vue, pas du filtre."""
        fields = _fields_from_real_sample()

        results = search_fields(fields, "as")

        positions = [fields.index(item) for item in results]
        assert positions == sorted(positions)

    def test_search_does_not_mutate_the_input_list(self) -> None:
        fields = _fields_from_real_sample()
        before = list(fields)

        search_fields(fields, "proxy-frontal")

        assert fields == before


# ---------------------------------------------------------------------------
# Chaîne complète (échantillon -> champs -> recherche)
# ---------------------------------------------------------------------------


class TestEndToEndOnRealShapedSample:
    def test_full_pipeline_on_driver_shaped_rows(self) -> None:
        """Bout en bout avec les TYPES du driver, pas des chaînes commodes."""
        client = _client_from_rows(
            [
                _real_shaped_row(exporter_name="serveur-fichiers", dst_country="FR", dst_as=3215),
                _real_shaped_row(exporter_name="serveur-fichiers", dst_country="GB", dst_as=16276),
                _real_shaped_row(exporter_name="proxy-frontal", dst_country="\x00\x00", dst_as=0),
            ]
        )

        rows = fetch_flow_sample(client, limit=3, window="1h")  # type: ignore[arg-type]
        fields = summarize_fields(rows)
        by_name = {f.name: f for f in fields}

        assert by_name["ExporterName"].sample_values == ["serveur-fichiers", "proxy-frontal"]
        assert set(by_name["DstCountry"].sample_values) == {"FR", "GB"}
        assert set(by_name["DstAS"].sample_values) == {"3215", "16276"}
        assert by_name["SrcAddr"].sample_values == ["198.51.100.25"]

        matched = search_fields(fields, "serveur-fichiers")
        assert "ExporterName" in [f.name for f in matched]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestValeursBinairesDuDriver:
    """Une `FixedString` arrive en `bytes` — `str()` dessus fabrique du faux.

    DÉFAUT VU À L'ÉCRAN (2026-08-06) : le compositeur de filtres proposait des
    pays sous la forme `b'FR'`, `b'US'`, `b'\\x00\\x00'`. Le driver ClickHouse
    rend `FixedString(2)` en **bytes**, et `str(b"FR")` produit la chaîne
    `"b'FR'"` — préfixe et guillemets compris.

    Cliquer sur une telle valeur composait `SrcCountry = b'FR'`, qui n'est pas
    une expression Akvorado valide. Le défaut ne levait aucune erreur : il
    transformait une donnée juste en donnée fausse, silencieusement.
    """

    def test_un_code_pays_en_bytes_devient_du_texte_lisible(self) -> None:
        from app.services.flow_sample import _normalize_fixed_string

        assert _normalize_fixed_string(b"FR") == "FR"
        assert _normalize_fixed_string(b"US") == "US"

    def test_le_prefixe_b_n_apparait_jamais_dans_une_valeur(self) -> None:
        """Le symptôme exact, tel qu'il était affiché."""
        from app.services.flow_sample import _normalize_fixed_string

        rendu = _normalize_fixed_string(b"BE")
        assert not rendu.startswith("b'"), (
            f"valeur rendue {rendu!r} : le préfixe de repr() Python a fuité "
            "jusqu'à l'écran, et le filtre construit serait invalide"
        )
        assert "'" not in rendu

    def test_le_bourrage_de_nul_reste_ecarte(self) -> None:
        """Non-régression : un pays inconnu revient en `\\0\\0`, pas en vide."""
        from app.services.flow_sample import _normalize_fixed_string

        assert _normalize_fixed_string(b"\x00\x00") == ""

    def test_un_octet_non_decodable_ne_leve_pas(self) -> None:
        """Une donnée corrompue ne doit pas casser tout l'échantillon.

        Un seul octet invalide ferait disparaître la totalité des champs si
        l'exception remontait — bien pire que la valeur illisible elle-même.
        """
        from app.services.flow_sample import _normalize_fixed_string

        assert isinstance(_normalize_fixed_string(b"\xff\xfe"), str)


class TestRechercheSurValeursTronquees:
    """La recherche doit voir TOUTES les valeurs, pas seulement le top affiché.

    DÉFAUT MESURÉ (2026-08-06) : `search_fields` cherchait dans
    `sample_values`, tronqué à `MAX_SAMPLE_VALUES` pour l'affichage. Sur la
    base réelle, `SrcAddr` gardait 12 valeurs sur 26 — et une adresse
    RÉELLEMENT présente dans l'échantillon, hors du top 12, était introuvable.

    L'écran répondait « Aucun champ ne correspond » pour une machine qui
    émettait des flux à cet instant précis. Chercher et afficher n'ont pas les
    mêmes contraintes : afficher 300 valeurs est illisible, ne pouvoir en
    chercher que 12 rend l'écran menteur.
    """

    def _echantillon_a_forte_cardinalite(self) -> list[dict[str, object]]:
        """Plus de valeurs distinctes que `MAX_SAMPLE_VALUES`, la 1re étant
        dominante pour que les suivantes soient bien reléguées hors du top."""
        from app.services.flow_sample import MAX_SAMPLE_VALUES

        rows: list[dict[str, object]] = [{"ExporterName": "dominant"} for _ in range(50)]
        for index in range(MAX_SAMPLE_VALUES + 5):
            rows.append({"ExporterName": f"machine-{index:02d}"})
        return rows

    def test_une_valeur_hors_du_top_affiche_reste_trouvable(self) -> None:
        from app.services.flow_sample import (
            MAX_SAMPLE_VALUES,
            search_fields,
            summarize_fields,
        )

        fields = summarize_fields(self._echantillon_a_forte_cardinalite())
        champ = next(f for f in fields if f.name == "ExporterName")

        assert champ.truncated, "l'échantillon de test doit être tronqué, sinon il ne prouve rien"
        assert len(champ.sample_values) == MAX_SAMPLE_VALUES

        # Une valeur PRÉSENTE dans l'échantillon mais absente de l'affichage.
        cachee = next(v for v in champ.searchable_values if v not in champ.sample_values)
        trouves = [f.name for f in search_fields(fields, cachee)]

        assert trouves == ["ExporterName"], (
            f"la valeur {cachee!r} est dans l'échantillon mais introuvable : "
            "l'écran annoncerait « aucun champ ne correspond » pour une machine "
            "qui émet des flux"
        )

    def test_l_affichage_reste_borne(self) -> None:
        """Corollaire : élargir la recherche ne doit pas noyer l'écran."""
        from app.services.flow_sample import MAX_SAMPLE_VALUES, summarize_fields

        champ = next(
            f
            for f in summarize_fields(self._echantillon_a_forte_cardinalite())
            if f.name == "ExporterName"
        )
        assert len(champ.sample_values) == MAX_SAMPLE_VALUES
        assert len(champ.searchable_values) > MAX_SAMPLE_VALUES
