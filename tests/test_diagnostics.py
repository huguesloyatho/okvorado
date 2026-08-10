"""Tests du module diagnostics — construction de SQL de convergence et par exportateur.

Ces tests prouvent l'INTENTION, pas un moyen : ils n'attendent jamais une chaîne
SQL exacte (piège vécu 5 fois dans ce projet — un test qui fige le texte casse au
premier refactor légitime). Ils vérifient des propriétés observables :

- aucune valeur utilisateur n'apparaît dans le texte SQL, elle est en paramètre ;
- une dimension/période hors allowlist lève une exception ;
- une limite excessive est plafonnée, jamais laissée libre ;
- toute somme de volume porte `* SamplingRate` (garde `test_sampling_rate.py`) ;
- le filtre de convergence exclut sources externes / multicast / ports éphémères /
  non-TCP-UDP — c'est ce qui sépare le motif SCCM du bruit de scan Internet
  (mesure décisive n°1 du 2026-08-07, cf. contexte métier de la tâche).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from app.services import diagnostics

# ---------------------------------------------------------------------------
# build_convergence_query — la vue qui rend le motif SCCM visible
# ---------------------------------------------------------------------------


def test_convergence_query_periode_valide_retourne_sql_et_parametres() -> None:
    sql, params = diagnostics.build_convergence_query(period="1h", min_sources=5, limit=50)
    assert isinstance(sql, str) and sql.strip()
    assert isinstance(params, dict)


def test_convergence_query_periode_hors_enumeration_refusee() -> None:
    """La période ne peut PAS être un nombre de jours libre : la table brute sert
    aussi la console Akvorado, une requête non bornée peut la faire tomber."""
    with pytest.raises(ValueError):
        diagnostics.build_convergence_query(period="42d", min_sources=5, limit=50)


@pytest.mark.parametrize("period", diagnostics.DIAGNOSTIC_PERIOD_CHOICES)
def test_convergence_query_toutes_les_periodes_de_l_enumeration_sont_acceptees(
    period: str,
) -> None:
    sql, params = diagnostics.build_convergence_query(period=period, min_sources=1, limit=10)
    assert sql.strip()


def test_convergence_query_limit_plafonnee_au_maximum_dur() -> None:
    """Un `limit` démesuré ne doit jamais atteindre ClickHouse tel quel."""
    _, params_excessif = diagnostics.build_convergence_query(
        period="1h", min_sources=1, limit=10_000_000
    )
    _, params_plafond = diagnostics.build_convergence_query(
        period="1h", min_sources=1, limit=diagnostics.MAX_CONVERGENCE_LIMIT
    )
    limit_applique = params_excessif.get("limit")
    assert limit_applique is not None
    assert limit_applique <= diagnostics.MAX_CONVERGENCE_LIMIT
    assert limit_applique == params_plafond.get("limit")


def test_convergence_query_limit_toujours_present_dans_le_sql() -> None:
    sql, _ = diagnostics.build_convergence_query(period="1h", min_sources=5, limit=50)
    assert "LIMIT" in sql.upper()


def test_convergence_query_somme_de_volume_applique_le_taux_d_echantillonnage() -> None:
    """Garde miroir de `tests/test_sampling_rate.py` : `sum(Bytes)` nu est un volume
    faux dès que l'exportateur échantillonne (facteur 1000 possible en entreprise,
    invisible en homelab où SamplingRate=1)."""
    sql, _ = diagnostics.build_convergence_query(period="1h", min_sources=5, limit=50)
    assert re.search(r"sum\(\s*Bytes\s*\*\s*SamplingRate\s*\)", sql)
    assert not re.search(r"sum\(\s*Bytes\s*\)", sql)


def test_convergence_query_filtre_sources_externes_rfc1918_et_cgnat() -> None:
    """MESURE DÉCISIVE n°1 (2026-08-07) : sans ce filtre, `198.51.100.9` remonte
    en tête avec 1071 sources dont 1059 EXTERNES — du scan de ports Internet, pas
    un motif de convergence applicative. Le filtre source-interne (RFC1918 +
    CGNAT 100.64/10) est ce qui sépare le vrai motif du bruit."""
    sql, _ = diagnostics.build_convergence_query(period="1h", min_sources=5, limit=50)
    lowered = sql.lower()
    # RFC1918
    assert "10." in sql or "10.0.0.0" in sql
    assert "172.16" in sql
    assert "192.168" in sql
    # Le CGNAT 100.64/10 n'est PLUS dans le défaut (2026-08-10) : c'est une
    # hypothèse d'infrastructure (VPN maillé), pas l'adressage d'une
    # entreprise. Il s'ajoute via OKVORADO_INTERNAL_NETWORKS si le site en a
    # besoin — voir TestPlagesInternesParametrables.
    assert "src" in lowered  # le filtre porte bien sur la source


def test_convergence_query_exclut_multicast_destination() -> None:
    """Destination doit être UNICAST : exclut 224.0.0.0/4 (multicast v4)."""
    sql, _ = diagnostics.build_convergence_query(period="1h", min_sources=5, limit=50)
    assert "224." in sql


def test_convergence_query_filtre_destinations_externes() -> None:
    """DÉFAUT MESURÉ À L'ÉCRAN (2026-08-07) : sur les 50 lignes affichées, 40
    étaient du STUN Tailscale port 3478 (9 sources, 6,9 Ko, 104 flux chacune),
    vers des IP publiques différentes — le signal (192.0.2.24, 17 sources)
    restait en tête mais noyé sous 84% de bruit.

    Mesure de tranche (prod, fenêtre 1h, seuil 5 sources) : destination EXTERNE
    -> 74 lignes (max 9 sources, du bruit) ; destination INTERNE -> 14 lignes
    (max 17 sources, le vrai motif). Le motif cible (« N postes internes -> 1
    serveur ») est TOUJOURS interne côté destination : un serveur SCCM, un
    partage SMB, un datacenter d'entreprise ne sont jamais sur Internet.

    Le test porte sur l'INTENTION (la destination doit être bornée aux mêmes
    plages RFC1918/CGNAT que la source), pas sur une chaîne SQL figée : il
    vérifie que le filtre destination-interne existe et porte bien sur DstAddr,
    avec les mêmes préfixes que le filtre source-interne déjà en place."""
    sql, _ = diagnostics.build_convergence_query(period="1h", min_sources=5, limit=50)

    # Le filtre doit porter sur DstAddr avec les préfixes RFC1918 + CGNAT,
    # symétriquement au filtre déjà appliqué à SrcAddr.
    assert re.search(r"DstAddr\s*>=\s*toIPv6\('::ffff:10\.0\.0\.0'\)", sql)
    assert re.search(r"DstAddr\s*>=\s*toIPv6\('::ffff:172\.16\.0\.0'\)", sql)
    assert re.search(r"DstAddr\s*>=\s*toIPv6\('::ffff:192\.168\.0\.0'\)", sql)
    # (plus de CGNAT dans le défaut — voir TestPlagesInternesParametrables)


def test_convergence_query_ne_retient_pas_une_destination_hors_plages_privees() -> None:
    """Preuve par la structure : les bornes du filtre destination-interne sont
    exactement celles de RFC1918 + CGNAT (10/8, 172.16/12, 192.168/16,
    100.64/10) — une destination publique (ex. STUN Tailscale sur IP publique)
    ne peut satisfaire aucune des quatre plages et est donc exclue par
    construction, pas par une chaîne de texte approximative."""
    sql, _ = diagnostics.build_convergence_query(period="1h", min_sources=5, limit=50)

    bornes_hautes_attendues = (
        "::ffff:10.255.255.255",
        "::ffff:172.31.255.255",
        "::ffff:192.168.255.255",
    )
    for borne in bornes_hautes_attendues:
        assert f"DstAddr <= toIPv6('{borne}')" in sql, (
            f"borne haute {borne} absente du filtre destination-interne : "
            "une IP publique juste au-dessus resterait acceptée"
        )


def test_convergence_query_filtre_ports_ephemeres_et_zero() -> None:
    """`DstPort > 0 AND DstPort < 32768` exclut ICMP/fragments (port 0) et les
    ports éphémères clients (>= 32768), qui ne portent aucun motif de service."""
    sql, _ = diagnostics.build_convergence_query(period="1h", min_sources=5, limit=50)
    assert "DstPort" in sql
    assert "32768" in sql


def test_convergence_query_filtre_protocoles_tcp_udp_uniquement() -> None:
    """MESURE DÉCISIVE n°1 : sans ce filtre, `198.51.100.51` remonte avec 217
    sources sur le port 41641 — maillage P2P Tailscale, pas un motif applicatif.
    `Proto IN (6, 17)` restreint à TCP/UDP."""
    sql, _ = diagnostics.build_convergence_query(period="1h", min_sources=5, limit=50)
    assert "Proto" in sql
    assert "6" in sql and "17" in sql


def test_convergence_query_classe_par_nombre_de_sources_distinctes() -> None:
    """C'est LA métrique de convergence : uniqExact(SrcAddr), pas count()."""
    sql, _ = diagnostics.build_convergence_query(period="1h", min_sources=5, limit=50)
    assert "uniqExact" in sql or "uniq(" in sql.replace("uniqExact", "")


def test_convergence_query_tape_la_table_brute_flows_jamais_un_agregat() -> None:
    """MESURE DÉCISIVE n°2 (2026-08-07) : `flows_1m0s`/`flows_5m0s`/`flows_1h0m0s`
    ne portent pas SrcAddr/DstAddr/DstPort — toute requête de convergence DOIT
    taper `default.flows`."""
    sql, _ = diagnostics.build_convergence_query(period="1h", min_sources=5, limit=50)
    assert "default.flows" in sql or re.search(r"\bflows\b", sql)
    assert "flows_1m0s" not in sql
    assert "flows_5m0s" not in sql
    assert "flows_1h0m0s" not in sql


def test_convergence_query_min_sources_transite_en_parametre() -> None:
    """Le seuil de sources minimales (HAVING) est une valeur numérique fournie
    par l'appelant : elle doit transiter en paramètre lié, jamais interpolée."""
    _, params = diagnostics.build_convergence_query(period="1h", min_sources=7, limit=50)
    assert 7 in params.values()


# ---------------------------------------------------------------------------
# build_convergence_detail_query — le drill-down sur une destination retenue
# ---------------------------------------------------------------------------


def test_convergence_detail_query_ip_hostile_jamais_dans_le_texte_sql() -> None:
    """Injection SQL classique : la valeur doit être un PARAMÈTRE, jamais
    concaténée dans le texte de la requête."""
    charge_utile = "'; DROP TABLE flows--"
    sql, params = diagnostics.build_convergence_detail_query(
        dst_addr=charge_utile, dst_port=445, period="1h", limit=50
    )
    assert charge_utile not in sql
    assert "DROP TABLE" not in sql.upper()
    assert charge_utile in params.values()


def test_convergence_detail_query_port_transite_en_parametre() -> None:
    sql, params = diagnostics.build_convergence_detail_query(
        dst_addr="10.0.0.5", dst_port=8443, period="1h", limit=50
    )
    assert "8443" not in sql
    assert 8443 in params.values()


def test_convergence_detail_query_periode_hors_enumeration_refusee() -> None:
    with pytest.raises(ValueError):
        diagnostics.build_convergence_detail_query(
            dst_addr="10.0.0.5", dst_port=445, period="3 semaines", limit=50
        )


def test_convergence_detail_query_limit_plafonnee() -> None:
    _, params = diagnostics.build_convergence_detail_query(
        dst_addr="10.0.0.5", dst_port=445, period="1h", limit=999_999_999
    )
    limit_applique = params.get("limit")
    assert limit_applique is not None
    assert limit_applique <= diagnostics.MAX_CONVERGENCE_LIMIT


def test_convergence_detail_query_somme_de_volume_applique_le_taux() -> None:
    sql, _ = diagnostics.build_convergence_detail_query(
        dst_addr="10.0.0.5", dst_port=445, period="1h", limit=50
    )
    assert re.search(r"sum\(\s*Bytes\s*\*\s*SamplingRate\s*\)", sql)
    assert not re.search(r"sum\(\s*Bytes\s*\)", sql)


def test_convergence_detail_query_expose_exportateur_entree() -> None:
    """Le drill-down doit porter l'exportateur d'entrée (ExporterName / InIfName) :
    c'est ce qui permet de localiser physiquement chaque source."""
    sql, _ = diagnostics.build_convergence_detail_query(
        dst_addr="10.0.0.5", dst_port=445, period="1h", limit=50
    )
    assert "ExporterName" in sql


def test_convergence_detail_query_tape_la_table_brute() -> None:
    sql, _ = diagnostics.build_convergence_detail_query(
        dst_addr="10.0.0.5", dst_port=445, period="1h", limit=50
    )
    assert re.search(r"\bflows\b", sql)
    assert "flows_1m0s" not in sql
    assert "flows_5m0s" not in sql
    assert "flows_1h0m0s" not in sql


def test_convergence_detail_query_filtre_les_sources_internes_comme_le_classement() -> None:
    """Cohérence classement <-> drill-down : `build_convergence_query` ne compte
    QUE les sources internes (mesure décisive n°1). Si le détail listait, lui,
    TOUTES les sources (y compris externes) pour la même destination, le
    nombre de lignes affichées au clic dépasserait le `source_count` annoncé
    dans le tableau — un défaut de cohérence entre les deux écrans, même sans
    lien avec le bruit STUN du défaut n°1."""
    sql, _ = diagnostics.build_convergence_detail_query(
        dst_addr="10.0.0.5", dst_port=445, period="1h", limit=50
    )
    assert re.search(r"SrcAddr\s*>=\s*toIPv6\('::ffff:10\.0\.0\.0'\)", sql)
    assert re.search(r"SrcAddr\s*>=\s*toIPv6\('::ffff:172\.16\.0\.0'\)", sql)
    assert re.search(r"SrcAddr\s*>=\s*toIPv6\('::ffff:192\.168\.0\.0'\)", sql)
    # Le CGNAT 100.64/10 ne fait plus partie du défaut (2026-08-10) : c'est une
    # hypothèse d'infrastructure (VPN maillé), ajoutable via
    # OKVORADO_INTERNAL_NETWORKS. Ce qui compte ici est la COHÉRENCE entre le
    # classement et le drill-down, pas la liste des plages elle-même.


# ---------------------------------------------------------------------------
# Écran par exportateur — allowlist de dimensions, jamais de nom libre
# ---------------------------------------------------------------------------


def test_dimension_hors_allowlist_levee_une_exception_jamais_interpolee() -> None:
    """Une dimension choisie par l'utilisateur (ex: sélecteur d'écran) qui ne
    figure pas dans l'allowlist doit être REFUSÉE, jamais utilisée comme nom de
    colonne SQL."""
    charge_utile = "SrcAddr; DROP TABLE flows--"
    with pytest.raises(ValueError):
        diagnostics.build_exporter_top_dimension_query(
            exporter_name="clm", dimension=charge_utile, period="1h", limit=10
        )


@pytest.mark.parametrize("dimension", sorted(diagnostics.EXPORTER_DIMENSION_ALLOWLIST))
def test_toute_dimension_de_l_allowlist_est_acceptee(dimension: str) -> None:
    sql, params = diagnostics.build_exporter_top_dimension_query(
        exporter_name="clm", dimension=dimension, period="1h", limit=10
    )
    assert sql.strip()
    assert dimension in sql  # littéral en dur, légitime : dérivé de l'allowlist


def test_dimension_query_nom_exportateur_hostile_jamais_dans_le_texte_sql() -> None:
    charge_utile = "clm' OR '1'='1"
    sql, params = diagnostics.build_exporter_top_dimension_query(
        exporter_name=charge_utile, dimension="SrcAddr", period="1h", limit=10
    )
    assert charge_utile not in sql
    assert charge_utile in params.values()


def test_dimension_query_limit_plafonnee() -> None:
    _, params = diagnostics.build_exporter_top_dimension_query(
        exporter_name="clm", dimension="SrcAddr", period="1h", limit=5_000_000
    )
    limit_applique = params.get("limit")
    assert limit_applique is not None
    assert limit_applique <= diagnostics.MAX_CONVERGENCE_LIMIT


def test_dimension_query_somme_de_volume_applique_le_taux() -> None:
    sql, _ = diagnostics.build_exporter_top_dimension_query(
        exporter_name="clm", dimension="DstPort", period="1h", limit=10
    )
    assert re.search(r"sum\(\s*Bytes\s*\*\s*SamplingRate\s*\)", sql)
    assert not re.search(r"sum\(\s*Bytes\s*\)", sql)


# ---------------------------------------------------------------------------
# Écran par exportateur — trafic dans le temps
# ---------------------------------------------------------------------------


def test_exporter_time_series_query_nom_exportateur_en_parametre() -> None:
    charge_utile = "clm'; DROP TABLE flows--"
    sql, params = diagnostics.build_exporter_time_series_query(
        exporter_name=charge_utile, period="24h"
    )
    assert charge_utile not in sql
    assert charge_utile in params.values()


def test_exporter_time_series_query_periode_hors_enumeration_refusee() -> None:
    with pytest.raises(ValueError):
        diagnostics.build_exporter_time_series_query(exporter_name="clm", period="99y")


def test_exporter_time_series_query_somme_de_volume_applique_le_taux() -> None:
    sql, _ = diagnostics.build_exporter_time_series_query(exporter_name="clm", period="1h")
    assert re.search(r"sum\(\s*Bytes\s*\*\s*SamplingRate\s*\)", sql)
    assert not re.search(r"sum\(\s*Bytes\s*\)", sql)


# ---------------------------------------------------------------------------
# Écran par exportateur — top interfaces
# ---------------------------------------------------------------------------


def test_exporter_top_interfaces_query_nom_exportateur_en_parametre() -> None:
    charge_utile = "clm' UNION SELECT--"
    sql, params = diagnostics.build_exporter_top_interfaces_query(
        exporter_name=charge_utile, period="1h", limit=10
    )
    assert charge_utile not in sql
    assert charge_utile in params.values()


def test_exporter_top_interfaces_query_limit_plafonnee() -> None:
    _, params = diagnostics.build_exporter_top_interfaces_query(
        exporter_name="clm", period="1h", limit=1_000_000
    )
    assert params.get("limit", 0) <= diagnostics.MAX_CONVERGENCE_LIMIT


def test_exporter_top_interfaces_query_somme_de_volume_applique_le_taux() -> None:
    sql, _ = diagnostics.build_exporter_top_interfaces_query(
        exporter_name="clm", period="1h", limit=10
    )
    assert re.search(r"sum\(\s*Bytes\s*\*\s*SamplingRate\s*\)", sql)
    assert not re.search(r"sum\(\s*Bytes\s*\)", sql)


# ---------------------------------------------------------------------------
# Écran par exportateur — top applications (par port)
# ---------------------------------------------------------------------------


def test_exporter_top_applications_query_nom_exportateur_en_parametre() -> None:
    charge_utile = "clm'; --"
    sql, params = diagnostics.build_exporter_top_applications_query(
        exporter_name=charge_utile, period="1h", limit=10
    )
    assert charge_utile not in sql
    assert charge_utile in params.values()


def test_exporter_top_applications_query_somme_de_volume_applique_le_taux() -> None:
    sql, _ = diagnostics.build_exporter_top_applications_query(
        exporter_name="clm", period="1h", limit=10
    )
    assert re.search(r"sum\(\s*Bytes\s*\*\s*SamplingRate\s*\)", sql)
    assert not re.search(r"sum\(\s*Bytes\s*\)", sql)


def test_exporter_top_applications_query_expose_port_et_protocole() -> None:
    sql, _ = diagnostics.build_exporter_top_applications_query(
        exporter_name="clm", period="1h", limit=10
    )
    assert "DstPort" in sql
    assert "Proto" in sql


# ---------------------------------------------------------------------------
# Écran par exportateur — top sources / top destinations
# ---------------------------------------------------------------------------


def test_exporter_top_sources_query_nom_exportateur_en_parametre() -> None:
    charge_utile = "clm' OR 1=1--"
    sql, params = diagnostics.build_exporter_top_sources_query(
        exporter_name=charge_utile, period="1h", limit=10
    )
    assert charge_utile not in sql
    assert charge_utile in params.values()


def test_exporter_top_sources_query_somme_de_volume_applique_le_taux() -> None:
    sql, _ = diagnostics.build_exporter_top_sources_query(
        exporter_name="clm", period="1h", limit=10
    )
    assert re.search(r"sum\(\s*Bytes\s*\*\s*SamplingRate\s*\)", sql)
    assert not re.search(r"sum\(\s*Bytes\s*\)", sql)


def test_exporter_top_destinations_query_nom_exportateur_en_parametre() -> None:
    charge_utile = "clm' OR 1=1--"
    sql, params = diagnostics.build_exporter_top_destinations_query(
        exporter_name=charge_utile, period="1h", limit=10
    )
    assert charge_utile not in sql
    assert charge_utile in params.values()


def test_exporter_top_destinations_query_somme_de_volume_applique_le_taux() -> None:
    sql, _ = diagnostics.build_exporter_top_destinations_query(
        exporter_name="clm", period="1h", limit=10
    )
    assert re.search(r"sum\(\s*Bytes\s*\*\s*SamplingRate\s*\)", sql)
    assert not re.search(r"sum\(\s*Bytes\s*\)", sql)


# ---------------------------------------------------------------------------
# Écran par exportateur — top conversations (src, dst, port)
# ---------------------------------------------------------------------------


def test_exporter_top_conversations_query_nom_exportateur_en_parametre() -> None:
    charge_utile = "clm' OR 1=1--"
    sql, params = diagnostics.build_exporter_top_conversations_query(
        exporter_name=charge_utile, period="1h", limit=10
    )
    assert charge_utile not in sql
    assert charge_utile in params.values()


def test_exporter_top_conversations_query_expose_source_destination_et_port() -> None:
    sql, _ = diagnostics.build_exporter_top_conversations_query(
        exporter_name="clm", period="1h", limit=10
    )
    assert "SrcAddr" in sql
    assert "DstAddr" in sql
    assert "DstPort" in sql


def test_exporter_top_conversations_query_somme_de_volume_applique_le_taux() -> None:
    sql, _ = diagnostics.build_exporter_top_conversations_query(
        exporter_name="clm", period="1h", limit=10
    )
    assert re.search(r"sum\(\s*Bytes\s*\*\s*SamplingRate\s*\)", sql)
    assert not re.search(r"sum\(\s*Bytes\s*\)", sql)


# ---------------------------------------------------------------------------
# Écran par exportateur — répartition QoS (DSCP = IPTos >> 2)
# ---------------------------------------------------------------------------


def test_exporter_qos_query_nom_exportateur_en_parametre() -> None:
    charge_utile = "clm' OR 1=1--"
    sql, params = diagnostics.build_exporter_qos_query(exporter_name=charge_utile, period="1h")
    assert charge_utile not in sql
    assert charge_utile in params.values()


def test_exporter_qos_query_calcule_le_dscp_par_decalage_de_bits() -> None:
    """DSCP = IPTos décalé de 2 bits (6 bits hauts de l'octet ToS), mesure
    métier citée dans le contexte de la tâche — pas une valeur au choix.

    DÉFAUT MESURÉ EN PRODUCTION (2026-08-07) : l'onglet QoS de
    `/exporters/routeur-agence-03` affichait l'erreur ClickHouse suivante au clic,
    en clair à l'écran :

        Code: 62. DB::Exception: Syntax error: failed at position 20 (>)
        (line 3, col 12): > 2 AS dscp, sum(Bytes * SamplingRate) AS
        total_bytes, count() AS flow_count FROM default.flows WHERE
        TimeReceived >= now() - toIntervalSecond({window_secon...

    Cause : le SQL généré utilisait l'opérateur C-like `IPTos >> 2`, que
    ClickHouse NE CONNAÎT PAS (vérifié en prod : `SELECT IPTos >> 2` échoue
    en `Code: 62 SYNTAX_ERROR`, `SELECT bitShiftRight(IPTos, 2)` fonctionne).
    Ce test vérifie l'INTENTION (extraire le DSCP par un décalage de 2 bits
    à droite) via la fonction ClickHouse réelle, pas via un opérateur qui
    n'existe que dans l'imagination du double de test — cf. le garde-fou
    générique `test_aucune_fonction_du_module_ne_produit_un_operateur_de_decalage_c_like`
    plus bas, qui interdit `>>`/`<<` dans TOUT le module pour cette famille
    de défaut (aucun double ClickHouse de test ne valide la syntaxe SQL,
    c'est l'angle mort structurel qui a laissé passer celui-ci)."""
    sql, _ = diagnostics.build_exporter_qos_query(exporter_name="clm", period="1h")
    assert "IPTos" in sql
    assert re.search(r"bitShiftRight\(\s*IPTos\s*,\s*2\s*\)", sql), (
        "le DSCP doit être extrait via bitShiftRight(IPTos, 2), la seule "
        "syntaxe que ClickHouse accepte pour ce décalage de bits"
    )


def test_exporter_qos_query_somme_de_volume_applique_le_taux() -> None:
    sql, _ = diagnostics.build_exporter_qos_query(exporter_name="clm", period="1h")
    assert re.search(r"sum\(\s*Bytes\s*\*\s*SamplingRate\s*\)", sql)
    assert not re.search(r"sum\(\s*Bytes\s*\)", sql)


# ---------------------------------------------------------------------------
# Toutes les requêtes exportateur : allowlist de période, limit plafonnée, LIMIT présent
# ---------------------------------------------------------------------------


_EXPORTER_QUERY_BUILDERS_AVEC_LIMIT = (
    diagnostics.build_exporter_top_interfaces_query,
    diagnostics.build_exporter_top_applications_query,
    diagnostics.build_exporter_top_sources_query,
    diagnostics.build_exporter_top_destinations_query,
    diagnostics.build_exporter_top_conversations_query,
)


@pytest.mark.parametrize("builder", _EXPORTER_QUERY_BUILDERS_AVEC_LIMIT)
def test_toutes_les_requetes_exportateur_avec_limit_ont_un_limit_dans_le_sql(builder) -> None:  # type: ignore[no-untyped-def]
    sql, _ = builder(exporter_name="clm", period="1h", limit=10)
    assert "LIMIT" in sql.upper()


@pytest.mark.parametrize("builder", _EXPORTER_QUERY_BUILDERS_AVEC_LIMIT)
def test_toutes_les_requetes_exportateur_avec_limit_refusent_une_periode_hors_enumeration(
    builder,  # type: ignore[no-untyped-def]
) -> None:
    with pytest.raises(ValueError):
        builder(exporter_name="clm", period="jamais", limit=10)


def test_exporter_time_series_et_qos_refusent_aussi_une_periode_hors_enumeration() -> None:
    with pytest.raises(ValueError):
        diagnostics.build_exporter_time_series_query(exporter_name="clm", period="jamais")
    with pytest.raises(ValueError):
        diagnostics.build_exporter_qos_query(exporter_name="clm", period="jamais")


# ---------------------------------------------------------------------------
# GARDE-FOU générique — ClickHouse n'a PAS l'opérateur C-like >> / <<
#
# ANGLE MORT STRUCTUREL (constat du 2026-08-07, cf. le défaut ci-dessus sur
# build_exporter_qos_query) : les tests de ce fichier utilisent un double —
# les builders `build_xxx_query()` sont de purs constructeurs de texte SQL,
# aucun test ici ne se connecte à un vrai ClickHouse. Un double accepte
# n'importe quelle chaîne, syntaxiquement valide ou pas : `IPTos >> 2` est
# passé tous les tests de ce fichier ET les 1055 tests du projet AVANT d'être
# vu, car SEUL le moteur ClickHouse réel refuse cet opérateur (`Code: 62
# SYNTAX_ERROR`). Ce test ne remplace pas un test d'intégration contre un
# vrai ClickHouse (absent de ce projet) : il ferme le trou le moins cher à
# fermer — interdire MÉCANIQUEMENT la famille d'opérateurs C-like qui n'a
# jamais existé en SQL ClickHouse, sur TOUTE fonction publique du module,
# présente ou future.
# ---------------------------------------------------------------------------

_TOUS_LES_BUILDERS_SQL_DU_MODULE: tuple[Any, ...] = (
    lambda: diagnostics.build_convergence_query(period="1h", min_sources=5, limit=50),
    lambda: diagnostics.build_convergence_detail_query(
        dst_addr="10.0.0.5", dst_port=445, period="1h", limit=50
    ),
    lambda: diagnostics.build_exporter_top_dimension_query(
        exporter_name="clm", dimension="SrcAddr", period="1h", limit=10
    ),
    lambda: diagnostics.build_exporter_time_series_query(exporter_name="clm", period="1h"),
    lambda: diagnostics.build_exporter_top_interfaces_query(
        exporter_name="clm", period="1h", limit=10
    ),
    lambda: diagnostics.build_exporter_top_applications_query(
        exporter_name="clm", period="1h", limit=10
    ),
    lambda: diagnostics.build_exporter_top_sources_query(
        exporter_name="clm", period="1h", limit=10
    ),
    lambda: diagnostics.build_exporter_top_destinations_query(
        exporter_name="clm", period="1h", limit=10
    ),
    lambda: diagnostics.build_exporter_top_conversations_query(
        exporter_name="clm", period="1h", limit=10
    ),
    lambda: diagnostics.build_exporter_qos_query(exporter_name="clm", period="1h"),
)


@pytest.mark.parametrize(
    "appelle_le_builder",
    _TOUS_LES_BUILDERS_SQL_DU_MODULE,
    ids=[
        "convergence",
        "convergence_detail",
        "exporter_top_dimension",
        "exporter_time_series",
        "exporter_top_interfaces",
        "exporter_top_applications",
        "exporter_top_sources",
        "exporter_top_destinations",
        "exporter_top_conversations",
        "exporter_qos",
    ],
)
def test_aucune_fonction_du_module_ne_produit_un_operateur_de_decalage_c_like(
    appelle_le_builder: Any,
) -> None:
    """ClickHouse ne connaît PAS `>>`/`<<` — ce sont des opérateurs C-like sans
    équivalent SQL ClickHouse (la fonction est `bitShiftRight()`/`bitShiftLeft()`).
    Ce test parcourt TOUS les builders SQL exposés par le module et vérifie
    qu'aucun n'écrit ces deux séquences dans le texte produit — c'est le
    garde-fou demandé contre CETTE famille de défaut (IPTos >> 2, défaut n°1
    du 2026-08-07), généralisé à toute construction future dans ce fichier."""
    sql, _ = appelle_le_builder()
    assert ">>" not in sql, f"opérateur C-like '>>' absent de ClickHouse trouvé dans le SQL : {sql}"
    assert "<<" not in sql, f"opérateur C-like '<<' absent de ClickHouse trouvé dans le SQL : {sql}"


class TestPlagesInternesParametrables:
    """Les plages « internes » doivent venir de la CONFIG, pas du code.

    DEMANDE UTILISATEUR (2026-08-10), qui corrige une erreur de conception que
    j'avais moi-même justifiée par un `CONFIG_HARDCODE_OK` :

        « les IP sont des bornes de plages RFC1918/CGNAT, ça pour moi ça part
          en variable d'environnement RFC1918 et c'est tout »

    Il a raison. L'argument « ce sont des constantes de la norme » ne tient
    pas : ces bornes ne décrivent pas une norme, elles décrivent CE QUE CE
    DÉPLOIEMENT considère comme son réseau interne.

    - Homelab : 192.168/16 + CGNAT 100.64/10 (adressage Tailscale).
    - Cible produit (CLAUDE.md) : 350 routeurs SFR en entreprise, adressage
      très probablement 10/8, AUCUN CGNAT Tailscale.

    Codées en dur, le filtre « source interne / destination interne » —
    celui-là même qui sépare le vrai motif de convergence du bruit (mesure
    décisive n°1 du 2026-08-07) — classerait mal le trafic chez le client.
    L'écran de diagnostic afficherait un résultat FAUX sans le moindre
    message : un zéro silencieux, proscrit par CLAUDE.md.
    """

    def test_le_defaut_est_le_prive_rfc1918_sans_cgnat(self) -> None:
        """Le défaut vise l'ENTREPRISE, pas le homelab.

        Le CGNAT `100.64.0.0/10` est délibérément ABSENT : c'est la plage
        qu'utilisent les VPN maillés (Tailscale…), donc une hypothèse
        d'infrastructure. L'inclure « au cas où » classerait « interne » du
        trafic qui ne l'est pas sur un site qui n'en utilise pas — le paquet
        porterait l'adressage du homelab jusque chez le client.

        Un déploiement derrière un VPN maillé l'ajoute dans son `.env` ; c'est
        documenté dans `stack/.env.example`.
        """
        from app.config import Settings

        reseaux = Settings().internal_networks_list()
        assert [str(r) for r in reseaux] == [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
        assert not any("100.64" in str(r) for r in reseaux), (
            "le CGNAT est de retour dans le défaut : le paquet réintroduit "
            "une hypothèse d'infrastructure (VPN maillé) chez le client"
        )

    def test_un_reglage_personnalise_change_reellement_le_sql(self) -> None:
        """Le cas d'entreprise : 10/8 seul, sans CGNAT Tailscale."""
        from app.services.diagnostics import build_internal_filter

        sql = build_internal_filter("SrcAddr", ["10.0.0.0/8"])
        assert "::ffff:10.0.0.0" in sql and "::ffff:10.255.255.255" in sql
        # Le CGNAT du homelab NE DOIT PLUS apparaître.
        assert "100.64" not in sql, (
            "une plage non déclarée par l'exploitant subsiste dans le SQL : "
            "le filtre porte encore l'adressage du homelab"
        )

    def test_plage_invalide_refusee_bruyamment(self) -> None:
        """Zéro silencieux : une saisie invalide ne doit pas passer inaperçue."""
        from app.services.diagnostics import build_internal_filter

        with pytest.raises(ValueError, match="pas-un-cidr"):
            build_internal_filter("SrcAddr", ["pas-un-cidr"])

    def test_liste_vide_refusee(self) -> None:
        """Un filtre vide ne matcherait RIEN — l'écran dirait « aucune
        convergence » comme si tout allait bien. Le pire des cas."""
        from app.services.diagnostics import build_internal_filter

        with pytest.raises(ValueError):
            build_internal_filter("SrcAddr", [])

    def test_plus_aucune_borne_litterale_dans_le_module(self) -> None:
        """Preuve que le paramétrage est RÉEL, pas ajouté à côté de l'ancien."""
        source = (
            Path(__file__).resolve().parent.parent / "app" / "services" / "diagnostics.py"
        ).read_text(encoding="utf-8")
        # On ignore les commentaires/docstrings : seul le code exécutable compte.
        code = "\n".join(
            ligne
            for ligne in source.splitlines()
            if not ligne.lstrip().startswith("#")
        )
        for borne in ("::ffff:10.0.0.0", "::ffff:192.168.0.0", "::ffff:100.64.0.0"):
            assert borne not in code, (
                f"borne littérale {borne} encore présente dans le code : "
                "le filtre n'est pas réellement paramétré"
            )


def test_classement_et_detail_partagent_exactement_les_memes_plages() -> None:
    """La cohérence porte sur la LISTE, pas sur des plages figées.

    Depuis le paramétrage (2026-08-10), les plages viennent de
    `OKVORADO_INTERNAL_NETWORKS`. Le vrai risque de régression n'est plus
    « telle plage manque » mais « le classement et le drill-down ne lisent pas
    la même configuration » : au clic, l'exploitant verrait alors plus (ou
    moins) de sources que le nombre annoncé dans le tableau.

    Ce test compare les bornes RÉELLEMENT présentes dans les deux requêtes,
    sans présumer lesquelles.
    """
    classement, _ = diagnostics.build_convergence_query(period="1h", min_sources=5, limit=50)
    detail, _ = diagnostics.build_convergence_detail_query(
        dst_addr="10.0.0.5", dst_port=445, period="1h", limit=50
    )

    bornes = lambda sql, col: set(  # noqa: E731 - lisibilité locale
        re.findall(rf"{col}\s*[<>]=\s*toIPv6\('::ffff:([0-9.]+)'\)", sql)
    )

    plages_classement = bornes(classement, "SrcAddr")
    assert plages_classement, "aucune borne source trouvée dans le classement"
    assert plages_classement == bornes(detail, "SrcAddr"), (
        "le classement et le drill-down ne filtrent pas sur les mêmes plages : "
        "le nombre de sources affiché au clic ne correspondra pas au compte "
        "annoncé dans le tableau"
    )
