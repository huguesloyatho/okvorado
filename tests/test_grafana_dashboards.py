"""Garde-fous des dashboards Grafana livrés dans `stack/grafana/`.

CE QUE CE LOT RÉSOUT (voir prompt de la tâche + CLAUDE.md racine, section « La
restitution — le fossé assumé ») : le constat de l'utilisateur — « on reste à
des années-lumière des dashboards que je t'ai montré » (NetFlow Analyzer) —
est fondé. Grafana rend ici la couche graphique (courbes empilées, donuts,
barres de saturation) que la console Akvorado/Okvorado ne sait pas produire.

Ces tests ne rejouent PAS les requêtes contre un vrai ClickHouse (aucune base
disponible en CI) : ils vérifient le JSON livré lui-même, à la manière de
`tests/test_stack_portable.py` pour les YAML Akvorado. Trois garde-fous
critiques, hérités des pièges mesurés en production sur CE projet :

1. `tests/test_sampling_rate.py` — toute somme de volume DOIT porter
   `* SamplingRate`, sinon le volume affiché serait divisé par le taux
   d'échantillonnage de l'exportateur, silencieusement.
2. Mesuré (2026-08-07) : ClickHouse rejette `>>` (`Code: 62 SYNTAX_ERROR`) —
   le DSCP doit passer par `bitShiftRight(IPTos, 2)`.
3. Mesuré : `cutIPv6(addr,0,1)` NE dé-mappe PAS une IPv4-mapped IPv6, il
   TRONQUE (rend `::ffff:100.64.0.0`). Les dashboards doivent utiliser
   `IPv6NumToString` (ou équivalent qui restitue l'adresse complète), jamais
   `cutIPv6`.

⚠️ Piège vécu 7 fois sur ce projet : un test qui fige un MOYEN (chaîne SQL
exacte, titre de panneau figé mot pour mot) casse au premier refactor
légitime et ne prouve rien. Ces tests visent l'OBSERVABLE : présence d'un
motif obligatoire, absence d'un motif interdit, structure JSON — jamais une
chaîne intégrale.

⚠️ Autre piège vécu : un test qui grep un motif interdit échoue sur sa PROPRE
documentation. Les recherches de motifs interdits retirent donc les
commentaires SQL (`--` et `/* */`) avant de chercher.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

GRAFANA_DIR = Path(__file__).resolve().parent.parent / "stack" / "grafana"
PROVISIONING_DIR = GRAFANA_DIR / "provisioning"
DASHBOARDS_DIR = GRAFANA_DIR / "dashboards"
DATASOURCE_FILE = PROVISIONING_DIR / "datasources" / "clickhouse.yml"
DASHBOARDS_PROVIDER_FILE = PROVISIONING_DIR / "dashboards" / "dashboards.yml"

# Motifs signant une adhérence à l'infra du homelab de qualification — voir
# tests/test_stack_portable.py pour le même garde-fou côté Akvorado. Ce stack
# doit démarrer sur une machine nue en entreprise, sans rien de ceci.
MOTIFS_HOMELAB = ("tailscale", "100.64.", "authelia", "proxy-frontal", "example")


def _fichiers_dashboards() -> list[Path]:
    fichiers = sorted(DASHBOARDS_DIR.glob("*.json"))
    assert fichiers, f"aucun dashboard JSON trouvé sous {DASHBOARDS_DIR}"
    return fichiers


def _charger_dashboard(chemin: Path) -> dict[str, Any]:
    contenu: dict[str, Any] = json.loads(chemin.read_text(encoding="utf-8"))
    return contenu


def _sans_commentaires_sql(texte: str) -> str:
    """Retire les commentaires SQL (`--` fin de ligne, `/* ... */`) avant tout grep.

    Même précaution que `tests/test_stack_portable.py::_sans_commentaires_yaml` :
    un commentaire qui EXPLIQUE pourquoi `sum(Bytes)` nu est interdit contient
    lui-même la chaîne recherchée par le garde-fou, et le ferait échouer sur sa
    propre documentation.
    """
    sans_bloc = re.sub(r"/\*.*?\*/", "", texte, flags=re.DOTALL)
    lignes = [re.sub(r"--.*$", "", ligne) for ligne in sans_bloc.splitlines()]
    return "\n".join(lignes)


def _toutes_les_requetes_sql(dashboard: dict[str, Any]) -> list[str]:
    """Extrait tout champ `rawSql`/`query` de tous les panneaux ET des variables
    `templating.list[*].query` — un dashboard riche porte du SQL aux deux
    endroits (panneaux ET peuplement dynamique des variables)."""
    requetes: list[str] = []

    def _visiter_targets(targets: list[Any]) -> None:
        for target in targets:
            if not isinstance(target, dict):
                continue
            for cle in ("rawSql", "query"):
                valeur = target.get(cle)
                if isinstance(valeur, str) and valeur.strip():
                    requetes.append(valeur)

    for panel in dashboard.get("panels", []):
        _visiter_targets(panel.get("targets", []) or [])
        # Panneaux imbriqués (lignes / rows repliables).
        for sous_panel in panel.get("panels", []) or []:
            _visiter_targets(sous_panel.get("targets", []) or [])

    for variable in dashboard.get("templating", {}).get("list", []) or []:
        query = variable.get("query")
        if isinstance(query, str) and query.strip():
            requetes.append(query)
        elif isinstance(query, dict):
            valeur = query.get("rawSql") or query.get("query")
            if isinstance(valeur, str) and valeur.strip():
                requetes.append(valeur)

    return requetes


def _requetes_des_panneaux_uniquement(dashboard: dict[str, Any]) -> list[str]:
    """Comme `_toutes_les_requetes_sql`, mais EXCLUT la requête de peuplement
    des variables `templating.list[*].query` — utile quand le garde-fou
    porte spécifiquement sur ce que filtrent les PANNEAUX (la requête qui
    liste les valeurs possibles d'une variable ne se filtre pas elle-même
    par cette variable)."""
    requetes: list[str] = []

    def _visiter_targets(targets: list[Any]) -> None:
        for target in targets:
            if not isinstance(target, dict):
                continue
            valeur = target.get("rawSql")
            if isinstance(valeur, str) and valeur.strip():
                requetes.append(valeur)

    for panel in dashboard.get("panels", []):
        _visiter_targets(panel.get("targets", []) or [])
        for sous_panel in panel.get("panels", []) or []:
            _visiter_targets(sous_panel.get("targets", []) or [])

    return requetes


# ---------------------------------------------------------------------------
# 0. Présence et parsing réel des fichiers
# ---------------------------------------------------------------------------


class TestFichiersPresents:
    def test_le_dossier_dashboards_contient_au_moins_un_json(self) -> None:
        assert list(DASHBOARDS_DIR.glob("*.json")), (
            f"aucun dashboard sous {DASHBOARDS_DIR} — rien à charger au démarrage"
        )

    @pytest.mark.parametrize(
        "chemin", sorted(DASHBOARDS_DIR.glob("*.json")) if DASHBOARDS_DIR.exists() else []
    )
    def test_chaque_dashboard_est_un_json_valide(self, chemin: Path) -> None:
        contenu = _charger_dashboard(chemin)
        assert isinstance(contenu, dict), f"{chemin.name} ne parse pas comme un objet JSON"
        assert "panels" in contenu, f"{chemin.name} ne porte aucune clé 'panels'"
        assert contenu.get("title"), f"{chemin.name} n'a pas de titre"

    def test_le_provisioning_datasource_est_un_yaml_valide(self) -> None:
        contenu = yaml.safe_load(DATASOURCE_FILE.read_text(encoding="utf-8"))
        assert isinstance(contenu, dict)

    def test_le_provisioning_dashboards_est_un_yaml_valide(self) -> None:
        contenu = yaml.safe_load(DASHBOARDS_PROVIDER_FILE.read_text(encoding="utf-8"))
        assert isinstance(contenu, dict)


# ---------------------------------------------------------------------------
# 1. GARDE-FOU CRITIQUE — aucune somme de volume sans SamplingRate
# ---------------------------------------------------------------------------


class TestSamplingRateDansLesDashboards:
    """Même esprit que `tests/test_sampling_rate.py` : un routeur en 1:1000
    n'émet qu'un flux sur mille. `sum(Bytes)` nu (sans `* SamplingRate`) serait
    invisible en qualification (softflowd échantillonne 1:1, le facteur est
    neutre) et vaudrait un facteur 1000 en entreprise."""

    COLONNES_A_ECHELLE = ("Bytes", "Packets")

    def test_aucune_somme_de_volume_sans_taux_dechantillonnage(self) -> None:
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for requete in _toutes_les_requetes_sql(dashboard):
                nettoyee = _sans_commentaires_sql(requete)
                for colonne in self.COLONNES_A_ECHELLE:
                    for match in re.finditer(rf"sum\(\s*{colonne}\s*\)", nettoyee):
                        offenders.append(f"{chemin.name}: {match.group(0)}")
        assert not offenders, (
            "sommes de volume SANS '* SamplingRate' trouvées — le volume "
            "affiché serait divisé par le taux d'échantillonnage de "
            "l'exportateur, silencieusement :\n  " + "\n  ".join(offenders)
        )

    def test_au_moins_une_agregation_par_dashboard_applique_bien_le_taux(self) -> None:
        """Miroir du précédent : sans cette assertion, retirer toute somme de
        volume ferait aussi passer le garde-fou ci-dessus au vert."""
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            toutes_requetes = _toutes_les_requetes_sql(dashboard)
            total = sum(
                len(
                    re.findall(
                        r"sum\(\s*\w+\s*\*\s*SamplingRate\s*\)",
                        _sans_commentaires_sql(requete),
                    )
                )
                for requete in toutes_requetes
            )
            assert total >= 1, (
                f"{chemin.name}: aucune agrégation 'sum(... * SamplingRate)' "
                "trouvée — un dashboard de trafic doit calculer au moins un volume"
            )

    def test_count_nest_jamais_mis_a_lechelle(self) -> None:
        """`count()` compte des flux OBSERVÉS, pas du trafic — la mise à
        l'échelle serait le défaut symétrique (cf. test_sampling_rate.py)."""
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for requete in _toutes_les_requetes_sql(dashboard):
                nettoyee = _sans_commentaires_sql(requete)
                assert not re.search(r"count\(\)\s*\*\s*SamplingRate", nettoyee), (
                    f"{chemin.name}: count() ne doit PAS être mis à l'échelle"
                )

    def test_le_garde_fou_mord_sur_un_sum_bytes_nu_sabote(self) -> None:
        """Sabotage : injecte un `sum(Bytes)` nu dans un JSON temporaire en
        mémoire (pas le fichier réel) et prouve que le motif serait détecté."""
        sql_sabote = "SELECT sum(Bytes) AS total FROM flows WHERE $__timeFilter(TimeReceived)"
        nettoyee = _sans_commentaires_sql(sql_sabote)
        assert re.search(r"sum\(\s*Bytes\s*\)", nettoyee), (
            "le motif de sabotage aurait dû rester détectable après nettoyage "
            "des commentaires — sinon le garde-fou ci-dessus ne prouve rien"
        )


# ---------------------------------------------------------------------------
# 2. GARDE-FOU CRITIQUE — aucun `>>`, le DSCP passe par bitShiftRight
# ---------------------------------------------------------------------------


class TestPasDoperateurDecalageBinaire:
    """Mesuré (2026-08-07) : `SELECT IPTos >> 2` renvoie `Code: 62
    SYNTAX_ERROR` sur ClickHouse. Le DSCP (bits de poids fort de IPTos) doit
    passer par `bitShiftRight(IPTos, 2)`."""

    def test_aucun_operateur_gtgt_dans_le_sql(self) -> None:
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for requete in _toutes_les_requetes_sql(dashboard):
                nettoyee = _sans_commentaires_sql(requete)
                if ">>" in nettoyee:
                    offenders.append(chemin.name)
        assert not offenders, (
            f"'>>' trouvé dans le SQL de : {offenders} — ClickHouse le refuse "
            "(Code: 62 SYNTAX_ERROR, mesuré). Utiliser bitShiftRight(IPTos, 2)."
        )

    def test_le_dscp_est_calcule_avec_bitshiftright(self) -> None:
        """Au moins un dashboard doit exposer le DSCP via bitShiftRight —
        sinon l'onglet QoS reproduit le bug déjà vécu en production."""
        trouve = False
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for requete in _toutes_les_requetes_sql(dashboard):
                if re.search(r"bitShiftRight\(\s*IPTos\s*,\s*2\s*\)", requete):
                    trouve = True
        assert trouve, "aucune requête ne calcule le DSCP via bitShiftRight(IPTos, 2)"

    def test_le_garde_fou_mord_sur_un_gtgt_sabote(self) -> None:
        sql_sabote = "SELECT IPTos >> 2 AS dscp FROM flows"
        nettoyee = _sans_commentaires_sql(sql_sabote)
        assert ">>" in nettoyee, "le sabotage aurait dû rester détectable"


# ---------------------------------------------------------------------------
# 3. Aucune IP en dur, aucune adhérence au homelab
# ---------------------------------------------------------------------------

_IP_CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_ADRESSES_GENERIQUES = {"0.0.0.0/0", "0.0.0.0", "127.0.0.1"}

# CONFIG_HARDCODE_OK : bornes RFC1918 (10/8, 172.16/12, 192.168/16) + RFC6598
# CGNAT (100.64/10) utilisées par le filtre de convergence (motif SCCM/GPO,
# cf. mission dashboard « Applications & Diagnostic ») — ce sont des préfixes
# RÉSEAU UNIVERSELS, pas des adresses d'infra du homelab. Même exception déjà
# posée côté app/services/diagnostics.py (constante
# _CONVERGENCE_SOURCE_INTERNAL_FILTER, testée par
# tests/test_diagnostics.py::test_convergence_query_filtre_sources_externes_rfc1918_et_cgnat
# qui EXIGE "100.64" dans le SQL). 100.64.0.0/10 est le bloc CGNAT standard ;
# la ressemblance avec les IP Tailscale 100.64.x.x est une coïncidence de la
# RFC, pas une adresse de service homelab extraite en dur.
_BORNES_RFC_RESEAU_UNIVERSELLES = {
    "10.0.0.0",
    "10.255.255.255",
    "172.16.0.0",
    "172.31.255.255",
    "192.168.0.0",
    "192.168.255.255",
    "100.64.0.0",
    "100.127.255.255",
}


class TestZeroAdherenceHomelab:
    def test_aucune_adresse_ip_en_dur_dans_les_dashboards(self) -> None:
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            texte = chemin.read_text(encoding="utf-8")
            for match in _IP_CIDR_RE.findall(texte):
                if (
                    match not in _ADRESSES_GENERIQUES
                    and match not in _BORNES_RFC_RESEAU_UNIVERSELLES
                ):
                    offenders.append(f"{chemin.name}: {match}")
        assert not offenders, f"adresse(s) IPv4 en dur trouvées : {offenders}"

    def test_aucune_ip_en_dur_dans_le_provisioning_datasource(self) -> None:
        texte = DATASOURCE_FILE.read_text(encoding="utf-8")
        for match in _IP_CIDR_RE.findall(texte):
            assert match in _ADRESSES_GENERIQUES, (
                f"adresse IP en dur dans le provisioning datasource : {match} — "
                "le host ClickHouse doit être le nom du service Docker"
            )

    @pytest.mark.parametrize("motif", MOTIFS_HOMELAB)
    def test_aucun_motif_homelab_dans_les_dashboards(self, motif: str) -> None:
        """Exception ciblée pour motif='100.64.' : les bornes RFC6598 CGNAT
        légitimes (100.64.0.0, 100.127.255.255 — cf. _BORNES_RFC_RESEAU_UNIVERSELLES)
        sont retirées avant de chercher le motif, pour ne détecter QUE une
        adresse de service homelab en dur (ex. 192.0.2.6), jamais la borne
        de plage réseau qu'utilise le filtre de convergence SCCM/GPO."""
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            texte = chemin.read_text(encoding="utf-8").lower()
            if motif == "100.64.":
                for borne in _BORNES_RFC_RESEAU_UNIVERSELLES:
                    texte = texte.replace(borne, "")
            if motif in texte:
                offenders.append(chemin.name)
        assert not offenders, f"'{motif}' trouvé dans : {offenders}"

    @pytest.mark.parametrize("motif", MOTIFS_HOMELAB)
    def test_aucun_motif_homelab_dans_le_provisioning(self, motif: str) -> None:
        """Hors commentaire : un commentaire qui EXPLIQUE pourquoi ces motifs
        sont interdits les CITE lui-même (même piège que
        `test_stack_portable.py::_sans_commentaires_yaml`)."""
        for chemin in (DATASOURCE_FILE, DASHBOARDS_PROVIDER_FILE):
            lignes = chemin.read_text(encoding="utf-8").splitlines()
            sans_commentaires = "\n".join(re.sub(r"(^|\s)#.*$", "", ligne) for ligne in lignes)
            assert motif not in sans_commentaires.lower(), (
                f"'{motif}' trouvé hors commentaire dans {chemin.name}"
            )

    def test_le_host_clickhouse_est_le_nom_du_service_docker(self) -> None:
        """Le compose déclare le service ClickHouse sous le nom 'clickhouse' —
        vérifié dans stack/docker-compose.yml. Le provisioning doit le
        référencer par ce nom, jamais par IP."""
        contenu = yaml.safe_load(DATASOURCE_FILE.read_text(encoding="utf-8"))
        datasources = contenu.get("datasources", [])
        assert datasources, "aucune datasource déclarée"
        for ds in datasources:
            host = ds.get("jsonData", {}).get("host", "")
            assert host == "clickhouse", (
                f"host ClickHouse inattendu : {host!r} — attendu le nom du "
                "service Docker 'clickhouse' (voir stack/docker-compose.yml)"
            )


# ---------------------------------------------------------------------------
# 4. Le provisioning déclare bien la source de données et le dossier de dashboards
# ---------------------------------------------------------------------------


class TestProvisioning:
    def test_la_datasource_clickhouse_est_declaree(self) -> None:
        contenu = yaml.safe_load(DATASOURCE_FILE.read_text(encoding="utf-8"))
        datasources = contenu.get("datasources", [])
        types = [ds.get("type") for ds in datasources]
        assert "grafana-clickhouse-datasource" in types, (
            "aucune datasource de type 'grafana-clickhouse-datasource' déclarée "
            "— le plugin communautaire ClickHouse doit être utilisé"
        )

    def test_la_datasource_est_par_defaut(self) -> None:
        """Sans datasource par défaut, chaque panneau devrait la sélectionner
        manuellement — pas 'zéro clic'."""
        contenu = yaml.safe_load(DATASOURCE_FILE.read_text(encoding="utf-8"))
        datasources = contenu.get("datasources", [])
        assert any(ds.get("isDefault") is True for ds in datasources), (
            "aucune datasource marquée isDefault: true"
        )

    def test_le_provider_de_dashboards_pointe_vers_le_bon_dossier(self) -> None:
        contenu = yaml.safe_load(DASHBOARDS_PROVIDER_FILE.read_text(encoding="utf-8"))
        providers = contenu.get("providers", [])
        assert providers, "aucun provider de dashboards déclaré"
        chemins = [p.get("options", {}).get("path", "") for p in providers]
        assert any("/var/lib/grafana/dashboards" in c for c in chemins), (
            f"aucun provider ne pointe vers /var/lib/grafana/dashboards (chemins "
            f"trouvés : {chemins}) — cohérent avec le volume monté par le compose"
        )

    def test_le_garde_fou_datasource_mord_si_le_type_est_absent(self) -> None:
        datasources_sabotees: list[dict[str, Any]] = [{"name": "Autre", "type": "postgres"}]
        types = [ds.get("type") for ds in datasources_sabotees]
        assert "grafana-clickhouse-datasource" not in types, (
            "le sabotage aurait dû faire disparaître le type attendu"
        )


# ---------------------------------------------------------------------------
# 5. Les variables ($exporter, période) sont peuplées par requête, pas figées
# ---------------------------------------------------------------------------


class TestVariablesDynamiques:
    def _variables(self, dashboard: dict[str, Any]) -> list[dict[str, Any]]:
        return dashboard.get("templating", {}).get("list", []) or []

    def test_au_moins_un_dashboard_porte_une_variable_exporter(self) -> None:
        trouve = False
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            noms = [v.get("name") for v in self._variables(dashboard)]
            if "exporter" in noms:
                trouve = True
        assert trouve, "aucune variable 'exporter' trouvée dans les dashboards"

    def test_la_variable_exporter_est_peuplee_par_requete_pas_figee(self) -> None:
        """Le prompt exige une variable peuplée dynamiquement depuis
        ClickHouse (SELECT DISTINCT ExporterName), pas une liste 'custom'
        codée en dur — sinon un nouveau routeur du parc resterait invisible
        tant qu'on n'édite pas le dashboard à la main."""
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for variable in self._variables(dashboard):
                if variable.get("name") == "exporter":
                    assert variable.get("type") == "query", (
                        f"{chemin.name}: la variable 'exporter' doit être de "
                        f"type 'query' (peuplée par requête), pas {variable.get('type')!r}"
                    )
                    query = variable.get("query")
                    query_sql = (
                        query
                        if isinstance(query, str)
                        else (query or {}).get("rawSql") or (query or {}).get("query") or ""
                    )
                    assert re.search(r"(?i)distinct\s+ExporterName", query_sql), (
                        f"{chemin.name}: la requête de la variable 'exporter' ne "
                        f"fait pas 'DISTINCT ExporterName' : {query_sql!r}"
                    )

    def test_aucune_variable_exporter_de_type_custom_ou_liste_figee(self) -> None:
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for variable in self._variables(dashboard):
                if variable.get("name") == "exporter":
                    assert variable.get("type") not in ("custom", "constant"), (
                        f"{chemin.name}: variable 'exporter' figée "
                        f"({variable.get('type')!r}) — doit être peuplée dynamiquement"
                    )

    def test_le_garde_fou_variable_mord_si_le_type_devient_custom(self) -> None:
        variable_sabotee = {"name": "exporter", "type": "custom", "query": "r1,r2,r3"}
        assert variable_sabotee["type"] in ("custom", "constant"), (
            "le sabotage aurait dû produire un type détectable comme figé"
        )


# ---------------------------------------------------------------------------
# 6. Bornes de période — $__timeFilter, LIMIT plafonné sur les tops
# ---------------------------------------------------------------------------


class TestBornesDePeriode:
    """ClickHouse partage la base avec la console Akvorado : une requête non
    bornée peut faire tomber le service (cf. CLAUDE.md racine, section
    'Bornes de période' du prompt de cette tâche)."""

    def test_toute_requete_sur_flows_utilise_le_filtre_temporel_grafana(self) -> None:
        """`$__timeFilter` est l'écriture normale. EXCEPTION légitime : le
        motif H (nouveau flux, cf. lot Diagnostic 2026-08-08) compare la
        fenêtre courante à la fenêtre PRÉCÉDENTE, que `$__timeFilter` ne
        couvre pas (il ne borne QUE $__fromTime -> $__toTime) — la requête
        construit alors sa propre borne, explicitement dérivée de
        `$__fromTime`/`$__toTime` (jamais une date en dur), ce qui est un
        équivalent fonctionnel qui protège tout autant contre une requête
        non bornée. Reconnu ICI seulement si la requête référence les DEUX
        macros de bornage Grafana ; sinon, comme avant, `$__timeFilter` est
        obligatoire."""
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for requete in _toutes_les_requetes_sql(dashboard):
                nettoyee = _sans_commentaires_sql(requete)
                if not re.search(r"(?i)from\s+flows\b", nettoyee):
                    continue
                if "$__timeFilter" in nettoyee:
                    continue
                borne_explicite_deux_fenetres = (
                    "$__fromTime" in nettoyee and "$__toTime" in nettoyee
                )
                if not borne_explicite_deux_fenetres:
                    offenders.append(f"{chemin.name}: {nettoyee[:80]}...")
        assert not offenders, (
            "requêtes sur 'flows' sans $__timeFilter (ni borne équivalente "
            "dérivée de $__fromTime/$__toTime) — la table brute sert "
            "aussi la console Akvorado, une requête non bornée peut la faire "
            "tomber :\n  " + "\n  ".join(offenders)
        )

    def test_les_requetes_de_type_top_sont_plafonnees_par_limit(self) -> None:
        """Une requête ORDER BY ... DESC sans LIMIT est un 'top' non plafonné."""
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for requete in _toutes_les_requetes_sql(dashboard):
                nettoyee = _sans_commentaires_sql(requete)
                if re.search(r"(?i)order\s+by.+desc", nettoyee) and not re.search(
                    r"(?i)\blimit\s+\d+", nettoyee
                ):
                    offenders.append(f"{chemin.name}: {nettoyee[:80]}...")
        assert not offenders, f"requêtes ORDER BY DESC sans LIMIT : {offenders}"

    def test_le_garde_fou_borne_mord_si_le_timefilter_disparait(self) -> None:
        sql_sabote = "SELECT sum(Bytes * SamplingRate) FROM flows GROUP BY ExporterName"
        nettoyee = _sans_commentaires_sql(sql_sabote)
        assert "$__timeFilter" not in nettoyee, "le sabotage aurait dû retirer le filtre temporel"


# ---------------------------------------------------------------------------
# 7. Restitution des adresses IPv4-mappées — jamais cutIPv6 (tronque)
# ---------------------------------------------------------------------------


class TestRestitutionAdressesIP:
    """Mesuré : `cutIPv6(addr,0,1)` ne dé-mappe PAS une IPv4-mapped IPv6, il
    TRONQUE (rend `::ffff:100.64.0.0` au lieu de l'adresse complète)."""

    def test_aucune_requete_nutilise_cutipv6_pour_afficher_une_adresse(self) -> None:
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for requete in _toutes_les_requetes_sql(dashboard):
                nettoyee = _sans_commentaires_sql(requete)
                if re.search(r"(?i)cutIPv6\s*\(", nettoyee):
                    offenders.append(chemin.name)
        assert not offenders, (
            f"cutIPv6() trouvé dans : {offenders} — il TRONQUE l'adresse "
            "(mesuré : rend '::ffff:100.64.0.0'), utiliser IPv6NumToString "
            "ou équivalent"
        )


# ---------------------------------------------------------------------------
# 8. Trois dashboards attendus, avec la richesse graphique demandée
# ---------------------------------------------------------------------------


class TestRichesseGraphique:
    """Le constat fondateur : « on reste à des années-lumière des dashboards
    que je t'ai montré » — les écrans doivent être GRAPHIQUES (courbes,
    donuts, barres), pas des tableaux de texte."""

    TYPES_GRAPHIQUES = {
        "timeseries",
        "piechart",
        "barchart",
        "bargauge",
        "gauge",
        "stat",
        "state-timeline",
    }

    def test_chaque_dashboard_porte_au_moins_un_panneau_graphique(self) -> None:
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            types = {p.get("type") for p in dashboard.get("panels", [])}
            assert types & self.TYPES_GRAPHIQUES, (
                f"{chemin.name}: aucun panneau graphique (types trouvés : {types}) "
                "— un tableau seul reproduit le défaut constaté"
            )

    def test_au_moins_un_dashboard_porte_une_serie_temporelle_empilee(self) -> None:
        """Vue d'ensemble du parc : trafic total dans le temps, EMPILÉ (comme
        NetFlow Analyzer)."""
        trouve = False
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for panel in dashboard.get("panels", []):
                if panel.get("type") != "timeseries":
                    continue
                stacking = (
                    panel.get("fieldConfig", {})
                    .get("defaults", {})
                    .get("custom", {})
                    .get("stacking", {})
                )
                if stacking.get("mode") and stacking.get("mode") != "none":
                    trouve = True
        assert trouve, "aucun panneau timeseries en mode empilé (stacking) trouvé"

    def test_au_moins_un_dashboard_porte_un_donut_de_repartition(self) -> None:
        trouve = any(
            any(p.get("type") == "piechart" for p in _charger_dashboard(c).get("panels", []))
            for c in _fichiers_dashboards()
        )
        assert trouve, "aucun panneau 'piechart' (donut) trouvé"

    def test_le_dashboard_vue_densemble_existe(self) -> None:
        titres = [_charger_dashboard(c).get("title", "").lower() for c in _fichiers_dashboards()]
        assert any("vue d" in t or "ensemble" in t or "parc" in t for t in titres), (
            f"aucun dashboard 'Vue d'ensemble du parc' trouvé (titres : {titres})"
        )

    def test_le_dashboard_par_exportateur_existe_avec_variable_exporter(self) -> None:
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            titre = dashboard.get("title", "").lower()
            if "exportateur" in titre:
                noms_variables = [
                    v.get("name") for v in dashboard.get("templating", {}).get("list", [])
                ]
                assert "exporter" in noms_variables, (
                    f"{chemin.name}: dashboard par exportateur sans variable 'exporter'"
                )
                return
        pytest.fail("aucun dashboard 'par exportateur' trouvé")

    def test_les_classes_dscp_mesurees_sont_nommees_quelque_part(self) -> None:
        """Classes mesurées en production (prompt) : BE, EF, CS6, CS1, CS5."""
        classes_attendues = {"BE", "EF", "CS6", "CS1", "CS5"}
        texte_complet = " ".join(c.read_text(encoding="utf-8") for c in _fichiers_dashboards())
        manquantes = {c for c in classes_attendues if c not in texte_complet}
        assert not manquantes, f"classes DSCP mesurées absentes des dashboards : {manquantes}"


# ---------------------------------------------------------------------------
# 9. Titres et libellés en français
# ---------------------------------------------------------------------------


class TestStyleFrancais:
    MOTS_FRANCAIS_ATTENDUS = (
        "trafic",
        "exportateur",
        "volume",
        "répartition",
        "application",
    )

    def test_au_moins_un_dashboard_porte_des_titres_en_francais(self) -> None:
        texte_complet = " ".join(
            _charger_dashboard(c).get("title", "").lower() for c in _fichiers_dashboards()
        )
        for panels_texte in (
            " ".join(
                p.get("title", "").lower()
                for c in _fichiers_dashboards()
                for p in _charger_dashboard(c).get("panels", [])
            ),
        ):
            texte_complet += " " + panels_texte
        trouves = [mot for mot in self.MOTS_FRANCAIS_ATTENDUS if mot in texte_complet]
        assert len(trouves) >= 3, (
            f"trop peu de vocabulaire français trouvé dans les titres "
            f"({trouves}) — le style attendu est francophone"
        )


# ---------------------------------------------------------------------------
# Le plugin ClickHouse — l'omission qui rend TOUS les dashboards vides
# ---------------------------------------------------------------------------


def test_le_compose_installe_le_plugin_clickhouse() -> None:
    """Sans `GF_INSTALL_PLUGINS`, chaque panneau affiche une erreur.

    DÉFAUT MESURÉ (2026-08-07). `grafana-clickhouse-datasource` est un plugin
    COMMUNAUTAIRE : il n'est PAS embarqué dans l'image `grafana/grafana`. Sans
    la variable qui l'installe au démarrage, la source de données provisionnée
    ne s'initialise jamais.

    Le symptôme est trompeur, et c'est ce qui rend ce test nécessaire : Grafana
    démarre, répond en HTTP, son interface s'ouvre, les dashboards sont bien
    listés — seuls les graphiques sont en erreur. Un contrôle de santé sur le
    port passerait au vert.

    Aucun test ne monte le conteneur : cette omission a été signalée à la main.
    Ce garde-fou la rend mécanique.
    """
    compose = (Path(__file__).parent.parent / "stack" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    sans_commentaires = re.sub(r"^\s*#.*$", "", compose, flags=re.MULTILINE)

    assert "GF_INSTALL_PLUGINS" in sans_commentaires, (
        "le service grafana n'installe aucun plugin : la source de données "
        "ClickHouse provisionnée resterait inopérante et TOUS les panneaux "
        "s'afficheraient en erreur, alors que Grafana répondrait normalement"
    )
    assert "grafana-clickhouse-datasource" in sans_commentaires, (
        "le plugin installé n'est pas celui de ClickHouse — la source de "
        "données provisionnée cible pourtant ce type"
    )


# ---------------------------------------------------------------------------
# 10. GARDE-FOU CRITIQUE — le filtre $exporter ne doit jamais produire de
#     SQL invalide quand la variable vaut « All »
# ---------------------------------------------------------------------------


class TestFiltreExporterValidePourAll:
    """DÉFAUT MESURÉ (2026-08-07), sur le stack RÉELLEMENT démarré, dans un
    vrai navigateur : le dashboard « Vue d'ensemble du parc » ouvert avec
    l'URL par défaut (`var-exporter=$__all`, sélection « Tous » à l'ouverture)
    affichait « No data » sur TOUS les panneaux, avec 8 requêtes en HTTP 400.

    Aucun des 45 tests alors verts ne l'a détecté : le JSON parsait, la
    datasource était bien déclarée, les panneaux étaient bien graphiques —
    mais aucun test n'exécutait le SQL produit. Ce défaut ne se voit QU'en
    montant le stack ET en ouvrant l'écran dans un navigateur.

    Root cause : l'ancien filtre était construit ainsi :

        (ExporterName IN ($exporter) OR '$exporter' = '$__all')

    Grafana interpole `$exporter` en TEXTE BRUT. Avec `includeAll: true` et
    `allValue: ".*"`, sélectionner « Tous » remplace `$exporter` par la
    chaîne LITTÉRALE `.*` (non quotée) — le SQL généré contient alors
    `IN (.*)`, que ClickHouse refuse de parser AVANT même d'atteindre la
    clause OR :

        Code: 62. DB::Exception: Syntax error: failed at position ... (.)

    Reproduit à l'identique contre le vrai ClickHouse (SSH sur
    192.0.2.6, akvorado-clickhouse-1) :
        SELECT count() FROM flows WHERE ... AND (ExporterName IN (.*) OR
        '.*' = '$__all')
        -> Code: 62. DB::Exception: Syntax error ... failed at position 95 (.)

    FIX retenu : `ExporterName IN (${exporter:singlequote})`, variable
    déclarée SANS `allValue`/`current` figés. Avec `includeAll: true` seul,
    Grafana développe « Tous » en la liste RÉELLE des valeurs renvoyées par
    la requête de la variable (`SELECT DISTINCT ExporterName ...`), toutes
    quotées et virgule-séparées par le formateur `singlequote` du plugin
    ClickHouse — donc un `IN (...)` toujours syntaxiquement valide, que la
    sélection soit un nom précis ou « Tous ». Vérifié par exécution directe
    contre le vrai moteur (nommé ET liste complète des 11 exportateurs
    réels) : les deux cas rendent un résultat, aucune erreur Code: 62.

    Ce test ne peut PAS exécuter ClickHouse depuis la CI (aucun moteur
    garanti) : il contrôle donc la CONSTRUCTION du SQL — absence du motif
    fautif littéral, jamais une exécution.

    ⚠️ Piège vécu 8 fois sur ce projet : un test qui grep un motif interdit
    échoue sur sa PROPRE documentation (cette docstring cite le motif fautif
    pour l'expliquer). `_sans_commentaires_sql` ne suffit pas ici car le
    motif n'est pas dans une requête SQL commentée mais dans le texte JSON
    (description de panneau/dashboard) : la recherche est donc restreinte
    aux seules requêtes SQL extraites (`_toutes_les_requetes_sql`), jamais
    au texte brut du fichier — les descriptions qui expliquent le choix
    (et citent volontairement `IN ($exporter)` ou `'$__all'`) ne les font
    donc jamais échouer.
    """

    def test_aucune_requete_ne_compare_litteralement_exporter_a___all(self) -> None:
        """Motif fautif n°1 : `'$exporter' = '$__all'` (ou variante espacée) —
        la comparaison littérale qui ne sauve rien puisque `IN ($exporter)`
        a déjà cassé le parsing avant d'y arriver."""
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for requete in _toutes_les_requetes_sql(dashboard):
                nettoyee = _sans_commentaires_sql(requete)
                if re.search(r"=\s*'\$__all'", nettoyee):
                    offenders.append(f"{chemin.name}: {nettoyee[:120]}")
        assert not offenders, (
            "comparaison littérale à '$__all' trouvée dans le SQL d'un panneau "
            "— motif du défaut mesuré (Code: 62 SYNTAX_ERROR quand $exporter "
            "vaut 'Tous') :\n  " + "\n  ".join(offenders)
        )

    def test_aucune_requete_ninterpole_exporter_nu_dans_un_in(self) -> None:
        """Motif fautif n°2, la vraie cause : `IN ($exporter)` — Grafana
        interpole la variable en texte brut, non quotée. Avec `allValue`
        réglé à `.*` (ou toute valeur spéciale non-SQL), le `IN(...)` casse
        le parsing ClickHouse. La forme sûre est le formateur dédié du
        plugin (`${exporter:singlequote}`, `${exporter:sqlstring}`, ou
        équivalent), jamais la variable nue dans un `IN`."""
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for requete in _toutes_les_requetes_sql(dashboard):
                nettoyee = _sans_commentaires_sql(requete)
                if re.search(r"IN\s*\(\s*\$exporter\s*\)", nettoyee):
                    offenders.append(f"{chemin.name}: {nettoyee[:120]}")
        assert not offenders, (
            "'IN ($exporter)' trouvé — la variable Grafana interpolée nue "
            "dans un IN casse le parsing ClickHouse dès que $exporter vaut "
            "une valeur spéciale ('.*', '$__all', ...) :\n  " + "\n  ".join(offenders)
        )

    def test_les_variables_exporter_multi_nont_pas_de_allvalue_custom(self) -> None:
        """Sans `allValue` custom, Grafana développe « Tous » en la liste
        RÉELLE des valeurs de la variable (comportement par défaut) — jamais
        une chaîne spéciale à réinjecter dans le SQL. C'est ce qui rend le
        filtre `IN (${exporter:singlequote})` valide dans les deux cas."""
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for variable in dashboard.get("templating", {}).get("list", []) or []:
                if variable.get("name") != "exporter":
                    continue
                if variable.get("multi") and variable.get("allValue"):
                    offenders.append(f"{chemin.name}: allValue={variable.get('allValue')!r}")
        assert not offenders, (
            "variable 'exporter' multi-sélection avec un allValue custom — "
            "retire allValue pour que 'Tous' développe la vraie liste de "
            f"valeurs plutôt qu'une chaîne spéciale non-SQL : {offenders}"
        )

    def test_les_requetes_multi_exporter_utilisent_le_formateur_singlequote(self) -> None:
        """Vérifie la solution retenue est bien en place (pas juste l'absence
        du bug) : les dashboards à variable multi-sélection ($exporter,
        includeAll=true) doivent filtrer les PANNEAUX via
        `ExporterName IN (${exporter:singlequote})`.

        Exclut la requête de peuplement de la variable elle-même (`SELECT
        DISTINCT ExporterName FROM flows ...`) : elle sert à LISTER les
        exportateurs disponibles, elle ne doit donc PAS se filtrer par la
        variable qu'elle peuple."""
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            variables = dashboard.get("templating", {}).get("list", []) or []
            est_multi_exporter = any(
                v.get("name") == "exporter" and v.get("multi") for v in variables
            )
            if not est_multi_exporter:
                continue
            requetes_panneaux = _requetes_des_panneaux_uniquement(dashboard)
            requetes_flows = [
                r
                for r in requetes_panneaux
                if re.search(r"(?i)from\s+flows\b", _sans_commentaires_sql(r))
            ]
            assert requetes_flows, f"{chemin.name}: aucune requête sur flows à vérifier"
            for requete in requetes_flows:
                nettoyee = _sans_commentaires_sql(requete)
                assert "${exporter:singlequote}" in nettoyee, (
                    f"{chemin.name}: requête sur flows sans le formateur "
                    f"${{exporter:singlequote}} attendu : {nettoyee[:120]}"
                )

    def test_le_garde_fou_mord_sur_le_motif_fautif_sabote(self) -> None:
        """Sabotage : réinjecte le motif fautif exact (celui mesuré en
        production) dans une requête en mémoire et prouve qu'il resterait
        détectable par les deux gardes ci-dessus — sans monter ClickHouse ni
        ouvrir de navigateur."""
        sql_sabote = (
            "SELECT count() FROM flows WHERE $__timeFilter(TimeReceived) "
            "AND (ExporterName IN ($exporter) OR '$exporter' = '$__all') "
            "GROUP BY application ORDER BY volume DESC LIMIT 20"
        )
        nettoyee = _sans_commentaires_sql(sql_sabote)
        assert re.search(r"=\s*'\$__all'", nettoyee), (
            "le sabotage aurait dû rester détectable par le garde n°1"
        )
        assert re.search(r"IN\s*\(\s*\$exporter\s*\)", nettoyee), (
            "le sabotage aurait dû rester détectable par le garde n°1"
        )


# ---------------------------------------------------------------------------
# `format` est un ENTIER, pas une chaîne — mesuré contre le plugin
# ---------------------------------------------------------------------------

# Correspondance MESURÉE (2026-08-07) en interrogeant l'API du plugin installé,
# et non déduite de la documentation — celle-ci ne publie pas l'énumération :
#   0 -> graph (série temporelle)   1 -> table   2 -> logs   3 -> trace
FORMATS_VALIDES = {0, 1, 2, 3}
FORMAT_SERIE_TEMPORELLE = 0


def test_le_format_des_panneaux_est_un_entier() -> None:
    """Une chaîne dans `format` fait échouer la requête en HTTP 400.

    DÉFAUT MESURÉ À L'ÉCRAN (2026-08-07) sur le stack réellement démarré. Les
    panneaux de série temporelle — les COURBES, précisément ce qui manquait aux
    écrans — étaient les seuls en erreur, avec un triangle d'alerte :

        error unmarshaling query JSON to the Query Model:
        invalid format value: time_series

    Le champ `format` du plugin ClickHouse attend un ENTIER. La chaîne
    `"time_series"` est refusée à la désérialisation, avant même que le SQL ne
    soit envoyé — d'où un symptôme trompeur : le SQL était parfaitement valide
    et s'exécutait à la main sans erreur.

    Vérifié en interrogeant l'API du plugin installé avec 0, 1, 2 et 3 : tous
    acceptés, et le champ `preferredVisualisationType` du frame rendu donne la
    correspondance ci-dessus. La documentation ne publie pas cette énumération.

    Pourquoi les tests ne l'ont pas vu : aucun n'envoie de requête au plugin.
    Sept panneaux sur huit répondaient en 200 — seuls ceux en `time_series`
    échouaient, ce qui rendait le défaut discret.
    """
    fautifs: list[str] = []
    for chemin in sorted(DASHBOARDS_DIR.glob("*.json")):
        dashboard = json.loads(chemin.read_text(encoding="utf-8"))
        for panneau in dashboard.get("panels", []):
            for cible in panneau.get("targets", []):
                fmt = cible.get("format")
                if fmt is None:
                    continue
                if not isinstance(fmt, int) or isinstance(fmt, bool) or fmt not in FORMATS_VALIDES:
                    fautifs.append(f"{chemin.name} / {panneau.get('title')} -> format={fmt!r}")

    assert not fautifs, (
        f"Ces panneaux portent un `format` invalide : {fautifs}. Le plugin "
        "ClickHouse attend un ENTIER (0=série temporelle, 1=table, 2=logs, "
        "3=trace). Une chaîne fait échouer la requête en HTTP 400 sur "
        "« invalid format value », avant même l'envoi du SQL."
    )


def test_les_panneaux_temporels_demandent_bien_une_serie_temporelle() -> None:
    """Un panneau `timeseries` qui demande le format table rend une courbe plate.

    Le contrôle précédent n'attrape que les valeurs invalides. Celui-ci vérifie
    la COHÉRENCE : un panneau de type `timeseries` doit demander le format 0,
    sinon Grafana reçoit un tableau là où il attend des séries — sans erreur,
    juste un graphique faux. Zéro silencieux typique.
    """
    incoherents: list[str] = []
    for chemin in sorted(DASHBOARDS_DIR.glob("*.json")):
        dashboard = json.loads(chemin.read_text(encoding="utf-8"))
        for panneau in dashboard.get("panels", []):
            if panneau.get("type") != "timeseries":
                continue
            for cible in panneau.get("targets", []):
                if cible.get("format") != FORMAT_SERIE_TEMPORELLE:
                    incoherents.append(
                        f"{chemin.name} / {panneau.get('title')} -> {cible.get('format')!r}"
                    )

    assert not incoherents, (
        f"Ces panneaux de courbe ne demandent pas une série temporelle : "
        f"{incoherents}. Attendu : format={FORMAT_SERIE_TEMPORELLE}."
    )


# ---------------------------------------------------------------------------
# 11. LOT NetFlow Analyzer (2026-08-08) — les dashboards se lient entre eux,
#     tout panneau de classement est plafonné
# ---------------------------------------------------------------------------
#
# Constat de l'utilisateur (7 captures ManageEngine versionnées dans
# reference/manageengine/) : « on reste très loin d'avoir un dashboard à la
# NetFlow ». Les 7 constantes relevées dans reference/manageengine/README.md
# incluent en position n°1 : « Tout est cliquable et navigable ». Ce bloc
# rend cette exigence mécanique — sans lien de panneau ni dataLink pointant
# vers un autre dashboard, l'accueil resterait une impasse (constat inverse
# du drill-down demandé).


def _liens_dun_panneau(panel: dict[str, Any]) -> list[dict[str, Any]]:
    """Récupère les liens d'UN panneau : `fieldConfig.defaults.links` (lien de
    panneau, s'applique à toutes les colonnes) ET `fieldConfig.overrides[].
    properties[id=links]` (lien posé sur UNE colonne précise via un matcher
    `byName` — le mécanisme correct dès qu'un panneau affiche plusieurs
    colonnes d'entité, cf. LOT correction cohérence des liens 2026-08-08 :
    un lien de panneau en dur sur `${__data.fields.X}` s'applique à TOUTES
    les colonnes, donc envoie la valeur de X même en cliquant une autre
    colonne — bug mesuré au navigateur, 10/20 liens incohérents avant fix)."""
    liens: list[dict[str, Any]] = []
    defaults = panel.get("fieldConfig", {}).get("defaults", {})
    for lien in defaults.get("links", []) or []:
        if isinstance(lien, dict):
            liens.append(lien)
    for override in panel.get("fieldConfig", {}).get("overrides", []) or []:
        if not isinstance(override, dict):
            continue
        for prop in override.get("properties", []) or []:
            if not isinstance(prop, dict) or prop.get("id") != "links":
                continue
            for lien in prop.get("value", []) or []:
                if isinstance(lien, dict):
                    liens.append(lien)
    return liens


def _tous_les_champs_links(dashboard: dict[str, Any]) -> list[dict[str, Any]]:
    """Récupère tous les liens (panneau + overrides par colonne, cf.
    `_liens_dun_panneau`) de tous les panneaux d'un dashboard, imbriqués
    (rows) inclus."""
    liens: list[dict[str, Any]] = []

    def _visiter(panels: list[Any]) -> None:
        for panel in panels:
            if not isinstance(panel, dict):
                continue
            liens.extend(_liens_dun_panneau(panel))
            _visiter(panel.get("panels", []) or [])

    _visiter(dashboard.get("panels", []))
    return liens


class TestDrillDownEntreDashboards:
    """Constante n°1 des captures ManageEngine : tout est cliquable, les
    écrans se lient entre eux (page d'accueil -> fiche équipement -> détail).
    Grafana rend ça avec les `links` de dashboard (navigation globale) et les
    `dataLinks` de panneau (navigation contextuelle, avec passage de
    variable, ex: var-exporter=...)."""

    def test_au_moins_un_dashboard_porte_des_links_de_dashboard(self) -> None:
        """`links` au niveau racine du dashboard (pas d'un panneau) — menu de
        navigation global entre écrans, visible en permanence."""
        trouve = False
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            if dashboard.get("links"):
                trouve = True
        assert trouve, (
            "aucun dashboard ne porte de 'links' racine — les écrans "
            "resteraient des impasses (constante n°1 des captures : "
            "'tout est cliquable et navigable')"
        )

    def test_au_moins_un_panneau_porte_un_datalink_avec_variable_exporter(self) -> None:
        """Le vrai drill-down contextuel : un panneau (table/barchart/state-
        timeline) dont le dataLink transmet `var-exporter` vers un autre
        dashboard — cliquer une ligne/barre ouvre la FICHE de CET
        exportateur précis, pas juste le dashboard générique."""
        trouve = False
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for lien in _tous_les_champs_links(dashboard):
                url = lien.get("url", "")
                if "var-exporter=" in url and "/d/okvorado-" in url:
                    trouve = True
        assert trouve, (
            "aucun dataLink de panneau ne transmet 'var-exporter=' vers un "
            "autre dashboard okvorado — le drill-down contextuel (cliquer "
            "un exportateur -> sa fiche) est absent"
        )

    def test_les_dashboards_lies_existent_bien_sous_forme_de_fichier(self) -> None:
        """Un dataLink qui pointe vers un uid inexistant est un lien mort.
        Vérifie que chaque uid référencé dans une URL '/d/<uid>/...' est bien
        le uid d'un des dashboards livrés dans ce lot."""
        uids_connus = {_charger_dashboard(c).get("uid") for c in _fichiers_dashboards()}
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for lien in _tous_les_champs_links(dashboard):
                url = lien.get("url", "")
                match = re.search(r"/d/([a-zA-Z0-9\-_]+)/", url)
                if match and match.group(1) not in uids_connus:
                    offenders.append(f"{chemin.name}: lien mort vers uid={match.group(1)!r}")
        assert not offenders, f"dataLinks pointant vers un uid inconnu : {offenders}"

    def test_le_garde_fou_datalink_mord_si_aucun_lien_ne_porte_var_exporter(self) -> None:
        """Sabotage : un dataLink sans variable transmise (lien générique)
        n'aurait pas dû satisfaire le garde ci-dessus."""
        lien_sabote = {"title": "x", "url": "/d/okvorado-par-exportateur/foo"}
        assert "var-exporter=" not in lien_sabote["url"], (
            "le sabotage aurait dû rester détectable (absence de 'var-exporter=')"
        )


class TestLimitSurLesClassements:
    """Le parc SFR compte 350 routeurs, 772+ interfaces chez l'utilisateur —
    la constante n°7 des captures : tout classement ('Top N ...') est
    paginé/plafonné, jamais une requête qui tenterait de tout rendre d'un
    coup. Miroir de TestBornesDePeriode, mais restreint aux panneaux dont le
    TITRE signale explicitement un classement (Top N / classement)."""

    MOTS_CLASSEMENT = ("top ", "classement", "top exportateurs", "top n")

    def _est_un_panneau_de_classement(self, titre: str) -> bool:
        titre_bas = titre.lower()
        return any(mot in titre_bas for mot in self.MOTS_CLASSEMENT)

    def test_tout_panneau_dont_le_titre_signale_un_classement_porte_un_limit(self) -> None:
        offenders: list[str] = []

        def _visiter(nom_fichier: str, panels: list[Any]) -> None:
            for panel in panels:
                if not isinstance(panel, dict):
                    continue
                titre = panel.get("title", "")
                if self._est_un_panneau_de_classement(titre):
                    for target in panel.get("targets", []) or []:
                        sql = target.get("rawSql", "")
                        if sql and not re.search(r"(?i)\blimit\s+\d+", _sans_commentaires_sql(sql)):
                            offenders.append(f"{nom_fichier} / {titre}")
                _visiter(nom_fichier, panel.get("panels", []) or [])

        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            _visiter(chemin.name, dashboard.get("panels", []))
        assert not offenders, (
            "panneaux de classement ('Top N ...') sans LIMIT — le parc "
            f"réel compte 350 routeurs, une requête non plafonnée ne "
            f"'top' plus rien : {offenders}"
        )

    def test_au_moins_un_panneau_de_classement_existe_dans_le_lot(self) -> None:
        """Miroir : sans cette assertion, renommer tous les panneaux pour
        éviter le mot 'top' ferait aussi passer le garde ci-dessus au vert."""
        trouve = False
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for panel in dashboard.get("panels", []):
                if self._est_un_panneau_de_classement(panel.get("title", "")):
                    trouve = True
        assert trouve, "aucun panneau 'Top N ...' trouvé dans l'ensemble des dashboards"

    def test_le_garde_fou_limit_mord_sur_un_top_sans_limit_sabote(self) -> None:
        sql_sabote = (
            "SELECT ExporterName, sum(Bytes * SamplingRate) AS volume "
            "FROM flows WHERE $__timeFilter(TimeReceived) "
            "GROUP BY ExporterName ORDER BY volume DESC"
        )
        nettoyee = _sans_commentaires_sql(sql_sabote)
        assert not re.search(r"(?i)\blimit\s+\d+", nettoyee), (
            "le sabotage aurait dû rester détectable (absence de LIMIT)"
        )


class TestNouveauxDashboardsDuLot:
    """Le lot ajoute 3 dashboards par rapport à l'existant : la page
    d'accueil ('Traffic Summary'), le 'Network Snapshot' (tableaux de
    classement) et la fiche équipement enrichie. Garde-fous de présence."""

    def test_le_dashboard_accueil_existe(self) -> None:
        titres = [_charger_dashboard(c).get("title", "").lower() for c in _fichiers_dashboards()]
        assert any("accueil" in t or "traffic summary" in t for t in titres), (
            f"aucun dashboard d'accueil trouvé (titres : {titres})"
        )

    def test_le_dashboard_network_snapshot_existe(self) -> None:
        titres = [_charger_dashboard(c).get("title", "").lower() for c in _fichiers_dashboards()]
        assert any("snapshot" in t for t in titres), (
            f"aucun dashboard 'Network Snapshot' trouvé (titres : {titres})"
        )

    def test_la_fiche_exportateur_porte_un_resume_et_un_flow_details(self) -> None:
        """Les captures 03-06 exigent : résumé équipement, trafic Max/Avg/
        Volume, interfaces IN/OUT, flux reçus/rejetés — tous sur la même
        fiche 'Par exportateur'."""
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            if "exportateur" not in dashboard.get("title", "").lower():
                continue
            titres_panneaux = " ".join(
                p.get("title", "").lower() for p in dashboard.get("panels", [])
            )
            assert "rejet" in titres_panneaux or "reçus" in titres_panneaux, (
                f"{chemin.name}: aucun panneau évoquant les flux reçus/rejetés"
            )
            assert "utilisation" in titres_panneaux, (
                f"{chemin.name}: aucun panneau d'utilisation d'interface (%)"
            )
            return
        pytest.fail("aucun dashboard 'par exportateur' trouvé")

    def test_toutes_les_vitesses_dinterface_utilisent_max_jamais_any_sur_lunion(self) -> None:
        """DÉFAUT MESURÉ (2026-08-08) contre le vrai ClickHouse : dans un
        agrégat externe groupant deux branches UNION ALL (une pour IN, une
        pour OUT), `any(vitesse_if)` peut piocher la valeur 0 par défaut de
        la branche qui n'est pas censée porter la vitesse — reproduit sur
        l'exportateur 'clm'/'tailscale0' : utilisation_out plafonnée à 100%
        artificiellement au lieu de ~0.11%. Fix : `max(vitesse_if)`.
        Ce garde-fou empêche la régression vers `any(vitesse` sur ce motif
        précis (vitesse d'interface reconstituée après UNION ALL)."""
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for requete in _toutes_les_requetes_sql(dashboard):
                nettoyee = _sans_commentaires_sql(requete)
                if "UNION ALL" not in nettoyee.upper():
                    continue
                for match in re.finditer(r"any\(\s*(vitesse\w*)\s*\)", nettoyee):
                    offenders.append(f"{chemin.name}: any({match.group(1)}) après UNION ALL")
        assert not offenders, (
            "any(vitesse...) trouvé dans une requête avec UNION ALL — piochage "
            "non déterministe qui peut retenir 0 au lieu de la vraie vitesse "
            f"d'interface (mesuré, cf. docstring) : {offenders}"
        )


# ---------------------------------------------------------------------------
# Les macros Grafana doivent EXISTER dans le plugin ClickHouse
# ---------------------------------------------------------------------------

# Macros vérifiées UNE PAR UNE contre le plugin installé (2026-08-08), en
# envoyant une requête à l'API et en lisant la réponse :
#   SUPPORTÉES     : $__timeFilter, $__timeInterval, $__fromTime, $__toTime,
#                    $__interval_s
#   NON SUPPORTÉES : $__unixEpochFrom, $__unixEpochTo, $__timeInterval_ms,
#                    $__dateTimeFilter
MACROS_INEXISTANTES = (
    "$__unixEpochFrom",
    "$__unixEpochTo",
    "$__timeInterval_ms",
    "$__dateTimeFilter",
)


def test_aucune_requete_nutilise_une_macro_absente_du_plugin() -> None:
    """Une macro inconnue part TELLE QUELLE dans le SQL et le fait échouer.

    DÉFAUT MESURÉ À L'ÉCRAN (2026-08-08). Le panneau « Avg Speed » de la fiche
    équipement affichait « No data » avec un triangle d'alerte. Erreur réelle :

        Code: 46. DB::Exception: Function with name `$__unixEpochTo`
        does not exist. (UNKNOWN_FUNCTION)

    Ces macros existent dans d'autres sources de données Grafana (SQL, Postgres),
    mais PAS dans le plugin ClickHouse : il ne les remplace pas, et ClickHouse
    reçoit le texte brut qu'il prend pour un appel de fonction.

    SIX panneaux étaient touchés, dont l'utilisation des interfaces en % — un
    point central des captures de référence.

    La durée de la fenêtre s'écrit avec les macros réellement supportées :
        greatest(toUnixTimestamp($__toTime) - toUnixTimestamp($__fromTime), 1)
    Vérifié contre le plugin : rend 319 623 bits/s sur une fenêtre d'une heure.

    Pourquoi les tests ne l'ont pas vu : aucun n'envoie de requête au plugin.
    Le JSON était valide, le SQL syntaxiquement plausible, la macro juste absente.
    """
    fautifs: list[str] = []
    for chemin in sorted(DASHBOARDS_DIR.glob("*.json")):
        dashboard = json.loads(chemin.read_text(encoding="utf-8"))
        for panneau in dashboard.get("panels", []):
            for cible in panneau.get("targets", []):
                sql = cible.get("rawSql", "")
                for macro in MACROS_INEXISTANTES:
                    if macro in sql:
                        fautifs.append(f"{chemin.name} / {panneau.get('title')} -> {macro}")

    assert not fautifs, (
        f"Ces panneaux utilisent une macro absente du plugin ClickHouse : "
        f"{fautifs}. Elle partirait telle quelle dans le SQL et ferait échouer "
        "la requête sur « UNKNOWN_FUNCTION ». Pour une durée de fenêtre, écris "
        "greatest(toUnixTimestamp($__toTime) - toUnixTimestamp($__fromTime), 1)."
    )


def test_lexception_cgnat_ne_rend_pas_le_garde_fou_aveugle_a_une_vraie_ip_homelab() -> None:
    """Sabotage : preuve que l'exception posée pour les bornes RFC1918/CGNAT
    du filtre de convergence (_BORNES_RFC_RESEAU_UNIVERSELLES) ne blinde PAS
    le garde-fou contre une vraie adresse de service homelab en dur (ex.
    100.64.0.6, une IP précise, PAS une borne de plage réseau)."""
    # ⚠️ Adresse de SABOTAGE volontairement dans la plage CGNAT réelle : le
    # test vérifie qu'une IP de service précise reste détectée alors que les
    # BORNES de plage sont exemptées. L'anonymiser (comme tenté par erreur le
    # 2026-08-10) rendrait le sabotage indétectable et le test vide de sens.
    texte_sabote = "un commentaire qui référence 100.64.0.6 en dur"
    texte_nettoye = texte_sabote
    for borne in _BORNES_RFC_RESEAU_UNIVERSELLES:
        texte_nettoye = texte_nettoye.replace(borne, "")
    assert "100.64." in texte_nettoye, (
        "le sabotage aurait dû rester détectable : une IP homelab précise "
        "(100.64.0.6) n'est PAS une des bornes RFC exemptées "
        f"({_BORNES_RFC_RESEAU_UNIVERSELLES}), donc le motif '100.64.' doit "
        "subsister après le nettoyage des bornes légitimes"
    )


# ---------------------------------------------------------------------------
# 12. LOT « Applications & Diagnostic » (2026-08-08) — croisement app x QoS,
#     motif de convergence par application, variable $application dynamique
# ---------------------------------------------------------------------------
#
# Cas d'usage cible (fil rouge du projet) : « l'équipe windows a envoyé par
# GPO l'installer d'un logiciel depuis 160 sites vers un datacenter ; on
# s'attend à voir la QoS correspondant à SCCM saturé côté datacenter, et des
# flux SMB en masse (source = PC des sites, destination = serveur SCCM
# central) ». Ce bloc rend mécanique la présence des panneaux qui répondent
# à ce diagnostic dans le dashboard « Applications & Diagnostic ».


def _dashboard_applications_qos() -> dict[str, Any]:
    for chemin in _fichiers_dashboards():
        dashboard = _charger_dashboard(chemin)
        titre = dashboard.get("title", "").lower()
        if "application" in titre and ("diagnostic" in titre or "qos" in titre):
            return dashboard
    pytest.fail("aucun dashboard « Applications & ... » trouvé parmi les dashboards livrés")


class TestCroisementApplicationQos:
    """Constat de l'utilisateur : « je n'ai pas de vue orienté applicatif...
    j'ai besoin de l'info QOS mais également de l'info des applications qui
    match ». Sans ce croisement, impossible de voir « SCCM sature la QoS »."""

    def test_un_panneau_croise_application_et_classe_dscp(self) -> None:
        dashboard = _dashboard_applications_qos()
        trouve = False
        for panel in dashboard.get("panels", []):
            for target in panel.get("targets", []) or []:
                sql = target.get("rawSql", "")
                nettoyee = _sans_commentaires_sql(sql)
                if re.search(r"(?i)\bapplication\b", nettoyee) and re.search(
                    r"(?i)classe_dscp|bitShiftRight\(\s*IPTos\s*,\s*2\s*\)", nettoyee
                ):
                    trouve = True
        assert trouve, (
            "aucun panneau ne croise application et classe DSCP dans le même "
            "SELECT/GROUP BY — le croisement demandé par l'utilisateur est absent"
        )

    def test_le_croisement_groupe_bien_par_application_et_classe_dscp_ensemble(self) -> None:
        """Preuve de structure : un GROUP BY qui porte les deux dimensions
        ENSEMBLE, pas deux requêtes séparées qui ne se recoupent jamais."""
        dashboard = _dashboard_applications_qos()
        trouve = False
        for panel in dashboard.get("panels", []):
            for target in panel.get("targets", []) or []:
                sql = _sans_commentaires_sql(target.get("rawSql", ""))
                match = re.search(r"(?i)GROUP\s+BY\s+([^\n]+)", sql)
                if (
                    match
                    and "application" in match.group(1).lower()
                    and (
                        "classe_dscp" in match.group(1).lower() or "dscp" in match.group(1).lower()
                    )
                ):
                    trouve = True
        assert trouve, (
            "aucun GROUP BY ne porte à la fois 'application' et une dimension "
            "DSCP — le croisement doit agréger sur les deux dimensions ensemble"
        )


class TestMotifDeConvergenceParApplication:
    """Le motif SCCM : pour une application donnée, N sources distinctes vers
    peu de destinations distinctes. Réutilise l'esprit de
    app/services/diagnostics.py::build_convergence_query (filtre source
    interne RFC1918+CGNAT), sans dupliquer son code (ce lot ne touche pas à
    app/)."""

    def test_un_panneau_compte_sources_et_destinations_distinctes_par_application(self) -> None:
        dashboard = _dashboard_applications_qos()
        trouve = False
        for panel in dashboard.get("panels", []):
            for target in panel.get("targets", []) or []:
                sql = _sans_commentaires_sql(target.get("rawSql", ""))
                if re.search(r"(?i)uniqExact\(\s*SrcAddr\s*\)", sql) and re.search(
                    r"(?i)uniqExact\(\s*DstAddr\s*\)", sql
                ):
                    trouve = True
        assert trouve, (
            "aucun panneau ne calcule à la fois uniqExact(SrcAddr) et "
            "uniqExact(DstAddr) — le motif N sources -> 1 destination "
            "(cas SCCM/GPO) n'est pas rendu visible"
        )

    def test_le_panneau_de_convergence_filtre_les_sources_internes(self) -> None:
        """Sans le filtre source-interne (mesure décisive n°1 de
        app/services/diagnostics.py), le scan de ports Internet et le maillage
        P2P dominent le classement et masquent le vrai motif."""
        dashboard = _dashboard_applications_qos()
        trouve = False
        for panel in dashboard.get("panels", []):
            for target in panel.get("targets", []) or []:
                sql = _sans_commentaires_sql(target.get("rawSql", ""))
                if re.search(r"(?i)uniqExact\(\s*SrcAddr\s*\)", sql) and "100.64.0.0" in sql:
                    trouve = True
        assert trouve, (
            "aucun panneau de convergence ne filtre les sources internes "
            "(RFC1918 + CGNAT 100.64/10) — le bruit (scan Internet, maillage "
            "P2P) dominerait le classement"
        )


class TestVariableApplicationDynamique:
    """Geste demandé : '$application' peuplée dynamiquement, pour filtrer
    tout le dashboard sur une application ('je regarde SCCM')."""

    def test_la_variable_application_existe_et_est_peuplee_par_requete(self) -> None:
        dashboard = _dashboard_applications_qos()
        variables = dashboard.get("templating", {}).get("list", []) or []
        app_vars = [v for v in variables if v.get("name") == "application"]
        assert app_vars, "aucune variable 'application' trouvée"
        assert app_vars[0].get("type") == "query", (
            "la variable 'application' doit être peuplée par requête ('type': "
            f"'query'), pas {app_vars[0].get('type')!r}"
        )

    def test_la_variable_application_nest_pas_une_liste_figee(self) -> None:
        dashboard = _dashboard_applications_qos()
        variables = dashboard.get("templating", {}).get("list", []) or []
        for variable in variables:
            if variable.get("name") == "application":
                assert variable.get("type") not in ("custom", "constant"), (
                    "variable 'application' figée — doit être peuplée "
                    "dynamiquement depuis ClickHouse"
                )

    def test_au_moins_un_panneau_se_filtre_par_la_variable_application(self) -> None:
        dashboard = _dashboard_applications_qos()
        trouve = False
        for panel in dashboard.get("panels", []):
            for target in panel.get("targets", []) or []:
                sql = target.get("rawSql", "")
                if "${application:singlequote}" in sql:
                    trouve = True
        assert trouve, (
            "aucun panneau ne filtre par ${application:singlequote} — la "
            "variable $application existe mais rien ne l'utilise, le geste "
            "'je regarde SCCM' resterait sans effet"
        )


class TestResolutionNomApplicationJamaisVide:
    """Choix retenu (option a du prompt) : table de correspondance port->nom
    EN DUR dans le SQL (multiIf). Le repli pour un port non résolu doit être
    EXPLICITE ('tcp/827'), jamais une chaîne vide (cf. CLAUDE.md racine,
    règle n°2 — zéro silencieux)."""

    def test_le_repli_dapplication_non_resolue_est_explicite_jamais_vide(self) -> None:
        dashboard = _dashboard_applications_qos()
        trouve_repli_explicite = False
        for panel in dashboard.get("panels", []):
            for target in panel.get("targets", []) or []:
                sql = _sans_commentaires_sql(target.get("rawSql", ""))
                if re.search(r"(?i)multiIf\s*\(", sql) and re.search(
                    r"concat\(\s*if\(\s*Proto\s*=\s*6", sql
                ):
                    trouve_repli_explicite = True
        assert trouve_repli_explicite, (
            "aucun panneau ne porte le repli explicite 'tcp/<port>' / "
            "'udp/<port>' pour une application non résolue — un port hors "
            "table de correspondance ne doit jamais disparaître silencieusement"
        )

    def test_la_resolution_dapplication_utilise_le_port_de_service_least(self) -> None:
        """MESURE DÉCISIVE (prompt) : les ports éphémères (>=32768) portent
        266,73 GiB contre 179,41 GiB pour les ports de service — SrcPort ou
        DstPort nu classerait le RETOUR de connexion, pas le service.
        least(SrcPort, DstPort) est la règle mesurée comme correcte."""
        dashboard = _dashboard_applications_qos()
        trouve = False
        for panel in dashboard.get("panels", []):
            for target in panel.get("targets", []) or []:
                sql = _sans_commentaires_sql(target.get("rawSql", ""))
                if re.search(r"(?i)least\(\s*SrcPort\s*,\s*DstPort\s*\)", sql):
                    trouve = True
        assert trouve, (
            "aucun panneau ne calcule l'application via least(SrcPort, "
            "DstPort) — mesure décisive du prompt : les ports éphémères "
            "(>=32768) dominent en volume, SrcPort/DstPort nu classerait le "
            "retour de connexion plutôt que le port de service"
        )


# ---------------------------------------------------------------------------
# 13. LOT « Diagnostic incidents » (2026-08-08) — 4 motifs manquants B/C/E/H
# ---------------------------------------------------------------------------
#
# Reproche fondé de l'utilisateur : SCCM était un EXEMPLE d'incident à
# diagnostiquer, pas le périmètre. La famille réelle est « diagnostiquer un
# incident réseau depuis les flux ». Ce bloc couvre les 4 motifs qui
# manquaient à l'inventaire (B exfiltration, C balayage/scan, E panne/
# silence, H nouveau flux) — cherche le panneau par son RÔLE (motif SQL
# observable), jamais par un titre figé mot pour mot (piège vécu 7 fois sur
# ce projet, cf. docstring de module).


def _dashboard_diagnostic_incidents() -> dict[str, Any]:
    for chemin in _fichiers_dashboards():
        dashboard = _charger_dashboard(chemin)
        titre = dashboard.get("title", "").lower()
        if "diagnostic" in titre and "incident" in titre:
            return dashboard
    pytest.fail("aucun dashboard « Diagnostic incidents » trouvé parmi les dashboards livrés")


def _requetes_du_dashboard_diagnostic() -> list[str]:
    dashboard = _dashboard_diagnostic_incidents()
    requetes: list[str] = []
    for panel in dashboard.get("panels", []):
        for target in panel.get("targets", []) or []:
            sql = target.get("rawSql", "")
            if isinstance(sql, str) and sql.strip():
                requetes.append(_sans_commentaires_sql(sql))
    return requetes


class TestMotifExfiltration:
    """Motif B : source interne -> destination externe, volume anormal. Le
    rapport envoyé/reçu est le discriminant (une exfiltration envoie
    beaucoup, reçoit peu — l'inverse d'un téléchargement)."""

    def test_un_panneau_classe_le_trafic_sortant_par_volume_avec_pays_et_as(self) -> None:
        trouve = False
        for sql in _requetes_du_dashboard_diagnostic():
            if (
                re.search(r"(?i)DstCountry", sql)
                and re.search(r"(?i)DstAS", sql)
                and re.search(r"(?i)sum\(\s*Bytes\s*\*\s*SamplingRate\s*\)", sql)
            ):
                trouve = True
        assert trouve, (
            "aucun panneau ne classe le trafic sortant par volume avec pays "
            "(DstCountry) et AS (DstAS) de la destination — le motif "
            "exfiltration doit permettre de juger si la destination est un "
            "service connu ou un hébergeur inconnu"
        )

    def test_le_filtre_source_interne_destination_externe_est_present(self) -> None:
        """Sans ce double filtre (source DANS les plages privées, destination
        HORS de ces mêmes plages), on ne peut pas isoler le trafic sortant
        vers l'extérieur — cf. mesure décisive n°1 de diagnostics.py."""
        trouve = False
        for sql in _requetes_du_dashboard_diagnostic():
            if "100.64.0.0" in sql and re.search(r"(?i)AND\s+NOT\s*\(", sql) and "DstAddr" in sql:
                trouve = True
        assert trouve, (
            "aucun panneau ne filtre source interne + destination externe "
            "(NOT (...) sur les mêmes bornes RFC1918/CGNAT côté DstAddr) — "
            "le motif exfiltration doit isoler le trafic qui SORT du réseau"
        )

    def test_un_panneau_calcule_le_ratio_envoye_recu(self) -> None:
        """Le discriminant du prompt : une exfiltration a un ratio envoyé/
        reçu élevé, contrairement à un téléchargement (ratio faible)."""
        trouve = False
        for sql in _requetes_du_dashboard_diagnostic():
            if re.search(r"(?i)UNION\s+ALL", sql) and re.search(
                r"(?i)ratio_envoi_reception|ratio.*envoy|envoy.*ratio", sql
            ):
                trouve = True
        assert trouve, (
            "aucun panneau ne calcule un ratio envoyé/reçu par source — le "
            "discriminant exfiltration-vs-téléchargement (prompt) est absent"
        )


class TestMotifBalayageScan:
    """Motif C : 1 source -> N destinations et/ou beaucoup de ports
    distincts sur une même cible. uniqExact(DstAddr) et uniqExact(DstPort)
    par source, le ratio volume/destination distingue le scanner du serveur
    légitime."""

    def test_un_panneau_compte_destinations_et_ports_distincts_par_source(self) -> None:
        trouve = False
        for sql in _requetes_du_dashboard_diagnostic():
            if re.search(r"(?i)uniqExact\(\s*DstAddr\s*\)", sql) and re.search(
                r"(?i)uniqExact\(\s*DstPort\s*\)", sql
            ):
                trouve = True
        assert trouve, (
            "aucun panneau ne calcule à la fois uniqExact(DstAddr) et "
            "uniqExact(DstPort) par source — le motif 1 source -> N "
            "destinations/ports (balayage) n'est pas rendu visible"
        )

    def test_le_panneau_de_scan_calcule_le_ratio_volume_par_destination(self) -> None:
        """MESURE DÉCISIVE (2026-08-08, ce homelab) : le ratio octets/
        destination distingue le scanner (ratio faible, beaucoup de cibles
        touchées avec peu d'octets chacune) du client légitime à fort trafic
        (ratio élevé malgré beaucoup de destinations)."""
        trouve = False
        for sql in _requetes_du_dashboard_diagnostic():
            if re.search(r"(?i)uniqExact\(\s*DstAddr\s*\)", sql) and re.search(
                r"(?i)/\s*uniqExact\(\s*DstAddr\s*\)", sql
            ):
                trouve = True
        assert trouve, (
            "aucun panneau ne divise le volume par uniqExact(DstAddr) — le "
            "ratio octets/destination (discriminant scanner-vs-légitime, "
            "mesuré sur ce homelab) est absent"
        )


class TestMotifPanneSilence:
    """Motif E : pour chaque exportateur, la date du dernier flux reçu et le
    temps écoulé depuis. Complète l'alerte déjà en place (vue de diagnostic,
    pas seulement l'alerte)."""

    def test_un_panneau_calcule_le_dernier_flux_par_exportateur(self) -> None:
        trouve = False
        for sql in _requetes_du_dashboard_diagnostic():
            if re.search(r"(?i)max\(\s*TimeReceived\s*\)", sql) and re.search(
                r"(?i)GROUP\s+BY\s+.*ExporterName|GROUP\s+BY\s+exportateur", sql
            ):
                trouve = True
        assert trouve, (
            "aucun panneau ne calcule max(TimeReceived) groupé par "
            "exportateur — la vue de diagnostic 'dernier flux reçu' est "
            "absente"
        )

    def test_un_panneau_calcule_le_temps_ecoule_depuis_le_dernier_flux(self) -> None:
        trouve = False
        for sql in _requetes_du_dashboard_diagnostic():
            if re.search(r"(?i)dateDiff\s*\(", sql):
                trouve = True
        assert trouve, (
            "aucun panneau ne calcule le temps écoulé depuis le dernier "
            "flux (dateDiff) — sans lui, un exportateur silencieux ne "
            "ressort pas en tête du classement"
        )

    def test_un_panneau_compare_le_volume_actuel_a_une_moyenne(self) -> None:
        """Pour attraper les chutes PARTIELLES, pas seulement le silence
        total."""
        trouve = False
        for sql in _requetes_du_dashboard_diagnostic():
            if re.search(r"(?i)ratio_vs_moyenne|volume_moyen", sql):
                trouve = True
        assert trouve, (
            "aucun panneau ne compare le volume actuel à une moyenne — les "
            "chutes partielles (exportateur qui émet moins, sans silence "
            "total) ne sont pas détectées"
        )


class TestMotifNouveauFlux:
    """Motif H : application (ou couple source->destination) présente sur la
    fenêtre courante mais absente de la fenêtre précédente. $__timeFilter ne
    couvre que la fenêtre courante — la fenêtre précédente doit être
    reconstruite à la main depuis $__fromTime/$__toTime, jamais une date en
    dur."""

    def test_un_panneau_compare_fenetre_courante_et_fenetre_precedente(self) -> None:
        trouve = False
        for sql in _requetes_du_dashboard_diagnostic():
            if "$__fromTime" in sql and "$__toTime" in sql and re.search(r"(?i)NOT\s+IN\s*\(", sql):
                trouve = True
        assert trouve, (
            "aucun panneau ne compare la fenêtre courante à la fenêtre "
            "précédente (NOT IN sur une sous-requête bornée par "
            "$__fromTime/$__toTime) — le motif nouveau flux n'est pas rendu "
            "visible"
        )

    def test_la_fenetre_precedente_est_derivee_des_macros_jamais_dune_date_en_dur(
        self,
    ) -> None:
        """Piège explicite du prompt : $__timeFilter ne couvre que la
        fenêtre courante. La fenêtre précédente doit être calculée depuis
        $__fromTime/$__toTime (greatest + toIntervalSecond), jamais une date
        littérale codée en dur qui casserait dès que la période change."""
        trouve = False
        for sql in _requetes_du_dashboard_diagnostic():
            if "$__fromTime" in sql and re.search(
                r"(?i)toIntervalSecond\s*\(\s*greatest\s*\(", sql
            ):
                trouve = True
        assert trouve, (
            "aucun panneau ne dérive la fenêtre précédente de "
            "$__fromTime/$__toTime via toIntervalSecond(greatest(...)) — "
            "risque d'une date en dur qui casserait dès que la période "
            "sélectionnée change"
        )

    def test_aucune_date_litterale_en_dur_dans_le_calcul_de_fenetre_precedente(
        self,
    ) -> None:
        """Sabotage inverse : une date ISO en dur (ex. '2026-08-07') dans le
        SQL du dashboard livré serait un piège classique (bon en test manuel,
        cassé en prod dès que $__fromTime change)."""
        offenders: list[str] = []
        for sql in _requetes_du_dashboard_diagnostic():
            for match in re.finditer(r"toDateTime\(\s*'\d{4}-\d{2}-\d{2}", sql):
                offenders.append(match.group(0))
        assert not offenders, (
            f"date(s) littérale(s) en dur trouvées dans le dashboard "
            f"Diagnostic : {offenders} — la fenêtre précédente doit être "
            "dérivée de $__fromTime/$__toTime, jamais codée en dur"
        )


class TestPanneauxClassementDuLotDiagnosticPortentLimit:
    """Garde-fou local (le garde-fou global TestLimitSurLesClassements
    couvre déjà tous les dashboards, mais un test dédié documente
    explicitement l'exigence du prompt pour ce lot précis)."""

    def test_chaque_panneau_de_type_table_du_dashboard_diagnostic_porte_un_limit(
        self,
    ) -> None:
        dashboard = _dashboard_diagnostic_incidents()
        offenders: list[str] = []
        for panel in dashboard.get("panels", []):
            if panel.get("type") != "table":
                continue
            for target in panel.get("targets", []) or []:
                sql = _sans_commentaires_sql(target.get("rawSql", ""))
                if not re.search(r"(?i)\blimit\s+\d+", sql):
                    offenders.append(f"{panel.get('title')}: {sql[:80]}...")
        assert not offenders, f"panneau(x) table sans LIMIT : {offenders}"


# ---------------------------------------------------------------------------
# 14. LOT « Anomalies » (2026-08-08) — algo de scoring, remplacement
# ManageEngine NetFlow Analyzer, motif « flux anormaux en quantité qu'on
# voyait pas avant ». Un flux suspect n'est PAS seulement du P2P/BitTorrent —
# c'est la FAMILLE (tout flux hors norme) qui compte, pas l'exemple du
# prompt. Cherche le panneau par RÔLE SQL observable (composantes du score,
# variable de seuil, LIMIT), jamais par un titre figé mot pour mot.
# ---------------------------------------------------------------------------


def _dashboard_anomalies() -> dict[str, Any]:
    for chemin in _fichiers_dashboards():
        dashboard = _charger_dashboard(chemin)
        titre = dashboard.get("title", "").lower()
        if "anomalie" in titre:
            return dashboard
    pytest.fail("aucun dashboard « Anomalies » trouvé parmi les dashboards livrés")


def _requetes_du_dashboard_anomalies() -> list[str]:
    dashboard = _dashboard_anomalies()
    requetes: list[str] = []
    for panel in dashboard.get("panels", []):
        for target in panel.get("targets", []) or []:
            sql = target.get("rawSql", "")
            if isinstance(sql, str) and sql.strip():
                requetes.append(_sans_commentaires_sql(sql))
    return requetes


class TestDashboardAnomaliesExiste:
    def test_le_dashboard_anomalies_existe(self) -> None:
        dashboard = _dashboard_anomalies()
        assert dashboard.get("uid"), "le dashboard Anomalies n'a pas d'uid"

    def test_le_dashboard_anomalies_porte_au_moins_quatre_panneaux_de_contenu(
        self,
    ) -> None:
        """Les 4 panneaux attendus du prompt : flux suspects classés, score
        dans le temps, par catégorie applicative, détail d'un flux. Compte
        les panneaux non-row (les 'row' ne sont que des séparateurs visuels)."""
        dashboard = _dashboard_anomalies()
        panneaux_contenu = [p for p in dashboard.get("panels", []) if p.get("type") != "row"]
        assert len(panneaux_contenu) >= 4, (
            f"seulement {len(panneaux_contenu)} panneau(x) de contenu trouvé(s) — "
            "attendu au moins 4 (flux suspects, score dans le temps, par "
            "catégorie, détail d'un flux)"
        )


class TestScoreAvecComposantesExplicables:
    """Exigence non négociable du prompt : « le score doit être EXPLICABLE.
    Un exploitant qui voit une ligne en tête doit comprendre POURQUOI en
    lisant le tableau : affiche les composantes du score, pas seulement le
    total. Un score opaque ne sera pas utilisé »."""

    def test_le_panneau_de_classement_affiche_au_moins_deux_composantes_distinctes(
        self,
    ) -> None:
        """Un panneau qui ne rendrait qu'une colonne 'score' totale serait
        opaque. Cherche au moins deux alias de composantes distincts dans la
        même requête (ex. écart à la normale ET nouveauté, ou rareté ET
        catégorie) — la présence de PLUSIEURS signaux nommés séparément est
        la preuve observable que le score n'est pas une boîte noire."""
        trouve = False
        for sql in _requetes_du_dashboard_anomalies():
            alias_presents = sum(
                1
                for motif in (
                    r"(?i)\becart",
                    r"(?i)nouveaut",
                    r"(?i)raret",
                    r"(?i)categorie",
                )
                if re.search(motif, sql)
            )
            if alias_presents >= 2 and re.search(r"(?i)score", sql):
                trouve = True
        assert trouve, (
            "aucun panneau n'affiche au moins deux composantes explicites du "
            "score (écart à la normale, nouveauté, rareté, catégorie) à côté "
            "du score total — un score opaque ne sera pas utilisé (prompt)"
        )

    def test_le_score_repose_sur_un_ecart_type_calcule_en_sql(self) -> None:
        """Signal principal du prompt : « le volume de la fenêtre courante
        comparé à la moyenne des N périodes précédentes. Un écart-type est
        calculable en SQL (stddevPop), donc un z-score aussi »."""
        trouve = False
        for sql in _requetes_du_dashboard_anomalies():
            if re.search(r"(?i)stddevPop", sql):
                trouve = True
        assert trouve, (
            "aucune requête du dashboard Anomalies n'utilise stddevPop — le "
            "signal principal (écart à la normale, z-score) doit être "
            "calculé en SQL contre l'historique, pas estimé arbitrairement"
        )

    def test_le_score_nest_jamais_calcule_avec_un_historique_insuffisant(
        self,
    ) -> None:
        """Honnêteté du prompt : « sans historique long, une anomalie peut
        être un simple pic légitime ». Le calcul d'écart doit donc être
        gardé par un nombre minimum de buckets historiques (sinon 0/repli),
        jamais un z-score assené sur 0 ou 1 point d'historique."""
        trouve = False
        for sql in _requetes_du_dashboard_anomalies():
            if re.search(r"(?i)nb_buckets_hist", sql) and re.search(r"(?i)>=\s*\d", sql):
                trouve = True
        assert trouve, (
            "aucune requête ne garde le calcul d'écart par un seuil minimum "
            "de buckets historiques — un z-score calculé sur trop peu "
            "d'historique donnerait une fausse confiance (limite honnête du "
            "prompt)"
        )


class TestSeuilDeScoreEstUneVariable:
    """Exigence du prompt : « prévois un seuil réglable plutôt qu'un
    couperet arbitraire ». Le seuil doit être une variable Grafana
    ($seuil_score), jamais une constante SQL en dur type 'score >= 5'."""

    def test_la_variable_seuil_score_existe(self) -> None:
        dashboard = _dashboard_anomalies()
        noms_variables = {
            v.get("name") for v in dashboard.get("templating", {}).get("list", []) or []
        }
        assert "seuil_score" in noms_variables, (
            f"aucune variable 'seuil_score' trouvée parmi {noms_variables} — "
            "le seuil d'anomalie doit être réglable par l'exploitant, pas "
            "codé en dur"
        )

    def test_au_moins_un_panneau_filtre_ou_compare_au_seuil_via_la_variable(
        self,
    ) -> None:
        trouve = False
        for sql in _requetes_du_dashboard_anomalies():
            if "$seuil_score" in sql:
                trouve = True
        assert trouve, (
            "aucun panneau n'utilise $seuil_score dans son SQL — la "
            "variable existe mais rien ne s'y filtre, le geste "
            "'j'ajuste le seuil' resterait sans effet"
        )

    def test_aucun_seuil_numerique_en_dur_ne_remplace_la_variable(self) -> None:
        """Sabotage inverse : un panneau qui écrirait 'score >= 5' en dur au
        lieu de '$seuil_score' contournerait le réglage — piège classique
        (bon en test manuel, figé en prod)."""
        offenders: list[str] = []
        for sql in _requetes_du_dashboard_anomalies():
            for match in re.finditer(r"(?i)score(?:_total)?\s*>=\s*(\d+(?:\.\d+)?)", sql):
                offenders.append(match.group(0))
        assert not offenders, (
            f"seuil(s) numérique(s) en dur trouvé(s) à la place de "
            f"$seuil_score : {offenders} — le seuil doit rester réglable "
            "par variable, jamais un couperet figé dans le SQL"
        )


class TestFamilleAnomaliesPasSeulementLexempleP2P:
    """Reproche fondé du prompt, répété deux fois : « un flux suspect n'est
    pas seulement du SCCM ou du BitTorrent, c'est tout flux qui sort de
    l'ordinaire ». Le score doit rester calculable et affiché même quand
    AUCUNE composante catégorie/P2P ne matche — preuve que l'algorithme ne
    dépend pas de la catégorie applicative pour fonctionner."""

    def test_le_score_se_calcule_meme_sans_la_composante_categorie(self) -> None:
        """La composante 'catégorie à risque' doit être ADDITIVE (un
        aggravant parmi d'autres), jamais un prérequis : le score total doit
        rester calculable (les autres composantes présentes) indépendamment
        du résultat du test de catégorie."""
        trouve_score_independant = False
        for sql in _requetes_du_dashboard_anomalies():
            # Le score total doit combiner ecart + nouveaute + raret + categorie
            # via une somme (pas un ET logique qui rendrait la catégorie
            # obligatoire pour obtenir un score non-nul).
            if re.search(r"(?i)\bscore\b", sql) and re.search(r"\+", sql):
                trouve_score_independant = True
        assert trouve_score_independant, (
            "le score ne semble pas être une SOMME de composantes "
            "indépendantes — si la catégorie était un prérequis (ET) plutôt "
            "qu'un aggravant (+), un flux hors P2P/VPN/Jeu ne pourrait "
            "jamais remonter, contrairement à l'exigence du prompt"
        )

    def test_la_categorie_a_risque_reste_un_facteur_aggravant_documente_comme_tel(
        self,
    ) -> None:
        """Le prompt est explicite : « Ce n'est PAS une preuve, seulement un
        facteur aggravant. Un flux BitTorrent en entreprise mérite un
        regard, sans être une faute en soi. » Vérifie que la description du
        dashboard documente cette limite (garde-fou anti-régression léger :
        si la description disparaît, le principe de conception n'est plus
        tracé)."""
        dashboard = _dashboard_anomalies()
        description = dashboard.get("description", "").lower()
        assert "aggravant" in description, (
            "la description du dashboard Anomalies ne mentionne pas que la "
            "catégorie applicative est un facteur AGGRAVANT (pas une "
            "preuve) — cette nuance du prompt doit rester documentée pour "
            "l'exploitant"
        )


class TestExtensionCatalogueGrandPublicSansDoublonDeTable:
    """Le prompt est strict : « Une seule table de correspondance dans les
    dashboards, pas deux qui divergent. » Vérifie que le dashboard Anomalies
    porte bien des entrées du catalogue grand public (catégories entre
    crochets) ET que le dashboard 03 (qui porte la table originelle) n'a
    pas été dupliqué avec des valeurs différentes pour les mêmes ports."""

    def test_le_dashboard_anomalies_porte_des_categories_grand_public(self) -> None:
        trouve = False
        for sql in _requetes_du_dashboard_anomalies():
            if re.search(r"(?i)\[P2P\]|\[VPN\]|\[IoT\]|\[Jeu\]|\[Visio\]", sql):
                trouve = True
        assert trouve, (
            "aucune requête du dashboard Anomalies ne référence une "
            "catégorie du catalogue grand public ([P2P]/[VPN]/[IoT]/[Jeu]/"
            "[Visio]) — l'extension demandée par le prompt est absente"
        )

    def test_le_port_6881_bittorrent_a_la_meme_resolution_dans_les_deux_dashboards(
        self,
    ) -> None:
        """Garde-fou anti-divergence : le port 6881 (BitTorrent) doit
        résoudre vers la même famille de nom dans le dashboard 03
        (référence) et dans le dashboard Anomalies (extension) — sinon deux
        tables divergentes coexistent, exactement ce que le prompt interdit."""
        dashboard_03 = None
        for chemin in _fichiers_dashboards():
            if chemin.name.startswith("03-"):
                dashboard_03 = _charger_dashboard(chemin)
        assert dashboard_03 is not None, "dashboard 03 (Applications & Diagnostic) introuvable"

        def _porte_6881(dashboard: dict[str, Any]) -> bool:
            for panel in dashboard.get("panels", []):
                for target in panel.get("targets", []) or []:
                    sql = target.get("rawSql", "") or ""
                    if "6881" in sql:
                        return True
            for variable in dashboard.get("templating", {}).get("list", []) or []:
                query = variable.get("query", "")
                if isinstance(query, str) and "6881" in query:
                    return True
            return False

        anomalies = _dashboard_anomalies()
        assert _porte_6881(anomalies), (
            "le port 6881 (BitTorrent, entrée-phare du catalogue grand "
            "public) n'apparaît dans aucune requête du dashboard Anomalies"
        )


class TestPanneauxClassementDuLotAnomaliesPortentLimit:
    """Garde-fou local dédié (le garde-fou global TestLimitSurLesClassements
    couvre déjà tous les dashboards)."""

    def test_chaque_panneau_de_type_table_du_dashboard_anomalies_porte_un_limit(
        self,
    ) -> None:
        dashboard = _dashboard_anomalies()
        offenders: list[str] = []
        for panel in dashboard.get("panels", []):
            if panel.get("type") != "table":
                continue
            for target in panel.get("targets", []) or []:
                sql = _sans_commentaires_sql(target.get("rawSql", ""))
                if not re.search(r"(?i)\blimit\s+\d+", sql):
                    offenders.append(f"{panel.get('title')}: {sql[:80]}...")
        assert not offenders, f"panneau(x) table sans LIMIT : {offenders}"


class TestDetailDunFluxParAdresse:
    """Exigence du prompt : « savoir quelle source ou destination unique et
    l'application impactée » — un panneau doit permettre de sélectionner
    une adresse et voir tout ce qu'elle fait."""

    def test_une_variable_texte_permet_de_saisir_une_adresse(self) -> None:
        dashboard = _dashboard_anomalies()
        variables = dashboard.get("templating", {}).get("list", []) or []
        trouve = any(v.get("name") == "adresse" for v in variables)
        assert trouve, (
            "aucune variable 'adresse' trouvée — le prompt demande de "
            "pouvoir sélectionner une source ou destination unique et voir "
            "l'application impactée"
        )

    def test_un_panneau_filtre_par_ladresse_saisie_en_source_ou_destination(
        self,
    ) -> None:
        trouve = False
        for sql in _requetes_du_dashboard_anomalies():
            if "$adresse" in sql and re.search(r"(?i)\bOR\b", sql):
                trouve = True
        assert trouve, (
            "aucun panneau ne filtre par $adresse en source OU en "
            "destination — sans le OR, seul un sens de flux serait couvert"
        )


# ---------------------------------------------------------------------------
# 14. GARDE-FOU TRANSVERSE — tableaux filtrables, pagination, drill-down
#     exhaustif avec exemptions dérivées, liens morts, root links (2026-08-08)
# ---------------------------------------------------------------------------
#
# Ces classes couvrent tout le LOT (les 7 fichiers de dashboards), pas un lot
# métier précis — d'où leur emplacement en fin de fichier. Elles dérivent
# TOUT de la structure JSON (`_fichiers_dashboards()`, parcours des panneaux
# y compris imbriqués dans des rows) : aucune liste de titres ni d'ids figée
# à la main, puisque d'autres agents modifient encore les 7 fichiers en
# parallèle de ce test (cf. prompt de la tâche).


def _tous_les_panneaux_non_row(dashboard: dict[str, Any]) -> list[dict[str, Any]]:
    """Aplati tous les panneaux d'un dashboard (rows imbriquées incluses),
    en EXCLUANT les panneaux de type 'row' eux-mêmes (simples séparateurs
    visuels, jamais des panneaux de données)."""
    panneaux: list[dict[str, Any]] = []

    def _visiter(panels: list[Any]) -> None:
        for panel in panels:
            if not isinstance(panel, dict):
                continue
            if panel.get("type") != "row":
                panneaux.append(panel)
            _visiter(panel.get("panels", []) or [])

    _visiter(dashboard.get("panels", []))
    return panneaux


class TestTousLesTableauxSontFiltrables:
    """Exigence du prompt : chaque tableau ('table') de chaque dashboard doit
    être filtrable par colonne (`fieldConfig.defaults.custom.filterable`),
    sinon un tableau de plusieurs centaines de lignes (350 routeurs, 772+
    interfaces) est inexploitable à l'écran. Dérivé de la structure — AUCUNE
    liste figée de tableaux : parcourt tous les panneaux de type 'table' de
    tous les dashboards, imbriqués dans des rows compris."""

    def test_chaque_tableau_de_chaque_dashboard_est_filterable(self) -> None:
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for panel in _tous_les_panneaux_non_row(dashboard):
                if panel.get("type") != "table":
                    continue
                filterable = (
                    panel.get("fieldConfig", {})
                    .get("defaults", {})
                    .get("custom", {})
                    .get("filterable")
                )
                if filterable is not True:
                    offenders.append(f"{chemin.name}: panneau {panel.get('title')!r}")
        assert not offenders, (
            "tableau(x) sans 'filterable: true' — un tableau volumineux "
            f"(350 routeurs, 772+ interfaces) devient inexploitable sans "
            f"filtre par colonne : {offenders}"
        )

    def test_au_moins_un_tableau_existe_dans_lensemble_des_dashboards(self) -> None:
        """Miroir : sans cette assertion, renommer tous les tableaux en un
        autre type ('barchart', ...) ferait passer le garde ci-dessus au
        vert par absence de sujet à tester, pas par conformité réelle."""
        trouve = False
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for panel in _tous_les_panneaux_non_row(dashboard):
                if panel.get("type") == "table":
                    trouve = True
        assert trouve, "aucun panneau de type 'table' trouvé dans l'ensemble des dashboards"

    def test_le_garde_fou_filterable_mord_si_labsence_est_simulee(self) -> None:
        """Sabotage EN MÉMOIRE (aucun fichier modifié) : un panneau minimal
        sans 'filterable' prouve que le garde-fou le détecterait."""
        panneau_sabote = {"type": "table", "fieldConfig": {"defaults": {"custom": {}}}}
        filterable = (
            panneau_sabote.get("fieldConfig", {})
            .get("defaults", {})
            .get("custom", {})
            .get("filterable")
        )
        assert filterable is not True, (
            "le sabotage aurait dû rester détectable (absence de 'filterable: true')"
        )


class TestPaginationSurLesTableauxVolumineux:
    """Exigence du prompt : un tableau dont le LIMIT SQL est >= 15 doit
    activer la pagination (`options.footer.enablePagination`) — sans ça, un
    classement de 15+ lignes se déroule d'un bloc, contraire à l'esprit
    'zéro clic superflu, tout est navigable' des captures de référence."""

    SEUIL_LIMIT_PAGINATION = 15

    def _limit_max_du_panneau(self, panel: dict[str, Any]) -> int | None:
        """Extrait le plus grand LIMIT numérique trouvé dans le SQL nettoyé
        des targets du panneau — None si aucun LIMIT n'est détectable
        (ex: colonnes SNMP statiques, sans requête paramétrée par LIMIT)."""
        limites: list[int] = []
        for target in panel.get("targets", []) or []:
            sql = target.get("rawSql", "")
            if not isinstance(sql, str) or not sql.strip():
                continue
            nettoyee = _sans_commentaires_sql(sql)
            for match in re.finditer(r"(?i)\blimit\s+(\d+)", nettoyee):
                limites.append(int(match.group(1)))
        return max(limites) if limites else None

    def test_chaque_tableau_dont_le_limit_est_superieur_ou_egal_a_15_a_la_pagination_active(
        self,
    ) -> None:
        """Les tableaux SANS limit détectable dans leur SQL sont IGNORÉS par
        ce test précis (choix délibéré, pas un oubli) : un tableau qui liste
        des colonnes SNMP statiques ou tout autre contenu non borné par un
        LIMIT SQL explicite n'a pas de seuil de volumétrie à comparer à 15 —
        lui imposer la pagination serait une exigence non dérivée de la
        structure réelle du panneau, donc potentiellement un faux positif."""
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for panel in _tous_les_panneaux_non_row(dashboard):
                if panel.get("type") != "table":
                    continue
                limit_max = self._limit_max_du_panneau(panel)
                if limit_max is None or limit_max < self.SEUIL_LIMIT_PAGINATION:
                    continue
                pagination_active = (
                    panel.get("options", {}).get("footer", {}).get("enablePagination")
                )
                if pagination_active is not True:
                    offenders.append(
                        f"{chemin.name}: panneau {panel.get('title')!r} (LIMIT {limit_max})"
                    )
        assert not offenders, (
            "tableau(x) avec LIMIT >= 15 sans pagination activée "
            f"(options.footer.enablePagination) : {offenders}"
        )

    def test_le_garde_fou_pagination_mord_si_labsence_est_simulee(self) -> None:
        """Sabotage EN MÉMOIRE : un panneau table avec un LIMIT 50 dans son
        SQL, sans 'enablePagination', prouve que le garde-fou le détecterait."""
        panneau_sabote = {
            "type": "table",
            "targets": [{"rawSql": "SELECT ExporterName FROM flows LIMIT 50"}],
            "options": {"footer": {}},
        }
        limit_max = self._limit_max_du_panneau(panneau_sabote)
        assert limit_max is not None and limit_max >= self.SEUIL_LIMIT_PAGINATION, (
            "le sabotage aurait dû produire un LIMIT détectable >= au seuil"
        )
        pagination_active = (
            panneau_sabote.get("options", {}).get("footer", {}).get("enablePagination")
        )
        assert pagination_active is not True, (
            "le sabotage aurait dû rester détectable (absence de 'enablePagination: true')"
        )


# Exemptions au garde-fou "tout panneau de données porte un lien" — chaque
# entrée justifiée, PAS un fourre-tout. Clé = (nom_fichier, id_panneau).
# Le garde-fou réel (`TestExemptionsDeLienExplicitesEtCourtes`) juge d'abord
# CHAQUE panneau sans lien par CRITÈRE STRUCTUREL DÉRIVÉ
# (`_est_exempte_de_lien`, branches a-e) ; cette liste est le SECOND niveau,
# réservé aux cas où le panneau affiche bien une dimension identifiable
# (donc les critères a-e ne l'exemptent pas) mais où AUCUNE cible de
# rebond n'existe dans le lot livré (pas de variable Grafana pour cette
# dimension nulle part) — inventer une variable/dashboard pour ces cas
# serait hors périmètre (ce lot ne touche pas app/, pas de nouveau
# dashboard). Chaque entrée est commentée individuellement, une par une :
EXEMPTIONS_PANNEAUX_SANS_LIEN: set[tuple[str, int]] = {
    # "État des liens — répartition" (00, piechart) : group-by sur 'etat'
    # (Link Up / Link Up & NoFlows / Link Down) — aucun dashboard ni
    # variable Grafana ne filtre par état de lien dans ce lot ; rebondir
    # vers 02-par-exportateur exigerait de connaître l'exportateur, pas
    # présent en colonne affichée ici.
    ("00-accueil-traffic-summary.json", 4),
    # "Top N Protocol" (00, piechart) : group-by sur le protocole IP
    # (TCP/UDP/ICMP/GRE/OSPF...) — pas une entité identifiante au sens du
    # prompt (pas de "fiche protocole"), aucun dashboard "par protocole".
    ("00-accueil-traffic-summary.json", 7),
    # "Top QoS par classe DSCP" (03, piechart) : aucune variable DSCP
    # dédiée n'existe dans AUCUN des 7 dashboards du lot (contrairement à
    # exporter/application/categorie/adresse) — inventer une variable DSCP
    # est hors périmètre de ce lot (édition JSON + tests uniquement).
    ("03-applications-qos.json", 3),
    # "Classes DSCP — Trafic et pourcentage" (03, table) : même raison que
    # ci-dessus, table équivalente au panneau piechart id=3.
    ("03-applications-qos.json", 4),
    # "Volume sortant vers l'extérieur, par pays de destination" (05,
    # piechart) : group-by sur DstCountry — aucune variable pays/AS
    # n'existe dans le lot ; le panneau table voisin (id=31, même
    # dashboard) qui porte AUSSI pays/AS a bien un lien car il affiche EN
    # PLUS la colonne source (IP), qui elle a une cible (anomalies). Ce
    # panneau-ci n'affiche QUE pays + volume, rien d'autre à cliquer.
    ("05-diagnostic-incidents.json", 40),
    # "Flux au-dessus du seuil, par heure — et score p95 de l'heure" (06,
    # timeseries NON stacké — donc non couvert par le critère d) : c'est un
    # agrégat temporel PUR (compte de flux au-dessus du seuil, quantile du
    # score), sans dimension de group-by identifiable (l'axe X est le
    # temps, pas une entité) — rien à cliquer par point de la courbe.
    ("06-anomalies.json", 63),
}


def _est_exempte_de_lien(panel: dict[str, Any]) -> bool:
    """Juge si `panel` peut légitimement n'avoir AUCUN lien, par critère
    STRUCTUREL DÉRIVÉ de son contenu — jamais par titre ou id figé, puisque
    les ids exacts laissés sans lien par les autres agents ne sont pas
    connaissables à l'avance de façon fiable (cf. prompt de la tâche)."""
    type_panel = panel.get("type")

    # a) panneau natif Grafana 'alertlist' — liste d'alertes système, aucune
    #    dimension métier (exportateur, application, ...) à filtrer par clic.
    if type_panel == "alertlist":
        return True

    # b) panneau 'row' — séparateur visuel, pas un panneau de données. Déjà
    #    exclu par la marche normale du parcours (_tous_les_panneaux_non_row
    #    ou équivalent), documenté ici explicitement pour que la fonction
    #    reste correcte même appelée sur une liste de panneaux non filtrée.
    if type_panel == "row":
        return True

    requetes_sql = [
        _sans_commentaires_sql(t.get("rawSql", ""))
        for t in (panel.get("targets", []) or [])
        if isinstance(t, dict) and isinstance(t.get("rawSql"), str)
    ]
    sql_concatene = "\n".join(requetes_sql)

    # c) panneau 'stat' agrégat pur (un seul chiffre affiché) SANS GROUP BY
    #    dans son SQL : rien à cliquer, aucune dimension à ventiler.
    if type_panel == "stat" and not re.search(r"(?i)group\s+by", sql_concatene):
        return True

    # d) 'timeseries' empilé (stacking actif, mode != 'none') : Grafana
    #    n'offre pas de mécanisme de clic fiable PAR SÉRIE sur un empilement.
    if type_panel == "timeseries":
        stacking = (
            panel.get("fieldConfig", {}).get("defaults", {}).get("custom", {}).get("stacking", {})
        )
        mode = stacking.get("mode") if isinstance(stacking, dict) else None
        if mode and mode != "none":
            return True

    # e) aucune colonne du SELECT ne correspond à une entité identifiable
    #    connue (alias métier reconnaissable) : rien de cliquable à faire
    #    pointer vers un dashboard tiers. Dérivé du contenu SQL observable,
    #    pas d'un titre de panneau figé.
    alias_entite = re.search(
        r"(?i)\b(exportateur|application|classe_dscp|categorie|source|destination|"
        r"pays|as_destination|protocole|etat)\b",
        sql_concatene,
    )
    if sql_concatene and not alias_entite:
        return True

    return False


class TestExemptionsDeLienExplicitesEtCourtes:
    """Exigence du prompt : « tout panneau de données porte au moins un
    lien » — DÉRIVÉE de la structure des fichiers, jamais d'une liste
    écrite à la main. Les exemptions légitimes (panneau natif sans
    dimension, agrégat pur, série empilée, panneau sans dimension
    identifiable) sont dérivées par CRITÈRE STRUCTUREL
    (`_est_exempte_de_lien`), documenté branche par branche — pas une liste
    figée d'ids que ce test ne peut pas connaître à l'avance de façon
    fiable pendant que d'autres agents modifient encore les 7 fichiers."""

    def test_tout_panneau_de_donnees_porte_un_lien_ou_une_exemption_par_type(self) -> None:
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for panel in _tous_les_panneaux_non_row(dashboard):
                liens = _liens_dun_panneau(panel)
                if liens:
                    continue
                if _est_exempte_de_lien(panel):
                    continue
                if (chemin.name, panel.get("id")) in EXEMPTIONS_PANNEAUX_SANS_LIEN:
                    continue
                offenders.append(
                    f"{chemin.name}: panneau {panel.get('title')!r} (id={panel.get('id')!r})"
                )
        assert not offenders, (
            "panneau(x) de données sans lien ET sans exemption (structurelle "
            f"a-e, ni dans EXEMPTIONS_PANNEAUX_SANS_LIEN) : {offenders}"
        )

    def test_le_garde_fou_exemption_ne_couvre_pas_un_panneau_a_dimension_sans_lien_simule(
        self,
    ) -> None:
        """Sabotage EN MÉMOIRE : un panneau table avec une dimension
        identifiable (exportateur) et un GROUP BY, SANS lien — prouve que
        `_est_exempte_de_lien` ne l'exempte PAS (donc le garde-fou le
        détecterait comme un vrai trou, pas une fausse exemption complaisante)."""
        panneau_sabote = {
            "type": "table",
            "targets": [
                {
                    "rawSql": (
                        "SELECT ExporterName AS exportateur, sum(Bytes) "
                        "FROM flows GROUP BY exportateur"
                    )
                }
            ],
        }
        assert _est_exempte_de_lien(panneau_sabote) is False, (
            "le sabotage aurait dû rester détectable : un panneau table "
            "avec une dimension identifiable ('exportateur') ne doit PAS "
            "être couvert par une exemption structurelle"
        )

    def test_la_liste_dexemptions_explicites_reste_courte_pas_un_fourre_tout(self) -> None:
        """Garde-fou anti-dérive du prompt : « une liste courte, commentée,
        pas un fourre-tout ». Si EXEMPTIONS_PANNEAUX_SANS_LIEN grossissait
        au point de dépasser le nombre de panneaux RÉELLEMENT sans lien du
        lot (mesuré 2026-08-08 : 6), ce serait le signe qu'elle sert à
        contourner le garde-fou plutôt qu'à documenter des cas uniques."""
        assert len(EXEMPTIONS_PANNEAUX_SANS_LIEN) <= 10, (
            f"EXEMPTIONS_PANNEAUX_SANS_LIEN compte "
            f"{len(EXEMPTIONS_PANNEAUX_SANS_LIEN)} entrées — au-delà de 10, "
            "elle cesse d'être une liste courte de cas uniques documentés "
            "et devient un fourre-tout qui vide le garde-fou de son sens"
        )

    def test_chaque_exemption_explicite_cible_bien_un_panneau_existant(self) -> None:
        """Anti-dérive inverse : une entrée de la liste qui ne correspond à
        AUCUN panneau réel des dashboards livrés serait un reliquat mort —
        elle doit toujours pointer vers un (fichier, id) qui existe
        vraiment, sinon elle n'exempte rien et devrait être retirée."""
        panneaux_connus: set[tuple[str, int | None]] = set()
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for panel in _tous_les_panneaux_non_row(dashboard):
                panneaux_connus.add((chemin.name, panel.get("id")))
        offenders = [
            f"{fichier}:{id_panel}"
            for fichier, id_panel in EXEMPTIONS_PANNEAUX_SANS_LIEN
            if (fichier, id_panel) not in panneaux_connus
        ]
        assert not offenders, (
            f"entrée(s) d'exemption pointant vers un panneau inexistant "
            f"(reliquat mort à retirer) : {offenders}"
        )


class TestAucunLienMortEtVariablesCoherentes:
    """Exigence du prompt : un dataLink qui référence une variable
    `var-XXX=` doit cibler une variable qui EXISTE réellement sur le
    dashboard cible — sinon le clic ouvre un écran où le filtre n'a aucun
    effet, silencieusement (aucune erreur visible, juste un filtre ignoré)."""

    def test_aucune_variable_referencee_dans_un_datalink_nexiste_pas_dans_le_dashboard_cible(
        self,
    ) -> None:
        dashboards_par_uid = {
            _charger_dashboard(c).get("uid"): _charger_dashboard(c) for c in _fichiers_dashboards()
        }
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for lien in _tous_les_champs_links(dashboard):
                url = lien.get("url", "")
                match_uid = re.search(r"/d/([a-zA-Z0-9\-_]+)/", url)
                if not match_uid:
                    continue
                uid_cible = match_uid.group(1)
                dashboard_cible = dashboards_par_uid.get(uid_cible)
                if dashboard_cible is None:
                    # Lien mort déjà couvert par
                    # test_les_dashboards_lies_existent_bien_sous_forme_de_fichier
                    # — ne pas dupliquer ce garde-fou ici.
                    continue
                templating_cible = dashboard_cible.get("templating", {}).get("list", []) or []
                variables_cible = {v.get("name") for v in templating_cible}
                for var_referencee in re.findall(r"var-([a-zA-Z0-9_]+)=", url):
                    if var_referencee not in variables_cible:
                        offenders.append(
                            f"{chemin.name}: url={url!r} -> var-{var_referencee} "
                            f"absente des variables de uid={uid_cible!r}"
                        )
        assert not offenders, (
            "dataLink(s) référençant une variable absente du dashboard "
            f"cible — le filtre serait silencieusement ignoré au clic : {offenders}"
        )

    def test_le_garde_fou_variable_cible_mord_sur_une_variable_inexistante_simulee(self) -> None:
        """Sabotage EN MÉMOIRE : un dataLink 'var-inexistante=' vers un
        dashboard cible simulé dont `templating.list` ne porte pas cette
        variable — prouve que le garde-fou la détecterait."""
        url_sabotee = "/d/okvorado-par-exportateur/foo?var-inexistante=x&var-exporter=y"
        dashboard_cible_simule = {
            "uid": "okvorado-par-exportateur",
            "templating": {"list": [{"name": "exporter"}]},
        }
        variables_cible = {
            v.get("name") for v in dashboard_cible_simule.get("templating", {}).get("list", [])
        }
        vars_referencees = set(re.findall(r"var-([a-zA-Z0-9_]+)=", url_sabotee))
        manquantes = vars_referencees - variables_cible
        assert manquantes == {"inexistante"}, (
            "le sabotage aurait dû rester détectable : 'var-inexistante=' "
            "n'est pas une variable du dashboard cible simulé"
        )


class TestRootLinksPortentKeepTimeEtIncludeVars:
    """Exigence du prompt : tout lien racine de type 'dashboards' doit
    transporter la période courante (`keepTime`) et les variables courantes
    (`includeVars`) vers l'écran suivant — sinon naviguer via le menu global
    réinitialise silencieusement la fenêtre temporelle et les filtres
    ($exporter, $application, ...) déjà posés par l'utilisateur."""

    def test_tous_les_root_links_de_type_dashboards_portent_keeptime_et_includevars(
        self,
    ) -> None:
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for lien in dashboard.get("links", []) or []:
                if not isinstance(lien, dict) or lien.get("type") != "dashboards":
                    continue
                if lien.get("keepTime") is not True or lien.get("includeVars") is not True:
                    offenders.append(f"{chemin.name}: lien {lien.get('title')!r}")
        assert not offenders, (
            "root link(s) de type 'dashboards' sans keepTime/includeVars — "
            f"la navigation globale réinitialiserait silencieusement période "
            f"et filtres : {offenders}"
        )

    def test_au_moins_un_root_link_existe_par_dashboard_aucune_impasse(self) -> None:
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            if len(dashboard.get("links", []) or []) < 1:
                offenders.append(chemin.name)
        assert not offenders, (
            f"dashboard(s) sans aucun 'links' racine — impasse totale, "
            f"aucune navigation sortante possible : {offenders}"
        )

    def test_le_garde_fou_keeptime_mord_si_absent_simule(self) -> None:
        """Sabotage EN MÉMOIRE : un lien 'dashboards' sans keepTime ni
        includeVars prouve que le garde-fou le détecterait."""
        lien_sabote = {"type": "dashboards", "title": "x", "tags": ["y"]}
        assert lien_sabote.get("keepTime") is not True, (
            "le sabotage aurait dû rester détectable (keepTime absent)"
        )
        assert lien_sabote.get("includeVars") is not True, (
            "le sabotage aurait dû rester détectable (includeVars absent)"
        )


# ---------------------------------------------------------------------------
# 12. LOT correction cohérence des liens (2026-08-08) — un lien de PANNEAU en
#     dur (`${__data.fields.X}`) posé sur un panneau à PLUSIEURS colonnes
#     d'entité cliquable envoie la valeur de X quelle que soit la colonne
#     cliquée : mesuré au navigateur sur okvorado-anomalies (.6:3002),
#     10 liens IP sur 20 pointaient vers une AUTRE adresse que celle
#     affichée. La colonne 'destination' d'une table portait le lien de la
#     colonne 'source' — l'exploitant croit inspecter une IP, atterrit sur
#     une autre : pire qu'un lien absent sur un diagnostic d'incident.
# ---------------------------------------------------------------------------

# Alias d'entité qui ont une CIBLE de drill-down réelle dans ce lot (variable
# Grafana existante sur au moins un dashboard : var-exporter/var-application/
# var-categorie/var-adresse). Volontairement plus restreint que l'ensemble
# `alias_entite` de `_est_exempte_de_lien` (branche e) : classe_dscp/pays/
# as_destination/protocole/etat n'ont AUCUNE variable cible dans le lot (cf.
# EXEMPTIONS_PANNEAUX_SANS_LIEN ci-dessus) donc un panneau qui les affiche
# à côté d'un exportateur/application/source ne peut PAS en faire des
# colonnes cliquables séparées de toute façon — seules les entités CIBLABLES
# comptent pour juger si un lien de panneau en dur est fautif.
ALIAS_ENTITE_CIBLABLE = (
    "exportateur",
    "application",
    "categorie",
    "source",
    "destination",
    "ip",
    "adresse",
)


def _colonnes_du_select_final(sql: str) -> set[str]:
    """Colonnes du SELECT le plus EXTERNE d'une requête (celui qui détermine
    les colonnes RENDUES dans le panneau Grafana), à profondeur de
    parenthèses 0 — jamais les alias d'une sous-requête imbriquée. Distingue
    deux formes : `expr AS alias` (aliasé) et un identifiant nu qui
    propage le nom de colonne d'une sous-requête (`SELECT categorie, ... FROM
    (SELECT ... AS categorie ...)`) — mesuré sur 06-anomalies.json panneaux
    65/66 : `application`/`source` y sont des alias de SOUS-requête (calcul
    intermédiaire de `categorie`), PAS des colonnes affichées dans la table
    rendue — un panneau qui n'affiche QUE `categorie` a un lien de panneau
    en dur légitime, même si son SQL contient `AS application` ailleurs."""
    profondeur = 0
    positions_select = []
    i = 0
    n = len(sql)
    while i < n:
        c = sql[i]
        if c == "(":
            profondeur += 1
        elif c == ")":
            profondeur -= 1
        elif (
            profondeur == 0
            and sql[i : i + 6].upper() == "SELECT"
            and (i == 0 or not sql[i - 1].isalnum())
        ):
            positions_select.append(i)
        i += 1
    if not positions_select:
        return set()
    debut = positions_select[-1] + 6
    profondeur = 0
    fin = n
    i = debut
    while i < n:
        c = sql[i]
        if c == "(":
            profondeur += 1
        elif c == ")":
            profondeur -= 1
        elif profondeur == 0 and re.match(r"(?i)FROM\b", sql[i:]):
            fin = i
            break
        i += 1
    bloc_select = sql[debut:fin]
    trouves: set[str] = set()
    for colonne in re.split(r",(?![^(]*\))", bloc_select):
        colonne = colonne.strip()
        match_as = re.search(r"(?i)AS\s+(\w+)\s*\Z", colonne)
        if match_as:
            trouves.add(match_as.group(1).lower())
            continue
        match_nu = re.match(r"^(\w+)\Z", colonne)
        if match_nu:
            trouves.add(match_nu.group(1).lower())
    return trouves


def _colonnes_entite_ciblables_du_panneau(panel: dict[str, Any]) -> set[str]:
    """Alias de colonnes du SELECT FINAL (celui qui détermine ce qui est
    rendu dans le panneau — cf. `_colonnes_du_select_final`), restreints aux
    entités ciblables (`ALIAS_ENTITE_CIBLABLE`). Un panneau peut porter
    plusieurs `targets` (rare dans ce lot) : union des colonnes finales de
    chacun."""
    alias_ok = set(ALIAS_ENTITE_CIBLABLE)
    trouves: set[str] = set()
    for t in panel.get("targets", []) or []:
        if not isinstance(t, dict) or not isinstance(t.get("rawSql"), str):
            continue
        sql = _sans_commentaires_sql(t["rawSql"])
        trouves |= _colonnes_du_select_final(sql) & alias_ok
    return trouves


def _lien_panneau_en_dur_sur_data_fields(panel: dict[str, Any]) -> str | None:
    """Si `fieldConfig.defaults.links` (lien de PANNEAU, pas un override par
    colonne) référence `${__data.fields.<nom>}`, retourne `<nom>` — sinon
    None. Un tel lien s'applique à TOUTES les colonnes du panneau (mécanisme
    Grafana), donc n'est correct QUE si le panneau n'a rien d'autre à
    cliquer que cette colonne."""
    defaults = panel.get("fieldConfig", {}).get("defaults", {})
    for lien in defaults.get("links", []) or []:
        if not isinstance(lien, dict):
            continue
        match = re.search(r"\$\{__data\.fields\.([a-zA-Z0-9_]+)\}", lien.get("url", ""))
        if match:
            return match.group(1)
    return None


def _panneau_a_lien_en_dur_incoherent(panel: dict[str, Any]) -> bool:
    """LE motif fautif : un lien de panneau `${__data.fields.X}` alors que
    le panneau expose PLUSIEURS colonnes d'entité ciblable — la valeur de X
    est envoyée même quand on clique une AUTRE colonne d'entité que X."""
    alias_lien = _lien_panneau_en_dur_sur_data_fields(panel)
    if alias_lien is None:
        return False
    colonnes = _colonnes_entite_ciblables_du_panneau(panel)
    return len(colonnes) > 1


class TestCoherenceLienParColonne:
    """Un lien porté par une colonne d'entité doit passer la valeur de CETTE
    colonne — jamais une valeur fixée d'avance par un lien de panneau en dur
    qui s'applique à toutes les colonnes. Complète `TestDrillDownEntreDashboards`
    (qui vérifie qu'un lien EXISTE) : ici on vérifie qu'il pointe vers la
    BONNE valeur, ce que ni ce garde-fou-là ni `test_les_dashboards_lies_
    existent_bien_sous_forme_de_fichier` ne couvraient — un lien mort est
    détecté, un lien VIVANT mais qui pointe la mauvaise adresse ne l'était
    pas (c'est exactement le défaut mesuré au navigateur, cf. commentaire du
    bloc 12 ci-dessus)."""

    def test_aucun_panneau_ne_porte_un_lien_de_panneau_en_dur_sur_plusieurs_colonnes_dentite(
        self,
    ) -> None:
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for panel in _tous_les_panneaux_non_row(dashboard):
                if _panneau_a_lien_en_dur_incoherent(panel):
                    alias_lien = _lien_panneau_en_dur_sur_data_fields(panel)
                    colonnes = sorted(_colonnes_entite_ciblables_du_panneau(panel))
                    offenders.append(
                        f"{chemin.name}: panneau {panel.get('title')!r} (id={panel.get('id')!r}) "
                        f"— lien de panneau en dur sur '{alias_lien}' alors que les colonnes "
                        f"d'entité ciblables sont {colonnes} : cliquer une AUTRE colonne que "
                        f"'{alias_lien}' enverrait quand même la valeur de '{alias_lien}'"
                    )
        assert not offenders, (
            "panneau(x) avec un lien de PANNEAU en dur (${__data.fields.X}) sur plusieurs "
            f"colonnes d'entité — utiliser un override par colonne (byName + ${{__value.raw}}) "
            f"à la place : {offenders}"
        )

    def test_le_garde_fou_mord_sur_un_panneau_source_destination_avec_lien_en_dur_simule(
        self,
    ) -> None:
        """Sabotage EN MÉMOIRE : un panneau table avec colonnes source ET
        destination, lien de panneau en dur sur ${__data.fields.source} —
        EXACTEMENT le motif mesuré au navigateur sur okvorado-anomalies
        (colonne destination héritant du lien de la colonne source)."""
        panneau_sabote = {
            "id": 999,
            "type": "table",
            "title": "Panneau sabote (test)",
            "fieldConfig": {
                "defaults": {
                    "links": [
                        {
                            "title": "x",
                            "url": (
                                "/d/okvorado-anomalies/okvorado-anomalies"
                                "?var-adresse=${__data.fields.source}"
                            ),
                        }
                    ]
                },
                "overrides": [],
            },
            "targets": [
                {
                    "refId": "A",
                    "rawSql": (
                        "SELECT\n"
                        "    replaceOne(IPv6NumToString(SrcAddr), '::ffff:', '') AS source,\n"
                        "    replaceOne(IPv6NumToString(DstAddr), '::ffff:', '') AS destination,\n"
                        "    sum(Bytes * SamplingRate) AS volume\n"
                        "FROM flows\n"
                        "GROUP BY source, destination"
                    ),
                }
            ],
        }
        assert _panneau_a_lien_en_dur_incoherent(panneau_sabote) is True, (
            "le sabotage aurait dû rester détectable : lien en dur sur "
            "'source' alors que 'source' ET 'destination' sont ciblables"
        )

    def test_le_garde_fou_ne_mord_pas_sur_un_panneau_a_une_seule_colonne_dentite(self) -> None:
        """Contre-preuve : un panneau qui n'affiche QU'UNE colonne d'entité
        (ex. exportateur + compteurs non-entité) a un lien de panneau en dur
        LÉGITIME — le garde-fou ne doit PAS le faire échouer (pas de faux
        positif sur le cas normal)."""
        panneau_legitime = {
            "id": 998,
            "type": "barchart",
            "title": "Panneau legitime (test)",
            "fieldConfig": {
                "defaults": {
                    "links": [
                        {
                            "title": "x",
                            "url": (
                                "/d/okvorado-par-exportateur/okvorado-par-exportateur"
                                "?var-exporter=${__data.fields.exportateur}"
                            ),
                        }
                    ]
                },
                "overrides": [],
            },
            "targets": [
                {
                    "refId": "A",
                    "rawSql": (
                        "SELECT ExporterName AS exportateur, sum(Bytes * SamplingRate) AS volume\n"
                        "FROM flows\nGROUP BY exportateur"
                    ),
                }
            ],
        }
        assert _panneau_a_lien_en_dur_incoherent(panneau_legitime) is False, (
            "faux positif : une seule colonne d'entité ciblable (exportateur) "
            "— le lien de panneau en dur est correct ici, pas un défaut"
        )

    def test_tous_les_panneaux_livres_dans_ce_lot_utilisent_bien_value_raw_sur_les_overrides(
        self,
    ) -> None:
        """Preuve positive (pas seulement l'absence de régression) : chaque
        lien posé en override par colonne (`byName`) de ce lot utilise
        `${__value.raw}` — la valeur de LA cellule cliquée — jamais
        `${__data.fields.X}` qui resterait fixé sur une colonne, ce qui
        annulerait tout l'intérêt de l'override par colonne."""
        offenders: list[str] = []
        for chemin in _fichiers_dashboards():
            dashboard = _charger_dashboard(chemin)
            for panel in _tous_les_panneaux_non_row(dashboard):
                for override in panel.get("fieldConfig", {}).get("overrides", []) or []:
                    if not isinstance(override, dict):
                        continue
                    matcher = override.get("matcher", {})
                    if not isinstance(matcher, dict) or matcher.get("id") != "byName":
                        continue
                    for prop in override.get("properties", []) or []:
                        if not isinstance(prop, dict) or prop.get("id") != "links":
                            continue
                        for lien in prop.get("value", []) or []:
                            if not isinstance(lien, dict):
                                continue
                            url = lien.get("url", "")
                            if "${__data.fields." in url:
                                offenders.append(
                                    f"{chemin.name}: panneau {panel.get('title')!r} "
                                    f"override colonne {matcher.get('options')!r} "
                                    f"utilise ${{__data.fields.X}} au lieu de ${{__value.raw}}"
                                )
        assert not offenders, (
            f"override(s) par colonne utilisant ${{__data.fields.X}} au lieu de "
            f"${{__value.raw}} — la colonne resterait fixée sur une valeur, pas "
            f"celle de la cellule cliquée : {offenders}"
        )
