"""Garde-fous de la section « Colonnes du schéma » (`schema.enabled`).

POURQUOI cette section existe : activer la colonne DSCP — donc le widget
Top N QoS de la console — demandait jusqu'ici d'éditer `akvorado.yaml` en SSH.
C'est exactement le geste que ce projet supprime : la configuration doit se
régler DEPUIS L'ÉCRAN, y compris par quelqu'un sans accès shell sur l'hôte.

Ce que ces tests empêchent de revenir :

1. Une liste de colonnes qui DÉRIVE de la réalité du binaire. L'allowlist est
   figée ici EN DUR, avec sa source, précisément pour que toute divergence
   fasse échouer un test au lieu de passer inaperçue.
2. Une allowlist ouverte : une colonne inconnue écrite dans `akvorado.yaml`
   empêche l'orchestrateur de redémarrer. Le refus doit avoir lieu AVANT la
   mise en file.
3. Le silence sur les 6 colonnes « table principale seulement » : absentes des
   tables d'agrégation, elles rendent une dimension VIDE sur les vues au long
   cours, sans le moindre message d'erreur. Zéro silencieux typique.
4. Une écriture qui échoue silencieusement parce que le bloc `schema:` n'existe
   pas encore dans `akvorado.yaml` (état mesuré en prod : il est ABSENT), ou
   qui détruit les directives `!include` — les perdre arrête l'orchestrateur.
5. Une classe CSS posée sans règle correspondante : l'élément se rend avec le
   style par défaut du navigateur, hors charte, sans aucune erreur.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.clients.yaml_editor import compute_file_hash, read_section, write_section
from app.db import SCHEMA
from app.services.config_sections import (
    MAIN_TABLE_ONLY_COLUMNS,
    SCHEMA_COLUMN_CHOICES,
    get_section,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = PROJECT_ROOT / "app" / "templates" / "config_sections.html"
STYLE_CSS = PROJECT_ROOT / "app" / "static" / "style.css"

SECTION_KEY = "schema_columns"

# SOURCE DE VÉRITÉ, recopiée en dur ICI volontairement.
#
# Obtenue par `akvorado version -d` sur le BINAIRE déployé
# (v2.4.1-44-g42e151bb), et NON dans la documentation — celle-ci ne donne que
# des exemples et n'est pas exhaustive.
#
# Ce doublon avec le catalogue est le but du test : si quelqu'un ajoute ou
# retire une colonne côté application sans re-mesurer le binaire, la comparaison
# échoue et l'oblige à revenir à la source. Une liste dérivée du catalogue
# testerait le catalogue contre lui-même et ne prouverait rien.
COLONNES_ATTENDUES = [
    "SrcVlan",
    "DstVlan",
    "SrcCommunities",
    "SrcLargeCommunities",
    "SrcAddrNAT",
    "DstAddrNAT",
    "SrcPortNAT",
    "DstPortNAT",
    "SrcMAC",
    "DstMAC",
    "IPTTL",
    "IPTos",
    "IPFragmentID",
    "IPFragmentOffset",
    "IPv6FlowLabel",
    "TCPFlags",
    "ICMPv4",
    "ICMPv4Type",
    "ICMPv4Code",
    "ICMPv6",
    "ICMPv6Type",
    "ICMPv6Code",
    "NextHop",
    "MPLSLabels",
    "MPLS1stLabel",
    "MPLS2ndLabel",
    "MPLS3rdLabel",
    "MPLS4thLabel",
    "IngressVRFID",
    "EgressVRFID",
]

# Les 6 colonnes marquées « main table only » par la même commande : elles
# n'existent pas dans les tables d'agrégation.
COLONNES_TABLE_PRINCIPALE_SEULEMENT = [
    "SrcCommunities",
    "SrcLargeCommunities",
    "SrcAddrNAT",
    "DstAddrNAT",
    "SrcPortNAT",
    "DstPortNAT",
]


# ---------------------------------------------------------------------------
# Fixtures — mêmes YAML de travail que les autres tests de sections, jamais la
# prod : SQLite en mémoire, fichiers en tmp_path.
#
# `akvorado.yaml` est écrit ICI SANS bloc `schema:` — c'est l'état RÉEL mesuré
# en production, et le cas que l'écriture doit savoir traiter en le créant.
# ---------------------------------------------------------------------------

_OUTLET_YAML = """\
networks:
  networks:
    192.168.1.0/24:
      name: lan-maison
core:
  exporter-classifiers: []
  interface-classifiers: []
"""

_AKVORADO_YAML = """\
# Configuration de l'orchestrateur Akvorado.
clickhouse:
  asns:
    64512: homelab-as
kafka:
  topic-configuration:
    num-partitions: 4

inlet: !include "inlet.yaml"
outlet: !include "outlet.yaml"
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
def memory_conn() -> Generator[sqlite3.Connection]:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    (tmp_path / "outlet.yaml").write_text(_OUTLET_YAML)
    (tmp_path / "akvorado.yaml").write_text(_AKVORADO_YAML)
    (tmp_path / "console.yaml").write_text(_CONSOLE_YAML)
    (tmp_path / "inlet.yaml").write_text(_INLET_YAML)
    return tmp_path


@pytest.fixture
def client(memory_conn: sqlite3.Connection, config_dir: Path) -> TestClient:
    from app.routers import config_sections as sections_router

    app = FastAPI()
    app.include_router(sections_router.router)
    app.dependency_overrides[sections_router.get_db_connection] = lambda: memory_conn
    app.dependency_overrides[sections_router.get_config_dir] = lambda: str(config_dir)
    return TestClient(app)


def _render(client: TestClient) -> str:
    response = client.get(f"/config/sections/{SECTION_KEY}")
    assert response.status_code == 200, "l'écran des colonnes du schéma n'a pas rendu"
    return response.text


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Catalogue : où la section écrit, et quoi
# ---------------------------------------------------------------------------


class TestCatalogue:
    def test_la_section_vise_le_bon_fichier_et_la_bonne_cle(self) -> None:
        """`schema.enabled` vit dans `akvorado.yaml` (orchestrateur), PAS dans
        `outlet.yaml`. La documentation d'Akvorado est explicite sur ce point,
        et se tromper de fichier produirait une configuration parfaitement
        valide... et totalement sans effet."""
        section = get_section(SECTION_KEY)
        assert section.file == "akvorado.yaml"
        assert section.dotted_key == "schema.enabled"
        assert section.kind == "list"

    def test_la_section_redemarre_l_orchestrateur_ET_l_outlet(self) -> None:
        """DEUX services, et l'omission de l'outlet a été MESURÉE le 2026-08-07.

        Ce test exigeait auparavant `("orchestrator",)` seul, en affirmant que
        « redémarrer l'outlet n'appliquerait aucune colonne ». La mesure a
        invalidé cette hypothèse.

        L'orchestrateur porte les migrations : il crée bien la colonne dans
        ClickHouse. Mais c'est l'OUTLET qui consomme Kafka, décode les flux et
        remplit les colonnes. Avec le seul orchestrateur redémarré, la colonne
        `IPTos` existait et restait À ZÉRO — 1320 paquets marqués AF21 côté
        iptables, `SELECT IPTos, count()` rendant `0  16367`. Aucune erreur.

        Après redémarrage de l'outlet, sept classes DSCP réelles remontaient :
        EF, AF21, CS6, CS1. C'est ce comportement que ce test protège.
        """
        section = get_section(SECTION_KEY)

        assert "orchestrator" in section.restart_services, (
            "sans l'orchestrateur, la migration n'a pas lieu et la colonne n'existe même pas"
        )
        assert "akvorado-outlet" in section.restart_services, (
            "sans l'outlet, la colonne est créée mais JAMAIS remplie : il "
            "continue de décoder les flux avec l'ancien schéma"
        )

    def test_la_section_apparait_dans_le_catalogue_expose(self, client: TestClient) -> None:
        """La section doit être atteignable par l'API du catalogue, sinon elle
        n'existe pas pour l'écran d'ensemble."""
        response = client.get("/api/config/sections")
        assert response.status_code == 200
        items = {item["key"]: item for item in response.json()["items"]}
        assert SECTION_KEY in items, "la section n'est pas exposée au catalogue"
        assert items[SECTION_KEY]["file"] == "akvorado.yaml"


# ---------------------------------------------------------------------------
# Exhaustivité de l'allowlist
# ---------------------------------------------------------------------------


class TestExhaustivite:
    def test_les_30_colonnes_du_binaire_sont_proposees(self) -> None:
        """Comparaison EXACTE contre la liste mesurée sur le binaire déployé.

        Toute divergence — colonne ajoutée à la main, colonne oubliée — casse
        ici, ce qui force à re-mesurer plutôt qu'à supposer.
        """
        assert list(SCHEMA_COLUMN_CHOICES) == COLONNES_ATTENDUES
        assert len(SCHEMA_COLUMN_CHOICES) == 30

    def test_les_30_colonnes_sont_rendues_a_l_ecran(self, client: TestClient) -> None:
        """Une colonne présente au catalogue mais absente de l'écran serait
        inactivable — un réglage qui existe sans être atteignable."""
        html = _render(client)
        manquantes = [
            colonne
            for colonne in COLONNES_ATTENDUES
            if f'name="columns" value="{colonne}"' not in html
        ]
        assert not manquantes, f"colonnes absentes de l'écran : {manquantes}"

    def test_chaque_colonne_rendue_appartient_a_l_allowlist(self, client: TestClient) -> None:
        """Le test miroir : aucune case ne propose une valeur que le validateur
        refuserait ensuite. Une case qui produit systématiquement une erreur
        est pire qu'une case absente."""
        html = _render(client)
        proposees = set(re.findall(r'name="columns" value="([^"]+)"', html))
        assert proposees <= set(COLONNES_ATTENDUES), (
            f"valeurs proposées hors allowlist : {sorted(proposees - set(COLONNES_ATTENDUES))}"
        )

    def test_les_colonnes_sont_groupees_par_famille(self, client: TestClient) -> None:
        """Trente cases en vrac ne se lisent pas : chaque colonne vit sous une
        légende de famille. On cherche « la QoS », pas « IPTos »."""
        html = _render(client)
        legendes = set(re.findall(r"<legend>([^<]+)</legend>", html))
        for famille in ("QoS / ToS", "VLAN", "MAC", "ICMP", "MPLS", "NAT"):
            assert famille in legendes, f"famille « {famille} » absente de l'écran"

    def test_la_colonne_qos_annonce_ce_qu_elle_debloque(self, client: TestClient) -> None:
        """`IPTos` est la colonne qui motive tout cet écran : son libellé doit
        dire QoS/DSCP et mentionner le widget qu'elle débloque, pas seulement
        son code technique."""
        html = _render(client)
        assert "QoS / DSCP" in html
        assert "Top N QoS" in html


# ---------------------------------------------------------------------------
# Colonnes « table principale seulement »
# ---------------------------------------------------------------------------


class TestTablePrincipaleSeulement:
    def test_le_catalogue_connait_les_6_colonnes_concernees(self) -> None:
        assert MAIN_TABLE_ONLY_COLUMNS == set(COLONNES_TABLE_PRINCIPALE_SEULEMENT)

    def test_ces_colonnes_font_partie_de_l_allowlist(self) -> None:
        """Une colonne signalée mais non proposée serait un avertissement sur
        un réglage inexistant."""
        assert set(COLONNES_TABLE_PRINCIPALE_SEULEMENT) <= set(SCHEMA_COLUMN_CHOICES)

    def test_chaque_colonne_concernee_porte_le_marqueur_a_l_ecran(self, client: TestClient) -> None:
        """Le symptôme, sinon, est MUET : la dimension paraît simplement vide
        sur les vues au long cours, sans message d'erreur nulle part."""
        html = _render(client)
        for colonne in COLONNES_TABLE_PRINCIPALE_SEULEMENT:
            # Le marqueur suit immédiatement le code technique de la colonne
            # dans le même bloc de libellé.
            bloc = re.search(
                r'value="' + re.escape(colonne) + r'".{0,1200}?</label>',
                html,
                re.DOTALL,
            )
            assert bloc, f"bloc de la colonne {colonne} introuvable à l'écran"
            assert "schema-badge" in bloc.group(0), (
                f"la colonne {colonne} n'est pas signalée « table principale seulement »"
            )

    def test_aucune_autre_colonne_ne_porte_le_marqueur(self, client: TestClient) -> None:
        """Un marqueur posé partout ne signale plus rien."""
        html = _render(client)
        marquees = set()
        for colonne in COLONNES_ATTENDUES:
            bloc = re.search(
                r'value="' + re.escape(colonne) + r'".{0,1200}?</label>',
                html,
                re.DOTALL,
            )
            if bloc and "schema-badge" in bloc.group(0):
                marquees.add(colonne)
        assert marquees == set(COLONNES_TABLE_PRINCIPALE_SEULEMENT)


# ---------------------------------------------------------------------------
# Validation : allowlist FERMÉE
# ---------------------------------------------------------------------------


class TestValidation:
    def test_le_validateur_accepte_les_colonnes_connues(self) -> None:
        section = get_section(SECTION_KEY)
        assert section.validator(["IPTos", "SrcVlan"]) == []

    def test_le_validateur_accepte_la_liste_vide(self) -> None:
        """Tout désactiver est une demande légitime : revenir au schéma
        minimal. Ce n'est pas une absence de données."""
        section = get_section(SECTION_KEY)
        assert get_section(SECTION_KEY).validator([]) == []
        assert section.validator([]) == []

    @pytest.mark.parametrize(
        "inconnue",
        [
            "IPToS",  # faute de casse — refusée par Akvorado au démarrage
            "DSCP",  # nom « intuitif » qui n'existe pas dans le schéma
            "SrcAddr",  # colonne du schéma de BASE, pas activable ici
            "'; DROP TABLE flows; --",
        ],
    )
    def test_le_validateur_refuse_une_colonne_inconnue(self, inconnue: str) -> None:
        """Une colonne inconnue écrite dans `akvorado.yaml` empêche
        l'orchestrateur de redémarrer : le refus doit avoir lieu ICI, avant même
        la mise en file d'attente."""
        section = get_section(SECTION_KEY)
        erreurs = section.validator(["IPTos", inconnue])
        assert erreurs, f"colonne inconnue acceptée : {inconnue!r}"
        assert any("inconnue" in erreur for erreur in erreurs)

    def test_le_validateur_refuse_autre_chose_qu_une_liste(self) -> None:
        section = get_section(SECTION_KEY)
        assert section.validator({"IPTos": True})
        assert section.validator("IPTos")

    def test_le_validateur_refuse_un_doublon(self) -> None:
        """Deux fois la même colonne dans `schema.enabled` est une
        configuration incohérente, jamais produite par l'écran mais possible
        par un autre chemin."""
        section = get_section(SECTION_KEY)
        assert section.validator(["IPTos", "IPTos"])


# ---------------------------------------------------------------------------
# Contrat du formulaire : cocher / décocher -> liste dans le payload
# ---------------------------------------------------------------------------


def _payloads(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute("SELECT payload FROM pending_config_changes ORDER BY id").fetchall()
    return [row[0] for row in rows]


class TestContratDuFormulaire:
    def test_cocher_des_cases_met_une_liste_en_file(
        self, client: TestClient, memory_conn: sqlite3.Connection
    ) -> None:
        """Le contrat est celui des cases à cocher HTML : le champ `columns` est
        répété une fois par case COCHÉE."""
        # PIÈGE MESURÉ (2026-08-07) : `data=[("columns", "IPTos"), ...]` — la
        # liste de tuples — n'est PAS encodée en formulaire par httpx, qui la
        # traite comme du contenu brut à streamer. Le serveur ne voyait alors
        # aucun champ `columns` et le test échouait en accusant le routeur.
        # La forme qui produit bien `columns=IPTos&columns=SrcVlan` est le
        # dict de listes.
        response = client.post(
            f"/config/sections/{SECTION_KEY}",
            data={"columns": ["IPTos", "SrcVlan"]},
        )
        assert response.status_code == 201, response.text

        import json

        payload = json.loads(_payloads(memory_conn)[-1])
        assert payload["section_key"] == SECTION_KEY
        assert payload["value"] == ["IPTos", "SrcVlan"]

    def test_tout_decocher_met_une_liste_vide_en_file(
        self, client: TestClient, memory_conn: sqlite3.Connection
    ) -> None:
        """Un formulaire dont TOUTES les cases sont décochées n'envoie AUCUN
        champ `columns`. Ce cas doit produire `[]` — une demande explicite de
        revenir au schéma minimal — et non être confondu avec « pas cet écran »
        ni ignoré en silence."""
        response = client.post(f"/config/sections/{SECTION_KEY}", data={})
        assert response.status_code == 201, response.text

        import json

        payload = json.loads(_payloads(memory_conn)[-1])
        assert payload["value"] == []

    def test_une_colonne_inconnue_postee_est_refusee(
        self, client: TestClient, memory_conn: sqlite3.Connection
    ) -> None:
        """L'allowlist est FERMÉE côté serveur : contourner l'écran (curl, DOM
        modifié) ne doit rien mettre en file."""
        response = client.post(
            f"/config/sections/{SECTION_KEY}",
            data={"columns": ["IPTos", "ColonneQuiNExistePas"]},
        )
        assert response.status_code != 201
        assert not _payloads(memory_conn), "un changement invalide a été mis en file"


# ---------------------------------------------------------------------------
# Écriture YAML : créer le bloc `schema:` absent, préserver les `!include`
# ---------------------------------------------------------------------------


class TestEcritureYaml:
    def test_le_bloc_schema_est_bien_absent_au_depart(self, config_dir: Path) -> None:
        """Prémisse du test suivant, vérifiée plutôt que supposée : c'est l'état
        RÉEL mesuré en production."""
        chemin = str(config_dir / "akvorado.yaml")
        assert read_section(chemin, "schema.enabled") is None

    def test_ecrire_cree_le_bloc_schema_absent(self, config_dir: Path) -> None:
        """MESURÉ, pas supposé : `write_section` crée les mappings
        intermédiaires manquants (`_ensure_path`). Sans cela, activer la
        première colonne échouerait — ou pire, n'écrirait rien."""
        chemin = str(config_dir / "akvorado.yaml")
        write_section(
            chemin,
            "schema.enabled",
            ["IPTos", "SrcVlan"],
            expected_hash=compute_file_hash(chemin),
        )
        assert read_section(chemin, "schema.enabled") == ["IPTos", "SrcVlan"]
        assert "schema:" in _read(config_dir / "akvorado.yaml")

    def test_les_directives_include_survivent_a_l_ecriture(self, config_dir: Path) -> None:
        """Perdre un `!include` arrête l'orchestrateur : `akvorado.yaml` inclut
        `inlet.yaml` et `outlet.yaml` par ce mécanisme."""
        chemin = str(config_dir / "akvorado.yaml")
        write_section(
            chemin,
            "schema.enabled",
            ["IPTos"],
            expected_hash=compute_file_hash(chemin),
        )
        contenu = _read(config_dir / "akvorado.yaml")
        assert contenu.count("!include") == 2, contenu
        assert 'inlet: !include "inlet.yaml"' in contenu
        assert 'outlet: !include "outlet.yaml"' in contenu

    def test_l_ecriture_preserve_les_autres_sections(self, config_dir: Path) -> None:
        """Créer `schema:` ne doit toucher ni `clickhouse.asns` ni
        `kafka.topic-configuration`, qui vivent dans le même fichier."""
        chemin = str(config_dir / "akvorado.yaml")
        write_section(
            chemin,
            "schema.enabled",
            ["IPTos"],
            expected_hash=compute_file_hash(chemin),
        )
        assert read_section(chemin, "clickhouse.asns") == {64512: "homelab-as"}
        assert read_section(chemin, "kafka.topic-configuration") == {"num-partitions": 4}
        # Le commentaire de tête survit au round-trip ruamel.
        assert "# Configuration de l'orchestrateur Akvorado." in _read(config_dir / "akvorado.yaml")

    def test_ecrire_une_seconde_fois_remplace_la_liste(self, config_dir: Path) -> None:
        """Le bloc existe désormais : la deuxième écriture emprunte un chemin
        différent de la première (mise à jour, pas création)."""
        chemin = str(config_dir / "akvorado.yaml")
        write_section(chemin, "schema.enabled", ["IPTos"], expected_hash=compute_file_hash(chemin))
        write_section(
            chemin,
            "schema.enabled",
            ["SrcVlan", "DstVlan"],
            expected_hash=compute_file_hash(chemin),
        )
        assert read_section(chemin, "schema.enabled") == ["SrcVlan", "DstVlan"]


# ---------------------------------------------------------------------------
# Charte : pas de classe orpheline, pas de script inline
# ---------------------------------------------------------------------------


_JINJA_COMMENT_RE = re.compile(r"\{#.*?#\}", re.DOTALL)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


class TestCharte:
    def test_les_classes_introduites_existent_dans_le_css(self, client: TestClient) -> None:
        """Une classe posée sans règle correspondante rend l'élément avec le
        style par défaut du navigateur : hors charte, et sans aucune erreur.
        Défaut déjà vécu quatre fois sur ce projet."""
        html = _render(client)
        css = _read(STYLE_CSS)

        classes = set()
        for attribut in re.findall(r'class="([^"]*)"', html):
            classes.update(attribut.split())

        # Seules les classes propres à CET écran sont de mon ressort ; les
        # classes partagées sont couvertes par test_design_system.py.
        a_verifier = sorted(c for c in classes if c.startswith("schema-"))
        assert a_verifier, "aucune classe propre à cet écran — le test ne prouverait rien"

        orphelines = [c for c in a_verifier if f".{c}" not in css]
        assert not orphelines, (
            f"classes CSS sans règle dans style.css : {orphelines} "
            "(l'élément se rendrait hors charte, sans erreur)"
        )

    def test_aucun_script_inline_dans_le_bloc_des_colonnes(self) -> None:
        """CSP `script-src 'self'` : un `<script>` inline ou un `onclick=`
        serait bloqué par le navigateur — page affichée, mais inerte au clic."""
        html = _read(TEMPLATE)
        html = _HTML_COMMENT_RE.sub("", _JINJA_COMMENT_RE.sub("", html))
        debut = html.find("{% elif detail.key == 'schema_columns' %}")
        assert debut != -1, "bloc schema_columns introuvable dans le template"
        fin = html.find("{% elif detail.key ==", debut + 10)
        bloc = html[debut:fin]

        assert "<script" not in bloc
        assert not re.search(r"\son[a-z]+\s*=", bloc), "gestionnaire d'événement inline"

    def test_chaque_case_est_enveloppee_dans_son_libelle(self, client: TestClient) -> None:
        """Une case détachée de son libellé n'est visible qu'à la capture
        d'écran — le DOM, lui, paraît correct. Défaut vécu le 2026-08-06."""
        html = _render(client)
        cases = re.findall(r'<input type="checkbox" name="columns"[^>]*>', html)
        assert len(cases) == 30
        # Chaque case vit à l'intérieur d'un <label class="widget-checklist__item">.
        assert html.count('class="widget-checklist__item') >= 30

    def test_le_cout_de_chaque_colonne_est_annonce(self, client: TestClient) -> None:
        """Activer une colonne, c'est un champ stocké pour CHAQUE flux. Ce n'est
        pas gratuit et l'écran doit le dire AVANT le clic, pas après la
        migration."""
        html = _render(client)
        assert "Chaque colonne activée a un coût." in html
        assert "disque" in html
        # Le caractère non destructif doit être dit aussi : sans lui, on
        # n'ose pas décocher.
        assert "ne supprime pas" in html
