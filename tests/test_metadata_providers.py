"""Garde-fous de la section « Découverte des interfaces (SNMP) ».

CE QUE CETTE SECTION RÉSOUT. Un flux NetFlow ne transporte que des INDEX
d'interface (ifIndex) ; le nom de l'interface vient d'ailleurs. Aujourd'hui il
vient d'une table `static` écrite à la main, un ifIndex par ligne. Défaut vécu
le 2026-08-05 : les ifIndex `tailscale0` de deux machines ont dérivé (219→409,
3→235) et **76 000 flux se sont classés `unknown`** — sans erreur, sans alerte.
En SNMP, l'équipement fait foi et la dérive disparaît.

CE QUE CES TESTS EMPÊCHENT DE REVENIR, par ordre de gravité :

1. **La perte du `static` existant.** Il pèse ~200 lignes en production (12
   exportateurs × leurs ifIndex). Activer SNMP ne doit pas le reconstruire,
   même « à l'identique » : un champ perdu ne produit aucune erreur, juste des
   flux qui retombent en `unknown`. `test_le_static_existant_survit_a_l_identique`
   compare l'objet AVANT/APRÈS par égalité stricte.
2. **La fuite de la communauté SNMP.** C'est un secret d'authentification. Deux
   chemins de fuite sont testés : le HTML rendu et les LOGS (`caplog`), ce
   dernier étant le plus insidieux — un message d'erreur de validation citant la
   valeur l'écrirait en clair sur le chemin qu'on regarde le moins.
3. **L'inversion de la cascade.** Akvorado s'arrête au premier fournisseur qui
   accepte la requête, et seul `static` sait laisser passer. `snmp` placé avant
   `static` neutralise donc le repli — silencieusement.
4. **Un type de fournisseur hors allowlist**, qui fait refuser tout le document
   par l'outlet au démarrage : plus aucune collecte.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.db import SCHEMA
from app.services.config_sections import (
    VALID_METADATA_PROVIDER_TYPES,
    check_cascade_order,
    get_section,
    is_env_reference,
    list_sections,
    mask_community,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = PROJECT_ROOT / "app" / "templates" / "config_sections.html"
STYLE_CSS = PROJECT_ROOT / "app" / "static" / "style.css"

SECTION = "metadata_providers"

# La communauté utilisée dans tous les tests. Une chaîne IMPROBABLE et unique :
# une valeur banale comme « public » se retrouverait par hasard dans le HTML ou
# les logs (mot courant), et le test de non-fuite passerait ou échouerait pour
# de mauvaises raisons.
SECRET_COMMUNITY = "zzq-secret-communaute-9f3a1c"


# ---------------------------------------------------------------------------
# Fixtures — mêmes YAML de travail que test_bulk_selection.py, jamais la prod.
# ---------------------------------------------------------------------------
#
# `_OUTLET_YAML` porte un `static` RÉALISTE : plusieurs exportateurs, chacun
# avec sa table d'ifIndex, `default` inclus. C'est la miniature du fichier de
# production — sans elle, le test d'identité vérifierait qu'on préserve un
# objet trivial, ce qui ne prouverait rien.

_OUTLET_YAML = """\
networks:
  networks:
    100.64.0.0/10:
      name: tailscale-mesh
core:
  exporter-classifiers:
    - ClassifyRegion("homelab")
  interface-classifiers: []
metadata:
  workers: 5
  providers:
    - type: static
      exporters:
        ::/0:
          default:
            name: unknown
            description: interface non declaree
          skip-missing-interfaces: false
        192.0.2.11/32:
          ifindexes:
            219:
              name: tailscale0
              description: mesh tailscale
              speed: 1000
            2:
              name: eth0
              description: lan
              speed: 1000
        192.0.2.12/32:
          ifindexes:
            3:
              name: tailscale0
              description: mesh tailscale
              speed: 1000
            1:
              name: lo
              description: loopback
              speed: 10
"""

_AKVORADO_YAML = """\
clickhouse:
  asns:
    64512: homelab-as
kafka:
  topic-configuration:
    num-partitions: 4
schema:
  enabled:
    - SrcVlan
"""

_CONSOLE_YAML = """\
default-visualize-options:
  limit: 10
  dimensions:
    - src-as
homepage-top-widgets:
  - src-as
database:
  saved-filters:
    - description: filtre 0
      content: "DstPort = 8000"
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


def _staged_value(conn: sqlite3.Connection) -> Any:
    """Valeur du DERNIER changement mis en file d'attente.

    Les changements sont stockés en JSON (`{"section_key": ..., "value": ...}`)
    dans la table commune. On relit ce qui a réellement été mis en file, pas ce
    que le handler a retourné : c'est le contenu de cette colonne qui sera un
    jour écrit dans le YAML.
    """
    import json

    row = conn.execute(
        "SELECT payload FROM pending_config_changes ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert row is not None, "aucun changement en file d'attente"
    return json.loads(row[0])["value"]


def _normalized(value: Any) -> Any:
    """Ramène toutes les clés de mapping à leur forme `str`, récursivement.

    POURQUOI cette normalisation avant de comparer AVANT/APRÈS : la file
    d'attente sérialise en JSON, qui n'a pas de clé entière, donc les clés
    d'ifIndex (`219`) reviennent en chaînes (`"219"`). Sans normalisation,
    l'égalité stricte échouerait sur ce SEUL écart de type et masquerait ce
    qu'elle doit vraiment prouver : qu'aucune ENTRÉE, aucun CHAMP et aucune
    VALEUR n'a disparu.

    Ce n'est donc pas un assouplissement du test : la limite de type est fixée
    séparément par `test_la_limite_des_cles_entieres_est_connue_et_documentee`,
    qui la rend impossible à oublier. Ici on compare la STRUCTURE et le CONTENU,
    là-bas on fige le TYPE.
    """
    if isinstance(value, dict):
        return {str(key): _normalized(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalized(item) for item in value]
    return value


def _static_provider(providers: list[Any]) -> dict[str, Any]:
    for provider in providers:
        if isinstance(provider, dict) and provider.get("type") == "static":
            return provider
    raise AssertionError(f"aucun fournisseur 'static' dans {providers!r}")


def _enable_snmp(client: TestClient, **overrides: str) -> Any:
    form = {
        "action": "enable_snmp",
        "subnet": "::/0",
        "community": SECRET_COMMUNITY,
    }
    form.update(overrides)
    return client.post(f"/config/sections/{SECTION}", data=form)


# ---------------------------------------------------------------------------
# 1. Présence au catalogue
# ---------------------------------------------------------------------------


class TestCatalogue:
    def test_la_section_existe_au_catalogue(self) -> None:
        section = get_section(SECTION)
        assert section.key == SECTION

    def test_elle_cible_le_bon_fichier_et_la_bonne_cle(self) -> None:
        """`metadata.providers` vit dans `outlet.yaml`, pas dans `akvorado.yaml`.

        Se tromper de fichier n'échouerait pas bruyamment : `read_section`
        dégrade vers `None` sur une section absente, l'écran afficherait donc
        « aucun fournisseur » sur une configuration qui en compte pourtant.
        """
        section = get_section(SECTION)
        assert section.file == "outlet.yaml"
        assert section.dotted_key == "metadata.providers"

    def test_elle_redemarre_l_outlet(self) -> None:
        """C'est l'outlet qui porte la résolution des métadonnées d'interface."""
        assert get_section(SECTION).restart_services == ("akvorado-outlet",)

    def test_elle_apparait_dans_la_liste_des_sections(self) -> None:
        assert SECTION in {section.key for section in list_sections()}

    def test_elle_est_exposee_par_l_api_du_catalogue(self, client: TestClient) -> None:
        payload = client.get("/api/config/sections").json()
        keys = {item["key"] for item in payload["items"]}
        assert SECTION in keys


# ---------------------------------------------------------------------------
# 2. LE test central — le `static` existant survit à l'identique
# ---------------------------------------------------------------------------


class TestPreservationDuStatic:
    def test_le_static_existant_survit_a_l_identique(
        self, client: TestClient, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        """Activer SNMP AJOUTE un fournisseur, sans TOUCHER au `static`.

        Égalité STRICTE sur l'objet entier, pas un échantillon de champs : c'est
        la seule forme qui attrape la perte d'un champ qu'on n'aurait pas pensé
        à vérifier. Une comparaison sur `ifindexes` seul aurait laissé passer la
        disparition de `skip-missing-interfaces` ou de `default`.
        """
        from app.clients.yaml_editor import read_section

        before = read_section(str(config_dir / "outlet.yaml"), "metadata.providers")
        static_before = _normalized(_static_provider(before))

        response = _enable_snmp(client)
        assert response.status_code == 201, response.text

        after = _staged_value(memory_conn)
        static_after = _normalized(_static_provider(after))

        assert static_after == static_before, (
            "le fournisseur 'static' a ete modifie par l'activation de SNMP. "
            "En production il pese ~200 lignes (12 exportateurs x leurs ifIndex) : "
            "un champ perdu ne leve aucune erreur, il fait simplement retomber "
            "les flux concernes en 'unknown' (defaut vecu le 2026-08-05)."
        )

    def test_tous_les_ifindexes_declares_survivent(
        self, client: TestClient, memory_conn: sqlite3.Connection
    ) -> None:
        """Vérification explicite au grain de l'ifIndex.

        Redondante avec l'égalité stricte ci-dessus, et VOLONTAIREMENT : si un
        jour l'égalité stricte est assouplie (pour tolérer une normalisation),
        ce test-ci reste le garde-fou sur ce qui compte vraiment — chaque index
        déclaré est toujours là, avec son nom et sa description.

        Les clés sont comparées sous leur forme `str` : la file d'attente
        sérialise en JSON, qui n'a PAS de clé entière, donc `219` en ressort en
        `"219"`. Ce n'est pas une tolérance de confort — c'est la limite mesurée
        le 2026-08-07, documentée au catalogue et dont la correction appartient
        à `config_writer._restore_key_types` (hors périmètre de ce lot). Ce test
        vérifie donc ce qui EST vérifiable ici : aucun ifIndex, aucun nom et
        aucune description ne DISPARAÎT au passage.
        """
        assert _enable_snmp(client).status_code == 201
        static = _static_provider(_staged_value(memory_conn))

        exporters = static["exporters"]

        def _by_text(ifindexes: dict[Any, Any]) -> dict[str, Any]:
            return {str(key): item for key, item in ifindexes.items()}

        first = _by_text(exporters["192.0.2.11/32"]["ifindexes"])
        assert set(first) == {"219", "2"}
        assert first["219"]["name"] == "tailscale0"
        assert first["219"]["description"] == "mesh tailscale"
        assert first["2"]["name"] == "eth0"

        second = _by_text(exporters["192.0.2.12/32"]["ifindexes"])
        assert set(second) == {"3", "1"}
        assert second["3"]["name"] == "tailscale0"
        assert second["1"]["name"] == "lo"

        # `default` et `skip-missing-interfaces` sont les champs qu'une
        # reconstruction champ par champ oublierait en premier.
        assert exporters["::/0"]["default"]["name"] == "unknown"
        assert exporters["::/0"]["skip-missing-interfaces"] is False

    def test_la_limite_des_cles_entieres_est_connue_et_documentee(
        self, client: TestClient, memory_conn: sqlite3.Connection
    ) -> None:
        """Fige la limite MESURÉE plutôt que de la laisser se découvrir en prod.

        La file d'attente sérialise en JSON : les clés entières d'ifIndex en
        ressortent en chaînes. `config_writer._restore_key_types` corrige déjà
        ce défaut à la désérialisation, mais seulement au PREMIER NIVEAU d'un
        mapping — pas pour des clés imbriquées sous une liste de fournisseurs.

        Si un jour ce test échoue parce que les clés sont redevenues entières,
        c'est que `config_writer` a été généralisé : ce sera une bonne nouvelle,
        et le commentaire du catalogue devra être retiré. Un test qui échoue
        quand un défaut est CORRIGÉ vaut mieux qu'une limite oubliée.
        """
        assert _enable_snmp(client).status_code == 201
        static = _static_provider(_staged_value(memory_conn))
        keys = list(static["exporters"]["192.0.2.11/32"]["ifindexes"])
        assert all(isinstance(key, str) for key in keys), (
            "les cles d'ifIndex sont redevenues entieres : config_writer a ete "
            "generalise, retirer la limite documentee au catalogue."
        )

    def test_desactiver_snmp_ne_touche_pas_au_static(
        self, client: TestClient, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        """Le chemin de RETRAIT est aussi dangereux que celui d'ajout."""
        from app.clients.yaml_editor import read_section

        static_before = _normalized(
            _static_provider(read_section(str(config_dir / "outlet.yaml"), "metadata.providers"))
        )

        assert _enable_snmp(client).status_code == 201
        # La désactivation relit le disque (le `static` d'origine), pas la file.
        response = client.post(f"/config/sections/{SECTION}", data={"action": "disable_snmp"})
        assert response.status_code == 422, (
            "sans snmp sur DISQUE, desactiver doit etre refuse explicitement"
        )

        # Le refus n'a rien mis en file : le dernier changement reste l'ajout.
        assert _normalized(_static_provider(_staged_value(memory_conn))) == static_before

    def test_le_reordonnancement_ne_reconstruit_pas_le_static(
        self, client: TestClient, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        """Monter/descendre déplace l'objet, ne le recrée pas."""
        from app.clients.yaml_editor import read_section

        static_before = _normalized(
            _static_provider(read_section(str(config_dir / "outlet.yaml"), "metadata.providers"))
        )
        response = client.post(
            f"/config/sections/{SECTION}", data={"action": "move_down", "index": "0"}
        )
        # Un seul fournisseur sur disque : descendre le premier est sans effet,
        # et c'est dit explicitement plutôt qu'un succes qui n'a rien change.
        assert response.status_code == 422
        assert "extrémité" in response.text

        assert _enable_snmp(client).status_code == 201
        assert _normalized(_static_provider(_staged_value(memory_conn))) == static_before


# ---------------------------------------------------------------------------
# 3. Ajout du fournisseur SNMP et ordre de la cascade
# ---------------------------------------------------------------------------


class TestCheminsReelsDeRetraitEtDeplacement:
    """Les chemins qui MODIFIENT réellement la cascade.

    Les tests de préservation ci-dessus partent d'un disque sans `snmp` et
    vérifient surtout des REFUS. Un refus ne prouve rien sur le chemin nominal :
    ces tests-ci exercent les gestes qui aboutissent, là où le `static` court un
    risque réel.
    """

    @staticmethod
    def _with_snmp(config_dir: Path) -> None:
        (config_dir / "outlet.yaml").write_text(
            _OUTLET_YAML
            + "    - type: snmp\n"
            + "      credentials:\n"
            + "        ::/0:\n"
            + "          communities:\n"
            + "            - ${SNMP_COMMUNITY}\n"
        )

    def test_desactiver_snmp_pour_de_vrai_conserve_le_static(
        self, client: TestClient, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        from app.clients.yaml_editor import read_section

        self._with_snmp(config_dir)
        before = _normalized(
            _static_provider(read_section(str(config_dir / "outlet.yaml"), "metadata.providers"))
        )

        response = client.post(f"/config/sections/{SECTION}", data={"action": "disable_snmp"})
        assert response.status_code == 201, response.text

        after = _staged_value(memory_conn)
        assert [p.get("type") for p in after] == ["static"]
        assert _normalized(_static_provider(after)) == before

    def test_descendre_le_static_sous_snmp_est_refuse(
        self, client: TestClient, config_dir: Path
    ) -> None:
        """Le réordonnancement ne peut pas produire une cascade cassée.

        Descendre `static` sous `snmp` est précisément l'inversion qui rend le
        repli inatteignable : le geste est offert à la souris, mais son
        RÉSULTAT est validé comme n'importe quel autre changement. Un bouton
        qui produit une configuration invalide sans rien dire serait pire que
        pas de bouton du tout.
        """
        self._with_snmp(config_dir)
        response = client.post(
            f"/config/sections/{SECTION}", data={"action": "move_down", "index": "0"}
        )
        assert response.status_code == 422, response.text
        assert "JAMAIS consulte" in response.text

    def test_remonter_le_static_pour_de_vrai_conserve_le_static(
        self, client: TestClient, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        """Chemin nominal du réordonnancement : réparer une cascade inversée.

        C'est LE geste que cet écran doit rendre possible à la souris — sans
        lui, corriger une cascade posée à l'envers imposerait de rouvrir le YAML
        en SSH. Le `static` traverse le déplacement inchangé.
        """
        from app.clients.yaml_editor import read_section

        # Cascade INVERSÉE au départ (snmp en tête) : c'est l'état à réparer.
        (config_dir / "outlet.yaml").write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: snmp\n"
            "      credentials:\n"
            "        ::/0:\n"
            "          communities:\n"
            "            - ${SNMP_COMMUNITY}\n"
            "    - type: static\n"
            "      exporters:\n"
            "        10.0.0.11/32:\n"
            "          ifindexes:\n"
            "            219:\n"
            "              name: tailscale0\n"
        )
        before = _normalized(
            _static_provider(read_section(str(config_dir / "outlet.yaml"), "metadata.providers"))
        )

        response = client.post(
            f"/config/sections/{SECTION}", data={"action": "move_up", "index": "1"}
        )
        assert response.status_code == 201, response.text

        after = _staged_value(memory_conn)
        assert [p.get("type") for p in after] == ["static", "snmp"]
        assert _normalized(_static_provider(after)) == before


class TestSuppressionDeMasse:
    """La suppression de masse ne doit PAS pouvoir emporter le `static`.

    DÉFAUT MESURÉ (2026-08-07) : `action=remove_selected` est traité avant le
    dispatch par section et suit la FORME de la donnée (une liste). Un simple
    `selected=["0"]` retirait le fournisseur `static` — ses 200 lignes d'ifIndex
    avec — et répondait **HTTP 201**. Le validateur ne rattrapait rien, une
    cascade `[snmp]` seule étant valide.
    """

    def test_remove_selected_ne_peut_pas_supprimer_le_static(
        self, client: TestClient, memory_conn: sqlite3.Connection
    ) -> None:
        response = client.post(
            f"/config/sections/{SECTION}",
            data={"action": "remove_selected", "selected": ["0"]},
        )
        assert response.status_code == 422, (
            "la suppression de masse a emporte le fournisseur 'static' : "
            "toute interface non resolue par SNMP retombe en 'unknown'."
        )
        assert memory_conn.execute("SELECT COUNT(*) FROM pending_config_changes").fetchone()[0] == 0

    def test_le_static_survit_meme_quand_la_cascade_ne_devient_pas_vide(
        self, client: TestClient, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        """LE cas que seul `guard_static_provider_survives` peut attraper.

        Avec un seul fournisseur, la suppression est déjà refusée par la règle
        « cascade vide ». Ici la cascade compte `static` + `snmp` : retirer le
        `static` laisse une liste NON VIDE et parfaitement valide — aucune autre
        règle ne s'y oppose. C'est exactement le cas mesuré le 2026-08-07, qui
        répondait HTTP 201 en emportant les 200 lignes d'ifIndex.
        """
        (config_dir / "outlet.yaml").write_text(
            _OUTLET_YAML
            + "    - type: snmp\n"
            + "      credentials:\n"
            + "        ::/0:\n"
            + "          communities:\n"
            + "            - ${SNMP_COMMUNITY}\n"
        )
        response = client.post(
            f"/config/sections/{SECTION}",
            data={"action": "remove_selected", "selected": ["0"]},
        )
        assert response.status_code == 422, (
            "le fournisseur 'static' a ete supprime alors que la cascade restait "
            "valide : c'est le defaut mesure le 2026-08-07 (HTTP 201)."
        )
        assert "static" in response.text
        assert "unknown" in response.text
        assert memory_conn.execute("SELECT COUNT(*) FROM pending_config_changes").fetchone()[0] == 0

    def test_retirer_le_snmp_par_suppression_de_masse_reste_possible(
        self, client: TestClient, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        """Le garde-fou protège le `static`, il ne bloque pas toute suppression.

        Un garde-fou qui refuserait aussi les gestes légitimes serait contourné
        ou désactivé — donc inutile le jour où il compte.
        """
        (config_dir / "outlet.yaml").write_text(
            _OUTLET_YAML
            + "    - type: snmp\n"
            + "      credentials:\n"
            + "        ::/0:\n"
            + "          communities:\n"
            + "            - ${SNMP_COMMUNITY}\n"
        )
        response = client.post(
            f"/config/sections/{SECTION}",
            data={"action": "remove_selected", "selected": ["1"]},
        )
        assert response.status_code == 201, response.text
        assert [p.get("type") for p in _staged_value(memory_conn)] == ["static"]

    def test_le_garde_fou_laisse_passer_ce_qui_ne_touche_pas_au_static(self) -> None:
        """Il ne refuse pas TOUT changement — seulement une perte de `static`."""
        from app.routers.config_sections import guard_static_provider_survives

        current = [{"type": "static"}, {"type": "snmp"}]
        assert guard_static_provider_survives(current, [{"type": "static"}]) == []
        assert guard_static_provider_survives(current, current) == []
        assert guard_static_provider_survives([{"type": "snmp"}], [{"type": "snmp"}]) == []
        # Perte effective : refusée.
        assert guard_static_provider_survives(current, [{"type": "snmp"}])


class TestRotationDeCommunaute:
    """Déclarer une nouvelle communauté ne doit pas effacer l'ancienne.

    DÉFAUT MESURÉ (2026-08-07) : l'écriture remplaçait tout le mapping du
    sous-réseau, donc `communities: [A, B]` devenait `[C]`. Or une liste à
    plusieurs communautés est le motif normal d'une ROTATION — on déclare
    l'ancienne et la nouvelle en parallèle le temps que le parc bascule. Les
    équipements pas encore migrés cessaient de répondre, sans erreur, sur un
    HTTP 201.
    """

    def test_ajouter_une_communaute_conserve_les_precedentes(
        self, client: TestClient, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        (config_dir / "outlet.yaml").write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: snmp\n"
            "      credentials:\n"
            "        ::/0:\n"
            "          communities:\n"
            "            - ${SNMP_ANCIENNE}\n"
        )
        assert _enable_snmp(client, community="${SNMP_NOUVELLE}").status_code == 201
        snmp = next(p for p in _staged_value(memory_conn) if p.get("type") == "snmp")
        assert snmp["credentials"]["::/0"]["communities"] == [
            "${SNMP_ANCIENNE}",
            "${SNMP_NOUVELLE}",
        ]

    def test_redeclarer_la_meme_communaute_ne_la_duplique_pas(
        self, client: TestClient, memory_conn: sqlite3.Connection
    ) -> None:
        assert _enable_snmp(client, community="${SNMP_A}").status_code == 201
        assert _enable_snmp(client, community="${SNMP_A}").status_code == 201
        snmp = next(p for p in _staged_value(memory_conn) if p.get("type") == "snmp")
        assert snmp["credentials"]["::/0"]["communities"] == ["${SNMP_A}"]


class TestAjoutEtCascade:
    def test_activer_snmp_ajoute_un_fournisseur(
        self, client: TestClient, memory_conn: sqlite3.Connection
    ) -> None:
        assert _enable_snmp(client).status_code == 201
        providers = _staged_value(memory_conn)
        types = [p.get("type") for p in providers]
        assert types.count("snmp") == 1
        assert types.count("static") == 1

    def test_snmp_est_insere_APRES_le_static(
        self, client: TestClient, memory_conn: sqlite3.Connection
    ) -> None:
        """L'ordre correct est `static` PUIS `snmp`.

        Contre-intuitif : on placerait spontanément la source qui fait foi en
        tête. Mais Akvorado s'arrête au premier fournisseur qui ACCEPTE la
        requête, et `snmp` les accepte toutes — en tête, il rendrait `static`
        inatteignable, donc les ifIndex saisis à la main sans effet.
        """
        assert _enable_snmp(client).status_code == 201
        types = [p.get("type") for p in _staged_value(memory_conn)]
        assert types.index("static") < types.index("snmp"), (
            f"cascade dans le mauvais ordre: {types}"
        )

    def test_une_cascade_inversee_est_signalee(self) -> None:
        """`snmp` avant `static` n'est pas refusé, mais il est DIT.

        Refuser serait présomptueux : une infrastructure peut légitimement
        vouloir que l'équipement fasse foi sans repli. Se taire serait pire —
        le repli statique deviendrait inatteignable en silence.
        """
        warnings = check_cascade_order(["snmp", "static"])
        assert warnings, "une cascade inversee doit etre signalee"
        assert "static" in warnings[0]

    def test_l_ordre_correct_ne_declenche_aucun_signalement(self) -> None:
        assert check_cascade_order(["static", "snmp"]) == []

    def test_une_cascade_sans_static_ne_declenche_rien(self) -> None:
        """Pas de `static` = pas de repli à protéger : rien à signaler."""
        assert check_cascade_order(["snmp"]) == []

    def test_un_static_enterre_apres_snmp_est_signale_meme_s_il_y_en_a_un_avant(
        self,
    ) -> None:
        """`['static', 'snmp', 'static']` : le premier repli est consulté, le
        SECOND est mort — `snmp` arrête le parcours avant lui. Ne comparer que
        les premières occurrences déclarait cette cascade saine, alors qu'un
        opérateur y a écrit des ifIndex qui ne seront jamais lus."""
        warnings = check_cascade_order(["static", "snmp", "static"])
        assert warnings, "le static enterre apres snmp doit etre signale"
        assert "#3" in warnings[0], "le rang du fournisseur inatteignable doit etre cite"

    def test_la_cascade_inversee_du_disque_est_affichee_a_l_ouverture(
        self, client: TestClient, config_dir: Path
    ) -> None:
        """Une cascade déjà inversée (posée en SSH) doit se voir SANS attendre
        qu'on tente une modification."""
        (config_dir / "outlet.yaml").write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: snmp\n"
            "      credentials:\n"
            "        ::/0:\n"
            "          communities:\n"
            "            - ${SNMP_COMMUNITY}\n"
            "    - type: static\n"
            "      exporters: {}\n"
        )
        html = client.get(f"/config/sections/{SECTION}").text
        assert "mauvais ordre" in html or "Remontez" in html

    def test_le_reordonnancement_est_possible_a_la_souris(self, client: TestClient) -> None:
        """L'ordre étant sémantique, il doit se corriger sans rouvrir le YAML."""
        html = client.get(f"/config/sections/{SECTION}").text
        assert 'name="action" value="move_up"' in html
        assert 'name="action" value="move_down"' in html

    def test_reactiver_snmp_met_a_jour_sans_dupliquer(
        self, client: TestClient, memory_conn: sqlite3.Connection
    ) -> None:
        """Deux activations ne créent pas deux fournisseurs snmp.

        Akvorado interrogeant les fournisseurs dans l'ordre, un doublon rendrait
        le second inatteignable — et masquerait qu'un réglage y a été posé.
        """
        assert _enable_snmp(client).status_code == 201
        assert _enable_snmp(client, subnet="10.0.0.0/8").status_code == 201
        types = [p.get("type") for p in _staged_value(memory_conn)]
        assert types.count("snmp") == 1


# ---------------------------------------------------------------------------
# 4. SÉCURITÉ — la communauté ne fuit ni à l'écran, ni dans les logs
# ---------------------------------------------------------------------------


class TestSecretDeLaCommunaute:
    def test_la_communaute_n_apparait_jamais_en_clair_dans_le_html(
        self, client: TestClient, config_dir: Path
    ) -> None:
        """Le YAML contient la communauté en clair ; le HTML ne doit pas.

        Le fichier de configuration est la source : on l'écrit délibérément avec
        une valeur en clair (cas de l'opérateur qui a fait ce choix), et on
        vérifie que l'écran refuse de la rendre. C'est le seul montage qui
        prouve le masquage — partir d'une configuration sans communauté
        prouverait seulement qu'on n'affiche pas ce qui n'existe pas.
        """
        (config_dir / "outlet.yaml").write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: static\n"
            "      exporters: {}\n"
            "    - type: snmp\n"
            "      credentials:\n"
            "        ::/0:\n"
            "          communities:\n"
            f"            - {SECRET_COMMUNITY}\n"
        )
        html = client.get(f"/config/sections/{SECTION}").text
        assert SECRET_COMMUNITY not in html, (
            "la communaute SNMP est rendue EN CLAIR dans le HTML. C'est un secret "
            "d'authentification : capture d'ecran, partage d'ecran, cache navigateur."
        )
        assert "••••••" in html, "la communaute doit etre visiblement MASQUEE, pas omise"

    def test_une_valeur_en_clair_declenche_un_avertissement_visible(
        self, client: TestClient, config_dir: Path
    ) -> None:
        """Accepté (c'est son choix), mais jamais silencieux."""
        (config_dir / "outlet.yaml").write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: snmp\n"
            "      credentials:\n"
            "        ::/0:\n"
            "          communities:\n"
            f"            - {SECRET_COMMUNITY}\n"
        )
        html = client.get(f"/config/sections/{SECTION}").text
        assert "en clair" in html.lower()
        assert "notice-warn" in html

    def test_la_communaute_n_apparait_jamais_dans_les_logs(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Chemin de fuite le plus insidieux : le message d'ERREUR.

        Un validateur qui cite la valeur refusée (« communaute invalide:
        'xxx' ») l'écrit en clair dans les logs — donc dans OpenObserve, dans
        les sauvegardes de logs, et sous les yeux de toute personne qui débogue.
        On capture TOUT (niveau DEBUG), sur un chemin de succès ET un chemin de
        refus.
        """
        caplog.set_level(logging.DEBUG)

        # Chemin de succès.
        assert _enable_snmp(client).status_code == 201
        # Chemin de refus : sous-réseau invalide, communauté pourtant fournie.
        client.post(
            f"/config/sections/{SECTION}",
            data={
                "action": "enable_snmp",
                "subnet": "pas-un-cidr",
                "community": SECRET_COMMUNITY,
            },
        )

        captured = "\n".join(record.getMessage() for record in caplog.records)
        assert SECRET_COMMUNITY not in captured, (
            "la communaute SNMP a fuite dans les logs. Un message d'erreur qui "
            "cite la valeur refusee l'ecrit en clair sur le chemin qu'on regarde "
            "le moins."
        )

    def test_le_refus_reste_exploitable_sans_citer_le_secret(self, client: TestClient) -> None:
        """Ne pas citer le secret ne doit pas rendre l'erreur incompréhensible.

        Le sous-réseau, lui, n'est pas un secret : il est cité, et c'est ce qui
        rend le message actionnable.
        """
        response = client.post(
            f"/config/sections/{SECTION}",
            data={
                "action": "enable_snmp",
                "subnet": "pas-un-cidr",
                "community": SECRET_COMMUNITY,
            },
        )
        assert response.status_code == 422
        assert "pas-un-cidr" in response.text
        assert SECRET_COMMUNITY not in response.text

    def test_le_champ_de_saisie_ne_prerempli_pas_la_communaute(
        self, client: TestClient, config_dir: Path
    ) -> None:
        """Un `value=` prérempli remettrait le secret dans le HTML par la
        porte de derrière — et le rendrait lisible via l'inspecteur."""
        (config_dir / "outlet.yaml").write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: snmp\n"
            "      credentials:\n"
            "        ::/0:\n"
            "          communities:\n"
            f"            - {SECRET_COMMUNITY}\n"
        )
        html = client.get(f"/config/sections/{SECTION}").text
        assert f'value="{SECRET_COMMUNITY}"' not in html

    def test_le_champ_communaute_est_un_champ_masque(self, client: TestClient) -> None:
        """`type="password"` + `autocomplete="off"` : la saisie ne s'affiche pas
        à l'écran et le navigateur ne la conserve pas dans son formulaire."""
        html = client.get(f"/config/sections/{SECTION}").text
        assert 'id="snmp-community"' in html
        field = html[
            html.index('id="snmp-community"') - 200 : html.index('id="snmp-community"') + 200
        ]
        assert 'type="password"' in field
        assert 'autocomplete="off"' in field


class TestMasquage:
    """Comportement unitaire de `mask_community` — la fonction par laquelle
    TOUTE communauté doit passer avant d'atteindre le gabarit."""

    def test_une_valeur_en_clair_est_masquee(self) -> None:
        assert mask_community(SECRET_COMMUNITY) == "••••••"

    def test_le_masque_ne_revele_pas_la_longueur(self) -> None:
        """Un masque proportionnel à la longueur divulguerait une information
        exploitable pour une attaque par force brute."""
        assert mask_community("ab") == mask_community("a" * 64)

    def test_une_reference_d_environnement_reste_lisible(self) -> None:
        """Elle ne révèle rien, et c'est la seule chose dont l'opérateur a
        besoin à l'écran : savoir QUELLE variable est attendue."""
        assert mask_community("${SNMP_COMMUNITY}") == "${SNMP_COMMUNITY}"

    def test_une_valeur_absente_rend_une_chaine_vide(self) -> None:
        assert mask_community(None) == ""
        assert mask_community("") == ""
        assert mask_community("   ") == ""


class TestModeReferenceEnvironnement:
    def test_le_mode_variable_est_propose_a_l_ecran(self, client: TestClient) -> None:
        """Proposé comme mode par DÉFAUT : c'est le placeholder du champ."""
        html = client.get(f"/config/sections/{SECTION}").text
        assert "${SNMP_COMMUNITY}" in html
        assert "recommand" in html.lower()

    def test_une_reference_est_acceptee_et_ecrite_telle_quelle(
        self, client: TestClient, memory_conn: sqlite3.Connection
    ) -> None:
        """La référence doit arriver INTACTE dans le YAML : c'est Akvorado (ou
        l'environnement du conteneur) qui la résout, pas cette application. La
        « résoudre » ici écrirait la valeur en clair dans le fichier — exactement
        ce que le mode par référence existe pour éviter."""
        assert _enable_snmp(client, community="${SNMP_COMMUNITY}").status_code == 201
        providers = _staged_value(memory_conn)
        snmp = next(p for p in providers if p.get("type") == "snmp")
        assert snmp["credentials"]["::/0"]["communities"] == ["${SNMP_COMMUNITY}"]

    def test_une_reference_est_signalee_comme_telle_a_l_ecran(
        self, client: TestClient, config_dir: Path
    ) -> None:
        (config_dir / "outlet.yaml").write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: snmp\n"
            "      credentials:\n"
            "        ::/0:\n"
            "          communities:\n"
            "            - ${SNMP_COMMUNITY}\n"
        )
        html = client.get(f"/config/sections/{SECTION}").text
        assert "Référence d'environnement" in html
        # Aucun avertissement « en clair » ne doit s'afficher dans ce mode :
        # un avertissement qui se déclenche pour rien apprend à les ignorer.
        assert "communauté(s) écrite(s) en clair" not in html

    def test_reconnaissance_d_une_reference(self) -> None:
        assert is_env_reference("${SNMP_COMMUNITY}")
        assert is_env_reference("  ${X}  ")
        assert not is_env_reference("public")
        assert not is_env_reference("$SNMP_COMMUNITY")  # sans accolades
        assert not is_env_reference("${}")  # vide


# ---------------------------------------------------------------------------
# 5. Allowlist des types de fournisseur
# ---------------------------------------------------------------------------


class TestAllowlistDesTypes:
    def test_les_quatre_types_connus_sont_acceptes(self) -> None:
        assert VALID_METADATA_PROVIDER_TYPES == {"snmp", "gnmi", "static", "bioris"}

    @pytest.mark.parametrize("provider_type", ["snmp", "gnmi", "static", "bioris"])
    def test_chaque_type_connu_passe_la_validation(self, provider_type: str) -> None:
        validator = get_section(SECTION).validator
        value: list[Any] = [{"type": provider_type}]
        if provider_type == "snmp":
            value = [{"type": "snmp", "credentials": {"::/0": {"communities": ["x"]}}}]
        assert validator(value) == []

    @pytest.mark.parametrize("unknown", ["ansible", "netbox", "SNMP", "", "snmpv3"])
    def test_un_type_inconnu_est_refuse(self, unknown: str) -> None:
        """Allowlist FERMÉE : un type inconnu fait refuser tout le document par
        l'outlet au démarrage — donc plus aucune collecte de flux."""
        errors = get_section(SECTION).validator([{"type": unknown}])
        assert errors, f"le type {unknown!r} aurait du etre refuse"

    def test_une_cascade_vide_est_refusee(self) -> None:
        """Sans aucun fournisseur, TOUS les flux retombent en `unknown` — le
        défaut même que cette section existe pour éviter."""
        errors = get_section(SECTION).validator([])
        assert errors
        assert "unknown" in errors[0]

    def test_une_valeur_non_liste_est_refusee(self) -> None:
        assert get_section(SECTION).validator({"type": "snmp"})

    def test_un_fournisseur_sans_type_est_refuse(self) -> None:
        assert get_section(SECTION).validator([{"credentials": {}}])


class TestReglagesSnmp:
    """Les leviers qu'on touche quand SNMP est lent."""

    def test_les_reglages_sont_ecrits_avec_le_bon_nom_de_cle(
        self, client: TestClient, memory_conn: sqlite3.Connection
    ) -> None:
        """Akvorado attend `poller-retries` (tiret), pas `poller_retries`
        (souligné, la convention des champs de formulaire HTML). Une clé mal
        nommée serait ignorée : le réglage n'aurait AUCUN effet, sans erreur."""
        response = _enable_snmp(client, workers="20", poller_retries="3", poller_timeout="2s")
        assert response.status_code == 201, response.text
        snmp = next(p for p in _staged_value(memory_conn) if p.get("type") == "snmp")
        assert snmp["workers"] == 20
        assert snmp["poller-retries"] == 3
        assert snmp["poller-timeout"] == "2s"

    def test_un_champ_vide_ne_pose_pas_de_reglage(
        self, client: TestClient, memory_conn: sqlite3.Connection
    ) -> None:
        """Vide = « laisser le défaut d'Akvorado », pas « écrire 0 » — qui
        serait un réglage bien réel, et absurde (0 worker = aucun sondage)."""
        assert _enable_snmp(client, workers="", poller_retries="").status_code == 201
        snmp = next(p for p in _staged_value(memory_conn) if p.get("type") == "snmp")
        assert "workers" not in snmp
        assert "poller-retries" not in snmp

    def test_un_delai_sans_unite_est_refuse(self) -> None:
        """Go lirait `5` comme 5 NANOSECONDES : le délai expirerait avant toute
        réponse et SNMP ne remonterait plus rien — un réglage censé le rendre
        plus tolérant le rendrait totalement inopérant."""
        errors = get_section(SECTION).validator(
            [
                {
                    "type": "snmp",
                    "poller-timeout": 5,
                    "credentials": {"::/0": {"communities": ["x"]}},
                }
            ]
        )
        assert errors
        assert "duree" in errors[0]

    @pytest.mark.parametrize("duration", ["0s", "0ms", "0s0ms", "٣s"])
    def test_un_delai_nul_ou_non_ascii_est_refuse(self, duration: str) -> None:
        """`0s` a la FORME d'une durée valide et produit exactement l'effet d'un
        entier nu : un délai qui expire immédiatement, donc plus aucune
        interface résolue par SNMP. Refuser l'entier nu tout en acceptant `0s`
        aurait laissé grande ouverte la porte qu'on croyait fermer.

        `٣s` (chiffre arabo-indien) est refusé par Go : le valider ici ferait
        échouer l'outlet au démarrage, sur une saisie que l'écran a acceptée."""
        errors = get_section(SECTION).validator(
            [
                {
                    "type": "snmp",
                    "poller-timeout": duration,
                    "credentials": {"::/0": {"communities": ["x"]}},
                }
            ]
        )
        assert errors, f"le delai {duration!r} aurait du etre refuse"

    @pytest.mark.parametrize("duration", ["1s", "500ms", "2m", "1m30s", "1h"])
    def test_les_durees_valides_passent(self, duration: str) -> None:
        assert (
            get_section(SECTION).validator(
                [
                    {
                        "type": "snmp",
                        "poller-timeout": duration,
                        "credentials": {"::/0": {"communities": ["x"]}},
                    }
                ]
            )
            == []
        )

    def test_les_cles_non_gerees_par_l_ecran_survivent(
        self, client: TestClient, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        """`ports` et `agents` sont acceptés par Akvorado mais absents de cet
        écran. Régler `workers` ici ne doit pas les effacer — ce serait une perte
        silencieuse de configuration, sur un chemin de succès."""
        (config_dir / "outlet.yaml").write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: snmp\n"
            "      agents:\n"
            "        192.168.1.1: 192.168.1.254\n"
            "      ports:\n"
            "        192.168.1.0/24: 1161\n"
            "      credentials:\n"
            "        ::/0:\n"
            "          communities:\n"
            "            - ${SNMP_COMMUNITY}\n"
        )
        assert _enable_snmp(client, workers="30").status_code == 201
        snmp = next(p for p in _staged_value(memory_conn) if p.get("type") == "snmp")
        assert snmp["agents"] == {"192.168.1.1": "192.168.1.254"}
        assert snmp["ports"] == {"192.168.1.0/24": 1161}


class TestPlusieursSousReseaux:
    def test_plusieurs_plages_cohabitent(
        self, client: TestClient, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        """Un parc hétérogène a souvent une communauté par site."""
        (config_dir / "outlet.yaml").write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: snmp\n"
            "      credentials:\n"
            "        10.1.0.0/16:\n"
            "          communities:\n"
            "            - ${SNMP_SITE_A}\n"
        )
        assert (
            _enable_snmp(client, subnet="10.2.0.0/16", community="${SNMP_SITE_B}").status_code
            == 201
        )
        snmp = next(p for p in _staged_value(memory_conn) if p.get("type") == "snmp")
        assert set(snmp["credentials"]) == {"10.1.0.0/16", "10.2.0.0/16"}

    def test_retirer_un_sous_reseau_conserve_les_autres(
        self, client: TestClient, memory_conn: sqlite3.Connection, config_dir: Path
    ) -> None:
        (config_dir / "outlet.yaml").write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: snmp\n"
            "      credentials:\n"
            "        10.1.0.0/16:\n"
            "          communities:\n"
            "            - ${SNMP_SITE_A}\n"
            "        10.2.0.0/16:\n"
            "          communities:\n"
            "            - ${SNMP_SITE_B}\n"
        )
        response = client.post(
            f"/config/sections/{SECTION}",
            data={"action": "remove_subnet", "subnet": "10.1.0.0/16"},
        )
        assert response.status_code == 201, response.text
        snmp = next(p for p in _staged_value(memory_conn) if p.get("type") == "snmp")
        assert set(snmp["credentials"]) == {"10.2.0.0/16"}

    def test_un_sous_reseau_invalide_est_refuse(self, client: TestClient) -> None:
        response = _enable_snmp(client, subnet="192.168.1.0/33")
        assert response.status_code == 422


# ---------------------------------------------------------------------------
# 6. Contrat du gabarit — CSP, classes CSS, hx-confirm
# ---------------------------------------------------------------------------


_JINJA_COMMENT_RE = re.compile(r"\{#.*?#\}", re.DOTALL)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def _markup(html: str) -> str:
    """Retire les commentaires avant analyse : une classe CITÉE dans un
    commentaire explicatif n'est pas une classe POSÉE sur un élément."""
    return _HTML_COMMENT_RE.sub("", _JINJA_COMMENT_RE.sub("", html))


class TestContratDuGabarit:
    def test_toutes_les_classes_introduites_existent_dans_le_css(
        self, client: TestClient, config_dir: Path
    ) -> None:
        """Défaut vécu QUATRE fois sur ce projet : une classe posée sans règle
        CSS correspondante. L'élément se rend avec le style par défaut du
        navigateur, hors charte, et sans la moindre erreur.

        Le YAML est monté avec SNMP actif : `.secret-cell` n'existe que sur la
        table des communautés, qui n'est rendue que dans cet état. Tester sur la
        configuration par défaut (SNMP inactif) ne prouverait rien sur elle.
        """
        (config_dir / "outlet.yaml").write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: snmp\n"
            "      credentials:\n"
            "        ::/0:\n"
            "          communities:\n"
            "            - ${SNMP_COMMUNITY}\n"
        )
        html = _markup(client.get(f"/config/sections/{SECTION}").text)
        css = STYLE_CSS.read_text(encoding="utf-8")

        introduced = ["providers-cascade__title", "providers-cascade__moves", "secret-cell"]
        for css_class in introduced:
            assert css_class in html, f"{css_class} n'est pas utilisee par le gabarit"
            assert re.search(rf"\.{re.escape(css_class)}\b", css), (
                f"la classe '{css_class}' est posee dans le gabarit mais n'a AUCUNE "
                "regle dans style.css : l'element se rend hors charte, sans erreur."
            )

    def test_aucune_classe_inconnue_n_est_posee_sur_le_bloc(self, client: TestClient) -> None:
        """Vérification par ÉNUMÉRATION DE LA SOURCE, pas d'une liste connue
        d'avance : on extrait les classes réellement écrites et on exige une
        règle pour chacune.

        Périmètre restreint au BLOC de cette section (entre son premier et son
        dernier marqueur), et non à la page entière : le gabarit partagé rend
        aussi le panneau de file d'attente et la sonde de fraîcheur, dont les
        classes appartiennent à d'autres lots. Les inclure ferait échouer ce
        test sur du code que cette section n'a pas écrit — un test qui accuse le
        mauvais coupable finit par être désactivé.
        """
        html = _markup(client.get(f"/config/sections/{SECTION}").text)
        css = STYLE_CSS.read_text(encoding="utf-8")

        start = html.index("Ordre d'interrogation")
        end = html.index('name="action" value="enable_snmp"')
        block = html[start:end]

        used: set[str] = set()
        for match in re.finditer(r'class="([^"]+)"', block):
            used.update(match.group(1).split())

        assert used, "aucune classe extraite : le bloc analyse est vide"
        missing = [
            css_class
            for css_class in sorted(used)
            if not re.search(rf"\.{re.escape(css_class)}\b", css)
        ]
        assert not missing, f"classes sans regle CSS: {missing}"

    def test_aucune_variable_css_inexistante(self) -> None:
        """Toute `var(--x)` doit être déclarée dans `:root` — sinon la propriété
        est simplement ignorée par le navigateur, sans erreur."""
        css = STYLE_CSS.read_text(encoding="utf-8")
        css_without_comments = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)

        root_block = css_without_comments[
            css_without_comments.index(":root") : css_without_comments.index("}")
        ]
        declared = set(re.findall(r"(--[a-zA-Z0-9-]+)\s*:", root_block))
        used = set(re.findall(r"var\((--[a-zA-Z0-9-]+)\)", css_without_comments))
        assert used <= declared, f"variables non declarees dans :root: {sorted(used - declared)}"

    def test_aucun_gestionnaire_javascript_inline(self, client: TestClient) -> None:
        """CSP `script-src 'self'` : un `onclick=` serait bloqué par le
        navigateur — page affichée, boutons inertes, aucune erreur visible."""
        html = _markup(client.get(f"/config/sections/{SECTION}").text)
        for match in re.finditer(r'\bon[a-z]+\s*=\s*["\']', html):
            prefix = html[max(0, match.start() - 8) : match.start()]
            excerpt = html[max(0, match.start() - 30) : match.start() + 40]
            assert "hx-" in prefix, f"gestionnaire inline interdit sous CSP: {excerpt!r}"

    def test_aucun_script_inline(self, client: TestClient) -> None:
        html = _markup(client.get(f"/config/sections/{SECTION}").text)
        for match in re.finditer(r"<script\b([^>]*)>", html):
            assert "src=" in match.group(1), "script inline interdit sous CSP"

    def test_hx_confirm_est_porte_par_le_formulaire_pas_par_le_bouton(
        self, client: TestClient, config_dir: Path
    ) -> None:
        """htmx remonte les ANCÊTRES depuis l'élément qui porte `hx-post`.
        Posé sur le bouton, `hx-confirm` est ignoré EN SILENCE : la suppression
        se ferait sans jamais demander confirmation."""
        (config_dir / "outlet.yaml").write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: snmp\n"
            "      credentials:\n"
            "        ::/0:\n"
            "          communities:\n"
            "            - ${SNMP_COMMUNITY}\n"
        )
        html = _markup(client.get(f"/config/sections/{SECTION}").text)

        assert "hx-confirm" in html, "les actions destructives doivent confirmer"
        for match in re.finditer(r"<button\b[^>]*>", html):
            assert "hx-confirm" not in match.group(0), (
                f"hx-confirm pose sur un BOUTON, il sera ignore: {match.group(0)!r}"
            )

    def test_les_actions_destructives_confirment(
        self, client: TestClient, config_dir: Path
    ) -> None:
        """Désactiver SNMP et retirer un sous-réseau font perdre la résolution
        d'interface : les deux doivent demander confirmation."""
        (config_dir / "outlet.yaml").write_text(
            "metadata:\n"
            "  providers:\n"
            "    - type: snmp\n"
            "      credentials:\n"
            "        ::/0:\n"
            "          communities:\n"
            "            - ${SNMP_COMMUNITY}\n"
        )
        html = _markup(client.get(f"/config/sections/{SECTION}").text)

        # Les deux gestes destructifs de cette section : retirer un sous-réseau
        # (l'équipement cesse d'être interrogé) et désactiver SNMP (on retombe
        # sur la seule table écrite à la main).
        #
        # La confirmation est cherchée dans le formulaire QUI PORTE l'action, et
        # non « quelque part dans la page » : une version antérieure de ce test
        # comptait les formulaires confirmants d'un côté et les actions de
        # l'autre, sans jamais vérifier leur CONJONCTION. Elle passait donc sur
        # une page où les deux gestes destructifs avaient perdu leur
        # `hx-confirm`, pourvu que deux formulaires anodins en portent un —
        # c'est-à-dire exactement le cas qu'elle prétendait interdire.
        #
        # Le corps complet du formulaire est capturé (`<form ...>...</form>`) :
        # la balise ouvrante seule ne contient pas les `<input type="hidden">`
        # qui portent l'action.
        forms = re.findall(r"<form\b.*?</form>", html, re.DOTALL)
        for destructive in ("disable_snmp", "remove_subnet"):
            carriers = [f for f in forms if f'value="{destructive}"' in f]
            assert carriers, f"aucun formulaire ne porte l'action {destructive!r}"
            for carrier in carriers:
                assert "hx-confirm" in carrier, (
                    f"le formulaire portant {destructive!r} ne demande AUCUNE "
                    "confirmation : le geste est destructif."
                )

    def test_chaque_champ_est_associe_a_son_label(self, client: TestClient) -> None:
        """Un champ sans label n'est pas seulement inaccessible : à l'écran, le
        libellé se rattache optiquement au champ SUIVANT quand la grille
        `auto-fit` retourne à la ligne (défaut vécu le 2026-08-06)."""
        html = _markup(client.get(f"/config/sections/{SECTION}").text)
        block = html[html.index('name="action" value="enable_snmp"') :]

        labelled = set(re.findall(r'<label\s+for="([^"]+)"', block))
        for field_id in re.findall(r'<input\b[^>]*id="(snmp-[^"]+)"', block):
            assert field_id in labelled, f"le champ {field_id!r} n'a aucun <label for>"

    def test_chaque_paire_label_champ_vit_dans_un_field(self, client: TestClient) -> None:
        html = _markup(client.get(f"/config/sections/{SECTION}").text)
        block = html[html.index('name="action" value="enable_snmp"') :]
        for field_id in re.findall(r'<input\b[^>]*id="(snmp-[^"]+)"', block):
            start = block.index(f'id="{field_id}"')
            before = block[max(0, start - 400) : start]
            assert 'class="field' in before, (
                f"le champ {field_id!r} n'est pas emballe dans un .field : la grille "
                "auto-fit peut couper la paire label/champ au retour a la ligne."
            )

    def test_les_formulaires_sont_proteges_du_double_submit(self, client: TestClient) -> None:
        html = _markup(client.get(f"/config/sections/{SECTION}").text)
        for form in re.findall(r"<form\b[^>]*?>", html, re.DOTALL):
            if "hx-post" not in form:
                continue
            assert "hx-sync" in form, f"formulaire sans hx-sync: {form[:120]!r}"
            assert "hx-disabled-elt" in form, f"formulaire sans hx-disabled-elt: {form[:120]!r}"

    def test_la_page_se_rend_sans_erreur(self, client: TestClient) -> None:
        response = client.get(f"/config/sections/{SECTION}")
        assert response.status_code == 200
        assert "Découverte des interfaces" in response.text

    def test_l_ordre_de_la_cascade_est_visible(self, client: TestClient) -> None:
        """L'ordre est sémantique : il doit se LIRE, pas se deviner."""
        html = client.get(f"/config/sections/{SECTION}").text
        assert "Ordre d'interrogation" in html
        assert "static" in html
