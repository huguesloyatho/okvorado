"""Tests de la résolution AUTOMATIQUE de la table ifIndex -> ifName par SNMP.

POURQUOI CE MODULE EXISTE — LE DÉFAUT MESURÉ (2026-08-10)
---------------------------------------------------------
L'écran /exporters affichait « Interface inconnue » sur 4 exportateurs sur 11,
avec des interfaces observées valant littéralement `unknown`. Cause mesurée :

  - `outlet.yaml` déclarait pour CHAQUE exportateur une liste `if-indexes`
    ÉCRITE À LA MAIN, différente machine par machine : serveur-fichiers=[2,152],
    routeur-agence-01=[2,2932], routeur-agence-02=[2,999], clm=[2,1222],
    routeur-agence-21=[2,235], routeur-agence-03=[2,39], serveur-media=[5]...
  - Ces valeurs ne correspondaient À AUCUNE interface réelle. Vérifié par SSH
    sur 4 machines : les ifIndex réels sont 1=lo, 2=eth0/ens18, 3=tailscale0,
    4+=bridges Docker. Les nombres 2932/999/235/1222/39 n'existent nulle part.
  - Conséquence : un flux arrivant avec ifIndex 3 (tailscale0) ne matchait
    aucune déclaration -> Akvorado appliquait le bloc `default:` -> écrivait
    `unknown` dans InIfName/OutIfName -> l'écran affichait « Interface
    inconnue ».

PREUVE QUE L'AUTOMATISATION EST POSSIBLE (mesurée sur un exportateur du parc) :
un walk de `1.3.6.1.2.1.31.1.1.1.1` (IF-MIB::ifName) rend la table COMPLÈTE —
ifName.1=lo, ifName.2=eth0, ifName.3=tailscale0, ifName.4=br-780869fa3032 —
c'est EXACTEMENT ce qui était écrit à la main dans outlet.yaml. Sur deux
autres machines du parc, aucun agent snmpd n'est installé (service inactive,
rien en écoute sur 161) : ce n'est pas un échec de la méthode, c'est un agent
absent côté équipement, et l'écran doit le DIRE au lieu de rendre une table
vide.

CE QUE LES TESTS PROUVENT ICI (l'intention, pas l'implémentation) :
  - la table ifIndex->ifName est résolue par un WALK SNMP, avec repli sur
    ifDescr quand ifName est vide (certains équipements ne remplissent que
    ifDescr) ;
  - ZÉRO SILENCIEUX : un agent muet produit un état DISTINCT
    (`no_response`), jamais une table vide qu'on confondrait avec « cet
    équipement n'a aucune interface » ;
  - le geste « Tout résoudre » rend compte PAR EXPORTATEUR (résolu / muet /
    erreur), jamais un compteur global qui masquerait les échecs — c'est le
    geste qui doit tenir à 350 routeurs ;
  - la communauté/les mots de passe SNMP n'apparaissent JAMAIS dans un rendu
    HTML ni dans un log ;
  - une adresse invalide est REFUSÉE avant tout accès réseau.

⚠️ Aucun test ici n'exige d'agent SNMP réel : le walk bas niveau
(`_snmp_walk_interfaces`) est systématiquement mocké. Les états d'échec
vérifiés plus bas sont des états SIMULÉS du produit, pas des constats sur
l'infrastructure.

⚠️ Les assertions anti-secret EXCLUENT commentaires/docstrings du code source :
un motif interdit DOCUMENTÉ dans un commentaire ne doit jamais faire échouer
son propre test (piège vécu 9 fois sur ce projet).
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

from app.db import init_database
from app.models import (
    Boundary,
    DeclaredExporter,
    ExporterHealth,
    ExporterStatus,
    InterfaceSpec,
    ObservedExporter,
)
from app.services import snmp_inventory

APP_DIR = Path(__file__).parent.parent / "app"

# SECRET_OK: placeholders de test, jamais des secrets réels — même convention
# que `_FAKE_COMMUNITY` dans tests/test_snmp_inventory.py. Ils servent
# précisément à PROUVER l'absence de fuite dans les logs et le HTML.
_FAKE_COMMUNITY = "s3cr3t-community-ifindex"
_FAKE_V3_AUTH_PASSWORD = "s3cr3t-auth-ifindex"
_FAKE_V3_PRIV_PASSWORD = "s3cr3t-priv-ifindex"

#: Fragment de phrase que le PRODUIT doit afficher quand l'agent SNMP d'un
#: équipement ne renvoie rien. C'est une chaîne d'interface utilisateur
#: attendue dans un rendu HTML, pas une affirmation sur l'état d'une machine :
#: les tests qui l'emploient pilotent un double de test (`_fake_walk_muet`),
#: aucun réseau n'est sollicité. Centralisée ici pour rester unique.
_LIBELLE_AGENT_SANS_REPONSE = "ne répond pas"


# ---------------------------------------------------------------------------
# Fixtures et doubles
# ---------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    path = str(tmp_path / "test.db")
    init_database(path)
    return path


@pytest.fixture
def db_conn(db_path: str) -> Generator[sqlite3.Connection]:
    """Connexion SQLite sur FICHIER et `check_same_thread=False`.

    Les deux routes de résolution déportent le sondage SNMP (bloquant) dans
    un thread via `asyncio.to_thread` — c'est obligatoire, `resolve_interface_table`
    appelle `asyncio.run()` en interne et l'exécuter dans la boucle d'uvicorn
    lèverait « asyncio.run() cannot be called from a running event loop »
    (défaut mesuré en prod le 2026-08-08). La connexion doit donc tolérer
    d'être vue depuis plusieurs threads, exactement comme la connexion réelle
    câblée par `app/main.py::_open_db`. Un `:memory:` ne conviendrait pas :
    il est PAR CONNEXION, donc invisible depuis l'autre thread.
    """
    connection = sqlite3.connect(db_path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


#: Table mesurée par un walk SNMP sur un exportateur du parc le 2026-08-10
#: (cf. docstring de module). Sert de double réaliste : c'est LITTÉRALEMENT
#: ce que l'agent rend.
_TABLE_REELLE_DOT_7: dict[int, str] = {
    1: "lo",
    2: "eth0",
    3: "tailscale0",
    4: "br-780869fa3032",
}


def _fake_walk_ok(*_args: Any, **_kwargs: Any) -> dict[int, str]:
    return dict(_TABLE_REELLE_DOT_7)


def _fake_walk_muet(*_args: Any, **_kwargs: Any) -> None:
    """Double simulant un agent qui ne renvoie rien : le walk bas niveau rend
    `None`, JAMAIS `{}` — c'est toute la distinction que ce module existe
    pour préserver."""
    return None


def _declared(
    cidr: str, name: str, if_indexes: dict[int, InterfaceSpec] | None = None
) -> DeclaredExporter:
    return DeclaredExporter(
        cidr=cidr,
        name=name,
        if_indexes=if_indexes or {},
        default=InterfaceSpec(if_index=0, name="unknown"),
        is_catchall=False,
    )


def _status_interface_inconnue(address: str = "192.0.2.7", name: str = "routeur-agence-02") -> Any:
    """Reproduit EXACTEMENT le cas mesuré : des if-indexes déclarés à la main
    (999) qui n'existent pas, et une interface observée valant `unknown`."""
    return ExporterStatus(
        address=address,
        name=name,
        health=ExporterHealth.UNKNOWN_INTERFACE,
        declared=_declared(
            f"{address}/32",
            name,
            if_indexes={
                2: InterfaceSpec(if_index=2, name="eth0", boundary=Boundary.EXTERNAL),
                999: InterfaceSpec(if_index=999, name="tailscale0", boundary=Boundary.INTERNAL),
            },
        ),
        observed=ObservedExporter(
            address=address,
            name=name,
            flows=1000,
            bytes=100000,
            interfaces=["unknown", "eth0"],
        ),
        forwarded_total=1000,
        rejected_total=0,
        explanation="interface inconnue",
    )


def _status_sain(address: str = "192.0.2.24", name: str = "routeur-agence-01") -> Any:
    return ExporterStatus(
        address=address,
        name=name,
        health=ExporterHealth.HEALTHY,
        declared=_declared(
            f"{address}/32", name, if_indexes={2: InterfaceSpec(if_index=2, name="eth0")}
        ),
        observed=ObservedExporter(
            address=address, name=name, flows=10, bytes=100, interfaces=["eth0"]
        ),
        forwarded_total=10,
        rejected_total=0,
        explanation="ok",
    )


def _make_test_app() -> FastAPI:
    """App minimale montant le router Exportateurs + la connexion SQLite.

    Même isolement que `_make_test_app` de tests/test_exporters.py : on ne
    monte pas `app.main` (auth, tâches de fond) pour tester le routing.
    """
    from app.routers import exporters as exporters_router
    from app.templating import build_templates

    test_app = FastAPI()
    test_app.state.templates = build_templates()
    test_app.include_router(exporters_router.router)
    return test_app


def _make_test_app_with_db(conn: sqlite3.Connection) -> FastAPI:
    from app.routers import exporters as exporters_router

    test_app = _make_test_app()
    test_app.dependency_overrides[exporters_router.get_db_connection] = lambda: conn
    return test_app


def _strip_comments_and_docstrings(source: str) -> str:
    """Retire commentaires et docstrings pour que la DOCUMENTATION d'un piège
    évité ne fasse pas échouer le test qui vérifie qu'il est bien évité."""
    without_triple_double = re.sub(r'""".*?"""', "", source, flags=re.DOTALL)
    without_triple_single = re.sub(r"'''.*?'''", "", without_triple_double, flags=re.DOTALL)
    return "\n".join(line.split("#", 1)[0] for line in without_triple_single.splitlines())


# ---------------------------------------------------------------------------
# 1. Le walk SNMP de la table d'interfaces — service
# ---------------------------------------------------------------------------


class TestResolveInterfaceTable:
    """`snmp_inventory.resolve_interface_table` : ifIndex -> ifName, en
    plusieurs issues DISTINCTES (ok / no_response / auth_failure / ...)."""

    def test_table_resolue_rend_le_mapping_ifindex_vers_ifname(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Le cas nominal MESURÉ : la table complète est rendue, avec des
        clés ENTIÈRES (l'ifIndex est un entier côté Akvorado)."""
        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk_ok)

        result = snmp_inventory.resolve_interface_table(
            address="192.0.2.7", community=_FAKE_COMMUNITY
        )

        assert result.status == "ok"
        assert result.interfaces == _TABLE_REELLE_DOT_7
        assert all(isinstance(key, int) for key in result.interfaces)

    def test_agent_muet_produit_un_etat_distinct_pas_une_table_vide(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ZÉRO SILENCIEUX (CLAUDE.md) : un agent qui ne renvoie rien ne doit
        JAMAIS produire `interfaces == {}` avec `status == 'ok'` — sinon
        l'écran afficherait « aucune interface » pour un équipement qui en a
        peut-être vingt. Le double `_fake_walk_muet` simule ce cas."""
        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk_muet)

        result = snmp_inventory.resolve_interface_table(
            address="192.0.2.23", community=_FAKE_COMMUNITY
        )

        assert result.status == "no_response"
        assert result.interfaces == {}
        assert result.is_usable is False
        # Le message doit ORIENTER l'exploitant, pas juste constater.
        assert "161" in result.message
        assert "snmpd" in result.message.lower()

    def test_echec_authentification_v3_est_distinct_de_agent_muet(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Un mauvais mot de passe v3 (l'agent RÉPOND mais refuse) ne se
        corrige pas comme un agent absent : deux états DISTINCTS, jamais
        fondus en un seul (même règle que `collect_one`)."""

        def _walk_auth_failure(*_args: Any, **_kwargs: Any) -> dict[int, str]:
            raise snmp_inventory.SnmpAuthenticationError("refus simule pour test")

        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _walk_auth_failure)

        result = snmp_inventory.resolve_interface_table(
            address="192.0.2.7",
            snmp_version="v3",
            v3_credentials=snmp_inventory.SnmpV3Credentials(
                username="okvorado-ro",
                security_level="authPriv",
                auth_protocol="SHA256",
                auth_password=_FAKE_V3_AUTH_PASSWORD,
                priv_protocol="AES256",
                priv_password=_FAKE_V3_PRIV_PASSWORD,
            ),
        )

        assert result.status == "auth_failure"
        assert result.status != "no_response"
        assert result.is_usable is False

    def test_sans_credentials_refus_avant_tout_acces_reseau(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SNMP non configuré = refus EXPLICITE avant sondage, jamais une
        communauté vide envoyée sur le fil (même garde que `collect_one`)."""
        appels: list[Any] = []

        def _walk_espion(*args: Any, **kwargs: Any) -> dict[int, str]:
            appels.append((args, kwargs))
            return {}

        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _walk_espion)

        result = snmp_inventory.resolve_interface_table(address="192.0.2.7", community="")

        assert result.status == "not_configured"
        assert result.is_usable is False
        assert appels == [], "aucun sondage réseau ne doit avoir lieu sans credentials"

    def test_adresse_invalide_est_refusee_avant_tout_acces_reseau(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SÉCURITÉ (CLAUDE.md) : une valeur qui n'est pas une adresse IP ne
        doit JAMAIS atteindre la couche réseau — pas d'input brut vers le
        réseau, même en provenance d'un chemin d'URL."""
        appels: list[Any] = []

        def _walk_espion(*args: Any, **kwargs: Any) -> dict[int, str]:
            appels.append((args, kwargs))
            return {}

        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _walk_espion)

        result = snmp_inventory.resolve_interface_table(
            address="pas-une-ip; rm -rf /", community=_FAKE_COMMUNITY
        )

        assert result.status == "invalid_address"
        assert result.is_usable is False
        assert appels == [], "une adresse invalide ne doit jamais être sondée"

    def test_table_vide_rendue_par_un_agent_qui_repond_est_signalee(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Un agent qui répond mais ne déclare AUCUNE interface est
        anormal : c'est un état distinct d'un succès, pas un `ok` avec zéro
        ligne (sinon on écrirait un outlet.yaml sans aucune interface)."""
        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", lambda *a, **k: {})

        result = snmp_inventory.resolve_interface_table(
            address="192.0.2.7", community=_FAKE_COMMUNITY
        )

        assert result.status == "empty_table"
        assert result.is_usable is False

    def test_communaute_absente_des_logs(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """La communauté ne doit JAMAIS apparaître dans un log, y compris sur
        le chemin d'échec (c'est là qu'on est tenté de tout logger)."""
        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk_muet)

        with caplog.at_level(logging.DEBUG):
            snmp_inventory.resolve_interface_table(address="192.0.2.23", community=_FAKE_COMMUNITY)

        assert _FAKE_COMMUNITY not in caplog.text

    def test_mots_de_passe_v3_absents_des_logs(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        def _walk_auth_failure(*_args: Any, **_kwargs: Any) -> dict[int, str]:
            raise snmp_inventory.SnmpAuthenticationError("refus simule pour test")

        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _walk_auth_failure)

        with caplog.at_level(logging.DEBUG):
            snmp_inventory.resolve_interface_table(
                address="192.0.2.7",
                snmp_version="v3",
                v3_credentials=snmp_inventory.SnmpV3Credentials(
                    username="okvorado-ro",
                    security_level="authPriv",
                    auth_protocol="SHA256",
                    auth_password=_FAKE_V3_AUTH_PASSWORD,
                    priv_protocol="AES256",
                    priv_password=_FAKE_V3_PRIV_PASSWORD,
                ),
            )

        assert _FAKE_V3_AUTH_PASSWORD not in caplog.text
        assert _FAKE_V3_PRIV_PASSWORD not in caplog.text

    def test_le_resultat_ne_porte_jamais_les_credentials(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Le modèle rendu à l'appelant (et donc potentiellement au template)
        ne doit porter AUCUN secret — même garde que `InventoryItem`."""
        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk_ok)

        result = snmp_inventory.resolve_interface_table(
            address="192.0.2.7", community=_FAKE_COMMUNITY
        )

        assert _FAKE_COMMUNITY not in repr(result)
        assert _FAKE_COMMUNITY not in str(result.model_dump())


class TestWalkOidsEtRepliIfDescr:
    """Le walk interroge bien IF-MIB::ifName, avec repli sur ifDescr."""

    def test_oid_ifname_est_le_walk_primaire(self) -> None:
        """1.3.6.1.2.1.31.1.1.1.1 = IF-MIB::ifName — l'OID MESURÉ qui rend la
        table complète. Littéral figé, jamais dérivé d'une saisie."""
        assert snmp_inventory._OID_IF_NAME == "1.3.6.1.2.1.31.1.1.1.1"

    def test_oid_ifdescr_est_le_repli(self) -> None:
        """1.3.6.1.2.1.2.2.1.2 = IF-MIB::ifDescr — certains équipements ne
        remplissent QUE ifDescr (ifName vide)."""
        assert snmp_inventory._OID_IF_DESCR == "1.3.6.1.2.1.2.2.1.2"

    def test_repli_sur_ifdescr_quand_ifname_est_vide(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Cas des équipements qui ne remplissent que ifDescr : le walk
        primaire (ifName) rend une table vide, le repli doit être tenté et
        c'est SON résultat qui compte — jamais un `empty_table` prématuré."""
        oids_interroges: list[str] = []

        def _walk_par_oid(
            address: str, oid: str, _timeout: float, **_kwargs: Any
        ) -> dict[int, str]:
            oids_interroges.append(oid)
            if oid == snmp_inventory._OID_IF_NAME:
                return {}
            return {1: "Loopback0", 2: "GigabitEthernet0/1"}

        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _walk_par_oid)

        result = snmp_inventory.resolve_interface_table(
            address="192.0.2.7", community=_FAKE_COMMUNITY
        )

        assert result.status == "ok"
        assert result.interfaces == {1: "Loopback0", 2: "GigabitEthernet0/1"}
        assert result.source_oid == snmp_inventory._OID_IF_DESCR
        assert oids_interroges == [snmp_inventory._OID_IF_NAME, snmp_inventory._OID_IF_DESCR]

    def test_pas_de_repli_inutile_quand_ifname_repond(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Un walk SNMP coûte un aller-retour réseau par ligne : à 350
        routeurs, un repli systématique doublerait le temps de résolution
        pour rien."""
        oids_interroges: list[str] = []

        def _walk_par_oid(
            address: str, oid: str, _timeout: float, **_kwargs: Any
        ) -> dict[int, str]:
            oids_interroges.append(oid)
            return dict(_TABLE_REELLE_DOT_7)

        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _walk_par_oid)

        result = snmp_inventory.resolve_interface_table(
            address="192.0.2.7", community=_FAKE_COMMUNITY
        )

        assert result.status == "ok"
        assert result.source_oid == snmp_inventory._OID_IF_NAME
        assert oids_interroges == [snmp_inventory._OID_IF_NAME]

    def test_aucun_sous_processus_dans_le_walk(self) -> None:
        """Même garde que le reste du module : pysnmp est pur Python, aucune
        commande shell n'est construite (donc aucune injection possible par
        construction)."""
        source = (APP_DIR / "services" / "snmp_inventory.py").read_text(encoding="utf-8")
        code_only = _strip_comments_and_docstrings(source)
        assert "shell=True" not in code_only
        assert "subprocess" not in code_only
        assert "os.system" not in code_only


# ---------------------------------------------------------------------------
# 2. Traduction table SNMP -> if-indexes outlet.yaml
# ---------------------------------------------------------------------------


class TestConstructionDesIfIndexes:
    """La table SNMP doit se traduire en `if-indexes` écrivables tels quels
    dans outlet.yaml, en PRÉSERVANT ce qui était déjà correctement déclaré."""

    def test_construit_une_specification_par_interface_reelle(self) -> None:
        from app.services.exporters import build_if_indexes_from_snmp

        specs = build_if_indexes_from_snmp(_TABLE_REELLE_DOT_7, existing={})

        assert set(specs) == {1, 2, 3, 4}
        assert specs[3].name == "tailscale0"
        assert specs[3].if_index == 3
        # Un ifIndex <= 0 fait rejeter les flux par Akvorado : jamais généré.
        assert all(spec.if_index > 0 for spec in specs.values())

    def test_les_reglages_existants_sont_preserves_par_nom(self) -> None:
        """`boundary`, `speed` et `description` sont un choix d'exploitant
        (SNMP ne les rend pas au même niveau de sens) : ré-indexer une
        interface ne doit pas EFFACER ce réglage. C'est ici que se joue le
        vrai correctif : `tailscale0` était déclaré à 999 avec
        `boundary=internal`, il doit se retrouver à 3 avec le MÊME boundary."""
        from app.services.exporters import build_if_indexes_from_snmp

        existing = {
            999: InterfaceSpec(
                if_index=999,
                name="tailscale0",
                description="tailscale mesh",
                speed=1000,
                boundary=Boundary.INTERNAL,
            ),
            2: InterfaceSpec(
                if_index=2, name="eth0", description="WAN", speed=1000, boundary=Boundary.EXTERNAL
            ),
        }

        specs = build_if_indexes_from_snmp(_TABLE_REELLE_DOT_7, existing=existing)

        assert 999 not in specs, "l'ifIndex fantôme doit disparaître"
        assert specs[3].name == "tailscale0"
        assert specs[3].boundary == Boundary.INTERNAL
        assert specs[3].description == "tailscale mesh"
        assert specs[2].boundary == Boundary.EXTERNAL
        assert specs[2].description == "WAN"

    def test_une_interface_inconnue_de_la_config_prend_un_defaut_neutre(self) -> None:
        """Une interface découverte qui n'était pas déclarée ne doit pas se
        voir attribuer un `boundary` INVENTÉ : `undefined` est l'état honnête
        (l'exploitant tranchera), jamais `internal` ou `external` deviné.

        ÉVOLUTION DATÉE (2026-08-11) : le nom d'interface utilisé ici est
        passé de `br-nouveau` à `eth1-nouveau`. Le cas `br-nouveau` est
        devenu CONTRADICTOIRE avec l'introduction du filtrage par motif
        (`app.services.exporters.filtrer_interfaces_exploitables`, motif
        `br-*` exclu par défaut — cf. `test_filtrage_interfaces.py`) : une
        interface `br-*` n'est plus censée atteindre `build_if_indexes_from_snmp`
        du tout, elle est écartée EN AMONT par le filtre. `build_if_indexes_from_snmp`
        reste une traduction PURE de ce qu'on lui donne (elle ne fait pas elle-même
        de filtrage, ce n'est pas son rôle) : ce test vérifie donc son comportement
        sur *n'importe quelle* interface inconnue de la config, avec un nom qui
        n'illustre plus, à tort, un cas que le filtre amont a vocation à exclure."""
        from app.services.exporters import build_if_indexes_from_snmp

        specs = build_if_indexes_from_snmp({7: "eth1-nouveau"}, existing={})

        assert specs[7].boundary == Boundary.UNDEFINED
        assert specs[7].speed > 0


# ---------------------------------------------------------------------------
# 3. Le bouton « Résoudre par SNMP » — UN exportateur
# ---------------------------------------------------------------------------


class TestBoutonResoudreUnExportateur:
    def test_resolution_reussie_rend_un_fragment_html_pas_du_json(
        self, db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """DÉFAUT DÉJÀ RENCONTRÉ 9 FOIS SUR CE PROJET : un POST HTMX qui rend
        du JSON brut affiche `{"status": "ok"}` en clair à l'écran. Le bouton
        doit rendre du HTML."""
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router

        monkeypatch.setattr(app_settings, "snmp_community", _FAKE_COMMUNITY)
        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk_ok)

        async def _fake_statuses(_window: str) -> list[Any]:
            return [_status_interface_inconnue()]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db(db_conn))
        response = client.post("/exporters/192.0.2.7/resolve-snmp")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert not response.text.lstrip().startswith("{")
        # La table trouvée doit être MONTRÉE : l'exploitant doit voir ce qui
        # va être écrit avant que ça le soit.
        assert "tailscale0" in response.text
        assert "eth0" in response.text

    def test_agent_muet_affiche_un_message_explicite_pas_un_tableau_vide(
        self, db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ZÉRO SILENCIEUX à l'écran : le message d'agent SNMP sans réponse
        doit être LU par l'exploitant, jamais une table vide qu'il
        confondrait avec « cet équipement n'a aucune interface ». Le walk est
        piloté par le double `_fake_walk_muet` : aucun réseau sollicité."""
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router

        monkeypatch.setattr(app_settings, "snmp_community", _FAKE_COMMUNITY)
        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk_muet)

        async def _fake_statuses(_window: str) -> list[Any]:
            return [_status_interface_inconnue(address="192.0.2.23", name="clm")]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db(db_conn))
        response = client.post("/exporters/192.0.2.23/resolve-snmp")

        # 422 (pas 500) : un 500 n'est PAS swappé par htmx -> message invisible
        # (cf. tests/test_htmx_error_visibility.py).
        assert response.status_code == 422
        texte = response.text.lower()
        assert _LIBELLE_AGENT_SANS_REPONSE in texte
        assert "161" in response.text
        assert "snmpd" in texte

    def test_resolution_met_le_changement_en_attente_dans_outlet_yaml(
        self, db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Le bouton doit réutiliser le MÉCANISME D'ÉCRITURE EXISTANT (file
        d'attente `pending_config_changes` -> `apply_pending_changes`, qui
        gère verrou optimiste + backup + écriture atomique), jamais une
        écriture sauvage d'outlet.yaml."""
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router
        from app.services.config_writer import list_pending_changes

        monkeypatch.setattr(app_settings, "snmp_community", _FAKE_COMMUNITY)
        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk_ok)

        async def _fake_statuses(_window: str) -> list[Any]:
            return [_status_interface_inconnue()]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db(db_conn))
        response = client.post("/exporters/192.0.2.7/resolve-snmp")
        assert response.status_code == 200

        pending = list_pending_changes(db_conn)
        assert len(pending) == 1
        change = pending[0]
        assert change.change_type == "update_exporter"
        assert change.payload["cidr"] == "192.0.2.7/32"
        # Les ifIndex fantômes disparaissent, les réels apparaissent.
        # DEPUIS LE CÂBLAGE DU FILTRAGE (2026-08-11, cf.
        # tests/test_ssh_ifindex_resolution.py::TestFiltrageCableSurLaResolutionSnmp) :
        # `lo` (1) et `br-780869fa3032` (4) sont désormais écartés par le
        # filtre par défaut (OKVORADO_INTERFACE_EXCLUDE_PATTERNS =
        # "lo,docker0,br-*,veth*"), qui s'applique AVANT la mise en file
        # d'attente. Seules eth0 (2, déjà déclarée) et tailscale0 (3, le cas
        # réel de ce module) survivent.
        indexes = {int(key) for key in change.payload["if_indexes"]}
        assert indexes == {2, 3}
        assert 999 not in indexes
        assert 1 not in indexes
        assert 4 not in indexes

    def test_adresse_invalide_est_refusee_sans_sondage(
        self, db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SÉCURITÉ : le chemin d'URL est une saisie utilisateur. Il ne doit
        jamais atteindre la couche réseau sans validation."""
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router

        appels: list[Any] = []

        def _walk_espion(*args: Any, **kwargs: Any) -> dict[int, str]:
            appels.append((args, kwargs))
            return dict(_TABLE_REELLE_DOT_7)

        monkeypatch.setattr(app_settings, "snmp_community", _FAKE_COMMUNITY)
        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _walk_espion)

        async def _fake_statuses(_window: str) -> list[Any]:
            return [_status_interface_inconnue()]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db(db_conn))
        response = client.post("/exporters/pas-une-ip/resolve-snmp")

        assert response.status_code == 422
        assert appels == []

    def test_exportateur_inconnu_est_refuse(
        self, db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """L'adresse sondée doit venir de la liste des exportateurs CONNUS
        (même règle que `app.services.snmp_inventory`), pas d'une IP
        arbitraire postée par un client : Okvorado ne doit pas devenir un
        scanner SNMP du réseau."""
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router

        appels: list[Any] = []

        def _walk_espion(*args: Any, **kwargs: Any) -> dict[int, str]:
            appels.append((args, kwargs))
            return dict(_TABLE_REELLE_DOT_7)

        monkeypatch.setattr(app_settings, "snmp_community", _FAKE_COMMUNITY)
        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _walk_espion)

        async def _fake_statuses(_window: str) -> list[Any]:
            return [_status_interface_inconnue(address="192.0.2.7")]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db(db_conn))
        response = client.post("/exporters/8.8.8.8/resolve-snmp")

        assert response.status_code == 422
        assert appels == [], "une IP hors du parc connu ne doit jamais être sondée"

    def test_aucun_secret_dans_le_fragment_rendu(
        self, db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router

        monkeypatch.setattr(app_settings, "snmp_community", _FAKE_COMMUNITY)
        monkeypatch.setattr(app_settings, "snmp_v3_auth_password", _FAKE_V3_AUTH_PASSWORD)
        monkeypatch.setattr(app_settings, "snmp_v3_priv_password", _FAKE_V3_PRIV_PASSWORD)
        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk_ok)

        async def _fake_statuses(_window: str) -> list[Any]:
            return [_status_interface_inconnue()]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db(db_conn))
        response = client.post("/exporters/192.0.2.7/resolve-snmp")

        assert _FAKE_COMMUNITY not in response.text
        assert _FAKE_V3_AUTH_PASSWORD not in response.text
        assert _FAKE_V3_PRIV_PASSWORD not in response.text


# ---------------------------------------------------------------------------
# 4. Le bouton « Tout résoudre » — LE geste qui tient à 350 routeurs
# ---------------------------------------------------------------------------


class TestBoutonToutResoudre:
    def test_traite_tous_les_exportateurs_en_anomalie(
        self, db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """C'est LE geste que ce projet doit rendre possible : à 350
        routeurs, cliquer 350 fois n'est pas une réponse."""
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router
        from app.services.config_writer import list_pending_changes

        monkeypatch.setattr(app_settings, "snmp_community", _FAKE_COMMUNITY)
        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk_ok)

        async def _fake_statuses(_window: str) -> list[Any]:
            return [
                _status_interface_inconnue(address="192.0.2.6", name="serveur-fichiers"),
                _status_interface_inconnue(address="192.0.2.7", name="routeur-agence-02"),
                _status_interface_inconnue(address="192.0.2.21", name="routeur-agence-21"),
                _status_sain(),
            ]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db(db_conn))
        response = client.post("/exporters/resolve-snmp-all")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

        pending = list_pending_changes(db_conn)
        cidrs = {change.payload["cidr"] for change in pending}
        assert cidrs == {"192.0.2.6/32", "192.0.2.7/32", "192.0.2.21/32"}
        # L'exportateur SAIN ne doit pas être touché : on ne réécrit pas une
        # configuration correcte.
        assert "192.0.2.24/32" not in cidrs

    def test_rend_compte_par_exportateur_jamais_un_compteur_global(
        self, db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ZÉRO SILENCIEUX, cas le plus dangereux du lot : « 2 exportateurs
        résolus » sur 3 masque QUI a échoué et POURQUOI. Chaque exportateur
        doit avoir sa ligne, avec un état DISTINCT. Les trois sorts sont
        SIMULÉS par `_walk_selectif`."""
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router

        monkeypatch.setattr(app_settings, "snmp_community", _FAKE_COMMUNITY)

        def _walk_selectif(
            address: str, oid: str, _timeout: float, **_kwargs: Any
        ) -> dict[int, str] | None:
            if address == "192.0.2.7":
                return dict(_TABLE_REELLE_DOT_7)
            if address == "192.0.2.21":
                raise snmp_inventory.SnmpAuthenticationError("refus simule pour test")
            return None

        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _walk_selectif)

        async def _fake_statuses(_window: str) -> list[Any]:
            return [
                _status_interface_inconnue(address="192.0.2.6", name="serveur-fichiers"),
                _status_interface_inconnue(address="192.0.2.7", name="routeur-agence-02"),
                _status_interface_inconnue(address="192.0.2.21", name="routeur-agence-21"),
            ]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db(db_conn))
        response = client.post("/exporters/resolve-snmp-all")

        assert response.status_code == 200
        texte = response.text

        # Les TROIS adresses apparaissent, chacune avec son sort.
        assert "192.0.2.6" in texte
        assert "192.0.2.7" in texte
        assert "192.0.2.21" in texte

        # Trois états DISTINCTS, lisibles : résolu / sans réponse / auth refusée.
        minuscules = texte.lower()
        assert "résolu" in minuscules or "resolu" in minuscules
        assert _LIBELLE_AGENT_SANS_REPONSE in minuscules
        assert "authentification" in minuscules

    def test_un_echec_n_interrompt_pas_les_suivants(
        self, db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """À 350 routeurs, un agent muet en position 2 ne doit pas empêcher
        les 348 suivants d'être résolus."""
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router
        from app.services.config_writer import list_pending_changes

        monkeypatch.setattr(app_settings, "snmp_community", _FAKE_COMMUNITY)

        def _walk_selectif(
            address: str, oid: str, _timeout: float, **_kwargs: Any
        ) -> dict[int, str] | None:
            if address == "192.0.2.6":
                return None
            return dict(_TABLE_REELLE_DOT_7)

        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _walk_selectif)

        async def _fake_statuses(_window: str) -> list[Any]:
            return [
                _status_interface_inconnue(address="192.0.2.6", name="serveur-fichiers"),
                _status_interface_inconnue(address="192.0.2.7", name="routeur-agence-02"),
                _status_interface_inconnue(address="192.0.2.21", name="routeur-agence-21"),
            ]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db(db_conn))
        response = client.post("/exporters/resolve-snmp-all")

        assert response.status_code == 200
        cidrs = {change.payload["cidr"] for change in list_pending_changes(db_conn)}
        assert cidrs == {"192.0.2.7/32", "192.0.2.21/32"}

    def test_aucun_exportateur_en_anomalie_est_dit_explicitement(
        self, db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """« Rien à faire » doit être ÉCRIT, jamais rendu par un fragment vide
        qu'on confondrait avec un bouton cassé."""
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router

        monkeypatch.setattr(app_settings, "snmp_community", _FAKE_COMMUNITY)
        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk_ok)

        async def _fake_statuses(_window: str) -> list[Any]:
            return [_status_sain()]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db(db_conn))
        response = client.post("/exporters/resolve-snmp-all")

        assert response.status_code == 200
        assert response.text.strip(), "jamais un fragment vide"
        assert "aucun" in response.text.lower()

    def test_snmp_non_configure_est_dit_explicitement(
        self, db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sans communauté ni utilisateur v3, l'écran doit dire que SNMP
        n'est pas configuré — pas « aucune interface trouvée », qui
        enverrait l'exploitant chercher une panne sur les équipements."""
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router

        monkeypatch.setattr(app_settings, "snmp_community", "")
        monkeypatch.setattr(app_settings, "snmp_v3_username", "")

        async def _fake_statuses(_window: str) -> list[Any]:
            return [_status_interface_inconnue()]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db(db_conn))
        response = client.post("/exporters/resolve-snmp-all")

        assert response.status_code == 422
        assert "configur" in response.text.lower()


# ---------------------------------------------------------------------------
# 5. L'écran — les boutons existent et ne tombent pas dans le piège hx-select
# ---------------------------------------------------------------------------


class TestEcranExportateurs:
    def _render(self, items: list[Any]) -> str:
        from starlette.requests import Request

        from app.templating import build_templates

        templates = build_templates()
        scope: dict[str, Any] = {
            "type": "http",
            "method": "GET",
            "path": "/exporters",
            "headers": [],
            "query_string": b"",
            "server": ("test", 80),
            "scheme": "http",
            "client": ("test", 123),
            "app": None,
        }
        response = templates.TemplateResponse(
            Request(scope),
            "exporters.html",
            {
                "items": items,
                "total": len(items),
                "window": "1h",
                "window_choices": ["1h", "6h", "24h", "7d"],
                "error": None,
                "snmp_configured": True,
            },
        )
        return response.body.decode("utf-8")

    def test_bouton_resoudre_par_snmp_present_sur_un_exportateur_en_anomalie(self) -> None:
        html = self._render([_status_interface_inconnue()])

        assert "resolve-snmp" in html
        assert "Résoudre par SNMP" in html

    def test_bouton_tout_resoudre_present(self) -> None:
        """Le geste global doit être atteignable À LA SOURIS depuis l'écran,
        pas seulement par une URL tapée à la main."""
        html = self._render([_status_interface_inconnue()])

        assert "resolve-snmp-all" in html
        assert "Tout résoudre" in html

    def test_les_boutons_coupent_l_heritage_hx_select(self) -> None:
        """PIÈGE MESURÉ, déjà vécu sur db_health.html et retention.html : le
        conteneur `#exporters-page` porte `hx-select="#exporters-page"` pour
        s'auto-rafraîchir. Les fragments rendus par ces boutons n'ont PAS cet
        id -> htmx hérite du sélecteur, ne trouve rien, et insère un fragment
        VIDE EN SILENCE. `hx-select="unset"` coupe cet héritage."""
        html = self._render([_status_interface_inconnue()])

        assert 'hx-select="unset"' in html

        # Et l'héritage est bien coupé AU-DESSUS des boutons de résolution,
        # pas ailleurs dans la page : le marqueur doit précéder le premier
        # `resolve-snmp` rencontré.
        position_unset = html.find('hx-select="unset"')
        position_bouton = html.find("resolve-snmp")
        assert position_unset != -1
        assert position_unset < position_bouton, (
            "hx-select=unset doit être posé sur la section qui CONTIENT les "
            "boutons, sinon l'héritage s'applique quand même"
        )

    def test_pas_de_bouton_snmp_sur_un_exportateur_sain(self) -> None:
        html = self._render([_status_sain()])

        assert "resolve-snmp-all" in html, "le geste global reste proposé"
        # Mais aucune action par ligne sur un exportateur sain.
        assert "/exporters/192.0.2.24/resolve-snmp" not in html


class TestAttenteVisiblePendantLeSondageSnmp:
    """Un bouton qui met des secondes à répondre doit le DIRE pendant l'attente.

    DÉFAUT MESURÉ À L'ÉCRAN (2026-08-10), sur la plateforme réelle : « Tout
    résoudre par SNMP » mettait **9,8 s** à rendre son tableau pour 11
    exportateurs (chaque agent muet coûte son timeout complet — 3,4 s mesurées
    sur un exportateur sans snmpd). Pendant ces dix secondes, l'écran ne
    montrait STRICTEMENT RIEN : ni indicateur, ni message. Le fragment serveur
    était pourtant correct, et la suite de tests verte.

    C'est un zéro silencieux d'INTERFACE : rien ne distingue « en cours » de
    « cassé », donc l'exploitant reclique. `hx-disabled-elt` empêche bien le
    double envoi, mais un bouton grisé sans texte n'explique pas l'attente.

    Deux corrections, verrouillées ici :
      - `hx-indicator` sur les deux boutons, avec la classe `htmx-indicator`
        définie dans `style.css` (sans elle, l'indicateur resterait affiché en
        permanence — l'inverse de l'effet voulu) ;
      - sondage CONCURRENT côté serveur (`asyncio.gather`) au lieu d'un `await`
        par exportateur : à 350 routeurs, l'addition des timeouts se compterait
        en minutes.
    """

    _TEMPLATE = Path(__file__).resolve().parent.parent / "app" / "templates" / "exporters.html"
    _CSS = Path(__file__).resolve().parent.parent / "app" / "static" / "style.css"
    _ROUTER = Path(__file__).resolve().parent.parent / "app" / "routers" / "exporters.py"

    def test_les_deux_boutons_snmp_portent_un_indicateur(self) -> None:
        html = self._TEMPLATE.read_text(encoding="utf-8")
        # Chaque bouton déclenchant un sondage SNMP doit annoncer son attente.
        for action in ("resolve-snmp-all", "/resolve-snmp"):
            debut = html.find(action)
            assert debut != -1, f"bouton {action} introuvable dans le gabarit"
            # La balise <button> englobante, bornée à sa fermeture.
            fin = html.find(">", html.find("</button>", debut))
            bloc = html[max(0, debut - 400) : fin if fin > 0 else debut + 400]
            assert "hx-indicator" in bloc, (
                f"le bouton {action} n'a pas d'hx-indicator : l'exploitant ne voit "
                "rien pendant plusieurs secondes et croit le bouton cassé"
            )

    def test_la_classe_htmx_indicator_est_definie_dans_le_css(self) -> None:
        css = self._CSS.read_text(encoding="utf-8")
        assert ".htmx-indicator" in css, (
            "classe htmx-indicator absente de style.css : les indicateurs "
            "resteraient affichés EN PERMANENCE au lieu d'apparaître pendant "
            "la requête"
        )
        assert re.search(r"\.htmx-indicator\s*{[^}]*display:\s*none", css), (
            "htmx-indicator doit être masquée AU REPOS (display:none), sinon "
            "le message d'attente s'affiche tout le temps"
        )

    def test_le_sondage_global_est_concurrent_pas_sequentiel(self) -> None:
        """À 350 routeurs, un `await` par exportateur additionne les timeouts."""
        source = self._ROUTER.read_text(encoding="utf-8")
        debut = source.find("async def post_resolve_snmp_all")
        assert debut != -1, "route de résolution globale introuvable"
        corps = source[debut : debut + 4000]

        assert "asyncio.gather" in corps, (
            "la résolution globale doit lancer les sondages ENSEMBLE "
            "(asyncio.gather) : en séquentiel, 11 exportateurs coûtaient 9,8 s "
            "mesurées, et 350 se compteraient en minutes"
        )
        assert "return_exceptions=True" in corps, (
            "gather doit utiliser return_exceptions=True : un échec isolé doit "
            "rester une LIGNE d'erreur, jamais interrompre les autres sondages"
        )


class TestLeResultatSnmpSurvitAuRafraichissementAuto:
    """Le compte rendu SNMP ne doit pas être effacé par l'auto-rafraîchissement.

    DÉFAUT MESURÉ À L'ÉCRAN (2026-08-10) sur la plateforme réelle : après un
    clic sur « Tout résoudre par SNMP », le tableau de résultats s'affichait
    (capture à l'appui) puis DISPARAISSAIT tout seul quelques secondes plus
    tard. Mesure : `#snmp-resolve-all-result` vide, et DEUX
    `GET /exporters?window=1h` après le POST.

    Cause : le formulaire de fenêtre porte `hx-trigger="change, every 30s"`
    avec `hx-target`/`hx-select` sur `#exporters-page` et `hx-swap=outerHTML`
    — toutes les 30 s la SECTION ENTIÈRE est remplacée, ce qui détruit le
    conteneur de résultat AVEC son contenu.

    Conséquence pour l'exploitant : il lance la résolution, commence à lire
    quelles machines ont répondu, et le compte rendu s'efface sous ses yeux.
    Le travail est bien fait (les changements sont en attente) mais il ne sait
    plus qui a échoué ni pourquoi. Aucun test ne le voyait : aucun ne laisse
    s'écouler 30 s de vie de page.

    Correctif retenu : SUSPENDRE le rafraîchissement tant qu'un résultat est
    affiché, plutôt que le supprimer (il tient les compteurs de flux à jour —
    le retirer serait une régression). Le poll reprend dès que l'exploitant
    ferme le compte rendu.
    """

    _TEMPLATE = Path(__file__).resolve().parent.parent / "app" / "templates" / "exporters.html"

    _GARDE = Path(__file__).resolve().parent.parent / "app" / "static" / "snmp-poll-guard.js"
    _BASE = Path(__file__).resolve().parent.parent / "app" / "templates" / "base.html"

    def test_le_rafraichissement_auto_existe_toujours(self) -> None:
        """Le supprimer « réglerait » le problème en cassant autre chose."""
        html = self._TEMPLATE.read_text(encoding="utf-8")
        assert re.search(r"hx-trigger=\"[^\"]*every\s+\d+s", html), (
            "le déclencheur périodique a disparu : les compteurs de flux ne se "
            "mettent plus à jour tout seuls (régression)"
        )

    def test_la_suspension_nutilise_pas_de_condition_htmx_evaluee(self) -> None:
        """DEUXIÈME DÉFAUT MESURÉ le 2026-08-10 — le piège à ne pas refaire.

        Le premier correctif tenté écrivait
        `every 30s [!document.querySelector(...).innerHTML.trim()]`. htmx
        évalue ces conditions en JavaScript DYNAMIQUE, ce que la CSP du projet
        interdit (`script-src 'self'`, sans `unsafe-eval`). Résultat mesuré au
        navigateur : `EvalError` à chaque tick, condition ignorée, compte rendu
        toujours effacé (présent à 5 s, effacé à 10 s) — plus trois erreurs
        console. Un correctif qui ne corrige rien ET ajoute du bruit.
        """
        html = self._TEMPLATE.read_text(encoding="utf-8")
        poll = re.search(r"hx-trigger=\"[^\"]*every\s+\d+s[^\"]*\"", html)
        assert poll, "déclencheur périodique introuvable"
        assert "[" not in poll.group(0), (
            "condition htmx `every Ns [ ... ]` détectée : elle est évaluée en "
            "JS dynamique et la CSP `script-src 'self'` (sans unsafe-eval) la "
            f"REJETTE en silence. Trouvé : {poll.group(0)}"
        )

    def test_un_garde_local_suspend_le_poll(self) -> None:
        assert self._GARDE.is_file(), (
            "app/static/snmp-poll-guard.js absent : rien ne suspend le poll, "
            "le compte rendu SNMP sera effacé au tick suivant"
        )
        js = self._GARDE.read_text(encoding="utf-8")
        assert "removeAttribute" in js and "hx-trigger" in js, (
            "le garde doit RETIRER l'attribut hx-trigger (seule façon de "
            "suspendre le poll sans évaluer de chaîne)"
        )
        assert "setAttribute" in js, (
            "le garde doit REMETTRE l'attribut : sinon le rafraîchissement "
            "reste suspendu pour toujours après une première résolution"
        )
        assert "MutationObserver" in js, (
            "le conteneur est rempli par un swap htmx, pas par une saisie : "
            "seul un MutationObserver voit le changement"
        )
        # Un script chargé nulle part ne s'exécute jamais.
        assert "snmp-poll-guard.js" in self._BASE.read_text(encoding="utf-8"), (
            "le garde n'est référencé dans aucun gabarit : il ne s'exécutera "
            "jamais (défaut « service existant non branché »)"
        )

    def test_le_conteneur_de_resultat_peut_etre_ferme(self) -> None:
        """Suspendre le poll n'est acceptable que si l'exploitant peut le relancer."""
        html = self._TEMPLATE.read_text(encoding="utf-8")
        assert "snmp-resolve-all-result" in html, "conteneur de résultat introuvable"
        # Un moyen de vider le compte rendu (donc de relancer le poll) doit exister.
        assert re.search(r"(Fermer|Masquer|fermer-resultat-snmp)", html), (
            "aucun moyen de fermer le compte rendu : le rafraîchissement "
            "automatique resterait suspendu indéfiniment"
        )
