"""Tests de la résolution des ifIndex par SSH — repli quand SNMP est muet.

POURQUOI CE MODULE EXISTE — LE BLOCAGE MESURÉ (2026-08-11)
------------------------------------------------------------
53 % des flux (101 326 / 189 449 sur 30 min) portent une interface `unknown`
en production. Cause PROUVÉE : l'ifIndex de `tailscale0` DÉRIVE à chaque
redémarrage de l'interface, et `outlet.yaml` porte des valeurs figées au
moment de la déclaration (voir CLAUDE.md du projet pour le détail par hôte).

Le bouton « Résoudre par SNMP » (cf. tests/test_snmp_ifindex_resolution.py)
est la voie PRINCIPALE et reste inchangée. Mais `snmpd` n'est pas déployé sur
une partie du parc homelab concerné : SNMP y rend systématiquement
`no_response`. Ce module ajoute une SECONDE source de résolution, par SSH
(`ip -o link show`), utilisable en repli — désactivée par défaut pour ne
jamais dégrader la cible entreprise où SNMP répond nativement (Palo Alto,
routeurs SFR).

CE QUE LES TESTS PROUVENT ICI (l'intention, pas l'implémentation) :
  - le parsing de `ip -o link show` (format réel du binaire iproute2) rend la
    même structure `{ifIndex: nom}` que la résolution SNMP — interchangeable ;
  - le même contrat à 3 issues que SNMP (`ok` / `no_response` / `auth_failure`) :
    une tentative sans succès produit un état DISTINCT, jamais une table vide
    qu'on confondrait avec « aucune interface » (zéro silencieux, CLAUDE.md) ;
  - une adresse qui ne parse pas en `ipaddress.ip_address` est un REFUS avant
    tout accès réseau, jamais un « on essaie quand même » ;
  - AUCUN shell n'est invoqué : `subprocess.run` reçoit une LISTE d'arguments,
    jamais `shell=True`, jamais de f-string assemblée en commande ;
  - un échec (timeout, code retour non nul, clé refusée) ne rend jamais une
    table vide silencieuse — le statut le distingue toujours.

⚠️ TOUS les tests ci-dessous mockent `subprocess.run` : aucun accès réseau ou
SSH réel n'est fait, aucune requête n'est jamais envoyée à un hôte du parc.
Les scénarios d'échec utilisent une adresse de la plage de documentation
RFC 5737 (203.0.113.0/24, réservée aux exemples, jamais routée) : ce sont des
états SIMULÉS du produit, pas des constats sur l'infrastructure réelle.

⚠️ Les assertions anti-secret EXCLUENT commentaires/docstrings du code source,
même convention que tests/test_snmp_ifindex_resolution.py.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from app.services import exporters as exporters_service

APP_DIR = Path(__file__).parent.parent / "app"

# ---------------------------------------------------------------------------
# Extrait RÉEL du format `ip -o link show` (iproute2) — capturé en tête de
# fonction plutôt que fabriqué à la main, pour coller au format exact que le
# parseur doit ingérer :
#   "<ifIndex>: <nom>: <FLAGS> mtu <N> qdisc <...> state <...> ..."
# Les interfaces TUN (tailscale0) portent POINTOPOINT dans les flags, pas
# BROADCAST — le parseur ne doit PAS dépendre d'un flag particulier.
# ---------------------------------------------------------------------------
_IP_LINK_SHOW_OUTPUT = (
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode "
    "DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd "
    "00:00:00:00:00:00\n"
    "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP "
    "mode DEFAULT group default qlen 1000\\    link/ether 02:42:ac:11:00:02 "
    "brd ff:ff:ff:ff:ff:ff\n"
    "3: tailscale0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1280 qdisc "
    "fq_codel state UNKNOWN mode DEFAULT group default qlen 500\\    "
    "link/none\n"
)

#: Adresse RFC 5737 (TEST-NET-3), réservée à la documentation : jamais
#: routable, jamais un hôte réel du parc. Utilisée pour les scénarios
#: d'échec simulés (subprocess.run mocké — aucun paquet n'est jamais émis).
_ADRESSE_DOC_TEST = "203.0.113.42"


class TestParseIpLinkShow:
    """Parsing pur — aucun accès réseau, un simple découpage de texte."""

    def test_parse_extrait_les_trois_interfaces_reelles(self) -> None:
        table = exporters_service.parse_ip_link_show(_IP_LINK_SHOW_OUTPUT)
        assert table == {1: "lo", 2: "eth0", 3: "tailscale0"}

    def test_parse_tailscale0_ifindex_3_meme_avec_flag_pointopoint(self) -> None:
        """Le cas EXACT du bug de prod : tailscale0 n'a pas BROADCAST dans ses
        flags (c'est une interface TUN point-à-point), un parseur qui
        suppose ce flag le raterait silencieusement."""
        table = exporters_service.parse_ip_link_show(_IP_LINK_SHOW_OUTPUT)
        assert table[3] == "tailscale0"

    def test_parse_sortie_vide_rend_table_vide(self) -> None:
        assert exporters_service.parse_ip_link_show("") == {}

    def test_parse_ignore_ligne_non_conforme_sans_lever(self) -> None:
        bruit = "quelque chose qui ne ressemble pas a une ligne ip link\n"
        table = exporters_service.parse_ip_link_show(bruit + _IP_LINK_SHOW_OUTPUT)
        assert table == {1: "lo", 2: "eth0", 3: "tailscale0"}

    def test_parse_interface_avec_arobase_vlan(self) -> None:
        """Format alternatif observé sur des interfaces empilées
        (`eth0.100@eth0`) : seul le nom AVANT `@` est l'interface elle-même."""
        sortie = (
            "4: eth0.100@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 "
            "qdisc noqueue state UP mode DEFAULT group default qlen 1000\\    "
            "link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff\n"
        )
        table = exporters_service.parse_ip_link_show(sortie)
        assert table == {4: "eth0.100"}


class TestResolveInterfaceTableSsh:
    """Contrat à 3 issues, IDENTIQUE à `resolve_interface_table` (SNMP)."""

    def test_adresse_invalide_est_refusee_avant_tout_appel(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        appele = False

        def _run_jamais_appele(*args: Any, **kwargs: Any) -> Any:
            nonlocal appele
            appele = True
            raise AssertionError(
                "subprocess.run ne doit JAMAIS être appelé sur une adresse invalide"
            )

        monkeypatch.setattr(subprocess, "run", _run_jamais_appele)

        result = exporters_service.resolve_interface_table_ssh(
            address="pas-une-ip; rm -rf /", ssh_user="root", timeout_seconds=2.0
        )

        assert appele is False
        assert result.status == "invalid_address"
        assert result.interfaces == {}
        assert result.is_usable is False

    def test_adresse_avec_metacaracteres_shell_est_refusee(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tentative d'injection déguisée en adresse — doit échouer au parsing
        `ipaddress.ip_address`, pas être neutralisée par un échappement."""
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("subprocess.run ne doit jamais être appelé")
            ),
        )
        result = exporters_service.resolve_interface_table_ssh(
            address=f"{_ADRESSE_DOC_TEST} && cat /etc/passwd", ssh_user="root", timeout_seconds=2.0
        )
        assert result.status == "invalid_address"
        assert result.interfaces == {}

    def test_ok_rend_la_table_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=_IP_LINK_SHOW_OUTPUT, stderr=""
            )

        monkeypatch.setattr(subprocess, "run", _fake_run)

        result = exporters_service.resolve_interface_table_ssh(
            address=_ADRESSE_DOC_TEST, ssh_user="root", timeout_seconds=2.0
        )

        assert result.status == "ok"
        assert result.is_usable is True
        assert result.interfaces == {1: "lo", 2: "eth0", 3: "tailscale0"}
        assert result.address == _ADRESSE_DOC_TEST

    def test_timeout_ssh_rend_no_response_jamais_table_vide_silencieuse(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _fake_run_timeout(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 2.0))

        monkeypatch.setattr(subprocess, "run", _fake_run_timeout)

        result = exporters_service.resolve_interface_table_ssh(
            address=_ADRESSE_DOC_TEST, ssh_user="root", timeout_seconds=2.0
        )

        assert result.status == "no_response"
        assert result.interfaces == {}
        assert result.is_usable is False
        # ZÉRO SILENCIEUX : le message doit exister et orienter l'action,
        # jamais une chaîne vide qu'on lirait comme "tout va bien".
        assert result.message

    def test_echec_connexion_generique_rend_no_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Simulation d'un échec de connexion TCP (code retour non nul, sans
        rapport avec l'authentification) : le binaire ssh sort en erreur avec
        un message sur stderr, sans lever d'exception Python. Ce test mocke
        entièrement `subprocess.run` — aucune tentative réseau n'a lieu."""

        def _fake_run_echec(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=255,
                stdout="",
                stderr=f"ssh: connect to host {_ADRESSE_DOC_TEST} port 22: Connection refused\n",
            )

        monkeypatch.setattr(subprocess, "run", _fake_run_echec)

        result = exporters_service.resolve_interface_table_ssh(
            address=_ADRESSE_DOC_TEST, ssh_user="root", timeout_seconds=2.0
        )

        assert result.status == "no_response"
        assert result.interfaces == {}
        assert result.is_usable is False

    def test_cle_ssh_refusee_rend_auth_failure_distinct_de_no_response(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Simulation d'un refus d'authentification par clé (la connexion TCP
        aboutit, seule l'auth échoue) — c'est un problème de credentials côté
        Okvorado, pas un état muet. Doit rester DISTINGUABLE de `no_response`
        (même exigence que le contrat SNMPv3). Mock intégral de
        `subprocess.run`."""

        def _fake_run_auth_refusee(
            cmd: list[str], **kwargs: Any
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=255,
                stdout="",
                stderr=f"root@{_ADRESSE_DOC_TEST}: Permission denied (publickey).\n",
            )

        monkeypatch.setattr(subprocess, "run", _fake_run_auth_refusee)

        result = exporters_service.resolve_interface_table_ssh(
            address=_ADRESSE_DOC_TEST, ssh_user="root", timeout_seconds=2.0
        )

        assert result.status == "auth_failure"
        assert result.interfaces == {}
        assert result.is_usable is False
        assert result.status != "no_response"

    def test_sortie_sans_aucune_interface_rend_empty_table_pas_ok(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Zéro silencieux au niveau parsing : un retour 0 sans la moindre
        interface reconnue ne doit JAMAIS produire `status='ok'` avec une
        table vide — sinon un appelant en aval pourrait écrire une config
        vide en la croyant valide (`is_usable` protège déjà ce cas, mais le
        `status` doit aussi le dire explicitement)."""

        def _fake_run_sortie_vide(
            cmd: list[str], **kwargs: Any
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", _fake_run_sortie_vide)

        result = exporters_service.resolve_interface_table_ssh(
            address=_ADRESSE_DOC_TEST, ssh_user="root", timeout_seconds=2.0
        )

        assert result.status == "empty_table"
        assert result.interfaces == {}
        assert result.is_usable is False

    def test_aucun_shell_invoque_liste_argv_uniquement(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Garde de sécurité CENTRALE : l'adresse vient de la base et se
        retrouve dans une commande SSH. `subprocess.run` doit recevoir une
        LISTE d'arguments (jamais `shell=True`, jamais une chaîne)."""
        captured: dict[str, Any] = {}

        def _fake_run(cmd: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=_IP_LINK_SHOW_OUTPUT, stderr=""
            )

        monkeypatch.setattr(subprocess, "run", _fake_run)

        exporters_service.resolve_interface_table_ssh(
            address=_ADRESSE_DOC_TEST, ssh_user="root", timeout_seconds=2.0
        )

        assert isinstance(captured["cmd"], list), "la commande DOIT être une liste d'arguments"
        assert captured["kwargs"].get("shell") is not True
        # L'adresse et l'utilisateur doivent apparaître comme des ÉLÉMENTS de
        # liste distincts, jamais interpolés dans une seule chaîne shell.
        joined = " ".join(captured["cmd"])
        assert _ADRESSE_DOC_TEST in joined
        assert "BatchMode=yes" in joined
        assert "StrictHostKeyChecking=accept-new" in joined

    def test_timeout_utilise_le_parametre_fourni_pas_une_valeur_en_dur(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            captured["timeout_kwarg"] = kwargs.get("timeout")
            captured["cmd"] = cmd
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=_IP_LINK_SHOW_OUTPUT, stderr=""
            )

        monkeypatch.setattr(subprocess, "run", _fake_run)

        exporters_service.resolve_interface_table_ssh(
            address=_ADRESSE_DOC_TEST, ssh_user="root", timeout_seconds=7.5
        )

        assert captured["timeout_kwarg"] == 7.5
        joined = " ".join(captured["cmd"])
        assert "ConnectTimeout=" in joined

    def test_utilisateur_ssh_configurable_apparait_dans_la_commande(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            captured["cmd"] = cmd
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=_IP_LINK_SHOW_OUTPUT, stderr=""
            )

        monkeypatch.setattr(subprocess, "run", _fake_run)

        exporters_service.resolve_interface_table_ssh(
            address=_ADRESSE_DOC_TEST, ssh_user="mon-user-ssh", timeout_seconds=2.0
        )

        joined = " ".join(captured["cmd"])
        assert f"mon-user-ssh@{_ADRESSE_DOC_TEST}" in joined

    def test_meme_forme_de_retour_que_la_resolution_snmp(self) -> None:
        """Interchangeabilité : le type de retour DOIT être `InterfaceTableResult`
        (le même modèle que `snmp_inventory.resolve_interface_table`), pour que
        le câblage aval (`build_if_indexes_from_snmp`, `stage_change`) marche
        sans distinction de source."""
        from app.services.snmp_inventory import InterfaceTableResult

        result = exporters_service.resolve_interface_table_ssh(
            address="pas-une-ip", ssh_user="root", timeout_seconds=2.0
        )
        assert isinstance(result, InterfaceTableResult)


class TestSourceDistincteSnmpVsSsh:
    """L'écran doit dire QUELLE source a résolu — sinon un succès SSH se lit
    comme un succès SNMP et masque que l'agent SNMP est absent."""

    def test_resolve_interface_table_ssh_porte_lorigine_ssh(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=_IP_LINK_SHOW_OUTPUT, stderr=""
            )

        monkeypatch.setattr(subprocess, "run", _fake_run)

        result = exporters_service.resolve_interface_table_ssh(
            address=_ADRESSE_DOC_TEST, ssh_user="root", timeout_seconds=2.0
        )
        # `source_oid` est le champ existant du modèle SNMP pour dire d'où
        # vient la table (ifName/ifDescr) ; côté SSH il porte la commande.
        assert result.source_oid is not None
        assert "ip" in result.source_oid


# ---------------------------------------------------------------------------
# Configuration — activable, défaut qui ne dégrade pas la cible entreprise.
# ---------------------------------------------------------------------------


class TestConfigurationSsh:
    def test_ssh_fallback_desactive_par_defaut(self) -> None:
        """SNMP reste la voie PRINCIPALE : le repli SSH ne doit PAS s'activer
        tout seul sur un déploiement entreprise fraîchement installé, où SNMP
        répond normalement (Palo Alto, routeurs SFR)."""
        from app.config import Settings

        fresh_settings = Settings(_env_file=None)
        assert fresh_settings.ssh_ifindex_fallback_enabled is False

    def test_ssh_ifindex_user_configurable(self) -> None:
        from app.config import Settings

        fresh_settings = Settings(_env_file=None)
        assert isinstance(fresh_settings.ssh_ifindex_user, str)
        assert fresh_settings.ssh_ifindex_user  # jamais vide : un défaut existe

    def test_ssh_ifindex_timeout_configurable(self) -> None:
        from app.config import Settings

        fresh_settings = Settings(_env_file=None)
        assert fresh_settings.ssh_ifindex_timeout_seconds > 0


# ---------------------------------------------------------------------------
# Anti-secret — même garde que test_snmp_ifindex_resolution.py : aucun mot de
# passe / token ne doit fuiter dans les logs de ce module (SSH par clé n'a de
# toute façon pas de secret texte à protéger, mais la commande elle-même ne
# doit jamais être loguée avec des données sensibles si un jour un mot de
# passe SSH est introduit).
# ---------------------------------------------------------------------------


def test_aucune_trace_de_mot_de_passe_en_dur_dans_le_module_source() -> None:
    source = (APP_DIR / "services" / "exporters.py").read_text(encoding="utf-8")
    lignes_suspectes = [
        ligne
        for ligne in source.splitlines()
        if ("password" in ligne.lower() or "passwd" in ligne.lower())
        and not ligne.strip().startswith(("#", '"""', "'''"))
    ]
    assert not lignes_suspectes, f"mot de passe potentiel en dur : {lignes_suspectes}"


# ---------------------------------------------------------------------------
# JONCTION MANQUANTE (signalée par le coordinateur, 2026-08-11) : le filtre
# `filtrer_interfaces_exploitables` (livré par l'autre agent, testé isolément,
# 20 tests verts) n'est appelé NULLE PART dans le câblage réel des routes.
# `OKVORADO_INTERFACE_EXCLUDE_PATTERNS` est donc une PROMESSE CREUSE tant que
# les routes `/exporters/{address}/resolve-snmp` et `/exporters/resolve-snmp-all`
# ne l'appliquent pas AVANT `build_if_indexes_from_snmp`, quelle que soit la
# source (SNMP ou repli SSH — un seul point de jonction, cf. plus bas).
#
# CAS RÉEL (rapporté par le coordinateur) : `docker-takas` (192.0.2.7)
# déclare 40 interfaces dont 37 sont des `veth*`/`br-*`/`docker0` sans valeur
# NetFlow. Sans ce câblage, TOUTES les 40 seraient mises en file d'attente.
# ---------------------------------------------------------------------------


import sqlite3  # noqa: E402 - regroupé avec les imports propres à cette section
from collections.abc import Generator  # noqa: E402

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import init_database  # noqa: E402
from app.models import (  # noqa: E402
    Boundary,
    DeclaredExporter,
    ExporterHealth,
    ExporterStatus,
    InterfaceSpec,
    ObservedExporter,
)
from app.services import snmp_inventory  # noqa: E402

#: Table réaliste : 3 interfaces UTILES + 37 `veth*` bruyantes — reproduit
#: EXACTEMENT le cas mesuré sur docker-takas (192.0.2.7, cf. ci-dessus).
_TABLE_DOCKER_TAKAS: dict[int, str] = {
    1: "lo",
    2: "eth0",
    3: "tailscale0",
    **{100 + i: f"veth{i:02d}abcd" for i in range(37)},
}


@pytest.fixture
def db_path_jonction(tmp_path: Path) -> str:
    path = str(tmp_path / "test_jonction.db")
    init_database(path)
    return path


@pytest.fixture
def db_conn_jonction(db_path_jonction: str) -> Generator[sqlite3.Connection]:
    connection = sqlite3.connect(db_path_jonction, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def _declared_docker_takas() -> DeclaredExporter:
    return DeclaredExporter(
        cidr="192.0.2.7/32",
        name="docker-takas",
        if_indexes={
            2: InterfaceSpec(if_index=2, name="eth0", boundary=Boundary.EXTERNAL),
        },
        default=InterfaceSpec(if_index=0, name="unknown"),
        is_catchall=False,
    )


def _status_docker_takas() -> ExporterStatus:
    return ExporterStatus(
        address="192.0.2.7",
        name="docker-takas",
        health=ExporterHealth.UNKNOWN_INTERFACE,
        declared=_declared_docker_takas(),
        observed=ObservedExporter(
            address="192.0.2.7",
            name="docker-takas",
            flows=1000,
            bytes=100000,
            interfaces=["unknown", "eth0"],
        ),
        forwarded_total=1000,
        rejected_total=0,
        explanation="interface inconnue",
    )


def _make_test_app_jonction() -> FastAPI:
    from app.routers import exporters as exporters_router
    from app.templating import build_templates

    test_app = FastAPI()
    test_app.state.templates = build_templates()
    test_app.include_router(exporters_router.router)
    return test_app


def _make_test_app_with_db_jonction(conn: sqlite3.Connection) -> FastAPI:
    from app.routers import exporters as exporters_router

    test_app = _make_test_app_jonction()
    test_app.dependency_overrides[exporters_router.get_db_connection] = lambda: conn
    return test_app


class TestFiltrageCableSurLaResolutionSnmp:
    """`POST /exporters/{address}/resolve-snmp` doit appliquer
    `filtrer_interfaces_exploitables` AVANT de mettre en file d'attente."""

    def test_les_interfaces_bruyantes_ne_sont_pas_mises_en_file(
        self, db_conn_jonction: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router
        from app.services.config_writer import list_pending_changes

        monkeypatch.setattr(app_settings, "snmp_community", "s3cr3t-jonction")

        def _fake_walk(*_args: Any, **_kwargs: Any) -> dict[int, str]:
            return dict(_TABLE_DOCKER_TAKAS)

        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk)

        async def _fake_statuses(_window: str) -> list[Any]:
            return [_status_docker_takas()]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db_jonction(db_conn_jonction))
        response = client.post("/exporters/192.0.2.7/resolve-snmp")
        assert response.status_code == 200

        pending = list_pending_changes(db_conn_jonction)
        assert len(pending) == 1
        indexes = {int(key) for key in pending[0].payload["if_indexes"]}
        # `lo` (1) et les 37 `veth*` (100..136) DOIVENT être écartés par le
        # filtre par défaut (OKVORADO_INTERFACE_EXCLUDE_PATTERNS =
        # "lo,docker0,br-*,veth*") : seuls eth0 (2) et tailscale0 (3) doivent
        # atteindre la file d'attente. C'EST le test qui échoue tant que le
        # filtre n'est pas câblé — SANS lui, les 40 index atteindraient
        # `pending`.
        assert indexes == {2, 3}, (
            f"les interfaces bruyantes n'ont pas été filtrées avant mise en "
            f"file d'attente (indexes obtenus : {sorted(indexes)}) — le "
            f"filtrage n'est probablement pas câblé sur ce chemin"
        )

    def test_une_interface_deja_declaree_nest_jamais_ecartee(
        self, db_conn_jonction: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PRÉSERVATION D'UNE DÉCISION D'EXPLOITANT : si `docker0` est déjà
        déclaré à la main (cas d'un exploitant qui veut le mesurer), le
        filtre ne doit PAS l'effacer — `declared_names` doit être transmis."""
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router
        from app.services.config_writer import list_pending_changes

        monkeypatch.setattr(app_settings, "snmp_community", "s3cr3t-jonction")

        table = {1: "lo", 2: "eth0", 3: "tailscale0", 9: "docker0"}

        def _fake_walk(*_args: Any, **_kwargs: Any) -> dict[int, str]:
            return dict(table)

        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk)

        declared = DeclaredExporter(
            cidr="192.0.2.7/32",
            name="docker-takas",
            if_indexes={
                2: InterfaceSpec(if_index=2, name="eth0"),
                9: InterfaceSpec(if_index=9, name="docker0", boundary=Boundary.INTERNAL),
            },
            default=InterfaceSpec(if_index=0, name="unknown"),
            is_catchall=False,
        )
        status = ExporterStatus(
            address="192.0.2.7",
            name="docker-takas",
            health=ExporterHealth.UNKNOWN_INTERFACE,
            declared=declared,
            observed=ObservedExporter(
                address="192.0.2.7",
                name="docker-takas",
                flows=10,
                bytes=100,
                interfaces=["unknown"],
            ),
            forwarded_total=10,
            rejected_total=0,
            explanation="interface inconnue",
        )

        async def _fake_statuses(_window: str) -> list[Any]:
            return [status]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db_jonction(db_conn_jonction))
        response = client.post("/exporters/192.0.2.7/resolve-snmp")
        assert response.status_code == 200

        pending = list_pending_changes(db_conn_jonction)
        assert len(pending) == 1
        indexes = {int(key) for key in pending[0].payload["if_indexes"]}
        # docker0 (9) est DÉJÀ déclaré : il doit survivre au filtre malgré le
        # motif "docker0" dans les exclusions par défaut. lo (1) doit
        # disparaître (jamais déclaré, matche le motif "lo").
        assert 9 in indexes, "docker0 déjà déclaré a été effacé par le filtre"
        assert 1 not in indexes, "lo (non déclaré) aurait dû être filtré"


class TestFiltrageCableSurLeRepliSsh:
    """Le filtrage doit s'appliquer QUELLE QUE SOIT la source : le repli SSH
    emprunte le MÊME point de jonction (`_stage_resolved_if_indexes`) que
    SNMP, donc un seul câblage doit couvrir les deux chemins."""

    def test_repli_ssh_filtre_aussi_les_interfaces_bruyantes(
        self, db_conn_jonction: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router
        from app.services.config_writer import list_pending_changes

        # SNMP configuré mais MUET (no_response) -> déclenche le repli SSH.
        monkeypatch.setattr(app_settings, "snmp_community", "s3cr3t-jonction")
        monkeypatch.setattr(app_settings, "ssh_ifindex_fallback_enabled", True)
        monkeypatch.setattr(app_settings, "ssh_ifindex_user", "root")
        monkeypatch.setattr(app_settings, "ssh_ifindex_timeout_seconds", 2.0)

        def _fake_walk_muet(*_args: Any, **_kwargs: Any) -> None:
            return None

        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk_muet)

        def _fake_ssh_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout=_IP_LINK_SHOW_OUTPUT, stderr=""
            )

        monkeypatch.setattr(subprocess, "run", _fake_ssh_run)

        status = _status_docker_takas()
        # Redéclare eth0 seulement, pour vérifier que tailscale0 (voulu) passe
        # et que lo (bruit) est filtré, même en provenance de SSH.
        async def _fake_statuses(_window: str) -> list[Any]:
            return [status]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db_jonction(db_conn_jonction))
        response = client.post("/exporters/192.0.2.7/resolve-snmp")
        assert response.status_code == 200

        pending = list_pending_changes(db_conn_jonction)
        assert len(pending) == 1
        indexes = {int(key) for key in pending[0].payload["if_indexes"]}
        # `_IP_LINK_SHOW_OUTPUT` = lo(1), eth0(2), tailscale0(3) : lo doit
        # être filtré même si la table vient de SSH, pas de SNMP.
        assert 1 not in indexes, "lo aurait dû être filtré sur le chemin SSH aussi"
        assert indexes == {2, 3}


class TestEcartementRestitueALEcran:
    """`InterfaceFiltrageResult` porte le décompte précisément pour être
    affiché — sinon le filtrage devient lui-même un zéro silencieux."""

    def test_le_fragment_dit_combien_ont_ete_ecartees(
        self, db_conn_jonction: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router

        monkeypatch.setattr(app_settings, "snmp_community", "s3cr3t-jonction")

        def _fake_walk(*_args: Any, **_kwargs: Any) -> dict[int, str]:
            return dict(_TABLE_DOCKER_TAKAS)

        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk)

        async def _fake_statuses(_window: str) -> list[Any]:
            return [_status_docker_takas()]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db_jonction(db_conn_jonction))
        response = client.post("/exporters/192.0.2.7/resolve-snmp")
        assert response.status_code == 200
        html = response.text
        # 40 interfaces vues, 38 écartées (lo + 37 veth*), 2 retenues
        # (eth0 + tailscale0). Le chiffre exact importe moins que le fait
        # qu'un décompte d'écartement soit VISIBLE dans le rendu.
        assert "38" in html or "écart" in html.lower(), (
            "le fragment ne restitue pas le nombre d'interfaces écartées par "
            "le filtre — zéro silencieux : l'exploitant ne peut pas savoir "
            "que des interfaces ont été retirées de la résolution"
        )


class TestToutEcarteEstUnSignalDalarme:
    """Si le filtre ne laisse RIEN, c'est une alarme — pas un résultat à
    mettre en file d'attente silencieusement."""

    def test_rien_nest_mis_en_file_si_tout_est_ecarte(
        self, db_conn_jonction: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.config import settings as app_settings
        from app.routers import exporters as exporters_router
        from app.services.config_writer import list_pending_changes

        monkeypatch.setattr(app_settings, "snmp_community", "s3cr3t-jonction")

        # Table où TOUT matche un motif d'exclusion par défaut.
        table_tout_bruit = {1: "lo", 2: "docker0", 3: "veth1234abc"}

        def _fake_walk(*_args: Any, **_kwargs: Any) -> dict[int, str]:
            return dict(table_tout_bruit)

        monkeypatch.setattr(snmp_inventory, "_snmp_walk_interfaces", _fake_walk)

        # Aucune interface pré-déclarée parmi lo/docker0/veth1234abc : rien
        # ne doit survivre au filtre.
        declared = DeclaredExporter(
            cidr="192.0.2.7/32",
            name="docker-takas",
            if_indexes={99: InterfaceSpec(if_index=99, name="ancienne-interface")},
            default=InterfaceSpec(if_index=0, name="unknown"),
            is_catchall=False,
        )
        status = ExporterStatus(
            address="192.0.2.7",
            name="docker-takas",
            health=ExporterHealth.UNKNOWN_INTERFACE,
            declared=declared,
            observed=ObservedExporter(
                address="192.0.2.7",
                name="docker-takas",
                flows=10,
                bytes=100,
                interfaces=["unknown"],
            ),
            forwarded_total=10,
            rejected_total=0,
            explanation="interface inconnue",
        )

        async def _fake_statuses(_window: str) -> list[Any]:
            return [status]

        monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_statuses)

        client = TestClient(_make_test_app_with_db_jonction(db_conn_jonction))
        response = client.post("/exporters/192.0.2.7/resolve-snmp")
        # 422, comme tout chemin d'erreur de cette route (cf. `_error_fragment`) :
        # un signal d'alarme n'est pas un succès, htmx doit tout de même swapper
        # le fragment (jamais un 500 nu — mais pas un 200 non plus, ce n'est pas
        # une réussite).
        assert response.status_code == 422

        pending = list_pending_changes(db_conn_jonction)
        assert pending == [], (
            "rien ne doit être mis en file d'attente quand le filtre écarte "
            "TOUTES les interfaces vues — sinon on efface silencieusement la "
            "configuration existante de l'exportateur"
        )
        # Le signal d'alarme doit être VISIBLE, pas juste absent de la DB.
        html = response.text
        assert "notice-error" in html or "notice-warn" in html, (
            "aucun signal d'alarme visible quand toutes les interfaces ont "
            "été écartées par le filtre"
        )
