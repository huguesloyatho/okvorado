"""Tests du module Inventaire SNMP (MIB-II système par exportateur).

Aucun test ici n'exige d'agent SNMP réel : la fonction de sondage bas niveau
(`_snmp_get_scalars`) est injectée/mockée, jamais appelée pour de vrai. Ce
qui est prouvé ici est l'INTENTION du module :
  - la communauté SNMP n'apparaît jamais en clair (ni rendu HTML, ni logs) ;
  - un agent muet produit un état DISTINCT ('no_response'), jamais des champs
    vides confondus avec un équipement sans nom (zéro silencieux) ;
  - `sysUpTime` (centièmes de seconde) est converti en durée lisible ;
  - aucune commande shell n'est construite (shell=True interdit, jamais de
    concaténation) — ce module n'utilise d'ailleurs AUCUN sous-processus ;
  - la page /inventory est atteignable depuis le menu.

⚠️ Les assertions anti-secret EXCLUENT les commentaires/docstrings du code
source : un motif interdit documenté dans un commentaire ne doit jamais faire
échouer son propre test (piège vécu 9 fois, cf. consigne de la tâche).
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
from app.services import snmp_inventory

APP_DIR = Path(__file__).parent.parent / "app"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    path = str(tmp_path / "test.db")
    init_database(path)
    return path


@pytest.fixture
def db_conn(db_path: str) -> Generator[sqlite3.Connection]:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


_FAKE_COMMUNITY = "s3cr3t-community-value"


def _fake_scalars_ok(*_args: Any, **_kwargs: Any) -> dict[str, str | int]:
    return {
        "sys_name": "routeur-test-01",
        "sys_descr": "Linux routeur-agence-02 6.12.94+deb13-amd64",
        "sys_location": "Salle-Test-Okvorado",
        "sys_contact": "exploitation@example.org",
        "sys_uptime_ticks": 6335745,
    }


def _fake_scalars_timeout(*_args: Any, **_kwargs: Any) -> None:
    return None


# ---------------------------------------------------------------------------
# 1. Conversion sysUpTime -> durée lisible
# ---------------------------------------------------------------------------


def test_format_uptime_valeur_capture_reference() -> None:
    """80 jours, 9 heures, 3 minutes, 30 secondes -> centièmes de seconde."""
    total_seconds = 80 * 86400 + 9 * 3600 + 3 * 60 + 30
    ticks = total_seconds * 100
    formatted = snmp_inventory.format_uptime(ticks)
    assert "80 day" in formatted or "80 j" in formatted
    assert "9 h" in formatted or "9 hour" in formatted


def test_format_uptime_zero() -> None:
    """Zéro n'est pas un échec silencieux : c'est une durée valide affichable."""
    formatted = snmp_inventory.format_uptime(0)
    assert formatted != ""
    assert "0" in formatted


def test_format_uptime_tres_grand() -> None:
    """Une valeur proche du plafond 32 bits ne doit ni planter ni déborder n'importe comment."""
    max_uint32_ticks = 2**32 - 1
    formatted = snmp_inventory.format_uptime(max_uint32_ticks)
    assert formatted != ""
    assert isinstance(formatted, str)


def test_format_uptime_negatif_ne_leve_pas() -> None:
    """Valeur invalide (négative) : dégrade en repli visible, ne lève jamais."""
    formatted = snmp_inventory.format_uptime(-1)
    assert formatted != ""


def test_format_uptime_moins_dune_minute() -> None:
    formatted = snmp_inventory.format_uptime(4555)  # 45.55s
    assert formatted != ""


# ---------------------------------------------------------------------------
# 2. Zéro silencieux — agent muet
# ---------------------------------------------------------------------------


def test_agent_muet_produit_un_etat_distinct(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un agent qui ne répond pas doit stocker status='no_response', jamais
    des champs sys_* vides qu'on confondrait avec un équipement sans nom."""
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_timeout)

    result = snmp_inventory.collect_one(db_conn, address="172.30.0.99", community="public")

    assert result.status == "no_response"
    row = db_conn.execute(
        "SELECT status, sys_name FROM snmp_inventory WHERE address = ?", ("172.30.0.99",)
    ).fetchone()
    assert row["status"] == "no_response"
    # Le nom n'est PAS une chaîne vide silencieuse : soit NULL, soit absent —
    # jamais "" qui se lirait comme un équipement réellement sans nom.
    assert row["sys_name"] != ""


def test_agent_muet_ne_confond_pas_avec_un_nom_vide_legitime(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Piège déjà rencontré ici : un nom de repli pris pour un nom légitime.

    `collect_one` ne doit JAMAIS écrire une chaîne de repli (ex. l'adresse IP,
    ou "inconnu") dans `sys_name` en cas d'échec — le statut 'no_response'
    porte à lui seul cette information, `sys_name` doit rester NULL.
    """
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_timeout)
    snmp_inventory.collect_one(db_conn, address="172.30.0.99", community="public")
    row = db_conn.execute(
        "SELECT sys_name FROM snmp_inventory WHERE address = ?", ("172.30.0.99",)
    ).fetchone()
    assert row["sys_name"] is None


def test_collecte_reussie_stocke_les_valeurs_reelles(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_ok)

    result = snmp_inventory.collect_one(db_conn, address="172.30.0.1", community="public")

    assert result.status == "ok"
    assert result.sys_name == "routeur-test-01"
    assert result.sys_location == "Salle-Test-Okvorado"
    row = db_conn.execute(
        "SELECT * FROM snmp_inventory WHERE address = ?", ("172.30.0.1",)
    ).fetchone()
    assert row["sys_name"] == "routeur-test-01"
    assert row["status"] == "ok"
    assert row["last_success_at"] is not None


def test_premiere_decouverte_et_derniere_collecte_distinctes(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`first_seen_at` ne doit pas bouger entre deux collectes successives,
    contrairement à `last_attempt_at` — sinon on perd la date de première
    découverte ('Device added time' de la capture ManageEngine)."""
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_ok)
    snmp_inventory.collect_one(db_conn, address="172.30.0.1", community="public")
    first_row = db_conn.execute(
        "SELECT first_seen_at FROM snmp_inventory WHERE address = ?", ("172.30.0.1",)
    ).fetchone()

    snmp_inventory.collect_one(db_conn, address="172.30.0.1", community="public")
    second_row = db_conn.execute(
        "SELECT first_seen_at FROM snmp_inventory WHERE address = ?", ("172.30.0.1",)
    ).fetchone()

    assert first_row["first_seen_at"] == second_row["first_seen_at"]


def test_status_repasse_a_ok_apres_une_panne_temporaire(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Une collecte réussie APRÈS un échec doit remettre status='ok' — pas de
    'no_response' figé qui masquerait le retour en service."""
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_timeout)
    snmp_inventory.collect_one(db_conn, address="172.30.0.1", community="public")

    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_ok)
    snmp_inventory.collect_one(db_conn, address="172.30.0.1", community="public")

    row = db_conn.execute(
        "SELECT status FROM snmp_inventory WHERE address = ?", ("172.30.0.1",)
    ).fetchone()
    assert row["status"] == "ok"


def test_collecte_sans_communaute_configuree_est_un_echec_visible(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Communauté vide (non configurée) : refus explicite, pas un sondage
    silencieux avec une communauté vide envoyée sur le réseau."""

    def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("_snmp_get_scalars ne doit pas etre appelee sans communaute")

    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _boom)
    result = snmp_inventory.collect_one(db_conn, address="172.30.0.1", community="")
    assert result.status == "no_response"


# ---------------------------------------------------------------------------
# 3. La communauté n'apparaît jamais en clair
# ---------------------------------------------------------------------------


def test_communaute_absente_du_rendu_liste_items(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_ok)
    snmp_inventory.collect_one(db_conn, address="172.30.0.1", community=_FAKE_COMMUNITY)

    items = snmp_inventory.list_inventory(db_conn)
    rendered = repr([item.model_dump() for item in items])
    assert _FAKE_COMMUNITY not in rendered


def test_communaute_absente_des_logs(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Ni succès ni échec ne doivent journaliser la communauté en clair."""
    caplog.set_level(logging.DEBUG)

    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_ok)
    snmp_inventory.collect_one(db_conn, address="172.30.0.1", community=_FAKE_COMMUNITY)

    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_timeout)
    snmp_inventory.collect_one(db_conn, address="172.30.0.2", community=_FAKE_COMMUNITY)

    assert _FAKE_COMMUNITY not in caplog.text


def test_communaute_absente_du_html_page_inventaire(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bout-en-bout HTTP : la page /inventory ne doit jamais exposer la
    communauté configurée, y compris via app.config.settings."""
    from app import config as config_module

    monkeypatch.setattr(config_module.settings, "snmp_community", _FAKE_COMMUNITY)

    from app.routers import inventory as inventory_router

    app = FastAPI()
    app.include_router(inventory_router.router)

    tmp_conn = sqlite3.connect(":memory:")
    tmp_conn.row_factory = sqlite3.Row
    tmp_conn.executescript(
        "CREATE TABLE snmp_inventory ("
        "address TEXT PRIMARY KEY, sys_name TEXT, sys_descr TEXT, sys_location TEXT, "
        "sys_contact TEXT, sys_uptime_ticks INTEGER, status TEXT NOT NULL DEFAULT 'no_response', "
        "first_seen_at TEXT NOT NULL DEFAULT (datetime('now')), "
        "last_attempt_at TEXT NOT NULL DEFAULT (datetime('now')), last_success_at TEXT, "
        "snmp_version TEXT NOT NULL DEFAULT 'v2c')"
    )

    def _override_db() -> sqlite3.Connection:
        return tmp_conn

    app.dependency_overrides[inventory_router.get_db_connection] = _override_db

    client = TestClient(app)
    response = client.get("/inventory")
    assert response.status_code == 200
    assert _FAKE_COMMUNITY not in response.text


def test_collecte_bout_en_bout_ne_leve_pas_dans_la_boucle_evenements(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """RÉGRESSION (mesuré en prod .7, 2026-08-08) : `POST /inventory/collect`
    appelait `collect_all` (synchrone, `asyncio.run()` interne) directement
    depuis une route `async def` déjà exécutée dans la boucle événements
    d'uvicorn -> `RuntimeError: asyncio.run() cannot be called from a running
    event loop`. Résultat observé à l'écran : TOUT agent, y compris un agent
    qui répond réellement, retombait en 'no_response' — un zéro silencieux
    côté utilisateur (le message affiché ne distinguait pas "agent muet" de
    "bug interne"). `TestClient` exécute un VRAI event loop (contrairement à
    un appel direct de fonction en test unitaire, qui ne l'aurait pas
    détecté) : ce test aurait échoué avant le fix (`asyncio.to_thread`)."""
    from app import config as config_module

    monkeypatch.setattr(config_module.settings, "snmp_community", "public")
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_ok)

    from app.routers import exporters as exporters_router
    from app.routers import inventory as inventory_router

    async def _fake_load_exporter_statuses(_window: str) -> list[Any]:
        return []

    monkeypatch.setattr(exporters_router, "load_exporter_statuses", _fake_load_exporter_statuses)

    app = FastAPI()
    app.include_router(inventory_router.router)

    # `check_same_thread=False` : `collect_one` est déportée dans un thread
    # via `asyncio.to_thread` (cf. app/routers/inventory.py) — même contrainte
    # que `_open_db` dans app/main.py (la connexion réelle en prod). Un fichier
    # (pas `:memory:`, qui est PAR CONNEXION et ne serait pas partagé entre
    # threads) pour que le thread de la requête et celui de l'assertion voient
    # la même base.
    db_file = tmp_path_factory.mktemp("snmp-e2e") / "test.db"
    tmp_conn = sqlite3.connect(str(db_file), check_same_thread=False)
    tmp_conn.row_factory = sqlite3.Row
    tmp_conn.executescript(
        "CREATE TABLE snmp_inventory ("
        "address TEXT PRIMARY KEY, sys_name TEXT, sys_descr TEXT, sys_location TEXT, "
        "sys_contact TEXT, sys_uptime_ticks INTEGER, status TEXT NOT NULL DEFAULT 'no_response', "
        "first_seen_at TEXT NOT NULL DEFAULT (datetime('now')), "
        "last_attempt_at TEXT NOT NULL DEFAULT (datetime('now')), last_success_at TEXT, "
        "snmp_version TEXT NOT NULL DEFAULT 'v2c')"
    )
    app.dependency_overrides[inventory_router.get_db_connection] = lambda: tmp_conn

    client = TestClient(app)
    response = client.post("/inventory/172.30.0.1/collect")
    assert response.status_code == 200
    assert "routeur-test-01" in response.text
    assert "asyncio.run" not in response.text


# ---------------------------------------------------------------------------
# 4. Aucune commande construite avec shell=True ni par concaténation shell
# ---------------------------------------------------------------------------


def _strip_comments_and_docstrings(source: str) -> str:
    """Retire commentaires `#...` et docstrings triple-guillemets, pour que
    la documentation d'un piège ÉVITÉ ne fasse pas échouer le test qui vérifie
    qu'il est bien évité (piège vécu 9 fois sur ce projet)."""
    without_triple_double = re.sub(r'""".*?"""', "", source, flags=re.DOTALL)
    without_triple_single = re.sub(r"'''.*?'''", "", without_triple_double, flags=re.DOTALL)
    lines = []
    for line in without_triple_single.splitlines():
        code_part = line.split("#", 1)[0]
        lines.append(code_part)
    return "\n".join(lines)


def test_aucun_shell_true_ni_sous_processus_dans_le_module_snmp() -> None:
    """Ce module n'utilise aucun sous-processus (pysnmp est pur Python) : ni
    `shell=True`, ni `subprocess`, ni construction de commande par
    concaténation de chaîne — vérifié sur le CODE, pas sur les commentaires."""
    source = (APP_DIR / "services" / "snmp_inventory.py").read_text(encoding="utf-8")
    code_only = _strip_comments_and_docstrings(source)
    assert "shell=True" not in code_only
    assert "subprocess" not in code_only
    assert "os.system" not in code_only


def test_aucun_shell_true_dans_le_routeur_inventaire() -> None:
    source = (APP_DIR / "routers" / "inventory.py").read_text(encoding="utf-8")
    code_only = _strip_comments_and_docstrings(source)
    assert "shell=True" not in code_only
    assert "subprocess" not in code_only


# ---------------------------------------------------------------------------
# 5. L'adresse interrogée vient de la liste des exportateurs connus
# ---------------------------------------------------------------------------


def test_collecte_globale_ne_prend_les_adresses_que_des_exportateurs_connus(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`collect_all` doit recevoir la liste d'adresses en paramètre (fournie
    par l'appelant à partir des exportateurs observés/déclarés) plutôt que de
    la construire elle-même depuis une saisie libre."""
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_ok)

    known_addresses = ["172.30.0.1", "172.30.0.2"]
    results = snmp_inventory.collect_all(db_conn, addresses=known_addresses, community="public")
    assert {r.address for r in results} == set(known_addresses)


# ---------------------------------------------------------------------------
# 5bis. SNMPv3 — construction USM, distinction auth_failure, coexistence v2c/v3
#
# SECRET_OK: les deux constantes ci-dessous sont des placeholders de test
# (jamais des secrets réels), même pattern que _FAKE_COMMUNITY plus haut dans
# ce fichier — servent à prouver l'absence de fuite dans logs/repr, pas des
# valeurs de production.
# ---------------------------------------------------------------------------

_FAKE_V3_AUTH_PASSWORD = "s3cr3t-auth-password-value"
_FAKE_V3_PRIV_PASSWORD = "s3cr3t-priv-password-value"


def _fake_v3_credentials(security_level: str) -> snmp_inventory.SnmpV3Credentials:
    return snmp_inventory.SnmpV3Credentials(
        username="okvorado-ro",
        security_level=security_level,
        auth_protocol="SHA256" if security_level != "noAuthNoPriv" else None,
        auth_password=_FAKE_V3_AUTH_PASSWORD if security_level != "noAuthNoPriv" else None,
        priv_protocol="AES256" if security_level == "authPriv" else None,
        priv_password=_FAKE_V3_PRIV_PASSWORD if security_level == "authPriv" else None,
    )


def test_build_usm_user_data_noauthnopriv() -> None:
    creds = _fake_v3_credentials("noAuthNoPriv")
    usm = snmp_inventory._build_usm_user_data(creds)
    assert str(usm.userName) == "okvorado-ro"
    assert usm.authentication_key is None
    assert usm.privacy_key is None


def test_build_usm_user_data_authnopriv() -> None:
    creds = _fake_v3_credentials("authNoPriv")
    usm = snmp_inventory._build_usm_user_data(creds)
    assert str(usm.userName) == "okvorado-ro"
    assert usm.authentication_key is not None
    assert usm.privacy_key is None


def test_build_usm_user_data_authpriv() -> None:
    creds = _fake_v3_credentials("authPriv")
    usm = snmp_inventory._build_usm_user_data(creds)
    assert str(usm.userName) == "okvorado-ro"
    assert usm.authentication_key is not None
    assert usm.privacy_key is not None


def test_build_usm_user_data_authpriv_sans_priv_protocol_leve_value_error() -> None:
    """`authPriv` sans `priv_protocol` : ValueError explicite, JAMAIS un
    repli silencieux vers noPriv (consigne de la tâche)."""
    creds = snmp_inventory.SnmpV3Credentials(
        username="okvorado-ro",
        security_level="authPriv",
        auth_protocol="SHA256",
        auth_password=_FAKE_V3_AUTH_PASSWORD,
        priv_protocol=None,
        priv_password=None,
    )
    with pytest.raises(ValueError, match="priv_protocol"):
        snmp_inventory._build_usm_user_data(creds)


def test_build_usm_user_data_protocole_non_supporte_leve_value_error() -> None:
    creds = snmp_inventory.SnmpV3Credentials(
        username="okvorado-ro",
        security_level="authNoPriv",
        auth_protocol="MD2",  # protocole inexistant côté pysnmp
        auth_password=_FAKE_V3_AUTH_PASSWORD,
    )
    with pytest.raises(ValueError, match="auth_protocol"):
        snmp_inventory._build_usm_user_data(creds)


def test_cryptography_disponible_pour_le_chiffrement_snmpv3(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GARDE-FOU root cause (mesuré 2026-08-08 contre un agent SNMP réel) :
    `pysnmp` ne déclare AUCUN backend de chiffrement comme dépendance
    obligatoire — `cryptography` n'apparaît que dans son extra `dev`
    (`pyproject.toml` de pysnmp). Sans lui installé dans l'environnement
    d'exécution, tout sondage SNMPv3 `authPriv` échoue avec un
    `error_indication` de classe `EncryptionError` ("Ciphering services not
    available"), qui n'est PAS dans `_AUTHENTICATION_FAILURE_INDICATIONS` et
    dégrade donc en `status='no_response'` — un paquet Python manquant se
    fait passer pour une panne réseau/agent (zéro silencieux, CLAUDE.md #2).

    Ce test vérifie la STRUCTURE (le module de chiffrement AES de pysnmp voit
    bien `cryptography` importable), pas le comportement réseau : il aurait
    fait échouer le run AVANT tout agent réel, sans mock ni sondage.
    `PysnmpCryptoError` est le flag interne que pysnmp bascule à `True`
    silencieusement quand l'import `cryptography` échoue — on le lit
    directement plutôt que de supposer sa valeur."""
    # Import de `pysnmp.hlapi.v3arch.asyncio` D'ABORD (même ordre que le
    # module sous test) : importer `...secmod.rfc3826.priv.aes` en premier,
    # seul, casse sur un import circulaire interne à pysnmp
    # (`AbstractAesBlumenthal(aes.Aes)` avant que `aes` soit pleinement
    # initialisé) — mesuré en isolant ce test seul, PAS un défaut du garde-fou.
    import pysnmp.proto.secmod.rfc3826.priv.aes as pysnmp_aes_module
    from pysnmp.hlapi.v3arch.asyncio import UsmUserData  # noqa: F401

    assert pysnmp_aes_module.PysnmpCryptoError is False, (
        "pysnmp ne peut PAS chiffrer (AES) : le paquet 'cryptography' est absent de "
        "l'environnement d'exécution. Tout sondage SNMPv3 authPriv dégraderait "
        "silencieusement en status='no_response'. Corrige en ajoutant 'cryptography' "
        "aux dependencies de pyproject.toml (PAS l'extra dev de pysnmp, non installé "
        "en prod)."
    )

    # Sabotage inline pour prouver que ce garde-fou MORD réellement : si le
    # flag repasse à True (import cryptography en échec), l'assertion
    # ci-dessus doit échouer — vérifié ici sans dépendre d'une vraie
    # désinstallation du paquet (qui casserait les autres tests du run).
    monkeypatch.setattr(pysnmp_aes_module, "PysnmpCryptoError", True)
    with pytest.raises(AssertionError, match="cryptography"):
        assert pysnmp_aes_module.PysnmpCryptoError is False, (
            "pysnmp ne peut PAS chiffrer (AES) : le paquet 'cryptography' est absent de "
            "l'environnement d'exécution."
        )


def test_mot_de_passe_v3_faux_produit_auth_failure_pas_no_response(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CYCLE RED-GREEN documenté dans le rapport : ce test échouait sur le
    code avant l'ajout de `SnmpAuthenticationError`/`status='auth_failure'`
    (AttributeError: pas de `SnmpAuthenticationError`, puis 'no_response' au
    lieu de 'auth_failure' une fois l'exception ajoutée mais avant que
    `collect_one` la capture). Un mauvais mot de passe SNMPv3 doit produire
    un état DISTINCT d'un agent muet — mot de passe faux et agent en panne
    se corrigent différemment (CLAUDE.md règle n°2)."""

    def _boom_auth(*_args: Any, **_kwargs: Any) -> None:
        raise snmp_inventory.SnmpAuthenticationError("authentification SNMPv3 refusee")

    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _boom_auth)

    result = snmp_inventory.collect_one(
        db_conn,
        address="172.30.0.50",
        snmp_version="v3",
        v3_credentials=_fake_v3_credentials("authPriv"),
    )

    assert result.status == "auth_failure"
    assert result.status != "no_response"
    row = db_conn.execute(
        "SELECT status FROM snmp_inventory WHERE address = ?", ("172.30.0.50",)
    ).fetchone()
    assert row["status"] == "auth_failure"


def test_v3_sans_credentials_reste_no_response_pas_auth_failure(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """v3_credentials absents = config Okvorado incomplète, PAS un échec
    d'authentification CONTRE l'agent (jamais contacté) : refus explicite
    avant tout sondage réseau, même pattern que `community` vide en v2c."""

    def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("_snmp_get_scalars ne doit pas etre appelee sans v3_credentials")

    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _boom)

    result = snmp_inventory.collect_one(
        db_conn, address="172.30.0.51", snmp_version="v3", v3_credentials=None
    )
    assert result.status == "no_response"


def test_collecte_reussie_en_v3_persiste_le_statut_ok_et_la_version(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_ok)

    result = snmp_inventory.collect_one(
        db_conn,
        address="172.30.0.52",
        snmp_version="v3",
        v3_credentials=_fake_v3_credentials("authPriv"),
    )

    assert result.status == "ok"
    assert result.snmp_version == "v3"
    row = db_conn.execute(
        "SELECT status, snmp_version FROM snmp_inventory WHERE address = ?", ("172.30.0.52",)
    ).fetchone()
    assert row["status"] == "ok"
    assert row["snmp_version"] == "v3"


def test_collecte_all_gere_deux_adresses_avec_deux_versions_differentes(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Choix de version configurable PAR EXPORTATEUR : deux adresses dans le
    même appel `collect_all`, l'une en v2c (défaut), l'autre en v3 (override)
    — chacune persiste son `snmp_version` correctement en DB."""
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_ok)

    results = snmp_inventory.collect_all(
        db_conn,
        addresses=["172.30.0.60", "172.30.0.61"],
        community="public",
        snmp_version="v2c",
        overrides={"172.30.0.61": ("v3", _fake_v3_credentials("authPriv"))},
    )

    by_address = {r.address: r for r in results}
    assert by_address["172.30.0.60"].snmp_version == "v2c"
    assert by_address["172.30.0.61"].snmp_version == "v3"

    row_v2c = db_conn.execute(
        "SELECT snmp_version FROM snmp_inventory WHERE address = ?", ("172.30.0.60",)
    ).fetchone()
    row_v3 = db_conn.execute(
        "SELECT snmp_version FROM snmp_inventory WHERE address = ?", ("172.30.0.61",)
    ).fetchone()
    assert row_v2c["snmp_version"] == "v2c"
    assert row_v3["snmp_version"] == "v3"


def test_mots_de_passe_v3_absents_des_logs(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Ni un échec d'authentification ni une collecte réussie ne doivent
    journaliser `auth_password`/`priv_password` en clair."""
    caplog.set_level(logging.DEBUG)

    def _boom_auth(*_args: Any, **_kwargs: Any) -> None:
        raise snmp_inventory.SnmpAuthenticationError("authentification SNMPv3 refusee")

    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _boom_auth)
    snmp_inventory.collect_one(
        db_conn,
        address="172.30.0.62",
        snmp_version="v3",
        v3_credentials=_fake_v3_credentials("authPriv"),
    )

    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_ok)
    snmp_inventory.collect_one(
        db_conn,
        address="172.30.0.63",
        snmp_version="v3",
        v3_credentials=_fake_v3_credentials("authPriv"),
    )

    assert _FAKE_V3_AUTH_PASSWORD not in caplog.text
    assert _FAKE_V3_PRIV_PASSWORD not in caplog.text


def test_mots_de_passe_v3_absents_du_repr_inventory_item(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`InventoryItem` ne porte aucun champ mot de passe v3 : son `repr()`/
    `model_dump()` ne peut donc jamais les exposer — preuve directe sur le
    modèle rendu en HTML par le routeur."""
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_ok)
    snmp_inventory.collect_one(
        db_conn,
        address="172.30.0.64",
        snmp_version="v3",
        v3_credentials=_fake_v3_credentials("authPriv"),
    )
    items = snmp_inventory.list_inventory(db_conn)
    rendered = repr([item.model_dump() for item in items])
    assert _FAKE_V3_AUTH_PASSWORD not in rendered
    assert _FAKE_V3_PRIV_PASSWORD not in rendered
    # Garantie structurelle : le modèle Pydantic n'a AUCUN champ mot de passe.
    assert "auth_password" not in snmp_inventory.InventoryItem.model_fields
    assert "priv_password" not in snmp_inventory.InventoryItem.model_fields


# ---------------------------------------------------------------------------
# 6. La page est atteignable depuis le menu (redondant avec test_navigation,
#    mais prouve l'intention au niveau de CE module)
# ---------------------------------------------------------------------------


def test_lien_inventaire_present_dans_le_menu() -> None:
    base_html = (APP_DIR / "templates" / "base.html").read_text(encoding="utf-8")
    nav_match = re.search(r"<nav class=\"nav\">(.*?)</nav>", base_html, re.DOTALL)
    assert nav_match is not None
    assert "/inventory" in nav_match.group(1)


def test_route_inventory_existe_et_rend_une_page_complete() -> None:
    source = (APP_DIR / "routers" / "inventory.py").read_text(encoding="utf-8")
    assert '"/inventory"' in source or "'/inventory'" in source
    template_source = (APP_DIR / "templates" / "inventory.html").read_text(encoding="utf-8")
    assert 'extends "base.html"' in template_source or "extends 'base.html'" in template_source


# ---------------------------------------------------------------------------
# 7. Bascule de version SNMP par équipement, depuis l'écran
#    (POST /inventory/{address}/snmp-version) — routeur, périmètre du LOT C.
# ---------------------------------------------------------------------------


def _build_inventory_test_app(db_path_str: str) -> tuple[FastAPI, sqlite3.Connection]:
    """App FastAPI minimale montant SEULEMENT le router inventory, avec la
    connexion réelle (schéma migré via `init_database`, `check_same_thread`
    False car `collect_one` est déportée dans un thread par
    `asyncio.to_thread` — même contrainte que
    `test_collecte_bout_en_bout_ne_leve_pas_dans_la_boucle_evenements`)."""
    from app.routers import inventory as inventory_router

    app = FastAPI()
    app.include_router(inventory_router.router)
    conn = sqlite3.connect(db_path_str, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    app.dependency_overrides[inventory_router.get_db_connection] = lambda: conn
    return app, conn


def test_bascule_v3_sans_credentials_v3_configures_est_refusee(
    db_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refus explicite (422), jamais une bascule silencieuse : si
    `OKVORADO_SNMP_V3_USERNAME` est vide, la bascule en v3 échoue AVANT tout
    sondage réseau, avec un message qui nomme la cause."""
    from app import config as config_module

    monkeypatch.setattr(config_module.settings, "snmp_v3_username", "")

    app, _conn = _build_inventory_test_app(db_path)
    client = TestClient(app)
    response = client.post("/inventory/172.30.0.70/snmp-version", json={"snmp_version": "v3"})

    assert response.status_code == 422
    assert "non configuré" in response.text


def test_bascule_version_invalide_est_refusee(db_path: str) -> None:
    """Allowlist FERMÉE : une valeur hors {v2c, v3} est un 422, jamais
    propagée telle quelle à `collect_one`."""
    app, _conn = _build_inventory_test_app(db_path)
    client = TestClient(app)
    response = client.post("/inventory/172.30.0.71/snmp-version", json={"snmp_version": "v9999"})

    assert response.status_code == 422


def test_bascule_v3_avec_credentials_configures_relance_une_collecte_immediate(
    db_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bascule v3 réussie : la collecte est relancée DANS LA MÊME REQUÊTE
    (pas seulement mémorisée) — le nouveau statut/version se voient tout de
    suite à l'écran, cf. docstring de `post_set_snmp_version`."""
    from app import config as config_module

    monkeypatch.setattr(config_module.settings, "snmp_v3_username", "monitoring")
    monkeypatch.setattr(config_module.settings, "snmp_v3_security_level", "authPriv")
    monkeypatch.setattr(config_module.settings, "snmp_v3_auth_protocol", "SHA256")
    monkeypatch.setattr(config_module.settings, "snmp_v3_auth_password", _FAKE_V3_AUTH_PASSWORD)
    monkeypatch.setattr(config_module.settings, "snmp_v3_priv_protocol", "AES256")
    monkeypatch.setattr(config_module.settings, "snmp_v3_priv_password", _FAKE_V3_PRIV_PASSWORD)
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_ok)

    app, conn = _build_inventory_test_app(db_path)
    client = TestClient(app)
    response = client.post("/inventory/172.30.0.72/snmp-version", json={"snmp_version": "v3"})

    assert response.status_code == 200
    assert "routeur-test-01" in response.text
    assert "SNMPv3" in response.text
    row = conn.execute(
        "SELECT status, snmp_version FROM snmp_inventory WHERE address = ?", ("172.30.0.72",)
    ).fetchone()
    assert row["status"] == "ok"
    assert row["snmp_version"] == "v3"
    # Zéro secret dans la réponse HTML — même garde que le reste du module.
    assert _FAKE_V3_AUTH_PASSWORD not in response.text
    assert _FAKE_V3_PRIV_PASSWORD not in response.text


def test_bascule_vers_v2c_sans_communaute_configuree_est_refusee(
    db_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Symétrique du refus v3 : basculer un équipement déjà en v3 vers v2c
    sans communauté configurée est aussi un refus explicite (422), jamais un
    sondage avec une communauté vide."""
    from app import config as config_module

    monkeypatch.setattr(config_module.settings, "snmp_community", "")

    app, _conn = _build_inventory_test_app(db_path)
    client = TestClient(app)
    response = client.post("/inventory/172.30.0.73/snmp-version", json={"snmp_version": "v2c"})

    assert response.status_code == 422
    assert "non configuré" in response.text


def test_ecran_liste_affiche_la_version_snmp_par_equipement(
    db_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """La capture ManageEngine de référence affiche « SNMP Version : v2 » —
    l'écran Okvorado doit refléter la VRAIE version par équipement, jamais
    une valeur figée en dur (régression du `v2` en dur d'origine)."""
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars_ok)

    app, conn = _build_inventory_test_app(db_path)
    snmp_inventory.collect_one(
        conn,
        address="172.30.0.74",
        snmp_version="v3",
        v3_credentials=_fake_v3_credentials("authPriv"),
    )

    client = TestClient(app)
    response = client.get("/inventory")
    assert response.status_code == 200
    assert "SNMPv3" in response.text

    detail_response = client.get("/inventory/172.30.0.74")
    assert detail_response.status_code == 200
    assert "SNMPv3" in detail_response.text
    # Non-régression : la valeur "v2" figée en dur d'origine ne doit plus
    # apparaître seule comme libellé de version (elle apparaît légitimement
    # dans "SNMPv2c" pour un AUTRE équipement, donc on vérifie l'ABSENCE
    # du fragment isolé, pas une simple absence de sous-chaîne "v2").
    assert ">v2<" not in detail_response.text


def test_ecran_detail_signale_lechec_dauthentification_distinctement(
    db_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """L'écran détail doit afficher un message DISTINCT pour `auth_failure`
    (pas la bannière générique "Pas de réponse SNMP") — zéro silencieux
    jusqu'à l'écran, pas seulement en base."""

    def _boom_auth(*_args: Any, **_kwargs: Any) -> None:
        raise snmp_inventory.SnmpAuthenticationError("authentification SNMPv3 refusee")

    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _boom_auth)

    app, conn = _build_inventory_test_app(db_path)
    snmp_inventory.collect_one(
        conn,
        address="172.30.0.75",
        snmp_version="v3",
        v3_credentials=_fake_v3_credentials("authPriv"),
    )

    client = TestClient(app)
    response = client.get("/inventory/172.30.0.75")
    assert response.status_code == 200
    assert "authentification" in response.text.lower()
    assert "Pas de réponse SNMP" not in response.text


# ---------------------------------------------------------------------------
# L'écran de configuration doit accepter v2c ET v3 pendant la migration
# ---------------------------------------------------------------------------


class TestValidationCredentialsV2cEtV3:
    """DÉFAUT MESURÉ (2026-08-08) : le validateur n'acceptait QUE `communities`.

    Signalé par l'agent qui a livré SNMPv3, puis reproduit : une entrée v3
    seule ET une table mixte v2c+v3 étaient toutes deux REJETÉES par l'écran
    `/config`.

    Pourquoi ça compte sur le parc visé : la bascule v2c → v3 sur 350 routeurs
    SFR s'étale sur des mois. Pendant toute la transition, la table `credentials`
    contient les DEUX. Un opérateur qui aurait migré un sous-réseau en v3
    n'aurait plus pu toucher à sa configuration depuis l'écran — alors que
    « tout piloter depuis l'écran » est l'objectif du projet (CLAUDE.md).

    Le défaut ne se voyait ni aux tests ni au démarrage : le stack tournait,
    seule l'ÉDITION cassait, et seulement après une migration v3.
    """

    def _valider(self, credentials: dict[str, object]) -> list[str]:
        from app.services.config_sections import _validate_snmp_credentials

        return _validate_snmp_credentials(0, credentials)

    def test_v2c_seul_reste_accepte(self) -> None:
        """Non-régression : c'est ce qui tourne aujourd'hui sur le parc."""
        assert not self._valider({"::/0": {"communities": ["public"]}})

    def test_v3_seul_est_accepte(self) -> None:
        assert not self._valider(
            {
                "10.0.0.0/8": {
                    "user-name": "okvorado",
                    "authentication-protocol": "SHA256",
                    "authentication-passphrase": "phrase-auth",
                    "privacy-protocol": "AES",
                    "privacy-passphrase": "phrase-priv",
                }
            }
        )

    def test_une_table_MIXTE_est_acceptee(self) -> None:
        """LE cas de la migration : v2c par défaut, v3 sur le sous-réseau migré."""
        assert not self._valider(
            {
                "::/0": {"communities": ["public"]},
                "10.0.0.0/8": {
                    "user-name": "okvorado",
                    "authentication-protocol": "SHA256",
                    "authentication-passphrase": "phrase-auth",
                },
            }
        )

    def test_v3_sans_nom_d_utilisateur_est_refuse(self) -> None:
        assert self._valider({"10.0.0.0/8": {"user-name": "  "}})

    def test_v3_protocole_sans_phrase_est_refuse(self) -> None:
        """Une moitié de couple produirait un échec d'authentification côté
        agent, sans explication lisible."""
        assert self._valider(
            {"10.0.0.0/8": {"user-name": "u", "authentication-protocol": "SHA256"}}
        )

    def test_v3_chiffrement_sans_authentification_est_refuse(self) -> None:
        """Ce niveau n'existe pas dans la RFC 3414 : il serait accepté par la
        configuration et rejeté par l'agent."""
        assert self._valider(
            {
                "10.0.0.0/8": {
                    "user-name": "u",
                    "privacy-protocol": "AES",
                    "privacy-passphrase": "p",
                }
            }
        )

    def test_aucun_secret_v3_ne_fuit_dans_un_message_d_erreur(self) -> None:
        """Les retours de validation sont JOURNALISÉS par le routeur appelant.

        Un secret cité dans un message fuirait par le chemin d'ERREUR — celui
        qu'on surveille le moins. Même règle que pour les communautés v2c.

        SECRET_OK: valeur FACTICE de test, jamais un identifiant reel. Elle sert
        precisement a prouver qu une phrase secrete N APPARAIT PAS dans les
        messages de validation — la retirer viderait le test de son sens.
        """
        temoin = "valeur-temoin-a-ne-jamais-divulguer"
        messages = " ".join(
            self._valider(
                {
                    "10.0.0.0/8": {
                        "user-name": "u",
                        "authentication-protocol": "SHA256",
                        "authentication-passphrase": temoin,
                    }
                }
            )
        )
        assert temoin not in messages, "une phrase secrète v3 apparaît dans un message d'erreur"
