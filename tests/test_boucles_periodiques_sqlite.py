"""Les tâches de fond de `app/main.py` ouvrent des connexions SQLite EXPLOITABLES.

POURQUOI (2026-08-11)
---------------------
Défaut mesuré en production, à chaque cycle de collecte SNMP automatique :

    ERROR app.main: echec cycle de collecte snmp automatique:
    'tuple' object has no attribute 'keys'
      app/main.py:73                        _snmp_inventory_periodic_loop
      app/services/snmp_inventory.py:1074   collect_all
      app/services/snmp_inventory.py:991    collect_one
      app/services/snmp_inventory.py:1101   _row_to_item   <-- row.keys()

La boucle ouvrait sa connexion sans `row_factory = sqlite3.Row`. La collecte
SNMP automatique n'a donc **JAMAIS produit un seul cycle réussi** depuis sa
mise en place : chaque tour partait à l'exception, était avalé par le
`except Exception` qui protège la boucle, et repartait pour un tour identique.
La boucle survivait — la fonctionnalité, non.

Ce que les tests existants ne prouvaient PAS : ils appelaient `collect_all`
avec une connexion construite à la main, `row_factory` correctement posé. Ils
validaient la LOGIQUE de collecte (juste) et jamais le CÂBLAGE de la boucle
(faux). C'est la quatrième famille de défauts invisibles aux tests documentée
dans le CLAUDE.md du projet : « service existant non branché ».

Les tests ci-dessous exercent les boucles RÉELLES de `app/main.py`, avec leur
propre ouverture de connexion — le seul endroit où le défaut était observable.
"""

import asyncio
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from app.db import init_database


@pytest.fixture
def base_reelle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Base SQLite sur FICHIER, avec le vrai schéma, pointée par `settings`.

    Fichier et non `:memory:` : les boucles déportent leur travail dans un
    autre thread via `asyncio.to_thread`, et une base `:memory:` est propre à
    chaque connexion. C'est exactement la contrainte de production.
    """
    from app.config import settings

    chemin = str(tmp_path / "boucles.db")
    init_database(chemin)
    monkeypatch.setattr(settings, "sqlite_path", chemin)
    return chemin


def test_collecte_snmp_periodique_rend_des_lignes_nommees(
    base_reelle: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED avant correctif : reproduit `'tuple' object has no attribute 'keys'`.

    Exerce UN cycle de `_snmp_inventory_periodic_loop` de bout en bout, avec sa
    propre ouverture de connexion — sans jamais lui fournir de connexion de
    test. Avant le correctif du 2026-08-11, ce test échouait avec l'erreur
    exacte lue en production ; il est la preuve que le correctif porte sur le
    chemin RÉEL et pas sur un double complaisant.

    L'interrogation SNMP elle-même est remplacée par un double (aucun test ne
    touche le réseau), mais TOUT le reste — ouverture de connexion, écriture,
    relecture, conversion en `InventoryItem` — est le code de production.
    """
    from app import main as main_module
    from app.config import settings
    from app.services import snmp_inventory

    monkeypatch.setattr(settings, "snmp_community", "communaute-de-test")
    monkeypatch.setattr(settings, "snmp_poll_interval_seconds", 0)

    class _Status:
        def __init__(self, address: str) -> None:
            self.address = address

    async def _fake_statuses(_window: Any) -> list[_Status]:
        return [_Status("192.0.2.11")]

    def _fake_scalars(*_args: Any, **_kwargs: Any) -> dict[str, str | int]:
        return {
            "sys_name": "routeur-agence-11",
            "sys_descr": "IOS-XE 17.9",
            "sys_location": "Agence-11",
            "sys_contact": "exploitation@example.org",
            "sys_uptime_ticks": 123456,
        }

    monkeypatch.setattr("app.routers.exporters.load_exporter_statuses", _fake_statuses)
    # Même point de découpe que `tests/test_snmp_inventory.py` : c'est
    # `_snmp_get_scalars` qui parle au réseau, tout ce qui est en aval (SQL,
    # conversion en `InventoryItem`) reste le code de production — donc le
    # `row.keys()` qui cassait.
    monkeypatch.setattr(snmp_inventory, "_snmp_get_scalars", _fake_scalars)

    # Un `except Exception` protège la boucle en production (une collecte ratée
    # ne doit jamais tuer la tâche de fond). C'est aussi ce qui a rendu le
    # défaut SILENCIEUX pendant des mois : il n'apparaissait qu'en log ERROR.
    # On capture donc les logs pour ÉCHOUER sur une erreur avalée, au lieu de
    # confondre « la boucle n'a pas planté » avec « la collecte a marché ».
    erreurs: list[str] = []

    def _capture(msg: Any, *a: Any, **k: Any) -> None:
        # Plafonné : la boucle réessaie indéfiniment, et sans plafond le
        # message d'échec du test contient des centaines de lignes identiques
        # qui NOISENT la seule information utile (la première erreur).
        if len(erreurs) < 3:
            erreurs.append(str(msg) % a if a else str(msg))

    monkeypatch.setattr(main_module.log, "error", _capture)

    async def _un_seul_cycle() -> None:
        tache = asyncio.create_task(main_module._snmp_inventory_periodic_loop())
        # `collect_all` est déportée hors de la boucle événements via
        # `asyncio.to_thread` : il faut donc laisser réellement la main à
        # l'exécuteur (`sleep` non nul), pas seulement au scheduler asyncio.
        for _ in range(100):
            await asyncio.sleep(0.02)
            conn_verif = sqlite3.connect(base_reelle)
            try:
                trouve = conn_verif.execute("SELECT COUNT(*) FROM snmp_inventory").fetchone()[0]
            finally:
                conn_verif.close()
            if trouve or erreurs:
                break
        tache.cancel()
        try:
            await tache
        except asyncio.CancelledError:
            pass

    asyncio.run(_un_seul_cycle())

    assert not erreurs, (
        "La boucle de collecte SNMP a journalisé une erreur au lieu de collecter : "
        f"{erreurs}. Défaut historique du 2026-08-11 : connexion ouverte sans "
        "row_factory = sqlite3.Row, donc _row_to_item recevait un tuple."
    )

    conn = sqlite3.connect(base_reelle)
    conn.row_factory = sqlite3.Row
    try:
        ligne = conn.execute(
            "SELECT * FROM snmp_inventory WHERE address = '192.0.2.11'"
        ).fetchone()
    finally:
        conn.close()
    assert ligne is not None, "aucun equipement inventorie : le cycle n'a pas abouti"
    assert ligne["status"] == "ok"
    assert ligne["sys_name"] == "routeur-agence-11"


def test_surveillance_sante_db_periodique_ecrit_son_historique(
    base_reelle: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Même câblage vérifié sur `_db_health_periodic_loop`.

    Cette boucle ouvrait elle aussi sa connexion à la main (même motif, même
    fichier). Son appelant `_record_history` n'indexe que par position, donc
    elle ne CRASHAIT pas — mais elle était armée : le jour où l'écriture aurait
    lu une colonne par nom, le même défaut serait réapparu ailleurs. Le test
    verrouille le comportement maintenant que tout passe par `app.db`.
    """
    from app import main as main_module
    from app.config import settings

    monkeypatch.setattr(settings, "db_health_poll_interval_seconds", 0)

    # Aucune connexion ClickHouse en test : la boucle doit basculer sur son
    # instantané « indisponible » (ZÉRO SILENCIEUX) et l'historiser quand même.
    def _connexion_impossible() -> Any:
        raise RuntimeError("clickhouse indisponible en test")

    monkeypatch.setattr("app.clients.clickhouse.connect", _connexion_impossible, raising=False)

    erreurs: list[str] = []
    vrai_log_error = main_module.log.error

    def _capture(msg: Any, *a: Any, **k: Any) -> None:
        texte = str(msg) % a if a else str(msg)
        # L'échec de connexion ClickHouse est ATTENDU ici et journalisé par
        # conception ; seul un échec de CYCLE trahirait le défaut de câblage.
        if "echec cycle" in texte:
            erreurs.append(texte)
        vrai_log_error(msg, *a, **k)

    monkeypatch.setattr(main_module.log, "error", _capture)

    async def _un_seul_cycle() -> None:
        tache = asyncio.create_task(main_module._db_health_periodic_loop())
        for _ in range(100):
            await asyncio.sleep(0.02)
            conn_verif = sqlite3.connect(base_reelle)
            try:
                trouve = conn_verif.execute("SELECT COUNT(*) FROM db_health_history").fetchone()[0]
            finally:
                conn_verif.close()
            if trouve or erreurs:
                break
        tache.cancel()
        try:
            await tache
        except asyncio.CancelledError:
            pass

    asyncio.run(_un_seul_cycle())

    assert not erreurs, f"cycle de surveillance sante db en erreur : {erreurs}"

    conn = sqlite3.connect(base_reelle)
    conn.row_factory = sqlite3.Row
    try:
        ligne = conn.execute(
            "SELECT overall_state FROM db_health_history ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    assert ligne is not None, "aucun snapshot historise : la boucle n'a pas abouti"
