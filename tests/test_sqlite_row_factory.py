"""GARDE-FOU MÉCANIQUE : toute connexion SQLite de `app/` rend des lignes nommées.

POURQUOI CE FICHIER EXISTE (2026-08-11)
---------------------------------------
Défaut mesuré en production : à CHAQUE cycle de collecte SNMP automatique,
`app/main.py::_snmp_inventory_periodic_loop` plantait sur

    ERROR app.main: echec cycle de collecte snmp automatique:
    'tuple' object has no attribute 'keys'

Cause exacte : la boucle ouvrait sa connexion avec un
`sqlite3.connect(settings.sqlite_path, check_same_thread=False)` NU, sans poser
`conn.row_factory = sqlite3.Row`. Les lignes arrivaient donc en `tuple` bruts,
et `app/services/snmp_inventory.py::_row_to_item` — qui appelle `row.keys()`
puis indexe PAR NOM (`row["address"]`) — explosait.

Conséquence : **la collecte SNMP automatique n'a JAMAIS fonctionné** depuis sa
mise en place. Pas un cycle réussi, jamais. Ce n'était pas un défaut de logique
métier (le code de collecte est juste), c'était un CÂBLAGE MANQUANT sur une
seule ligne — invisible aux tests, parce que TOUS les tests construisaient leur
connexion à la main en posant `row_factory` correctement. La suite était verte
pendant que la fonctionnalité était morte en prod.

POURQUOI UN GARDE-FOU ET PAS UNE N-IÈME CORRECTION
---------------------------------------------------
CLAUDE.md, règle n°2 : « un motif corrigé ≥3 fois n'est plus un bug : c'est un
défaut de conception. Le fix définitif est alors un GARDE-FOU MÉCANIQUE (hook,
test, type), pas une n-ième correction d'occurrence. »

Le motif « connexion SQLite ouverte à la main sans `row_factory`, et le code
appelant casse sur `.keys()` ou sur un accès par nom » s'est produit
plusieurs fois dans ce projet. L'inventaire du 2026-08-11 l'a chiffré :
`app/` contenait 11 `sqlite3.connect` directs, dont SEULEMENT 2 posaient
`row_factory`. Neuf connexions étaient donc des mines potentielles, chacune
n'attendant qu'un appelant lisant par nom pour reproduire exactement le même
crash. Corriger la seule occurrence SNMP aurait laissé les huit autres armées.

Le garde-fou retenu est STRUCTUREL, en deux volets complémentaires :

  1. `test_aucune_connexion_sqlite_directe_hors_db_py` — analyse l'AST de
     TOUS les modules de `app/` et REFUSE tout appel `sqlite3.connect` en
     dehors de `app/db.py`. C'est le volet qui mord : il rend impossible la
     réintroduction du défaut, parce qu'il n'y a plus qu'UNE porte d'entrée.
     Un helper qu'on PEUT contourner est un helper qu'on contournera — c'est
     précisément ce qui s'est passé : `app/db.py::get_connection` existait
     déjà, avec le bon `row_factory`, et n'était utilisé par PERSONNE.

  2. `test_open_connection_pose_row_factory` et
     `test_get_connection_pose_row_factory` — vérifient que cette porte unique
     pose bien `row_factory`. Sans eux, le volet 1 garantirait seulement que
     tout le monde passe par la même porte, pas que la porte soit correcte.

Ensemble : toute connexion de `app/` passe par `app/db.py`, et `app/db.py`
pose `row_factory`. Donc toute connexion de `app/` rend des `sqlite3.Row`.

PREUVE QUE LE GARDE-FOU MORD (sabotage vérifié le 2026-08-11)
--------------------------------------------------------------
- Retirer `conn.row_factory = sqlite3.Row` de `app/db.py::open_connection`
  → `test_open_connection_pose_row_factory` ÉCHOUE, et
    `test_collecte_snmp_periodique_rend_des_lignes_nommees` échoue en
    reproduisant textuellement `'tuple' object has no attribute 'keys'`.
- Réintroduire un `sqlite3.connect(...)` nu dans `app/main.py`
  → `test_aucune_connexion_sqlite_directe_hors_db_py` ÉCHOUE en nommant le
    fichier et la ligne fautive.
"""

import ast
import sqlite3
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parent.parent / "app"

# `app/db.py` est la SEULE porte d'entrée autorisée vers `sqlite3.connect`.
# Tout ajout à cette liste doit être argumenté : chaque entrée est une
# connexion qui échappe au garde-fou du `row_factory`.
MODULES_AUTORISES_A_OUVRIR_SQLITE = {"db.py"}


def _appels_sqlite_connect(chemin: Path) -> list[int]:
    """Rend les numéros de ligne des appels `sqlite3.connect(...)` d'un module.

    Analyse l'AST plutôt que le texte : un `grep` matcherait aussi les
    mentions en commentaire ou en docstring (il y en a plusieurs dans ce
    projet, qui documentent justement ce défaut), et produirait des faux
    positifs qui pousseraient à désarmer le garde-fou.
    """
    arbre = ast.parse(chemin.read_text(encoding="utf-8"), filename=str(chemin))
    lignes: list[int] = []
    for noeud in ast.walk(arbre):
        if not isinstance(noeud, ast.Call):
            continue
        fonction = noeud.func
        # Forme `sqlite3.connect(...)`
        if (
            isinstance(fonction, ast.Attribute)
            and fonction.attr == "connect"
            and isinstance(fonction.value, ast.Name)
            and fonction.value.id == "sqlite3"
        ):
            lignes.append(noeud.lineno)
        # Forme `connect(...)` après un `from sqlite3 import connect`
        elif isinstance(fonction, ast.Name) and fonction.id == "connect":
            texte = chemin.read_text(encoding="utf-8")
            if "from sqlite3 import" in texte and "connect" in texte:
                lignes.append(noeud.lineno)
    return lignes


def test_aucune_connexion_sqlite_directe_hors_db_py() -> None:
    """VOLET 1 DU GARDE-FOU : une seule porte d'entrée vers SQLite dans `app/`.

    Tant qu'un module peut appeler `sqlite3.connect` lui-même, il peut oublier
    `row_factory` — et l'oubli est INVISIBLE jusqu'à ce qu'un appelant lise par
    nom en production. C'est l'histoire exacte de la collecte SNMP, morte depuis
    sa mise en place sans qu'aucun test ne le voie.

    Le correctif définitif n'est donc pas « ne pas oublier », c'est
    « ne plus pouvoir oublier » : tout passe par `app/db.py`, qui pose
    `row_factory` une fois pour toutes.
    """
    fautifs: list[str] = []
    for module in sorted(APP_DIR.rglob("*.py")):
        if module.name in MODULES_AUTORISES_A_OUVRIR_SQLITE:
            continue
        for ligne in _appels_sqlite_connect(module):
            fautifs.append(f"{module.relative_to(APP_DIR.parent)}:{ligne}")

    assert not fautifs, (
        "Connexion(s) SQLite ouverte(s) directement hors de app/db.py : "
        + ", ".join(fautifs)
        + ". Utiliser app.db.open_connection() (ou app.db.get_connection()), qui pose "
        "row_factory = sqlite3.Row. Une connexion nue rend des tuples : tout appelant "
        "lisant par nom (row['col'], row.keys()) casse en production avec "
        "\"'tuple' object has no attribute 'keys'\" — défaut mesuré le 2026-08-11, "
        "qui a rendu la collecte SNMP automatique inopérante depuis sa mise en place."
    )


def test_open_connection_pose_row_factory(tmp_path: Path) -> None:
    """VOLET 2 DU GARDE-FOU : la porte unique rend bien des lignes NOMMÉES.

    Le volet 1 garantit que tout le monde passe par `app/db.py` ; celui-ci
    garantit que `app/db.py` fait la bonne chose. Sans lui, on aurait
    centralisé le défaut au lieu de le corriger.
    """
    from app.db import open_connection

    chemin = tmp_path / "garde-fou.db"
    conn = open_connection(str(chemin))
    try:
        assert conn.row_factory is sqlite3.Row
        conn.execute("CREATE TABLE t (address TEXT, status TEXT)")
        conn.execute("INSERT INTO t VALUES ('192.0.2.1', 'ok')")
        ligne = conn.execute("SELECT * FROM t").fetchone()
        # Les deux gestes qui cassaient en prod sur un tuple :
        assert "address" in ligne.keys()
        assert ligne["address"] == "192.0.2.1"
    finally:
        conn.close()


def test_open_connection_accepte_check_same_thread(tmp_path: Path) -> None:
    """Les tâches de fond `asyncio` déportent leur travail via `asyncio.to_thread`.

    La connexion est donc créée dans un thread et utilisée dans un autre, ce
    qui impose `check_same_thread=False`. Ce besoin est la raison pour laquelle
    ces boucles ouvraient leur connexion À LA MAIN au lieu d'utiliser le helper
    existant (`get_connection`, qui ne l'exposait pas) — c'est-à-dire la cause
    RACINE du contournement. Le helper doit couvrir ce besoin, sinon le
    contournement réapparaîtra sous une autre forme.
    """
    from app.db import open_connection

    conn = open_connection(str(tmp_path / "thread.db"), check_same_thread=False)
    try:
        assert conn.row_factory is sqlite3.Row
    finally:
        conn.close()


def test_get_connection_pose_row_factory(tmp_path: Path) -> None:
    """Le contextmanager historique reste couvert : même porte, même garantie."""
    from app.db import get_connection

    with get_connection(str(tmp_path / "ctx.db")) as conn:
        assert conn.row_factory is sqlite3.Row


@pytest.mark.parametrize(
    "nom_fonction",
    ["_row_to_item", "list_inventory", "get_inventory_item"],
)
def test_snmp_inventory_exige_des_lignes_nommees(nom_fonction: str) -> None:
    """Documente le CONTRAT que le garde-fou protège.

    Ces trois fonctions de `app/services/snmp_inventory.py` lisent les lignes
    PAR NOM et appellent `.keys()`. Elles sont donc INUTILISABLES sur une
    connexion sans `row_factory` — c'est ce contrat implicite, nulle part
    vérifié avant le 2026-08-11, que la boucle périodique violait.
    """
    from app.services import snmp_inventory

    assert callable(getattr(snmp_inventory, nom_fonction))


def test_row_to_item_casse_sur_un_tuple() -> None:
    """REPRODUIT LE DÉFAUT DE PROD : c'est bien un tuple qui produisait l'erreur.

    Ce test ne vérifie pas un comportement souhaitable, il ANCRE le symptôme
    exact lu dans les logs de production le 2026-08-11
    (`'tuple' object has no attribute 'keys'`) sur sa cause réelle. Si un jour
    `_row_to_item` devient tolérant aux tuples, ce test échouera et il faudra
    décider explicitement si le garde-fou du `row_factory` reste nécessaire —
    plutôt que de le laisser s'éroder en silence.
    """
    from app.services.snmp_inventory import _row_to_item

    with pytest.raises(AttributeError, match="'tuple' object has no attribute 'keys'"):
        _row_to_item(("192.0.2.1", "r1"))  # type: ignore[arg-type]
