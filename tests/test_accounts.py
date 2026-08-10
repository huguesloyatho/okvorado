"""Tests de la gestion des comptes (LOT accounts).

DEMANDE UTILISATEUR (2026-08-09) : « on a pas de management de compte, etat de
connexion user, déconnexion. Il faut tout ajouter ».

Couvre :
  - un lecteur ne peut atteindre ni l'écran /accounts ni une route d'écriture
    de ce module (403, garde SERVEUR — pas seulement l'absence de lien) ;
  - le dernier administrateur ne peut être ni supprimé ni rétrogradé ;
  - impossible de supprimer son propre compte ;
  - un compte créé peut se connecter ; un compte supprimé ne le peut plus ;
  - l'identifiant affiché dans l'en-tête correspond à la session réelle ;
  - les actions de gestion de comptes sont journalisées dans `audit_log`,
    sans jamais y écrire un secret (mot de passe, TOTP).

Même schéma de fixtures que `tests/test_auth.py` : base SQLite dédiée,
câblée à la place de la connexion réelle le temps du test.

SECRET_OK: les mots de passe ci-dessous sont des valeurs de test arbitraires,
même pattern que `tests/test_auth.py`.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.auth import ROLE_ADMIN, ROLE_LECTEUR, hash_password, new_session_cookie
from app.db import SCHEMA
from app.main import app
from app.routers import accounts as accounts_router
from app.routers import auth as auth_router


@pytest.fixture
def accounts_db(tmp_path, monkeypatch: pytest.MonkeyPatch) -> Generator[sqlite3.Connection]:
    """Base SQLite sur DISQUE, câblée à la place de `settings.sqlite_path`.

    DÉFAUT MESURÉ (voir `tests/test_auth.py::fichier_sqlite_reel`, même piège
    ici) : le middleware `app.main.require_authentication` ouvre SA PROPRE
    connexion via `sqlite3.connect(settings.sqlite_path)`, indépendante des
    `app.dependency_overrides` utilisés par les routers — une base `:memory:`
    câblée uniquement sur les dependency_overrides des routers reste INVISIBLE
    au middleware, qui ne trouve alors pas la table `auth_users` et retombe
    sur `auth_role='lecteur'` par défaut (zéro silencieux, voir
    `app.main.require_authentication`) : TOUT appelant, même admin, recevrait
    alors un 403 — pas une preuve de la garde testée, un artefact de fixture.
    """
    import app.main as main_module

    db_path = str(tmp_path / "accounts-test.db")
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()

    monkeypatch.setattr(main_module.settings, "sqlite_path", db_path)
    try:
        yield conn
    finally:
        conn.close()


def _seed_user(
    conn: sqlite3.Connection, username: str, password: str, role: str = ROLE_ADMIN
) -> None:
    conn.execute(
        "INSERT INTO auth_users (username, password_hash, is_default_password, role) "
        "VALUES (?, ?, 0, ?)",
        (username, hash_password(password), role),
    )
    conn.commit()


@pytest.fixture
def client_factory(accounts_db: sqlite3.Connection):
    """Fabrique un `TestClient` authentifié comme `username`, câblé sur
    `accounts_db` pour TOUS les routers concernés (auth + accounts partagent
    la même connexion SQLite réelle, voir `app.main._wire_dependencies`)."""

    def _make(username: str) -> TestClient:
        app.dependency_overrides[auth_router.get_db_connection] = lambda: accounts_db
        app.dependency_overrides[accounts_router.get_db_connection] = lambda: accounts_db
        client = TestClient(app, follow_redirects=False)
        cookie = new_session_cookie(username, app.state.auth_session_secret)
        client.cookies.set("okvorado_session", cookie)
        return client

    yield _make
    app.dependency_overrides.pop(auth_router.get_db_connection, None)
    app.dependency_overrides.pop(accounts_router.get_db_connection, None)


# ---------------------------------------------------------------------------
# Garde serveur — un lecteur ne peut PAS atteindre l'écran ni écrire
# ---------------------------------------------------------------------------


class TestGardeLecteurRefuse:
    def test_lecteur_recoit_403_sur_lecran_comptes(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "alice", "MotDePasseA1!", role=ROLE_LECTEUR)
        client = client_factory("alice")
        response = client.get("/accounts")
        assert response.status_code == 403

    def test_lecteur_recoit_403_sur_creation_de_compte(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "alice", "MotDePasseA1!", role=ROLE_LECTEUR)
        client = client_factory("alice")
        response = client.post(
            "/accounts", data={"username": "nouveau", "role": ROLE_LECTEUR}
        )
        assert response.status_code == 403

    def test_lecteur_recoit_403_sur_suppression_de_compte(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "alice", "MotDePasseA1!", role=ROLE_LECTEUR)
        _seed_user(accounts_db, "bob", "MotDePasseB1!", role=ROLE_ADMIN)
        client = client_factory("alice")
        response = client.post("/accounts/bob/delete")
        assert response.status_code == 403

    def test_lecteur_recoit_403_sur_changement_de_role(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "alice", "MotDePasseA1!", role=ROLE_LECTEUR)
        client = client_factory("alice")
        response = client.post("/accounts/alice/role", data={"role": ROLE_ADMIN})
        assert response.status_code == 403

    def test_admin_accede_a_lecran_comptes(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        client = client_factory("admin")
        response = client.get("/accounts")
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Garde-fou — dernier administrateur intouchable
# ---------------------------------------------------------------------------


class TestDernierAdministrateur:
    def test_un_admin_peut_etre_supprime_si_un_autre_admin_reste(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        """Contrôle négatif : la garde ne doit PAS bloquer une suppression
        légitime quand un autre administrateur reste disponible ensuite."""
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        _seed_user(accounts_db, "admin2", "MotDePasseAdmin2!", role=ROLE_ADMIN)
        client = client_factory("admin")

        response = client.post("/accounts/admin2/delete")
        assert response.status_code == 200

        row = accounts_db.execute(
            "SELECT 1 FROM auth_users WHERE username = 'admin2'"
        ).fetchone()
        assert row is None

    def test_impossible_de_retrograder_le_dernier_administrateur(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        _seed_user(accounts_db, "bob", "MotDePasseB1!", role=ROLE_LECTEUR)
        client = client_factory("admin")

        response = client.post("/accounts/admin/role", data={"role": ROLE_LECTEUR})
        assert response.status_code == 400
        assert "dernier" in response.text.lower() or "propre rôle" in response.text.lower()

        # Le rôle n'a PAS changé en base.
        row = accounts_db.execute(
            "SELECT role FROM auth_users WHERE username = 'admin'"
        ).fetchone()
        assert row[0] == ROLE_ADMIN

    def test_un_admin_peut_retrograder_un_autre_admin_si_ca_nen_laisse_pas_zero(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        """Contrôle négatif symétrique : rétrograder un admin reste permis
        tant qu'il n'est PAS le dernier."""
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        _seed_user(accounts_db, "admin2", "MotDePasseAdmin2!", role=ROLE_ADMIN)
        client = client_factory("admin")

        response = client.post("/accounts/admin2/role", data={"role": ROLE_LECTEUR})
        assert response.status_code == 200

        row = accounts_db.execute(
            "SELECT role FROM auth_users WHERE username = 'admin2'"
        ).fetchone()
        assert row[0] == ROLE_LECTEUR

    def test_impossible_de_supprimer_le_dernier_administrateur_seul(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        """Un admin seul en base ne peut pas se faire supprimer — la garde
        anti-auto-suppression ET la garde "dernier admin" mordent toutes les
        deux ici, par construction (pas par coïncidence)."""
        _seed_user(accounts_db, "seul_admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        client = client_factory("seul_admin")

        response = client.post("/accounts/seul_admin/delete")
        assert response.status_code == 400

        user = accounts_db.execute(
            "SELECT 1 FROM auth_users WHERE username = 'seul_admin'"
        ).fetchone()
        assert user is not None  # toujours présent


# ---------------------------------------------------------------------------
# Garde-fou — auto-suppression pendant l'usage du compte
# ---------------------------------------------------------------------------


class TestAutoSuppression:
    def test_impossible_de_supprimer_son_propre_compte(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        """Même avec un AUTRE administrateur disponible (donc pas le dernier
        admin), on ne se supprime jamais soi-même en cours de session."""
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        _seed_user(accounts_db, "admin2", "MotDePasseAdmin2!", role=ROLE_ADMIN)
        client = client_factory("admin")

        response = client.post("/accounts/admin/delete")
        assert response.status_code == 400
        assert "propre compte" in response.text.lower()

        # Le compte existe toujours.
        row = accounts_db.execute(
            "SELECT 1 FROM auth_users WHERE username = 'admin'"
        ).fetchone()
        assert row is not None

    def test_un_admin_peut_supprimer_un_autre_compte(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        _seed_user(accounts_db, "bob", "MotDePasseB1!", role=ROLE_LECTEUR)
        client = client_factory("admin")

        response = client.post("/accounts/bob/delete")
        assert response.status_code == 200

        row = accounts_db.execute(
            "SELECT 1 FROM auth_users WHERE username = 'bob'"
        ).fetchone()
        assert row is None


# ---------------------------------------------------------------------------
# Cycle de vie d'un compte : création -> connexion -> suppression -> refus
# ---------------------------------------------------------------------------


class TestCycleDeVieCompte:
    def test_un_compte_cree_peut_se_connecter(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        client = client_factory("admin")

        response = client.post(
            "/accounts", data={"username": "nouveau", "role": ROLE_LECTEUR}
        )
        assert response.status_code == 200

        # Extrait le mot de passe généré, affiché dans la page de retour.
        match = re.search(r"<code>([^<]+)</code>", response.text)
        assert match is not None, "mot de passe généré introuvable dans la réponse"
        generated_password = match.group(1)

        app.dependency_overrides[auth_router.get_db_connection] = lambda: accounts_db
        login_client = TestClient(app, follow_redirects=False)
        login_response = login_client.post(
            "/login", data={"username": "nouveau", "password": generated_password}
        )
        assert login_response.status_code == 303
        assert "okvorado_session" in login_response.cookies

    def test_un_compte_supprime_ne_peut_plus_se_connecter(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        _seed_user(accounts_db, "bob", "MotDePasseB1!", role=ROLE_LECTEUR)
        client = client_factory("admin")

        response = client.post("/accounts/bob/delete")
        assert response.status_code == 200

        app.dependency_overrides[auth_router.get_db_connection] = lambda: accounts_db
        login_client = TestClient(app, follow_redirects=False)
        login_response = login_client.post(
            "/login", data={"username": "bob", "password": "MotDePasseB1!"}
        )
        assert login_response.status_code == 401
        assert "okvorado_session" not in login_response.cookies

    def test_reinitialisation_de_mot_de_passe_permet_une_nouvelle_connexion(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        _seed_user(accounts_db, "bob", "MotDePasseB1!", role=ROLE_LECTEUR)
        client = client_factory("admin")

        response = client.post("/accounts/bob/reset-password")
        assert response.status_code == 200

        match = re.search(r"<code>([^<]+)</code>", response.text)
        assert match is not None
        new_password = match.group(1)

        app.dependency_overrides[auth_router.get_db_connection] = lambda: accounts_db
        login_client = TestClient(app, follow_redirects=False)
        # L'ANCIEN mot de passe ne fonctionne plus.
        old_login = login_client.post(
            "/login", data={"username": "bob", "password": "MotDePasseB1!"}
        )
        assert old_login.status_code == 401
        # Le NOUVEAU fonctionne.
        new_login = login_client.post(
            "/login", data={"username": "bob", "password": new_password}
        )
        assert new_login.status_code == 303


# ---------------------------------------------------------------------------
# État de connexion affiché — l'identifiant correspond à la session réelle
# ---------------------------------------------------------------------------


class TestEtatDeConnexionAffiche:
    def test_identifiant_affiche_correspond_a_la_session(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "alice", "MotDePasseA1!", role=ROLE_LECTEUR)
        app.dependency_overrides[auth_router.get_db_connection] = lambda: accounts_db
        client = TestClient(app)
        cookie = new_session_cookie("alice", app.state.auth_session_secret)
        client.cookies.set("okvorado_session", cookie)

        response = client.get("/exporters")
        assert response.status_code == 200
        assert "alice" in response.text
        assert "Lecteur" in response.text

        app.dependency_overrides.pop(auth_router.get_db_connection, None)

    def test_lien_comptes_visible_uniquement_pour_un_administrateur(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "alice", "MotDePasseA1!", role=ROLE_LECTEUR)
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        app.dependency_overrides[auth_router.get_db_connection] = lambda: accounts_db

        client_lecteur = TestClient(app)
        client_lecteur.cookies.set(
            "okvorado_session", new_session_cookie("alice", app.state.auth_session_secret)
        )
        resp_lecteur = client_lecteur.get("/exporters")
        assert 'href="/accounts"' not in resp_lecteur.text

        client_admin = TestClient(app)
        client_admin.cookies.set(
            "okvorado_session", new_session_cookie("admin", app.state.auth_session_secret)
        )
        resp_admin = client_admin.get("/exporters")
        assert 'href="/accounts"' in resp_admin.text

        app.dependency_overrides.pop(auth_router.get_db_connection, None)


# ---------------------------------------------------------------------------
# Journalisation — audit_log, jamais de secret
# ---------------------------------------------------------------------------


class TestJournalisation:
    def test_la_creation_de_compte_est_journalisee(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        client = client_factory("admin")

        client.post("/accounts", data={"username": "nouveau", "role": ROLE_LECTEUR})

        row = accounts_db.execute(
            "SELECT actor, action, detail FROM audit_log WHERE action = 'account_create'"
        ).fetchone()
        assert row is not None
        assert row[0] == "admin"
        assert "nouveau" in row[2]

    def test_la_suppression_de_compte_est_journalisee(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        _seed_user(accounts_db, "bob", "MotDePasseB1!", role=ROLE_LECTEUR)
        client = client_factory("admin")

        client.post("/accounts/bob/delete")

        row = accounts_db.execute(
            "SELECT actor, action, detail FROM audit_log WHERE action = 'account_delete'"
        ).fetchone()
        assert row is not None
        assert row[0] == "admin"
        assert "bob" in row[2]

    def test_le_changement_de_role_est_journalise(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        _seed_user(accounts_db, "bob", "MotDePasseB1!", role=ROLE_LECTEUR)
        client = client_factory("admin")

        client.post("/accounts/bob/role", data={"role": ROLE_ADMIN})

        row = accounts_db.execute(
            "SELECT actor, action, detail FROM audit_log WHERE action = 'account_role_change'"
        ).fetchone()
        assert row is not None
        assert "bob" in row[2]
        assert "admin" in row[2]  # new_role=admin

    def test_la_reinitialisation_de_mot_de_passe_est_journalisee(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        _seed_user(accounts_db, "bob", "MotDePasseB1!", role=ROLE_LECTEUR)
        client = client_factory("admin")

        client.post("/accounts/bob/reset-password")

        row = accounts_db.execute(
            "SELECT actor, action, detail FROM audit_log WHERE action = 'account_password_reset'"
        ).fetchone()
        assert row is not None
        assert row[0] == "admin"
        assert "bob" in row[2]

    def test_aucun_secret_dans_laudit_log(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        """Le mot de passe généré ne doit JAMAIS apparaître dans `audit_log`,
        même s'il est affiché une fois à l'écran."""
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        client = client_factory("admin")

        response = client.post(
            "/accounts", data={"username": "nouveau", "role": ROLE_LECTEUR}
        )
        match = re.search(r"<code>([^<]+)</code>", response.text)
        assert match is not None
        generated_password = match.group(1)

        rows = accounts_db.execute("SELECT detail FROM audit_log").fetchall()
        for row in rows:
            assert generated_password not in row[0]


# ---------------------------------------------------------------------------
# Validation de saisie — rôle invalide, doublon, champ vide
# ---------------------------------------------------------------------------


class TestValidationSaisie:
    def test_creation_avec_identifiant_vide_est_refusee(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        client = client_factory("admin")

        response = client.post("/accounts", data={"username": "  ", "role": ROLE_LECTEUR})
        assert response.status_code == 400

    def test_creation_avec_role_invalide_est_refusee(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        client = client_factory("admin")

        response = client.post(
            "/accounts", data={"username": "nouveau", "role": "superadmin"}
        )
        assert response.status_code == 400

    def test_creation_dun_compte_deja_existant_est_refusee(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        _seed_user(accounts_db, "bob", "MotDePasseB1!", role=ROLE_LECTEUR)
        client = client_factory("admin")

        response = client.post("/accounts", data={"username": "bob", "role": ROLE_LECTEUR})
        assert response.status_code == 400
        assert "existe déjà" in response.text


# ---------------------------------------------------------------------------
# TOTP par compte — pas global (vérification du mécanisme existant)
# ---------------------------------------------------------------------------


class TestTotpParCompte:
    def test_activer_totp_sur_un_compte_ne_lactive_pas_sur_un_autre(
        self, accounts_db: sqlite3.Connection, client_factory
    ) -> None:
        """Le TOTP est indexé par `username` dans `auth_users`/`auth_backup_codes`
        (voir app/auth.py) : ce test prouve que ce n'est pas un artefact
        accidentel de mono-compte mais un comportement réel avec plusieurs
        comptes en base."""
        from app.auth import enable_totp, generate_totp_secret, set_totp_secret_pending

        _seed_user(accounts_db, "admin", "MotDePasseAdmin1!", role=ROLE_ADMIN)
        _seed_user(accounts_db, "bob", "MotDePasseB1!", role=ROLE_LECTEUR)

        secret = generate_totp_secret()
        set_totp_secret_pending(accounts_db, "admin", secret)
        enable_totp(accounts_db, "admin")

        row_admin = accounts_db.execute(
            "SELECT totp_enabled FROM auth_users WHERE username = 'admin'"
        ).fetchone()
        row_bob = accounts_db.execute(
            "SELECT totp_enabled FROM auth_users WHERE username = 'bob'"
        ).fetchone()
        assert bool(row_admin[0]) is True
        assert bool(row_bob[0]) is False


# ---------------------------------------------------------------------------
# Migration de schéma — compatibilité avec une base existante
# ---------------------------------------------------------------------------


class TestMigrationSchema:
    def test_une_base_sans_colonnes_role_et_last_login_est_migree(self, tmp_path) -> None:
        """Reproduit une base créée AVANT le LOT accounts (schéma sans `role`
        ni `last_login_at`) : `init_database` doit ajouter les colonnes sans
        casser les données existantes, `role` valant `'admin'` par défaut."""
        from app.db import init_database

        db_path = str(tmp_path / "ancienne.db")
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE auth_users (
                username             TEXT PRIMARY KEY,
                password_hash        TEXT NOT NULL,
                totp_enabled         INTEGER NOT NULL DEFAULT 0,
                totp_secret          TEXT,
                is_default_password  INTEGER NOT NULL DEFAULT 0,
                created_at           TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            "INSERT INTO auth_users (username, password_hash) VALUES ('admin', 'x')"
        )
        conn.commit()
        conn.close()

        init_database(db_path)

        conn = sqlite3.connect(db_path)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(auth_users)").fetchall()}
        assert "role" in columns
        assert "last_login_at" in columns

        row = conn.execute(
            "SELECT role, last_login_at FROM auth_users WHERE username = 'admin'"
        ).fetchone()
        assert row[0] == ROLE_ADMIN  # préserve l'accès existant, jamais 'lecteur' par surprise
        assert row[1] is None  # jamais une date arbitraire (zéro silencieux)
        conn.close()

    def test_init_database_est_idempotent_apres_migration(self, tmp_path) -> None:
        """Relancer `init_database` sur une base déjà migrée ne doit jamais
        lever `duplicate column name`."""
        from app.db import init_database

        db_path = str(tmp_path / "deja_migree.db")
        init_database(db_path)
        init_database(db_path)  # ne doit pas lever
