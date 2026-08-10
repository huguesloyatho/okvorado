"""Tests de l'authentification autonome (LOT auth).

DEMANDE UTILISATEUR (2026-08-09) : « il faut créer une authentification
autonome a okvorado ... avec un user+mdp définissable dans le fichier .env du
docker-compose pour l'admin initiale. 2fa totp activable sur demande ».

Deux niveaux de test :
  - unitaire sur `app.auth` (hachage, TOTP, session, rate limiter) — sans
    FastAPI, la logique cryptographique doit être correcte isolément ;
  - bout en bout via `TestClient(app)` — la protection réelle des routes,
    `/health` accessible sans session (LE test le plus important : sinon le
    conteneur Docker ne démarre jamais), le flux TOTP complet.

Aucun secret n'apparaît en clair dans une assertion de log : les tests qui
vérifient l'absence de fuite lisent le texte produit et cherchent l'ABSENCE
du secret, jamais son affichage volontaire dans le test lui-même au-delà de
ce qui est strictement nécessaire pour la comparaison.

SECRET_OK: les chaînes type "MonMotDePasse!" / "MotDePasseSecretUnique42" /
"MotDePasseTest2026" ci-dessous sont des VALEURS DE TEST arbitraires
(fixtures locales, jamais un identifiant réel ni un secret d'infra) — pattern
standard d'une suite de tests d'authentification, comparable aux mots de
passe factices utilisés dans les autres lots de tests du projet.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.auth import (
    RateLimiter,
    consume_backup_code,
    ensure_bootstrap_user,
    generate_backup_codes,
    generate_totp_secret,
    get_auth_user,
    hash_backup_code,
    hash_password,
    new_session_cookie,
    reconcile_bootstrap_password,
    resolve_bootstrap_admin,
    resolve_session_secret,
    set_totp_secret_pending,
    store_backup_codes,
    totp_now,
    verify_backup_code,
    verify_password,
    verify_session,
    verify_totp_code,
)
from app.db import SCHEMA
from app.main import app
from app.routers import auth as auth_router

# ---------------------------------------------------------------------------
# Unitaire — hachage de mot de passe
# ---------------------------------------------------------------------------


class TestHashagePassword:
    def test_le_hash_ne_contient_jamais_le_mot_de_passe_en_clair(self) -> None:
        stored = hash_password("SuperSecret123!")
        assert "SuperSecret123!" not in stored

    def test_verify_password_accepte_le_bon_mot_de_passe(self) -> None:
        stored = hash_password("SuperSecret123!")
        assert verify_password("SuperSecret123!", stored) is True

    def test_verify_password_refuse_un_mauvais_mot_de_passe(self) -> None:
        stored = hash_password("SuperSecret123!")
        assert verify_password("MauvaisMotDePasse", stored) is False

    def test_deux_hachages_du_meme_mot_de_passe_different(self) -> None:
        """Sel aléatoire : deux hashes du même mot de passe ne doivent jamais
        être identiques, sinon une table arc-en-ciel redevient possible."""
        assert hash_password("identique") != hash_password("identique")

    def test_verify_password_refuse_un_hash_corrompu_sans_lever(self) -> None:
        """Un hash de format inattendu doit refuser, jamais planter en 500."""
        assert verify_password("quelconque", "pas-un-hash-valide") is False
        assert verify_password("quelconque", "md5$deadbeef") is False

    def test_jamais_de_md5_ou_sha_nu(self) -> None:
        """Garde-fou explicite du format attendu."""
        stored = hash_password("x")
        assert stored.startswith("pbkdf2_sha256$")


# ---------------------------------------------------------------------------
# Unitaire — TOTP (RFC 6238)
# ---------------------------------------------------------------------------


class TestTotp:
    def test_code_valide_est_accepte(self) -> None:
        secret = generate_totp_secret()
        code = totp_now(secret, at=1_000_000_000)
        assert verify_totp_code(secret, code, at=1_000_000_000) is True

    def test_code_invalide_est_refuse(self) -> None:
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "000000", at=1_000_000_000) is False

    def test_code_non_numerique_est_refuse(self) -> None:
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "abcdef", at=1_000_000_000) is False

    def test_code_dune_longueur_incorrecte_est_refuse(self) -> None:
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "12345", at=1_000_000_000) is False

    def test_tolerance_plus_ou_moins_un_intervalle(self) -> None:
        """Un décalage d'horloge de ±30s doit rester accepté (RFC 6238)."""
        secret = generate_totp_secret()
        code = totp_now(secret, at=1_000_000_000)
        # +30s : un pas de tolérance plus loin, toujours accepté.
        assert verify_totp_code(secret, code, at=1_000_000_030) is True
        # +90s : trois pas plus loin, hors tolérance.
        assert verify_totp_code(secret, code, at=1_000_000_090) is False

    def test_secret_different_produit_un_code_different(self) -> None:
        secret_a = generate_totp_secret()
        secret_b = generate_totp_secret()
        assert totp_now(secret_a, at=1_000_000_000) != totp_now(secret_b, at=1_000_000_000)


# ---------------------------------------------------------------------------
# Unitaire — codes de secours
# ---------------------------------------------------------------------------


class TestCodesDeSecours:
    def test_genere_dix_codes_par_defaut(self) -> None:
        codes = generate_backup_codes()
        assert len(codes) == 10
        assert len(set(codes)) == 10  # tous distincts

    def test_code_hache_ne_contient_pas_le_code_en_clair(self) -> None:
        code = "ABCDE-FGH"
        hashed = hash_backup_code(code)
        assert code not in hashed

    def test_verify_backup_code_accepte_le_bon_code(self) -> None:
        code = generate_backup_codes(1)[0]
        assert verify_backup_code(code, hash_backup_code(code)) is True

    def test_verify_backup_code_est_insensible_a_la_casse(self) -> None:
        """Un exploitant qui recopie un code à la main peut le taper en
        minuscules : le format canonique est uppercase, la vérification doit
        rester tolérante."""
        code = generate_backup_codes(1)[0]
        hashed = hash_backup_code(code)
        assert verify_backup_code(code.lower(), hashed) is True

    def test_consume_backup_code_usage_unique(self, memory_db: sqlite3.Connection) -> None:
        """Le cœur de la garantie « usage unique » : un code consommé une
        fois doit être refusé la seconde fois."""
        memory_db.execute(
            "INSERT INTO auth_users (username, password_hash) VALUES (?, ?)",
            ("bob", hash_password("x")),
        )
        codes = generate_backup_codes(3)
        store_backup_codes(memory_db, "bob", codes)

        assert consume_backup_code(memory_db, "bob", codes[0]) is True
        # REJOUÉ : le même code ne doit plus jamais être accepté.
        assert consume_backup_code(memory_db, "bob", codes[0]) is False
        # Les autres codes restent valides.
        assert consume_backup_code(memory_db, "bob", codes[1]) is True

    def test_consume_backup_code_refuse_un_code_inconnu(
        self, memory_db: sqlite3.Connection
    ) -> None:
        memory_db.execute(
            "INSERT INTO auth_users (username, password_hash) VALUES (?, ?)",
            ("bob", hash_password("x")),
        )
        store_backup_codes(memory_db, "bob", generate_backup_codes(2))
        assert consume_backup_code(memory_db, "bob", "ZZZZZ-ZZZ") is False


# ---------------------------------------------------------------------------
# Unitaire — session signée
# ---------------------------------------------------------------------------


class TestSession:
    def test_un_cookie_valide_rend_le_bon_username(self) -> None:
        cookie = new_session_cookie("alice", "secret-de-test")
        assert verify_session(cookie, "secret-de-test", max_age_seconds=3600) == "alice"

    def test_un_cookie_signe_avec_un_autre_secret_est_refuse(self) -> None:
        cookie = new_session_cookie("alice", "secret-a")
        assert verify_session(cookie, "secret-b", max_age_seconds=3600) is None

    def test_un_cookie_trafique_est_refuse(self) -> None:
        """Changer le username sans re-signer doit être détecté (intégrité)."""
        cookie = new_session_cookie("alice", "secret-de-test")
        _, issued_at, mac = cookie.split(".", 2)
        trafique = f"attacker.{issued_at}.{mac}"
        assert verify_session(trafique, "secret-de-test", max_age_seconds=3600) is None

    def test_un_cookie_expire_est_refuse(self) -> None:
        import hashlib
        import hmac as hmac_module

        old_timestamp = int(time.time()) - 10_000
        raw = f"alice.{old_timestamp}"
        mac = hmac_module.new(
            b"secret-de-test", raw.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        cookie = f"{raw}.{mac}"
        assert verify_session(cookie, "secret-de-test", max_age_seconds=3600) is None

    def test_format_invalide_est_refuse_sans_lever(self) -> None:
        assert verify_session("nimportequoi", "secret", max_age_seconds=3600) is None
        assert verify_session("", "secret", max_age_seconds=3600) is None


# ---------------------------------------------------------------------------
# Unitaire — limitation de tentatives
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_bloque_apres_n_tentatives(self) -> None:
        limiter = RateLimiter(max_attempts=3, window_seconds=60)
        now = 1_000_000.0
        for _ in range(3):
            assert limiter.is_blocked("1.2.3.4", now=now) is False
            limiter.register_attempt("1.2.3.4", now=now)
        assert limiter.is_blocked("1.2.3.4", now=now) is True

    def test_fenetre_glissante_libere_apres_expiration(self) -> None:
        limiter = RateLimiter(max_attempts=2, window_seconds=60)
        limiter.register_attempt("ip", now=1000.0)
        limiter.register_attempt("ip", now=1001.0)
        assert limiter.is_blocked("ip", now=1002.0) is True
        # 61s plus tard : la fenêtre a glissé, les tentatives sont expirées.
        assert limiter.is_blocked("ip", now=1062.0) is False

    def test_reset_debloque_immediatement(self) -> None:
        limiter = RateLimiter(max_attempts=1, window_seconds=60)
        limiter.register_attempt("ip", now=1000.0)
        assert limiter.is_blocked("ip", now=1000.0) is True
        limiter.reset("ip")
        assert limiter.is_blocked("ip", now=1000.0) is False

    def test_deux_cles_sont_independantes(self) -> None:
        limiter = RateLimiter(max_attempts=1, window_seconds=60)
        limiter.register_attempt("ip-a", now=1000.0)
        assert limiter.is_blocked("ip-a", now=1000.0) is True
        assert limiter.is_blocked("ip-b", now=1000.0) is False


# ---------------------------------------------------------------------------
# Unitaire — admin initial (résolution depuis l'environnement)
# ---------------------------------------------------------------------------


class TestBootstrapAdmin:
    def test_mot_de_passe_fourni_est_utilise_haches(self) -> None:
        admin = resolve_bootstrap_admin(env_user="admin", env_password="MonMotDePasse!")
        assert admin.generated is False
        assert admin.plaintext_if_generated is None
        assert verify_password("MonMotDePasse!", admin.password_hash) is True

    def test_mot_de_passe_absent_genere_un_mot_de_passe_aleatoire(self) -> None:
        """DÉCISION DE CONCEPTION : pas de défaut faible type "admin" — un mot
        de passe aléatoire est généré (voir docstring de `BootstrapAdmin`)."""
        admin = resolve_bootstrap_admin(env_user="admin", env_password="")
        assert admin.generated is True
        assert admin.plaintext_if_generated is not None
        assert len(admin.plaintext_if_generated) >= 16
        assert verify_password(admin.plaintext_if_generated, admin.password_hash) is True

    def test_deux_generations_produisent_des_mots_de_passe_differents(self) -> None:
        admin_a = resolve_bootstrap_admin(env_user="admin", env_password="")
        admin_b = resolve_bootstrap_admin(env_user="admin", env_password="")
        assert admin_a.plaintext_if_generated != admin_b.plaintext_if_generated

    def test_username_par_defaut_est_admin(self) -> None:
        admin = resolve_bootstrap_admin(env_user="", env_password="x")
        assert admin.username == "admin"

    def test_ensure_bootstrap_user_necrase_jamais_un_utilisateur_existant(
        self, memory_db: sqlite3.Connection
    ) -> None:
        """Un exploitant qui a changé son mot de passe depuis l'écran ne doit
        JAMAIS le voir réinitialisé par un redémarrage (piège d'UX documenté)."""
        memory_db.execute(
            "INSERT INTO auth_users (username, password_hash, is_default_password) "
            "VALUES (?, ?, 0)",
            ("admin", hash_password("MotDePasseChangeParLUtilisateur")),
        )
        memory_db.commit()

        admin = resolve_bootstrap_admin(env_user="admin", env_password="ValeurEnvDifferente")
        ensure_bootstrap_user(memory_db, admin)

        user = get_auth_user(memory_db, "admin")
        assert user is not None
        assert verify_password("MotDePasseChangeParLUtilisateur", user.password_hash) is True
        assert verify_password("ValeurEnvDifferente", user.password_hash) is False

    def test_mot_de_passe_fourni_en_env_ne_pose_pas_le_drapeau_par_defaut(
        self, memory_db: sqlite3.Connection
    ) -> None:
        """DÉFAUT MESURÉ À L'ÉCRAN (2026-08-09) : le bandeau « mot de passe par
        défaut toujours actif » s'affichait alors même qu'un mot de passe était
        explicitement fourni en `.env` (`OKVORADO_AUTH_PASSWORD`). Cause :
        `ensure_bootstrap_user` écrivait `is_default_password` à 1 EN DUR sur
        l'INSERT, sans lire `admin.generated`. Ce test aurait échoué avant le
        correctif (il aurait affirmé `True`).

        SECRET_OK: "MotDePasseTest2026" est une valeur de test arbitraire,
        même pattern que le reste du fichier (voir docstring de module)."""
        admin = resolve_bootstrap_admin(
            env_user="admin", env_password="MotDePasseTest2026"
        )
        ensure_bootstrap_user(memory_db, admin)

        user = get_auth_user(memory_db, "admin")
        assert user is not None
        assert user.is_default_password is False

    def test_mot_de_passe_genere_pose_bien_le_drapeau_par_defaut(
        self, memory_db: sqlite3.Connection
    ) -> None:
        """Symétrique du test précédent : sans `OKVORADO_AUTH_PASSWORD`, le
        mot de passe est généré aléatoirement et le bandeau DOIT s'afficher —
        c'est le seul cas où il est légitime."""
        admin = resolve_bootstrap_admin(env_user="admin", env_password="")
        ensure_bootstrap_user(memory_db, admin)

        user = get_auth_user(memory_db, "admin")
        assert user is not None
        assert user.is_default_password is True


class TestReconcileBootstrapPassword:
    """Cas limite explicitement demandé (2026-08-09) : `.env` renseigné APRÈS
    un premier démarrage sans mot de passe — le bandeau doit disparaître au
    redémarrage suivant, sans que l'exploitant passe par l'écran Sécurité.

    SECRET_OK: "MotDePasseTest2026" / "ValeurEnvTardive" sont des valeurs de
    test arbitraires, même pattern que le reste du fichier."""

    def test_env_fourni_apres_coup_leve_le_drapeau_au_redemarrage(
        self, memory_db: sqlite3.Connection
    ) -> None:
        premier_demarrage = resolve_bootstrap_admin(env_user="admin", env_password="")
        ensure_bootstrap_user(memory_db, premier_demarrage)
        assert get_auth_user(memory_db, "admin").is_default_password is True  # type: ignore[union-attr]

        redemarrage = resolve_bootstrap_admin(
            env_user="admin", env_password="MotDePasseTest2026"
        )
        ensure_bootstrap_user(memory_db, redemarrage)  # no-op, l'utilisateur existe déjà
        reconcile_bootstrap_password(memory_db, redemarrage)

        user = get_auth_user(memory_db, "admin")
        assert user is not None
        assert user.is_default_password is False
        assert verify_password("MotDePasseTest2026", user.password_hash) is True

    def test_necrase_jamais_un_mot_de_passe_deja_change_par_lecran(
        self, memory_db: sqlite3.Connection
    ) -> None:
        """Même garde que `ensure_bootstrap_user` : un `.env` qui traîne un
        ancien mot de passe ne doit jamais écraser un choix explicite déjà
        fait depuis l'écran Sécurité."""
        memory_db.execute(
            "INSERT INTO auth_users (username, password_hash, is_default_password) "
            "VALUES (?, ?, 0)",
            ("admin", hash_password("MotDePasseChangeParLUtilisateur")),
        )
        memory_db.commit()

        admin = resolve_bootstrap_admin(env_user="admin", env_password="ValeurEnvTardive")
        reconcile_bootstrap_password(memory_db, admin)

        user = get_auth_user(memory_db, "admin")
        assert user is not None
        assert verify_password("MotDePasseChangeParLUtilisateur", user.password_hash) is True

    def test_sans_env_ne_touche_rien(self, memory_db: sqlite3.Connection) -> None:
        """Redémarrage sans `.env` (toujours généré) : rien à réconcilier."""
        admin = resolve_bootstrap_admin(env_user="admin", env_password="")
        ensure_bootstrap_user(memory_db, admin)

        autre_generation = resolve_bootstrap_admin(env_user="admin", env_password="")
        reconcile_bootstrap_password(memory_db, autre_generation)

        user = get_auth_user(memory_db, "admin")
        assert user is not None
        assert user.is_default_password is True


class TestResolveSessionSecret:
    def test_secret_fourni_est_conserve_tel_quel(self) -> None:
        secret, generated = resolve_session_secret(env_secret="ma-cle-fixe")
        assert secret == "ma-cle-fixe"
        assert generated is False

    def test_secret_absent_est_genere_aleatoirement(self) -> None:
        secret_a, generated_a = resolve_session_secret(env_secret="")
        secret_b, _ = resolve_session_secret(env_secret="")
        assert generated_a is True
        assert secret_a != secret_b
        assert len(secret_a) >= 32


# ---------------------------------------------------------------------------
# Bout en bout — protection réelle des routes via TestClient(app)
# ---------------------------------------------------------------------------


@pytest.fixture
def auth_db() -> Generator[sqlite3.Connection]:
    """Base SQLite dédiée à l'authentification pour les tests bout en bout,
    câblée à la place de la connexion réelle le temps du test."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def client_sans_session(auth_db: sqlite3.Connection) -> Generator[TestClient]:
    """Client HTTP SANS cookie de session — pour prouver le refus."""
    app.dependency_overrides[auth_router.get_db_connection] = lambda: auth_db
    try:
        yield TestClient(app, follow_redirects=False)
    finally:
        app.dependency_overrides.pop(auth_router.get_db_connection, None)


def _seed_user(auth_db: sqlite3.Connection, username: str, password: str) -> None:
    auth_db.execute(
        "INSERT INTO auth_users (username, password_hash, is_default_password) "
        "VALUES (?, ?, 0)",
        (username, hash_password(password)),
    )
    auth_db.commit()


class TestHealthAccessibleSansAuthentification:
    """LE test le plus important du lot : sans lui, le HEALTHCHECK du
    Dockerfile échoue et le conteneur ne devient jamais `healthy`."""

    def test_health_repond_200_sans_cookie(self, client_sans_session: TestClient) -> None:
        response = client_sans_session.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_login_get_accessible_sans_cookie(self, client_sans_session: TestClient) -> None:
        response = client_sans_session.get("/login")
        assert response.status_code == 200

    def test_static_accessible_sans_cookie(self, client_sans_session: TestClient) -> None:
        """Sans cette allowlist, la page de connexion s'afficherait sans CSS."""
        response = client_sans_session.get("/static/style.css")
        assert response.status_code == 200


class TestRouteProtegeeSansSession:
    def test_route_protegee_redirige_vers_login_sans_session(
        self, client_sans_session: TestClient
    ) -> None:
        response = client_sans_session.get("/exporters")
        assert response.status_code == 303
        assert response.headers["location"].endswith("/login")

    def test_requete_htmx_sans_session_recoit_hx_redirect(
        self, client_sans_session: TestClient
    ) -> None:
        """Sans `HX-Redirect`, htmx swapperait `false` sur un 4xx générique
        (voir `app/static/htmx-config.js`) — l'utilisateur ne verrait RIEN."""
        response = client_sans_session.get("/exporters", headers={"HX-Request": "true"})
        assert response.status_code == 401
        assert response.headers.get("HX-Redirect", "").endswith("/login")


class TestRouteProtegeeAvecSession:
    def test_route_protegee_accessible_avec_session_valide(
        self, auth_db: sqlite3.Connection
    ) -> None:
        app.dependency_overrides[auth_router.get_db_connection] = lambda: auth_db
        try:
            client = TestClient(app)
            cookie = new_session_cookie("test-user", app.state.auth_session_secret)
            client.cookies.set("okvorado_session", cookie)
            response = client.get("/exporters")
            assert response.status_code == 200
        finally:
            app.dependency_overrides.pop(auth_router.get_db_connection, None)


class TestFluxDeConnexion:
    def test_mot_de_passe_correct_ouvre_une_session(
        self, client_sans_session: TestClient, auth_db: sqlite3.Connection
    ) -> None:
        _seed_user(auth_db, "admin", "MonMotDePasse!")
        response = client_sans_session.post(
            "/login", data={"username": "admin", "password": "MonMotDePasse!"}
        )
        assert response.status_code == 303
        assert "okvorado_session" in response.cookies

    def test_mot_de_passe_incorrect_est_refuse(
        self, client_sans_session: TestClient, auth_db: sqlite3.Connection
    ) -> None:
        _seed_user(auth_db, "admin", "MonMotDePasse!")
        response = client_sans_session.post(
            "/login", data={"username": "admin", "password": "mauvais"}
        )
        assert response.status_code == 401
        assert "okvorado_session" not in response.cookies

    def test_message_erreur_identique_compte_existant_ou_non(
        self, client_sans_session: TestClient, auth_db: sqlite3.Connection
    ) -> None:
        """Ne doit JAMAIS révéler si le compte existe (énumération de comptes)."""
        _seed_user(auth_db, "admin", "MonMotDePasse!")
        reponse_mauvais_mdp = client_sans_session.post(
            "/login", data={"username": "admin", "password": "mauvais"}
        )
        reponse_compte_inconnu = client_sans_session.post(
            "/login", data={"username": "inconnu", "password": "quelconque"}
        )
        assert reponse_mauvais_mdp.status_code == reponse_compte_inconnu.status_code == 401
        # Même contenu de page d'erreur (le texte du message générique).
        assert "Identifiant ou mot de passe incorrect" in reponse_mauvais_mdp.text
        assert "Identifiant ou mot de passe incorrect" in reponse_compte_inconnu.text

    def test_limitation_de_tentatives_bloque_apres_n_echecs(
        self, client_sans_session: TestClient, auth_db: sqlite3.Connection
    ) -> None:
        from app.config import settings

        _seed_user(auth_db, "admin", "MonMotDePasse!")
        auth_router.login_rate_limiter.reset("testclient")

        for _ in range(settings.auth_login_max_attempts):
            client_sans_session.post(
                "/login", data={"username": "admin", "password": "mauvais"}
            )

        response = client_sans_session.post(
            "/login", data={"username": "admin", "password": "MonMotDePasse!"}
        )
        assert response.status_code == 429
        auth_router.login_rate_limiter.reset("testclient")

    def test_totp_actif_exige_un_code_apres_mot_de_passe_correct(
        self, client_sans_session: TestClient, auth_db: sqlite3.Connection
    ) -> None:
        _seed_user(auth_db, "admin", "MonMotDePasse!")
        secret = generate_totp_secret()
        set_totp_secret_pending(auth_db, "admin", secret)
        auth_db.execute("UPDATE auth_users SET totp_enabled = 1 WHERE username = 'admin'")
        auth_db.commit()

        # Sans code : pas d'erreur, mais pas de session non plus — l'écran
        # redemande le code (require_totp).
        response = client_sans_session.post(
            "/login", data={"username": "admin", "password": "MonMotDePasse!"}
        )
        assert response.status_code == 200
        assert "okvorado_session" not in response.cookies

        # Avec le bon code : session ouverte.
        code = totp_now(secret)
        response = client_sans_session.post(
            "/login",
            data={"username": "admin", "password": "MonMotDePasse!", "totp_code": code},
        )
        assert response.status_code == 303
        assert "okvorado_session" in response.cookies

    def test_totp_actif_refuse_un_code_incorrect(
        self, client_sans_session: TestClient, auth_db: sqlite3.Connection
    ) -> None:
        _seed_user(auth_db, "admin", "MonMotDePasse!")
        secret = generate_totp_secret()
        set_totp_secret_pending(auth_db, "admin", secret)
        auth_db.execute("UPDATE auth_users SET totp_enabled = 1 WHERE username = 'admin'")
        auth_db.commit()

        response = client_sans_session.post(
            "/login",
            data={"username": "admin", "password": "MonMotDePasse!", "totp_code": "000000"},
        )
        assert response.status_code == 401
        assert "okvorado_session" not in response.cookies

    def test_totp_actif_accepte_un_code_de_secours_a_usage_unique(
        self, client_sans_session: TestClient, auth_db: sqlite3.Connection
    ) -> None:
        _seed_user(auth_db, "admin", "MonMotDePasse!")
        secret = generate_totp_secret()
        set_totp_secret_pending(auth_db, "admin", secret)
        auth_db.execute("UPDATE auth_users SET totp_enabled = 1 WHERE username = 'admin'")
        auth_db.commit()
        codes = generate_backup_codes(2)
        store_backup_codes(auth_db, "admin", codes)

        response = client_sans_session.post(
            "/login",
            data={
                "username": "admin",
                "password": "MonMotDePasse!",
                "totp_code": codes[0],
            },
        )
        assert response.status_code == 303
        assert "okvorado_session" in response.cookies

        # Le code de secours utilisé ne doit plus jamais fonctionner.
        client2 = TestClient(app, follow_redirects=False)
        app.dependency_overrides[auth_router.get_db_connection] = lambda: auth_db
        response2 = client2.post(
            "/login",
            data={
                "username": "admin",
                "password": "MonMotDePasse!",
                "totp_code": codes[0],
            },
        )
        assert response2.status_code == 401


class TestLogout:
    def test_logout_supprime_le_cookie_de_session(self, auth_db: sqlite3.Connection) -> None:
        app.dependency_overrides[auth_router.get_db_connection] = lambda: auth_db
        try:
            client = TestClient(app, follow_redirects=False)
            cookie = new_session_cookie("test-user", app.state.auth_session_secret)
            client.cookies.set("okvorado_session", cookie)
            response = client.post("/logout")
            assert response.status_code == 303
            set_cookie_header = response.headers.get("set-cookie", "")
            assert "okvorado_session=" in set_cookie_header
        finally:
            app.dependency_overrides.pop(auth_router.get_db_connection, None)


# ---------------------------------------------------------------------------
# Pas de secret dans les logs — vérification statique du code
# ---------------------------------------------------------------------------


class TestAucunSecretDansLesLogs:
    def test_verify_password_nemet_jamais_le_mot_de_passe_dans_un_message_erreur(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        verify_password("MotDePasseSecretUnique42", "hash-corrompu")
        assert "MotDePasseSecretUnique42" not in caplog.text


# ---------------------------------------------------------------------------
# Bandeau « mot de passe par défaut » — bout en bout via le middleware réel
# ---------------------------------------------------------------------------
#
# DÉFAUT MESURÉ À L'ÉCRAN (2026-08-09) : le middleware `require_authentication`
# (app/main.py) lit `is_default_password` via SA PROPRE connexion SQLite
# (`sqlite3.connect(settings.sqlite_path)`), indépendante des
# `app.dependency_overrides` utilisés par les routers. Un test qui ne
# monkeypatch que `auth_router.get_db_connection` ne couvrirait donc PAS le
# chemin réel qui a produit le bandeau erroné — d'où la fixture dédiée
# `fichier_sqlite_reel` ci-dessous, seule à passer par `settings.sqlite_path`.


@pytest.fixture
def fichier_sqlite_reel(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> Generator[str]:
    """Base SQLite sur disque, câblée à la place de `settings.sqlite_path` —
    seul moyen de couvrir le middleware `require_authentication`, qui ouvre
    sa propre connexion sans passer par `app.dependency_overrides`."""
    import app.main as main_module

    db_path = str(tmp_path / "okvorado-test.db")
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()

    monkeypatch.setattr(main_module.settings, "sqlite_path", db_path)
    yield db_path


class TestBandeauMotDePasseParDefaut:
    """Le bandeau ne doit s'afficher QUE si le mot de passe est celui généré
    aléatoirement au premier démarrage — jamais quand l'exploitant en a fourni
    un via `.env` ou changé un depuis l'écran Sécurité."""

    def _seed_user_avec_drapeau(
        self, db_path: str, username: str, *, is_default_password: bool
    ) -> None:
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO auth_users (username, password_hash, is_default_password) "
            "VALUES (?, ?, ?)",
            (username, hash_password("peu-importe-ici"), 1 if is_default_password else 0),
        )
        conn.commit()
        conn.close()

    def test_mot_de_passe_fourni_najamais_le_bandeau(
        self, fichier_sqlite_reel: str
    ) -> None:
        """Reproduit le défaut mesuré : `OKVORADO_AUTH_PASSWORD` fourni ->
        `is_default_password=0` en base -> le bandeau ne doit PAS apparaître."""
        self._seed_user_avec_drapeau(
            fichier_sqlite_reel, "test-user", is_default_password=False
        )
        client = TestClient(app, follow_redirects=False)
        cookie = new_session_cookie("test-user", app.state.auth_session_secret)
        client.cookies.set("okvorado_session", cookie)

        response = client.get("/exporters")

        assert response.status_code == 200
        assert "default-password-banner" not in response.text
        assert "Mot de passe par défaut toujours actif" not in response.text

    def test_mot_de_passe_genere_affiche_le_bandeau(
        self, fichier_sqlite_reel: str
    ) -> None:
        """Cas où le bandeau EST légitime : mot de passe généré, jamais changé."""
        self._seed_user_avec_drapeau(
            fichier_sqlite_reel, "test-user", is_default_password=True
        )
        client = TestClient(app, follow_redirects=False)
        cookie = new_session_cookie("test-user", app.state.auth_session_secret)
        client.cookies.set("okvorado_session", cookie)

        response = client.get("/exporters")

        assert response.status_code == 200
        assert "default-password-banner" in response.text
        assert "Mot de passe par défaut toujours actif" in response.text


# ---------------------------------------------------------------------------
# Mise en page du bandeau — ce qui est VÉRIFIABLE STATIQUEMENT
# ---------------------------------------------------------------------------
#
# HONNÊTETÉ MÉTHODOLOGIQUE : un test de structure HTML/CSS ne prouve PAS
# l'absence de chevauchement visuel (ça dépend du rendu réel du navigateur —
# flex-wrap, largeurs de police, largeur de viewport). Le défaut mesuré
# (bannière top=56/bottom=123 chevauchant le menu top=47/bottom=116) a été
# constaté À L'ÉCRAN, pas par un test. Ce qui suit couvre uniquement ce qui
# est vérifiable sans navigateur : le bandeau est HORS du bloc de navigation
# dans le DOM, porte la classe attendue, et cette classe existe dans le CSS
# avec une règle qui ne fige plus la hauteur de la topbar (cause racine du
# chevauchement : `height: 56px` fixe + `flex-wrap: wrap`).


class TestStructureBandeauEtMenu:
    def test_le_bandeau_est_hors_du_bloc_nav_dans_le_template(self) -> None:
        """Le bandeau doit être un frère du <nav>, jamais un enfant — sinon il
        hériterait du `flex-wrap` de `.nav` et le chevauchement se
        reproduirait sous une autre forme."""
        base_html = Path("app/templates/base.html").read_text(encoding="utf-8")
        nav_start = base_html.index('<nav class="nav">')
        nav_end = base_html.index("</nav>") + len("</nav>")
        nav_block = base_html[nav_start:nav_end]
        assert "default-password-banner" not in nav_block

        banner_start = base_html.index("default-password-banner")
        assert banner_start > nav_end, (
            "le bandeau doit apparaître APRÈS la fermeture de <nav> dans le document"
        )

    def test_la_classe_default_password_banner_existe_dans_le_css(self) -> None:
        css = Path("app/static/style.css").read_text(encoding="utf-8")
        assert ".default-password-banner" in css

    def test_la_topbar_ne_fige_plus_une_hauteur_fixe(self) -> None:
        """CAUSE RACINE du chevauchement mesuré (2026-08-09) : `.topbar` avait
        `height: 56px` fixe combiné à `flex-wrap: wrap` — dès que son contenu
        (marque + 10 liens + lien externe + bouton déconnexion) ne tenait plus
        sur une ligne, il débordait de la boîte réservée tout en restant
        `position: sticky`, chevauchant le bandeau qui suit dans le flux.
        `min-height` laisse la boîte grandir avec son contenu réel."""
        css = Path("app/static/style.css").read_text(encoding="utf-8")
        topbar_start = css.index(".topbar {")
        topbar_end = css.index("}", topbar_start)
        # Ne garde que les déclarations CSS effectives (une par ligne, hors
        # commentaires) : le bloc contient un commentaire qui MENTIONNE
        # "height: 56px" en prose pour expliquer la cause racine — chercher
        # la sous-chaîne brute dans tout le bloc matcherait ce commentaire à
        # tort, pas une déclaration active.
        declaration_lines = [
            line.strip()
            for line in css[topbar_start:topbar_end].splitlines()
            if line.strip().endswith(";")
        ]
        assert any(line.startswith("min-height") for line in declaration_lines)
        assert not any(line.startswith("height:") for line in declaration_lines)
