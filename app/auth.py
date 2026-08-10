"""Authentification autonome d'Okvorado — sans dépendance externe.

DEMANDE UTILISATEUR (2026-08-09) : « il faut créer une authentification
autonome a okvorado ... avec un user+mdp définissable dans le fichier .env du
docker-compose pour l'admin initiale. 2fa totp activable sur demande ».

Cohérent avec la contrainte du projet (CLAUDE.md, section « Zéro dépendance à
l'infrastructure du homelab ») : le stack doit démarrer sur une machine nue en
entreprise, sans Authelia/Tailscale/Vault maison. L'authentification vit donc
DANS l'application, pas déléguée à une brique du homelab.

CHOIX DE DÉPENDANCES : `cryptography` est DÉJÀ une dépendance du projet
(pyproject.toml). Elle fournit tout ce dont ce module a besoin :
  - PBKDF2-HMAC-SHA256 pour le hachage du mot de passe (via `hashlib`, stdlib —
    pas besoin de la sortir de `cryptography` non plus : `hashlib.pbkdf2_hmac`
    est en C, constant-time par construction côté implémentation OpenSSL).
  - HMAC-SHA1 pour TOTP (RFC 6238), via `hmac`/`hashlib` stdlib.
Aucune dépendance nouvelle (`pyotp`, `passlib`, `bcrypt`) : chaque paquet
ajouté est un coût pour un stack qui vise la portabilité et l'installation
sur une machine nue — la stdlib + `cryptography` suffisent intégralement ici.
Seule addition réelle du lot : `qrcode` (voir `app/services/qrcode_svg.py`),
pour le rendu du QR TOTP en SVG local — encoder un QR à la main serait un
projet en soi (Reed-Solomon, placement de matrice, masques) et une source de
bugs silencieux, un mauvais compromis pour une fonctionnalité optionnelle.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import sqlite3
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hachage de mot de passe — PBKDF2-HMAC-SHA256
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS = 600_000
"""Nombre d'itérations explicite (recommandation OWASP 2023 pour PBKDF2-SHA256
>= 600 000). Un nombre fixe et documenté plutôt qu'une valeur arbitraire."""

_SALT_BYTES = 16


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Hache un mot de passe en clair avec PBKDF2-HMAC-SHA256, sel aléatoire.

    Format de sortie auto-descriptif : `pbkdf2_sha256$<iterations>$<sel_b64>$<hash_b64>`
    — permet de faire évoluer le nombre d'itérations plus tard sans invalider
    les hashes existants (l'itération réelle est relue depuis le hash stocké,
    jamais supposée constante).

    JAMAIS de MD5/SHA nu : un hash sans sel ni étirement est cassable par table
    arc-en-ciel en un temps négligeable sur un mot de passe court.
    """
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return (
        f"pbkdf2_sha256${iterations}$"
        f"{base64.b64encode(salt).decode('ascii')}$"
        f"{base64.b64encode(digest).decode('ascii')}"
    )


def verify_password(password: str, stored_hash: str) -> bool:
    """Vérifie un mot de passe en clair contre un hash stocké, en temps constant.

    `hmac.compare_digest` évite qu'un attaquant mesure le temps de réponse pour
    déduire progressivement le hash correct (timing attack). Toute anomalie de
    format (hash corrompu, algorithme inconnu) renvoie False plutôt que de
    lever une exception — un mot de passe stocké de travers ne doit jamais se
    traduire en 500, seulement en refus d'authentification.
    """
    try:
        algo, iterations_s, salt_b64, digest_b64 = stored_hash.split("$")
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iterations_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except (ValueError, TypeError):
        log.error("verify_password: format de hash inattendu (pas de secret loggue)")
        return False

    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate, expected)


# ---------------------------------------------------------------------------
# TOTP — RFC 6238 (SHA1, 6 chiffres, période 30 s, tolérance ±1 intervalle)
# ---------------------------------------------------------------------------

TOTP_DIGITS = 6
TOTP_PERIOD_SECONDS = 30
TOTP_TOLERANCE_STEPS = 1
"""Fenêtre de tolérance : ±1 pas de 30 s absorbe le décalage d'horloge courant
entre le serveur et le téléphone de l'exploitant, sans élargir excessivement
la fenêtre d'attaque par rejeu."""


def generate_totp_secret() -> str:
    """Génère un secret TOTP aléatoire, encodé en base32 (format standard RFC 4648).

    160 bits (20 octets) : recommandation RFC 4226 §4 pour HMAC-SHA1, la marge
    de sécurité usuelle au-delà du minimum de 128 bits.
    """
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def _hotp(secret_b32: str, counter: int) -> str:
    """HOTP RFC 4226 — brique de base du TOTP."""
    key = base64.b32decode(secret_b32.upper())
    counter_bytes = counter.to_bytes(8, byteorder="big")
    digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = digest[offset : offset + 4]
    code_int = (int.from_bytes(truncated, byteorder="big") & 0x7FFFFFFF) % (10**TOTP_DIGITS)
    return str(code_int).zfill(TOTP_DIGITS)


def totp_now(secret_b32: str, *, at: float | None = None) -> str:
    """Code TOTP courant pour un secret donné (utile aux tests et à l'affichage)."""
    timestamp = at if at is not None else time.time()
    counter = int(timestamp // TOTP_PERIOD_SECONDS)
    return _hotp(secret_b32, counter)


def verify_totp_code(
    secret_b32: str,
    code: str,
    *,
    at: float | None = None,
    tolerance_steps: int = TOTP_TOLERANCE_STEPS,
) -> bool:
    """Vérifie un code TOTP à ±`tolerance_steps` intervalles de 30 s.

    Comparaison en temps constant sur chaque candidat (même garde que les mots
    de passe) : un TOTP est un secret temporaire mais reste un secret.
    """
    code = code.strip()
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    timestamp = at if at is not None else time.time()
    counter = int(timestamp // TOTP_PERIOD_SECONDS)
    for offset in range(-tolerance_steps, tolerance_steps + 1):
        candidate = _hotp(secret_b32, counter + offset)
        if hmac.compare_digest(candidate, code):
            return True
    return False


def totp_provisioning_uri(secret_b32: str, *, account: str, issuer: str = "Okvorado") -> str:
    """URI `otpauth://` standard, à encoder en QR côté appelant.

    Format RFC (de facto, Google Authenticator) : les authentificateurs TOTP
    du marché (Authenticator, FreeOTP, Bitwarden...) le lisent tous.
    """
    from urllib.parse import quote

    label = quote(f"{issuer}:{account}")
    return (
        f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD_SECONDS}"
    )


# ---------------------------------------------------------------------------
# Codes de secours — à usage unique, hachés en base
# ---------------------------------------------------------------------------

_BACKUP_CODE_COUNT = 10
_BACKUP_CODE_BYTES = 5  # 5 octets -> 8 caractères base32, format lisible XXXXX-XXX


def generate_backup_codes(count: int = _BACKUP_CODE_COUNT) -> list[str]:
    """Génère `count` codes de secours à usage unique, lisibles (ex. `A3F9K-2QZ`).

    Retournés EN CLAIR une seule fois à l'activation, pour affichage/impression
    par l'exploitant — jamais stockés tels quels (voir `hash_backup_code`).
    """
    codes = []
    for _ in range(count):
        raw = base64.b32encode(secrets.token_bytes(_BACKUP_CODE_BYTES)).decode("ascii").rstrip("=")
        codes.append(f"{raw[:5]}-{raw[5:8]}")
    return codes


def hash_backup_code(code: str) -> str:
    """Hache un code de secours avec le même schéma que les mots de passe.

    Itérations réduites (100k) : un code de secours est court (8 caractères
    base32, ~40 bits) et à usage unique — un PBKDF2 à 600k itérations par
    tentative de connexion ralentirait sans bénéfice proportionné, mais un
    hachage reste impératif (jamais de code en clair en base).
    """
    return hash_password(code.strip().upper(), iterations=100_000)


def verify_backup_code(code: str, stored_hash: str) -> bool:
    return verify_password(code.strip().upper(), stored_hash)


# ---------------------------------------------------------------------------
# Session — cookie signé (HMAC), stateless côté serveur
# ---------------------------------------------------------------------------

SESSION_COOKIE_NAME = "okvorado_session"


@dataclass
class SessionPayload:
    """Contenu d'une session authentifiée."""

    username: str
    issued_at: int


def _session_secret_bytes(secret: str) -> bytes:
    return secret.encode("utf-8")


def sign_session(payload: SessionPayload, secret: str) -> str:
    """Construit un cookie de session signé : `username.issued_at.hmac_hex`.

    Stateless (pas de table `sessions` en base) : la signature HMAC-SHA256
    garantit qu'un client ne peut ni forger ni modifier le contenu sans
    connaître `secret`. Compact, pas de purge de session à prévoir côté serveur.
    """
    raw = f"{payload.username}.{payload.issued_at}"
    mac = hmac.new(_session_secret_bytes(secret), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{raw}.{mac}"


def verify_session(cookie_value: str, secret: str, *, max_age_seconds: int) -> str | None:
    """Vérifie un cookie de session ; renvoie le username si valide, sinon None.

    Trois causes de refus, jamais distinguées dans la réponse (n'aide pas un
    attaquant à savoir laquelle) : signature invalide, format inattendu,
    session expirée. Comparaison HMAC en temps constant.
    """
    try:
        username, issued_at_s, mac = cookie_value.split(".", 2)
        issued_at = int(issued_at_s)
    except (ValueError, AttributeError):
        return None

    raw = f"{username}.{issued_at}"
    expected_mac = hmac.new(
        _session_secret_bytes(secret), raw.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_mac, mac):
        return None

    if time.time() - issued_at > max_age_seconds:
        return None

    return username


def new_session_cookie(username: str, secret: str) -> str:
    return sign_session(SessionPayload(username=username, issued_at=int(time.time())), secret)


# ---------------------------------------------------------------------------
# Limitation de tentatives — fenêtre glissante en mémoire
# ---------------------------------------------------------------------------


class RateLimiter:
    """Fenêtre glissante en mémoire, par clé (ex. adresse IP ou username).

    Un stockage en mémoire process suffit ici : Okvorado est déployé en UN
    SEUL conteneur (pas de réplication horizontale dans ce projet — voir
    CLAUDE.md « un seul nœud ClickHouse suffit », même logique de simplicité
    assumée), donc pas de besoin de coordination inter-instances (Redis...).
    Un redémarrage remet le compteur à zéro : acceptable, un redémarrage n'est
    pas un vecteur d'attaque par force brute soutenue.
    """

    def __init__(self, *, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = {}

    def is_blocked(self, key: str, *, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        attempts = self._attempts.get(key, [])
        recent = [t for t in attempts if now - t < self.window_seconds]
        self._attempts[key] = recent
        return len(recent) >= self.max_attempts

    def register_attempt(self, key: str, *, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        self._attempts.setdefault(key, []).append(now)

    def reset(self, key: str) -> None:
        self._attempts.pop(key, None)


# ---------------------------------------------------------------------------
# Compte admin initial — lu depuis l'environnement, haché EN MÉMOIRE au démarrage
# ---------------------------------------------------------------------------


def generate_random_password(length: int = 20) -> str:
    """Mot de passe aléatoire lisible (alphabet sans caractères ambigus)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


@dataclass
class BootstrapAdmin:
    """État de l'admin initial, résolu au démarrage.

    DÉCISION DE CONCEPTION (documentée, tranchée) : que se passe-t-il si
    `OKVORADO_AUTH_PASSWORD` n'est pas défini ?

    Option retenue : (b) génération d'un mot de passe aléatoire, affiché UNE
    SEULE FOIS dans les logs au premier démarrage — PAS un défaut faible
    type "admin".

    POURQUOI : ce projet protège des routes qui écrivent la config Akvorado
    ET REDÉMARRENT DES CONTENEURS, purgent ClickHouse, déclenchent des
    collectes SNMP (cf. CLAUDE.md, ~30 routes POST/DELETE). Un défaut faible
    style "admin/admin" démarre toujours sans .env (confort maximal), mais un
    exploitant qui oublie de fixer OKVORADO_AUTH_PASSWORD se retrouve alors
    avec un identifiant PUBLIQUEMENT CONNU (documenté dans ce fichier même,
    sur Gitea) protégeant des gestes destructifs — un attaquant sur le même
    réseau n'a même pas besoin de deviner. Le générateur aléatoire coûte le
    même "ça démarre toujours sans .env" (la portabilité n'est PAS sacrifiée :
    le stack boot sans intervention), mais élimine la classe de risque
    "mot de passe connu à l'avance". Le prix : l'exploitant DOIT consulter les
    logs au premier démarrage pour se connecter — compromis jugé correct pour
    une app qui pilote un stack réseau de 350 routeurs.

    Dans tous les cas, `is_default_password` reste vrai tant qu'aucun mot de
    passe n'a été changé depuis l'écran Paramètres, et l'écran AVERTIT
    visiblement (bandeau) tant que c'est le cas — l'exploitant qui a lu le
    mot de passe généré dans les logs peut décider de le garder, mais le
    risque reste affiché, jamais masqué.
    """

    username: str
    password_hash: str
    generated: bool
    plaintext_if_generated: str | None


def resolve_bootstrap_admin(*, env_user: str, env_password: str) -> BootstrapAdmin:
    """Résout l'admin initial depuis l'environnement.

    Le mot de passe en clair (fourni ou généré) n'est JAMAIS conservé au-delà
    de cette fonction et de son unique usage (log au démarrage, écriture du
    hash en base) : il ne fuit dans aucune autre variable de longue durée.
    """
    username = env_user.strip() or "admin"
    if env_password:
        return BootstrapAdmin(
            username=username,
            password_hash=hash_password(env_password),
            generated=False,
            plaintext_if_generated=None,
        )
    plaintext = generate_random_password()
    return BootstrapAdmin(
        username=username,
        password_hash=hash_password(plaintext),
        generated=True,
        plaintext_if_generated=plaintext,
    )


def resolve_session_secret(*, env_secret: str) -> tuple[str, bool]:
    """Résout la clé de signature de session.

    Vide -> génération aléatoire au démarrage (deuxième renvoi = True) : les
    sessions ne survivent alors pas à un redémarrage du processus (tous les
    cookies signés avec l'ancienne clé deviennent invalides), ce qui est
    acceptable et documenté — préférable à une clé par défaut connue à
    l'avance (même raisonnement que le mot de passe admin ci-dessus : une
    clé de signature prévisible permettrait de FORGER un cookie de session
    valide pour n'importe quel utilisateur).
    """
    if env_secret:
        return env_secret, False
    return secrets.token_hex(32), True


# ---------------------------------------------------------------------------
# Persistance base — table `auth_users` (créée par app/db.py, voir SCHEMA)
# ---------------------------------------------------------------------------


ROLE_ADMIN = "admin"
ROLE_LECTEUR = "lecteur"
VALID_ROLES = frozenset({ROLE_ADMIN, ROLE_LECTEUR})
"""Deux rôles, décidés d'après les routes RÉELLES de l'application (audit du
2026-08-09) : une majorité d'écrans sont de la CONSULTATION (exportateurs,
inventaire, vues, santé DB), mais un sous-ensemble ÉCRIT — `/config/apply`
réécrit les YAML Akvorado et redémarre des conteneurs, `/api/retention/*/execute`
modifie ou purge ClickHouse, `/app-catalog` et `/views|api/portmap` écrivent en
base. `admin` accède à tout. `lecteur` est cantonné à la consultation : refusé
côté SERVEUR sur toute route d'écriture ET sur l'écran de gestion des comptes
(voir `app.routers.accounts`) — jamais une simple absence de lien dans le menu,
qui ne protège rien contre un accès direct par URL."""


@dataclass
class AuthUser:
    username: str
    password_hash: str
    totp_enabled: bool
    totp_secret: str | None
    is_default_password: bool
    role: str = ROLE_ADMIN
    last_login_at: str | None = None

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN


def ensure_bootstrap_user(conn: sqlite3.Connection, admin: BootstrapAdmin) -> None:
    """Insère l'admin initial en base s'il n'existe aucun utilisateur.

    Idempotent et NON DESTRUCTEUR : si des utilisateurs existent déjà (un
    redémarrage après un changement de mot de passe depuis l'écran), cette
    fonction ne touche RIEN — le hash saisi par l'exploitant ne doit jamais
    être écrasé par le hash dérivé de la variable d'environnement au
    redémarrage suivant (sinon changer son mot de passe serait sans effet
    persistant, un piège d'UX vécu sur d'autres projets du homelab).

    DÉFAUT MESURÉ À L'ÉCRAN (2026-08-09) : `is_default_password` était écrit à
    `1` EN DUR sur cette ligne, sans lire `admin.generated` — donc même un
    déploiement avec `OKVORADO_AUTH_PASSWORD` explicitement fourni en `.env`
    (mot de passe choisi par l'exploitant, jamais généré) recevait le bandeau
    d'avertissement « mot de passe par défaut toujours actif », un faux
    positif permanent. Le champ correct existait déjà sur `BootstrapAdmin`
    (`generated`, `False` quand `env_password` est non vide, résolu dans
    `resolve_bootstrap_admin`) mais n'était jamais consulté ici. Le bandeau ne
    doit s'afficher QUE si le mot de passe initial a été généré aléatoirement.
    """
    existing = conn.execute("SELECT COUNT(*) FROM auth_users").fetchone()[0]
    if existing:
        return
    conn.execute(
        "INSERT INTO auth_users (username, password_hash, is_default_password, role) "
        "VALUES (?, ?, ?, ?)",
        (admin.username, admin.password_hash, 1 if admin.generated else 0, ROLE_ADMIN),
    )
    conn.commit()


def reconcile_bootstrap_password(conn: sqlite3.Connection, admin: BootstrapAdmin) -> None:
    """Adopte un `OKVORADO_AUTH_PASSWORD` défini APRÈS le tout premier démarrage.

    CAS LIMITE explicitement demandé (2026-08-09) : un exploitant démarre
    Okvorado sans `.env` (mot de passe généré, `is_default_password=1`), puis
    ajoute `OKVORADO_AUTH_PASSWORD` au `.env` et redémarre — SANS être passé
    par l'écran Sécurité entre-temps. `ensure_bootstrap_user` ne fait alors
    rien (un utilisateur existe déjà), donc le bandeau resterait affiché à
    tort si rien d'autre n'agit.

    Cette fonction ne s'applique QUE si le mot de passe courant est encore le
    défaut (`is_default_password=1`) ET que l'environnement fournit désormais
    un mot de passe explicite : elle adopte ce mot de passe et lève le
    drapeau, exactement comme si l'exploitant l'avait saisi depuis l'écran
    Sécurité (`set_password`). Si l'exploitant a DÉJÀ changé son mot de passe
    depuis l'écran (`is_default_password=0`), cette fonction ne touche RIEN —
    même garde que `ensure_bootstrap_user` : un `.env` qui traîne un ancien
    mot de passe ne doit jamais écraser un choix explicite plus récent.
    """
    if admin.generated:
        return  # pas de mot de passe fourni par l'environnement : rien à adopter
    row = conn.execute(
        "SELECT is_default_password FROM auth_users WHERE username = ?",
        (admin.username,),
    ).fetchone()
    if row is None or not bool(row[0]):
        return
    conn.execute(
        "UPDATE auth_users SET password_hash = ?, is_default_password = 0 WHERE username = ?",
        (admin.password_hash, admin.username),
    )
    conn.commit()


def get_auth_user(conn: sqlite3.Connection, username: str) -> AuthUser | None:
    row = conn.execute(
        "SELECT username, password_hash, totp_enabled, totp_secret, is_default_password, "
        "role, last_login_at FROM auth_users WHERE username = ?",
        (username,),
    ).fetchone()
    if row is None:
        return None
    return AuthUser(
        username=row[0],
        password_hash=row[1],
        totp_enabled=bool(row[2]),
        totp_secret=row[3],
        is_default_password=bool(row[4]),
        role=row[5],
        last_login_at=row[6],
    )


def set_password(conn: sqlite3.Connection, username: str, new_password: str) -> None:
    conn.execute(
        "UPDATE auth_users SET password_hash = ?, is_default_password = 0 WHERE username = ?",
        (hash_password(new_password), username),
    )
    conn.commit()


def set_totp_secret_pending(conn: sqlite3.Connection, username: str, secret: str) -> None:
    """Enregistre un secret TOTP en attente de confirmation (`totp_enabled` reste faux).

    Tant que le premier code n'est pas vérifié (voir `enable_totp`), l'écran de
    connexion ne réclame aucun code : on ne veut jamais verrouiller
    l'exploitant dehors avec un secret qu'il n'a pas confirmé avoir scanné.
    """
    conn.execute(
        "UPDATE auth_users SET totp_secret = ?, totp_enabled = 0 WHERE username = ?",
        (secret, username),
    )
    conn.commit()


def enable_totp(conn: sqlite3.Connection, username: str) -> None:
    conn.execute("UPDATE auth_users SET totp_enabled = 1 WHERE username = ?", (username,))
    conn.commit()


def disable_totp(conn: sqlite3.Connection, username: str) -> None:
    """Désactive le TOTP et purge le secret + les codes de secours.

    Purge complète (pas seulement `totp_enabled = 0`) : un secret désactivé
    mais laissé en base serait un résidu inutile, et le pattern du projet est
    de ne jamais garder de secret au-delà de son usage (cf. `snmp_v3_*`,
    jamais loggés/persistés hors nécessité)."""
    conn.execute(
        "UPDATE auth_users SET totp_enabled = 0, totp_secret = NULL WHERE username = ?",
        (username,),
    )
    conn.execute("DELETE FROM auth_backup_codes WHERE username = ?", (username,))
    conn.commit()


def store_backup_codes(conn: sqlite3.Connection, username: str, codes: list[str]) -> None:
    """Remplace les codes de secours existants par les nouveaux (hachés)."""
    conn.execute("DELETE FROM auth_backup_codes WHERE username = ?", (username,))
    conn.executemany(
        "INSERT INTO auth_backup_codes (username, code_hash) VALUES (?, ?)",
        [(username, hash_backup_code(code)) for code in codes],
    )
    conn.commit()


def consume_backup_code(conn: sqlite3.Connection, username: str, code: str) -> bool:
    """Vérifie un code de secours et le CONSOMME (usage unique) s'il est valide.

    Chaque code stocké est essayé (peu nombreux, ~10) : un code de secours
    n'est pas indexable directement puisqu'il est haché (même raison que les
    mots de passe — jamais de recherche par valeur en clair)."""
    rows = conn.execute(
        "SELECT id, code_hash FROM auth_backup_codes WHERE username = ? AND used_at IS NULL",
        (username,),
    ).fetchall()
    for row_id, code_hash in rows:
        if verify_backup_code(code, code_hash):
            conn.execute(
                "UPDATE auth_backup_codes SET used_at = datetime('now') WHERE id = ?",
                (row_id,),
            )
            conn.commit()
            return True
    return False


def count_unused_backup_codes(conn: sqlite3.Connection, username: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM auth_backup_codes WHERE username = ? AND used_at IS NULL",
        (username,),
    ).fetchone()
    return int(row[0])


def touch_last_login(conn: sqlite3.Connection, username: str) -> None:
    """Marque l'instant de la connexion réussie — appelé UNIQUEMENT après
    succès complet du flux (mot de passe + TOTP le cas échéant), jamais sur
    une tentative refusée : `last_login_at` doit rester une preuve de
    connexion réelle, pas de tentative."""
    conn.execute(
        "UPDATE auth_users SET last_login_at = datetime('now') WHERE username = ?",
        (username,),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Gestion des comptes (LOT accounts) — réservée aux administrateurs, la
# vérification du rôle appelant vit dans app/routers/accounts.py (garde
# SERVEUR, jamais seulement l'absence de lien dans le menu).
# ---------------------------------------------------------------------------


def list_users(conn: sqlite3.Connection) -> list[AuthUser]:
    rows = conn.execute(
        "SELECT username, password_hash, totp_enabled, totp_secret, is_default_password, "
        "role, last_login_at FROM auth_users ORDER BY username"
    ).fetchall()
    return [
        AuthUser(
            username=row[0],
            password_hash=row[1],
            totp_enabled=bool(row[2]),
            totp_secret=row[3],
            is_default_password=bool(row[4]),
            role=row[5],
            last_login_at=row[6],
        )
        for row in rows
    ]


def count_admins(conn: sqlite3.Connection) -> int:
    """Nombre de comptes `role='admin'` — brique du garde-fou « impossible de
    supprimer/rétrograder le dernier administrateur » (voir
    `app.routers.accounts`)."""
    row = conn.execute(
        "SELECT COUNT(*) FROM auth_users WHERE role = ?", (ROLE_ADMIN,)
    ).fetchone()
    return int(row[0])


def create_user(
    conn: sqlite3.Connection, username: str, password: str, role: str
) -> None:
    """Crée un nouveau compte avec un mot de passe fourni par l'administrateur.

    `is_default_password=1` : même logique que le bootstrap — tant que le
    titulaire n'a pas changé ce mot de passe initial depuis l'écran Sécurité,
    le bandeau d'avertissement reste affiché pour CE compte."""
    conn.execute(
        "INSERT INTO auth_users (username, password_hash, is_default_password, role) "
        "VALUES (?, ?, 1, ?)",
        (username, hash_password(password), role),
    )
    conn.commit()


def delete_user(conn: sqlite3.Connection, username: str) -> None:
    """Supprime un compte et ses codes de secours associés.

    Les garde-fous (dernier admin, auto-suppression) sont vérifiés par
    l'APPELANT (`app.routers.accounts`) AVANT d'appeler cette fonction — elle
    reste volontairement sans condition, comme le reste des primitives de ce
    module (cf. `set_password`, `disable_totp`)."""
    conn.execute("DELETE FROM auth_backup_codes WHERE username = ?", (username,))
    conn.execute("DELETE FROM auth_users WHERE username = ?", (username,))
    conn.commit()


def set_role(conn: sqlite3.Connection, username: str, role: str) -> None:
    """Change le rôle d'un compte. Le garde-fou « ne jamais rétrograder le
    dernier admin » est vérifié par l'appelant, pas ici (même séparation que
    `delete_user`)."""
    conn.execute("UPDATE auth_users SET role = ? WHERE username = ?", (role, username))
    conn.commit()


def admin_reset_password(conn: sqlite3.Connection, username: str, new_password: str) -> None:
    """Réinitialise le mot de passe d'un AUTRE compte, depuis l'écran de
    gestion des comptes.

    Repose le drapeau `is_default_password` : le nouveau mot de passe a été
    choisi par l'administrateur, pas par le titulaire du compte — le même
    bandeau d'avertissement que pour un compte tout juste créé doit
    réapparaître tant que le titulaire ne l'a pas changé lui-même."""
    conn.execute(
        "UPDATE auth_users SET password_hash = ?, is_default_password = 1 WHERE username = ?",
        (hash_password(new_password), username),
    )
    conn.commit()
