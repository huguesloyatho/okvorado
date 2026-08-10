"""Router LOT auth — connexion, déconnexion, réglages de sécurité (TOTP, mot de passe).

Routes :
  GET  /login              formulaire de connexion
  POST /login               vérifie identifiant + mot de passe (+ code TOTP si activé)
  POST /logout               efface le cookie de session
  GET  /settings/security    écran Paramètres : changer le mot de passe, activer/désactiver le TOTP
  POST /settings/security/password       change le mot de passe
  POST /settings/security/totp/start     génère un secret TOTP en attente + QR
  POST /settings/security/totp/confirm   vérifie le premier code, active le TOTP,
                                          génère les codes de secours
  POST /settings/security/totp/disable   désactive le TOTP (purge secret + codes de secours)

Toute la logique cryptographique (hachage, TOTP, session signée, rate limiter)
vit dans `app.auth` — ce module ne fait que traduire des requêtes HTTP en
appels à cette couche, comme les autres routers du projet (cf. `config.py`).
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.auth import (
    RateLimiter,
    consume_backup_code,
    count_unused_backup_codes,
    disable_totp,
    enable_totp,
    generate_backup_codes,
    generate_totp_secret,
    get_auth_user,
    new_session_cookie,
    set_password,
    set_totp_secret_pending,
    store_backup_codes,
    totp_provisioning_uri,
    touch_last_login,
    verify_password,
    verify_totp_code,
)
from app.config import settings as default_settings

log = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])

login_rate_limiter = RateLimiter(
    max_attempts=default_settings.auth_login_max_attempts,
    window_seconds=default_settings.auth_login_window_seconds,
)
"""Instance PARTAGÉE, au niveau module — une fenêtre glissante en mémoire n'a
de sens que si toutes les requêtes /login voient le même compteur, jamais une
instance par requête (qui repartirait de zéro à chaque tentative)."""

_GENERIC_LOGIN_ERROR = "Identifiant ou mot de passe incorrect."
"""Message IDENTIQUE que l'utilisateur existe ou non : distinguer les deux cas
révélerait à un attaquant quels identifiants sont valides (énumération de
comptes)."""


# ---------------------------------------------------------------------------
# Dépendances — placeholders câblés par app/main.py
# ---------------------------------------------------------------------------


def get_db_connection() -> sqlite3.Connection:
    raise RuntimeError(
        "get_db_connection non câblée : app/main.py doit surcharger cette "
        "dépendance avec la connexion SQLite réelle."
    )


def get_templates() -> Jinja2Templates:
    raise RuntimeError("get_templates non câblée : app/main.py doit surcharger cette dépendance.")


def get_session_secret() -> str:
    raise RuntimeError(
        "get_session_secret non câblée : app/main.py doit surcharger cette "
        "dépendance avec `app.state.auth_session_secret`."
    )


DbConnection = Annotated[sqlite3.Connection, Depends(get_db_connection)]
Templates = Annotated[Jinja2Templates, Depends(get_templates)]
SessionSecret = Annotated[str, Depends(get_session_secret)]


def _client_ip(request: Request) -> str:
    """Clé de rate-limiting. `client.host` suffit ici : pas de reverse proxy
    supposé dans le périmètre par défaut (contrainte "zéro dépendance à
    l'infra du homelab") — X-Forwarded-For n'est pas fiable sans proxy de
    confiance en amont qui le pose lui-même."""
    return request.client.host if request.client else "inconnu"


# ---------------------------------------------------------------------------
# Connexion / déconnexion
# ---------------------------------------------------------------------------


@router.get("/login", response_class=HTMLResponse)
def get_login_page(request: Request, templates: Templates, error: str = "") -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": error, "active_page": "login"},
    )


@router.post("/login", response_class=HTMLResponse)
def post_login(
    request: Request,
    templates: Templates,
    conn: DbConnection,
    session_secret: SessionSecret,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    totp_code: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Vérifie identifiant + mot de passe, puis le code TOTP si activé.

    Limitation de tentatives par IP : protège contre la force brute sur le
    mot de passe sans nécessiter de service externe (Redis, fail2ban...).
    """
    ip = _client_ip(request)
    if login_rate_limiter.is_blocked(ip):
        log.error("post_login: trop de tentatives depuis %s", ip)
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "error": "Trop de tentatives. Réessayez dans quelques minutes.",
                "active_page": "login",
            },
            status_code=429,
        )

    login_rate_limiter.register_attempt(ip)

    user = get_auth_user(conn, username.strip())
    password_ok = user is not None and verify_password(password, user.password_hash)

    if not password_ok:
        # Message générique : ne révèle jamais si c'est l'identifiant ou le
        # mot de passe qui est en cause, ni si le compte existe.
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": _GENERIC_LOGIN_ERROR, "active_page": "login"},
            status_code=401,
        )

    assert user is not None  # narrows type: password_ok implique user is not None

    if user.totp_enabled:
        if not totp_code:
            return templates.TemplateResponse(
                request,
                "login.html",
                {
                    "error": "",
                    "active_page": "login",
                    "require_totp": True,
                    "username": user.username,
                },
                status_code=200,
            )
        totp_ok = user.totp_secret is not None and verify_totp_code(user.totp_secret, totp_code)
        backup_ok = not totp_ok and consume_backup_code(conn, user.username, totp_code)
        if not (totp_ok or backup_ok):
            return templates.TemplateResponse(
                request,
                "login.html",
                {
                    "error": "Code de vérification incorrect.",
                    "active_page": "login",
                    "require_totp": True,
                    "username": user.username,
                },
                status_code=401,
            )

    login_rate_limiter.reset(ip)
    touch_last_login(conn, user.username)
    cookie_value = new_session_cookie(user.username, session_secret)
    response = RedirectResponse(url=_prefixed("/"), status_code=303)
    _set_session_cookie(response, cookie_value)
    return response


@router.post("/logout")
def post_logout() -> RedirectResponse:
    response = RedirectResponse(url=_prefixed("/login"), status_code=303)
    response.delete_cookie("okvorado_session")
    return response


# ---------------------------------------------------------------------------
# Réglages de sécurité — mot de passe, TOTP « activable sur demande »
# ---------------------------------------------------------------------------


@router.get("/settings/security", response_class=HTMLResponse)
def get_security_settings_page(
    request: Request, templates: Templates, conn: DbConnection
) -> HTMLResponse:
    username = getattr(request.state, "auth_username", None)
    user = get_auth_user(conn, username) if username else None
    backup_codes_left = count_unused_backup_codes(conn, username) if username else 0
    return templates.TemplateResponse(
        request,
        "security_settings.html",
        {
            "active_page": "security_settings",
            "user": user,
            "backup_codes_left": backup_codes_left,
            "totp_setup": None,
            "new_backup_codes": None,
        },
    )


@router.post("/settings/security/password", response_class=HTMLResponse)
def post_change_password(
    request: Request,
    templates: Templates,
    conn: DbConnection,
    current_password: Annotated[str, Form()],
    new_password: Annotated[str, Form()],
) -> HTMLResponse:
    username = getattr(request.state, "auth_username", None)
    user = get_auth_user(conn, username) if username else None

    error: str | None = None
    success: str | None = None
    if user is None or not verify_password(current_password, user.password_hash):
        error = "Mot de passe actuel incorrect."
    elif len(new_password) < 8:
        error = "Le nouveau mot de passe doit compter au moins 8 caractères."
    else:
        set_password(conn, user.username, new_password)
        success = "Mot de passe mis à jour."
        user = get_auth_user(conn, username)

    backup_codes_left = count_unused_backup_codes(conn, username) if username else 0
    return templates.TemplateResponse(
        request,
        "security_settings.html",
        {
            "active_page": "security_settings",
            "user": user,
            "backup_codes_left": backup_codes_left,
            "totp_setup": None,
            "new_backup_codes": None,
            "password_error": error,
            "password_success": success,
        },
    )


@router.post("/settings/security/totp/start", response_class=HTMLResponse)
def post_start_totp(request: Request, templates: Templates, conn: DbConnection) -> HTMLResponse:
    """Génère un secret TOTP en attente de confirmation + son QR (SVG inline).

    Le TOTP n'est PAS activé à cette étape (`totp_enabled` reste faux, voir
    `app.auth.set_totp_secret_pending`) : il faut d'abord prouver, en
    confirmant un premier code, que l'exploitant a bien scanné le QR — sinon
    une erreur de manipulation ici verrouillerait la connexion suivante.
    """
    username = getattr(request.state, "auth_username", None)
    secret = generate_totp_secret()
    set_totp_secret_pending(conn, username, secret)

    uri = totp_provisioning_uri(secret, account=username)
    qr_svg = _render_qr_svg(uri)

    backup_codes_left = count_unused_backup_codes(conn, username) if username else 0
    return templates.TemplateResponse(
        request,
        "security_settings.html",
        {
            "active_page": "security_settings",
            "user": get_auth_user(conn, username),
            "backup_codes_left": backup_codes_left,
            "totp_setup": {"secret": secret, "qr_svg": qr_svg},
            "new_backup_codes": None,
        },
    )


@router.post("/settings/security/totp/confirm", response_class=HTMLResponse)
def post_confirm_totp(
    request: Request,
    templates: Templates,
    conn: DbConnection,
    code: Annotated[str, Form()],
) -> HTMLResponse:
    """Vérifie le premier code avant d'activer réellement le TOTP.

    Sans cette vérification préalable, un secret mal scanné (QR flouté,
    mauvaise app) activerait un TOTP dont l'exploitant ne peut produire aucun
    code valide — verrouillage total à la prochaine connexion.
    """
    username = getattr(request.state, "auth_username", None)
    user = get_auth_user(conn, username) if username else None

    error: str | None = None
    new_codes: list[str] | None = None
    if user is None or user.totp_secret is None:
        error = "Aucune activation TOTP en cours. Relancez depuis le bouton « Activer »."
    elif not verify_totp_code(user.totp_secret, code):
        error = "Code incorrect. Vérifiez l'heure de votre téléphone et réessayez."
    else:
        enable_totp(conn, user.username)
        new_codes = generate_backup_codes()
        store_backup_codes(conn, user.username, new_codes)
        user = get_auth_user(conn, username)

    backup_codes_left = count_unused_backup_codes(conn, username) if username else 0
    return templates.TemplateResponse(
        request,
        "security_settings.html",
        {
            "active_page": "security_settings",
            "user": user,
            "backup_codes_left": backup_codes_left,
            "totp_setup": None,
            "new_backup_codes": new_codes,
            "totp_error": error,
        },
    )


@router.post("/settings/security/totp/disable", response_class=HTMLResponse)
def post_disable_totp(request: Request, templates: Templates, conn: DbConnection) -> HTMLResponse:
    username = getattr(request.state, "auth_username", None)
    if username:
        disable_totp(conn, username)
    user = get_auth_user(conn, username) if username else None
    return templates.TemplateResponse(
        request,
        "security_settings.html",
        {
            "active_page": "security_settings",
            "user": user,
            "backup_codes_left": 0,
            "totp_setup": None,
            "new_backup_codes": None,
            "totp_success": "Authentification à deux facteurs désactivée.",
        },
    )


# ---------------------------------------------------------------------------
# Utilitaires internes
# ---------------------------------------------------------------------------


def _set_session_cookie(response: RedirectResponse, value: str) -> None:
    response.set_cookie(
        "okvorado_session",
        value,
        max_age=default_settings.auth_session_max_age_seconds,
        httponly=True,
        samesite="lax",
        secure=default_settings.auth_cookie_secure,
    )


def _prefixed(path: str) -> str:
    prefix = default_settings.url_prefix
    return f"{prefix}{path}" if prefix else path


def _render_qr_svg(data: str) -> str:
    """QR code en SVG inline — CSP `script-src 'self'` sans CDN : le rendu est
    fait ICI, côté serveur, en pur Python (dépendance `qrcode`, voir
    `app/services/qrcode_svg.py`), jamais chargé depuis un service externe."""
    from app.services.qrcode_svg import render_qr_svg

    return render_qr_svg(data)
