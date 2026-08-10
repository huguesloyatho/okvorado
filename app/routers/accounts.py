"""Router LOT accounts — gestion des comptes exploitants.

DEMANDE UTILISATEUR (2026-08-09) : « on a pas de management de compte, etat de
connexion user, déconnexion. Il faut tout ajouter ».

Routes (toutes réservées aux administrateurs — voir `_require_admin`) :
  GET  /accounts                          liste des comptes
  POST /accounts                          crée un compte
  POST /accounts/{username}/role          change le rôle d'un compte
  POST /accounts/{username}/reset-password réinitialise le mot de passe d'un compte
  POST /accounts/{username}/delete        supprime un compte

GARDE-FOUS D'AUTO-VERROUILLAGE (le défaut classique de tout écran de
comptes, explicitement demandé) :
  - impossible de supprimer le DERNIER administrateur ;
  - impossible de RÉTROGRADER le dernier administrateur (le passer en
    'lecteur' aurait le même effet que le supprimer : plus aucun compte ne
    pourrait plus jamais gérer les comptes) ;
  - impossible de supprimer SON PROPRE compte pendant qu'on l'utilise (même
    en étant administrateur, et même si d'autres admins existent — un
    exploitant qui se supprime lui-même perd sa session en cours de route,
    sans confirmation possible de ce qu'il vient de faire) ;
  - seul un administrateur atteint cet écran : vérifié ICI, côté SERVEUR,
    PAS seulement par l'absence de lien dans le menu (`base.html`) — un
    lecteur qui taperait l'URL directement doit recevoir un 403, jamais un
    200 avec le contenu de l'écran.

Toute la logique de persistance (hachage, garde-fous de comptage) vit dans
`app.auth` — ce module ne fait que traduire des requêtes HTTP en appels à
cette couche et appliquer les gardes qui dépendent de LA REQUÊTE (qui est
l'appelant, quel compte cible), comme les autres routers du projet (cf.
`app/routers/auth.py`, `app/routers/retention.py`).
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.auth import (
    ROLE_ADMIN,
    ROLE_LECTEUR,
    VALID_ROLES,
    admin_reset_password,
    count_admins,
    create_user,
    delete_user,
    generate_random_password,
    get_auth_user,
    list_users,
    set_role,
)

log = logging.getLogger(__name__)

router = APIRouter(tags=["accounts"])


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


DbConnection = Annotated[sqlite3.Connection, Depends(get_db_connection)]
Templates = Annotated[Jinja2Templates, Depends(get_templates)]


# ---------------------------------------------------------------------------
# Écran de gestion des comptes
# ---------------------------------------------------------------------------


@router.get("/accounts", response_class=HTMLResponse)
def get_accounts_page(
    request: Request, templates: Templates, conn: DbConnection
) -> HTMLResponse:
    _require_admin(request)
    return _render_accounts_page(request, templates, conn)


@router.post("/accounts", response_class=HTMLResponse)
def post_create_account(
    request: Request,
    templates: Templates,
    conn: DbConnection,
    username: Annotated[str, Form()],
    role: Annotated[str, Form()],
) -> HTMLResponse:
    """Crée un compte. Le mot de passe est GÉNÉRÉ (jamais saisi en clair par
    l'administrateur créateur dans un formulaire, jamais transmis dans
    l'audit) — même choix que le bootstrap admin initial
    (`app.auth.BootstrapAdmin`), affiché UNE SEULE FOIS à l'écran juste après
    la création, avec le même avertissement `is_default_password`."""
    actor = _require_admin(request)
    username = username.strip()

    error: str | None = None
    if not username:
        error = "L'identifiant ne peut pas être vide."
    elif role not in VALID_ROLES:
        error = "Rôle invalide."
    elif get_auth_user(conn, username) is not None:
        error = "Ce compte existe déjà."

    if error:
        return _render_accounts_page(request, templates, conn, error=error, status_code=400)

    plaintext = generate_random_password()
    create_user(conn, username, plaintext, role)
    _record_audit(conn, actor, "account_create", f"username={username} role={role}")

    return _render_accounts_page(
        request,
        templates,
        conn,
        success=f"Compte « {username} » créé.",
        generated_password=plaintext,
        generated_password_for=username,
    )


@router.post("/accounts/{username}/role", response_class=HTMLResponse)
def post_change_role(
    request: Request,
    templates: Templates,
    conn: DbConnection,
    username: str,
    role: Annotated[str, Form()],
) -> HTMLResponse:
    """Change le rôle d'un compte.

    GARDE-FOU : impossible de rétrograder le dernier administrateur — le
    passer en 'lecteur' aurait EXACTEMENT le même effet que le supprimer
    (plus aucun compte administrateur ne resterait pour gérer les comptes,
    y compris pour annuler l'erreur). Vérifié AVANT toute écriture."""
    actor = _require_admin(request)

    error: str | None = None
    target = get_auth_user(conn, username)
    if target is None:
        error = "Compte introuvable."
    elif role not in VALID_ROLES:
        error = "Rôle invalide."
    elif target.role == ROLE_ADMIN and role != ROLE_ADMIN and count_admins(conn) <= 1:
        error = (
            f"Impossible de rétrograder « {username} » : c'est le dernier "
            "administrateur. Promouvez d'abord un autre compte."
        )
    elif (
        username == actor
        and target.role == ROLE_ADMIN
        and role != ROLE_ADMIN
    ):
        # Redondant avec la garde ci-dessus dans la majorité des cas (un
        # admin unique EST le dernier admin), mais reste vrai même s'il en
        # existe d'autres : on ne se retire jamais SOI-MÊME son propre rôle
        # d'administrateur, demande explicite distincte du garde-fou
        # "dernier admin" (on pourrait vouloir garder la main sur son propre
        # compte même si un collègue reste administrateur).
        error = "Impossible de retirer votre propre rôle d'administrateur."

    if error:
        return _render_accounts_page(request, templates, conn, error=error, status_code=400)

    set_role(conn, username, role)
    _record_audit(conn, actor, "account_role_change", f"username={username} new_role={role}")
    return _render_accounts_page(
        request, templates, conn, success=f"Rôle de « {username} » mis à jour."
    )


@router.post("/accounts/{username}/reset-password", response_class=HTMLResponse)
def post_reset_password(
    request: Request, templates: Templates, conn: DbConnection, username: str
) -> HTMLResponse:
    """Réinitialise le mot de passe d'un compte à une valeur GÉNÉRÉE, affichée
    une seule fois — jamais de mot de passe choisi par l'administrateur
    saisi en clair dans un formulaire (même raisonnement que la création)."""
    actor = _require_admin(request)

    if get_auth_user(conn, username) is None:
        return _render_accounts_page(
            request, templates, conn, error="Compte introuvable.", status_code=400
        )

    plaintext = generate_random_password()
    admin_reset_password(conn, username, plaintext)
    _record_audit(conn, actor, "account_password_reset", f"username={username}")

    return _render_accounts_page(
        request,
        templates,
        conn,
        success=f"Mot de passe de « {username} » réinitialisé.",
        generated_password=plaintext,
        generated_password_for=username,
    )


@router.post("/accounts/{username}/delete", response_class=HTMLResponse)
def post_delete_account(
    request: Request, templates: Templates, conn: DbConnection, username: str
) -> HTMLResponse:
    """Supprime un compte.

    GARDE-FOUS, dans cet ordre :
      1. impossible de se supprimer SOI-MÊME pendant qu'on utilise son
         compte (session en cours) ;
      2. impossible de supprimer le DERNIER administrateur.
    Les deux se recoupent partiellement (un admin seul qui tenterait de se
    supprimer déclenche déjà la garde n°1) mais restent deux règles
    distinctes : la garde n°2 s'applique aussi à un admin qui tenterait de
    supprimer un AUTRE dernier admin restant (cas improbable en pratique
    avec la garde n°1, mais correct par construction, pas par coïncidence)."""
    actor = _require_admin(request)

    error: str | None = None
    target = get_auth_user(conn, username)
    if target is None:
        error = "Compte introuvable."
    elif username == actor:
        error = "Impossible de supprimer votre propre compte pendant que vous l'utilisez."
    elif target.role == ROLE_ADMIN and count_admins(conn) <= 1:
        error = f"Impossible de supprimer « {username} » : c'est le dernier administrateur."

    if error:
        return _render_accounts_page(request, templates, conn, error=error, status_code=400)

    delete_user(conn, username)
    _record_audit(conn, actor, "account_delete", f"username={username}")
    return _render_accounts_page(
        request, templates, conn, success=f"Compte « {username} » supprimé."
    )


# ---------------------------------------------------------------------------
# Utilitaires internes
# ---------------------------------------------------------------------------


def _require_admin(request: Request) -> str:
    """Garde SERVEUR : refuse tout appelant qui n'est pas administrateur.

    `request.state.auth_role` est posé par le middleware
    `app.main.require_authentication` (toujours présent : cette route est
    elle-même derrière ce middleware, hors allowlist publique). Un lecteur
    qui atteindrait cette URL directement — sans passer par le lien de menu,
    qui n'existe même pas pour lui — reçoit un 403 explicite, jamais un
    contenu partiel ou une redirection silencieuse.

    Retourne le username de l'appelant : quasiment toutes les routes de ce
    module en ont besoin pour appliquer le garde-fou anti-auto-suppression.
    """
    role = getattr(request.state, "auth_role", None)
    if role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Réservé aux administrateurs.")
    username = getattr(request.state, "auth_username", None)
    if not username:
        raise HTTPException(status_code=403, detail="Session invalide.")
    return username


def _render_accounts_page(
    request: Request,
    templates: Jinja2Templates,
    conn: sqlite3.Connection,
    *,
    error: str | None = None,
    success: str | None = None,
    generated_password: str | None = None,
    generated_password_for: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    current_username = getattr(request.state, "auth_username", None)
    return templates.TemplateResponse(
        request,
        "accounts.html",
        {
            "active_page": "accounts",
            "users": list_users(conn),
            "current_username": current_username,
            "roles": (ROLE_ADMIN, ROLE_LECTEUR),
            "error": error,
            "success": success,
            "generated_password": generated_password,
            "generated_password_for": generated_password_for,
        },
        status_code=status_code,
    )


def _record_audit(
    conn: sqlite3.Connection, actor: str, action: str, detail: str
) -> None:
    """Insère une ligne dans `audit_log` — même schéma et même garde que
    `app.routers.retention._record_audit` : un échec d'écriture d'audit est
    journalisé mais jamais fatal pour l'opération métier déjà réussie.

    JAMAIS de mot de passe ni de secret TOTP dans `detail` — vérifié par
    construction : chaque appel ci-dessous ne passe que des identifiants
    (username cible, rôle), jamais une valeur issue de `Form(...)` portant un
    secret."""
    try:
        conn.execute(
            "INSERT INTO audit_log (actor, action, detail) VALUES (?, ?, ?)",
            (actor, action, detail),
        )
        conn.commit()
    except sqlite3.Error as exc:  # noqa: BLE001 - un audit manquant ne doit pas faire échouer l'action
        log.error("accounts: echec ecriture audit_log action=%s: %s", action, exc)
