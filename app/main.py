"""Point d'entrée FastAPI d'Okvorado.

Okvorado est une surcouche de pilotage au-dessus d'Akvorado : il ne stocke ni ne
décode aucun flux. Il lit ClickHouse et les métriques de l'outlet, et expose des
vues métier que la console Akvorado ne fournit pas (croisement config x données,
diagnostic d'ingestion, correspondances port -> application).
"""

import asyncio
import contextlib
import logging
import sqlite3
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.auth import (
    SESSION_COOKIE_NAME,
    ensure_bootstrap_user,
    reconcile_bootstrap_password,
    resolve_bootstrap_admin,
    resolve_session_secret,
    verify_session,
)
from app.config import DEFAULT_WINDOW, settings
from app.db import init_database
from app.routers import proxy_akvorado
from app.templating import templates

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent


async def _snmp_inventory_periodic_loop() -> None:
    """Collecte SNMP d'inventaire équipement, à intervalle régulier.

    Même mécanisme que le reste de l'app : pas de scheduler externe (aucun
    APScheduler/cron déjà en place ici) — une tâche de fond `asyncio` lancée
    depuis `lifespan`, annulée proprement à l'arrêt. Désactivée sans bruit si
    aucune communauté SNMP n'est configurée (fail-safe, même choix que
    `restart_agent_token` vide = restart indisponible).
    """
    if not settings.snmp_community:
        log.info("collecte snmp automatique desactivee (OKVORADO_SNMP_COMMUNITY vide)")
        return

    from app.routers.exporters import load_exporter_statuses
    from app.services import snmp_inventory

    while True:
        try:
            await asyncio.sleep(settings.snmp_poll_interval_seconds)
            statuses = await load_exporter_statuses(DEFAULT_WINDOW)
            addresses = [status.address for status in statuses]
            conn = sqlite3.connect(settings.sqlite_path, check_same_thread=False)
            try:
                # `collect_all` est SYNCHRONE et bloquante (appelle
                # `asyncio.run()` en interne pour piloter pysnmp) : exécutée
                # directement dans cette boucle `async def`, elle échoue avec
                # "asyncio.run() cannot be called from a running event loop"
                # (même défaut que app/routers/inventory.py, mesuré en prod
                # .7 le 2026-08-08). `asyncio.to_thread` la déporte hors de la
                # boucle événements d'uvicorn.
                await asyncio.to_thread(
                    snmp_inventory.collect_all,
                    conn,
                    addresses=addresses,
                    community=settings.snmp_community,
                )
            finally:
                conn.close()
            log.info("collecte snmp automatique terminee: %d exportateur(s)", len(addresses))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - une collecte ratee ne doit jamais tuer la boucle
            log.error("echec cycle de collecte snmp automatique: %s", exc, exc_info=True)


async def _db_health_periodic_loop() -> None:
    """Surveillance de santé ClickHouse, à intervalle régulier.

    Même mécanisme que `_snmp_inventory_periodic_loop` : pas de scheduler
    externe, tâche `asyncio` de fond lancée depuis `lifespan`, annulée
    proprement à l'arrêt. Persiste chaque snapshot dans `db_health_history`
    (voir `app.routers.db_health._record_history`) pour qu'une dérive soit
    visible sur la durée, pas seulement au dernier chargement de l'écran.

    GARDE-FOU CENTRAL DU LOT : cette boucle ne fait QUE lire l'état et
    persister un snapshot. Elle n'exécute JAMAIS `OPTIMIZE`, ne purge JAMAIS
    de parts détachées, et surtout ne redémarre JAMAIS ClickHouse — ces
    gestes restent exclusivement déclenchés par un clic exploitant depuis
    l'écran (voir `app.routers.db_health`, actions POST). Un état critique
    est ALERTÉ (visible dans l'historique et sur l'écran), jamais traité
    automatiquement dans le dos de l'exploitant.
    """
    from app.clients.clickhouse import connect
    from app.deps import RowsAdapter
    from app.routers.db_health import _record_history
    from app.services.db_health import build_unavailable_snapshot, collect_snapshot

    while True:
        try:
            await asyncio.sleep(settings.db_health_poll_interval_seconds)
            try:
                client = RowsAdapter(connect())
                snapshot = collect_snapshot(client, settings.db_health_memory_limit_bytes)
            except Exception as exc:  # noqa: BLE001 - connexion ClickHouse absente/en erreur
                log.error("db_health: echec connexion pour le cycle periodique: %s", exc)
                snapshot = build_unavailable_snapshot(str(exc))

            conn = sqlite3.connect(settings.sqlite_path, check_same_thread=False)
            try:
                _record_history(conn, snapshot)
            finally:
                conn.close()
            log.info("db_health: cycle periodique termine etat=%s", snapshot.overall_state.value)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - un cycle rate ne doit jamais tuer la boucle
            log.error("echec cycle de surveillance sante db: %s", exc, exc_info=True)


_PURGE_SETTINGS_TABLE_MAP: dict[str, str] = {
    "audit_log_max_age_days": "audit_log",
    "pending_config_changes_max_age_days": "pending_config_changes",
    "snmp_inventory_max_age_days": "snmp_inventory",
}
"""Correspondance clé de `retention_settings` -> table purgeable associée.

Même trio que `app.services.purge.PURGEABLE_TABLES` (source de vérité de
l'allowlist, revalidée par `preview_table_purge`/`execute_table_purge`
eux-mêmes) : ce dict ne fait QUE router le réglage d'âge vers la bonne table,
il ne contourne aucune garde — `preview_table_purge` continue de refuser
toute table hors allowlist avant tout accès SQL.
"""


async def _purge_periodic_loop() -> None:
    """Purge périodique des tables SQLite internes, à intervalle régulier.

    Même mécanisme que `_snmp_inventory_periodic_loop` ci-dessus : pas de
    scheduler externe, une tâche de fond `asyncio` lancée depuis `lifespan`,
    annulée proprement à l'arrêt.

    RÈGLE ABSOLUE DU PROJET (CLAUDE.md) : ne jamais purger sans action
    explicite. Cette boucle ne supprime RIEN par défaut — elle ne purge QUE
    si l'utilisateur a explicitement activé `purge_auto_enabled=true` depuis
    l'écran Rétention (persisté dans `retention_settings`, lu à CHAQUE cycle
    donc une désactivation prend effet au cycle suivant, jamais besoin de
    redémarrer). Tant que ce réglage est absent ou faux (défaut), le cycle se
    contente de logger et de ne rien faire — même comportement fail-safe que
    `_snmp_inventory_periodic_loop` avec une communauté SNMP vide.

    Ne purge QUE les tables internes (`audit_log`, `pending_config_changes`,
    `snmp_inventory`) par âge — jamais les fichiers `.bak-*` : une purge de
    fichiers automatique et non supervisée est un risque disproportionné par
    rapport au gain (quelques Ko), le geste reste manuel depuis l'écran.
    """
    from app.services.purge import execute_table_purge, preview_table_purge

    while True:
        try:
            await asyncio.sleep(settings.purge_poll_interval_seconds)
            conn = sqlite3.connect(settings.sqlite_path, check_same_thread=False)
            try:
                rows = conn.execute(
                    "SELECT setting_key, setting_value FROM retention_settings"
                ).fetchall()
                current = {row[0]: row[1] for row in rows}

                if current.get("purge_auto_enabled") != "true":
                    log.info(
                        "purge automatique desactivee (purge_auto_enabled absent ou "
                        "faux) : aucune suppression effectuee ce cycle"
                    )
                    continue

                for setting_key, table in _PURGE_SETTINGS_TABLE_MAP.items():
                    raw_age = current.get(setting_key)
                    if raw_age is None:
                        continue  # réglage non configuré : cette table n'est pas purgée
                    try:
                        max_age_days = int(raw_age)
                    except ValueError:
                        log.error(
                            "purge automatique: valeur non entiere ignoree table=%s "
                            "cle=%s valeur=%r",
                            table,
                            setting_key,
                            raw_age,
                        )
                        continue

                    preview = preview_table_purge(conn, table, max_age_days)
                    if preview.rows_to_delete == 0:
                        continue
                    result = execute_table_purge(conn, preview)
                    conn.execute(
                        "INSERT INTO audit_log (actor, action, detail) VALUES (?, ?, ?)",
                        (
                            "purge_auto",
                            "retention_purge_execute",
                            f"target={table} max_age_days={max_age_days} "
                            f"supprimes={result.deleted_count}",
                        ),
                    )
                    conn.commit()
                    log.info(
                        "purge automatique: table=%s max_age_days=%d supprimes=%d",
                        table,
                        max_age_days,
                        result.deleted_count,
                    )
            finally:
                conn.close()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - un cycle de purge rate ne doit jamais tuer la boucle
            log.error("echec cycle de purge periodique: %s", exc, exc_info=True)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None]:
    """Prépare la base locale au démarrage."""
    try:
        init_database()
    except Exception as exc:  # noqa: BLE001 - on log et on continue en mode dégradé
        log.error("initialisation de la base locale impossible: %s", exc)

    # Compte admin initial (LOT auth) : résolu depuis l'environnement puis
    # inséré s'il n'existe encore aucun utilisateur — voir `app.auth.BootstrapAdmin`
    # pour la justification du choix « mot de passe généré affiché au démarrage »
    # plutôt qu'un défaut faible. JAMAIS réécrit si un utilisateur existe déjà
    # (un exploitant qui a changé son mot de passe depuis l'écran ne doit jamais
    # le voir réinitialisé par un redémarrage).
    try:
        admin = resolve_bootstrap_admin(
            env_user=settings.auth_user, env_password=settings.auth_password
        )
        conn = sqlite3.connect(settings.sqlite_path)
        try:
            existing = conn.execute("SELECT COUNT(*) FROM auth_users").fetchone()[0]
            ensure_bootstrap_user(conn, admin)
            # Cas limite (2026-08-09) : `.env` renseigné APRÈS un premier
            # démarrage sans mot de passe — voir la docstring de
            # `reconcile_bootstrap_password`. No-op si le mot de passe a déjà
            # été changé depuis l'écran Sécurité (is_default_password=0).
            reconcile_bootstrap_password(conn, admin)
        finally:
            conn.close()
        if not existing and admin.generated:
            # AFFICHÉ UNE SEULE FOIS : ce mot de passe n'est conservé nulle
            # part ailleurs (ni en base en clair, ni dans une variable de
            # longue durée) — c'est cette ligne de log, et elle seule, qui en
            # porte la valeur en clair.
            log.info(
                "=" * 70 + "\n"
                "OKVORADO_AUTH_PASSWORD non defini : mot de passe admin genere.\n"
                "Identifiant : %s\n"
                "Mot de passe (affiche UNE SEULE FOIS) : %s\n"
                "Changez-le depuis l'ecran Securite des la premiere connexion.\n" + "=" * 70,
                admin.username,
                admin.plaintext_if_generated,
            )
    except Exception as exc:  # noqa: BLE001 - un echec ici ne doit pas bloquer le demarrage
        log.error("initialisation du compte admin impossible: %s", exc)

    # Précharge les correspondances port -> application. Idempotent, et ne réécrit
    # jamais une surcharge saisie par un utilisateur : sans ce seed, la volumétrie
    # par service n'afficherait que des numéros de port bruts.
    try:
        from app.services.portmap import seed_iana_defaults

        conn = sqlite3.connect(settings.sqlite_path)
        try:
            seed_iana_defaults(conn)
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001 - dégradation : ports affichés en brut
        log.error("preremplissage des correspondances port/application impossible: %s", exc)

    # Catalogue applicatif étendu (LOT app_catalog) : amorce le catalogue IANA
    # complet (~11 600 entrées) depuis le repli EMBARQUÉ (jamais d'appel réseau
    # au démarrage — un proxy d'entreprise en échec ne doit jamais retarder le
    # boot), puis précharge le catalogue métier (SCCM, Tailscale, RDP...). Un
    # rechargement réseau reste déclenchable ensuite depuis l'écran.
    try:
        from app.services.app_catalog import (
            ensure_catalog_seeded_at_startup,
            seed_grand_public_defaults,
            seed_metier_defaults,
        )

        conn = sqlite3.connect(settings.sqlite_path)
        try:
            status = ensure_catalog_seeded_at_startup(conn)
            log.info(
                "catalogue applicatif amorce au demarrage: statut=%s entrees_iana=%d",
                status.status,
                status.entries_iana,
            )
            seed_metier_defaults(conn)
            grand_public_written = seed_grand_public_defaults(conn)
            log.info(
                "catalogue grand public amorce au demarrage: %d entree(s)",
                grand_public_written,
            )
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001 - dégradation : catalogue reste au socle portmap
        log.error("amorcage du catalogue applicatif impossible: %s", exc)

    snmp_task = asyncio.create_task(_snmp_inventory_periodic_loop())
    purge_task = asyncio.create_task(_purge_periodic_loop())
    db_health_task = asyncio.create_task(_db_health_periodic_loop())
    try:
        yield
    finally:
        snmp_task.cancel()
        purge_task.cancel()
        db_health_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await snmp_task
        with contextlib.suppress(asyncio.CancelledError):
            await purge_task
        with contextlib.suppress(asyncio.CancelledError):
            await db_health_task


app = FastAPI(
    title="Okvorado",
    description="Interface de management pour Akvorado",
    version="0.1.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Certains routers récupèrent le moteur de templates via `request.app.state.templates`
# plutôt que par injection : on le publie ici pour que les deux conventions marchent.
app.state.templates = templates

# Clé de signature des cookies de session (LOT auth) — résolue UNE FOIS au
# chargement du module, publiée sur app.state pour que `app.routers.auth`
# (et les tests) la lisent sans réimporter `app.main` en boucle. Voir
# `app.auth.resolve_session_secret` : vide -> génération aléatoire, les
# sessions ne survivent alors pas à un redémarrage (documenté, acceptable).
app.state.auth_session_secret, _auth_session_secret_generated = resolve_session_secret(
    env_secret=settings.auth_session_secret
)
if _auth_session_secret_generated:
    log.info(
        "OKVORADO_AUTH_SESSION_SECRET non definie : cle de session generee "
        "aleatoirement. Les sessions ne survivront pas a un redemarrage."
    )


@app.middleware("http")
async def add_security_headers(request: Request, call_next: object) -> object:
    """En-têtes de sécurité sur toute réponse.

    CSP stricte : aucun script ni style externe. HTMX est servi localement,
    ce qui permet d'interdire toute origine tierce.

    CADRAGE (iframe) — allowlist, jamais une ouverture totale : DEMANDE
    UTILISATEUR « qu'en prod je dise pas à mon manager qu'il faut jongler sur
    4 url » → Grafana devient la porte d'entrée unique et embarque Okvorado
    dans un panneau. `frame-ancestors` (CSP) est la directive MODERNE qui
    gère ce cas ; `X-Frame-Options` est son ancêtre, standardisé par le W3C
    comme deprecated en faveur de `frame-ancestors` — et surtout, il ne sait
    exprimer QUE `DENY` / `SAMEORIGIN` / une origine UNIQUE (`ALLOW-FROM`,
    lui-même retiré des navigateurs modernes) : il ne peut PAS porter une
    liste de plusieurs origines. Le garder à `DENY` aux côtés d'une CSP
    `frame-ancestors` permissive serait contradictoire (et bloquerait quand
    même l'affichage, un navigateur qui respecte les deux en applique le plus
    restrictif) ; il est donc retiré, au profit de `frame-ancestors` seule,
    qui EST la protection anti-clickjacking effective ici. Ce n'est pas un
    retrait de protection : c'est son remplacement par le mécanisme qui sait
    exprimer une allowlist. Jamais de `*` : seules les origines listées dans
    `settings.frame_ancestors` (configurable via `OKVORADO_FRAME_ANCESTORS`,
    défaut = l'origine Grafana du stack local) peuvent encadrer cette app.
    """
    response = await call_next(request)  # type: ignore[operator]  # call_next non typé par Starlette
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data:; connect-src 'self'; frame-ancestors {settings.frame_ancestors}"
    )

    # EXCEPTION CSP CIBLÉE — proxy de la console Akvorado (`app/routers/proxy_akvorado.py`).
    # La console est une application Vue (build Vite) : elle embarque ses PROPRES
    # scripts et styles, générés par SON build, jamais servis depuis `/static/`
    # d'Okvorado. La CSP stricte ci-dessus (`script-src 'self'` uniquement, sans
    # inline ni eval) CASSERAIT la console si elle s'appliquait à ses réponses —
    # exactement le défaut qui a fait abandonner le proxy Grafana (lui posait une
    # CSP `sandbox`, non contournable ; ici le risque inverse serait une CSP TROP
    # stricte plutôt que TROP permissive, mais le résultat visible est le même :
    # page blanche/sans style). Le middleware s'exécute APRÈS le retour de la
    # route (Starlette : `call_next` retourne la réponse, PUIS le middleware pose
    # ses en-têtes) — sans cette RÉÉCRITURE CIBLÉE, il écraserait systématiquement
    # toute CSP posée par le routeur lui-même. Seules les réponses SOUS CE PRÉFIXE
    # reçoivent la CSP alternative ci-dessous ; toutes les autres pages d'Okvorado
    # gardent la CSP stricte assignée juste au-dessus, INCHANGÉE (c'est elle que
    # `tests/test_csp_handlers.py::test_la_csp_interdit_bien_les_scripts_inline`
    # vérifie — assignée en PREMIER, textuellement, pour rester la valeur que ce
    # test capture).
    if request.url.path.startswith(f"{settings.url_prefix}{proxy_akvorado.PROXY_PREFIX}"):
        # Toujours restreinte à 'self' (aucun CDN, aucune origine tierce) : la
        # console est servie DEPUIS Okvorado (même origine, via le proxy), donc
        # 'self' suffit à couvrir ses propres scripts/styles/connexions. Ce
        # n'est PAS un `*` ni un `unsafe-eval` — seul `'unsafe-inline'` est
        # ajouté (build Vite : styles injectés inline par le runtime Vue),
        # absent de la CSP stricte des autres pages pour script-src.
        #
        # `frame-ancestors 'self' <origines>` — DÉFAUT MESURÉ le 2026-08-10 :
        # la valeur par défaut de `settings.frame_ancestors` est l'origine
        # GRAFANA (`http://localhost:3000`) et ne contient PAS `'self'`.
        # L'écran d'intégration (`/akvorado`, voir `app/routers/console_embed.py`)
        # encadre ces réponses de proxy dans un `<iframe>` servi par Okvorado :
        # l'encadrant est donc Okvorado LUI-MÊME, c'est-à-dire la MÊME ORIGINE.
        # Sans `'self'`, le navigateur refuse d'afficher le cadre alors même
        # que le proxy répond 200 — le cadre reste blanc, sans erreur visible
        # à l'écran (exactement le zéro silencieux que le projet proscrit).
        #
        # `'self'` est AJOUTÉ, jamais substitué : les origines configurées
        # (Grafana, porte d'entrée unique) continuent d'encadrer. Et c'est
        # l'ajustement LE PLUS ÉTROIT possible — `'self'` désigne la seule
        # origine d'Okvorado, jamais `*`. Ajouté UNIQUEMENT sur cette branche :
        # les pages normales gardent `frame-ancestors {settings.frame_ancestors}`
        # inchangé (elles n'ont aucune raison de s'auto-encadrer).
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            f"connect-src 'self'; frame-ancestors 'self' {settings.frame_ancestors}"
        )
    return response


# Allowlist EXPLICITE des chemins accessibles SANS session (LOT auth).
# `/health` DOIT rester dessus : c'est la sonde du HEALTHCHECK Dockerfile
# (`CMD python3 -c "...http://127.0.0.1:8099/health..."`) — si cette route
# exigeait une authentification, le conteneur ne deviendrait jamais `healthy`
# et ne démarrerait jamais en pratique (orchestrateurs qui attendent l'état
# healthy avant de router du trafic). `/login` et `/logout` sont nécessaires
# par construction (on ne peut pas exiger une session pour se connecter).
# `/static/` sert le CSS/JS de la page de connexion elle-même : sans cette
# entrée, `/login` s'afficherait sans aucun style ni script.
_AUTH_PUBLIC_PATHS: frozenset[str] = frozenset({"/health", "/login", "/logout"})
_AUTH_PUBLIC_PREFIXES: tuple[str, ...] = ("/static/",)


def _is_public_path(path: str) -> bool:
    if path in _AUTH_PUBLIC_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in _AUTH_PUBLIC_PREFIXES)


@app.middleware("http")
async def require_authentication(request: Request, call_next: object) -> object:
    """Protège TOUTE route hors allowlist explicite derrière une session valide.

    Une requête HTMX non authentifiée ne doit JAMAIS produire un échec
    silencieux : `app/static/htmx-config.js` swap `false` sur un 4xx générique,
    donc un simple 401 ne montrerait RIEN à l'écran (l'utilisateur croirait
    son clic ignoré). `HX-Redirect` est le mécanisme prévu par htmx pour ce
    cas précis : l'en-tête déclenche une navigation complète côté client,
    quel que soit le code de statut de la réponse — vérifié dans la
    documentation htmx (`HX-Redirect` : « can be used to do a client-side
    redirect to a new location »), c'est le contrat que ce garde-fou exploite.
    Une requête NON-HTMX reçoit une redirection HTTP 303 classique.
    """
    path = request.url.path
    if _is_public_path(path):
        return await call_next(request)  # type: ignore[operator]

    cookie_value = request.cookies.get(SESSION_COOKIE_NAME)
    username = (
        verify_session(
            cookie_value,
            request.app.state.auth_session_secret,
            max_age_seconds=settings.auth_session_max_age_seconds,
        )
        if cookie_value
        else None
    )

    if username is None:
        login_url = f"{settings.url_prefix}/login"
        if request.headers.get("HX-Request") == "true":
            return HTMLResponse(status_code=401, headers={"HX-Redirect": login_url})
        return RedirectResponse(url=login_url, status_code=303)

    # Publié pour les routers (écran Sécurité, bandeau mot de passe par
    # défaut, écran Comptes) sans re-décoder le cookie à chaque endroit qui
    # en a besoin.
    request.state.auth_username = username
    conn = sqlite3.connect(settings.sqlite_path)
    try:
        row = conn.execute(
            "SELECT is_default_password, role FROM auth_users WHERE username = ?", (username,)
        ).fetchone()
        request.state.auth_default_password_warning = bool(row[0]) if row else False
        # Défaut `'lecteur'` si la ligne a disparu entre la signature du
        # cookie et cette requête (compte supprimé) : le compte n'existe
        # plus, aucune route d'écriture ni l'écran Comptes ne doit rester
        # accessible avec les droits de l'ancienne session (ZÉRO SILENCIEUX
        # — un rôle absent ne doit JAMAIS se comporter comme 'admin').
        request.state.auth_role = row[1] if row else "lecteur"
    except sqlite3.Error as exc:  # noqa: BLE001 - degradation : pas de bandeau plutot qu'un 500
        log.error("require_authentication: lecture is_default_password/role impossible: %s", exc)
        request.state.auth_default_password_warning = False
        request.state.auth_role = "lecteur"
    finally:
        conn.close()

    response = await call_next(request)  # type: ignore[operator]
    return response


@app.get("/health")
async def get_health() -> JSONResponse:
    """Sonde de vie, sans dépendance externe (utilisable par Kuma/Gatus)."""
    return JSONResponse({"status": "ok", "service": "okvorado", "version": app.version})


@app.get("/", include_in_schema=False)
async def get_root() -> RedirectResponse:
    return RedirectResponse(url="/exporters")


def _register_routers() -> list[str]:
    """Monte les routers disponibles.

    Chaque lot est monté indépendamment : un module encore absent ou en erreur
    n'empêche pas les autres de fonctionner. L'échec est journalisé, jamais avalé.
    """
    mounted: list[str] = []
    for module_name, attr in (
        ("app.routers.auth", "router"),
        ("app.routers.accounts", "router"),
        ("app.routers.exporters", "router"),
        ("app.routers.views", "router"),
        ("app.routers.ingestion", "router"),
        ("app.routers.retention", "router"),
        ("app.routers.config", "router"),
        ("app.routers.config_sections", "router"),
        ("app.routers.filter_composer", "router"),
        ("app.routers.diagnostics", "router"),
        ("app.routers.inventory", "router"),
        ("app.routers.app_catalog", "router"),
        ("app.routers.db_health", "router"),
        ("app.routers.proxy_akvorado", "router"),
        # Écran d'intégration de la console (`/akvorado`) — encadre le proxy
        # ci-dessus dans une page Okvorado. Monté APRÈS lui : il importe
        # `PROXY_PREFIX` depuis `proxy_akvorado` (source de vérité unique du
        # préfixe), jamais une copie du chemin en dur.
        ("app.routers.console_embed", "router"),
    ):
        try:
            module = __import__(module_name, fromlist=[attr])
            app.include_router(getattr(module, attr))
            mounted.append(module_name)
        except Exception as exc:  # noqa: BLE001 - un lot absent ne doit pas tuer l'app
            log.error("router non monte %s: %s", module_name, exc)
    return mounted


MOUNTED_ROUTERS = _register_routers()


def _wire_dependencies() -> list[str]:
    """Branche les dépendances réelles sur les placeholders des routers.

    Chaque lot expose un `get_*` qui lève une RuntimeError explicite tant qu'il
    n'est pas surchargé : c'est volontaire, un câblage manquant échoue bruyamment
    plutôt que de dégrader en silence. C'est ici que le câblage a lieu.
    """
    wired: list[str] = []

    try:
        from app.deps import get_clickhouse_client, get_clickhouse_rows_client
        from app.routers import retention as retention_router
        from app.routers import views as views_router

        # Rétention et vues consomment des lignes brutes -> adaptateur .result_rows
        app.dependency_overrides[retention_router.get_clickhouse_client] = (
            get_clickhouse_rows_client
        )
        wired.append("retention.clickhouse")

        # Les vues attendent le QueryResult natif (elles lisent .result_rows elles-mêmes)
        app.dependency_overrides[views_router.get_clickhouse_client] = get_clickhouse_client
        wired.append("views.clickhouse")

        def _open_db() -> Generator[sqlite3.Connection]:
            # `check_same_thread=False` est requis ici : FastAPI exécute les
            # routes synchrones dans un pool de threads, donc la connexion est
            # créée et utilisée dans des threads différents. C'est sans risque
            # car la connexion est ouverte PAR REQUÊTE puis refermée — elle
            # n'est jamais partagée entre deux requêtes concurrentes.
            conn = sqlite3.connect(settings.sqlite_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()

        app.dependency_overrides[views_router.get_db_connection] = _open_db
        wired.append("views.sqlite")

        # Réglages de rétention (retention_settings), audit des purges/apply, et
        # purge des sauvegardes .bak-* : même connexion SQLite que les autres
        # routers (_open_db, définie ci-dessus) et même répertoire de config
        # qu'`config_sections` pour le glob des `.bak-*` (généré par
        # `akvorado_yaml.py` à côté d'`outlet.yaml`, jamais un chemin distinct).
        app.dependency_overrides[retention_router.get_db_connection] = _open_db
        app.dependency_overrides[retention_router.get_backup_directory] = lambda: Path(
            settings.akvorado_config_path
        ).parent
        wired.append("retention.sqlite")

        app.dependency_overrides[views_router.get_templates] = lambda: templates
        wired.append("views.templates")

        # --- Résolution SNMP des ifIndex (écran Exportateurs, 2026-08-10) ---
        # Les boutons « Résoudre par SNMP » / « Tout résoudre » écrivent les
        # `if-indexes` d'`outlet.yaml` via le mécanisme de changements en
        # attente (table SQLite `pending_changes`) et rendent un fragment
        # Jinja : il leur faut donc les DEUX dépendances, comme `views`.
        #
        # SANS CE CÂBLAGE, LES TESTS PASSENT ET LA PROD ÉCHOUE : les tests
        # surchargent ces dépendances eux-mêmes, alors qu'en production
        # `exporters_router.get_db_connection` lève délibérément une exception
        # (« non câblée : app/main.py doit surcharger cette dépendance »).
        # Le défaut n'apparaîtrait qu'au clic, à l'écran — famille de défaut
        # déjà mesurée sur ce projet (« service existant non branché »).
        from app.routers import exporters as exporters_router

        app.dependency_overrides[exporters_router.get_db_connection] = _open_db
        app.dependency_overrides[exporters_router.get_templates] = lambda: templates
        wired.append("exporters.snmp")

        # --- Authentification (LOT auth) ----------------------------------
        # Même connexion SQLite que les autres routers (_open_db) : la table
        # `auth_users` vit dans la même base que `port_mappings`.
        from app.routers import auth as auth_router

        app.dependency_overrides[auth_router.get_db_connection] = _open_db
        app.dependency_overrides[auth_router.get_templates] = lambda: templates
        app.dependency_overrides[auth_router.get_session_secret] = (
            lambda: app.state.auth_session_secret
        )
        wired.append("auth")

        # --- Gestion des comptes (LOT accounts) ---------------------------
        # Même connexion SQLite que les autres routers (_open_db) : la table
        # `auth_users` vit dans la même base que `port_mappings`.
        from app.routers import accounts as accounts_router

        app.dependency_overrides[accounts_router.get_db_connection] = _open_db
        app.dependency_overrides[accounts_router.get_templates] = lambda: templates
        wired.append("accounts")

        # --- Routes d'ÉCRITURE (v2) -------------------------------------------
        from app.clients.restart import RestartReport, RestartResult, restart_akvorado
        from app.routers import config as config_router

        app.dependency_overrides[config_router.get_db_connection] = _open_db
        app.dependency_overrides[config_router.get_akvorado_config_path] = (
            lambda: settings.akvorado_config_path
        )
        app.dependency_overrides[config_router.get_templates] = lambda: templates
        wired.append("config.sqlite")

        class _RestartOutcomeAdapter:
            """Adapte `RestartResult` (champ `.ok`) au contrat attendu (`.success`).

            INCIDENT 2026-08-05 : les deux lots ont été développés en parallèle et
            ont nommé le même concept différemment — `config_writer` exige
            `.success`, le client expose `.ok`. Câblé sans adaptateur, l'appel
            levait `AttributeError` APRÈS l'écriture du YAML, donc hors de la
            portée du rollback : la config de production a été vidée.

            C'est à la colle d'intégration d'adapter, pas à l'un des deux lots de
            céder. D'où cet adaptateur explicite.
            """

            def __init__(self, result: RestartResult) -> None:
                self._result = result
                self.success = result.ok
                self.message = result.message

            @property
            def reports(self) -> list[RestartReport]:
                return self._result.reports

        def _restart_akvorado_sync(services: tuple[str, ...] = ()) -> _RestartOutcomeAdapter:
            """Pont synchrone vers le client de restart, qui est async.

            `apply_pending_changes` est synchrone (il enchaîne des I/O fichier) et
            attend `restart_fn() -> RestartOutcome`. Le client, lui, est async.
            On exécute donc la coroutine dans un thread avec sa propre boucle :
            `asyncio.run` depuis un thread du pool ne perturbe pas la boucle
            principale d'uvicorn.

            Les services redémarrés sont l'orchestrator (il porte les migrations)
            puis l'outlet (il consomme la config des exportateurs). ClickHouse
            n'est JAMAIS redémarré : la base ne doit pas tomber pour un simple
            changement de configuration.
            """
            # `purge_metadata_cache=True` : un apply modifie la déclaration des
            # exportateurs (ifIndex, interfaces, boundary). Sans purge, Akvorado
            # relit son cache et conserve l'ANCIENNE correspondance — la
            # correction est écrite mais reste sans effet visible, les flux
            # restent classés `unknown`/`undefined` (mesuré le 2026-08-05).
            # `services` est l'UNION calculee par config_writer a partir des
            # sections modifiees. L'orchestrator est ajoute systematiquement : il
            # porte les migrations et la redistribution de config aux autres
            # services. Le nom "orchestrator" du catalogue est harmonise ici vers
            # le nom de service compose reel "akvorado-orchestrator".
            wanted = {("akvorado-orchestrator" if s == "orchestrator" else s) for s in services}
            wanted.add("akvorado-orchestrator")
            if not services:
                wanted.add("akvorado-outlet")
            result = asyncio.run(restart_akvorado(sorted(wanted), purge_metadata_cache=True))
            return _RestartOutcomeAdapter(result)

        app.dependency_overrides[config_router.get_restart_fn] = lambda: _restart_akvorado_sync
        wired.append("config.restart")

        # --- Édition de TOUTES les sections de config (v3) ---------------------
        # C'est l'objectif du projet : la config Akvorado vit dans 4 fichiers YAML
        # qu'il fallait éditer en SSH. Ces routes les rendent modifiables depuis
        # l'interface web.
        from app.routers import config_sections as sections_router

        app.dependency_overrides[sections_router.get_db_connection] = _open_db
        app.dependency_overrides[sections_router.get_config_dir] = lambda: str(
            Path(settings.akvorado_config_path).parent
        )
        app.dependency_overrides[sections_router.get_templates] = lambda: templates
        wired.append("config_sections")

        # --- Compositeur de filtres (v7) ---------------------------------------
        # Lit un ECHANTILLON des derniers flux pour proposer les champs et leurs
        # valeurs reelles. Le meme client natif que les vues : le service
        # `flow_sample` lit `.result_rows` lui-meme.
        from app.routers import filter_composer as composer_router

        app.dependency_overrides[composer_router.get_clickhouse_client] = get_clickhouse_client
        wired.append("filter_composer.clickhouse")

        # --- Diagnostics réseau (convergence + écran exportateur) --------------
        # Même client natif que les vues et le compositeur : ce router lit
        # .result_rows/.column_names lui-même, pas l'adaptateur RowsAdapter.
        from app.routers import diagnostics as diagnostics_router

        app.dependency_overrides[diagnostics_router.get_clickhouse_client] = get_clickhouse_client
        app.dependency_overrides[diagnostics_router.get_templates] = lambda: templates
        # Même `_open_db` que les vues (views.sqlite ci-dessus) : la résolution
        # port -> application (portmap) a besoin d'une connexion SQLite sur
        # `port_mappings`, pas un second mécanisme de câblage.
        app.dependency_overrides[diagnostics_router.get_db_connection] = _open_db
        wired.append("diagnostics.clickhouse")

        # --- Inventaire équipement SNMP (LOT inventaire) -----------------------
        # Même connexion SQLite que les autres routers (_open_db) : la table
        # `snmp_inventory` vit dans la même base que `port_mappings`.
        from app.routers import inventory as inventory_router

        app.dependency_overrides[inventory_router.get_db_connection] = _open_db
        app.dependency_overrides[inventory_router.get_templates] = lambda: templates
        wired.append("inventory.sqlite")

        # --- Catalogue applicatif (LOT app_catalog) -----------------------------
        # Même connexion SQLite que les autres routers (_open_db) : le catalogue
        # étend `port_mappings`, déjà partagée par views/diagnostics/inventory.
        from app.routers import app_catalog as app_catalog_router

        app.dependency_overrides[app_catalog_router.get_db_connection] = _open_db
        app.dependency_overrides[app_catalog_router.get_templates] = lambda: templates
        wired.append("app_catalog.sqlite")

        # --- Santé DB (LOT db_health) -------------------------------------
        # Même client natif que retention/views : ce router lit .result_rows
        # via l'adaptateur RowsAdapter (get_clickhouse_rows_client), comme
        # retention (il agrège des lignes, ne construit pas de modèles
        # depuis le QueryResult natif directement).
        from app.routers import db_health as db_health_router

        app.dependency_overrides[db_health_router.get_clickhouse_client] = (
            get_clickhouse_rows_client
        )
        app.dependency_overrides[db_health_router.get_db_connection] = _open_db
        app.dependency_overrides[db_health_router.get_memory_limit_bytes] = (
            lambda: settings.db_health_memory_limit_bytes
        )
        wired.append("db_health")

        # --- Diagnostic d'ingestion (tendance, LOT db_health étendu) -------
        # Même `_open_db` que les autres routers : la table
        # `ingestion_rejection_history` porte les points de comparaison de
        # tendance (voir `app.services.ingestion`, défaut mesuré 2026-08-09).
        from app.routers import ingestion as ingestion_router

        app.dependency_overrides[ingestion_router.get_db_connection] = _open_db
        wired.append("ingestion.sqlite")
    except Exception as exc:  # noqa: BLE001 - le câblage ne doit pas empêcher le démarrage
        log.error("cablage des dependances incomplet: %s", exc)

    return wired


WIRED_DEPENDENCIES = _wire_dependencies()


@app.exception_handler(500)
async def handle_server_error(request: Request, exc: Exception) -> HTMLResponse:
    """Évite d'exposer une stacktrace à l'utilisateur."""
    log.error("erreur non geree sur %s: %s", request.url.path, exc)
    return HTMLResponse(
        "<h1>Erreur interne</h1><p>L'incident a ete journalise.</p>",
        status_code=500,
    )
