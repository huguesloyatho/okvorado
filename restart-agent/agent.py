"""Agent de restart Akvorado — service HTTP minimal, séparé d'Okvorado.

Pourquoi un agent séparé : `/var/run/docker.sock` donne un accès root sur
l'hôte à qui le monte. Le monter dans Okvorado (app web exposée à des
utilisateurs) est EXCLU — règle non négociable du projet (voir CONTRACT.md).
Cet agent isole ce privilège : il tourne dans un container à part, monte le
socket docker, et n'expose qu'UNE capacité étroite — redémarrer les
containers Akvorado d'une allowlist figée — derrière un token.

GARDES DE SÉCURITÉ (cœur de ce module) :
1. Allowlist EN DUR des services redémarrables (`ALLOWED_SERVICES`). Tout nom
   hors de cette liste est refusé (403) AVANT tout appel docker.
2. Aucune interpolation shell : le SDK docker Python (`docker.from_env()`)
   est utilisé pour cibler un container par son nom exact ou son label
   `com.docker.compose.service` — jamais de `subprocess(shell=True)`, jamais
   de nom de service concaténé dans une commande.
3. Auth par token statique (`RESTART_AGENT_TOKEN`), comparaison en temps
   constant (`hmac.compare_digest`), header `Authorization: Bearer <token>`.
   Absence de la variable d'env au démarrage => le service refuse de
   démarrer (fail-fast, jamais de mode sans auth).
4. Rate-limit : un seul restart toutes les `MIN_RESTART_INTERVAL_SECONDS`
   (défaut 30) — un appel trop rapproché reçoit 429.
5. Chaque appel à `/restart` est journalisé (heure, services demandés,
   résultat) ; tout échec logge `log.error()` avec contexte.
"""

from __future__ import annotations

import hmac
import logging
import os
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

log = logging.getLogger("restart-agent")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

ALLOWED_SERVICES: frozenset[str] = frozenset(
    {"akvorado-outlet", "akvorado-inlet", "akvorado-orchestrator", "akvorado-console"}
)
"""Allowlist en dur des services Akvorado redémarrables par cet agent.

`clickhouse` est volontairement EXCLU : la base ne se redémarre jamais via
cet agent. Tout nom hors de cette liste est refusé en 403, jamais exécuté —
qu'il s'agisse d'une tentative d'injection (`"; rm -rf /"`), d'un chemin
(`"../etc"`) ou d'un nom docker valide mais non autorisé.
"""

RESTART_ORDER: tuple[str, ...] = (
    "akvorado-orchestrator",
    "akvorado-inlet",
    "akvorado-outlet",
    "akvorado-console",
)
"""Ordre déterministe de redémarrage.

L'orchestrator porte les migrations de schéma/config au démarrage : il doit
redémarrer AVANT les autres services Akvorado qui dépendent de cet état.
"""

COMPOSE_PROJECT = "akvorado"
COMPOSE_FILE = "/root/akvorado/docker-compose.yml"
"""Repère documentaire : les containers réels suivent le nommage compose
`<projet>-<service>-<index>` (ex: `akvorado-akvorado-outlet-1`). Le SDK
docker cible les containers par le label `com.docker.compose.service`, donc
ce module n'a pas besoin d'interpoler ce nommage lui-même."""

DEFAULT_MIN_RESTART_INTERVAL_SECONDS = 30.0
DEFAULT_HEALTHY_TIMEOUT_SECONDS = 120.0
DEFAULT_HEALTH_POLL_INTERVAL_SECONDS = 2.0

DEFAULT_METADATA_CACHE_PATH = "/data/akvorado/run/metadata.cache"
"""Chemin par défaut du cache de metadata Akvorado (ifIndex -> nom d'interface
+ boundary), sur l'hôte du collecteur. Surchageable via la variable
d'env `METADATA_CACHE_PATH` — jamais par le corps de la requête HTTP (voir
`resolve_metadata_cache_path` et le garde de `/restart`)."""

METADATA_CACHE_ALLOWED_PARENT = Path("/data/akvorado/run")
"""Répertoire attendu du cache de metadata. `resolve_metadata_cache_path`
refuse tout chemin (même venu de la config) qui ne tombe pas sous ce
répertoire : le chemin de suppression ne doit JAMAIS pouvoir devenir
arbitraire, quelle que soit la source de la valeur."""

METADATA_CACHE_FILENAME = "metadata.cache"
"""Nom de fichier attendu en bout de chemin — deuxième garde indépendante du
répertoire parent."""


class MetadataCachePathError(Exception):
    """Le chemin du cache de metadata (résolu depuis la config) ne satisfait
    pas les gardes de sécurité — jamais utilisé pour une suppression."""


def resolve_metadata_cache_path(raw_path: str, *, allowed_parent: Path | None = None) -> Path:
    """Valide un chemin de cache de metadata contre les gardes de sécurité.

    Le chemin ne vient JAMAIS du corps de la requête HTTP — uniquement de la
    configuration (variable d'env `METADATA_CACHE_PATH`, avec
    `DEFAULT_METADATA_CACHE_PATH` en repli). Cette fonction est le seul point
    qui transforme une chaîne de config en `Path` utilisable pour une
    suppression, et refuse tout chemin qui :
    - ne se termine pas par `metadata.cache` ;
    - ne se trouve pas sous `allowed_parent` (défaut
      `METADATA_CACHE_ALLOWED_PARENT`) une fois résolu (élimine `..`,
      symlinks de répertoire, etc.).

    `allowed_parent` n'est override-able que par du code appelant (tests),
    jamais par une valeur venue de la requête HTTP — en usage réel il vaut
    toujours `METADATA_CACHE_ALLOWED_PARENT`.

    Raises:
        MetadataCachePathError: si l'une des deux gardes échoue.
    """
    parent = allowed_parent if allowed_parent is not None else METADATA_CACHE_ALLOWED_PARENT
    candidate = Path(raw_path)
    if candidate.name != METADATA_CACHE_FILENAME:
        raise MetadataCachePathError(
            f"chemin de cache refusé (nom de fichier inattendu): {raw_path!r}"
        )
    resolved = candidate.resolve()
    try:
        resolved.relative_to(parent.resolve())
    except ValueError as exc:
        raise MetadataCachePathError(
            f"chemin de cache refusé (hors de {parent}): {raw_path!r}"
        ) from exc
    return resolved


@dataclass
class CachePurgeReport:
    """Résultat de la tentative de purge du cache de metadata."""

    requested: bool
    purged: bool
    message: str | None = None


def purge_metadata_cache(cache_path: Path) -> CachePurgeReport:
    """Supprime le fichier de cache de metadata s'il existe.

    Ne lève jamais : un fichier absent n'est pas une erreur (il peut ne pas
    exister, notamment sur un premier démarrage — voir `cannot load cache,
    ignoring` loggé par l'outlet, qui est normal). Un échec de suppression
    (droits) est reporté dans le message mais ne bloque pas la suite de la
    séquence de restart : mieux vaut un restart sans purge qu'un service
    resté arrêté.
    """
    try:
        cache_path.unlink()
    except FileNotFoundError:
        log.info("purge cache metadata: fichier absent (%s), rien à faire", cache_path)
        return CachePurgeReport(requested=True, purged=False, message="fichier absent")
    except OSError as exc:
        log.error("purge cache metadata: échec de suppression de %s: %s", cache_path, exc)
        return CachePurgeReport(
            requested=True, purged=False, message=f"échec de suppression: {exc}"
        )
    log.info("purge cache metadata: fichier supprimé (%s)", cache_path)
    return CachePurgeReport(requested=True, purged=True, message="fichier supprimé")


def read_metadata_cache_path_from_env() -> str:
    """Lit `METADATA_CACHE_PATH` en env, avec repli sur la valeur par défaut.

    Seul point d'entrée légitime pour cette valeur — jamais depuis le corps
    d'une requête HTTP (voir docstring de `resolve_metadata_cache_path`)."""
    return os.environ.get("METADATA_CACHE_PATH", DEFAULT_METADATA_CACHE_PATH)


def order_services(requested: Iterable[str]) -> list[str]:
    """Trie les services demandés selon `RESTART_ORDER` (déterministe).

    Les noms hors de `RESTART_ORDER` (ne devrait pas arriver après passage
    par l'allowlist) sont ajoutés à la fin, dans leur ordre d'apparition,
    plutôt que silencieusement perdus.
    """
    requested_set = list(dict.fromkeys(requested))  # dédoublonne, garde l'ordre
    known = [s for s in RESTART_ORDER if s in requested_set]
    unknown = [s for s in requested_set if s not in RESTART_ORDER]
    return known + unknown


class RestartAgentError(Exception):
    """Erreur métier de l'agent, portée par un code HTTP explicite."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def validate_requested_services(services: Iterable[str]) -> list[str]:
    """Valide une liste de noms de services contre l'allowlist en dur.

    Raises:
        RestartAgentError: 403 si `services` est vide ou contient un nom
            hors de `ALLOWED_SERVICES`. Aucun appel docker n'a lieu avant
            cette validation.
    """
    services_list = list(services)
    if not services_list:
        raise RestartAgentError(403, "aucun service demandé")
    for name in services_list:
        if name not in ALLOWED_SERVICES:
            log.error("service hors allowlist refusé: %r", name)
            raise RestartAgentError(403, f"service non autorisé: {name!r}")
    return services_list


@dataclass
class RateLimiter:
    """Rate-limit simple : un seul restart autorisé toutes les `interval_seconds`."""

    interval_seconds: float = DEFAULT_MIN_RESTART_INTERVAL_SECONDS
    _last_call_at: float | None = field(default=None, init=False, repr=False)

    def check(self) -> None:
        """Raises RestartAgentError(429) si un appel a eu lieu trop récemment."""
        now = time.monotonic()
        if self._last_call_at is not None:
            elapsed = now - self._last_call_at
            if elapsed < self.interval_seconds:
                retry_after = self.interval_seconds - elapsed
                log.error(
                    "rate-limit restart: appel il y a %.1fs (min %.0fs), retry_after=%.1fs",
                    elapsed,
                    self.interval_seconds,
                    retry_after,
                )
                raise RestartAgentError(
                    429, f"trop de restarts rapprochés, réessayer dans {retry_after:.0f}s"
                )
        self._last_call_at = now

    def reset(self) -> None:
        """Réinitialise le rate-limit. Utilisé par les tests uniquement."""
        self._last_call_at = None


class DockerContainerLike(Protocol):
    """Ce dont ce module a besoin d'un container docker (sous-ensemble typé du SDK).

    `Protocol` : typage structurel, pour que `RealDockerClient` (basé sur le
    SDK `docker` réel) et les doubles de test (aucune parenté de classe avec
    ce type) soient tous les deux acceptés sans cast ni héritage forcé.
    """

    name: str
    status: str

    def restart(self, timeout: int = 10) -> None: ...

    def stop(self, timeout: int = 10) -> None: ...

    def start(self) -> None: ...

    def reload(self) -> None: ...

    @property
    def health(self) -> str | None: ...  # "healthy" | "unhealthy" | "starting" | None


class DockerClientLike(Protocol):
    """Ce dont ce module a besoin du SDK docker (sous-ensemble typé, structurel)."""

    def find_container(self, service_name: str) -> DockerContainerLike | None: ...


class RealDockerClient:
    """Implémentation réelle, basée sur `docker.from_env()`.

    Cible un container par le label `com.docker.compose.service` du projet
    compose Akvorado — jamais par interpolation du nom dans une commande.
    """

    def __init__(self) -> None:
        import docker  # import différé : évite la dépendance dure en test

        self._client = docker.from_env()

    def find_container(self, service_name: str) -> DockerContainerLike | None:
        containers = self._client.containers.list(
            all=True,
            filters={
                "label": [
                    f"com.docker.compose.project={COMPOSE_PROJECT}",
                    f"com.docker.compose.service={service_name}",
                ]
            },
        )
        if not containers:
            return None
        # `Container` du SDK docker (types-docker) satisfait structurellement
        # `DockerContainerLike` (mêmes attributs/méthodes) mais n'en hérite pas
        # nommément : le cast documente une compatibilité vérifiée, pas une
        # incertitude.
        return cast(DockerContainerLike, containers[0])


def _container_health(container: DockerContainerLike) -> str | None:
    """Lit l'état de santé du container en re-synchronisant son état local.

    `reload()` est nécessaire : les attributs d'un objet `Container` du SDK
    docker sont figés à l'instant de leur récupération, sans re-fetch.
    """
    container.reload()
    return container.health


class RestartReport(BaseModel):
    """Résultat du restart d'un service — miroir du contrat client (voir app/clients/restart.py)."""

    service: str
    restarted: bool
    healthy: bool
    duration_seconds: float
    error: str | None = None
    cache_purged: bool = False
    cache_purge_message: str | None = None


class RestartRequest(BaseModel):
    services: list[str]
    purge_metadata_cache: bool = False
    """Purge optionnelle et explicite du cache de metadata Akvorado avant le
    redémarrage. Défaut `False` — jamais implicite. Nécessaire après une
    correction d'ifIndex/interface dans `outlet.yaml` : sans purge, l'outlet
    réutilise le cache disque et la correction reste sans effet visible sur
    les flux (`InIfName=unknown` / `InIfBoundary=undefined` persistants).
    N'affecte QUE le chemin résolu depuis la config serveur
    (`METADATA_CACHE_PATH`) — ce booléen ne transporte jamais de chemin."""


class RestartResponse(BaseModel):
    status: str
    reports: list[RestartReport]


class StatusEntry(BaseModel):
    service: str
    name: str | None = None
    status: str | None = None
    health: str | None = None


class StatusResponse(BaseModel):
    status: str
    items: list[StatusEntry]
    total: int


def restart_service(
    docker_client: DockerClientLike,
    service_name: str,
    *,
    healthy_timeout_seconds: float = DEFAULT_HEALTHY_TIMEOUT_SECONDS,
    poll_interval_seconds: float = DEFAULT_HEALTH_POLL_INTERVAL_SECONDS,
    sleep: Callable[[float], None] | None = None,
    now: Callable[[], float] | None = None,
    purge_cache_path: Path | None = None,
) -> RestartReport:
    """Redémarre UN service et attend qu'il redevienne `healthy`.

    Ne prétend jamais au succès sans vérification : si le container est
    introuvable, si le restart échoue, ou si le healthcheck ne passe pas au
    vert dans le délai imparti, le rapport porte `healthy=False` et `error`
    explicite.

    `purge_cache_path` : si fourni (chemin déjà validé par
    `resolve_metadata_cache_path`), la séquence devient **stop → purge du
    fichier → start** au lieu d'un simple `restart()`. Purger PENDANT que le
    service tourne ne sert à rien (il réécrit le cache en continu / à son
    prochain flush) ; il faut que le container soit arrêté avant la
    suppression, et la purge doit avoir lieu avant le redémarrage effectif
    pour que l'outlet reparte sans cache disque (log `cannot load cache,
    ignoring`, attendu). Si `purge_cache_path` est `None` (comportement par
    défaut, purge non demandée), le fichier n'est jamais touché.
    """
    sleep_fn = sleep or time.sleep
    now_fn = now or time.monotonic

    started_at = now_fn()

    container = docker_client.find_container(service_name)
    if container is None:
        log.error("container introuvable pour le service %r", service_name)
        return RestartReport(
            service=service_name,
            restarted=False,
            healthy=False,
            duration_seconds=now_fn() - started_at,
            error="container introuvable",
        )

    cache_purge_report: CachePurgeReport | None = None
    try:
        if purge_cache_path is not None:
            # Ordre critique : stop (le service arrête d'écrire/tenir le
            # fichier) -> purge -> start. Un `restart()` simple ne laisse pas
            # de fenêtre pour intervenir entre l'arrêt et le redémarrage.
            container.stop(timeout=10)
            cache_purge_report = purge_metadata_cache(purge_cache_path)
            container.start()
        else:
            container.restart(timeout=10)
    except Exception as exc:
        log.error("échec du restart docker pour %r: %s", service_name, exc)
        return RestartReport(
            service=service_name,
            restarted=False,
            healthy=False,
            duration_seconds=now_fn() - started_at,
            error=f"échec du restart: {exc}",
            cache_purged=bool(cache_purge_report and cache_purge_report.purged),
            cache_purge_message=cache_purge_report.message if cache_purge_report else None,
        )

    deadline = now_fn() + healthy_timeout_seconds
    healthy = False
    last_health: str | None = None
    while now_fn() < deadline:
        try:
            last_health = _container_health(container)
        except Exception as exc:
            log.error("échec de lecture de santé pour %r: %s", service_name, exc)
            last_health = None
        if last_health == "healthy":
            healthy = True
            break
        if last_health is None:
            # Pas de healthcheck défini sur ce container : on ne peut pas
            # prouver la santé, donc on ne prétend jamais healthy=True ici.
            break
        sleep_fn(poll_interval_seconds)

    duration = now_fn() - started_at
    error = None
    if not healthy:
        error = f"container non healthy après {duration:.0f}s (dernier état: {last_health!r})"
        log.error("service %r non healthy après restart: %s", service_name, error)

    return RestartReport(
        service=service_name,
        restarted=True,
        healthy=healthy,
        duration_seconds=duration,
        error=error,
        cache_purged=bool(cache_purge_report and cache_purge_report.purged),
        cache_purge_message=cache_purge_report.message if cache_purge_report else None,
    )


def _read_token_from_env() -> str:
    """Lit `RESTART_AGENT_TOKEN`. Fail-fast si absent (jamais de mode sans auth)."""
    token = os.environ.get("RESTART_AGENT_TOKEN", "")
    if not token:
        raise RuntimeError(
            "RESTART_AGENT_TOKEN n'est pas défini — l'agent refuse de démarrer sans auth"
        )
    return token


def check_token(provided_authorization_header: str | None, expected_token: str) -> None:
    """Vérifie le header `Authorization: Bearer <token>` en temps constant.

    Raises:
        RestartAgentError: 401 si le header est absent, mal formé, ou si le
            token ne correspond pas (comparaison `hmac.compare_digest`).
    """
    if not provided_authorization_header:
        raise RestartAgentError(401, "authentification requise")
    prefix = "Bearer "
    if not provided_authorization_header.startswith(prefix):
        raise RestartAgentError(401, "authentification requise")
    provided_token = provided_authorization_header[len(prefix) :]
    if not hmac.compare_digest(provided_token, expected_token):
        log.error("token de restart invalide fourni")
        raise RestartAgentError(401, "token invalide")


def create_app(
    *,
    token: str | None = None,
    docker_client: DockerClientLike | None = None,
    rate_limiter: RateLimiter | None = None,
    metadata_cache_path_raw: str | None = None,
    metadata_cache_allowed_parent: Path | None = None,
) -> FastAPI:
    """Construit l'app FastAPI. Fail-fast si aucun token n'est fourni/en env.

    `token` / `docker_client` / `rate_limiter` sont injectables pour les
    tests ; en usage réel (voir bas de fichier) ils viennent de l'env et de
    `docker.from_env()`. `metadata_cache_path_raw` de même : en usage réel il
    vient de `METADATA_CACHE_PATH` (voir `read_metadata_cache_path_from_env`),
    JAMAIS du corps d'une requête HTTP — `RestartRequest.purge_metadata_cache`
    n'est qu'un booléen, il ne transporte aucun chemin.
    `metadata_cache_allowed_parent` : override du répertoire attendu par la
    garde de `resolve_metadata_cache_path`, utile uniquement pour les tests
    (`tmp_path` n'est jamais sous `/data/akvorado/run`) ; en usage réel il
    vaut toujours `METADATA_CACHE_ALLOWED_PARENT`.
    """
    resolved_token = token if token is not None else _read_token_from_env()
    limiter = rate_limiter or RateLimiter()
    raw_cache_path = (
        metadata_cache_path_raw
        if metadata_cache_path_raw is not None
        else read_metadata_cache_path_from_env()
    )
    cache_allowed_parent = metadata_cache_allowed_parent or METADATA_CACHE_ALLOWED_PARENT

    app = FastAPI(title="okvorado-restart-agent")

    # Cache paresseux dans une liste à 1 élément (plutôt qu'une variable
    # réassignée via `nonlocal`) : mypy --strict ne parvient pas à re-figer le
    # type de `docker_client` après une réaffectation dans une closure, la
    # liste évite l'aller-retour de narrowing.
    _docker_client_cache: list[DockerClientLike] = (
        [docker_client] if docker_client is not None else []
    )

    def _get_docker_client() -> DockerClientLike:
        if not _docker_client_cache:
            _docker_client_cache.append(RealDockerClient())
        return _docker_client_cache[0]

    @app.get("/health")
    def get_health() -> dict[str, str]:
        return {"status": "ok", "service": "okvorado-restart-agent"}

    @app.post("/restart", response_model=RestartResponse)
    def post_restart(
        request: RestartRequest, authorization: str | None = Header(default=None)
    ) -> RestartResponse:
        try:
            check_token(authorization, resolved_token)
            ordered = order_services(validate_requested_services(request.services))
            limiter.check()
        except RestartAgentError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

        # Le chemin de purge vient UNIQUEMENT de la config serveur
        # (`raw_cache_path`, résolu à la construction de l'app depuis
        # `METADATA_CACHE_PATH`) — `request.purge_metadata_cache` n'est qu'un
        # booléen, il ne transporte jamais de chemin. Un chemin de config
        # invalide (garde `resolve_metadata_cache_path`) désactive la purge
        # pour toute la requête plutôt que de faire échouer le restart.
        purge_cache_path: Path | None = None
        if request.purge_metadata_cache:
            try:
                purge_cache_path = resolve_metadata_cache_path(
                    raw_cache_path, allowed_parent=cache_allowed_parent
                )
            except MetadataCachePathError as exc:
                log.error("purge cache metadata refusée: %s", exc)

        log.info(
            "restart demandé at=%s services=%s purge_metadata_cache=%s",
            datetime.now(UTC).isoformat(),
            ordered,
            request.purge_metadata_cache,
        )
        client = _get_docker_client()
        reports = [
            restart_service(client, name, purge_cache_path=purge_cache_path) for name in ordered
        ]
        for report in reports:
            if not report.healthy:
                log.error(
                    "restart terminé avec échec service=%s error=%s", report.service, report.error
                )
        log.info(
            "restart terminé services=%s résultats=%s",
            ordered,
            [(r.service, r.restarted, r.healthy) for r in reports],
        )
        status = "ok" if all(r.healthy for r in reports) else "degraded"
        return RestartResponse(status=status, reports=reports)

    @app.get("/status", response_model=StatusResponse)
    def get_status(authorization: str | None = Header(default=None)) -> StatusResponse:
        try:
            check_token(authorization, resolved_token)
        except RestartAgentError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

        client = _get_docker_client()
        items: list[StatusEntry] = []
        for service_name in sorted(ALLOWED_SERVICES):
            container = client.find_container(service_name)
            if container is None:
                items.append(StatusEntry(service=service_name, status="absent"))
                continue
            try:
                container.reload()
                health = container.health
            except Exception as exc:
                log.error("échec de lecture de statut pour %r: %s", service_name, exc)
                health = None
            items.append(
                StatusEntry(
                    service=service_name,
                    name=container.name,
                    status=container.status,
                    health=health,
                )
            )
        return StatusResponse(status="ok", items=items, total=len(items))

    return app


# Point d'entrée réel (uvicorn agent:app). Fail-fast si le token env manque.
app = create_app()
