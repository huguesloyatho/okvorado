"""Client HTTP vers l'agent de restart Akvorado (`restart-agent/agent.py`).

Okvorado ne monte JAMAIS `/var/run/docker.sock` (ça donnerait root sur l'hôte
à une app web exposée à des utilisateurs — règle non négociable, voir
CONTRACT.md). Le redémarrage des containers Akvorado passe donc par ce client,
qui parle à un agent HTTP séparé, protégé par token, qui lui monte le socket.

Les settings attendus (`restart_agent_host`, `restart_agent_port`,
`restart_agent_token`, `restart_timeout_seconds`) n'existent pas encore dans
`app/config.py` (hors périmètre de ce module — voir le rapport de livraison
pour les noms et défauts exacts à câbler ; `.env.example` documente déjà
`OKVORADO_RESTART_AGENT_HOST` / `OKVORADO_RESTART_AGENT_PORT` /
`OKVORADO_RESTART_AGENT_TOKEN` / `OKVORADO_RESTART_TIMEOUT_SECONDS`, ce module
s'y aligne). En attendant, ce client lit ces attributs sur `settings` via
`getattr(..., default)` pour ne pas planter à l'import tant que LOT 0 n'a pas
ajouté les champs.
"""

from __future__ import annotations

import logging

import httpx
from pydantic import BaseModel

from app.config import settings

log = logging.getLogger(__name__)

DEFAULT_RESTART_AGENT_TIMEOUT_SECONDS = 150.0
"""Généreux à dessein : un restart + attente `healthy` peut prendre 60-120 s
côté agent (`DEFAULT_HEALTHY_TIMEOUT_SECONDS` dans restart-agent/agent.py).
Un timeout de 10s côté client couperait l'appel avant que l'agent ait fini,
et Okvorado rapporterait un échec sur un restart qui a en fait réussi."""


class RestartReport(BaseModel):
    """Résultat du restart d'UN service — miroir exact de `agent.py:RestartReport`."""

    service: str
    restarted: bool
    healthy: bool
    duration_seconds: float
    error: str | None = None


class RestartResult(BaseModel):
    """Résultat consolidé, consommé par les routers/templates Okvorado."""

    ok: bool
    """True seulement si TOUS les services demandés sont revenus `healthy`."""

    reports: list[RestartReport]
    message: str
    """Phrase en clair pour un utilisateur non expert (jamais une trace brute)."""


class AkvoradoStatusEntry(BaseModel):
    """Statut d'UN container Akvorado — miroir de `agent.py:StatusEntry`."""

    service: str
    name: str | None = None
    status: str | None = None
    health: str | None = None


class AkvoradoStatus(BaseModel):
    """Statut de tous les containers Akvorado connus de l'agent (pour l'UI)."""

    items: list[AkvoradoStatusEntry]
    total: int


def _restart_agent_url() -> str:
    """URL de base de l'agent de restart, construite depuis host+port.

    Lu via `getattr` : `restart_agent_host` / `restart_agent_port` n'existent
    pas encore dans `Settings` (LOT 0 doit les ajouter — voir rapport de
    livraison). Suit le même pattern que `settings.outlet_metrics_url` /
    `settings.akvorado_console_url` (host+port assemblés, jamais une URL
    stockée telle quelle) pour rester cohérent avec `app/config.py`.
    """
    host = getattr(settings, "restart_agent_host", "")
    if not host:
        raise RuntimeError(
            "restart_agent_host n'est pas configuré (settings.restart_agent_host manquant ou vide)"
        )
    port = getattr(settings, "restart_agent_port", 8098)
    return f"http://{host}:{port}"


def _restart_agent_token() -> str:
    """Token porté par le header `Authorization: Bearer <token>`.

    Lu via `getattr` : `restart_agent_token` n'existe pas encore dans
    `Settings` (LOT 0 doit l'ajouter — voir rapport de livraison).
    """
    token = getattr(settings, "restart_agent_token", "")
    if not token:
        raise RuntimeError(
            "restart_agent_token n'est pas configuré "
            "(settings.restart_agent_token manquant ou vide)"
        )
    return str(token)


def _restart_agent_timeout_seconds() -> float:
    """Timeout HTTP du client, généreux par défaut (restart + attente healthy)."""
    return float(
        getattr(settings, "restart_timeout_seconds", DEFAULT_RESTART_AGENT_TIMEOUT_SECONDS)
    )


def _auth_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_restart_agent_token()}"}


async def restart_akvorado(
    services: list[str], *, purge_metadata_cache: bool = False
) -> RestartResult:
    """Demande à l'agent de redémarrer les `services` Akvorado listés.

    Ne lève JAMAIS d'exception httpx brute : toute erreur réseau, timeout,
    401 (token refusé) ou 429 (rate-limit) est traduite en `RuntimeError`
    avec un message clair, après un `log.error()` avec contexte. Les erreurs
    métier de l'agent (403 sur un service hors allowlist, par ex.) suivent le
    même traitement — l'appelant n'a jamais à connaître httpx.

    Args:
        services: services Akvorado à redémarrer (allowlist côté agent).
        purge_metadata_cache: supprime le cache de metadata pendant que les
            services sont arrêtés. INDISPENSABLE après un changement d'ifIndex
            ou d'interface : sans purge, Akvorado conserve l'ancienne
            correspondance `ifIndex -> interface` et les flux restent classés
            `unknown`/`undefined` — la correction reste sans effet visible
            (mesuré en production le 2026-08-05).

    Returns:
        RestartResult: `ok=True` seulement si TOUS les rapports sont healthy.
    """
    url = f"{_restart_agent_url()}/restart"
    timeout = _restart_agent_timeout_seconds()
    payload = {"services": services, "purge_metadata_cache": purge_metadata_cache}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=_auth_headers())
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        log.error(
            "délai dépassé en demandant le restart Akvorado url=%s timeout=%ss services=%s: %s",
            url,
            timeout,
            services,
            exc,
        )
        raise RuntimeError(
            f"pas de réponse de l'agent de restart après {timeout:.0f}s : redémarrage incertain, "
            "vérifier l'état des containers Akvorado manuellement"
        ) from exc
    except httpx.HTTPStatusError as exc:
        status_code = exc.response.status_code
        log.error(
            "l'agent de restart a refusé la demande url=%s status=%s services=%s body=%s",
            url,
            status_code,
            services,
            exc.response.text,
        )
        if status_code == 401:
            raise RuntimeError("authentification refusée par l'agent de restart") from exc
        if status_code == 403:
            raise RuntimeError(
                f"service non autorisé par l'agent de restart: {exc.response.text}"
            ) from exc
        if status_code == 429:
            raise RuntimeError(
                "trop de demandes de restart rapprochées, réessayer dans quelques instants"
            ) from exc
        raise RuntimeError(
            f"l'agent de restart a répondu {status_code}: {exc.response.text}"
        ) from exc
    except httpx.HTTPError as exc:
        log.error(
            "échec de connexion à l'agent de restart url=%s services=%s: %s", url, services, exc
        )
        raise RuntimeError(f"échec de connexion à l'agent de restart ({url}) : {exc}") from exc

    payload = response.json()
    reports = [RestartReport.model_validate(item) for item in payload.get("reports", [])]
    ok = bool(reports) and all(report.healthy for report in reports)

    if ok:
        message = "Tous les services Akvorado demandés ont redémarré et sont sains."
    else:
        failed = [r.service for r in reports if not r.healthy]
        message = (
            f"Redémarrage incomplet : {', '.join(failed) or 'aucun service traité'} "
            "n'est pas revenu sain. Vérifier les logs des containers concernés."
        )

    return RestartResult(ok=ok, reports=reports, message=message)


async def fetch_akvorado_status() -> AkvoradoStatus:
    """Récupère l'état courant des containers Akvorado connus de l'agent (pour l'UI).

    Mêmes garanties que `restart_akvorado()` : jamais d'exception httpx brute,
    toujours un `RuntimeError` clair après `log.error()`.
    """
    url = f"{_restart_agent_url()}/status"
    timeout = _restart_agent_timeout_seconds()

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=_auth_headers())
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        log.error(
            "délai dépassé en récupérant le statut Akvorado url=%s timeout=%ss: %s",
            url,
            timeout,
            exc,
        )
        raise RuntimeError(f"pas de réponse de l'agent de restart après {timeout:.0f}s") from exc
    except httpx.HTTPStatusError as exc:
        log.error(
            "l'agent de restart a refusé la demande de statut url=%s status=%s body=%s",
            url,
            exc.response.status_code,
            exc.response.text,
        )
        if exc.response.status_code == 401:
            raise RuntimeError("authentification refusée par l'agent de restart") from exc
        raise RuntimeError(
            f"l'agent de restart a répondu {exc.response.status_code}: {exc.response.text}"
        ) from exc
    except httpx.HTTPError as exc:
        log.error("échec de connexion à l'agent de restart url=%s: %s", url, exc)
        raise RuntimeError(f"échec de connexion à l'agent de restart ({url}) : {exc}") from exc

    payload = response.json()
    items = [AkvoradoStatusEntry.model_validate(item) for item in payload.get("items", [])]
    return AkvoradoStatus(items=items, total=payload.get("total", len(items)))
