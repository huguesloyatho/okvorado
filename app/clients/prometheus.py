"""Client et parser des métriques Prometheus de l'outlet Akvorado.

Un flux rejeté par Akvorado n'est JAMAIS stocké dans ClickHouse : la liste
des rejets est donc structurellement incalculable depuis la base. La seule
source de vérité est ce endpoint Prometheus de l'outlet
(`settings.outlet_metrics_url` -> `http://<host>:8080/api/v0/outlet/metrics`).

⚠️ `/metrics` renvoie 404 sur l'outlet — seul le chemin de la config est valide.

Le parsing (fonction pure, testable sur échantillon figé) est séparé du fetch
(I/O réseau via httpx, async, timeout explicite).
"""

from __future__ import annotations

import asyncio
import logging
import re

import httpx
from pydantic import BaseModel, Field

from app.config import settings

log = logging.getLogger(__name__)

_METRIC_FORWARDED = "akvorado_outlet_core_forwarded_flows_total"
_METRIC_REJECTED = "akvorado_outlet_core_flows_errors_total"
_METRIC_KAFKA_DROPPED = "akvorado_outlet_kafkaoutput_dropped_messages_total"
_METRIC_METADATA_ERRORS = "akvorado_outlet_metadata_provider_errors_total"
_METRIC_KAFKA_CONNECT_ERRORS = "akvorado_outlet_kafkainput_connect_errors_total"

# Format Prometheus text-exposition d'une ligne de métrique :
#   metric_name{label1="value1",label2="value2"} value
#   metric_name value
# `value` peut être en notation scientifique (2.161545e+06). Les valeurs de
# labels peuvent contenir des espaces et des guillemets échappés (\").
_METRIC_LINE_RE = re.compile(
    r"""^
    (?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)
    (?:\{(?P<labels>[^}]*)\})?
    \s+
    (?P<value>[-+0-9.eE]+)
    \s*$
    """,
    re.VERBOSE,
)

# Une paire label="value" à l'intérieur des accolades. La valeur peut contenir
# n'importe quel caractère échappé (\") ou non (espaces compris), jusqu'au
# prochain guillemet non échappé.
_LABEL_PAIR_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


class OutletMetrics(BaseModel):
    """Compteurs bruts extraits des métriques Prometheus de l'outlet.

    Contrat consommé par le LOT 1 (`build_exporter_statuses`) — ne pas
    renommer les champs `forwarded_by_exporter` / `rejected_by_exporter` /
    `rejection_reasons`.
    """

    forwarded_by_exporter: dict[str, int] = Field(default_factory=dict)
    rejected_by_exporter: dict[str, int] = Field(default_factory=dict)
    rejection_reasons: dict[str, dict[str, int]] = Field(default_factory=dict)

    kafka_dropped_messages: int = 0
    metadata_provider_errors: int = 0
    kafka_connect_errors: int = 0


def _unescape_label_value(raw: str) -> str:
    """Dé-échappe une valeur de label Prometheus (`\\"` -> `"`, `\\\\` -> `\\`)."""
    return raw.replace('\\"', '"').replace("\\\\", "\\")


def _parse_labels(raw_labels: str | None) -> dict[str, str]:
    """Parse la liste de labels `key="value",key2="value2"` d'une ligne.

    Ignore silencieusement toute paire qui ne matche pas le format attendu :
    une ligne malformée ne doit jamais faire planter le parsing global.
    """
    if not raw_labels:
        return {}
    labels: dict[str, str] = {}
    for match in _LABEL_PAIR_RE.finditer(raw_labels):
        key, value = match.group(1), match.group(2)
        labels[key] = _unescape_label_value(value)
    return labels


def _parse_value(raw_value: str) -> int | None:
    """Parse une valeur Prometheus (notation scientifique ou entière) en int.

    Une lecture naïve en `int()` échoue sur `2.161545e+06` : on passe
    obligatoirement par `float` avant de tronquer en `int`.
    """
    try:
        return int(float(raw_value))
    except ValueError:
        return None


def parse_outlet_metrics(text: str) -> OutletMetrics:
    """Parse un corps Prometheus text-format en `OutletMetrics`.

    Fonction pure, aucune I/O. Tolère : lignes de commentaire (`# HELP`,
    `# TYPE`), lignes vides, lignes malformées, métriques sans labels,
    métriques absentes (le résultat ne comporte alors que des dicts vides).
    """
    metrics = OutletMetrics()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        match = _METRIC_LINE_RE.match(line)
        if match is None:
            log.debug("ligne prometheus ignorée (format non reconnu): %r", line)
            continue

        metric_name = match.group("name")
        value = _parse_value(match.group("value"))
        if value is None:
            log.debug("valeur prometheus ignorée (non numérique): %r", line)
            continue

        labels = _parse_labels(match.group("labels"))

        if metric_name == _METRIC_FORWARDED:
            exporter = labels.get("exporter")
            if exporter is not None:
                metrics.forwarded_by_exporter[exporter] = value
        elif metric_name == _METRIC_REJECTED:
            exporter = labels.get("exporter")
            error = labels.get("error")
            if exporter is not None and error is not None:
                metrics.rejected_by_exporter[exporter] = (
                    metrics.rejected_by_exporter.get(exporter, 0) + value
                )
                metrics.rejection_reasons.setdefault(exporter, {})[error] = value
        elif metric_name == _METRIC_KAFKA_DROPPED:
            metrics.kafka_dropped_messages = value
        elif metric_name == _METRIC_METADATA_ERRORS:
            metrics.metadata_provider_errors = value
        elif metric_name == _METRIC_KAFKA_CONNECT_ERRORS:
            metrics.kafka_connect_errors += value

    return metrics


CACHE_TTL_SECONDS = 15.0
"""Durée de vie du cache des métriques.

Le endpoint renvoie ~100 Ko et met 1,5 à 4 s à répondre. Sans cache, la page
HTML et chaque rafraîchissement HTMX déclenchent leur propre fetch : sous
concurrence les appels se piétinent et expirent (mesuré : 3 timeouts sur
4 requêtes simultanées, compteurs affichés à 0 alors que l'outlet répondait).

Les compteurs sont cumulatifs et l'UI se rafraîchit toutes les 30 s : 15 s de
cache ne perd aucune information utile.
"""

_cache: tuple[float, OutletMetrics] | None = None
_cache_lock = asyncio.Lock()


def clear_metrics_cache() -> None:
    """Vide le cache des métriques.

    Indispensable pour les tests : sans cela un cas d'erreur (timeout, HTTP 500)
    renverrait la valeur mise en cache par un test précédent au lieu de lever,
    et le test passerait à tort.
    """
    global _cache
    _cache = None


async def fetch_outlet_metrics(*, force_refresh: bool = False) -> OutletMetrics:
    """Récupère et parse les métriques Prometheus de l'outlet.

    Résultat mis en cache `CACHE_TTL_SECONDS` et protégé par un verrou : plusieurs
    requêtes concurrentes ne déclenchent qu'UN seul appel réseau, les autres
    réutilisent le résultat au lieu d'entrer en compétition et d'expirer.

    Timeout explicite via `settings.http_timeout_seconds`. Toute erreur
    réseau ou HTTP est loggée avec contexte puis relevée en `RuntimeError`
    contrôlée — jamais une exception httpx brute qui remonterait jusqu'à
    l'UI (l'appelant doit pouvoir afficher un message clair sans page
    blanche ni 500 nu).
    """
    global _cache

    loop = asyncio.get_running_loop()
    if not force_refresh and _cache is not None:
        cached_at, cached_value = _cache
        if loop.time() - cached_at < CACHE_TTL_SECONDS:
            return cached_value

    async with _cache_lock:
        # Re-vérification sous verrou : pendant l'attente, une autre requête a
        # pu remplir le cache — inutile de refaire l'appel réseau.
        if not force_refresh and _cache is not None:
            cached_at, cached_value = _cache
            if loop.time() - cached_at < CACHE_TTL_SECONDS:
                return cached_value
        metrics = await _fetch_outlet_metrics_uncached()
        _cache = (loop.time(), metrics)
        return metrics


async def _fetch_outlet_metrics_uncached() -> OutletMetrics:
    """Appel réseau réel, sans cache. Utilisé par `fetch_outlet_metrics()`."""
    url = settings.outlet_metrics_url
    timeout = settings.http_timeout_seconds

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            response.raise_for_status()
    except httpx.TimeoutException as exc:
        log.error(
            "délai dépassé en récupérant les métriques outlet url=%s timeout=%ss: %s",
            url,
            timeout,
            exc,
        )
        raise RuntimeError(f"pas de réponse de l'outlet après {timeout}s ({url}) : {exc}") from exc
    except httpx.HTTPStatusError as exc:
        log.error(
            "statut HTTP inattendu en récupérant les métriques outlet url=%s status=%s: %s",
            url,
            exc.response.status_code,
            exc,
        )
        raise RuntimeError(f"outlet a répondu {exc.response.status_code} sur {url}") from exc
    except httpx.HTTPError as exc:
        log.error("erreur réseau en récupérant les métriques outlet url=%s: %s", url, exc)
        raise RuntimeError(f"échec de connexion à l'outlet ({url}) : {exc}") from exc

    return parse_outlet_metrics(response.text)
