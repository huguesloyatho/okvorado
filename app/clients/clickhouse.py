"""Client ClickHouse en lecture seule pour le module Exportateurs.

GARDE SÉCU N°1 DU PROJET : requêtes paramétrées exclusivement. Les noms de
tables/colonnes sont des littéraux en dur ; seule la fenêtre temporelle (déjà
validée en amont par `window_to_interval()`) transite, et elle transite via
le mécanisme de paramètres du driver (`{nom:Type}`), jamais par interpolation
de chaîne.
"""

from __future__ import annotations

import logging

import clickhouse_connect
from clickhouse_connect.driver.client import Client

from app.config import Settings, interval_to_seconds, settings
from app.models import ObservedExporter

log = logging.getLogger(__name__)

# ⚠️ `Bytes * SamplingRate`, JAMAIS `Bytes` seul.
#
# NetFlow échantillonné ne transporte QU'UNE FRACTION des flux : un routeur
# configuré en 1:1000 n'émet qu'un flux sur mille, et `SamplingRate` porte le
# facteur à réappliquer. Sommer `Bytes` sans le multiplier sous-estime le
# volume d'autant — on lirait 1 Go là où il y a 1 To.
#
# INVISIBLE EN HOMELAB, et c'est ce qui rend le défaut dangereux : les
# exportateurs logiciels du homelab (softflowd) émettent TOUS les flux, donc
# `SamplingRate = 1` (mesuré le 2026-08-07 : 510 898 flux, tous à 1) et
# `Bytes * 1 == Bytes`. Le calcul faux et le calcul juste donnent le même
# résultat ici, et divergeraient d'un facteur 1000 sur un équipement
# d'entreprise — sans erreur, sans avertissement, avec des graphes cohérents
# entre eux mais tous faux.
_OBSERVED_EXPORTERS_SQL = """
SELECT
    ExporterAddress AS exporter_address,
    ExporterName AS exporter_name,
    count() AS flow_count,
    sum(Bytes * SamplingRate) AS byte_count,
    max(TimeReceived) AS last_seen,
    groupUniqArray(InIfName) AS in_if_names
FROM default.flows
WHERE TimeReceived >= now() - toIntervalSecond({window_seconds:UInt32})
GROUP BY ExporterAddress, ExporterName
ORDER BY flow_count DESC
"""
"""SQL figé : table et colonnes sont des littéraux en dur, seule la fenêtre
transite en paramètre lié (`{window_seconds:UInt32}`), jamais interpolée
dans la chaîne.

ATTENTION (mesuré le 2026-08-05 sur la vraie base) : `INTERVAL {p:String}` est
REFUSÉ par ClickHouse (SYNTAX_ERROR) — la clause INTERVAL exige un littéral.
`toIntervalSecond({p:UInt32})` accepte un paramètre lié et conserve donc la
garde anti-injection."""


def normalize_exporter_address(address: str) -> str:
    """Normalise une adresse ClickHouse (potentiellement IPv6-mapped) en IPv4 lisible.

    `ExporterAddress` est stockée en IPv6 dans ClickHouse : une IPv4 s'écrit
    préfixée `::ffff:` (cf. CONTRACT.md). Une IPv6 native (non mappée) est
    retournée inchangée.
    """
    lowered = address.lower()
    prefix = "::ffff:"
    if lowered.startswith(prefix):
        return address[len(prefix) :]
    return address


def build_observed_exporters_query(window_interval: str) -> tuple[str, dict[str, int]]:
    """Construit la requête d'agrégation des exportateurs observés.

    Args:
        window_interval: littéral d'intervalle ClickHouse (ex "1 HOUR"), produit
            exclusivement par `app.config.window_to_interval()` — jamais une
            saisie utilisateur brute.

    Returns:
        Un tuple (sql, parameters) : `sql` ne contient JAMAIS la fenêtre
        interpolée en dur, la valeur transite uniquement via `parameters`, liée
        par le driver via `toIntervalSecond({window_seconds:UInt32})`.
    """
    return _OBSERVED_EXPORTERS_SQL, {"window_seconds": interval_to_seconds(window_interval)}


def connect(config: Settings = settings) -> Client:
    """Ouvre un client ClickHouse HTTP à partir de la configuration.

    Aucune valeur d'infra en dur : hôte/port/creds proviennent de `settings`.
    """
    return clickhouse_connect.get_client(
        host=config.effective_clickhouse_host,
        port=config.clickhouse_port,
        username=config.clickhouse_user,
        password=config.clickhouse_password,
        database=config.clickhouse_database,
    )


def fetch_observed_exporters(client: Client, window_interval: str) -> list[ObservedExporter]:
    """Exécute la requête d'agrégation et retourne les exportateurs observés.

    Args:
        client: client ClickHouse déjà connecté (injecté — jamais construit ici
            implicitement, pour que les tests puissent fournir un mock).
        window_interval: littéral d'intervalle issu de `window_to_interval()`.
    """
    sql, parameters = build_observed_exporters_query(window_interval)
    try:
        result = client.query(sql, parameters=parameters)
    except Exception:
        log.error(
            "echec requete clickhouse fetch_observed_exporters window=%s",
            window_interval,
            exc_info=True,
        )
        raise

    observed: list[ObservedExporter] = []
    for row in result.result_rows:
        address_raw, exporter_name, flow_count, byte_count, last_seen, in_if_names = row
        observed.append(
            ObservedExporter(
                address=normalize_exporter_address(str(address_raw)),
                name=str(exporter_name),
                flows=int(flow_count),
                bytes=int(byte_count),
                last_seen=last_seen,
                interfaces=[str(if_name) for if_name in in_if_names if if_name],
            )
        )
    return observed
