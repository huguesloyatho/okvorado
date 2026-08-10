"""Dépendances partagées — la colle entre les lots.

Le client `clickhouse_connect` renvoie un `QueryResult` (avec `.result_rows`)
alors que certains services attendent directement une `list[tuple]`. Plutôt que
d'imposer une forme à l'un ou à l'autre, cet adaptateur réconcilie les deux :
chaque service reste testable avec un double simple, et le câblage réel vit ici.
"""

import logging
from typing import Any, Protocol

from app.clients.clickhouse import connect

log = logging.getLogger(__name__)


class ClickHouseQueryable(Protocol):
    """Ce dont les services ont besoin : exécuter une requête paramétrée."""

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> Any: ...


class RowsAdapter:
    """Expose un client clickhouse_connect en renvoyant directement les lignes.

    `QueryResult.result_rows` est une `list[tuple]` : c'est la forme attendue par
    les services qui agrègent (rétention, vues métier).
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> list[tuple[Any, ...]]:
        result = self._client.query(sql, parameters=parameters or {})
        rows: list[tuple[Any, ...]] = list(result.result_rows)
        return rows


def get_clickhouse_rows_client() -> RowsAdapter:
    """Client ClickHouse renvoyant des lignes brutes (services rétention/vues).

    Raises:
        RuntimeError: si la connexion ne peut pas être établie. L'appelant doit
            la capturer pour afficher un message clair plutôt qu'une erreur nue.
    """
    try:
        return RowsAdapter(connect())
    except Exception as exc:
        log.error("connexion ClickHouse impossible: %s", exc)
        raise RuntimeError(f"connexion ClickHouse impossible: {exc}") from exc


def get_clickhouse_client() -> Any:
    """Client ClickHouse natif (service exportateurs, qui type ses retours lui-même)."""
    try:
        return connect()
    except Exception as exc:
        log.error("connexion ClickHouse impossible: %s", exc)
        raise RuntimeError(f"connexion ClickHouse impossible: {exc}") from exc
