"""PostgreSQL backend via asyncpg (optional extra: ``auditchain[postgres]``)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from ..records import AuditRecord
from .base import StorageBackend

_SCHEMA = """
CREATE TABLE IF NOT EXISTS "{table}" (
    seq       BIGINT PRIMARY KEY,
    ts        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    subject   TEXT NOT NULL DEFAULT '',
    meta      TEXT NOT NULL DEFAULT '{{}}',
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL,
    key_id    TEXT NOT NULL DEFAULT ''
)
"""

_INSERT_SQL = (
    'INSERT INTO "{table}" (seq, ts, actor, action, subject, meta, prev_hash, hash, key_id)'
    " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
)

_SELECT_SQL = (
    "SELECT seq, ts, actor, action, subject, meta, prev_hash, hash, key_id"
    ' FROM "{table}" ORDER BY seq'
)


class PostgresBackend(StorageBackend):
    """Stores records in a PostgreSQL table through a connection pool.

    Requires the optional dependency: ``pip install auditchain[postgres]``.
    """

    def __init__(self, dsn: str, table: str = "audit_records") -> None:
        self.dsn = dsn
        self.table = table
        self._pool: Any = None

    def _require_asyncpg(self):
        try:
            import asyncpg  # noqa: F401 - imported for the side effect of the error message

            return asyncpg
        except ImportError as exc:
            raise ImportError(
                "PostgresBackend requires the 'postgres' extra: pip install auditchain[postgres]"
            ) from exc

    async def init(self) -> None:
        asyncpg = self._require_asyncpg()
        if self._pool is None:
            self._pool = await asyncpg.create_pool(self.dsn)
        async with self._pool.acquire() as conn:
            await conn.execute(_SCHEMA.format(table=self.table))

    async def append(self, record: AuditRecord) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                _INSERT_SQL.format(table=self.table),
                *self._row_values(record),
            )

    async def append_many(self, records: Sequence[AuditRecord]) -> None:
        rows = [self._row_values(record) for record in records]
        async with self._pool.acquire() as conn, conn.transaction():
            await conn.executemany(_INSERT_SQL.format(table=self.table), rows)

    @staticmethod
    def _row_values(record: AuditRecord) -> tuple:
        return (
            record.seq,
            record.timestamp,
            record.actor,
            record.action,
            record.subject,
            json.dumps(record.metadata, sort_keys=True, ensure_ascii=False, separators=(",", ":")),
            record.prev_hash,
            record.hash,
            record.key_id,
        )

    async def load(self) -> list[AuditRecord]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(_SELECT_SQL.format(table=self.table))
        return [
            AuditRecord.from_stored(
                {
                    "seq": row["seq"],
                    "ts": row["ts"],
                    "actor": row["actor"],
                    "action": row["action"],
                    "subject": row["subject"],
                    "meta": json.loads(row["meta"]),
                    "prev_hash": row["prev_hash"],
                    "hash": row["hash"],
                    "key_id": row["key_id"],
                }
            )
            for row in rows
        ]

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
