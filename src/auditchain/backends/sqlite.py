"""SQLite backend — durable storage for real applications (zero extra dependencies)."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from collections.abc import Sequence
from pathlib import Path

from ..records import AuditRecord
from .base import StorageBackend

_INSERT_SQL = (
    "INSERT INTO audit_records (seq, ts, actor, action, subject, meta, prev_hash, hash, key_id)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_records (
    seq       INTEGER PRIMARY KEY,
    ts        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    subject   TEXT NOT NULL DEFAULT '',
    meta      TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL,
    key_id    TEXT NOT NULL DEFAULT ''
)
"""


class SqliteBackend(StorageBackend):
    """Stores records in a single SQLite table.

    The sqlite3 module is synchronous, so all calls run through ``asyncio.to_thread``
    with a lock; this keeps the library free of runtime dependencies.

    Existing v0.1 databases (without the ``key_id`` column) are migrated in place on
    ``init()``; their records stay verifiable.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def _connection(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("SqliteBackend is not initialized; call init() first")
        return self._conn

    async def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

        def _init() -> sqlite3.Connection:
            conn = sqlite3.connect(self.path, check_same_thread=False)
            conn.execute(_SCHEMA)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_records)")}
            if "key_id" not in columns:
                conn.execute("ALTER TABLE audit_records ADD COLUMN key_id TEXT NOT NULL DEFAULT ''")
            conn.commit()
            return conn

        self._conn = await asyncio.to_thread(_init)

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

    # fmt: off
    _SELECT_SQL = (
        "SELECT seq, ts, actor, action, subject, meta, prev_hash, hash, key_id"
        " FROM audit_records ORDER BY seq"
    )
    # fmt: on

    async def append(self, record: AuditRecord) -> None:
        def _append() -> None:
            with self._lock:
                self._connection().execute(_INSERT_SQL, self._row_values(record))
                self._connection().commit()

        await asyncio.to_thread(_append)

    async def append_many(self, records: Sequence[AuditRecord]) -> None:
        rows = [self._row_values(record) for record in records]

        def _append_many() -> None:
            with self._lock:
                conn = self._connection()
                try:
                    conn.executemany(_INSERT_SQL, rows)
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise

        await asyncio.to_thread(_append_many)

    async def load(self) -> list[AuditRecord]:
        def _load() -> list[AuditRecord]:
            with self._lock:
                rows = self._connection().execute(self._SELECT_SQL).fetchall()
            return [
                AuditRecord.from_stored(
                    {
                        "seq": row[0],
                        "ts": row[1],
                        "actor": row[2],
                        "action": row[3],
                        "subject": row[4],
                        "meta": json.loads(row[5]),
                        "prev_hash": row[6],
                        "hash": row[7],
                        "key_id": row[8],
                    }
                )
                for row in rows
            ]

        return await asyncio.to_thread(_load)

    async def close(self) -> None:
        def _close() -> None:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

        await asyncio.to_thread(_close)
