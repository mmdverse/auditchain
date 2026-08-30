"""SQLite backend — durable storage for real applications (zero extra dependencies)."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from pathlib import Path

from ..records import AuditRecord
from .base import StorageBackend

_INSERT_SQL = (
    "INSERT INTO audit_records (seq, ts, actor, action, subject, meta, prev_hash, hash)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
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
    hash      TEXT NOT NULL
)
"""


class SqliteBackend(StorageBackend):
    """Stores records in a single SQLite table.

    The sqlite3 module is synchronous, so all calls run through ``asyncio.to_thread``
    with a lock; this keeps the library free of runtime dependencies.
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
            conn.commit()
            return conn

        self._conn = await asyncio.to_thread(_init)

    async def append(self, record: AuditRecord) -> None:
        meta = json.dumps(
            record.metadata, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        )

        def _append() -> None:
            with self._lock:
                self._connection().execute(
                    _INSERT_SQL,
                    (
                        record.seq,
                        record.timestamp,
                        record.actor,
                        record.action,
                        record.subject,
                        meta,
                        record.prev_hash,
                        record.hash,
                    ),
                )
                self._connection().commit()

        await asyncio.to_thread(_append)

    async def load(self) -> list[AuditRecord]:
        def _load() -> list[AuditRecord]:
            with self._lock:
                rows = (
                    self._connection()
                    .execute(
                        "SELECT seq, ts, actor, action, subject, meta, prev_hash, hash"
                        " FROM audit_records ORDER BY seq"
                    )
                    .fetchall()
                )
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
