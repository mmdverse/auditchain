"""Newline-delimited JSON backend — a simple, git-friendly, append-only log file."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from pathlib import Path

from ..records import AuditRecord
from .base import LogCorruptedError, StorageBackend


class JsonlBackend(StorageBackend):
    """Appends one JSON object per line.

    Each line contains the full payload plus ``hash`` (and ``key_id`` when sealed).
    Lines are never rewritten; verification (re)reads the file and rebuilds the chain.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    async def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _serialize(record: AuditRecord) -> str:
        payload = {
            "seq": record.seq,
            "ts": record.timestamp,
            "actor": record.actor,
            "action": record.action,
            "subject": record.subject,
            "meta": record.metadata,
            "prev_hash": record.prev_hash,
            "hash": record.hash,
        }
        if record.key_id:
            payload["key_id"] = record.key_id
        return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    async def append(self, record: AuditRecord) -> None:
        await asyncio.to_thread(self._append_line, self._serialize(record))

    def _append_line(self, line: str) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    async def append_many(self, records: Sequence[AuditRecord]) -> None:
        lines = [self._serialize(record) for record in records]

        def _append_lines() -> None:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write("\n".join(lines))
                if lines:
                    handle.write("\n")

        await asyncio.to_thread(_append_lines)

    async def load(self) -> list[AuditRecord]:
        def _read() -> list[str]:
            if not self.path.exists():
                return []
            with self.path.open("r", encoding="utf-8") as handle:
                return handle.read().splitlines()

        records: list[AuditRecord] = []
        for lineno, line in enumerate(await asyncio.to_thread(_read), start=1):
            if not line.strip():
                continue
            try:
                records.append(AuditRecord.from_stored(json.loads(line)))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise LogCorruptedError(f"{self.path}:{lineno}: {exc}") from exc
        return records

    async def close(self) -> None:
        return None
