"""Checkpoints: signed anchors of the chain at a point in time.

A checkpoint records the hash of the record at a given sequence number plus a
signature (HMAC-SHA256 with the seal key when the log is sealed). Stored outside the
log's trust boundary, it turns a tail truncation — which the chain alone cannot
detect — into a provable break, and lets you prove the log's state as of that point.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

from .records import AuditRecord


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """Anchors ``hash`` as the hash of the record at ``seq``."""

    seq: int
    hash: str
    key_id: str = ""
    timestamp: str = ""
    signature: str = ""


def _signature(seq: int, record_hash: str, key_id: str, seal_key: bytes) -> str:
    data = f"{seq}:{record_hash}:{key_id}".encode()
    return hmac.new(seal_key, data, hashlib.sha256).hexdigest()


def make_checkpoint(record: AuditRecord, seal_key: bytes | None = None) -> Checkpoint:
    """Build a checkpoint for the given (last) record."""
    signature = _signature(record.seq, record.hash, record.key_id, seal_key) if seal_key else ""
    return Checkpoint(
        seq=record.seq,
        hash=record.hash,
        key_id=record.key_id,
        timestamp=record.timestamp,
        signature=signature,
    )


def save_checkpoint(checkpoint: Checkpoint, path: str | Path) -> None:
    """Write a checkpoint as a JSON file."""
    payload = {
        "version": 1,
        "seq": checkpoint.seq,
        "hash": checkpoint.hash,
        "key_id": checkpoint.key_id,
        "ts": checkpoint.timestamp,
        "sig": checkpoint.signature,
    }
    Path(path).write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def load_checkpoint(path: str | Path, seal_key: bytes | None = None) -> Checkpoint:
    """Read a checkpoint file.

    A signed checkpoint (non-empty ``signature``) requires the matching seal key;
    without it the signature cannot be validated and the checkpoint is rejected.
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    checkpoint = Checkpoint(
        seq=int(payload["seq"]),
        hash=str(payload["hash"]),
        key_id=str(payload.get("key_id", "")),
        timestamp=str(payload.get("ts", "")),
        signature=str(payload.get("sig", "")),
    )
    if checkpoint.signature:
        if seal_key is None:
            raise ValueError("checkpoint is signed; pass the seal key to load it")
        expected = _signature(checkpoint.seq, checkpoint.hash, checkpoint.key_id, seal_key)
        if not hmac.compare_digest(checkpoint.signature, expected):
            raise ValueError("checkpoint signature mismatch: the checkpoint was modified")
    return checkpoint
