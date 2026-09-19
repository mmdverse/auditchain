"""Checkpoints: signed anchors of the chain at a point in time.

A checkpoint records the hash of the record at a given sequence number plus a
signature (HMAC-SHA256 with the seal key when the log is sealed). Stored outside the
log's trust boundary, it turns a tail truncation — which the chain alone cannot
detect — into a provable break, and lets you prove the log's state as of that point.

A checkpoint also carries the Merkle root of everything up to that record, and the
signature covers it. That is what makes single-record inclusion proofs meaningful: the
root is anchored by a signature the log's own writer cannot rewrite afterwards.
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
    """Anchors ``hash`` as the hash of the record at ``seq``.

    ``merkle_root``, when set, is the Merkle root over records 0..``seq`` (see
    :mod:`auditchain.merkle`); it is part of the signed message, so inclusion proofs
    can be checked against it later.
    """

    seq: int
    hash: str
    key_id: str = ""
    timestamp: str = ""
    signature: str = ""
    merkle_root: str = ""


def _signature(
    seq: int, record_hash: str, key_id: str, seal_key: bytes, merkle_root: str = ""
) -> str:
    """HMAC over the checkpoint fields.

    Checkpoints without a Merkle root keep the 0.2.0 message (``seq:hash:key_id``) so
    files written by older versions still verify; the root, when present, is appended
    to the message instead of replacing anything.
    """
    data = f"{seq}:{record_hash}:{key_id}"
    if merkle_root:
        data = f"{data}:{merkle_root}"
    return hmac.new(seal_key, data.encode(), hashlib.sha256).hexdigest()


def make_checkpoint(
    record: AuditRecord, seal_key: bytes | None = None, merkle_root: str = ""
) -> Checkpoint:
    """Build a checkpoint for the given (last) record."""
    signature = (
        _signature(record.seq, record.hash, record.key_id, seal_key, merkle_root)
        if seal_key
        else ""
    )
    return Checkpoint(
        seq=record.seq,
        hash=record.hash,
        key_id=record.key_id,
        timestamp=record.timestamp,
        signature=signature,
        merkle_root=merkle_root,
    )


def save_checkpoint(checkpoint: Checkpoint, path: str | Path) -> None:
    """Write a checkpoint as a JSON file."""
    payload = {
        "version": 2 if checkpoint.merkle_root else 1,
        "seq": checkpoint.seq,
        "hash": checkpoint.hash,
        "key_id": checkpoint.key_id,
        "ts": checkpoint.timestamp,
        "sig": checkpoint.signature,
    }
    if checkpoint.merkle_root:
        payload["merkle_root"] = checkpoint.merkle_root
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
        merkle_root=str(payload.get("merkle_root", "")),
    )
    if checkpoint.signature:
        if seal_key is None:
            raise ValueError("checkpoint is signed; pass the seal key to load it")
        expected = _signature(
            checkpoint.seq,
            checkpoint.hash,
            checkpoint.key_id,
            seal_key,
            checkpoint.merkle_root,
        )
        if not hmac.compare_digest(checkpoint.signature, expected):
            raise ValueError("checkpoint signature mismatch: the checkpoint was modified")
    return checkpoint
