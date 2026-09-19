"""Checkpoints: signed anchors of the chain at a point in time.

A checkpoint records the hash of the record at a given sequence number plus a
signature (HMAC-SHA256 with the seal key when the log is sealed). Stored outside the
log's trust boundary, it turns a tail truncation — which the chain alone cannot
detect — into a provable break, and lets you prove the log's state as of that point.

A checkpoint also carries the Merkle root of everything up to that record, and the
signature covers it. That is what makes single-record inclusion proofs meaningful: the
root is anchored by a signature the log's own writer cannot rewrite afterwards.

Two kinds of signature are supported:

- **HMAC** (``seal_key``) — proves to the log's owner that the anchor was not swapped
  later; checking it needs the same secret that can forge it.
- **Ed25519** (``signing_key``) — lets someone who only has the *public* key verify the
  anchor, which is the difference between "the operator says this was the state" and
  "anyone can check that this was the state". A signed checkpoint refuses to load
  without a key that can verify it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    #: HMAC over the fields below, when the log was opened with a ``seal_key``.
    signature: str = ""
    merkle_root: str = ""
    #: Ed25519 signer and signature, when the log was opened with a ``signing_key``.
    signer_id: str = ""
    signature_ed25519: str = ""

    @property
    def signed(self) -> bool:
        """True when the checkpoint carries an Ed25519 signature."""
        return bool(self.signature_ed25519)


def checkpoint_message(seq: int, record_hash: str, key_id: str, merkle_root: str = "") -> bytes:
    """The exact bytes a checkpoint signature covers.

    ``seq:hash:key_id`` is the 0.2.0 message; the Merkle root is appended when present,
    so an HMAC written before Merkle roots existed still verifies and both signature
    kinds cover the same thing.
    """
    data = f"{seq}:{record_hash}:{key_id}"
    if merkle_root:
        data = f"{data}:{merkle_root}"
    return data.encode()


def verify_checkpoint_signature(checkpoint: Checkpoint, public_key: Any) -> bool:
    """Check a checkpoint's Ed25519 signature against a public key.

    Never raises on a bad signature (an unusable *key* still raises).
    """
    if not checkpoint.signature_ed25519:
        return False
    from .signing import verify_signature  # local import keeps the optional dep optional

    message = checkpoint_message(
        checkpoint.seq, checkpoint.hash, checkpoint.key_id, checkpoint.merkle_root
    )
    return verify_signature(checkpoint.signature_ed25519, message, public_key)


def _signature(
    seq: int, record_hash: str, key_id: str, seal_key: bytes, merkle_root: str = ""
) -> str:
    """HMAC-SHA256 over :func:`checkpoint_message` with the seal key."""
    message = checkpoint_message(seq, record_hash, key_id, merkle_root)
    return hmac.new(seal_key, message, hashlib.sha256).hexdigest()


def make_checkpoint(
    record: AuditRecord,
    seal_key: bytes | None = None,
    merkle_root: str = "",
    *,
    signing_key: Any | None = None,
    signer_id: str = "s0",
) -> Checkpoint:
    """Build a checkpoint for the given (last) record.

    ``signing_key`` adds an Ed25519 signature: anyone holding the public key can verify
    the anchor, without holding the secret that produced it.
    """
    signature = (
        _signature(record.seq, record.hash, record.key_id, seal_key, merkle_root)
        if seal_key
        else ""
    )
    ed25519 = ""
    if signing_key is not None:
        from .signing import sign_message

        ed25519 = sign_message(
            checkpoint_message(record.seq, record.hash, record.key_id, merkle_root),
            signing_key,
        )
    return Checkpoint(
        seq=record.seq,
        hash=record.hash,
        key_id=record.key_id,
        timestamp=record.timestamp,
        signature=signature,
        merkle_root=merkle_root,
        signer_id=signer_id if ed25519 else "",
        signature_ed25519=ed25519,
    )


def save_checkpoint(checkpoint: Checkpoint, path: str | Path) -> None:
    """Write a checkpoint as a JSON file."""
    payload = {
        # 1: 0.2.0 anchors; 2: with a Merkle root; 3: with an Ed25519 signature
        "version": 3 if checkpoint.signature_ed25519 else (2 if checkpoint.merkle_root else 1),
        "seq": checkpoint.seq,
        "hash": checkpoint.hash,
        "key_id": checkpoint.key_id,
        "ts": checkpoint.timestamp,
        "sig": checkpoint.signature,
    }
    if checkpoint.merkle_root:
        payload["merkle_root"] = checkpoint.merkle_root
    if checkpoint.signature_ed25519:
        payload["signer_id"] = checkpoint.signer_id
        payload["signature_ed25519"] = checkpoint.signature_ed25519
    Path(path).write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def load_checkpoint(
    path: str | Path, seal_key: bytes | None = None, public_key: Any | None = None
) -> Checkpoint:
    """Read a checkpoint file.

    A **signed** checkpoint has to be verified before it can be used: with
    ``public_key`` for an Ed25519 signature, or with the matching ``seal_key`` for an
    HMAC. Loading a signed anchor without verifying it would defeat the point, so it is
    refused rather than silently trusted.

    A checkpoint may carry both signatures; when the Ed25519 one verifies, the HMAC is
    not asked for, because it covers the same message and is the weaker of the two.
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    checkpoint = Checkpoint(
        seq=int(payload["seq"]),
        hash=str(payload["hash"]),
        key_id=str(payload.get("key_id", "")),
        timestamp=str(payload.get("ts", "")),
        signature=str(payload.get("sig", "")),
        merkle_root=str(payload.get("merkle_root", "")),
        signer_id=str(payload.get("signer_id", "")),
        signature_ed25519=str(payload.get("signature_ed25519", "")),
    )
    signed_asymmetrically = False
    if checkpoint.signature_ed25519:
        if public_key is None:
            raise ValueError("checkpoint is signed with Ed25519; pass the public key to verify it")
        if not verify_checkpoint_signature(checkpoint, public_key):
            raise ValueError("checkpoint signature mismatch: the checkpoint was modified")
        signed_asymmetrically = True
    # A verified Ed25519 signature covers exactly the same message as the HMAC, so asking
    # an auditor for the seal key on top of it would be pointless: the stronger check
    # already passed.
    if checkpoint.signature and not signed_asymmetrically:
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
