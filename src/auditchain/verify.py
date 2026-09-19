"""Chain verification."""

from __future__ import annotations

from dataclasses import dataclass

from .checkpoint import Checkpoint
from .hash import compute_record_hash
from .merkle import merkle_root
from .records import GENESIS_HASH, AuditRecord
from .signing import verify_record_signature


@dataclass(frozen=True, slots=True)
class VerifyReport:
    """Result of a full-chain verification."""

    ok: bool
    records_checked: int
    first_error_seq: int | None
    reason: str | None = None
    #: How many records were checked against an Ed25519 public key.
    signed_records: int = 0
    #: Merkle root over the records that were checked (see :mod:`auditchain.merkle`).
    merkle_root: str = ""

    def __str__(self) -> str:
        if self.ok:
            return f"OK: {self.records_checked} record(s) verified"
        where = f" at seq {self.first_error_seq}" if self.first_error_seq is not None else ""
        return f"FAILED{where}: {self.reason}"


def _key_for(record: AuditRecord, seal_key: bytes | None, keyring: dict[str, bytes] | None):
    """The key that sealed ``record``, or None for integrity-only records."""
    if not record.key_id:
        return seal_key
    if keyring is None:
        return None
    return keyring.get(record.key_id)


def verify_chain(
    records: list[AuditRecord],
    seal_key: bytes | None = None,
    *,
    expected_count: int | None = None,
    keyring: dict[str, bytes] | None = None,
    checkpoint: Checkpoint | None = None,
    signers: dict[str, object] | None = None,
) -> VerifyReport:
    """Recompute and check every link of the chain in O(n).

    Detects, in order of appearance: missing/extra records (vs ``expected_count``),
    sequence gaps, reordered or removed middle records (via ``prev_hash``), modified
    records (via the record hash) and unknown key ids (after key rotation).

    A pure tail truncation (deleting the last records) cannot be detected from the
    chain itself — pass ``expected_count`` or a ``checkpoint`` anchor to catch it.

    ``keyring`` maps key ids to seal keys (needed after :meth:`AuditLog.rotate`);
    records carry their own ``key_id`` next to the hash (outside the hashed payload),
    so v0.1 logs without key ids stay verifiable with the plain ``seal_key``.

    ``signers`` maps signer ids to Ed25519 public keys. When it is given, *every*
    record must carry a signature from a known signer: an attacker who holds the seal
    key could otherwise strip the signatures and still pass the hash checks.
    """
    if checkpoint is not None:
        if len(records) <= checkpoint.seq:
            return VerifyReport(
                ok=False,
                records_checked=len(records),
                first_error_seq=None,
                reason="chain ends before the checkpoint: tail truncation",
            )
        if records[checkpoint.seq].hash != checkpoint.hash:
            return VerifyReport(
                ok=False,
                records_checked=checkpoint.seq,
                first_error_seq=records[checkpoint.seq].seq,
                reason="checkpoint anchor mismatch: the log changed since the checkpoint",
            )

    if expected_count is not None and len(records) != expected_count:
        return VerifyReport(
            ok=False,
            records_checked=len(records),
            first_error_seq=None,
            reason=f"count mismatch: {len(records)} record(s), expected {expected_count}",
        )

    signed = 0
    prev_hash = GENESIS_HASH
    for index, record in enumerate(records):
        if record.seq != index:
            return VerifyReport(
                ok=False,
                records_checked=index,
                first_error_seq=record.seq,
                reason=f"sequence gap: expected seq {index}, found {record.seq}",
            )
        if record.prev_hash != prev_hash:
            return VerifyReport(
                ok=False,
                records_checked=index,
                first_error_seq=record.seq,
                reason="prev_hash mismatch: a record was removed or reordered",
            )
        key = _key_for(record, seal_key, keyring)
        if record.key_id and key is None:
            return VerifyReport(
                ok=False,
                records_checked=index,
                first_error_seq=record.seq,
                reason=f"unknown key_id {record.key_id!r}: pass the matching keyring",
            )
        if record.hash != compute_record_hash(record, key):
            return VerifyReport(
                ok=False,
                records_checked=index,
                first_error_seq=record.seq,
                reason="hash mismatch: the record was modified",
            )

        if signers is not None:
            # Checked after the hash: the signature covers the hash, so a broken hash
            # is already reported above and never reported as a signature problem.
            if not record.signature:
                return VerifyReport(
                    ok=False,
                    records_checked=index,
                    first_error_seq=record.seq,
                    reason="missing signature: the record is not signed",
                )
            public_key = signers.get(record.signer_id)
            if public_key is None:
                return VerifyReport(
                    ok=False,
                    records_checked=index,
                    first_error_seq=record.seq,
                    reason=f"unknown signer_id {record.signer_id!r}: pass the matching public key",
                )
            if not verify_record_signature(record, public_key):
                return VerifyReport(
                    ok=False,
                    records_checked=index,
                    first_error_seq=record.seq,
                    reason="signature mismatch: the record was rewritten without the signing key",
                )
            signed += 1

        prev_hash = record.hash

    root = merkle_root([r.hash for r in records])
    # The root was signed when the checkpoint was written, so a log that no longer
    # hashes to it was rewritten (or truncated/extended) after that point.
    if checkpoint is not None and checkpoint.merkle_root and checkpoint.merkle_root != root:
        return VerifyReport(
            ok=False,
            records_checked=len(records),
            first_error_seq=None,
            reason="merkle root mismatch: the records do not match the checkpoint",
            signed_records=signed,
            merkle_root=root,
        )

    return VerifyReport(
        ok=True,
        records_checked=len(records),
        first_error_seq=None,
        signed_records=signed,
        merkle_root=root,
    )
