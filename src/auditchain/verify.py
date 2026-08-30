"""Chain verification."""

from __future__ import annotations

from dataclasses import dataclass

from .hash import compute_record_hash
from .records import GENESIS_HASH, AuditRecord


@dataclass(frozen=True, slots=True)
class VerifyReport:
    """Result of a full-chain verification."""

    ok: bool
    records_checked: int
    first_error_seq: int | None
    reason: str | None = None

    def __str__(self) -> str:
        if self.ok:
            return f"OK: {self.records_checked} record(s) verified"
        where = f" at seq {self.first_error_seq}" if self.first_error_seq is not None else ""
        return f"FAILED{where}: {self.reason}"


def verify_chain(
    records: list[AuditRecord],
    seal_key: bytes | None = None,
    *,
    expected_count: int | None = None,
) -> VerifyReport:
    """Recompute and check every link of the chain in O(n).

    Detects, in order of appearance: missing/extra records (vs ``expected_count``),
    sequence gaps, reordered or removed middle records (via ``prev_hash``), and
    modified records (via the record hash).

    A pure tail truncation (deleting the last records) cannot be detected from the
    chain itself; pass ``expected_count`` to catch it.
    """
    if expected_count is not None and len(records) != expected_count:
        return VerifyReport(
            ok=False,
            records_checked=len(records),
            first_error_seq=None,
            reason=f"count mismatch: {len(records)} record(s), expected {expected_count}",
        )

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
        if record.hash != compute_record_hash(record, seal_key):
            return VerifyReport(
                ok=False,
                records_checked=index,
                first_error_seq=record.seq,
                reason="hash mismatch: the record was modified",
            )
        prev_hash = record.hash

    return VerifyReport(ok=True, records_checked=len(records), first_error_seq=None)
