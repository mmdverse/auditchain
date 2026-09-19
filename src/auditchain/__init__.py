"""auditchain — tamper-evident, hash-chained audit logging for Python.

A record's hash commits to the previous record's hash (SHA-256, or HMAC-SHA256 when
``seal_key`` is provided), so any later edit, insertion, removal or reordering of
records breaks the chain and is detected by :meth:`auditchain.AuditLog.verify`.

Records can also be signed with Ed25519 (``auditchain[ed25519]``), which lets an
auditor verify a log holding only a public key — they cannot forge records, unlike
with HMAC where the verification secret is also the forging secret.

Checkpoints carry a Merkle root over every record behind them, so one record can be
proven to be part of a log without disclosing the rest: hand the auditor a signed
checkpoint once, then ~log2(n) hashes per record.

Async-first, zero runtime dependencies (PostgreSQL and Ed25519 are optional extras).
An ``AuditLogHandler`` feeds Python's :mod:`logging` into the chain, so existing log
calls become auditable without touching the call sites.
"""

from .backends import (
    BackendError,
    JsonlBackend,
    LogCorruptedError,
    MemoryBackend,
    PostgresBackend,
    SqliteBackend,
    StorageBackend,
)
from .checkpoint import Checkpoint, load_checkpoint, make_checkpoint, save_checkpoint
from .handlers import AuditLogHandler
from .hash import compute_record_hash, verify_record_hash
from .locks import BaseLock, FileLock, LockError, LockTimeout, NoLock
from .log import AuditLog
from .merkle import InclusionProof, ProofStep, merkle_proof, merkle_root
from .records import GENESIS_HASH, AuditRecord
from .signing import (
    SignatureError,
    SignatureUnavailableError,
    generate_keypair,
    sign_record,
    verify_record_signature,
)
from .sync import SyncAuditLog
from .verify import VerifyReport, verify_chain

__version__ = "0.3.0"

__all__ = [
    "AuditLog",
    "AuditLogHandler",
    "AuditRecord",
    "BaseLock",
    "BackendError",
    "Checkpoint",
    "FileLock",
    "GENESIS_HASH",
    "InclusionProof",
    "JsonlBackend",
    "LockError",
    "LockTimeout",
    "LogCorruptedError",
    "MemoryBackend",
    "NoLock",
    "PostgresBackend",
    "ProofStep",
    "SqliteBackend",
    "StorageBackend",
    "SignatureError",
    "SignatureUnavailableError",
    "SyncAuditLog",
    "VerifyReport",
    "compute_record_hash",
    "generate_keypair",
    "load_checkpoint",
    "make_checkpoint",
    "merkle_proof",
    "merkle_root",
    "save_checkpoint",
    "sign_record",
    "verify_record_signature",
    "verify_chain",
    "verify_record_hash",
    "__version__",
]
