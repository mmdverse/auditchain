"""auditchain — tamper-evident, hash-chained audit logging for Python.

A record's hash commits to the previous record's hash (SHA-256, or HMAC-SHA256 when
``seal_key`` is provided), so any later edit, insertion, removal or reordering of
records breaks the chain and is detected by :meth:`auditchain.AuditLog.verify`.

Async-first, zero runtime dependencies (a PostgreSQL backend is available through the
optional ``auditchain[postgres]`` extra).
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
from .hash import compute_record_hash, verify_record_hash
from .log import AuditLog
from .records import GENESIS_HASH, AuditRecord
from .sync import SyncAuditLog
from .verify import VerifyReport, verify_chain

__version__ = "0.2.0"

__all__ = [
    "AuditLog",
    "AuditRecord",
    "BackendError",
    "Checkpoint",
    "GENESIS_HASH",
    "JsonlBackend",
    "LogCorruptedError",
    "MemoryBackend",
    "PostgresBackend",
    "SqliteBackend",
    "StorageBackend",
    "SyncAuditLog",
    "VerifyReport",
    "compute_record_hash",
    "load_checkpoint",
    "make_checkpoint",
    "save_checkpoint",
    "verify_chain",
    "verify_record_hash",
    "__version__",
]
