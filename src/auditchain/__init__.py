"""auditchain — tamper-evident, hash-chained audit logging for Python.

A record's hash commits to the previous record's hash (SHA-256, or HMAC-SHA256 when
``seal_key`` is provided), so any later edit, insertion, removal or reordering of
records breaks the chain and is detected by :meth:`auditchain.AuditLog.verify`.

Async-first, zero runtime dependencies.
"""

from .backends import (
    BackendError,
    JsonlBackend,
    LogCorruptedError,
    MemoryBackend,
    SqliteBackend,
    StorageBackend,
)
from .hash import compute_record_hash, verify_record_hash
from .log import AuditLog
from .records import GENESIS_HASH, AuditRecord
from .sync import SyncAuditLog
from .verify import VerifyReport, verify_chain

__version__ = "0.1.0"

__all__ = [
    "AuditLog",
    "AuditRecord",
    "BackendError",
    "GENESIS_HASH",
    "JsonlBackend",
    "LogCorruptedError",
    "MemoryBackend",
    "SqliteBackend",
    "StorageBackend",
    "SyncAuditLog",
    "VerifyReport",
    "compute_record_hash",
    "verify_chain",
    "verify_record_hash",
    "__version__",
]
