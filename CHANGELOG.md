# Changelog

## 0.3.0 — 2026-09-19

Four additions, all of them about the same gap: an audit log is only evidence if someone
who is *not* the operator can check it, and if it keeps working under real deployment
pressure.

- **Multi-process append safety**: `AuditLog(..., lock_path="audit.lock")` (or
  `lock=FileLock(...)`) makes several processes share one log. While the lock is held the
  tail is re-read from the backend (`load_last()`, O(1) on sqlite/postgres, a backwards
  scan on jsonl) before the next record is built, so writers chain onto the real tail
  instead of their own stale one. The lock is advisory (`flock` on POSIX,
  `msvcrt.locking` on Windows), released by the OS if the process dies, supports
  `timeout=`, and `lock=` accepts any object with `acquire()`/`release()` so a lock that
  lives with the data (Postgres advisory lock, Redis) can be used across machines.
  Readers and `verify()` never lock. SQLite connections now set `busy_timeout` instead of
  failing immediately when another process holds the database.
- **`logging.Handler` bridge** (`AuditLogHandler`): attach it to an existing logger and
  its log calls become audit records. Records are prepared on the emitting thread and
  written by a daemon worker thread, so `emit()` never blocks and stays safe inside
  event loops, sync code and thread pools; `flush()`/`close()` bound the draining. The
  actor defaults to the logger name and can be overridden per handler (`actor=`,
  `metadata=`) or per record (`extra={"audit_actor", "audit_action", "audit_subject",
  "audit_metadata"}`); exceptions are captured as a traceback in the metadata, unrelated
  `extra` keys are ignored, and write failures are counted (`error_count`,
  `last_error`) instead of reaching the application. `background=False` writes through
  synchronously for scripts and tests.
- **`SyncAuditLog` catches up** with the async API: it now accepts `signing_key` /
  `signer_id` and exposes `public_key`, `merkle_root()`, `inclusion_proof()` and
  `verify(signers=...)`, so the sync facade can do everything the handler needs.
- **Merkle inclusion proofs**: `AuditLog.inclusion_proof(seq)` / `merkle_proof()` return
  a path of ~log2(n) hashes proving that one record is part of a log with a given root,
  without disclosing the rest of the records. `auditchain proof` writes the proof and
  `auditchain verify-proof --root|--checkpoint` checks it (exit code 1 on failure).
  Checkpoints now carry the Merkle root over everything behind them and **sign it**
  (checkpoint files go 1 → version 2; v1 files still load and verify unchanged), and
  `verify()` compares the log against that root, so a log that was rebuilt, extended or
  truncated after the anchor fails with `merkle root mismatch`. The tree follows RFC 6962
  (domain-separated leaves, promoted odd nodes), so proofs are bound to `(seq, size)` and
  cannot be replayed or padded.
- **Ed25519 record signatures** (`auditchain[ed25519]`, via `cryptography`):
  `AuditLog(..., signing_key=..., signer_id=...)` signs every record over
  `seq:hash:signer_id`, and `verify(signers={...})` checks them against public keys only.
  This closes the gap HMAC cannot: an attacker who holds the seal key can rewrite a
  record and recompute the chain, but cannot produce a valid signature. Verification with
  `signers` is strict — every record must be signed — so signatures cannot simply be
  stripped. `AuditRecord` gained `signer_id` and `signature` (both outside the hashed
  payload, so pre-existing logs and unsigned JSONL lines are unaffected); SQLite and
  Postgres add the columns in place on `init()`. New `auditchain keygen` command and
  `--signer NAME=PATH|HEX` on `auditchain verify`.

## 0.2.0 — 2026-08-30

- **Key rotation**: records carry a `key_id` (stored next to the hash, *not* part of
  the hashed payload). `AuditLog.rotate()` switches the HMAC key and appends a
  `key.rotate` marker sealed with the old key; `verify()` takes a `keyring` of
  retired keys. v0.1 logs (no key ids) stay fully verifiable.
- **Checkpoints**: `checkpoint()` / `save_checkpoint()` / `load_checkpoint()` create
  signed anchors ("at seq N the chain hash was H"). Verifying against an anchor
  detects tail truncation and rejects forged checkpoint files; `auditchain checkpoint`
  CLI command added.
- **PostgreSQL backend** (`auditchain[postgres]`, via asyncpg): same record shape,
  atomic batch writes, covered by a dedicated CI job against a real Postgres.
- **Batch appends**: `append_many()` — builds and seals the whole batch before a
  single backend write (atomic on SQLite/Postgres).
- **Backward compatibility**: SQLite databases from v0.1 are migrated in place on
  open (adds the `key_id` column); JSONL lines without `key_id` parse as v0.1
  records. Golden vector tests pin the serialization/hashing format.
- `verify` CLI gained `--checkpoint`; `checkpoint` CLI subcommand added.

## 0.1.0 — 2026-08-30

Initial public release.

- Async-first audit log where every record commits to the hash of the previous one
  (SHA-256 for integrity, HMAC-SHA256 when a `seal_key` is provided).
- Backends: `MemoryBackend`, `JsonlBackend`, `SqliteBackend` — zero runtime dependencies.
- `AuditLog` (async) and `SyncAuditLog` (synchronous wrappers).
- `verify()` / `verify_chain()` with the exact location of the first broken link.
- `auditchain verify` CLI with CI-friendly exit codes (0 ok / 1 broken / 2 usage).
- Fully typed (`py.typed`), Python 3.10+.
