# Changelog

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
