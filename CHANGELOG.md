# Changelog

## 0.1.0 — 2026-08-30

Initial public release.

- Async-first audit log where every record commits to the hash of the previous one
  (SHA-256 for integrity, HMAC-SHA256 when a `seal_key` is provided).
- Backends: `MemoryBackend`, `JsonlBackend`, `SqliteBackend` — zero runtime dependencies.
- `AuditLog` (async) and `SyncAuditLog` (synchronous wrappers).
- `verify()` / `verify_chain()` with the exact location of the first broken link.
- `auditchain verify` CLI with CI-friendly exit codes (0 ok / 1 broken / 2 usage).
- Fully typed (`py.typed`), Python 3.10+.
