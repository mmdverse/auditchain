# Changelog

## Unreleased

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
