# auditchain

[![CI](https://github.com/mmdverse/auditchain/actions/workflows/ci.yml/badge.svg)](https://github.com/mmdverse/auditchain/actions/workflows/ci.yml)

Tamper-evident, hash-chained audit logging for Python.
Async-first, zero runtime dependencies.

Every record commits to the hash of the previous one. Anyone who edits, inserts,
removes or reorders records later breaks the chain — and `verify` tells you exactly
where. Built for compliance (SOC 2, ISO 27001, PCI) and for any system where "who
did what" must be provable after the fact.

## How it works

```
record[0].hash = SHA-256(prev_hash(genesis) || payload[0])
record[1].hash = SHA-256(record[0].hash   || payload[1])
...
```

With a `seal_key`, records are signed with **HMAC-SHA256** instead, so a party that
does not hold the key cannot silently rewrite the log at all. Verification recomputes
the whole chain in O(n) and reports the first broken link.

## Features

- Async-first API (`AuditLog`) plus thin sync wrappers (`SyncAuditLog`)
- Backends: `SqliteBackend`, `JsonlBackend`, `MemoryBackend`, `PostgresBackend`
- HMAC-SHA256 sealing with **key rotation** (per-record `key_id`), or plain SHA-256
  integrity without a key
- **Checkpoints**: signed anchors that detect tail truncation and prove a chain's
  state at a point in time
- Batch appends (`append_many`) — one write for many records
- `verify()` API and a `verify`/`checkpoint` CLI (exit code 1 on failure — CI friendly)
- Zero runtime dependencies (the `postgres` extra adds `asyncpg`), Python 3.10+,
  fully typed (`py.typed`)

## Install

```bash
pip install auditchain                # sqlite / jsonl / memory backends
pip install "auditchain[postgres]"    # + PostgreSQL backend (asyncpg)
```

## Quickstart (async)

```python
import asyncio
from auditchain import AuditLog, SqliteBackend

async def main():
    async with AuditLog(SqliteBackend("audit.sqlite")) as log:
        await log.append("sara", "login", "admin", metadata={"ip": "10.0.0.1"})
        await log.append("jawad", "payment.approve", "invoice:12", metadata={"amount": 1200})

        report = await log.verify()
        print(report)  # OK: 2 record(s) verified

asyncio.run(main())
```

## Sealing records (HMAC)

```python
from auditchain import AuditLog, SqliteBackend

key = secrets.token_bytes(32)
log = AuditLog(SqliteBackend("audit.sqlite"), seal_key=key)
```

Without a `seal_key`, tampering is still detected — but only by integrity; anyone who
can write the log can rewrite it and re-seal it. Use a key when attackers might have
write access. Keep the key outside the log (env var, secret manager, file).

## Key rotation

Rotate the seal key and the chain records the rotation itself (the marker is sealed
with the old key, so it documents the decision under the key that was in effect):

```python
log = AuditLog(SqliteBackend("audit.sqlite"), seal_key=key0, key_id="k0")
await log.append("sara", "login")

await log.rotate(new_key, "k1")       # appends a "key.rotate" marker, switches key
await log.append("jawad", "logout")

report = await log.verify()           # uses the keyring (retired keys) automatically
```

Pass retired keys explicitly (or to `verify`) when reopening outside the same object:

```python
log = AuditLog(SqliteBackend("audit.sqlite"), seal_key=new_key, key_id="k1",
               keyring={"k0": key0})
```

`key_id` is stored next to each record but is **not** part of the hashed payload, so
logs written by v0.1 (which has no key ids) still verify — and records from 0.1 that
were sealed keep working with the same key.

## Checkpoints (anchors)

The chain alone cannot detect someone deleting the *last* records — the remaining
chain still links cleanly. A checkpoint is a signed anchor ("at seq N, the chain hash
was H") that you store **outside the log's trust boundary** and verify against later:

```python
cp = await log.checkpoint()                 # anchor the current tail
save_checkpoint(cp, "anchors/audit.checkpoint")   # e.g. other machine, object storage

# later, on a possibly-tampered copy:
log = AuditLog(SqliteBackend("audit.sqlite"), seal_key=key)
report = await log.verify(checkpoint=load_checkpoint("anchors/audit.checkpoint", key))
# FAILED: chain ends before the checkpoint: tail truncation
```

Checkpoints with a seal key are signed (HMAC-SHA256), so a forged or edited
checkpoint file is rejected. Without a key, the checkpoint is unsigned and only as
trustworthy as the place you store it.

## Sync API

```python
from auditchain import JsonlBackend, SyncAuditLog

log = SyncAuditLog(JsonlBackend("audit.jsonl"))
log.append("sara", "login")
assert log.verify().ok
log.close()
```

`SyncAuditLog` runs its own event loop per call; use the async API from inside an
already-running loop.

## Backends

| Backend         | Used for                                  |
| --------------- | ----------------------------------------- |
| `SqliteBackend` | Real applications (durable, queryable)    |
| `PostgresBackend` | Multi-service setups, shared/remote storage |
| `JsonlBackend`  | Simple logs, git-friendly, streaming-friendly |
| `MemoryBackend` | Short-lived processes, tests              |

`PostgresBackend` takes a DSN (asyncpg) and stores the same record shape; v0.1
SQLite databases are migrated in place on first open (the `key_id` column is added).

## Verify from the CLI

```bash
# format is auto-detected from the extension
python -m auditchain verify audit.sqlite
auditchain verify audit.jsonl --seal-key-file seal.key --expected-count 1000
auditchain verify audit.sqlite --checkpoint anchors/audit.checkpoint

# write an anchor after each batch (e.g. in CI/cron)
auditchain checkpoint audit.sqlite --output anchors/audit.checkpoint --seal-key-file seal.key
```

Example output when the log was tampered with:

```
$ python -m auditchain verify audit.jsonl
FAILED at seq 1: hash mismatch: the record was modified
```

Exit code `0` on success, `1` when the chain is broken, `2` on usage/file errors —
so it drops straight into CI.

## Security model — be honest about limits

- **Detected:** modification of any record, insertion, reordering, removal of middle
  records, sequence gaps, unknown key ids, count mismatches (with `--expected-count`),
  and tail truncation (with a `--checkpoint` anchor or `expected_count`).
- **Not detectable from the chain alone, without an anchor:** removal of the *last*
  records. Keep a `checkpoint` outside the log's trust boundary, or pass
  `expected_count` to `verify()`.
- **Single writer:** one process appends at a time. Use a queue/lock for writers;
  the chain must be serialized.
- Without a `seal_key`, records are integrity-protected, not authenticated — an
  attacker who can rewrite the log can re-seal it.
- **Key rotation only helps if you control the keyring.** Store retired keys safely;
  losing a key means the records sealed with it fail verification.

## Beyond the basics

Read the full argument — threat model, honest limits, and when to anchor digests —
in [Why your audit log needs a hash chain](docs/tamper-evident-audit-logs.md)
or on [DEV Community](https://dev.to/mmdverse/why-your-audit-log-needs-a-hash-chain-3loo).

## خلاصهٔ فارسی

**auditchain** یک کتابخانهٔ پایتونی برای لاگ حسابرسیِ ضدتغییر است. هر رکورد با هشِ
رکورد قبلی زنجیر می‌شود (و در صورت دادن `seal_key` با HMAC-SHA256 امضا می‌گردد)،
بنابراین هر تغییر بعدی — ویرایش، جابه‌جایی، حذف یا درج — زنجیره را می‌شکند و
`verify` دقیقاً نشان می‌دهد کجا. بدون وابستگی، async-first؛ بک‌اندهای
SQLite/JSONL/Postgres؛ چرخش کلید HMAC با keyring؛ لنگر امضاشده (checkpoint) برای
تشخیص بریده‌شدن انتهای زنجیره؛ و CLI با کد خروج مناسب CI (کد ۱ یعنی زنجیره شکسته).

## License

MIT — see [LICENSE](LICENSE).

---

Made ❤️ by Mohammad — [@llllxyz](https://t.me/llllxyz)
