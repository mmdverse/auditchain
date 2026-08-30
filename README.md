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
- Backends: `SqliteBackend`, `JsonlBackend`, `MemoryBackend` (more planned)
- HMAC-SHA256 sealing, or plain SHA-256 integrity without a key
- `verify()` API and a `verify` CLI (exit code 1 on failure — CI friendly)
- Zero runtime dependencies, Python 3.10+, fully typed (`py.typed`)

## Install

```bash
pip install auditchain
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

| Backend        | Used for                          |
| -------------- | --------------------------------- |
| `SqliteBackend`| Real applications (durable, queryable) |
| `JsonlBackend` | Simple logs, git-friendly, streaming-friendly |
| `MemoryBackend`| Short-lived processes, tests      |

## Verify from the CLI

```bash
# format is auto-detected from the extension
python -m auditchain verify audit.sqlite
auditchain verify audit.jsonl --seal-key-file seal.key --expected-count 1000
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
  records, sequence gaps, count mismatches (with `--expected-count`).
- **Not detectable from the chain alone:** removal of the *last* records (tail
  truncation). Pass `expected_count` to `verify()` if that matters to you.
- **Single writer:** one process appends at a time. Concurrent appends are not
  supported in 0.1.
- Without a `seal_key`, records are integrity-protected, not authenticated.

## Roadmap

- 0.2: Postgres backend, key rotation, periodic checkpoints for huge logs

## Why hash chains?

Read the full argument — threat model, honest limits, and when to anchor digests —
in [Why your audit log needs a hash chain](docs/tamper-evident-audit-logs.md).

## خلاصهٔ فارسی

**auditchain** یک کتابخانهٔ پایتونی برای لاگ حسابرسیِ ضدتغییر است. هر رکورد با هشِ
رکورد قبلی زنجیر می‌شود (و در صورت دادن `seal_key` با HMAC-SHA256 امضا می‌گردد)،
بنابراین هر تغییر بعدی — ویرایش، جابه‌جایی، حذف یا درج — زنجیره را می‌شکند و
`verify` دقیقاً نشان می‌دهد کجا. بدون وابستگی، async-first، با بک‌اندهای
SQLite/JSONL و یک CLI که خروجی آن برای CI مناسب است (کد خروج ۱ یعنی زنجیره شکسته).

## License

MIT — see [LICENSE](LICENSE).

---

Made ❤️ by Mohammad — [@llllxyz](https://t.me/llllxyz)
