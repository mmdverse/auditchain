# auditchain

[![CI](https://github.com/mmdverse/auditchain/actions/workflows/ci.yml/badge.svg)](https://github.com/mmdverse/auditchain/actions/workflows/ci.yml)

Tamper-evident, hash-chained audit logging for Python.
Async-first, zero runtime dependencies, `mypy --strict` clean, 91% branch coverage
(203 tests).

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
- **Ed25519 signatures** (`auditchain[ed25519]`): an auditor verifies with a public key
  only, so they can check the log without being able to forge it
- **Merkle inclusion proofs**: prove that one record belongs to the log using ~log₂n
  hashes and a root you already trust — without revealing the other records
- **`logging.Handler`**: drop it on an existing logger and the calls you already write
  become auditable records — written off the application's thread
- **Multi-process writers**: an advisory file lock (`lock_path=`) plus a tail re-read
  keeps workers, web processes and cron jobs on one valid chain
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
pip install "auditchain[ed25519]"     # + Ed25519 record signatures (cryptography)
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

## Signing records (Ed25519)

HMAC answers "was this written by someone holding the seal key?" — and anyone who can
verify also holds the forging secret. Ed25519 splits those apart.

```python
from auditchain import AuditLog, SqliteBackend, generate_keypair

seed, public_key = generate_keypair()          # or: auditchain keygen
log = AuditLog(SqliteBackend("audit.sqlite"), signing_key=seed)
await log.append("alice", "invoice.approve", "inv-1")
```

Keep the private key; hand the public key to whoever verifies:

```bash
auditchain keygen --private-out signing.key --public-out signing.pub
auditchain verify audit.sqlite --signer s0=signing.pub
```

In code, pass `signers` to `verify`:

```python
report = await log.verify(signers={"s0": public_key})
report.signed_records   # how many records were checked against a public key
```

### What it adds over HMAC

Someone who holds the seal key can rewrite a record, recompute every hash after it, and
leave the chain perfectly consistent — HMAC cannot tell you. A signature can:

```
verifying a log an insider rewrote after recomputing the hashes
  with the HMAC key      → OK: 2 record(s) verified              (undetected)
  with the public key    → FAILED at seq 0: signature mismatch: the record was
                           rewritten without the signing key
```

Design notes:

- The signature covers `seq:hash:signer_id`. The hash already commits to the previous
  hash and the payload, so a signature cannot move to another record or another chain
  position.
- Signature fields are stored next to the record but are **not part of the hashed
  payload**, exactly like `key_id`. Logs written before signing existed keep verifying,
  and unsigned JSONL lines are byte-for-byte unchanged.
- Passing `signers` makes verification **strict**: every record must carry a valid
  signature. Without that rule an attacker holding the seal key could simply delete the
  signatures and still pass the hash checks.
- Signatures are independent of sealing, so you can use either or both.

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

A checkpoint also carries the **Merkle root** of every record behind it, and the
signature covers that root — which is what makes single-record proofs possible:

```bash
auditchain checkpoint audit.sqlite --seal-key-file seal.key   # anchors seq + merkle root
auditchain proof audit.sqlite --seq 42 --output 42.proof      # ~log2(n) hashes
auditchain verify-proof 42.proof --checkpoint audit.sqlite.checkpoint --seal-key-file seal.key
```

```python
proof = await log.inclusion_proof(42)
proof.verify(trusted_root)      # True
```

`verify-proof` exits 1 on failure, so a third party can gate on it in CI. Publish the
checkpoint somewhere you cannot rewrite it, hand out proofs, and an auditor confirms any
single record without seeing the rest of the log — and without holding your seal key.

The tree is the RFC 6962 construction: leaves are `SHA256(0x00 || record_hash)`,
interior nodes are `SHA256(0x01 || left || right)`, and a node with an odd number of
children is promoted instead of duplicated. The prefix stops a leaf hash from passing as
an interior node, and promoting removes the classic "duplicate the last hash" ambiguity,
so a proof cannot be replayed at a different size. Proofs commit to `(seq, size)`.

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

## Audit the logs you already write

Application logs are verbose and disposable; audit logs are ordered and kept. One
handler serves both, so the call site does not change:

```python
import logging
from auditchain import AuditLog, AuditLogHandler, SqliteBackend

log = AuditLog(SqliteBackend("audit.sqlite"), seal_key=secrets.token_bytes(32))
logging.getLogger("billing").addHandler(AuditLogHandler(log))

logger.info("invoice.approve %s", invoice_id)     # ← now also an audit record
```

```json
{"actor": "billing", "action": "invoice.approve inv-7", "subject": "",
 "metadata": {"logger": "billing", "level": "INFO", "module": "app", "line": 42,
              "func": "approve", "amount": 1200}}
```

Details worth knowing:

- **Nothing blocks the caller.** Records are prepared on the emitting thread (the
  `LogRecord` is not valid afterwards) and written by a daemon worker thread, so it is
  safe from async code, sync code and thread pools alike. `handler.flush()` waits until
  everything queued is on disk; `handler.close()` drains, stops the worker and (with
  `close_log=True`) closes the log.
- **One writer, in order.** The chain stays serialized no matter how many threads log.
- **Attribution is explicit.** The actor defaults to the logger name; override it per
  record with `extra={"audit_actor": ..., "audit_action": ..., "audit_subject": ...,
  "audit_metadata": {...}}`, or per handler with `actor=` (string or callable) and
  `metadata=`.
- **Unrelated `extra` keys are not copied**, so request ids and process ids do not leak
  into the audit metadata. Exceptions are captured as a formatted traceback in
  `metadata["exception"]` (turn off with `include_exception=False`).
- **A broken log never breaks the application:** failures go to `handleError` and are
  counted in `handler.error_count` / `handler.last_error`.
- Set `background=False` to write through synchronously (useful in scripts and tests);
  it refuses to run inside an event loop, where you want the default instead.

## Many processes, one log

Workers, web processes and cron jobs can append to the same log. Pass a lock and every
writer re-reads the tail of the log before building its next record, so it chains onto
what is really stored instead of what it last saw:

```python
log = AuditLog(SqliteBackend("audit.sqlite"), lock_path="audit.lock")
```

```python
lock = FileLock("/var/lib/myapp/audit.lock")          # or share one object
log = AuditLog(SqliteBackend("audit.sqlite"), lock=lock)
```

What that buys, and what it does not:

- The lock is an advisory `flock` (POSIX) or `msvcrt.locking` (Windows) on a lock file
  next to the log. **A crashed process cannot leave the log locked** — the OS drops the
  lock with the process. `timeout=` turns a long wait into `LockTimeout`.
- It serializes the writers that use it, **on one machine**. It is not a distributed
  lock and it does not stop a rogue process from writing to the storage directly.
- Several machines need a lock that lives with the data: pass your own `lock=` object
  (Postgres advisory lock, Redis, etc.). Anything with `acquire()`/`release()` works,
  and the tail re-read happens while it is held.
- Readers and `verify()` never take the lock.
- Without the lock, two long-lived writers that both saw an empty log write sequence 0
  twice: SQLite refuses the second insert with an `IntegrityError`, while a JSONL file
  ends up with a broken chain that only verification notices.

Honest data point: four processes appending 15 records each to one SQLite log →
seq 0..59, contiguous `prev_hash` links, valid chain, every record sealed. That is
`tests/test_locks.py`, not a claim.

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
- A checkpoint's Merkle root pins the *content* of everything behind it, not just the
  tail hash: a log that was rewritten, extended or truncated afterwards fails with
  `merkle root mismatch`, even if every hash in it was recomputed with the real key.
- **Inclusion proofs prove membership, not freshness.** A proof only says "this record
  is in the log with this root". An old root stays valid forever — the anchor's
  timestamp and what you do with it are yours to manage.
- **Single writer at a time:** the chain must be serialized. `logging.Handler` with
  `background=True` funnels a process's threads through one worker; for several
  processes pass `lock_path=`/`lock=` (advisory, one machine) or a lock that lives with
  the data (Postgres advisory lock, Redis) across machines.
- Without a `seal_key`, records are integrity-protected, not authenticated — an
  attacker who can rewrite the log can re-seal it.
- HMAC also fails against an attacker who holds the seal key: they can rewrite records
  and recompute the chain. Only Ed25519 signatures (`signing_key`) survive that, because
  verification needs just the public key.
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
تشخیص بریده‌شدن انتهای زنجیره؛ امضای Ed25519 روی رکوردها (اختیاری، `auditchain[ed25519]`)
تا حسابرس فقط با کلید عمومی بتواند لاگ را تایید کند و خودش قادر به جعل نباشد؛ و اثبات
مرکل: با یک ریشهٔ مورد اعتماد و ~log₂n هش می‌توان ثابت کرد یک رکورد مشخص عضو همین
لاگ است، بدون افشای بقیهٔ رکوردها؛ و یک `logging.Handler` آماده که با اضافه‌کردنش به
لاگرهای موجود، همان `logger.info(...)`‌هایی که از قبل می‌نویسید به رکورد حسابرسی
تبدیل می‌شوند (نوشتن در ترد جداگانه، پس مسیر درخواست کند نمی‌شود)؛ و نوشتن امن از چند
پروسه با یک قفل فایل (`lock_path=`) که پیش از هر append، انتهای زنجیره را از استوریج
دوباره می‌خواند. checkpoint ریشهٔ مرکل را هم امضا می‌کند و CLI با
کد خروج مناسب CI کار می‌کند (کد ۱ یعنی زنجیره شکسته یا اثبات نامعتبر).

## License

MIT — see [LICENSE](LICENSE).

---

Made ❤️ by Mohammad — [@llllxyz](https://t.me/llllxyz)
