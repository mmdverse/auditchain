# Why your audit log needs a hash chain

*An honest engineering argument for tamper-evident audit logging — and the limits it cannot overcome.*

## 1. The promise of an audit log

Compliance frameworks (SOC 2, ISO 27001, PCI DSS) and security teams ask one
question repeatedly: **can you show what happened, and can you prove nobody changed
the record afterwards?**

An audit log is supposed to answer both halves. In practice, most logs answer only
the first. The second half — *prove* — is the hard part, and it's the part that
matters when an incident happens, when an auditor asks, or when a dispute lands in
front of a lawyer.

## 2. The threat model nobody wants to discuss

Audit logs live on the same machines as the systems they monitor. Anyone who can
do damage usually has access to the machine where the log sits. Realistic cases:

- an application server compromised through a dependency or a leaked secret;
- a database operator with more permissions than the app itself;
- a rogue insider with legitimate access who wants to hide a specific action;
- nobody malicious at all: a buggy cleanup job, a botched migration, or a restore
  from an old backup that silently rewrites the past.

If the log is a normal database table or a plain text file, "who did what" is only
ever as good as the permissions of whoever is asking. Anyone with write access can
rewrite history and leave no trace. That's not auditing — that's storytelling.

## 3. The usual countermeasures, and where they leak

| Approach | What it actually gives you |
| --- | --- |
| Append-only files | A convention, not a property. A file is not an immutable structure. |
| WORM storage | Genuinely strong, but costs money, latency, and logistics. |
| Replication / SIEM ingestion | Copies of a lie are still lies; the original stays mutable. |
| Read-only DB permissions | The log is still a table — you're back to trusting permissions. |

The gap in all of these: **no mechanism that makes rewriting detectable by itself.**

## 4. Hash chains: making rewriting detectable

A hash chain is a simple construction — append every new record's *hash* to the
record, and link each record to the one before it:

```
record 0:  (seq=0, ..., prev_hash=GENESIS)        hash = H(GENESIS ‖ payload₀)
record 1:  (seq=1, ..., prev_hash=hash₀)          hash = H(hash₀   ‖ payload₁)
record 2:  (seq=2, ..., prev_hash=hash₁)          hash = H(hash₁   ‖ payload₂)
...
```

Each record's hash commits to the entire history before it. Verification is a single
linear pass: recompute every hash and check three things —

1. the stored hash matches the record content,
2. each `prev_hash` equals the previous record's hash,
3. the sequence numbers are continuous.

Any violation tells you **exactly which record** broke the chain.

| Attack | Detected? | How |
| --- | --- | --- |
| Edit a record in place | ✅ | content hash no longer matches |
| Delete a record from the middle | ✅ | next record's `prev_hash` points at nothing |
| Insert a record | ✅ | sequence and/or linkage breaks |
| Reorder records | ✅ | chain order no longer consistent |
| Rewrite the whole log (no key) | ⚠️ | integrity only — re-sealing is possible |
| Rewrite the whole log (with an HMAC key) | ✅ | attacker lacks the key |
| Drop the last N records (tail truncation) | ❌ without an anchor | the chain stays internally consistent |

## 5. The honest limits — the part most marketing skips

**Tail truncation is undetectable from the chain alone.** Deleting the last records
leaves a perfectly valid chain behind. Two practical fixes:

- pass an **expected record count** to `verify()` (the CLI flag `--expected-count`);
- or **anchor** the latest hash somewhere the writer cannot reach — a signed digest
  to a second system, an email, a SIEM, anything immutable. The anchor turns the
  tail cut into a provable break.

**A key is only as good as its custody.** HMAC-SHA256 sealing protects against
attackers who can write the log but not read the key. A key stored next to the log
is decoration. Keys belong in a secret manager or an env-injected file outside the
log's trust boundary.

**Single writer.** Concurrent appends are not safe on a plain hash chain. Batch
your writes or use a queue; the chain must be serialized.

**Detectability ≠ prevention.** Hash chains detect tampering after the fact. They
don't stop it. For prevention you still need access control, least privilege, and
audited key management.

## 6. What it looks like in practice

```python
import asyncio, secrets
from auditchain import AuditLog, SqliteBackend

key = secrets.token_bytes(32)  # store this in a secret manager, not next to the log

async def main():
    async with AuditLog(SqliteBackend("audit.sqlite"), seal_key=key) as log:
        await log.append("sara", "payment.approve", "invoice:12", metadata={"amount": 1200})
        report = await log.verify()
        print(report)  # OK: 1 record(s) verified

asyncio.run(main())
```

```bash
# CI-friendly integrity check (exit code 1 when the chain is broken)
python -m auditchain verify audit.sqlite --expected-count 1000
```

## 7. The takeaway

For any system where "who did what" must be *provable* — compliance, incident
response, insider-threat investigations, disputes — an audit log that depends only
on permissions is a liability disguised as a control. A hash chain costs a few
microseconds per record, needs no special hardware, and converts every rewrite
attempt into a detectable, localizable break. It is not a silver bullet; combined
with anchoring, expected counts and proper key custody, it's the difference between
"trust our word" and "verify yourself."

---

*Made with [auditchain](https://github.com/mmdverse/auditchain) — a zero-dependency,
async-first implementation of the above (MIT).*
