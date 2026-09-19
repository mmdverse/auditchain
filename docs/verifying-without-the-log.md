# Verifying an audit log you do not own

*How an auditor, a customer or a regulator checks a log without getting the keys, the
database, or even the records.*

The person who needs to trust an audit log is almost never the person who runs it. They
are the auditor who shows up once a quarter, the customer asking whether the access
record is real, the regulator with a deadline. Handing them the database is both
impractical and dangerous: it exposes every record to someone who only needs to check
one, and it usually means handing over a credential that can also write.

This page is the workflow for the other side — verifying a log with artifacts that are
useless to anyone who wants to forge one.

## What the verifier needs

Three things, none of which is a secret:

| Artifact | What it gives them | How it travels |
|---|---|---|
| The public key | proves *who* wrote each record, and who signed the anchor | a few lines in a config or a published fingerprint |
| A signed checkpoint | an anchor they can trust without trusting the log | one small JSON file, published hourly |
| An inclusion proof | proves one record is in that anchored log | ~log₂n hashes — 1,150 bytes for a 7,342-record log |

None of these lets the verifier write, re-seal, or forge anything. That is the whole
point: the sealing key and the signing key never leave the operator.

One artifact is **not** on that list, on purpose: **the seal key**. A verifier should not
have it, because holding it also means being able to re-seal the log. Everything they
need instead is public — including the anchor, which is signed with the Ed25519 key
rather than the HMAC one, so checking it takes the public key and nothing else.

## The workflow

**1. The operator certifies a state of the log.**

```bash
auditchain keygen --private-out signing.key --public-out signing.pub
auditchain checkpoint audit.sqlite --signing-key signing.key --signer-id ops-2026 \
  --output audit.checkpoint
```

The checkpoint says: *at this moment, the record at sequence 7,341 had this hash, and
everything up to it hashes to this Merkle root*. It is signed with Ed25519 and it is
stored outside the log — in a different system, a git repository, a transparency log.
Anywhere the log's own writer cannot rewrite later.

**2. The operator publishes the checkpoint** (web page, S3 object with a retention
policy, a commit in a public repository) and keeps the log itself where it is.

**3. The verifier checks the whole log, occasionally, if they have it.**

```bash
auditchain verify audit.sqlite --signer s0=signing.pub --checkpoint audit.checkpoint \
  --public-key signing.pub
```

Note what is in that command: two public keys (the records' and the anchor's) and no
secrets. The anchor is loaded only after its signature checks out.

**4. The verifier checks a single record, on demand.**

The operator produces the proof (their log, their checkpoint), and sends only the proof
file:

```bash
auditchain proof audit.sqlite --seq 7341 --checkpoint audit.checkpoint \
  --seal-key-file seal.key --output 7341.proof
# 7341.proof is 13 hashes for that 7,342-record log (1,150 bytes on disk);
# no other record and no key is in the file
```

The verifier checks it against the published anchor — with no secret, no log, and no
access to the system:

```bash
auditchain verify-proof 7341.proof --checkpoint audit.checkpoint --public-key signing.pub
# or, if they copied the root out of the anchor by hand:
auditchain verify-proof 7341.proof --root 9f2c1e...b7a4
```

Exit code `0` means the record is in the log that produced the published root. Exit code
`1` means it is not — or that the proof was altered on the way.

The same two steps in code:

```python
from auditchain import InclusionProof

proof = InclusionProof.load("7341.proof")
assert proof.verify(published_root)
assert proof.seq == 7341 and proof.size == 7342   # position and log size are committed
```

If the verifier *does* get the full log (a quarterly audit, say), they can recompute
everything themselves:

```python
from auditchain import merkle_root

assert merkle_root([record.hash for record in records]) == published_root
```

## What each failure means

| Output | What happened |
|---|---|
| `signature mismatch: the record was rewritten without the signing key` | someone edited a record and recomputed the chain — with the seal key, but without the signing key |
| `missing signature: the record is not signed` | signatures were stripped, or records were appended by a writer that does not sign |
| `checkpoint anchor mismatch` | the log was rebuilt, extended or truncated after the anchor was signed |
| `merkle root mismatch` | same, but caught by the content root rather than the tail hash |
| `the proof does not match the trusted root` | the record you were shown is not in the anchored log |
| `FAILED at seq N: prev_hash mismatch` | a record was removed, reordered or inserted in the middle |

## What this proves — and what it does not

**Proves.** Every record is unchanged since it was written. Records cannot be inserted,
removed, reordered or moved. Every signed record really came from the holder of the
signing key. Each verified proof shows a specific record is part of a specific anchored
state.

**Does not prove.** *Freshness*: an inclusion proof says "this record is in the log with
this root", and an old proof of an old root stays true forever. The timestamp inside the
record is written by the operator, so treat it as a claim unless the checkpoint was
published somewhere with an independent clock. A chain also cannot show that a record
was *never going to be deleted* — only that it was there when the anchor was signed.

**Still the operator's job.** Protecting the signing key. Publishing checkpoints on a
schedule so the gap between anchors stays small. Backing up the log. The library makes
the evidence verifiable; it cannot make anyone look at it.

## A minute-by-minute recipe

For a system that logs a few thousand events a day:

```bash
# hourly, by cron
auditchain checkpoint /var/lib/app/audit.sqlite \
  --seal-key-file /etc/app/seal.key --output /var/lib/app/checkpoints/$(date -u +%Y%m%dT%H%M)
# then ship the file somewhere the log's writer cannot touch
aws s3 cp /var/lib/app/checkpoints/ s3://audit-anchors/ --recursive --storage-class STANDARD_IA
```

```bash
# quarterly, by an auditor with no access to the application at all
auditchain verify-proof 7341.proof --checkpoint 20260101T0000 --public-key signing.pub
```

That is the asymmetry worth building: the operator needs the keys to write; the auditor
needs nothing but a root they can check, on hardware they control.

## Both sides are asymmetric now

- **Records**: `auditchain verify --signer s0=signing.pub` — the writer signs, the
  verifier cannot forge.
- **Anchors**: `--signing-key` when the checkpoint is written, `--public-key` when it is
  read. A signed checkpoint will not load unverified, and the HMAC is not demanded once
  the Ed25519 signature has checked out.

So the verifier holds two public keys and the artifacts above, and never a secret that
could rewrite the log. What is still worth being careful about: the **private key** (one
file, mode 600, off the application server if you can), the **publishing schedule** (a
gap between anchors is a gap an attacker can use), and the **freshness** point from the
section above — a valid old anchor proves the past, not the present.
