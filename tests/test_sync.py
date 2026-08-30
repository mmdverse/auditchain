from auditchain import JsonlBackend, SyncAuditLog


def test_sync_roundtrip_and_verify(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = SyncAuditLog(JsonlBackend(path))
    rec0 = log.append("sara", "login", "admin", metadata={"ip": "10.0.0.1"})
    rec1 = log.append("jawad", "logout", "admin")
    assert (rec0.seq, rec1.seq) == (0, 1)
    assert rec1.prev_hash == rec0.hash
    report = log.verify()
    assert report.ok and report.records_checked == 2
    log.close()


def test_sync_persists_across_reopen(tmp_path):
    path = tmp_path / "audit.jsonl"
    SyncAuditLog(JsonlBackend(path)).append("sara", "login")
    reopened = SyncAuditLog(JsonlBackend(path))
    rec = reopened.append("jawad", "logout")
    assert rec.seq == 1
    assert reopened.verify().ok
    reopened.close()


def test_sync_append_many_checkpoint_rotate(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = SyncAuditLog(JsonlBackend(path), seal_key=b"a" * 32, key_id="k0")
    recs = log.append_many(
        [("sara", "login", "", None), ("jawad", "update", "invoice:1", {"f": "x"})]
    )
    assert [r.seq for r in recs] == [0, 1]
    assert log.verify().ok
    marker = log.rotate(b"b" * 32, "k1")
    assert marker.action == "key.rotate"
    log.append("sara", "logout")
    report = log.verify()
    assert report.ok, report
    cp = log.checkpoint()
    assert cp.seq == 3
    assert log.verify(checkpoint=cp).ok
    log.close()
