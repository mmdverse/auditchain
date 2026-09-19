"""Tests for cross-process append safety (the lock and the tail refresh)."""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from auditchain import (
    AuditLog,
    FileLock,
    JsonlBackend,
    LockTimeout,
    MemoryBackend,
    NoLock,
    SqliteBackend,
)
from auditchain.verify import verify_chain

SEAL_KEY = b"shared-secret-for-many-writers!!"


def _records(log: AuditLog):
    return asyncio.run(log.read())


# ------------------------------------------------------------------- the lock itself


def test_file_lock_acquire_release_and_reuse(tmp_path):
    lock = FileLock(tmp_path / "audit.lock")
    assert not lock.held
    with lock:
        assert lock.held
        assert (tmp_path / "audit.lock").exists()
    assert not lock.held

    with lock:  # a released lock can be taken again
        assert lock.held


def test_file_lock_is_reentrant_within_one_thread(tmp_path):
    lock = FileLock(tmp_path / "audit.lock")
    with lock, lock:
        assert lock.held
    assert not lock.held


def test_two_instances_on_one_path_serialize(tmp_path):
    first = FileLock(tmp_path / "audit.lock")
    second = FileLock(tmp_path / "audit.lock")
    order: list[str] = []
    first_holds = threading.Event()
    release_first = threading.Event()

    def holder() -> None:
        with first:
            order.append("first-in")
            first_holds.set()
            release_first.wait(timeout=5)
            order.append("first-out")

    def waiter() -> None:
        first_holds.wait(timeout=5)
        with second:
            order.append("second-in")

    threads = [threading.Thread(target=holder), threading.Thread(target=waiter)]
    for thread in threads:
        thread.start()
    time.sleep(0.2)
    assert order == ["first-in"]  # the second thread is still waiting
    release_first.set()
    for thread in threads:
        thread.join(timeout=5)
    assert order == ["first-in", "first-out", "second-in"]


def test_timeout_instead_of_waiting_forever(tmp_path):
    lock = FileLock(tmp_path / "audit.lock")
    with lock, pytest.raises(LockTimeout):
        FileLock(tmp_path / "audit.lock", timeout=0.1).acquire()


def test_lock_is_released_when_the_body_raises(tmp_path):
    lock = FileLock(tmp_path / "audit.lock")
    with pytest.raises(ValueError), lock:
        raise ValueError("boom")

    assert not lock.held
    # and another writer can take it immediately
    started = time.monotonic()
    with FileLock(tmp_path / "audit.lock", timeout=1):
        pass
    assert time.monotonic() - started < 0.5


def test_the_lock_file_records_the_holder_pid(tmp_path):
    path = tmp_path / "audit.lock"
    with FileLock(path):
        assert str(os.getpid()) in path.read_text()


def test_no_lock_is_a_no_op():
    lock = NoLock()
    with lock:
        pass
    assert not hasattr(lock, "held")


# ----------------------------------------------------------------------- load_last


def test_load_last_on_every_backend(tmp_path):
    async def run(backend, path=None):
        log = AuditLog(backend)
        await log.init()  # load_last() reads storage, so it has to be open
        assert await backend.load_last() is None  # empty log
        await log.append("sara", "one")
        await log.append("sara", "two")
        last = await backend.load_last()
        assert last is not None and last.action == "two"
        await log.close()
        return backend

    for backend in (
        MemoryBackend(),
        JsonlBackend(tmp_path / "audit.jsonl"),
        SqliteBackend(tmp_path / "audit.sqlite"),
    ):
        asyncio.run(run(backend))


def test_jsonl_load_last_scans_backwards_over_many_lines(tmp_path):
    path = tmp_path / "audit.jsonl"

    async def run():
        log = AuditLog(JsonlBackend(path))
        for i in range(200):
            await log.append("sara", f"action-{i}", metadata={"pad": "x" * 200})
        await log.close()
        return await JsonlBackend(path).load_last()

    last = asyncio.run(run())
    assert last is not None and last.action == "action-199"


# ------------------------------------------------------- sharing a log between writers


def test_two_writers_without_a_lock_collide(tmp_path):
    """The failure this feature exists for: two long-lived writers, one log.

    Both open the log while it is empty (the situation in two processes that started
    around the same time), so both believe the next sequence number is 0.
    """
    # sqlite: the primary key refuses the duplicate — loud, but only after the fact
    path = tmp_path / "audit.sqlite"

    async def run_sqlite():
        first = AuditLog(SqliteBackend(path))
        second = AuditLog(SqliteBackend(path))
        await first.init()  # both see an empty log
        await second.init()
        await first.append("sara", "from-first")
        with pytest.raises(sqlite3.IntegrityError):
            await second.append("bob", "from-second")
        await first.close()
        await second.close()

    asyncio.run(run_sqlite())

    # jsonl: nothing stands in the way — the chain is written broken and verification
    # is the first thing that notices
    jsonl_path = tmp_path / "audit.jsonl"

    async def run_jsonl():
        first = AuditLog(JsonlBackend(jsonl_path))
        second = AuditLog(JsonlBackend(jsonl_path))
        await first.init()
        await second.init()
        await first.append("sara", "from-first")
        await second.append("bob", "from-second")
        await first.close()
        await second.close()
        return await AuditLog(JsonlBackend(jsonl_path)).read()

    records = asyncio.run(run_jsonl())
    assert [record.seq for record in records] == [0, 0]
    assert not verify_chain(records).ok


def test_two_writers_with_a_shared_lock_agree(tmp_path):
    path = tmp_path / "audit.sqlite"
    lock_path = tmp_path / "audit.lock"

    async def run():
        first = AuditLog(SqliteBackend(path), lock_path=lock_path)
        await first.append("sara", "from-first")

        second = AuditLog(SqliteBackend(path), lock_path=lock_path)
        await second.append("bob", "from-second")

        await first.append("sara", "from-first-again")
        await first.close()
        await second.close()
        return await AuditLog(SqliteBackend(path)).read()

    records = asyncio.run(run())
    assert [record.seq for record in records] == [0, 1, 2]
    assert [record.prev_hash for record in records][1:] == [r.hash for r in records][:-1]
    assert verify_chain(records).ok


def test_batch_append_also_refreshes_the_tail(tmp_path):
    path = tmp_path / "audit.sqlite"
    lock_path = tmp_path / "audit.lock"

    async def run():
        first = AuditLog(SqliteBackend(path), lock_path=lock_path)
        second = AuditLog(SqliteBackend(path), lock_path=lock_path)
        await first.append("sara", "single")
        await second.append_many([("bob", "batch-1", "", None), ("bob", "batch-2", "", None)])
        await first.append("sara", "last")
        await first.close()
        await second.close()
        return await AuditLog(SqliteBackend(path)).read()

    records = asyncio.run(run())
    assert [record.action for record in records] == ["single", "batch-1", "batch-2", "last"]
    assert verify_chain(records).ok


def test_the_lock_can_be_any_object_with_the_interface(tmp_path):
    calls: list[str] = []

    class RecordingLock(NoLock):
        def acquire(self) -> None:
            calls.append("acquire")

        def release(self) -> None:
            calls.append("release")

    async def run():
        log = AuditLog(SqliteBackend(tmp_path / "a.sqlite"), lock=RecordingLock())
        await log.append("sara", "one")
        await log.close()

    asyncio.run(run())
    assert calls == ["acquire", "release"]


def test_lock_and_lock_path_together_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="either lock or lock_path"):
        AuditLog(MemoryBackend(), lock=NoLock(), lock_path=tmp_path / "x.lock")


# ------------------------------------------------------------------- real processes


def _append_worker(db: str, lock_path: str, worker: int, count: int) -> None:
    """Append ``count`` records as this process; must be importable for spawn."""
    from auditchain import AuditLog, SqliteBackend

    async def run() -> None:
        log = AuditLog(
            SqliteBackend(db), seal_key=b"shared-secret-for-many-writers!!", lock_path=lock_path
        )
        for i in range(count):
            await log.append(f"worker-{worker}", f"action-{i}")
        await log.close()

    asyncio.run(run())


def _jsonl_worker(path: str, lock_path: str, worker: int, count: int) -> None:
    from auditchain import AuditLog, JsonlBackend

    async def run() -> None:
        log = AuditLog(JsonlBackend(path), lock_path=lock_path)
        for i in range(count):
            await log.append(f"worker-{worker}", f"line-{i}")
        await log.close()

    asyncio.run(run())


def _run_processes(target, args_list):
    context = multiprocessing.get_context("spawn")
    processes = [context.Process(target=target, args=args) for args in args_list]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=120)
        assert process.exitcode == 0, f"worker exited with {process.exitcode}"


@pytest.mark.slow
def test_four_processes_share_one_sqlite_log(tmp_path):
    db = tmp_path / "shared.sqlite"
    lock_path = tmp_path / "shared.lock"
    workers, each = 4, 15

    _run_processes(
        _append_worker,
        [(str(db), str(lock_path), worker, each) for worker in range(workers)],
    )

    async def run():
        log = AuditLog(SqliteBackend(db), seal_key=SEAL_KEY)
        return await log.read()

    records = asyncio.run(run())
    assert len(records) == workers * each
    assert [record.seq for record in records] == list(range(workers * each))
    assert len({record.actor for record in records}) == workers
    report = verify_chain(records, SEAL_KEY, keyring={"k0": SEAL_KEY})
    assert report.ok, report
    # every signature was made over the record it is stored with
    assert all(
        record.prev_hash == previous.hash
        for previous, record in zip(records, records[1:], strict=False)
    )


@pytest.mark.slow
def test_three_processes_share_one_jsonl_log(tmp_path):
    path = tmp_path / "shared.jsonl"
    lock_path = tmp_path / "shared.lock"
    workers, each = 3, 10

    _run_processes(
        _jsonl_worker,
        [(str(path), str(lock_path), worker, each) for worker in range(workers)],
    )

    lines = [line for line in Path(path).read_text().splitlines() if line.strip()]
    assert len(lines) == workers * each

    async def run():
        log = AuditLog(JsonlBackend(path))
        return await log.read()

    records = asyncio.run(run())
    assert [record.seq for record in records] == list(range(workers * each))
    assert verify_chain(records).ok
