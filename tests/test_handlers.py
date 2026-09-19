"""Tests for the logging.Handler bridge."""

from __future__ import annotations

import asyncio
import logging
import threading
import time

import pytest

from auditchain import AuditLog, AuditLogHandler, MemoryBackend, SyncAuditLog
from auditchain.signing import CRYPTOGRAPHY_AVAILABLE
from auditchain.verify import verify_chain

SEAL_KEY = b"a-seal-key-long-enough-to-matter"

# Signing is an optional extra; the suite has to pass with and without it.
requires_cryptography = pytest.mark.skipif(
    not CRYPTOGRAPHY_AVAILABLE, reason="requires the 'ed25519' extra"
)


def _logger(handler: AuditLogHandler, name: str = "billing", level: int = logging.DEBUG):
    logger = logging.getLogger(f"{name}-{id(handler)}")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger


def _records(log: AuditLog):
    return asyncio.run(log.read())


# ------------------------------------------------------------------------ basics


def test_messages_become_audit_records():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log, background=False)
    logger = _logger(handler)

    logger.info("invoice.approve %s", "inv-1")
    records = _records(log)

    assert len(records) == 1
    record = records[0]
    assert record.action == "invoice.approve inv-1"  # lazy %-args are applied
    assert record.actor == logger.name  # default actor: the logger name
    assert record.subject == ""
    handler.close()


def test_metadata_carries_where_it_came_from():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log, background=False)
    logger = _logger(handler)

    logger.warning("disk %s", "almost full")
    metadata = _records(log)[0].metadata

    assert metadata["logger"] == logger.name
    assert metadata["level"] == "WARNING"
    assert metadata["module"] == "test_handlers"
    assert metadata["line"] > 0
    assert "func" in metadata
    assert metadata["level"] == "WARNING"
    handler.close()


def test_extra_overrides_actor_action_subject_and_metadata():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log, background=False)
    logger = _logger(handler)

    logger.info(
        "ignored text",
        extra={
            "audit_actor": "alice@example.com",
            "audit_action": "invoice.approve",
            "audit_subject": "inv-7",
            "audit_metadata": {"amount": 1200},
        },
    )
    record = _records(log)[0]

    assert record.actor == "alice@example.com"
    assert record.action == "invoice.approve"
    assert record.subject == "inv-7"
    assert record.metadata["amount"] == 1200
    handler.close()


def test_unrelated_extra_keys_stay_out_of_the_audit_record():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log, background=False)
    logger = _logger(handler)

    logger.info("login", extra={"request_id": "r-1", "tenant": "acme"})
    metadata = _records(log)[0].metadata

    assert "request_id" not in metadata and "tenant" not in metadata
    handler.close()


def test_actor_can_be_a_string_or_a_callable():
    log = AuditLog(MemoryBackend())
    fixed = AuditLogHandler(log, actor="service-account", background=False)
    _logger(fixed, "one").info("a")

    dynamic = AuditLogHandler(log, actor=lambda record: record.name.split("-")[0], background=False)
    _logger(dynamic, "two").info("b")

    actors = [record.actor for record in _records(log)]
    assert actors == ["service-account", "two"]
    fixed.close()
    dynamic.close()


def test_fixed_metadata_is_merged_but_record_extras_win():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log, metadata={"env": "prod", "tier": "db"}, background=False)
    logger = _logger(handler)

    logger.info("x", extra={"audit_metadata": {"tier": "api"}})
    metadata = _records(log)[0].metadata

    assert metadata["env"] == "prod" and metadata["tier"] == "api"
    handler.close()


def test_timestamp_comes_from_the_log_record():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log, background=False)
    record = logging.LogRecord(
        name="billing",
        level=logging.INFO,
        pathname=__file__,
        lineno=3,
        msg="frozen",
        args=(),
        exc_info=None,
    )
    record.created = 1_700_000_000.5  # a fixed moment in time

    handler.emit(record)
    assert _records(log)[0].timestamp == "2023-11-14T22:13:20.500000Z"
    handler.close()


# ------------------------------------------------------------------ exceptions


def test_an_exception_is_captured_in_the_metadata():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log, background=False)
    logger = _logger(handler)

    try:
        raise ValueError("payment gateway said no")
    except ValueError:
        logger.exception("charge.failed")

    record = _records(log)[0]
    assert record.action == "charge.failed"
    assert "ValueError: payment gateway said no" in record.metadata["exception"]
    assert "Traceback" in record.metadata["exception"]
    handler.close()


def test_exception_capture_can_be_turned_off():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log, include_exception=False, background=False)
    logger = _logger(handler)

    try:
        raise ValueError("nope")
    except ValueError:
        logger.exception("charge.failed")

    assert "exception" not in _records(log)[0].metadata
    handler.close()


# -------------------------------------------------------------------- filtering


def test_handler_level_and_logger_level_both_apply():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log, level=logging.WARNING, background=False)
    logger = _logger(handler, level=logging.DEBUG)

    logger.info("skipped by the handler")
    logger.warning("kept")

    assert [record.action for record in _records(log)] == ["kept"]
    handler.close()


# ------------------------------------------------------------------ background


def test_background_mode_writes_everything_after_flush():
    log = AuditLog(MemoryBackend(), seal_key=SEAL_KEY)
    handler = AuditLogHandler(log)  # background=True by default
    logger = _logger(handler)
    try:
        for i in range(50):
            logger.info("step %d", i)
        handler.flush()

        records = _records(log)
        assert len(records) == 50
        assert [r.action for r in records] == [f"step {i}" for i in range(50)]
        assert [r.seq for r in records] == list(range(50))

        # the chain the handler built is a normal, verifiable chain
        report = verify_chain(records, SEAL_KEY, keyring={"k0": SEAL_KEY})
        assert report.ok, report
    finally:
        handler.close()


def test_background_mode_keeps_the_caller_off_the_disk(monkeypatch):
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log)
    logger = _logger(handler)
    seen: list[str] = []

    original = handler._write

    def slow_write(entry):
        seen.append(threading.current_thread().name)
        time.sleep(0.01)
        original(entry)

    monkeypatch.setattr(handler, "_write", slow_write)
    try:
        started = time.monotonic()
        for i in range(20):
            logger.info("fast %d", i)
        elapsed = time.monotonic() - started

        assert elapsed < 0.2  # emit() did not wait for the writes
        handler.flush()
        assert len(seen) == 20
        assert all(name == "auditchain-handler" for name in seen)
    finally:
        handler.close()


def test_concurrent_logging_from_threads_loses_nothing():
    log = AuditLog(MemoryBackend(), seal_key=SEAL_KEY)
    handler = AuditLogHandler(log)
    logger = _logger(handler)

    def burst(tag: str) -> None:
        for i in range(25):
            logger.info("t-%s-%d", tag, i)

    threads = [threading.Thread(target=burst, args=(f"t{n}",)) for n in range(4)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        handler.flush()

        records = _records(log)
        assert len(records) == 100
        assert len({r.action for r in records}) == 100  # no duplicates, none lost
        assert verify_chain(records, SEAL_KEY, keyring={"k0": SEAL_KEY}).ok
    finally:
        handler.close()


def test_close_drains_and_stops_the_worker():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log)
    logger = _logger(handler)

    for i in range(10):
        logger.info("before close %d", i)
    handler.close()

    assert len(_records(log)) == 10
    assert handler._thread is None  # the worker thread is gone


def test_emitting_after_close_is_reported_not_raised(caplog):
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log)
    handler.close()

    record = logging.LogRecord("x", logging.INFO, __file__, 1, "late", (), None)
    handler.emit(record)  # accepted silently, but nothing is written any more

    assert _records(log) == []


# ------------------------------------------------------------------ sync wiring


def test_sync_mode_writes_immediately():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log, background=False)
    logger = _logger(handler)

    logger.info("straight to the log")
    assert len(_records(log)) == 1  # nothing buffered
    handler.close()


def test_sync_mode_refuses_to_run_inside_an_event_loop():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log, background=False)
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "hello", (), None)

    async def emit_inside_loop():
        with pytest.raises(RuntimeError, match="background=True"):
            handler.emit(record)

    asyncio.run(emit_inside_loop())
    handler.close()


def test_background_handler_works_from_inside_an_event_loop():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log)
    logger = _logger(handler)

    async def main() -> None:
        logger.info("from async code")
        await asyncio.sleep(0)

    asyncio.run(main())
    handler.flush()
    assert [r.action for r in _records(log)] == ["from async code"]
    handler.close()


# -------------------------------------------------------------------- failures


def test_a_failing_log_is_reported_but_never_raised():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log)
    logger = _logger(handler)

    async def boom(*args, **kwargs):
        raise RuntimeError("storage is gone")

    logger.info("fine")  # let the worker start and the log initialize
    handler.flush()
    log.append = boom  # type: ignore[method-assign]

    logger.info("this one cannot be written")
    handler.flush()

    assert handler.error_count == 1
    assert isinstance(handler.last_error, RuntimeError)
    logger.info("still alive")
    handler.close()


def test_sync_failure_is_counted_too():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log, background=False)

    async def boom(*args, **kwargs):
        raise RuntimeError("storage is gone")

    log.append = boom  # type: ignore[method-assign]
    handler.emit(logging.LogRecord("x", logging.INFO, __file__, 1, "nope", (), None))

    assert handler.error_count == 1 and isinstance(handler.last_error, RuntimeError)
    handler.close()


# -------------------------------------------------------------------- lifecycle


def test_close_log_closes_the_audit_log_too():
    log = AuditLog(MemoryBackend())
    log_closed = False

    async def close():
        nonlocal log_closed
        log_closed = True

    log.close = close  # type: ignore[method-assign]
    handler = AuditLogHandler(log, close_log=True)
    handler.close()
    assert log_closed


def test_the_handler_leaves_the_log_open_by_default():
    log = AuditLog(MemoryBackend())
    handler = AuditLogHandler(log)
    handler.close()

    asyncio.run(log.append("someone", "still.works"))
    assert len(_records(log)) == 1


@requires_cryptography
def test_sync_facade_can_sign_records():
    facade = SyncAuditLog(MemoryBackend(), signing_key=SEAL_KEY)
    facade.append("sara", "login")

    assert facade.public_key is not None
    assert facade.verify(signers={"s0": facade.public_key}).ok
    assert facade.merkle_root()
    assert facade.inclusion_proof(0).verify(facade.merkle_root())
    facade.close()


def test_sync_facade_exposes_signing_to_the_handler():
    facade = SyncAuditLog(MemoryBackend())
    handler = AuditLogHandler(facade._log, background=False)  # same underlying log
    logger = _logger(handler)

    logger.info("audited")
    records = facade.read()
    assert len(records) == 1 and records[0].action == "audited"
    handler.close()
    facade.close()
