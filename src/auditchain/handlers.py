"""A :mod:`logging` handler that feeds records into an audit log.

Application logs and audit logs want different things: application logs are verbose,
rotated and disposable; audit logs are ordered, sealed and kept. This handler lets the
same call site serve both — ``logger.info("invoice.approve %s", invoice_id)`` leaves a
hash-chained record behind without an extra line of code.

:class:`AuditLogHandler` writes from a background thread by default, so ``emit()`` never
blocks the caller and works from inside an event loop, from sync code and from threads.
The audit log itself is written by one thread at a time, which is what the chain needs.

Per-record overrides ride on the usual ``extra`` dict::

    logger.info(
        "invoice.approve %s",
        invoice_id,
        extra={
            "audit_actor": "alice@example.com",   # default: the logger name
            "audit_subject": invoice_id,          # default: ""
            "audit_metadata": {"amount": 1200},   # merged into the record metadata
        },
    )

Anything unrecognized in ``extra`` stays out of the audit record — the standard
application-log noise (process ids, request ids, stack objects) is not automatically
copied, so the audit metadata stays small and predictable.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import queue
import threading
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from .log import AuditLog

#: Keys this handler looks for in a LogRecord's ``extra``.
ACTOR_KEY = "audit_actor"
ACTION_KEY = "audit_action"
SUBJECT_KEY = "audit_subject"
METADATA_KEY = "audit_metadata"


class _Stop:
    """Sentinel that tells the worker thread to finish; compared by identity."""


#: What the emitting thread hands to the worker: everything already resolved, so the
#: LogRecord itself never crosses the thread boundary.
Entry = tuple[str, str, str, dict[str, Any], str]

_STOP = _Stop()
_EXCEPTION_FORMATTER = logging.Formatter()

__all__ = ["AuditLogHandler"]


def _iso_from_created(created: float) -> str:
    """Render a LogRecord timestamp the way the log itself does (UTC, microseconds)."""
    moment = datetime.fromtimestamp(created, tz=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


class AuditLogHandler(logging.Handler):
    """Append a record to a hash-chained audit log for every log record it sees.

    ``log`` is an :class:`~auditchain.AuditLog`. With ``background=True`` (the default)
    a daemon thread owns the log and drains a queue, so ``emit()`` returns immediately;
    ``flush()`` blocks until everything queued has been written, and ``close()`` drains
    and stops the thread.

    ``actor`` is either a string or a callable taking the LogRecord (for example
    ``lambda record: record.name`` or a request-scoped user id). ``metadata`` adds
    fixed keys to every audit record.

    Failures never propagate into the application: they are reported through
    :meth:`logging.Handler.handleError` and counted in :attr:`error_count`.
    """

    def __init__(
        self,
        log: AuditLog,
        *,
        level: int = logging.NOTSET,
        actor: str | Callable[[logging.LogRecord], str] | None = None,
        metadata: Mapping[str, Any]
        | Callable[[logging.LogRecord], Mapping[str, Any]]
        | None = None,
        background: bool = True,
        include_exception: bool = True,
        close_log: bool = False,
    ) -> None:
        super().__init__(level=level)
        self._log = log
        self._actor = actor
        self._metadata = metadata
        self._background = background
        self._include_exception = include_exception
        self._close_log = close_log
        self._closed = False
        self.error_count = 0
        self.last_error: BaseException | None = None
        self._queue: queue.Queue[Entry | _Stop] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        if background:
            self._start_worker()

    # --------------------------------------------------------------- preparation

    def _resolve_actor(self, record: logging.LogRecord) -> str:
        override = getattr(record, ACTOR_KEY, None)
        if override is not None:
            return str(override)
        if callable(self._actor):
            return str(self._actor(record))
        if self._actor is not None:
            return str(self._actor)
        return record.name

    def _resolve_metadata(self, record: logging.LogRecord) -> dict[str, Any]:
        data: dict[str, Any] = {
            "logger": record.name,
            "level": record.levelname,
            "module": record.module,
            "line": record.lineno,
            "func": record.funcName,
        }
        if self._include_exception and record.exc_info:
            data["exception"] = _EXCEPTION_FORMATTER.formatException(record.exc_info)
        if callable(self._metadata):
            data.update(dict(self._metadata(record)))
        elif self._metadata is not None:
            data.update(dict(self._metadata))
        extra = getattr(record, METADATA_KEY, None)
        if isinstance(extra, Mapping):
            data.update(dict(extra))
        return data

    def _entry(self, record: logging.LogRecord) -> Entry:
        action = getattr(record, ACTION_KEY, None) or record.getMessage()
        subject = getattr(record, SUBJECT_KEY, None) or ""
        return (
            self._resolve_actor(record),
            str(action),
            str(subject),
            self._resolve_metadata(record),
            _iso_from_created(record.created),
        )

    # -------------------------------------------------------------------- writing

    def _report_error(self, record: logging.LogRecord, error: BaseException | None = None) -> None:
        """Hand a failure to ``handleError`` without risking a raise of our own.

        Python 3.13 reads the traceback out of ``sys.exception()``, which only exists
        inside an ``except`` block, so the failure is re-raised here on purpose before
        being reported.
        """
        try:
            try:
                raise (
                    error
                    if error is not None
                    else RuntimeError("auditchain: the record could not be written")
                )
            except BaseException:  # noqa: BLE001 - reported just below
                self.handleError(record)
        except BaseException:  # noqa: BLE001 - the logging contract forbids raising
            pass

    def emit(self, record: logging.LogRecord) -> None:
        if self._closed:
            self._report_error(record, RuntimeError("auditchain: the handler is closed"))
            return
        try:
            entry = self._entry(record)
        except Exception as exc:  # noqa: BLE001 - logging must never raise into the caller
            self._report_error(record, exc)
            return
        if self._background:
            # _entry() runs on the caller's thread on purpose: the record object is only
            # guaranteed to be valid while emit() is running.
            self._queue.put(entry)
            return
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError(
                "AuditLogHandler(background=False) cannot write from inside a running "
                "event loop; use background=True"
            )
        self._write(entry)

    def _write(self, entry: Entry) -> None:
        actor, action, subject, metadata, timestamp = entry
        try:
            self._run(
                self._log.append(actor, action, subject, metadata=metadata, timestamp=timestamp)
            )
        except BaseException as exc:  # noqa: BLE001 - reported, never raised at the caller
            self.error_count += 1
            self.last_error = exc
            self._report_error(_synthetic_record(actor, action), exc)

    def _run(self, coro: Any) -> Any:
        """Run a coroutine, whether or not this thread owns an event loop."""
        if self._loop is not None:
            return self._loop.run_until_complete(coro)
        return asyncio.run(coro)

    # ------------------------------------------------------------------ background

    def _start_worker(self) -> None:
        def worker() -> None:
            self._loop = asyncio.new_event_loop()
            try:
                while True:
                    entry = self._queue.get()
                    try:
                        if isinstance(entry, _Stop):
                            return
                        self._write(entry)
                    finally:
                        self._queue.task_done()
            finally:
                if self._close_log:
                    with contextlib.suppress(BaseException):  # shutdown must not explode
                        self._loop.run_until_complete(self._log.close())
                self._loop.close()
                self._loop = None

        self._thread = threading.Thread(target=worker, name="auditchain-handler", daemon=True)
        self._thread.start()

    def flush(self) -> None:
        """Block until every queued record has been written to the log."""
        if self._background and not self._closed:
            self._queue.join()

    def close(self) -> None:
        """Drain the queue, stop the worker thread and release the handler."""
        if self._closed:
            return
        if self._background:
            self.flush()
            self._queue.put(_STOP)
            if self._thread is not None:
                self._thread.join()
                self._thread = None
        elif self._close_log:
            try:
                self._run(self._log.close())
            except BaseException as exc:  # noqa: BLE001
                self.error_count += 1
                self.last_error = exc
        self._closed = True
        super().close()


def _synthetic_record(actor: str, action: str) -> logging.LogRecord:
    """A minimal record so ``handleError`` has something to print."""
    return logging.LogRecord(
        name="auditchain",
        level=logging.ERROR,
        pathname=__file__,
        lineno=0,
        msg=f"auditchain: failed to append {actor!r}/{action!r}",
        args=(),
        exc_info=None,
    )
