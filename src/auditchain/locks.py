"""Cross-process locks for writers sharing one log.

A hash chain has exactly one writer at a time: two processes that both append from
their own idea of the tail produce duplicate sequence numbers and a broken chain. On
one machine the cheapest fix is an advisory lock on a file next to the log.

    log = AuditLog(SqliteBackend("audit.sqlite"), lock=FileLock("audit.lock"))

While the lock is held, :class:`~auditchain.AuditLog` re-reads the tail of the log from
the backend before building the next record, so every writer chains onto what is really
there instead of what it last saw.

Scope and honesty:

- The lock is **advisory**: it protects writers that use it. Nothing stops a rogue
  process from writing to the storage directly.
- It is **local**: ``flock``/``msvcrt.locking`` work between processes on one machine.
  Use a distributed lock (and a backend that supports it) across machines — see the
  README.
- It is not reentrant *across instances*: a second :class:`FileLock` for the same path
  waits, as it should. Acquiring the same instance twice on one thread is allowed.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from types import TracebackType

try:  # pragma: no cover - platform switch
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

try:  # pragma: no cover - platform switch
    import msvcrt
except ImportError:  # pragma: no cover - POSIX
    msvcrt = None  # type: ignore[assignment]


class LockError(Exception):
    """Base class for lock problems."""


class LockTimeout(LockError):
    """Raised when a lock could not be acquired within ``timeout`` seconds."""


class BaseLock:
    """Minimal lock interface: context manager with ``acquire``/``release``."""

    def acquire(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def release(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def __enter__(self) -> BaseLock:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()


class NoLock(BaseLock):
    """Does nothing. The default: a single writer, no locking overhead."""

    def acquire(self) -> None:
        return None

    def release(self) -> None:
        return None


#: One in-process mutex per lock file, so threads of the same process queue up before
#: they reach the OS lock (flock is per open file description and would otherwise let
#: two threads of one process fight over the same file).
_PROCESS_MUTEXES: dict[str, threading.RLock] = {}
_PROCESS_MUTEXES_GUARD = threading.Lock()


def _mutex_for(path: str) -> threading.RLock:
    with _PROCESS_MUTEXES_GUARD:
        return _PROCESS_MUTEXES.setdefault(path, threading.RLock())


class FileLock(BaseLock):
    """An advisory cross-process lock backed by a lock file.

    On POSIX it uses ``fcntl.flock``, on Windows ``msvcrt.locking``; both are blocking
    and released automatically when the process dies, so a crash cannot leave the log
    permanently locked. The lock file is created if missing and never deleted — deleting
    it would let two processes lock different inodes with the same name.

    ``timeout`` (seconds) turns a long wait into a :class:`LockTimeout`; by default the
    call blocks until the lock is free.
    """

    def __init__(
        self, path: str | Path, *, timeout: float | None = None, poll_interval: float = 0.05
    ) -> None:
        self.path = Path(path)
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._fd: int | None = None
        self._depth = 0
        self._owner: int | None = None
        self._mutex = _mutex_for(str(self.path.absolute()))

    # ------------------------------------------------------------------ internals

    def _try_os_lock(self) -> bool:
        assert self._fd is not None
        if fcntl is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except OSError:
                return False
        if msvcrt is not None:  # pragma: no cover - Windows
            try:
                os.lseek(self._fd, 0, os.SEEK_SET)
                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
                return True
            except OSError:
                return False
        raise LockError(
            "no cross-process locking primitive available on this platform; "
            "pass a lock implementation of your own"
        )

    def _unlock_os(self) -> None:
        assert self._fd is not None
        if fcntl is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        elif msvcrt is not None:  # pragma: no cover - Windows
            os.lseek(self._fd, 0, os.SEEK_SET)
            msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)

    # --------------------------------------------------------------------- public

    def acquire(self) -> None:
        """Take the lock, waiting up to ``timeout`` seconds (forever by default)."""
        if self._depth and self._owner == threading.get_ident():
            self._depth += 1  # same instance, same thread: no need to fight ourselves
            return
        self._mutex.acquire()
        try:
            self._fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            deadline = None if self.timeout is None else time.monotonic() + self.timeout
            while not self._try_os_lock():
                if deadline is not None and time.monotonic() >= deadline:
                    raise LockTimeout(
                        f"could not lock {self.path} within {self.timeout}s: "
                        "another writer is holding it"
                    )
                time.sleep(self.poll_interval)
            self._depth = 1
            self._owner = threading.get_ident()
            self._write_owner()
        except BaseException:
            self._close_fd()
            self._mutex.release()
            raise

    def _write_owner(self) -> None:
        """Best-effort note of who holds the lock, for humans debugging a stuck log."""
        if self._fd is None:  # pragma: no cover - defensive
            return
        try:
            os.ftruncate(self._fd, 0)
            os.write(self._fd, f"{os.getpid()} {time.time():.0f}\n".encode())
        except OSError:  # pragma: no cover - not worth failing a write over
            pass

    def release(self) -> None:
        if self._depth == 0:
            return
        self._depth -= 1
        if self._depth:
            return
        try:
            if self._fd is not None:
                self._unlock_os()
        finally:
            self._close_fd()
            self._owner = None
            self._mutex.release()

    def _close_fd(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    @property
    def held(self) -> bool:
        return self._depth > 0
