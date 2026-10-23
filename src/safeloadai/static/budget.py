"""A bound on the host memory one scan's static analysis may hold.

The pickle machine keeps an inert stand-in for every value a pickle builds: the
strings and bytes themselves, and a small object for everything else. A file can ask
for far more than its own size this way (one value fetched many times is held once,
but every pushed value is), so each scan gets a budget, charged per opcode and per byte
of string and bytes data, shared by every machine the scan starts (nested pickles, other
readings). Running out is a tool error (errors.py E105), never a crash of the process
and never a verdict about the file.
"""
from __future__ import annotations

import contextlib
import contextvars

# Bytes of string and bytes data plus OPCODE_COST per opcode, per scan: BASE_BYTES plus
# twice the file's size (a pickle holds its data once; a second reading of the same
# bytes, such as joblib's parser differential, may hold it again), never more than
# MAX_HOST_BYTES.
BASE_BYTES = 512 << 20
MAX_HOST_BYTES = 4 << 30
OPCODE_COST = 64


def limit_for(size: int) -> int:
    return min(MAX_HOST_BYTES, BASE_BYTES + 2 * size)


class ResourceLimit(Exception):
    """The scan needs more host memory than MAX_HOST_BYTES allows."""


class Budget:
    __slots__ = ("left", "limit")

    def __init__(self, limit: int):
        self.left = self.limit = limit

    def charge(self, amount: int) -> None:
        self.left -= amount
        if self.left < 0:
            raise ResourceLimit(f"the pickle data needs more than {self.limit >> 20} MiB of host memory")


_ACTIVE: contextvars.ContextVar[Budget | None] = contextvars.ContextVar("safeloadai_budget", default=None)


def current() -> Budget:
    """The scan's budget, or a fresh one for a walk outside a scan (tests, tools)."""
    return _ACTIVE.get() or Budget(MAX_HOST_BYTES)


@contextlib.contextmanager
def scope(limit: int | None = None):
    token = _ACTIVE.set(Budget(MAX_HOST_BYTES if limit is None else limit))
    try:
        yield
    finally:
        _ACTIVE.reset(token)
