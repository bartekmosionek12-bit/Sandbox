"""Failures of safeloadai itself, kept apart from verdicts about the file.

A verdict (CLEAN, UNSUPPORTED, SUSPICIOUS, MALICIOUS) is a statement about the
bytes. An error is a statement about the tool: it could not finish the analysis
(the file could not be read, a parser raised an exception it does not expect, the
sandbox crashed or ran out of time, the runtime failed its integrity check, the
options were invalid). A report with an error has ``status == "error"`` and no
verdict; it is never CLEAN and never loadable by ``safe_load``.

The one exception: MALICIOUS evidence found before the failure still decides. The
report then has ``status == "ok"``, the MALICIOUS verdict, and the failure listed
under ``errors``.

Codes are stable and documented in docs/ERRORS.md. Add new codes; never reuse one.
"""
from __future__ import annotations

from dataclasses import dataclass

# code -> (layer, short title). The layer is where the failure happened.
CODES: dict[str, tuple[str, str]] = {
    # E1xx: reading the file
    "E101": ("io", "file not found"),
    "E102": ("io", "file could not be read"),
    "E103": ("io", "file too large to read"),
    "E104": ("io", "path is not a regular file"),
    # E2xx: a parser or walker raised an exception it does not expect (a bug in safeloadai)
    "E200": ("static", "internal error in the static analysis"),
    "E201": ("static", "internal error in the pickle walker"),
    "E202": ("static", "internal error in the Keras reader"),
    "E203": ("static", "internal error in the HDF5 metadata reader"),
    "E204": ("static", "internal error in the PyTorch archive reader"),
    "E205": ("static", "internal error in the joblib reader"),
    # E3xx: the sandboxes
    "E300": ("emulation", "internal error in the emulation layer"),
    "E301": ("emulation", "WASI sandbox unavailable"),
    "E302": ("emulation", "WASI sandbox crashed"),
    "E303": ("emulation", "WASI sandbox timed out"),
    "E304": ("emulation", "WASI sandbox ran out of its compute budget"),
    "E310": ("deep", "deep sandbox did not run"),
    "E311": ("deep", "deep sandbox timed out"),
    # E4xx: runtime integrity
    "E401": ("runtime", "WASI runtime failed its integrity check"),
    # E5xx: options and usage
    "E501": ("options", "invalid scan option"),
}


@dataclass(frozen=True)
class ToolError:
    code: str
    message: str
    layer: str

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "layer": self.layer}


def error(code: str, message: str, layer: str | None = None) -> dict:
    """A tool error as the report stores it: ``{"code", "message", "layer"}``."""
    default_layer, title = CODES[code]
    return ToolError(code, f"{title}: {message}" if message else title, layer or default_layer).to_dict()


def internal(code: str, exc: BaseException, layer: str | None = None) -> dict:
    """An exception safeloadai did not expect, as a tool error."""
    return error(code, f"{type(exc).__name__}: {str(exc)[:300]}", layer)


# How a WASI guest run ended (sandbox.host.GuestRun.status) -> tool error code. "ok" is
# no tool error; whether the guest finished its work is judged from the evidence.
GUEST_STATUS_CODES = {"unavailable": "E301", "runner_error": "E302", "trap": "E302", "exit": "E302",
                      "timeout": "E303", "fuel_exhausted": "E304"}


def guest_error(status: str, problems: list[str], layer: str = "emulation") -> dict | None:
    """The tool error for a guest run that ended with ``status``, or None."""
    code = GUEST_STATUS_CODES.get(status)
    if code is None:
        return None
    return error(code, "; ".join(str(p) for p in problems[:5]) or f"status {status}", layer)


__all__ = ["CODES", "GUEST_STATUS_CODES", "ToolError", "error", "guest_error", "internal"]
