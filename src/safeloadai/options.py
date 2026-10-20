"""Scan options: their safe defaults, how they are recorded, and the config file.

Plain ``scan(path)`` / ``safeloadai scan FILE`` uses every default below, and every
default is the strictest behaviour. An option that can make a verdict less strict
(``direction == "looser"``) names exact items only, is never turned on by an
environment variable, and is recorded in every Report under ``options`` with its value
and where it came from. ``docs/OPTIONS.md`` documents each option.

The config file (``safeloadai.toml``) is read only when it is named explicitly
(``safeloadai scan --config FILE``); a file that merely sits in the working directory
is never used, and the CLI prints which file set which option.
"""
from __future__ import annotations

import dataclasses
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .sandbox.host import Limits

CONFIG_NAME = "safeloadai.toml"

# Where a non-default value came from, as recorded in Report.options[*].source.
ARGUMENT = "argument"  # Python API keyword argument
CLI = "CLI flag"  # e.g. "CLI flag --allow"
CONFIG = "config file"  # e.g. "config file ./safeloadai.toml"
ENV = "environment variable"
PROMPT = "interactive prompt"


@dataclass(frozen=True)
class Option:
    name: str
    default: object
    direction: str  # "looser" (can make a verdict less strict), "stricter", "neutral"
    risk: str  # "high", "medium", "low", "none"
    summary: str
    api: str | None  # keyword argument of scan()/safe_load(), if any
    cli: str | None  # CLI flag, if any
    config: bool = False  # may be set in the config file
    env: str | None = None  # environment variable (never for "looser" options)


OPTIONS: tuple[Option, ...] = (
    Option("allow", (), "looser", "high",
           "extra exact (module, qualname) pickle globals to treat as allowlisted",
           "allow", "--allow MODULE:QUALNAME", config=True),
    Option("accept_unverified", None, "looser", "medium",
           "accept named UNVERIFIABLE items for one file (sha256-bound); refused on any RISKY or MALICIOUS reason",
           "accept_unverified", "--accept-unverified [SHA256:]ITEM", config=True),
    Option("trust_inert_from", (), "looser", "medium",
           "treat classes of the named installed distributions as state-only when their installed source says so "
           "(read with ast, never imported)",
           "trust_inert_from", "--trust-inert-from DISTRIBUTION", config=True),
    Option("known_good", True, "stricter", "low",
           "use the shipped list of reviewed benign files (exact sha256); turning it off only makes verdicts stricter",
           "known_good", "--no-known-good", config=True),
    Option("deep", False, "stricter", "high",
           "also run the file's own code in a Docker/bwrap/nsjail sandbox (can only raise the verdict)",
           "deep", "--deep", config=True),
    Option("judge", False, "stricter", "medium",
           "send the scan evidence to an LLM judge (can only raise the verdict; data leaves the machine)",
           "judge", "--judge", config=True),
    Option("limits", None, "neutral", "low",
           "resource limits of the WASI emulation (lower limits only make more files SUSPICIOUS)",
           "limits", None),
    Option("deep_backend", None, "neutral", "low",
           "which deep sandbox to use when --deep is on (docker, bwrap, nsjail)",
           None, None, env="SAFELOADAI_DEEP_BACKEND"),
    Option("judge_model", None, "neutral", "low",
           "which Claude model the judge asks when --judge is on",
           None, None, env="SAFELOADAI_JUDGE_MODEL"),
    Option("runtime_path", None, "neutral", "none",
           "another copy of the pinned WASI runtime; it must still match the pinned sha256",
           None, None, env="SAFELOADAI_WASI_PYTHON"),
    Option("prompt", True, "stricter", "low",
           "on a terminal, ask before accepting UNVERIFIABLE items (default answer No); --no-input never asks",
           None, "--no-input"),
)
BY_NAME = {o.name: o for o in OPTIONS}
LOOSER = frozenset(o.name for o in OPTIONS if o.direction == "looser")


class OptionError(ValueError):
    """An option value that is not explicit and narrow, or a config file that is not valid."""


def _value(name: str, value):
    if name == "limits":
        return dataclasses.asdict(value) if value is not None else None
    if name == "allow":
        return [f"{m}:{n}" for m, n in value]
    if name == "trust_inert_from":
        return list(value)
    return value


def is_default(name: str, value) -> bool:
    default = BY_NAME[name].default
    if name == "limits":
        return value is None or value == Limits()
    if name in ("allow", "trust_inert_from"):
        return not tuple(value or ())
    return value == default or (default is None and not value)


def record(name: str, value, source: str) -> dict:
    return {"name": name, "value": _value(name, value), "source": source,
            "direction": BY_NAME[name].direction}


def scan_options(*, allow, judge: bool, deep: bool, limits, sources: Mapping[str, str] | None,
                 trust_inert_from=(), known_good: bool = True) -> list[dict]:
    """Report.options entries for the non-default scan() arguments, plus environment
    settings that change how an enabled option runs."""
    sources = sources or {}
    out = []
    for name, value in (("allow", allow), ("trust_inert_from", trust_inert_from), ("known_good", known_good),
                        ("deep", deep), ("judge", judge), ("limits", limits)):
        if not is_default(name, value):
            out.append(record(name, value, sources.get(name, ARGUMENT)))
    for option in OPTIONS:
        if option.env and os.environ.get(option.env):
            if (option.name == "deep_backend" and not deep) or (option.name == "judge_model" and not judge):
                continue
            out.append(record(option.name, os.environ[option.env], f"{ENV} {option.env}"))
    return out


def validate_allow(allow: Iterable[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    """Exact, non-sink pairs only: a user allowlist can never turn a sink, a known gadget
    or getattr into an allowed global (MALICIOUS stays MALICIOUS)."""
    from .static.allowlists import GETATTR, KNOWN_GADGETS
    from .static.pickle_static import is_dangerous_import

    pairs = []
    for item in allow:
        try:
            module, name = item
        except (TypeError, ValueError):
            raise OptionError(f"allow entries are (module, qualname) pairs, got {item!r}") from None
        module, name = str(module), str(name)
        if not module or not name or any(c in module + name for c in "*? \t\n:"):
            raise OptionError(f"allow entry {module}:{name} is not an exact module and qualname")
        if (module, name) in GETATTR or (module, name) in KNOWN_GADGETS or is_dangerous_import(module, name):
            raise OptionError(f"allow entry {module}:{name} is a known sink or gadget; it can never be allowed")
        pairs.append((module, name))
    return tuple(pairs)


def validate_trust_inert_from(names: Iterable[str]) -> tuple[str, ...]:
    """Exact names of installed distributions (importlib.metadata finds them without
    importing anything); no patterns, nothing that is not installed."""
    from importlib import metadata

    out = []
    for name in names:
        name = str(name).strip()
        if not name or any(c in name for c in "*?/\\ \t\n:"):
            raise OptionError(f"trust_inert_from entry {name!r} is not an exact distribution name")
        try:
            metadata.distribution(name)
        except metadata.PackageNotFoundError:
            raise OptionError(f"trust_inert_from: distribution {name!r} is not installed") from None
        if name not in out:
            out.append(name)
    return tuple(out)


# --- config file -----------------------------------------------------------------------

CONFIG_KEYS = {"allow": list, "accept_unverified": list, "deep": bool, "judge": bool, "trust_inert_from": list,
               "known_good": bool}


def load_config(path: str | os.PathLike) -> dict:
    """The [scan] table of a safeloadai.toml. Unknown keys are an error, so a typo never
    silently does nothing."""
    import tomllib

    with open(path, "rb") as fh:
        try:
            data = tomllib.load(fh)
        except tomllib.TOMLDecodeError as exc:
            raise OptionError(f"{path}: {exc}") from exc
    unknown_tables = set(data) - {"scan"}
    if unknown_tables:
        raise OptionError(f"{path}: unknown table(s) {sorted(unknown_tables)}; only [scan] is read")
    table = data.get("scan", {})
    out = {}
    for key, value in table.items():
        kind = CONFIG_KEYS.get(key)
        if kind is None:
            raise OptionError(f"{path}: unknown key scan.{key}; known keys: {sorted(CONFIG_KEYS)}")
        if not isinstance(value, kind) or (kind is list and not all(isinstance(v, str) for v in value)):
            raise OptionError(f"{path}: scan.{key} must be a {'list of strings' if kind is list else 'boolean'}")
        out[key] = value
    return out


def find_config(directory: str | os.PathLike = ".") -> str | None:
    """A safeloadai.toml in ``directory`` (reported by ``safeloadai options``, never used
    unless named with --config)."""
    path = os.path.join(os.fspath(directory), CONFIG_NAME)
    return path if os.path.isfile(path) else None


# --- text for the CLI ------------------------------------------------------------------

def warning(entry: dict) -> str:
    option = BY_NAME[entry["name"]]
    effect = {"looser": "can make verdicts less strict", "stricter": "can only make verdicts stricter",
              "neutral": "does not change what counts as safe"}[option.direction]
    return (f"safeloadai: warning: non-default option {entry['name']}={entry['value']!r} "
            f"(from {entry['source']}; {effect}; see docs/OPTIONS.md)")


def summary_table() -> str:
    rows = [("option", "default", "stricter or looser", "risk")]
    rows += [(o.name, repr(o.default), o.direction, o.risk) for o in OPTIONS]
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    lines = ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip() for row in rows]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)
