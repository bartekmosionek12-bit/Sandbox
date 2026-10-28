"""One scan: container parsing and static analysis, fake-API emulation in the WASI
sandbox, then the optional deep detonation and the optional LLM judge.

The final verdict is the worst layer verdict (report.combine). CLEAN therefore
needs a clean static layer AND a completed emulation without any recorded
anomaly or dangerous call, and nothing found by the optional layers.
"""
from __future__ import annotations

import dataclasses
import hashlib
import os
import time
from collections.abc import Callable, Iterable, Mapping

from . import behaviour, errors, verdict
from . import known_good as known_good_mod
from . import options as options_mod
from . import static as static_mod
from .parsing import detect as detect_mod
from .parsing.zipsafe import SafeZip, ZipRefused
from .report import LayerResult, Report, Verdict, settle
from .sandbox import Limits, RuntimeIntegrityError, emulate_keras_lambdas, emulate_pickle
from .sandbox.host import scaled_limits
from .static import clearance as clearance_mod
from .static import data_formats
from .static.torch_static import MAX_PICKLE_MEMBER_BYTES

Progress = Callable[[str], None] | None


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


def _is_legacy_torch(parser_report: dict) -> bool:
    return any("legacy PyTorch" in str(n) for n in parser_report.get("notes") or [])


def cleared_pairs(parser_report: dict) -> tuple[frozenset, frozenset]:
    """(pairs the static layer accepted as state-only or by another rule, pairs it found
    only referenced) for one reading (static/clearance.py)."""
    allowed, referenced = set(), set()
    for entry in parser_report.get("cleared") or []:
        pair = tuple(entry["pair"])
        (referenced if entry["mechanism"] == "referenced" else allowed).add(pair)
    return frozenset(allowed), frozenset(referenced - allowed)


def _pickle_limits(limits: Limits | None, size: int, parser_report: dict) -> Limits:
    """The limits the user chose, or by default limits that grow with the pickle data and its
    opcode count up to fixed ceilings (sandbox.host.scaled_limits)."""
    if limits is not None:
        return limits
    return scaled_limits(size, sum((parser_report.get("opcode_counts") or {}).values()))


def emulation_layer(data: bytes, parser_report: dict, extra_allowed: frozenset,
                    limits: Limits | None = None) -> LayerResult:
    fmt = parser_report.get("file_format")
    cleared, referenced = cleared_pairs(parser_report)
    extra_allowed = frozenset(extra_allowed) | cleared
    if fmt == detect_mod.JOBLIB:
        stream = parser_report.get("_stream", data if not parser_report.get("compression") else None)
        if stream is None:
            layer = LayerResult(name="emulation", verdict=Verdict.CLEAN, ran=False)
            layer.raise_to(Verdict.SUSPICIOUS, "compressed joblib file could not be decompressed; nothing emulated")
            return layer
        run = emulate_pickle([stream], max_pickles=parser_report.get("pickle_count") or 1, joblib=True,
                             limits=_pickle_limits(limits, len(stream), parser_report))
        return behaviour.classify(run, extra_allowed=extra_allowed, framework=False, referenced=referenced)
    if fmt == detect_mod.PICKLE:
        torch = _is_legacy_torch(parser_report)
        run = emulate_pickle([data], max_pickles=parser_report.get("pickle_count") or 1,
                             limits=_pickle_limits(limits, len(data), parser_report))
        return behaviour.classify(run, torch=torch, extra_allowed=extra_allowed, framework=False,
                                  referenced=referenced)
    if fmt == detect_mod.TORCH:
        try:
            with SafeZip(data, max_member_bytes=MAX_PICKLE_MEMBER_BYTES) as zf:
                streams = [zf.read(n, ignore_crc=True) for n in zf.names if n.endswith(".pkl")]
        except ZipRefused as exc:
            layer = LayerResult(name="emulation", verdict=Verdict.CLEAN, ran=False)
            layer.raise_to(Verdict.SUSPICIOUS, f"archive refused, nothing emulated: {exc}")
            return layer
        if not streams:
            layer = LayerResult(name="emulation", verdict=Verdict.CLEAN, ran=False)
            layer.raise_to(Verdict.SUSPICIOUS, "torch archive without a pickle member")
            return layer
        run = emulate_pickle(streams, max_pickles=1,
                             limits=_pickle_limits(limits, sum(map(len, streams)), parser_report))
        return behaviour.classify(run, torch=True, extra_allowed=extra_allowed, framework=False,
                                  referenced=referenced)
    if fmt in (detect_mod.KERAS, detect_mod.H5):
        if parser_report.get("error") and fmt == detect_mod.H5:
            layer = LayerResult(name="emulation", verdict=Verdict.CLEAN, ran=False)
            layer.raise_to(Verdict.SUSPICIOUS, "HDF5 metadata could not be read; nothing emulated")
            return layer
        lambdas = parser_report.get("lambdas") or []
        if not lambdas:
            return LayerResult(name="emulation", verdict=Verdict.CLEAN, ran=False,
                               reasons=["no executable content in the Keras config; nothing to emulate"])
        return behaviour.classify(emulate_keras_lambdas(lambdas, limits=limits))
    layer = LayerResult(name="emulation", verdict=Verdict.CLEAN, ran=False)
    if fmt in detect_mod.DATA_ONLY or fmt in detect_mod.NO_CODE:
        layer.reasons.append("nothing to emulate: the format runs no code on load")
        return layer
    if parser_report.get("unsupported"):
        layer.reasons.append("nothing to emulate: the file is in no supported format (UNSUPPORTED)")
        return layer
    layer.raise_to(Verdict.SUSPICIOUS, f"no emulator for format {fmt!r}")
    return layer


MAX_EMBEDDED = 16
MAX_EMBEDDED_DEPTH = 4


def _reading_layers(label: str, data: bytes, report: dict, extra_allowed: frozenset,
                    limits: Limits | None) -> list[LayerResult]:
    static = verdict.static_layer(report, defer_lambdas=True)
    emulation = _guarded("emulation", "E300", emulation_layer, data, report, extra_allowed, limits)
    static.name, emulation.name = f"static[{label}]", f"emulation[{label}]"
    out = [static, emulation] + _code_layers(label, report, limits)
    for layer in out:
        for finding in layer.findings:
            finding["layer"] = layer.name
    return out


def _code_layers(label: str, report: dict, limits: Limits | None) -> list[LayerResult]:
    """Functions a dill pickle carries with their bytecode, rebuilt inside the WASI sandbox
    and called on fakes like Keras Lambdas (owner's decision of 2026-10-19)."""
    entries = report.get("dill_code") or []
    if not entries:
        return []
    layer = _guarded("emulation", "E300", lambda: behaviour.classify(emulate_keras_lambdas(entries, limits=limits)))
    layer.name = f"emulation[{label + '/' if label else ''}dill code]"
    for finding in layer.findings:
        finding["layer"] = layer.name
    return [layer]


def _embedded(parser_report: dict, extra_views: list, extra_allowed: frozenset):
    """(label, bytes, static report) for every embedded model, its own readings and the
    models embedded in those, breadth first, at most MAX_EMBEDDED in all. A Keras loader
    reads the bytes, so anything that is not a Keras archive is RISKY."""
    todo = [(item, "", 0) for rep in [parser_report] + [r for _v, r in extra_views]
            for item in rep.get("_embedded") or []]
    count = 0
    while todo:
        item, parent, depth = todo.pop(0)
        label = f"{parent}{item['label']}"
        if count >= MAX_EMBEDDED or depth >= MAX_EMBEDDED_DEPTH:
            layer = LayerResult(name=f"static[{label}]", verdict=Verdict.CLEAN, ran=False)
            layer.raise_to(Verdict.SUSPICIOUS, f"more than {MAX_EMBEDDED} embedded models or nesting deeper "
                                               f"than {MAX_EMBEDDED_DEPTH}; {label} is not analysed")
            parser_report.setdefault("_embedded_skipped", []).append(layer)
            continue
        count += 1
        blob = item["data"]
        report = static_mod.analyze_bytes(blob, f"{label}.keras", extra_allowed)
        if report.get("file_format") != detect_mod.KERAS:
            report["reasons"].append(f"the embedded bytes the Keras loader reads are not a Keras archive "
                                     f"(detected {report.get('file_format')})")
            if report["static_risk"] in ("clean", "unsupported"):
                report["static_risk"] = "suspicious"
        view = report.get("_view")
        yield label, view.slice(blob) if view else blob, report
        for other, rep in report.get("_extra_views") or []:
            yield f"{label}/{other.label}", other.slice(blob), rep
        for rep in [report] + [r for _v, r in report.get("_extra_views") or []]:
            todo += [(sub, f"{label}/", depth + 1) for sub in rep.get("_embedded") or []]


def _deep_layer(path: str, file_format: str) -> LayerResult:
    from . import deep

    return verdict.docker_layer(deep.run_deep(path, file_format))


def _judge_layer(parser_report: dict, emulation: LayerResult) -> LayerResult | None:
    from . import judge as judge_mod

    summary = {"detonated": emulation.ran, "load_succeeded": emulation.details.get("completed"),
               "events": emulation.evidence}
    return verdict.judge_layer(judge_mod.judge(parser_report, summary))


def scan(path: str | os.PathLike, *, judge: bool = False, deep: bool = False,
         allow: Iterable[tuple[str, str]] = (), limits: Limits | None = None,
         progress: Progress = None, option_sources: Mapping[str, str] | None = None,
         trust_inert_from: Iterable[str] = (), known_good: bool = True,
         validate_boosters: bool = False) -> Report:
    """Scan one model file. Never deserialises it on the host.

    Every keyword defaults to the strictest behaviour (docs/OPTIONS.md). Non-default
    options are recorded in ``Report.options`` with their source (``option_sources``
    maps an option name to where it came from; the default is "argument")."""

    def step(message: str) -> None:
        if progress:
            progress(message)

    path = os.fspath(path)
    try:
        allow = options_mod.validate_allow(allow)
        trust_inert_from = options_mod.validate_trust_inert_from(trust_inert_from)
        if not isinstance(validate_boosters, bool):
            raise options_mod.OptionError(f"validate_boosters must be True or False, got {validate_boosters!r}")
        used_options = options_mod.scan_options(allow=allow, judge=judge, deep=deep, limits=limits,
                                                sources=option_sources, trust_inert_from=trust_inert_from,
                                                known_good=known_good, validate_boosters=validate_boosters)
        trust = clearance_mod.for_distributions(trust_inert_from)
        if validate_boosters:
            trust = dataclasses.replace(trust, validate_boosters=True, _cache={})
    except options_mod.OptionError as exc:
        return error_report(path, errors.error("E501", str(exc)))
    extra_allowed = frozenset(allow)
    try:
        with clearance_mod.active(trust):
            report = _scan(path, judge=judge, deep=deep, extra_allowed=extra_allowed, limits=limits, step=step)
    except RuntimeIntegrityError as exc:
        # The runtime is not the pinned one: no result of this scan is trusted, not even
        # MALICIOUS evidence from the sandbox.
        return error_report(path, errors.error("E401", str(exc)), options=used_options)
    except _ReadFailed as failed:
        return error_report(path, failed.error, options=used_options)
    if known_good:
        known_good_mod.apply(report)
    report.options = used_options
    return report


class _ReadFailed(Exception):
    def __init__(self, error: dict):
        super().__init__(error["message"])
        self.error = error


def _read(path: str) -> tuple[int, bytes]:
    """(size, bytes) of the file, or _ReadFailed with an E1xx tool error."""
    try:
        if not os.path.exists(path):
            raise _ReadFailed(errors.error("E101", path))
        if not os.path.isfile(path):
            raise _ReadFailed(errors.error("E104", path))
        size = os.path.getsize(path)
        if size > static_mod.MAX_FILE_BYTES:
            raise _ReadFailed(errors.error("E103", f"{size} bytes, the limit is {static_mod.MAX_FILE_BYTES}"))
        with open(path, "rb") as fh:
            data = fh.read(static_mod.MAX_FILE_BYTES + 1)
    except OSError as exc:
        code = "E101" if isinstance(exc, FileNotFoundError) else "E102"
        raise _ReadFailed(errors.error(code, f"{type(exc).__name__}: {exc}")) from exc
    if len(data) > static_mod.MAX_FILE_BYTES:
        raise _ReadFailed(errors.error("E103", f"the file grew past {static_mod.MAX_FILE_BYTES} bytes while read"))
    return len(data), data


def error_report(path: str, error: dict, *, options: list[dict] | None = None) -> Report:
    """The report of a scan that failed before any layer could run: status "error", no verdict."""
    from . import __version__

    return Report(path=path, file_name=os.path.basename(path), sha256="", size=-1, file_format="unknown",
                  verdict=None, reasons=[], layers=[], timings_ms={}, version=__version__,
                  options=list(options or []), status="error", error=error, errors=[error])


def _scan(path: str, *, judge: bool, deep: bool, extra_allowed: frozenset, limits: Limits | None,
          step: Callable[[str], None]) -> Report:
    from . import __version__

    started = time.perf_counter()
    timings: dict[str, float] = {}

    size, data = _read(path)
    sha256 = hashlib.sha256(data).hexdigest()

    step("static analysis")
    t = time.perf_counter()
    try:
        with static_mod.companions(static_mod.read_companions(path)):
            parser_report = static_mod.analyze_bytes(data, os.path.basename(path), extra_allowed)
    except RuntimeIntegrityError:
        raise
    except Exception as exc:  # noqa: BLE001 - a bug in safeloadai fails closed as a tool error
        parser_report = static_mod.parse_pickle(b"", os.path.basename(path), file_format="unknown")
        parser_report["tool_errors"].append(errors.internal("E200", exc))
        parser_report["static_risk"] = "suspicious"
    file_format = str(parser_report.get("file_format"))
    layers = [verdict.static_layer(parser_report, defer_lambdas=True)]
    layers[0].timings_ms["total"] = timings["static"] = _ms(t)
    extra_views = parser_report.get("_extra_views") or []

    step("emulation in the WASI sandbox")
    t = time.perf_counter()
    view = parser_report.get("_view")
    emulation = _guarded("emulation", "E300", emulation_layer, view.slice(data) if view else data, parser_report,
                         extra_allowed, limits)
    timings["emulation"] = _ms(t)
    layers.append(emulation)
    layers += _code_layers("", parser_report, limits)

    # Every other reading of a polyglot file gets its own static and emulation layers.
    for view, report in extra_views:
        step(f"other reading: {view.fmt} at offset {view.start}")
        layers += _reading_layers(view.label, view.slice(data), report, extra_allowed, limits)
    # A model a pickle carries as bytes for a loader it calls (Keras 3 pickles a model as an
    # embedded .keras archive) is analysed as a file of its own.
    for label, part, report in _embedded(parser_report, extra_views, extra_allowed):
        step(f"embedded model: {label}")
        layers += _reading_layers(label, part, report, extra_allowed, limits)

    layers += parser_report.pop("_embedded_skipped", [])

    if deep:
        step("deep detonation")
        t = time.perf_counter()
        layers.append(_guarded("deep", "E310", _deep_layer, path, file_format))
        timings["deep"] = _ms(t)

    if judge:
        step("LLM judge")
        t = time.perf_counter()
        judged = _judge_layer(parser_report, emulation)
        if judged is not None:
            layers.append(judged)
        timings["judge"] = _ms(t)

    status, final, reasons, findings, category, tool_errors = settle(layers)
    if final is Verdict.CLEAN and parser_report.get("data_only") and not extra_views:
        reasons = [parser_report.get("clean_reason") or data_formats.DATA_ONLY_REASON]
    timings["total"] = _ms(started)
    return Report(path=path, file_name=os.path.basename(path), sha256=sha256, size=size,
                  file_format=file_format, verdict=final, reasons=reasons, layers=layers,
                  timings_ms=timings, version=__version__, findings=findings, category=category,
                  cleared=_cleared(layers), status=status, error=tool_errors[0] if status == "error" else None,
                  errors=tool_errors)


def _guarded(name: str, code: str, build: Callable[..., LayerResult], *args) -> LayerResult:
    """``build(*args)``; an exception it does not expect becomes a tool error in a layer of its
    own (never a verdict). A runtime integrity failure still ends the scan."""
    try:
        return build(*args)
    except RuntimeIntegrityError:
        raise
    except Exception as exc:  # noqa: BLE001 - a bug in safeloadai fails closed as a tool error
        layer = LayerResult(name=name, verdict=Verdict.CLEAN, ran=False)
        layer.errors.append(errors.internal(code, exc, name))
        return layer


def _cleared(layers: list[LayerResult]) -> list[dict]:
    """Imports outside the allowlist that a rule accepted (static/clearance.py), once each."""
    seen, out = set(), []
    for layer in layers:
        for entry in (layer.details or {}).get("cleared") or []:
            key = (entry["item"], entry["mechanism"])
            if key not in seen:
                seen.add(key)
                out.append({"item": entry["item"], "pair": entry["pair"], "mechanism": entry["mechanism"],
                            "detail": entry["detail"], "layer": layer.name})
    return out
