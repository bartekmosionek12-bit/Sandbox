"""One scan: container parsing and static analysis, fake-API emulation in the WASI
sandbox, then the optional deep detonation and the optional LLM judge.

The final verdict is the worst layer verdict (report.combine). CLEAN therefore
needs a clean static layer AND a completed emulation without any recorded
anomaly or dangerous call, and nothing found by the optional layers.
"""
from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable, Iterable

from . import behaviour, verdict
from . import static as static_mod
from .parsing import detect as detect_mod
from .parsing.zipsafe import SafeZip, ZipRefused
from .report import LayerResult, Report, Verdict, combine, combine_findings
from .sandbox import Limits, emulate_keras_lambdas, emulate_pickle
from .static.torch_static import MAX_PICKLE_MEMBER_BYTES

Progress = Callable[[str], None] | None


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


def _is_legacy_torch(parser_report: dict) -> bool:
    return any("legacy PyTorch" in str(n) for n in parser_report.get("notes") or [])


def emulation_layer(data: bytes, parser_report: dict, extra_allowed: frozenset,
                    limits: Limits | None = None) -> LayerResult:
    fmt = parser_report.get("file_format")
    if fmt == detect_mod.JOBLIB:
        stream = parser_report.get("_stream", data if not parser_report.get("compression") else None)
        if stream is None:
            layer = LayerResult(name="emulation", verdict=Verdict.CLEAN, ran=False)
            layer.raise_to(Verdict.SUSPICIOUS, "compressed joblib file could not be decompressed; nothing emulated")
            return layer
        run = emulate_pickle([stream], max_pickles=parser_report.get("pickle_count") or 1, joblib=True,
                             limits=limits)
        return behaviour.classify(run, extra_allowed=extra_allowed, framework=False)
    if fmt == detect_mod.PICKLE:
        torch = _is_legacy_torch(parser_report)
        run = emulate_pickle([data], max_pickles=parser_report.get("pickle_count") or 1, limits=limits)
        return behaviour.classify(run, torch=torch, extra_allowed=extra_allowed, framework=False)
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
        run = emulate_pickle(streams, max_pickles=1, limits=limits)
        return behaviour.classify(run, torch=True, extra_allowed=extra_allowed, framework=False)
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
    layer.raise_to(Verdict.SUSPICIOUS, f"no emulator for format {fmt!r}")
    return layer


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
         progress: Progress = None) -> Report:
    """Scan one model file. Never deserialises it on the host."""
    from . import __version__

    def step(message: str) -> None:
        if progress:
            progress(message)

    path = os.fspath(path)
    extra_allowed = frozenset((str(m), str(n)) for m, n in allow)
    started = time.perf_counter()
    timings: dict[str, float] = {}

    size = os.path.getsize(path)
    if size > static_mod.MAX_FILE_BYTES:
        parser_report = static_mod.analyze_file(path)
        data = b""
    else:
        with open(path, "rb") as fh:
            data = fh.read()
    sha256 = hashlib.sha256(data).hexdigest() if data else _sha256_file(path)

    step("static analysis")
    t = time.perf_counter()
    if data:
        parser_report = static_mod.analyze_bytes(data, os.path.basename(path), extra_allowed)
    file_format = str(parser_report.get("file_format"))
    layers = [verdict.static_layer(parser_report, defer_lambdas=True)]
    layers[0].timings_ms["total"] = timings["static"] = _ms(t)
    extra_views = parser_report.get("_extra_views") or []

    step("emulation in the WASI sandbox")
    t = time.perf_counter()
    if data:
        view = parser_report.get("_view")
        emulation = emulation_layer(view.slice(data) if view else data, parser_report, extra_allowed, limits)
    else:
        emulation = LayerResult(name="emulation", verdict=Verdict.CLEAN, ran=False)
        emulation.raise_to(Verdict.SUSPICIOUS, "file too large to emulate")
    timings["emulation"] = _ms(t)
    layers.append(emulation)

    # Every other reading of a polyglot file gets its own static and emulation layers.
    for view, report in extra_views:
        step(f"other reading: {view.fmt} at offset {view.start}")
        extra_static = verdict.static_layer(report, defer_lambdas=True)
        extra_emulation = emulation_layer(view.slice(data), report, extra_allowed, limits)
        extra_static.name, extra_emulation.name = f"static[{view.label}]", f"emulation[{view.label}]"
        for layer in (extra_static, extra_emulation):
            for finding in layer.findings:
                finding["layer"] = layer.name
        layers += [extra_static, extra_emulation]

    if deep:
        step("deep detonation")
        t = time.perf_counter()
        layers.append(_deep_layer(path, file_format))
        timings["deep"] = _ms(t)

    if judge:
        step("LLM judge")
        t = time.perf_counter()
        judged = _judge_layer(parser_report, emulation)
        if judged is not None:
            layers.append(judged)
        timings["judge"] = _ms(t)

    final, reasons = combine(layers)
    findings, category = combine_findings(layers)
    timings["total"] = _ms(started)
    return Report(path=path, file_name=os.path.basename(path), sha256=sha256, size=size,
                  file_format=file_format, verdict=final, reasons=reasons, layers=layers,
                  timings_ms=timings, version=__version__, findings=findings, category=category)


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
