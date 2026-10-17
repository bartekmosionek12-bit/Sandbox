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
from .report import LayerResult, Report, Verdict, combine
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
    if fmt == detect_mod.PICKLE:
        torch = _is_legacy_torch(parser_report)
        run = emulate_pickle([data], max_pickles=parser_report.get("pickle_count") or 1, limits=limits)
        return behaviour.classify(run, torch=torch, extra_allowed=extra_allowed)
    if fmt == detect_mod.TORCH:
        try:
            with SafeZip(data, max_member_bytes=MAX_PICKLE_MEMBER_BYTES) as zf:
                streams = [zf.read(n) for n in zf.names if n.endswith(".pkl")]
        except ZipRefused as exc:
            layer = LayerResult(name="emulation", verdict=Verdict.CLEAN, ran=False)
            layer.raise_to(Verdict.SUSPICIOUS, f"archive refused, nothing emulated: {exc}")
            return layer
        if not streams:
            layer = LayerResult(name="emulation", verdict=Verdict.CLEAN, ran=False)
            layer.raise_to(Verdict.SUSPICIOUS, "torch archive without a pickle member")
            return layer
        run = emulate_pickle(streams, max_pickles=1, limits=limits)
        return behaviour.classify(run, torch=True, extra_allowed=extra_allowed)
    if fmt == detect_mod.KERAS:
        lambdas = parser_report.get("lambdas") or []
        if not lambdas:
            return LayerResult(name="emulation", verdict=Verdict.CLEAN, ran=False,
                               reasons=["no executable content in the Keras config; nothing to emulate"])
        return behaviour.classify(emulate_keras_lambdas(lambdas, limits=limits))
    layer = LayerResult(name="emulation", verdict=Verdict.CLEAN, ran=False)
    layer.raise_to(Verdict.SUSPICIOUS, f"no emulator for format {fmt!r}")
    return layer


def _deep_layer(path: str, file_format: str) -> LayerResult:
    from . import docker_sandbox

    profile = {"pickle": "pickle", "keras": "keras"}.get(file_format)
    if profile is None:
        report = docker_sandbox._empty_report(os.path.basename(path), f"no deep backend for {file_format!r}")
    else:
        report = docker_sandbox.detonate_in_docker(path, profile=profile)
    return verdict.docker_layer(report)


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

    step("emulation in the WASI sandbox")
    t = time.perf_counter()
    if data:
        emulation = emulation_layer(data, parser_report, extra_allowed, limits)
    else:
        emulation = LayerResult(name="emulation", verdict=Verdict.CLEAN, ran=False)
        emulation.raise_to(Verdict.SUSPICIOUS, "file too large to emulate")
    timings["emulation"] = _ms(t)
    layers.append(emulation)

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
    timings["total"] = _ms(started)
    return Report(path=path, file_name=os.path.basename(path), sha256=sha256, size=size,
                  file_format=file_format, verdict=final, reasons=reasons, layers=layers,
                  timings_ms=timings, version=__version__)


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
