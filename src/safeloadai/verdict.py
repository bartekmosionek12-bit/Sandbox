"""Layer verdicts from the layer reports, and the final verdict.

Each builder maps one layer's report to a LayerResult. ``final_verdict`` takes
the worst of them (see report.combine), so no layer can lower another.
"""
from __future__ import annotations

from .report import Category, LayerResult, Verdict, combine

M, S, C = Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.CLEAN

_STATIC = {"clean": C, "suspicious": S, "malicious": M}
_JUDGE = {"malicious": M, "suspicious": S}
# Docker detonation events that only code execution produces.
HARD_EVENT_TYPES = frozenset({"os_system", "subprocess", "network"})
STATIC_DETAIL_DROP = ("raw_disasm",)


def lambdas_only(parser_report: dict) -> bool:
    """True when the only static findings are Lambda layers with bytecode and no sink names.

    Owner rule: such a model is CLEAN only if emulation then completes without any
    anomaly or dangerous behaviour, so the static layer defers to emulation.
    """
    lambdas = parser_report.get("lambdas") or []
    if parser_report.get("file_format") not in ("keras", "h5") or not lambdas or parser_report.get("error"):
        return False
    if parser_report.get("suspicious_imports") or parser_report.get("unknown_imports"):
        return False
    if not all(lam.get("has_code") and not lam.get("sink_tokens") for lam in lambdas):
        return False
    if any(flag.get("name") != "Lambda" for flag in parser_report.get("flagged_opcodes") or []):
        return False
    prefixes = tuple(f"{lam['path']}: Lambda layer" for lam in lambdas)
    return all(str(r).startswith(prefixes) for r in parser_report.get("reasons") or [])


def static_layer(parser_report: dict, *, defer_lambdas: bool = False) -> LayerResult:
    risk = parser_report.get("static_risk")
    details = {k: v for k, v in parser_report.items() if k not in STATIC_DETAIL_DROP and not k.startswith("_")}
    layer = LayerResult(name="static", verdict=C, details=details)
    reasons = [str(r) for r in parser_report.get("reasons") or []]
    if risk == "suspicious" and defer_lambdas and lambdas_only(parser_report):
        layer.reasons.append("Lambda bytecode without sink names; deferred to emulation: "
                             + "; ".join(reasons))
        return layer
    verdict = _STATIC.get(str(risk), S)
    if verdict is C:
        return layer
    unverifiable = parser_report.get("unverifiable") or {}
    for reason in reasons or [f"static risk {risk!r}"]:
        meta = unverifiable.get(reason) if verdict is S else None
        if meta:
            layer.raise_to(verdict, reason, category=Category.UNVERIFIABLE, item=meta.get("item"),
                           explanation=meta.get("explanation"), pair=meta.get("pair"))
        else:
            layer.raise_to(verdict, reason)
    return layer


def docker_layer(sandbox_report: dict | None, *, requested: bool = True) -> LayerResult | None:
    """Deep-mode (Docker) detonation report -> layer. None when deep mode was not requested."""
    if not requested:
        return None
    report = sandbox_report or {}
    layer = LayerResult(name="deep", verdict=C, details={k: v for k, v in report.items() if k != "raw_log"})
    if report.get("tampered"):
        layer.raise_to(M, report.get("tamper_reason") or "detonation result forged from inside the sandbox")
    if not report.get("detonated"):
        layer.ran = False
        layer.raise_to(S, "deep detonation did not run: "
                       + str(report.get("skipped_reason") or report.get("error") or "unknown reason"))
    elif report.get("timed_out"):
        layer.raise_to(S, "deep detonation timed out")
    elif report.get("load_succeeded") is not True:
        layer.raise_to(S, f"load inside the deep sandbox failed: {report.get('error')}")
    for event in report.get("events") or []:
        kind = event.get("type")
        severity = M if kind in HARD_EVENT_TYPES else S
        layer.raise_to(severity, f"detonation event {kind}: {str(event.get('detail'))[:200]}")
        layer.evidence.append({"type": kind, "severity": severity.value})
    return layer


def judge_layer(judge_report: dict | None) -> LayerResult | None:
    """LLM judge -> layer. It can only add severity: 'safe' maps to CLEAN, which
    never lowers the max over layers."""
    if not judge_report:
        return None
    layer = LayerResult(name="judge", verdict=C, ran=bool(judge_report.get("available")),
                        details=dict(judge_report))
    if not judge_report.get("available"):
        layer.reasons.append(str(judge_report.get("error") or "judge unavailable"))
        return layer
    verdict = _JUDGE.get(str(judge_report.get("verdict")))
    if verdict:
        layer.raise_to(verdict, f"LLM judge: {str(judge_report.get('reasoning'))[:500]}")
    if judge_report.get("injection_attempt_detected"):
        layer.raise_to(S, "LLM judge saw text in the evidence trying to steer the verdict")
    return layer


def final_verdict(parser_report: dict, judge_report: dict | None = None,
                  sandbox_report: dict | None = None) -> tuple[Verdict, list[str]]:
    """Worst of the static, deep-detonation and judge layers."""
    layers = [static_layer(parser_report)]
    for extra in (docker_layer(sandbox_report, requested=sandbox_report is not None), judge_layer(judge_report)):
        if extra is not None:
            layers.append(extra)
    return combine(layers)
