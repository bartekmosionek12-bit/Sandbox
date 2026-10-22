"""Report data model and the monotone verdict combination.

The final verdict is the maximum over layer verdicts. No layer can lower what
another layer found: that is how "the judge can only raise severity" and
"detonation evidence always affects the verdict" are enforced in code.

Every reason also carries a category (``Category``): MALICIOUS evidence, RISKY
behaviour, or UNVERIFIABLE (the scanner cannot know what code a named object would
run). The category never changes the verdict; it only decides whether an informed,
per-file override is possible (``override.py``): only when every reason is
UNVERIFIABLE.

UNSUPPORTED is a verdict of its own: the bytes are in no format safeloadai reads
(no pickle, joblib, PyTorch, Keras or HDF5 reading exists), so nothing was analysed.
It is never CLEAN, never loadable by ``safe_load`` and never overridable; any other
finding on the same file makes it SUSPICIOUS.

A failure of safeloadai itself is not a verdict: the report gets ``status == "error"``,
an ``error`` ({code, message, layer}, see errors.py and docs/ERRORS.md) and no verdict.
Only MALICIOUS evidence found before the failure still decides (``status == "ok"``, the
failure listed under ``errors``).
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum

SCHEMA_VERSION = "3.0"


class Verdict(StrEnum):
    CLEAN = "CLEAN"
    UNSUPPORTED = "UNSUPPORTED"  # no reading in a supported format; nothing analysed
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {Verdict.CLEAN: 0, Verdict.UNSUPPORTED: 1, Verdict.SUSPICIOUS: 2, Verdict.MALICIOUS: 3}


def worst(*verdicts: Verdict) -> Verdict:
    return max(verdicts, key=lambda v: v.rank, default=Verdict.CLEAN)


class Category(StrEnum):
    """Why a reason was raised. UNVERIFIABLE is only ever given to SUSPICIOUS reasons."""

    MALICIOUS = "MALICIOUS"  # evidence of a known sink or of tampering
    RISKY = "RISKY"  # behaviour or a structure the scanner refuses (anomaly, error, limit, code)
    UNVERIFIABLE = "UNVERIFIABLE"  # a named object whose code the scanner cannot see
    UNSUPPORTED = "UNSUPPORTED"  # a file in no format the scanner reads (only for UNSUPPORTED verdicts)

    @property
    def rank(self) -> int:
        return _CATEGORY_RANK[self]


_CATEGORY_RANK = {Category.UNVERIFIABLE: 0, Category.UNSUPPORTED: 1, Category.RISKY: 2, Category.MALICIOUS: 3}


@dataclass
class LayerResult:
    name: str
    verdict: Verdict
    ran: bool = True
    reasons: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    timings_ms: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    # failures of safeloadai itself in this layer (errors.error); never a verdict
    errors: list[dict] = field(default_factory=list)

    def raise_to(self, verdict: Verdict, reason: str, *, category: Category | None = None,
                 item: str | None = None, explanation: str | None = None, pair: tuple | None = None) -> None:
        """Record a finding; the layer verdict only ever goes up.

        ``category`` defaults to MALICIOUS for a MALICIOUS reason and RISKY otherwise.
        UNVERIFIABLE needs the exact ``item`` a user would have to accept, and is never
        kept for a MALICIOUS reason. UNSUPPORTED goes with an UNSUPPORTED verdict only.
        """
        self.verdict = worst(self.verdict, verdict)
        text = f"{verdict.value}: {reason}"
        self.reasons.append(text)
        if verdict is Verdict.MALICIOUS:
            category = Category.MALICIOUS
        elif verdict is Verdict.UNSUPPORTED:
            category = Category.UNSUPPORTED
        elif category is Category.UNSUPPORTED:
            category = Category.RISKY
        elif category is None or category is Category.MALICIOUS or (category is Category.UNVERIFIABLE and not item):
            category = Category.RISKY
        finding = {"layer": self.name, "verdict": verdict.value, "category": category.value, "text": text}
        if category is Category.UNVERIFIABLE:
            finding.update(item=item, explanation=explanation)
            if pair is not None:
                finding["pair"] = [str(pair[0]), str(pair[1])]
        self.findings.append(finding)


@dataclass
class Report:
    path: str
    file_name: str
    sha256: str
    size: int
    file_format: str
    verdict: Verdict | None  # None exactly when status == "error"
    reasons: list[str]
    layers: list[LayerResult]
    timings_ms: dict
    version: str
    schema_version: str = SCHEMA_VERSION
    findings: list[dict] = field(default_factory=list)
    category: str | None = None
    override: dict | None = None
    # non-default options: {"name", "value", "source", "direction"} (options.py)
    options: list[dict] = field(default_factory=list)
    # imports outside the allowlist a rule accepted: {"item", "mechanism", "detail", "layer"}
    # (static/clearance.py: "referenced", "policy", "inert-class"; profiles; known files)
    cleared: list[dict] = field(default_factory=list)
    # "ok": the verdict stands. "error": safeloadai failed (``error``); there is no verdict.
    status: str = "ok"
    error: dict | None = None
    # every tool failure seen, also when MALICIOUS evidence decided despite one
    errors: list[dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def outcome(self) -> str:
        """The verdict's name, or "ERROR" when safeloadai failed."""
        return self.verdict.value if self.ok and self.verdict is not None else "ERROR"

    @property
    def clean(self) -> bool:
        return self.ok and self.verdict is Verdict.CLEAN

    @property
    def unverifiable_only(self) -> bool:
        """SUSPICIOUS, and every reason is UNVERIFIABLE: the only case an override can apply to."""
        return (self.ok and self.verdict is Verdict.SUSPICIOUS and bool(self.findings)
                and all(f["category"] == Category.UNVERIFIABLE for f in self.findings))

    @property
    def unverifiable_items(self) -> list[str]:
        return sorted({f["item"] for f in self.findings if f["category"] == Category.UNVERIFIABLE})

    @property
    def accepted(self) -> bool:
        """CLEAN, or SUSPICIOUS with every reason UNVERIFIABLE and an accepted override.
        The verdict itself stays SUSPICIOUS."""
        return self.clean or (self.unverifiable_only and bool(self.override) and self.override.get("accepted") is True)

    def layer(self, name: str) -> LayerResult | None:
        return next((layer for layer in self.layers if layer.name == name), None)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["verdict"] = self.verdict.value if self.verdict is not None else None
        for layer in data["layers"]:
            layer["verdict"] = Verdict(layer["verdict"]).value
        return data

    def to_json(self, **kwargs) -> str:
        return json.dumps(self.to_dict(), default=str, **kwargs)


# A reason that is evidence of what the file does: a sink import or call, a process,
# network or file write, code execution, a called getattr result or a dunder read.
_EVIDENCE = re.compile(
    r"known sink|sink attribute|of the sink|\b(?:code_exec|process|network|file_write|native): |"
    r"is called \(|dunder|reverse_shell|tamper|forged|detonation event", re.IGNORECASE)


def evidence_rank(text: str) -> int:
    """0 for evidence (see ``_EVIDENCE``), 1 for any other MALICIOUS reason, 2 for the rest."""
    if _EVIDENCE.search(text):
        return 0
    return 1 if "MALICIOUS:" in text else 2


def combine(layers: list[LayerResult]) -> tuple[Verdict, list[str]]:
    """Final verdict = worst layer verdict; reasons from every non-clean layer, evidence
    first (``evidence_rank``), otherwise in layer order."""
    verdict = worst(*(layer.verdict for layer in layers))
    reasons = [f"[{layer.name}] {r}" for layer in layers if layer.verdict is not Verdict.CLEAN
               for r in layer.reasons]
    return verdict, sorted(reasons, key=evidence_rank)


def combine_findings(layers: list[LayerResult]) -> tuple[list[dict], str | None]:
    """Categorised reasons of every non-clean layer, and the worst category.

    A reason recorded without a finding (written to ``reasons`` directly) is RISKY:
    nothing becomes UNVERIFIABLE unless the code that raised it said so.
    """
    findings: list[dict] = []
    for layer in layers:
        if layer.verdict is Verdict.CLEAN:
            continue
        covered = {f["text"] for f in layer.findings}
        findings.extend(dict(f, text=f"[{layer.name}] {f['text']}") for f in layer.findings)
        findings.extend({"layer": layer.name, "verdict": Verdict.SUSPICIOUS.value, "category": Category.RISKY.value,
                         "text": f"[{layer.name}] {r}"} for r in layer.reasons if r not in covered)
    findings.sort(key=lambda f: evidence_rank(f["text"]))
    if not findings:
        return findings, None
    return findings, max((Category(f["category"]) for f in findings), key=lambda c: c.rank).value


def settle(layers: list[LayerResult]) -> tuple[str, Verdict | None, list[str], list[dict], str | None, list[dict]]:
    """(status, verdict, reasons, findings, category, tool errors) from the layers.

    A tool error in any layer makes the status "error" and leaves no verdict, unless a
    layer found MALICIOUS evidence anyway: that decides (errors.py)."""
    final, reasons = combine(layers)
    findings, category = combine_findings(layers)
    tool_errors = [e for layer in layers for e in layer.errors]
    if tool_errors and final is not Verdict.MALICIOUS:
        return "error", None, reasons, findings, None, tool_errors
    return "ok", final, reasons, findings, category, tool_errors
