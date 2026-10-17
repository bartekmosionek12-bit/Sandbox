"""Report data model and the monotone verdict combination.

The final verdict is the maximum over layer verdicts. No layer can lower what
another layer found: that is how "the judge can only raise severity" and
"detonation evidence always affects the verdict" are enforced in code.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum

SCHEMA_VERSION = "2.0"


class Verdict(StrEnum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {Verdict.CLEAN: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}


def worst(*verdicts: Verdict) -> Verdict:
    return max(verdicts, key=lambda v: v.rank, default=Verdict.CLEAN)


@dataclass
class LayerResult:
    name: str
    verdict: Verdict
    ran: bool = True
    reasons: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    timings_ms: dict = field(default_factory=dict)
    details: dict = field(default_factory=dict)

    def raise_to(self, verdict: Verdict, reason: str) -> None:
        """Record a finding; the layer verdict only ever goes up."""
        self.verdict = worst(self.verdict, verdict)
        self.reasons.append(f"{verdict.value}: {reason}")


@dataclass
class Report:
    path: str
    file_name: str
    sha256: str
    size: int
    file_format: str
    verdict: Verdict
    reasons: list[str]
    layers: list[LayerResult]
    timings_ms: dict
    version: str
    schema_version: str = SCHEMA_VERSION

    @property
    def clean(self) -> bool:
        return self.verdict is Verdict.CLEAN

    def layer(self, name: str) -> LayerResult | None:
        return next((layer for layer in self.layers if layer.name == name), None)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        for layer in data["layers"]:
            layer["verdict"] = Verdict(layer["verdict"]).value
        return data

    def to_json(self, **kwargs) -> str:
        return json.dumps(self.to_dict(), default=str, **kwargs)


def combine(layers: list[LayerResult]) -> tuple[Verdict, list[str]]:
    """Final verdict = worst layer verdict; reasons from every non-clean layer."""
    verdict = worst(*(layer.verdict for layer in layers))
    reasons = [f"[{layer.name}] {r}" for layer in layers if layer.verdict is not Verdict.CLEAN
               for r in layer.reasons]
    return verdict, reasons
