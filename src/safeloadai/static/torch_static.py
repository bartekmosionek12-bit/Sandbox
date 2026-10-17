"""Static analysis of PyTorch zip checkpoints. torch is never imported here.

A ``torch.save`` zip holds ``<root>/data.pkl`` (the object graph) plus raw tensor
storages under ``<root>/data/``. Every ``.pkl`` member is analysed with the pickle
walker and the torch allowlist; storages are never read. A TorchScript archive
(``code/`` or ``constants.pkl``) ships Python source that ``torch.jit.load`` runs,
so it is always SUSPICIOUS: analysing TorchScript code is out of scope.
"""
from __future__ import annotations

import os

from ..parsing.zipsafe import SafeZip, ZipRefused
from .pickle_static import parse_pickle

MAX_PICKLE_MEMBER_BYTES = 256 * 1024 * 1024
_SEVERITY = {"clean": 0, "suspicious": 1, "malicious": 2}


def parse_torch_zip(data: bytes, file_name: str = "<memory>", extra_allowed: frozenset = frozenset()) -> dict:
    try:
        with SafeZip(data, max_member_bytes=MAX_PICKLE_MEMBER_BYTES) as zf:
            problems = list(zf.inventory.problems)
            names = zf.names
            pickles = [n for n in names if n.endswith(".pkl")]
            members = {n: zf.read(n) for n in pickles}
    except ZipRefused as exc:
        report = parse_pickle(b"", file_name, torch=True, file_format="torch")
        report["error"] = str(exc)
        report["reasons"] = [str(exc)]
        report["static_risk"] = "suspicious"
        return report

    combined = None
    for member, raw in members.items():
        part = parse_pickle(raw, f"{file_name}:{member}", torch=True, file_format="torch",
                            extra_allowed=extra_allowed)
        if combined is None:
            combined = part
            combined["file_name"] = file_name
            combined["members"] = []
        else:
            for key in ("opcodes", "flagged_opcodes", "suspicious_imports", "unknown_imports",
                        "imports", "suspicious_strings", "reasons", "notes"):
                combined[key].extend(part[key])
            combined["raw_disasm"] += f"\n--- {member} ---\n" + part["raw_disasm"]
            combined["error"] = combined["error"] or part["error"]
            if _SEVERITY[part["static_risk"]] > _SEVERITY[combined["static_risk"]]:
                combined["static_risk"] = part["static_risk"]
        combined["members"].append({"name": member, "static_risk": part["static_risk"]})

    if combined is None:
        combined = parse_pickle(b"", file_name, torch=True, file_format="torch")
        combined["members"] = []
    is_torchscript = any(n.split("/")[1:2] == ["code"] or n.endswith("/constants.pkl") for n in names)
    extra = [f"archive: {p}" for p in problems]
    if is_torchscript:
        extra.append("TorchScript archive: contains Python code run by torch.jit.load (out of scope)")
    if extra:
        combined["reasons"].extend(extra)
        if combined["static_risk"] == "clean":
            combined["static_risk"] = "suspicious"
    return combined


def parse_file(path: str) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    return parse_torch_zip(data, file_name=os.path.basename(path))
