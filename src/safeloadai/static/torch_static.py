"""Static analysis of PyTorch zip checkpoints. torch is never imported here.

A ``torch.save`` zip holds ``<root>/data.pkl`` (the object graph) plus raw tensor
storages under ``<root>/data/``. Every ``.pkl`` member is analysed with the pickle
walker and the torch allowlist; storages are not analysed. A TorchScript archive
(``code/`` or ``constants.pkl``) ships Python source that ``torch.jit.load`` runs,
so it is always SUSPICIOUS: analysing TorchScript code is out of scope.

Members without a ``.pkl`` name are only looked at when they start like a pickle
(PROTO 2-5): one that is a complete pickle importing anything is reported, since a
loader can be told to unpickle it by name (CVE-2025-1889, the picklescan bypass that
relied on file extensions). Raw storages that merely start with those two bytes do
not parse as a complete pickle with imports.
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
            # torch's zip reader does not check CRC-32 (P6): read what it would read.
            members = {n: zf.read(n, ignore_crc=True) for n in pickles}
            hidden = {}
            for n in names:
                if n.endswith(".pkl") or n.endswith("/") or zf.size(n) > MAX_PICKLE_MEMBER_BYTES:
                    continue
                head = zf.head(n, 2)
                if len(head) == 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
                    hidden[n] = zf.read(n, ignore_crc=True)
            crc = dict(zf.crc_mismatches)
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
    for member, raw in hidden.items():
        part = parse_pickle(raw, f"{file_name}:{member}", torch=True, file_format="torch",
                            extra_allowed=extra_allowed)
        if part["error"] or not part["imports"]:
            continue  # tensor bytes that happen to start like a pickle
        imported = ", ".join(sorted({f"{i['module']}.{i['symbol']}" for i in part["imports"]}))
        combined["reasons"].append(f"member {member!r} is a pickle outside the .pkl members "
                                   f"(imports {imported[:300]})")
        for key in ("suspicious_imports", "unknown_imports", "reasons"):
            combined[key].extend(part[key])
        combined["members"].append({"name": member, "static_risk": part["static_risk"], "hidden": True})
        risk = part["static_risk"] if part["static_risk"] != "clean" else "suspicious"
        if _SEVERITY[risk] > _SEVERITY[combined["static_risk"]]:
            combined["static_risk"] = risk
    is_torchscript = any(n.split("/")[1:2] == ["code"] or n.endswith("/constants.pkl") for n in names)
    extra = [f"archive: {p}" for p in problems]
    extra += [f"archive: CRC-32 of member {n!r} is {got:#010x}, the archive records {want:#010x}; torch.load "
              "does not check CRC-32, so these are the bytes it would unpickle (analysed above)"
              for n, (want, got) in sorted(crc.items())]
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
