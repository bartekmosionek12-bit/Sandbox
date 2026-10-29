"""The operators of every standard OpenVINO opset (0.10.0; development time only).

    python tools/gen_openvino_opsets.py [--check] [--source DIR]

OpenVINO lists the operators of each opset in ``src/core/include/openvino/opsets/
opsetN_tbl.hpp`` (one ``_OPENVINO_OP_REG(Type, namespace)`` line per operator, every
opset complete; the IR writes four of them under another name, ``IR_NAMES``). This tool
reads those headers for the pinned release tag (``TAG``) from GitHub, or from
``--source DIR`` when they were downloaded before, checks each against its recorded
sha256 once recorded, and writes ``src/safeloadai/static/upstream/
openvino_opsets.json``: opset name -> operator types. The OpenVINO IR validator
(``static/model_formats.py``) accepts a layer only as one of these exact (opset, type)
pairs; anything else is a custom or extension layer (UNVERIFIABLE).

``--check`` regenerates into memory and exits 1 if the committed file differs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "src", "safeloadai", "static", "upstream", "openvino_opsets.json")
TAG = "2026.4.1"
URL = "https://raw.githubusercontent.com/openvinotoolkit/openvino/{tag}/src/core/include/openvino/opsets/{name}"
OPSETS = range(1, 18)
REG = re.compile(r"^_OPENVINO_OP_REG\((\w+),\s*([\w:]+)\)", re.M)
# The IR writer renames four types (src/core/src/xml_util/xml_serialize_util.cpp,
# get_translate_type_name_translator); the reader maps them back. Both names are accepted.
IR_NAMES = {"Constant": "Const", "PRelu": "PReLU", "Relu": "ReLU", "Softmax": "SoftMax"}


def read(name: str, source: str | None) -> bytes:
    if source:
        with open(os.path.join(source, name), "rb") as fh:
            return fh.read()
    with urllib.request.urlopen(URL.format(tag=TAG, name=name), timeout=60) as response:  # noqa: S310
        return response.read()


def generate(source: str | None, pinned: dict[str, str]) -> dict:
    opsets, hashes = {}, {}
    for number in OPSETS:
        name = f"opset{number}_tbl.hpp"
        raw = read(name, source)
        digest = hashlib.sha256(raw).hexdigest()
        if name in pinned and pinned[name] != digest:
            raise SystemExit(f"{name}: sha256 {digest} differs from the recorded {pinned[name]}")
        hashes[name] = digest
        ops = {m.group(1) for m in REG.finditer(raw.decode("utf-8"))}
        ops = sorted(ops | {IR_NAMES[op] for op in ops if op in IR_NAMES})
        if not ops:
            raise SystemExit(f"{name}: no operator found")
        opsets[f"opset{number}"] = ops
    return {"generated_by": "tools/gen_openvino_opsets.py", "openvino_tag": TAG, "sources": hashes,
            "opsets": opsets}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--source", help="directory with the opsetN_tbl.hpp files of the tag")
    args = parser.parse_args(argv)
    pinned = {}
    if os.path.exists(OUT):
        with open(OUT, encoding="utf-8") as fh:
            committed = json.load(fh)
        if committed.get("openvino_tag") == TAG:
            pinned = committed.get("sources", {})
    data = generate(args.source, pinned)
    text = json.dumps(data, indent=1, sort_keys=True) + "\n"
    if args.check:
        with open(OUT, encoding="utf-8") as fh:
            if fh.read() != text:
                print(f"{OUT} is not current; run tools/gen_openvino_opsets.py", file=sys.stderr)
                return 1
        return 0
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {OUT}: {len(data['opsets'])} opsets", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
