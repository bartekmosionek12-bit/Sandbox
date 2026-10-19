"""Mutation corpus: the same marker payloads, re-encoded every way a loader accepts.

Each malicious seed is one call of a known sink with a marker argument. The generator
re-assembles it, opcode by opcode, across:

* how the callable is imported: GLOBAL, STACK_GLOBAL, STACK_GLOBAL from memoised
  strings, a memo round trip (stored, popped, fetched back), INST and OBJ;
* how strings are written: STRING, BINUNICODE, SHORT_BINUNICODE, UNICODE;
* protocol headers: none (protocol 0/1 style), PROTO 2, PROTO 4/5 with a FRAME;
* nesting: a pickle passed as bytes to ``pickle.loads`` / ``_pickle.loads``;
* containers: joblib compressors (zlib, gzip, bz2, lzma, xz, legacy ZF), PyTorch zip
  (stored, deflated, other archive prefixes), legacy PyTorch, trailing after a benign
  pickle, and polyglots (in front of a zip, in an HDF5 user block, benign pickle in
  front of an evil zip).

Benign seeds go through the same encodings and containers (not the polyglots) and
must stay CLEAN. Like ``build_corpus``, nothing here loads or unpickles anything.

    python -m tests.corpus.mutate OUT_DIR
"""
from __future__ import annotations

import bz2
import gzip
import io
import itertools
import json
import lzma
import os
import struct
import sys
import zipfile
import zlib

from .build_corpus import (
    CLEAN,
    MALICIOUS,
    MARKER_CMD,
    TORCH_LEGACY_MAGIC,
    _h5_with_userblock,
    _keras_zip,
    _model,
)

CODE = f"__import__('os').system('{MARKER_CMD}')"

# (seed name, module, name, argument) - each one is a single call with one string.
SINKS = [
    ("posix_system", "posix", "system", MARKER_CMD),
    ("os_system", "os", "system", MARKER_CMD),
    ("nt_system", "nt", "system", MARKER_CMD),
    ("subprocess_getoutput", "subprocess", "getoutput", MARKER_CMD),
    ("builtins_exec", "builtins", "exec", CODE),
    ("builtins_eval", "builtins", "eval", CODE),
]
IMPORTS = ("global", "stack_global", "stack_global_memo", "memo_roundtrip", "inst", "obj")
STRINGS = ("string", "binunicode", "short_binunicode", "unicode")
PROTOCOLS = (0, 2, 4, 5)


# --- encoders ------------------------------------------------------------------

def enc_str(text: str, how: str) -> bytes:
    raw = text.encode()
    if how == "string":
        return b"S" + repr(text).encode() + b"\n"
    if how == "binunicode":
        return b"X" + struct.pack("<I", len(raw)) + raw
    if how == "short_binunicode":
        if len(raw) > 255:
            return b"X" + struct.pack("<I", len(raw)) + raw
        return b"\x8c" + bytes([len(raw)]) + raw
    if how == "unicode":
        return b"V" + text.encode("raw-unicode-escape") + b"\n"
    raise ValueError(how)


class _Memo:
    """Memo writes that are valid at any protocol (BINPUT/BINGET by explicit index)."""

    def __init__(self) -> None:
        self.next = 0

    def put(self) -> tuple[bytes, int]:
        idx, self.next = self.next, self.next + 1
        return b"q" + bytes([idx]), idx

    @staticmethod
    def get(idx: int) -> bytes:
        return b"h" + bytes([idx])


def call_pickle(module: str, name: str, arg: str, *, imp: str, strings: str) -> bytes:
    """Body (no PROTO, no STOP) that calls module.name(arg) once."""
    a = enc_str(arg, strings)
    memo = _Memo()
    if imp == "global":
        return b"c" + module.encode() + b"\n" + name.encode() + b"\n" + b"(" + a + b"tR"
    if imp == "stack_global":
        return enc_str(module, strings) + enc_str(name, strings) + b"\x93(" + a + b"tR"
    if imp == "stack_global_memo":
        put_m, im = memo.put()
        put_n, iname = memo.put()
        # The strings are memoised, popped, then fetched back for STACK_GLOBAL.
        return (enc_str(module, strings) + put_m + b"0" + enc_str(name, strings) + put_n + b"0"
                + memo.get(im) + memo.get(iname) + b"\x93(" + a + b"tR")
    if imp == "memo_roundtrip":
        put, idx = memo.put()
        decoy = b"c" + b"collections\nOrderedDict\n" + b")R0"  # a harmless call in between
        return b"c" + module.encode() + b"\n" + name.encode() + b"\n" + put + b"0" + decoy + memo.get(idx) \
            + b"(" + a + b"tR"
    if imp == "inst":
        return b"(" + a + b"i" + module.encode() + b"\n" + name.encode() + b"\n"
    if imp == "obj":
        return b"(" + b"c" + module.encode() + b"\n" + name.encode() + b"\n" + a + b"o"
    raise ValueError(imp)


def frame(body: bytes, protocol: int) -> bytes:
    """A whole pickle: protocol header, optional FRAME, body, STOP."""
    body = body + b"."
    if protocol == 0:
        return body
    if protocol < 4:
        return b"\x80" + bytes([protocol]) + body
    return b"\x80" + bytes([protocol]) + b"\x95" + struct.pack("<Q", len(body)) + body


def nested(inner: bytes, loader: tuple[str, str]) -> bytes:
    """An outer pickle whose only call is loader(inner_bytes)."""
    module, name = loader
    return frame(b"c" + module.encode() + b"\n" + name.encode() + b"\n(" + b"B" + struct.pack("<I", len(inner))
                 + inner + b"tR", 2)


# Benign bodies: plain containers and the classes ordinary model pickles use.
BENIGN_BODIES = {
    "dict": b"}(" + b"X\x01\x00\x00\x00aK\x01" + b"X\x01\x00\x00\x00bG?\xe0\x00\x00\x00\x00\x00\x00" + b"u",
    "list": b"](K\x01K\x02K\x03e",
    "ordered_dict": b"ccollections\nOrderedDict\n)R(X\x01\x00\x00\x00wK\x07u",
    "tuple_bytes": b"(X\x04\x00\x00\x00nameC\x03\x00\x01\x02t",
}


# --- containers ----------------------------------------------------------------

def _zip(members: dict[str, bytes], compression: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def torch_zip(pkl: bytes, *, prefix: str = "archive", compression: int = zipfile.ZIP_STORED) -> bytes:
    return _zip({f"{prefix}/data.pkl": pkl, f"{prefix}/version": b"3\n", f"{prefix}/byteorder": b"little"},
                compression)


def torch_legacy(pkl: bytes) -> bytes:
    magic = frame(b"\x8a\x0a" + TORCH_LEGACY_MAGIC.to_bytes(10, "little"), 2)
    return magic + frame(b"M\xe9\x03", 2) + frame(b"}", 2) + pkl + frame(b"]", 2) + b"\x00" * 16


def joblib_zf(pkl: bytes) -> bytes:
    """joblib's legacy ZF container: 'ZF' + hex length padded to 19 + zlib stream."""
    return b"ZF" + hex(len(pkl)).encode().ljust(19) + zlib.compress(pkl)


COMPRESSORS = {
    "zlib": zlib.compress,
    "gzip": lambda d: gzip.compress(d, mtime=0),
    "bz2": bz2.compress,
    "lzma": lambda d: lzma.compress(d, format=lzma.FORMAT_ALONE),
    "xz": lambda d: lzma.compress(d, format=lzma.FORMAT_XZ),
    "zf": joblib_zf,
}

BENIGN_PICKLE = frame(BENIGN_BODIES["dict"], 2)


def containers(pkl: bytes, *, polyglots: bool) -> list[tuple[str, str, bytes]]:
    """(container name, file extension, bytes) for one pickle."""
    out = [("raw", ".pkl", pkl)]
    out += [(f"joblib_{name}", ".joblib", fn(pkl)) for name, fn in COMPRESSORS.items()]
    out += [
        ("torch_zip_stored", ".pt", torch_zip(pkl)),
        ("torch_zip_deflated", ".pt", torch_zip(pkl, compression=zipfile.ZIP_DEFLATED)),
        ("torch_zip_prefix", ".bin", torch_zip(pkl, prefix="pytorch_model")),
        ("torch_legacy", ".bin", torch_legacy(pkl)),
    ]
    if polyglots:
        benign_torch = torch_zip(BENIGN_PICKLE)
        out += [
            ("trailing_after_benign", ".pkl", BENIGN_PICKLE + pkl),
            ("before_torch_zip", ".pt", pkl + benign_torch),
            ("before_keras_zip", ".keras", pkl + _keras_zip(_model())),
            ("benign_before_evil_zip", ".pkl", BENIGN_PICKLE + torch_zip(pkl)),
        ]
        if len(pkl) <= 512:
            out.append(("h5_userblock", ".h5", _h5_with_userblock(pkl)))
    return out


# --- the corpus ----------------------------------------------------------------

def mutations() -> list[tuple[str, str, str, bytes]]:
    """(file name, category, expected verdict, bytes), deterministic order."""
    out: list[tuple[str, str, str, bytes]] = []
    # 1. Encodings: every sink x import form x string opcode x protocol, raw pickle.
    for (seed, module, name, arg), imp, strings, proto in itertools.product(SINKS, IMPORTS, STRINGS, PROTOCOLS):
        data = frame(call_pickle(module, name, arg, imp=imp, strings=strings), proto)
        out.append((f"m_{seed}_{imp}_{strings}_p{proto}.pkl", f"encoding:{imp}", MALICIOUS, data))
    # 2. Containers and polyglots: every import form, two protocols, one sink.
    for imp, proto in itertools.product(IMPORTS, (2, 4)):
        pkl = frame(call_pickle("posix", "system", MARKER_CMD, imp=imp, strings="binunicode"), proto)
        for cname, ext, data in containers(pkl, polyglots=True):
            out.append((f"m_container_{cname}_{imp}_p{proto}{ext}", f"container:{cname}", MALICIOUS, data))
    # 3. Nested pickles: the payload only exists as bytes handed to pickle.loads.
    for (seed, module, name, arg), loader in itertools.product(SINKS[:2] + SINKS[4:5],
                                                                (("pickle", "loads"), ("_pickle", "loads"))):
        inner = frame(call_pickle(module, name, arg, imp="global", strings="binunicode"), 2)
        out.append((f"m_nested_{loader[0]}_{seed}.pkl", "nested", MALICIOUS, nested(inner, loader)))
    # 4. Benign controls through the same encodings and (non-polyglot) containers.
    for (bname, body), proto in itertools.product(BENIGN_BODIES.items(), PROTOCOLS):
        out.append((f"b_mut_{bname}_p{proto}.pkl", "benign:encoding", CLEAN, frame(body, proto)))
    for bname, body in BENIGN_BODIES.items():
        for cname, ext, data in containers(frame(body, 2), polyglots=False):
            if cname != "raw":
                out.append((f"b_mut_{bname}_{cname}{ext}", f"benign:{cname}", CLEAN, data))
    names = [n for n, *_ in out]
    if len(names) != len(set(names)):
        raise AssertionError("duplicate mutation names")
    return out


def build(out_dir: str) -> list[dict]:
    os.makedirs(out_dir, exist_ok=True)
    manifest = []
    for name, category, expected, data in mutations():
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(data)
        manifest.append({"file": name, "label": "benign" if expected == CLEAN else "malicious",
                         "category": category, "expected": expected})
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return manifest


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m tests.corpus.mutate OUT_DIR", file=sys.stderr)
        return 2
    manifest = build(argv[0])
    print(f"wrote {len(manifest)} files to {argv[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
