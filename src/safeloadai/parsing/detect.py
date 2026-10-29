"""Format detection by content, not by file extension.

The extension is only a hint. A mismatch between what the name says and what the
bytes are is reported, because a ``.keras`` that is really a pickle (or the other
way round) is either broken or crafted.
"""
from __future__ import annotations

import io
import os
import pickletools

from . import decompress
from .zipsafe import ZIP_MAGIC, SafeZip, ZipRefused

HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"

PICKLE = "pickle"
JOBLIB = "joblib"
TORCH = "torch"
KERAS = "keras"
H5 = "h5"
UNKNOWN = "unknown"
# Data-only formats (0.9.0, static/data_formats.py): their loaders run no code from the file.
SAFETENSORS = "safetensors"
GGUF = "gguf"
NPY = "npy"
NPZ = "npz"
DATA_ONLY = (SAFETENSORS, GGUF, NPY, NPZ)
# Model formats that run no code on load (0.10.0, static/model_formats.py): they name
# operators, not Python objects. An OpenVINO .bin holds raw weights and is read only
# through the .xml beside it.
ONNX = "onnx"
TFLITE = "tflite"
MSGPACK = "msgpack"
OPENVINO_XML = "openvino-xml"
OPENVINO_BIN = "openvino-bin"
COREML_WEIGHTS = "coreml-weights"
CTRANSLATE2 = "ctranslate2"
GGML_WHISPER = "ggml-whisper"
NO_CODE = (ONNX, TFLITE, MSGPACK, OPENVINO_XML, OPENVINO_BIN, COREML_WEIGHTS, CTRANSLATE2, GGML_WHISPER)

GGUF_MAGIC = b"GGUF"
NPY_MAGIC = b"\x93NUMPY"
SAFETENSORS_MAX_HEADER = 100_000_000

EXTENSION_HINTS = {
    ".pkl": {PICKLE, JOBLIB},
    ".pickle": {PICKLE, JOBLIB},
    ".joblib": {PICKLE, JOBLIB},
    ".pt": {TORCH, PICKLE},
    ".pth": {TORCH, PICKLE},
    ".bin": {TORCH, PICKLE, OPENVINO_BIN, COREML_WEIGHTS, CTRANSLATE2, GGML_WHISPER},
    ".keras": {KERAS},
    ".h5": {H5},
    ".hdf5": {H5},
    ".safetensors": {SAFETENSORS},
    ".gguf": {GGUF},
    ".npy": {NPY},
    ".npz": {NPZ},
    ".onnx": {ONNX},
    ".tflite": {TFLITE},
    ".msgpack": {MSGPACK},
    ".xml": {OPENVINO_XML},
}

SUPPORTED_EXTENSIONS = tuple(EXTENSION_HINTS)
# What a directory scan picks up: an OpenVINO .xml is checked with its .bin (and a
# directory holds many .xml files that are no model).
SCAN_EXTENSIONS = tuple(e for e in EXTENSION_HINTS if e != ".xml")


# The unpickler does not check that an opcode belongs to the stream's protocol, and a
# stream needs no PROTO header: any opcode that takes nothing from the stack can come
# first (a protocol-0-style stream may open with SHORT_BINUNICODE or FRAME, say).
_PICKLE_FIRST_BYTES = frozenset(
    op.code.encode("latin-1") for op in pickletools.opcodes if not op.stack_before
)


# A stream is taken for a pickle when its opcodes decode up to a STOP, or up to this
# many opcodes, or up to any opcode that imports or calls. A stream that fails before
# all three cannot make pickle.load import or call anything.
PICKLE_PROBE_OPCODES = 8
_PICKLE_ACTIVE = frozenset({
    "GLOBAL", "STACK_GLOBAL", "INST", "OBJ", "REDUCE", "NEWOBJ", "NEWOBJ_EX", "BUILD",
    "EXT1", "EXT2", "EXT4", "PERSID", "BINPERSID",
})


def _looks_like_pickle(data: bytes) -> bool:
    """Would ``pickle.load`` get far enough into these bytes to import or call anything?
    Decodes with ``pickletools.genops`` only; nothing is unpickled."""
    if data[:1] not in _PICKLE_FIRST_BYTES or data.startswith(ZIP_MAGIC):
        # A file that starts with a ZIP local header begins with PERSID ("P"): the
        # default Unpickler raises on it before reading anything else.
        return False
    count = 0
    try:
        for opcode, _arg, _pos in pickletools.genops(io.BytesIO(data)):
            count += 1
            if opcode.name == "STOP" or opcode.name in _PICKLE_ACTIVE or count >= PICKLE_PROBE_OPCODES:
                return True
    except Exception:  # noqa: BLE001 - any decoding failure means "not a pickle here"
        return False
    return False


def data_only_format(data: bytes) -> str | None:
    """The data-only format these bytes start with (by magic number, or for safetensors by
    a plausible header length followed by a JSON object), or None. Whether the structure
    is valid is checked by ``static.data_formats``."""
    if data.startswith(GGUF_MAGIC):
        return GGUF
    if data.startswith(NPY_MAGIC):
        return NPY
    if len(data) >= 9:
        n = int.from_bytes(data[:8], "little")
        if 2 <= n <= SAFETENSORS_MAX_HEADER and 8 + n <= len(data) and data[8:9] == b"{":
            return SAFETENSORS
    return None


def no_code_format(data: bytes, file_name: str = "") -> str | None:
    """The no-code model format these bytes start with, or None: TFLite by its file
    identifier, ONNX by a ModelProto header, an OpenVINO IR by its ``<net>`` root, a Flax
    msgpack checkpoint by a msgpack map when the name ends in ``.msgpack`` (a msgpack map
    has no magic number), a Core ML ``weight.bin`` by its version-2 storage header and
    the first blob's sentinel, a CTranslate2 ``model.bin`` by its binary version and spec name, a
    whisper.cpp ggml model by its magic and hyperparameters. Whether the structure is valid is
    ``static.model_formats``' job."""
    from ..static import model_formats

    if data[4:8] == model_formats.TFLITE_IDENTIFIER:
        return TFLITE
    if model_formats.looks_like_onnx(data):
        return ONNX
    if model_formats.looks_like_openvino_xml(data):
        return OPENVINO_XML
    if model_formats.looks_like_coreml_weights(data):
        return COREML_WEIGHTS
    if model_formats.looks_like_ctranslate2(data):
        return CTRANSLATE2
    if model_formats.looks_like_ggml_whisper(data):
        return GGML_WHISPER
    if file_name.lower().endswith(".msgpack") and data[:1] and (0x80 <= data[0] <= 0x8F or data[0] in (0xDE, 0xDF)):
        return MSGPACK
    return None


def detect(data: bytes) -> str:
    """Container format of the bytes: pickle, joblib (compressed), torch, keras, h5 or unknown.

    An uncompressed joblib file is a pickle stream; the pickle walker reports it as
    joblib once it meets joblib's array wrappers.
    """
    if data.startswith(HDF5_MAGIC):
        return H5
    if data.startswith(ZIP_MAGIC) or b"PK\x05\x06" in data[-65_557:]:
        try:
            with SafeZip(data) as zf:
                names = zf.names
        except ZipRefused:
            return UNKNOWN
        if "config.json" in names or "model.json" in names:
            return KERAS
        if any(n == "data.pkl" or n.endswith("/data.pkl") for n in names):
            return TORCH
        return UNKNOWN
    if decompress.detect(data) is not None:
        return JOBLIB
    if _looks_like_pickle(data):
        return PICKLE
    return UNKNOWN


def extension_mismatch(path: str, detected: str) -> str | None:
    """A note when the extension promises a different format than the bytes."""
    ext = os.path.splitext(path)[1].lower()
    expected = EXTENSION_HINTS.get(ext)
    if expected is None or detected in expected:
        return None
    return f"file extension {ext!r} does not match its content (detected: {detected})"
