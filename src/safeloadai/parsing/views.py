"""Every way a loader could read the same bytes ("views").

A model file is not one format but whatever the loader the user calls makes of it.
The readers disagree about where a file starts:

* ``pickle.load``, ``joblib.load``, ``numpy.load(allow_pickle=True)`` and the legacy
  branch of ``torch.load`` read a pickle stream from offset 0 (joblib first looks for
  a compressor's magic number at offset 0);
* ``torch.load`` takes its zip branch only when a local file header is at offset 0;
* ``zipfile`` (Keras ``.keras``) finds the archive from the end-of-central-directory
  record, so any amount of data may come before it;
* ``h5py`` looks for the HDF5 superblock at offset 0, 512, 1024, 2048, ... (a user
  block may come before it);
* the data-only loaders (safetensors, GGUF, ``numpy.load`` of ``.npy`` / ``.npz`` without
  pickle) read a header at offset 0; a ``.npz`` is a ZIP archive of ``.npy`` members;
* the no-code model loaders (ONNX, TFLite, Flax msgpack, OpenVINO IR) read the whole file
  from offset 0.

So one file can be a valid pickle for one loader and a valid ``.keras`` archive for
another (a polyglot). ``find_views`` lists every reading that parses, and the scan
analyses each of them; the most severe verdict wins. Nothing here deserialises
anything: pickle bytes are only decoded by ``pickletools.genops``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from . import decompress
from .detect import (
    COREML_WEIGHTS,
    CTRANSLATE2,
    DATA_ONLY,
    EXTENSION_HINTS,
    GGML_WHISPER,
    GGUF,
    H5,
    HDF5_MAGIC,
    JOBLIB,
    KERAS,
    MSGPACK,
    NO_CODE,
    NPY,
    NPZ,
    ONNX,
    OPENVINO_XML,
    PICKLE,
    SAFETENSORS,
    TFLITE,
    TORCH,
    UNKNOWN,
    _looks_like_pickle,
    data_only_format,
    no_code_format,
)
from .zipsafe import ZIP_MAGIC, SafeZip, ZipRefused

ZIP = "zip"  # a valid archive that is neither a Keras nor a PyTorch file

MAX_H5_USERBLOCK_PROBES = 40  # 512 * 2**39 is far beyond any file we accept


@dataclass(frozen=True)
class View:
    """One loader's reading: ``fmt`` starting at byte ``start`` and ending before ``end``."""

    fmt: str
    start: int
    end: int
    loader: str

    @property
    def label(self) -> str:
        return f"{self.fmt}@{self.start}"

    def slice(self, data: bytes) -> bytes:
        """The bytes this reading's analyser gets. A ZIP reading gets the whole file: the
        archive reader locates it from the end and reports any data in front of it."""
        if self.fmt in (KERAS, TORCH, ZIP, NPZ) or (self.start, self.end) == (0, len(data)):
            return data
        return data[self.start:self.end]

    def describe(self) -> dict:
        return {"format": self.fmt, "start": self.start, "end": self.end, "loader": self.loader}


def pickle_at_start(data: bytes) -> bool:
    """Would ``pickle.load`` get far enough into these bytes to import or call anything?"""
    return _looks_like_pickle(data)


def _zip_view(data: bytes) -> View | None:
    if not (data.startswith(ZIP_MAGIC) or b"PK\x05\x06" in data[-65_557:]):
        return None
    try:
        with SafeZip(data) as zf:
            names, leading = zf.names, zf.inventory.leading_bytes
    except ZipRefused:
        return None
    if "config.json" in names or "model.json" in names:
        fmt, loader = KERAS, "keras.saving.load_model (zipfile, end of central directory)"
    elif any(n == "data.pkl" or n.endswith("/data.pkl") for n in names):
        fmt, loader = TORCH, "torch.load (zip branch)"
    elif names and all(n.endswith(".npy") for n in names):
        fmt, loader = NPZ, "numpy.load (.npz, allow_pickle=False)"
    else:
        fmt, loader = ZIP, "zipfile (end of central directory)"
    return View(fmt, leading, len(data), loader)


def _h5_offsets(size: int):
    yield 0
    offset = 512
    for _ in range(MAX_H5_USERBLOCK_PROBES):
        if offset >= size:
            return
        yield offset
        offset *= 2


def find_views(data: bytes, file_name: str = "") -> list[View]:
    """Every valid reading of ``data``, offset-0 readings first. ``file_name`` only decides
    whether a msgpack map is taken for a Flax checkpoint (it has no magic number)."""
    views: list[View] = []
    zip_view = _zip_view(data)
    data_only = data_only_format(data)
    no_code = no_code_format(data, file_name) if data_only is None else None
    if decompress.detect(data) is not None:
        # joblib reads exactly one compressed stream; an archive after it is a second reading.
        cut = zip_view.start if zip_view and zip_view.start > 0 else len(data)
        views.append(View(JOBLIB, 0, cut, "joblib.load (compressed)"))
    elif pickle_at_start(data):
        # Not cut at the archive: an archive found from the end may sit inside one of the
        # pickle's byte strings (a pickled Keras 3 model carries its .keras zip that way),
        # and pickle.load reads on until STOP either way. Bytes after STOP are reported
        # by the pickle walker.
        views.append(View(PICKLE, 0, len(data), "pickle.load / joblib.load / torch.load (legacy)"))
    for offset in _h5_offsets(len(data)):
        if data.startswith(HDF5_MAGIC, offset):
            views.append(View(H5, offset, len(data), "h5py (superblock" + (f" after a {offset}-byte user block)"
                                                                         if offset else " at offset 0)")))
            break  # h5py uses the first superblock it finds
    if data_only is not None:
        views.append(View(data_only, 0, len(data), _DATA_LOADERS[data_only]))
    if no_code is not None:
        views.append(View(no_code, 0, len(data), _DATA_LOADERS[no_code]))
    if zip_view is not None:
        views.append(zip_view)
    return views


_DATA_LOADERS = {SAFETENSORS: "safetensors (header at offset 0)", GGUF: "gguf / llama.cpp (magic at offset 0)",
                 NPY: "numpy.load (allow_pickle=False)", ONNX: "onnx.load / onnxruntime (protobuf at offset 0)",
                 TFLITE: "tf.lite.Interpreter (flatbuffer at offset 0)",
                 MSGPACK: "flax.serialization.msgpack_restore (msgpack at offset 0)",
                 OPENVINO_XML: "openvino.Core.read_model (XML)",
                 COREML_WEIGHTS: "Core ML runtime (MIL blob storage at offset 0)",
                 CTRANSLATE2: "ctranslate2 runtime (model.bin at offset 0)",
                 GGML_WHISPER: "whisper.cpp (ggml magic at offset 0)"}


# The view a loader picked by file extension reads first.
_EXTENSION_ORDER = {
    ".pkl": (JOBLIB, PICKLE), ".pickle": (JOBLIB, PICKLE), ".joblib": (JOBLIB, PICKLE),
    ".keras": (KERAS,), ".h5": (H5,), ".hdf5": (H5,),
    ".safetensors": (SAFETENSORS,), ".gguf": (GGUF,), ".npy": (NPY,), ".npz": (NPZ,),
    ".onnx": (ONNX,), ".tflite": (TFLITE,), ".msgpack": (MSGPACK,), ".xml": (OPENVINO_XML,),
}
_DEFAULT_ORDER = (H5, KERAS, TORCH, JOBLIB, PICKLE, *DATA_ONLY, *NO_CODE, ZIP)


def primary_view(views: list[View], file_name: str) -> View | None:
    """The reading the user's loader most likely performs: by extension when one of the
    views matches it, otherwise by content (the order ``detect`` has always used)."""
    if not views:
        return None
    ext = os.path.splitext(file_name)[1].lower()
    if ext in (".pt", ".pth", ".bin"):
        # torch.load: zip branch only for a local header at offset 0, else legacy pickle.
        order: tuple[str, ...] = (TORCH, ZIP, PICKLE) if data_starts_zip(views) else (PICKLE, TORCH)
    else:
        order = _EXTENSION_ORDER.get(ext, ())
    for fmt in (*order, *_DEFAULT_ORDER):
        for view in views:
            if view.fmt == fmt:
                return view
    return views[0]


def data_starts_zip(views: list[View]) -> bool:
    return any(v.fmt in (TORCH, KERAS, ZIP, NPZ) and v.start == 0 for v in views)


def detected_format(view: View | None) -> str:
    """The value ``detect.detect`` used to return for this reading."""
    if view is None or view.fmt == ZIP:
        return UNKNOWN
    return view.fmt


__all__ = ["EXTENSION_HINTS", "View", "find_views", "pickle_at_start", "primary_view", "detected_format"]
