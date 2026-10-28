"""Model formats that cannot run code on load (0.10.0): ONNX, TFLite, Flax/JAX msgpack
checkpoints and OpenVINO IR. Like the data-only formats (``data_formats.py``), their
loaders read a described structure and copy tensor bytes; the file names operators, not
Python objects. A file whose structure is exactly what the format allows, with only
standard operators, is CLEAN with the reason ``format runs no code on load``. Any
inconsistency (a field the schema does not have, a length or offset outside the file, an
external data path that leaves the model directory, data after the end) is RISKY, because
a file that is not what it claims to be may be read differently by another loader. An
operator from a custom domain or a custom/extension layer is UNVERIFIABLE and names the
domain or operator: a runtime implements it with a native library the loading code
registers, whose code the scanner cannot see.

Everything is read here with ``struct``, a schema-driven protobuf and flatbuffer walker of
our own, a strict msgpack walker and ``xml.parsers.expat`` with DTDs and entities
refused; nothing is loaded by a framework. Every length and count is checked against the
bytes that are really there before it is used, nesting is bounded, and every walk charges
the scan's host-memory budget (``budget.py``). Tensor bytes are never copied.

The references (sources read, never imported or run):

* ONNX 1.23.2 ``onnx/onnx.proto`` (IR version 1 to 14) and ``onnx/checker.cc``
  (``resolve_external_data_location``: relative, no ``..``, no symlink, inside the model
  directory); ``onnx/external_data_helper.py`` for the external-data keys.
* TensorFlow Lite schema 2.18.0 (``tflite`` 2.18.0, generated from ``schema.fbs``): file
  identifier ``TFL3``, schema version 3, ``BuiltinOperator`` 0 to 208, ``TensorType`` 0 to 18, ``CUSTOM`` = 32,
  ``GetBuiltinCode`` = max(deprecated_builtin_code, builtin_code).
* Flax 0.12.12 ``flax/serialization.py``: ``msgpack_restore`` with ext types 1 (ndarray:
  shape, dtype name, buffer), 2 (complex) and 3 (NumPy scalar); every other ext type is
  returned as an opaque object (not a Flax checkpoint).
* OpenVINO 2026.4.1 ``src/core/include/openvino/opsets/opset1_tbl.hpp`` to
  ``opset17_tbl.hpp`` (``upstream/openvino_opsets.json``, ``tools/gen_openvino_opsets.py``)
  and the IR v10/v11 reader: ``<net>`` with ``<layers>`` and ``<edges>``; a ``Const``
  layer reads ``size`` bytes at ``offset`` of the ``.bin`` with the same name.
* coremltools 9.0 ``mlmodel/src/MILBlob/Blob/StorageFormat.hpp``, ``StorageReader.cpp``,
  ``StorageWriter.cpp`` and ``BlobDataType.hpp``: the ``weight.bin`` of an ML Program
  (``.mlpackage``), read by the Core ML runtime, never by Python.
* CTranslate2 4.6.0 ``src/models/model.cc`` (``Model::load``, binary versions 1 to 6),
  ``src/models/model_factory.cc`` (the registered specs) and
  ``python/ctranslate2/specs/model_spec.py`` (``ModelSpec._serialize``): the ``model.bin``
  of a converted model, read by the C++ runtime.
* whisper.cpp 1.8.2 ``src/whisper.cpp`` (``whisper_model_load``), ``src/whisper-arch.h``
  and ggml ``ggml.h`` / ``ggml-common.h`` / ``ggml.c`` (type ids, block sizes,
  ``ggml_ftype_to_ggml_type``): the legacy ``ggml`` whisper model file.
"""
from __future__ import annotations

import math
import os
import re
import struct
from functools import lru_cache

from ..parsing.detect import COREML_WEIGHTS, CTRANSLATE2, GGML_WHISPER, MSGPACK, ONNX, OPENVINO_BIN, OPENVINO_XML, TFLITE
from . import budget as budget_mod
from .data_formats import Invalid

NO_CODE_REASON = "format runs no code on load"
MAX_DEPTH = 64  # nested messages, graphs in attributes, msgpack containers
MAX_COMPANION_BYTES = 256 << 20  # an OpenVINO .xml read next to its .bin


def _charge(amount: int = budget_mod.OPCODE_COST) -> None:
    budget_mod.current().charge(amount)


class Unverifiable:
    """An operator the file names whose implementation is native code outside the file."""

    __slots__ = ("item", "reason", "explanation")

    def __init__(self, item: str, reason: str, explanation: str):
        self.item, self.reason, self.explanation = item, reason, explanation


# --- protobuf (ONNX) --------------------------------------------------------------------

# Field kinds: scalar wire types are checked; "msg:<Name>" is a nested message.
V, F32, F64, STR, BYTES = "varint", "fixed32", "fixed64", "string", "bytes"
PV, PF32, PF64 = "packed-varint", "packed-fixed32", "packed-fixed64"

ONNX_SCHEMA: dict[str, dict[int, tuple[str, str]]] = {
    "ModelProto": {1: ("ir_version", V), 8: ("opset_import", "msg:OperatorSetIdProto"), 2: ("producer_name", STR),
                   3: ("producer_version", STR), 4: ("domain", STR), 5: ("model_version", V), 6: ("doc_string", STR),
                   7: ("graph", "msg:GraphProto"), 14: ("metadata_props", "msg:StringStringEntryProto"),
                   20: ("training_info", "msg:TrainingInfoProto"), 25: ("functions", "msg:FunctionProto"),
                   26: ("configuration", "msg:DeviceConfigurationProto")},
    "OperatorSetIdProto": {1: ("domain", STR), 2: ("version", V)},
    "StringStringEntryProto": {1: ("key", STR), 2: ("value", STR)},
    "DeviceConfigurationProto": {1: ("name", STR), 2: ("num_devices", V), 3: ("device", STR)},
    "TrainingInfoProto": {1: ("initialization", "msg:GraphProto"), 2: ("algorithm", "msg:GraphProto"),
                          3: ("initialization_binding", "msg:StringStringEntryProto"),
                          4: ("update_binding", "msg:StringStringEntryProto")},
    "GraphProto": {1: ("node", "msg:NodeProto"), 2: ("name", STR), 5: ("initializer", "msg:TensorProto"),
                   15: ("sparse_initializer", "msg:SparseTensorProto"), 10: ("doc_string", STR),
                   11: ("input", "msg:ValueInfoProto"), 12: ("output", "msg:ValueInfoProto"),
                   13: ("value_info", "msg:ValueInfoProto"), 14: ("quantization_annotation", "msg:TensorAnnotation"),
                   16: ("metadata_props", "msg:StringStringEntryProto")},
    "NodeProto": {1: ("input", STR), 2: ("output", STR), 3: ("name", STR), 4: ("op_type", STR), 7: ("domain", STR),
                  8: ("overload", STR), 5: ("attribute", "msg:AttributeProto"), 6: ("doc_string", STR),
                  9: ("metadata_props", "msg:StringStringEntryProto"),
                  10: ("device_configurations", "msg:NodeDeviceConfigurationProto")},
    "NodeDeviceConfigurationProto": {1: ("configuration_id", STR), 2: ("sharding_spec", "msg:ShardingSpecProto"),
                                     3: ("pipeline_stage", V)},
    "ShardingSpecProto": {1: ("tensor_name", STR), 2: ("device", PV),
                          3: ("index_to_device_group_map", "msg:IntIntListEntryProto"),
                          4: ("sharded_dim", "msg:ShardedDimProto")},
    "IntIntListEntryProto": {1: ("key", V), 2: ("value", PV)},
    "ShardedDimProto": {1: ("axis", V), 2: ("simple_sharding", "msg:SimpleShardedDimProto")},
    "SimpleShardedDimProto": {1: ("dim_value", V), 2: ("dim_param", STR), 3: ("num_shards", V)},
    "AttributeProto": {1: ("name", STR), 21: ("ref_attr_name", STR), 13: ("doc_string", STR), 20: ("type", V),
                       2: ("f", F32), 3: ("i", V), 4: ("s", BYTES), 5: ("t", "msg:TensorProto"),
                       6: ("g", "msg:GraphProto"), 22: ("sparse_tensor", "msg:SparseTensorProto"),
                       14: ("tp", "msg:TypeProto"), 7: ("floats", PF32), 8: ("ints", PV), 9: ("strings", BYTES),
                       10: ("tensors", "msg:TensorProto"), 11: ("graphs", "msg:GraphProto"),
                       23: ("sparse_tensors", "msg:SparseTensorProto"), 15: ("type_protos", "msg:TypeProto")},
    "ValueInfoProto": {1: ("name", STR), 2: ("type", "msg:TypeProto"), 3: ("doc_string", STR),
                       4: ("metadata_props", "msg:StringStringEntryProto")},
    "TensorProto": {1: ("dims", PV), 2: ("data_type", V), 3: ("segment", "msg:Segment"), 4: ("float_data", PF32),
                    5: ("int32_data", PV), 6: ("string_data", BYTES), 7: ("int64_data", PV), 8: ("name", STR),
                    12: ("doc_string", STR), 9: ("raw_data", BYTES), 13: ("external_data", "msg:StringStringEntryProto"),
                    14: ("data_location", V), 10: ("double_data", PF64), 11: ("uint64_data", PV),
                    16: ("metadata_props", "msg:StringStringEntryProto")},
    "Segment": {1: ("begin", V), 2: ("end", V)},
    "SparseTensorProto": {1: ("values", "msg:TensorProto"), 2: ("indices", "msg:TensorProto"), 3: ("dims", PV)},
    "TensorAnnotation": {1: ("tensor_name", STR), 2: ("quant_parameter_tensor_names", "msg:StringStringEntryProto")},
    "TensorShapeProto": {1: ("dim", "msg:Dimension")},
    "Dimension": {1: ("dim_value", V), 2: ("dim_param", STR), 3: ("denotation", STR)},
    "TypeProto": {1: ("tensor_type", "msg:TypeTensor"), 4: ("sequence_type", "msg:TypeSequence"),
                  5: ("map_type", "msg:TypeMap"), 9: ("optional_type", "msg:TypeSequence"),
                  8: ("sparse_tensor_type", "msg:TypeTensor"), 7: ("opaque_type", "msg:TypeOpaque"),
                  6: ("denotation", STR)},
    "TypeTensor": {1: ("elem_type", V), 2: ("shape", "msg:TensorShapeProto")},
    "TypeSequence": {1: ("elem_type", "msg:TypeProto")},
    "TypeMap": {1: ("key_type", V), 2: ("value_type", "msg:TypeProto")},
    "TypeOpaque": {1: ("domain", STR), 2: ("name", STR)},
    "FunctionProto": {1: ("name", STR), 4: ("input", STR), 5: ("output", STR), 6: ("attribute", STR),
                      11: ("attribute_proto", "msg:AttributeProto"), 7: ("node", "msg:NodeProto"),
                      8: ("doc_string", STR), 9: ("opset_import", "msg:OperatorSetIdProto"), 10: ("domain", STR),
                      13: ("overload", STR), 12: ("value_info", "msg:ValueInfoProto"),
                      14: ("metadata_props", "msg:StringStringEntryProto")},
}
_WIRE = {V: 0, F64: 1, F32: 5, STR: 2, BYTES: 2}
_PACKED_WIRE = {PV: 0, PF32: 5, PF64: 1}


def _varint(data, pos: int, end: int) -> tuple[int, int]:
    result = shift = 0
    for i in range(10):
        if pos + i >= end:
            raise Invalid(f"varint at offset {pos} runs past the end of its message")
        byte = data[pos + i]
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if i == 9 and byte > 1:
                raise Invalid(f"varint at offset {pos} is longer than 64 bits")
            return result, pos + i + 1
        shift += 7
    raise Invalid(f"varint at offset {pos} is longer than 10 bytes")


def _signed(value: int) -> int:
    return value - (1 << 64) if value >= 1 << 63 else value


class _Message:
    """One decoded protobuf message: field name -> list of values. Strings are decoded,
    ``bytes`` fields are kept as (offset, length), packed fields as their element count."""

    __slots__ = ("kind", "fields", "start")

    def __init__(self, kind: str, start: int):
        self.kind, self.start, self.fields = kind, start, {}

    def all(self, name: str) -> list:
        return self.fields.get(name, [])

    def one(self, name: str, default=None):
        values = self.fields.get(name)
        return values[-1] if values else default  # protobuf: the last occurrence wins


def _parse_message(data, kind: str, start: int, end: int, depth: int = 0) -> _Message:
    if depth > MAX_DEPTH:
        raise Invalid(f"messages nested deeper than {MAX_DEPTH}")
    schema = ONNX_SCHEMA[kind]
    message = _Message(kind, start)
    pos = start
    while pos < end:
        _charge()
        key, pos = _varint(data, pos, end)
        number, wire = key >> 3, key & 7
        if number not in schema:
            raise Invalid(f"{kind} at offset {start}: field {number} is not in the ONNX schema")
        name, ftype = schema[number]
        if wire == 2:
            length, pos = _varint(data, pos, end)
            if length > end - pos:
                raise Invalid(f"{kind}.{name} at offset {pos}: {length} bytes run past the end of the message")
            body = (pos, pos + length)
            pos += length
            if ftype.startswith("msg:"):
                value = _parse_message(data, ftype[4:], body[0], body[1], depth + 1)
            elif ftype == STR:
                _charge(length)
                try:
                    value = bytes(data[body[0]:body[1]]).decode("utf-8")
                except UnicodeDecodeError:
                    raise Invalid(f"{kind}.{name} at offset {body[0]} is not UTF-8") from None
            elif ftype == BYTES:
                value = body
            elif ftype in _PACKED_WIRE:
                _packed_count(data, body[0], body[1], ftype, f"{kind}.{name}")
                value = ("packed", body[0], body[1])
            else:
                raise Invalid(f"{kind}.{name}: wire type 2 for a {ftype} field")
        elif ftype in _PACKED_WIRE and wire == _PACKED_WIRE[ftype]:  # an unpacked repeated scalar
            if wire == 0:
                value, pos = _varint(data, pos, end)
            else:
                pos = _skip_scalar(data, pos, end, wire)
                value = 0
        elif _WIRE.get(ftype) == wire:
            if wire == 0:
                value, pos = _varint(data, pos, end)
            else:
                size = 8 if wire == 1 else 4
                if pos + size > end:
                    raise Invalid(f"{kind}.{name} at offset {pos} runs past the end of the message")
                value = struct.unpack_from("<d" if wire == 1 else "<f", data, pos)[0]
                pos += size
        else:
            raise Invalid(f"{kind}.{name} at offset {pos}: wire type {wire} does not match the schema ({ftype})")
        message.fields.setdefault(name, []).append(value)
    return message


def _skip_scalar(data, pos: int, end: int, wire: int) -> int:
    if wire == 0:
        return _varint(data, pos, end)[1]
    size = 8 if wire == 1 else 4
    if pos + size > end:
        raise Invalid(f"scalar at offset {pos} runs past the end of the message")
    return pos + size


def _packed_count(data, start: int, end: int, ftype: str, what: str) -> int:
    if ftype == PV:
        count, pos = 0, start
        while pos < end:
            pos = _varint(data, pos, end)[1]
            count += 1
        _charge(count)
        return count
    size = 4 if ftype == PF32 else 8
    if (end - start) % size:
        raise Invalid(f"{what}: packed data of {end - start} bytes is not a multiple of {size}")
    return (end - start) // size


def _packed_ints(data, start: int, end: int) -> list[int]:
    out, pos = [], start
    while pos < end:
        value, pos = _varint(data, pos, end)
        out.append(_signed(value))
    _charge(len(out))
    return out


ONNX_MAX_IR = 14
# ONNX domains whose operators the ONNX specification defines (onnx/defs, onnx.proto).
ONNX_STANDARD_DOMAINS = frozenset({"", "ai.onnx", "ai.onnx.ml", "ai.onnx.training", "ai.onnx.preview.training"})
# TensorProto.DataType -> bits per element (STRING = 8 and UNDEFINED = 0 apart)
ONNX_BITS = {1: 32, 2: 8, 3: 8, 4: 16, 5: 16, 6: 32, 7: 64, 9: 8, 10: 16, 11: 64, 12: 32, 13: 64, 14: 64, 15: 128,
             16: 16, 17: 8, 18: 8, 19: 8, 20: 8, 21: 4, 22: 4, 23: 4, 24: 8, 25: 2, 26: 2, 27: 6, 28: 6}
ONNX_STRING = 8
ONNX_EXTERNAL_KEYS = frozenset({"location", "offset", "length", "checksum", "basepath"})


def looks_like_onnx(data: bytes) -> bool:
    """A cheap content probe: field 1 (ir_version) first with a known value, then a
    length-delimited or varint field of ModelProto. Validity is ``check_onnx``'s job."""
    if len(data) < 4 or data[0] != 0x08:
        return False
    try:
        version, pos = _varint(data, 1, min(len(data), 12))
        key, _ = _varint(data, pos, min(len(data), pos + 3))
    except Invalid:
        return False
    return 1 <= version <= ONNX_MAX_IR and (key >> 3) in ONNX_SCHEMA["ModelProto"] and (key & 7) in (0, 2)


def external_location_problem(location: str) -> str | None:
    """Why an external-data location may not be used (onnx checker.cc rules), or None."""
    if not location:
        return "is empty"
    if "\0" in location:
        return "contains a NUL byte"
    if location.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", location) or location.startswith("~"):
        return "is an absolute path"
    parts = re.split(r"[\\/]+", location)
    if ".." in parts:
        return "leaves the model directory ('..')"
    return None


def _domain_explanation(domain: str) -> str:
    return (f"The ONNX model uses operators from the domain '{domain}', which is not an ONNX standard domain. "
            "A runtime implements such operators with a custom operator library that the loading code registers "
            "(native code, for example onnxruntime's register_custom_ops_library or its built-in contrib ops), "
            "so the scanner cannot see what they do. Accept "
            f"'onnx-domain:{domain}' for this file only if you know which library provides them and trust it.")


def check_onnx(data: bytes, model_dir: str | None = None) -> dict:
    """Facts of a valid ONNX model (``unverifiable``: custom domains); Invalid otherwise."""
    view = memoryview(data)
    model = _parse_message(view, "ModelProto", 0, len(data))
    ir = model.one("ir_version")
    if ir is None or not 1 <= ir <= ONNX_MAX_IR:
        raise Invalid(f"IR version {ir!r} (1 to {ONNX_MAX_IR} are defined)")
    graph = model.one("graph")
    if graph is None:
        raise Invalid("no graph")
    if len(model.all("graph")) > 1:
        raise Invalid("more than one graph field (parsers merge them)")
    functions = {(f.one("domain", ""), f.one("name", ""), f.one("overload", "")) for f in model.all("functions")}
    local_domains = {d for d, _n, _o in functions}
    domains: dict[str, int] = {}
    for opset in model.all("opset_import"):
        domain = opset.one("domain", "")
        if domain in domains:
            raise Invalid(f"opset_import names the domain {domain!r} twice")
        domains[domain] = _signed(opset.one("version", 0))
    if not domains:
        raise Invalid("no opset_import")
    used: set[str] = set()
    state = {"nodes": 0, "tensors": 0, "external": 0}
    graphs = [graph] + [g for t in model.all("training_info") for g in t.all("initialization") + t.all("algorithm")]
    for g in graphs:
        _walk_graph(g, data, used, functions, state, model_dir, 0)
    for function in model.all("functions"):
        for opset in function.all("opset_import"):
            domains.setdefault(opset.one("domain", ""), _signed(opset.one("version", 0)))
        for node in function.all("node"):
            _walk_node(node, data, used, functions, state, model_dir, 1)
    for domain in used:
        if domain not in domains and domain not in ("ai.onnx",):
            raise Invalid(f"a node uses the domain {domain!r}, which opset_import does not declare")
    unverifiable = []
    for domain in sorted(set(domains) | used):
        if domain in ONNX_STANDARD_DOMAINS or (domain in local_domains and domain not in used):
            continue
        unverifiable.append(Unverifiable(f"onnx-domain:{domain}", f"ONNX operators from the custom domain "
                                         f"'{domain}' are implemented by native code outside the file",
                                         _domain_explanation(domain)))
    return {"ir_version": ir, "opsets": dict(sorted(domains.items())), **state, "unverifiable": unverifiable}


def _walk_graph(graph: _Message, data, used: set, functions: set, state: dict, model_dir, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise Invalid(f"graphs nested deeper than {MAX_DEPTH}")
    for tensor in graph.all("initializer"):
        _check_tensor(tensor, data, state, model_dir)
    for sparse in graph.all("sparse_initializer"):
        for part in sparse.all("values") + sparse.all("indices"):
            _check_tensor(part, data, state, model_dir)
    for node in graph.all("node"):
        _walk_node(node, data, used, functions, state, model_dir, depth)


def _walk_node(node: _Message, data, used: set, functions: set, state: dict, model_dir, depth: int) -> None:
    state["nodes"] += 1
    domain = node.one("domain", "")
    if not node.one("op_type"):
        raise Invalid("a node has no op_type")
    if (domain, node.one("op_type"), node.one("overload", "")) not in functions:
        used.add(domain)
    for attribute in node.all("attribute"):
        for tensor in attribute.all("t") + attribute.all("tensors"):
            _check_tensor(tensor, data, state, model_dir)
        for sparse in attribute.all("sparse_tensor") + attribute.all("sparse_tensors"):
            for part in sparse.all("values") + sparse.all("indices"):
                _check_tensor(part, data, state, model_dir)
        for sub in attribute.all("g") + attribute.all("graphs"):
            _walk_graph(sub, data, used, functions, state, model_dir, depth + 1)


def _check_tensor(tensor: _Message, data, state: dict, model_dir: str | None) -> None:
    state["tensors"] += 1
    name = tensor.one("name", "")
    dtype = tensor.one("data_type", 0)
    if dtype != ONNX_STRING and dtype not in ONNX_BITS:
        raise Invalid(f"tensor {name!r}: data type {dtype} is not defined")
    dims = []
    for value in tensor.all("dims"):
        dims += _packed_ints(data, value[1], value[2]) if isinstance(value, tuple) else [_signed(value)]
    if any(d < 0 for d in dims):
        raise Invalid(f"tensor {name!r}: negative dimension")
    location = tensor.one("data_location", 0)
    if location not in (0, 1):
        raise Invalid(f"tensor {name!r}: data_location {location} is not defined")
    if location == 1:
        _check_external(tensor, name, state, model_dir)
        return
    if tensor.all("external_data"):
        raise Invalid(f"tensor {name!r}: external_data on a tensor stored in the file")
    raw = tensor.all("raw_data")
    if raw and dtype in ONNX_BITS and tensor.one("segment") is None:
        start, end = raw[-1]
        need = math.ceil(math.prod(dims) * ONNX_BITS[dtype] / 8)
        if end - start != need:
            raise Invalid(f"tensor {name!r}: {end - start} bytes of raw_data for {need} bytes of data")


def _check_external(tensor: _Message, name: str, state: dict, model_dir: str | None) -> None:
    state["external"] += 1
    entries = {}
    for entry in tensor.all("external_data"):
        key = entry.one("key", "")
        if key not in ONNX_EXTERNAL_KEYS:
            raise Invalid(f"tensor {name!r}: external_data key {key!r} is not one onnx defines")
        if key in entries:
            raise Invalid(f"tensor {name!r}: external_data key {key!r} appears twice")
        entries[key] = entry.one("value", "")
    if "location" not in entries:
        raise Invalid(f"tensor {name!r} is stored externally without a location")
    if "basepath" in entries:
        raise Invalid(f"tensor {name!r}: external_data sets basepath (the data path is decided by the loader)")
    problem = external_location_problem(entries["location"])
    if problem:
        raise Invalid(f"tensor {name!r}: external data location {entries['location']!r} {problem}")
    for key in ("offset", "length"):
        if key in entries and not re.fullmatch(r"[0-9]{1,19}", entries[key]):
            raise Invalid(f"tensor {name!r}: external data {key} {entries[key]!r} is not a non-negative integer")
    if model_dir is not None:
        path = os.path.join(model_dir, *re.split(r"[\\/]+", entries["location"]))
        if os.path.lexists(path):
            real, base = os.path.realpath(path), os.path.realpath(model_dir)
            if os.path.islink(path) or os.path.commonpath([real, base]) != base or not os.path.isfile(real):
                raise Invalid(f"tensor {name!r}: external data {entries['location']!r} is a link or leaves "
                              "the model directory")


# --- flatbuffers (TFLite) ---------------------------------------------------------------

TFLITE_IDENTIFIER = b"TFL3"
TFLITE_SCHEMA_VERSION = 3
TFLITE_CUSTOM = 32
TFLITE_MAX_BUILTIN = 208  # tflite 2.18.0: BuiltinOperator.STABLEHLO_CBRT is the last value
TFLITE_MAX_TENSOR_TYPE = 18  # tflite 2.18.0: TensorType.BFLOAT16 is the last value
FLATBUFFER_MAX_BYTES = 2 ** 31 - 1  # flatbuffers' offsets are 32-bit; data past it is in Buffer.offset


class _Flat:
    """Bounds-checked flatbuffer tables, vectors and strings in ``data[:limit]``."""

    def __init__(self, data, limit: int):
        self.data, self.limit = data, limit

    def u32(self, pos: int) -> int:
        if pos < 0 or pos + 4 > self.limit:
            raise Invalid(f"offset {pos} is outside the flatbuffer")
        return struct.unpack_from("<I", self.data, pos)[0]

    def table(self, pos: int) -> tuple[int, int, int]:
        """(table position, vtable position, vtable size in fields) of the table at ``pos``."""
        _charge()
        if pos % 4 or pos + 4 > self.limit:
            raise Invalid(f"table at offset {pos} is misaligned or outside the flatbuffer")
        (soffset,) = struct.unpack_from("<i", self.data, pos)
        vt = pos - soffset
        if vt < 0 or vt % 2 or vt + 4 > self.limit:
            raise Invalid(f"vtable of the table at offset {pos} is outside the flatbuffer")
        vt_size, obj_size = struct.unpack_from("<HH", self.data, vt)
        if vt_size < 4 or vt_size % 2 or vt + vt_size > self.limit or obj_size < 4 or pos + obj_size > self.limit:
            raise Invalid(f"vtable of the table at offset {pos} has impossible sizes")
        return pos, vt, (vt_size - 4) // 2

    def field(self, table: tuple[int, int, int], index: int, size: int) -> int | None:
        pos, vt, count = table
        if index >= count:
            return None
        (off,) = struct.unpack_from("<H", self.data, vt + 4 + 2 * index)
        if not off:
            return None
        (_, obj_size) = struct.unpack_from("<HH", self.data, vt)
        if off + size > obj_size:
            raise Invalid(f"field {index} of the table at offset {pos} lies outside the table")
        return pos + off

    def scalar(self, table, index: int, fmt: str, default=0):
        at = self.field(table, index, struct.calcsize("<" + fmt))
        return default if at is None else struct.unpack_from("<" + fmt, self.data, at)[0]

    def indirect(self, table, index: int) -> int | None:
        at = self.field(table, index, 4)
        if at is None:
            return None
        target = at + self.u32(at)
        if target >= self.limit:
            raise Invalid(f"offset field {index} at {at} points outside the flatbuffer")
        return target

    def vector(self, table, index: int, elem: int) -> tuple[int, int] | None:
        """(first element position, length) of a vector field."""
        at = self.indirect(table, index)
        if at is None:
            return None
        if at % 4:
            raise Invalid(f"vector at offset {at} is misaligned")
        length = self.u32(at)
        if length * elem > self.limit - at - 4:
            raise Invalid(f"vector of {length} elements at offset {at} runs past the end of the flatbuffer")
        _charge(length)
        return at + 4, length

    def string(self, table, index: int) -> str | None:
        vec = self.vector(table, index, 1)
        if vec is None:
            return None
        start, length = vec
        if start + length >= self.limit or self.data[start + length] != 0:
            raise Invalid(f"string at offset {start} is not NUL-terminated")
        try:
            return bytes(self.data[start:start + length]).decode("utf-8")
        except UnicodeDecodeError:
            raise Invalid(f"string at offset {start} is not UTF-8") from None

    def tables(self, table, index: int) -> list[tuple[int, int, int]]:
        vec = self.vector(table, index, 4)
        if vec is None:
            return []
        start, length = vec
        return [self.table(start + 4 * i + self.u32(start + 4 * i)) for i in range(length)]

    def ints(self, table, index: int, fmt: str = "i") -> list[int]:
        vec = self.vector(table, index, struct.calcsize("<" + fmt))
        if vec is None:
            return []
        start, length = vec
        return list(struct.unpack_from(f"<{length}{fmt}", self.data, start))


def _custom_op_explanation(code: str) -> str:
    return (f"The TFLite model uses the custom operator '{code}'. The interpreter runs it with a kernel the "
            "loading code registers (native code, or TensorFlow itself for Flex ops), so the scanner cannot see "
            f"what it does. Accept 'tflite-custom-op:{code}' for this file only if you know which kernel "
            "provides it and trust it.")


def check_tflite(data: bytes) -> dict:
    """Facts of a valid TFLite flatbuffer (``unverifiable``: custom operators); Invalid otherwise."""
    if len(data) < 8 or data[4:8] != TFLITE_IDENTIFIER:
        raise Invalid("no TFL3 file identifier")
    view = memoryview(data)
    fb = _Flat(view, min(len(data), FLATBUFFER_MAX_BYTES))
    model = fb.table(fb.u32(0))
    version = fb.scalar(model, 0, "I")
    if version != TFLITE_SCHEMA_VERSION:
        raise Invalid(f"schema version {version} (this reader knows {TFLITE_SCHEMA_VERSION})")
    codes = []
    unverifiable = []
    for code in fb.tables(model, 1):
        deprecated = fb.scalar(code, 0, "b")
        builtin = max(deprecated, fb.scalar(code, 3, "i"))
        custom = fb.string(code, 1)
        if builtin == TFLITE_CUSTOM or (deprecated == TFLITE_CUSTOM):
            name = custom or "<unnamed>"
            if not any(u.item == f"tflite-custom-op:{name}" for u in unverifiable):
                unverifiable.append(Unverifiable(f"tflite-custom-op:{name}",
                                                 f"TFLite custom operator '{name}' is implemented by native code "
                                                 "outside the file", _custom_op_explanation(name)))
        elif not 0 <= builtin <= TFLITE_MAX_BUILTIN:
            raise Invalid(f"builtin operator code {builtin} is not one this reader knows")
        codes.append(builtin)
    buffers = fb.tables(model, 4)
    for i, buffer in enumerate(buffers):
        fb.vector(buffer, 0, 1)
        offset, size = fb.scalar(buffer, 1, "Q"), fb.scalar(buffer, 2, "Q")
        if offset > 1 and offset + size > len(data):
            raise Invalid(f"buffer {i}: {size} bytes at offset {offset} run past the end of the file")
    subgraphs = fb.tables(model, 2)
    if not subgraphs:
        raise Invalid("no subgraph")
    operators = 0
    for s, subgraph in enumerate(subgraphs):
        tensors = fb.tables(subgraph, 0)
        for t, tensor in enumerate(tensors):
            fb.ints(tensor, 0)
            if not 0 <= fb.scalar(tensor, 1, "b") <= TFLITE_MAX_TENSOR_TYPE:
                raise Invalid(f"subgraph {s} tensor {t}: tensor type is not defined")
            if fb.scalar(tensor, 2, "I") >= max(len(buffers), 1):
                raise Invalid(f"subgraph {s} tensor {t}: buffer index outside the buffer list")
            fb.string(tensor, 3)
        for index in fb.ints(subgraph, 1) + fb.ints(subgraph, 2):
            if not -1 <= index < len(tensors):
                raise Invalid(f"subgraph {s}: input or output tensor index {index} outside the tensor list")
        for o, operator in enumerate(fb.tables(subgraph, 3)):
            operators += 1
            if fb.scalar(operator, 0, "I") >= len(codes):
                raise Invalid(f"subgraph {s} operator {o}: opcode index outside the operator codes")
            for index in fb.ints(operator, 1) + fb.ints(operator, 2):
                if not -1 <= index < len(tensors):
                    raise Invalid(f"subgraph {s} operator {o}: tensor index {index} outside the tensor list")
            for slot in (4, 12):  # builtin_options, builtin_options_2: union tables
                at = fb.indirect(operator, slot)
                if at is not None:
                    fb.table(at)
            fb.vector(operator, 5, 1)  # custom_options
            large_offset, large_size = fb.scalar(operator, 9, "Q"), fb.scalar(operator, 10, "Q")
            if large_offset > 1 and large_offset + large_size > len(data):
                raise Invalid(f"subgraph {s} operator {o}: custom options run past the end of the file")
    for metadata in fb.tables(model, 6):
        fb.string(metadata, 0)
        if fb.scalar(metadata, 1, "I") >= max(len(buffers), 1):
            raise Invalid("metadata buffer index outside the buffer list")
    fb.string(model, 3)
    return {"subgraphs": len(subgraphs), "operators": operators, "operator_codes": len(codes),
            "buffers": len(buffers), "unverifiable": unverifiable}


# --- msgpack (Flax / JAX checkpoints) ---------------------------------------------------

FLAX_DTYPES = {"bool": 1, "int8": 1, "int16": 2, "int32": 4, "int64": 8, "uint8": 1, "uint16": 2, "uint32": 4,
               "uint64": 8, "float16": 2, "bfloat16": 2, "float32": 4, "float64": 8, "complex64": 8,
               "complex128": 16}
FLAX_NDARRAY, FLAX_COMPLEX, FLAX_SCALAR = 1, 2, 3


class _Pack:
    """A strict msgpack walker: every object of the msgpack specification except ext types
    other than Flax's three, which are checked as Flax decodes them."""

    def __init__(self, data, start: int, end: int):
        self.data, self.pos, self.end = data, start, end

    def take(self, size: int, what: str):
        if size > self.end - self.pos:
            raise Invalid(f"{what} at offset {self.pos} ({size} bytes) runs past the end")
        start = self.pos
        self.pos += size
        return start

    def unpack(self, fmt: str, what: str):
        start = self.take(struct.calcsize(">" + fmt), what)
        return struct.unpack_from(">" + fmt, self.data, start)[0]

    def value(self, depth: int = 0, keep: bool = False):
        """The next object: for containers a marker, for scalars the value when ``keep``."""
        if depth > MAX_DEPTH:
            raise Invalid(f"containers nested deeper than {MAX_DEPTH}")
        _charge()
        b = self.data[self.take(1, "type byte")]
        if b <= 0x7F or b >= 0xE0:
            return b if b <= 0x7F else b - 0x100
        if 0x80 <= b <= 0x8F:
            return self._map(b & 0x0F, depth, keep)
        if 0x90 <= b <= 0x9F:
            return self._array(b & 0x0F, depth, keep)
        if 0xA0 <= b <= 0xBF:
            return self._str(b & 0x1F, keep)
        simple = {0xC0: None, 0xC2: False, 0xC3: True}
        if b in simple:
            return simple[b]
        if b == 0xC1:
            raise Invalid(f"byte 0xc1 at offset {self.pos - 1} is never used by msgpack")
        sizes = {0xC4: "B", 0xC5: "H", 0xC6: "I"}
        if b in sizes:
            start = self.take(self.unpack(sizes[b], "bin length"), "bin")
            return (start, self.pos) if keep else None
        ext = {0xC7: "B", 0xC8: "H", 0xC9: "I"}
        if b in ext:
            return self._ext(self.unpack(ext[b], "ext length"), depth)
        fixed_ext = {0xD4: 1, 0xD5: 2, 0xD6: 4, 0xD7: 8, 0xD8: 16}
        if b in fixed_ext:
            return self._ext(fixed_ext[b], depth)
        numbers = {0xCA: "f", 0xCB: "d", 0xCC: "B", 0xCD: "H", 0xCE: "I", 0xCF: "Q",
                   0xD0: "b", 0xD1: "h", 0xD2: "i", 0xD3: "q"}
        if b in numbers:
            return self.unpack(numbers[b], "number")
        if b in (0xD9, 0xDA, 0xDB):
            return self._str(self.unpack({0xD9: "B", 0xDA: "H", 0xDB: "I"}[b], "str length"), keep)
        if b in (0xDC, 0xDD):
            return self._array(self.unpack("H" if b == 0xDC else "I", "array length"), depth, keep)
        return self._map(self.unpack("H" if b == 0xDE else "I", "map length"), depth, keep)

    def _str(self, length: int, keep: bool):
        start = self.take(length, "str")
        try:
            text = bytes(self.data[start:self.pos]).decode("utf-8")
        except UnicodeDecodeError:
            raise Invalid(f"str at offset {start} is not UTF-8") from None
        return text if keep else None

    def _array(self, count: int, depth: int, keep: bool):
        if count > self.end - self.pos:
            raise Invalid(f"array of {count} items cannot fit in the {self.end - self.pos} bytes left")
        items = [self.value(depth + 1, keep) for _ in range(count)]
        return items if keep else None

    def _map(self, count: int, depth: int, keep: bool):
        if 2 * count > self.end - self.pos:
            raise Invalid(f"map of {count} entries cannot fit in the {self.end - self.pos} bytes left")
        keys = set()
        for _ in range(count):
            at = self.pos
            if at >= self.end or not _plain_key(self.data[at]):
                raise Invalid(f"map key at offset {at} is not a string or an integer")
            key = self.value(depth + 1, True)
            if key in keys:
                raise Invalid(f"map key {key!r} appears twice (loaders disagree on which one counts)")
            keys.add(key)
            self.value(depth + 1, keep)
        return None

    def _ext(self, length: int, depth: int):
        code = struct.unpack(">b", bytes(self.data[self.take(1, "ext type"):self.pos]))[0]
        start = self.take(length, "ext data")
        if code == FLAX_COMPLEX:
            inner = _Pack(self.data, start, self.pos)
            pair = inner.value(depth + 1, True)
            if inner.pos != inner.end or not (isinstance(pair, list) and len(pair) == 2
                                              and all(isinstance(x, int | float) for x in pair)):
                raise Invalid(f"ext type 2 (complex) at offset {start} is not two numbers")
            return None
        if code in (FLAX_NDARRAY, FLAX_SCALAR):
            _flax_array(self.data, start, self.pos, code, depth)
            return None
        raise Invalid(f"ext type {code} at offset {start}: not one Flax writes (an opaque object to the loader)")


def _plain_key(b: int) -> bool:
    """A msgpack type byte of a str or an integer (Flax keys are strings, lists become
    string indices; ``msgpack_restore`` passes strict_map_key=False)."""
    return b <= 0x7F or b >= 0xE0 or 0xA0 <= b <= 0xBF or b in (0xD9, 0xDA, 0xDB) or 0xCC <= b <= 0xD3


def _flax_array(data, start: int, end: int, code: int, depth: int) -> None:
    inner = _Pack(data, start, end)
    triple = inner.value(depth + 1, True)
    if inner.pos != inner.end or not (isinstance(triple, list) and len(triple) == 3):
        raise Invalid(f"ext type {code} at offset {start} is not (shape, dtype, buffer)")
    shape, dtype, buffer = triple
    if not (isinstance(shape, list) and all(type(d) is int and d >= 0 for d in shape)):
        raise Invalid(f"array at offset {start}: shape is not a list of non-negative integers")
    if isinstance(dtype, tuple):
        dtype = bytes(data[dtype[0]:dtype[1]]).decode("ascii", "replace")
    if dtype not in FLAX_DTYPES:
        raise Invalid(f"array at offset {start}: dtype {dtype!r} is not a numeric dtype")
    if not isinstance(buffer, tuple):
        raise Invalid(f"array at offset {start}: buffer is not bytes")
    need = math.prod(shape) * FLAX_DTYPES[dtype]
    if buffer[1] - buffer[0] != need:
        raise Invalid(f"array at offset {start}: {buffer[1] - buffer[0]} bytes for {need} bytes of data")
    if code == FLAX_SCALAR and shape:
        raise Invalid(f"scalar at offset {start} has a shape")


def check_msgpack(data: bytes) -> dict:
    """Facts of a valid Flax msgpack checkpoint: one msgpack object that is a map, whose
    leaves are plain numbers, strings, booleans, nil or Flax arrays; Invalid otherwise."""
    if not data or not (0x80 <= data[0] <= 0x8F or data[0] in (0xDE, 0xDF)):
        raise Invalid("does not start with a msgpack map")
    reader = _Pack(memoryview(data), 0, len(data))
    reader.value()
    if reader.pos != len(data):
        raise Invalid(f"{len(data) - reader.pos} bytes after the msgpack object (trailing data)")
    return {"bytes": len(data)}


# --- OpenVINO IR ------------------------------------------------------------------------

OPENVINO_IR_VERSIONS = ("10", "11")
OPENVINO_TOP = frozenset({"layers", "edges", "rt_info", "meta_data", "quantization_parameters", "statistics"})
# element_type -> bits (openvino/core/type/element_type.hpp); string tensors apart
OPENVINO_BITS = {"boolean": 8, "bf16": 16, "f16": 16, "f32": 32, "f64": 64, "i4": 4, "i8": 8, "i16": 16, "i32": 32,
                 "i64": 64, "u1": 1, "u2": 2, "u3": 3, "u4": 4, "u6": 6, "u8": 8, "u16": 16, "u32": 32, "u64": 64,
                 "nf4": 4, "f8e4m3": 8, "f8e5m2": 8, "f4e2m1": 4, "f8e8m0": 8}


@lru_cache(maxsize=1)
def openvino_opsets() -> dict[str, frozenset[str]]:
    from .upstream import _load

    data = _load("openvino_opsets.json")
    return {name: frozenset(ops) for name, ops in data["opsets"].items()}


def looks_like_openvino_xml(data: bytes) -> bool:
    head = data[:512].lstrip(b"\xef\xbb\xbf \t\r\n")
    return (head.startswith(b"<?xml") and b"<net " in data[:4096]) or head.startswith(b"<net ")


def _parse_xml(data: bytes):
    """An element tree from expat with DOCTYPE, entity declarations and external entities
    refused (they are the XML features that read other files or expand without bound)."""
    import xml.parsers.expat as expat

    if len(data) > MAX_COMPANION_BYTES:
        raise Invalid(f"XML of {len(data)} bytes (limit {MAX_COMPANION_BYTES})")
    parser = expat.ParserCreate()
    root: list = []
    stack: list = []

    def refuse(*_args):
        raise Invalid("the XML declares a DTD or entities (refused: they can read other files)")

    def start(tag, attrs):
        _charge()
        node = (tag, dict(attrs), [])
        (stack[-1][2] if stack else root).append(node)
        stack.append(node)

    def end(_tag):
        stack.pop()

    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    parser.UnparsedEntityDeclHandler = refuse
    parser.ExternalEntityRefHandler = refuse
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise Invalid(f"not well-formed XML: {exc}") from None
    if len(root) != 1:
        raise Invalid("not one root element")
    return root[0]


def _openvino_explanation(op: str) -> str:
    return (f"The OpenVINO IR uses the layer {op}, which is in no standard OpenVINO opset. OpenVINO runs such "
            "layers with an extension library the loading code adds (core.add_extension, native code), so the "
            f"scanner cannot see what they do. Accept 'openvino-op:{op}' for this file only if you know which "
            "extension provides it and trust it.")


def check_openvino_xml(data: bytes, bin_size: int | None) -> dict:
    """Facts of a valid OpenVINO IR ``.xml`` (``unverifiable``: layers outside the standard
    opsets); Invalid otherwise. ``bin_size`` is the size of the ``.bin`` beside it (None
    when there is none); every Const layer must lie inside it."""
    tag, attrs, children = _parse_xml(data)
    if tag != "net":
        raise Invalid(f"root element is <{tag}>, not <net>")
    if attrs.get("version") not in OPENVINO_IR_VERSIONS:
        raise Invalid(f"IR version {attrs.get('version')!r} (10 and 11 are read)")
    names = [c[0] for c in children]
    for name in names:
        if name not in OPENVINO_TOP:
            raise Invalid(f"unexpected element <{name}> in <net>")
        if names.count(name) > 1:
            raise Invalid(f"<{name}> appears twice in <net>")
    if "layers" not in names:
        raise Invalid("no <layers>")
    opsets = openvino_opsets()
    unverifiable, ids, consts = [], set(), 0
    weights = 0
    for layer in next(c for c in children if c[0] == "layers")[2]:
        ltag, la, lchildren = layer
        if ltag != "layer":
            raise Invalid(f"unexpected element <{ltag}> in <layers>")
        lid, ltype, version = la.get("id"), la.get("type"), la.get("version")
        if lid is None or ltype is None or lid in ids:
            raise Invalid(f"layer {la.get('name')!r}: missing or repeated id, or no type")
        ids.add(lid)
        if version not in opsets or ltype not in opsets[version]:
            item = f"openvino-op:{version}.{ltype}"
            if not any(u.item == item for u in unverifiable):
                unverifiable.append(Unverifiable(item, f"OpenVINO layer {version}.{ltype} is in no standard "
                                                 "opset; an extension library (native code) implements it",
                                                 _openvino_explanation(f"{version}.{ltype}")))
        if ltype == "Const" and version in opsets:
            consts += 1
            data_el = next((c for c in lchildren if c[0] == "data"), None)
            if data_el is None:
                raise Invalid(f"Const layer {lid} has no <data>")
            weights = max(weights, _const_extent(lid, data_el[1], bin_size))
    if "edges" in names:
        for edge in next(c for c in children if c[0] == "edges")[2]:
            if edge[0] != "edge" or edge[1].get("from-layer") not in ids or edge[1].get("to-layer") not in ids:
                raise Invalid("an edge refers to a layer that does not exist")
    return {"ir_version": attrs["version"], "layers": len(ids), "consts": consts, "weights_bytes": weights,
            "unverifiable": unverifiable}


def _const_extent(lid: str, d: dict, bin_size: int | None) -> int:
    """End of the weights a Const reads, checked against its shape and the ``.bin``."""
    try:
        offset, size = int(d.get("offset", "")), int(d.get("size", ""))
    except ValueError:
        raise Invalid(f"Const layer {lid}: offset or size is not an integer") from None
    if offset < 0 or size < 0:
        raise Invalid(f"Const layer {lid}: negative offset or size")
    element = d.get("element_type")
    shape = d.get("shape", "")
    if element in OPENVINO_BITS:
        try:
            dims = [int(x) for x in shape.split(",")] if shape.strip() else []
        except ValueError:
            raise Invalid(f"Const layer {lid}: shape {shape!r} is not a list of integers") from None
        if any(x < 0 for x in dims):
            raise Invalid(f"Const layer {lid}: negative dimension")
        need = math.ceil(math.prod(dims) * OPENVINO_BITS[element] / 8)
        # XmlDeserializer::set_constant_num_buffer throws only when size < need; a larger
        # region (openvino_tokenizers writes size 1 for an empty tensor) is read the same way,
        # range-checked against the .bin (DECISIONS.md, 0.10.0 structure relaxations).
        if size < need:
            raise Invalid(f"Const layer {lid}: {size} bytes for a {element} tensor of shape [{shape}] "
                          f"({need} bytes)")
    elif element != "string":
        raise Invalid(f"Const layer {lid}: element type {element!r} is not one this reader knows")
    if bin_size is None:
        raise Invalid(f"Const layer {lid} reads weights, and there is no .bin beside the .xml")
    if offset + size > bin_size:
        raise Invalid(f"Const layer {lid}: {size} bytes at offset {offset} run past the end of the .bin "
                      f"({bin_size} bytes)")
    return offset + size


# --- Core ML weights (MIL blob storage) -------------------------------------------------

COREML_SENTINEL = 0xDEADBEEF
COREML_ALIGN = 64
# BlobDataType -> bits per element (coremltools 9.0 BlobDataType.hpp)
COREML_BITS = {1: 16, 2: 32, 3: 8, 4: 8, 5: 16, 6: 16, 7: 16, 8: 4, 9: 1, 10: 2, 11: 4, 12: 3, 13: 6,
               14: 32, 15: 32, 16: 8, 17: 8}


def looks_like_coreml_weights(data: bytes) -> bool:
    """A MIL blob storage file: a 64-byte header with version 2 and at least one blob
    whose metadata starts with the sentinel right after the header."""
    return (len(data) >= COREML_ALIGN + 4 and data[4:8] == b"\x02\0\0\0"
            and int.from_bytes(data[:4], "little") > 0
            and int.from_bytes(data[64:68], "little") == COREML_SENTINEL)


def _align(n: int) -> int:
    return -(-n // COREML_ALIGN) * COREML_ALIGN


def check_coreml_weights(data: bytes) -> dict:
    """Facts of a valid Core ML ``weight.bin``: the blobs ``StorageReader::GetAllOffsets``
    walks (metadata at the next 64-byte boundary after the previous blob's data, each
    with the sentinel, a known data type, its data right after it, inside the file, and
    padding the reader accepts), zero bytes between them and nothing after the last one;
    Invalid otherwise. The reserved fields of a blob's metadata are not checked, nor its
    padding for byte-sized types: before iOS 18 the writer left them uninitialised and the
    reader ignores them."""
    size = len(data)
    if size < COREML_ALIGN:
        raise Invalid("shorter than the 64-byte storage header")
    count, version = struct.unpack_from("<II", data, 0)
    if version != 2:
        raise Invalid(f"storage version {version} (the reader accepts only 2)")
    if any(data[8:COREML_ALIGN]):
        raise Invalid("reserved fields of the storage header are not zero")
    pos = end = COREML_ALIGN
    for index in range(count):
        _charge()
        if pos + COREML_ALIGN > size:
            raise Invalid(f"blob {index}: metadata at offset {pos} runs past the end of the file ({size} bytes)")
        sentinel, dtype, length, offset, padding = struct.unpack_from("<IIQQQ", data, pos)
        if sentinel != COREML_SENTINEL:
            raise Invalid(f"blob {index}: no sentinel in the metadata at offset {pos}")
        bits = COREML_BITS.get(dtype)
        if bits is None:
            raise Invalid(f"blob {index}: data type {dtype} is not one the reader knows")
        if offset != pos + COREML_ALIGN:
            raise Invalid(f"blob {index}: data at offset {offset}, not right after its metadata ({pos + COREML_ALIGN})")
        if not length:
            raise Invalid(f"blob {index} is empty (the reader's Span::Slice refuses a zero-length read)")
        if offset + length > size:
            raise Invalid(f"blob {index}: {length} bytes at offset {offset} run past the end of the file ({size} bytes)")
        if bits % 8 == 0:
            # GetDataViewForByteAligned never reads padding_size_in_bits, which was a
            # reserved (uninitialised) field before sub-byte types. SpanCast would drop a
            # partial element; no writer makes one, so it is refused here.
            if length % (bits // 8):
                raise Invalid(f"blob {index}: {length} bytes for {bits}-bit elements")
        elif padding >= 8 or (length * 8 - padding) % bits or (bits in (1, 2, 4) and padding % bits):
            raise Invalid(f"blob {index}: {padding} padding bits for {bits}-bit elements in {length} bytes")
        end = offset + length
        pos = _align(end)
        if index + 1 < count and any(data[end:min(pos, size)]):
            raise Invalid(f"blob {index}: non-zero bytes between its data and the next blob")
    if size not in (end, pos) or any(data[end:size]):
        raise Invalid(f"{size - end} bytes after the last blob (trailing data)")
    return {"bytes": size, "blobs": count}


# --- CTranslate2 model.bin --------------------------------------------------------------

CT2_MAX_VERSION = 6  # CURRENT_BINARY_VERSION in 4.6.0
# model_factory.cc register_supported_models (the empty spec name is binary version 1's)
CT2_SPECS = frozenset({"TransformerBase", "TransformerBig", "TransformerSpec", "TransformerDecoderSpec",
                       "TransformerEncoderSpec", "WhisperSpec", "Wav2Vec2Spec", "Wav2Vec2BertSpec"})
CT2_ITEM_SIZES = (4, 1, 2, 4, 2, 2)  # DataType: FLOAT32, INT8, INT16, INT32, FLOAT16, BFLOAT16


def looks_like_ctranslate2(data: bytes) -> bool:
    """A CTranslate2 ``model.bin``: binary version 2 to 6, then a registered spec name."""
    if len(data) < 8 or not 2 <= int.from_bytes(data[:4], "little") <= CT2_MAX_VERSION:
        return False
    n = int.from_bytes(data[4:6], "little")
    return n >= 2 and data[6 + n - 1:6 + n] == b"\0" and data[6:5 + n].decode("ascii", "replace") in CT2_SPECS


class _Stream:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def take(self, n: int, what: str) -> bytes:
        if self.pos + n > len(self.data):
            raise Invalid(f"{what} at offset {self.pos} runs past the end of the file ({len(self.data)} bytes)")
        self.pos += n
        return self.data[self.pos - n:self.pos]

    def u(self, fmt: str, what: str) -> int:
        return struct.unpack(fmt, self.take(struct.calcsize(fmt), what))[0]

    def string(self, what: str) -> str:
        # consume<std::string> builds std::string(c_str): the length counts a final NUL,
        # and a missing one makes the runtime read past its buffer
        n = self.u("<H", what)
        raw = self.take(n, what) if n else b""
        if not raw or raw[-1:] != b"\0" or b"\0" in raw[:-1]:
            raise Invalid(f"{what} ending at offset {self.pos} is not one NUL-terminated string")
        try:
            return raw[:-1].decode("ascii")
        except UnicodeDecodeError:
            raise Invalid(f"{what} ending at offset {self.pos} is not ASCII (the writer counts characters, "
                          "not bytes)") from None


def check_ctranslate2(data: bytes) -> dict:
    """Facts of a valid CTranslate2 ``model.bin``: the layout ``Model::load`` reads for its
    binary version, a registered spec, every variable's byte count equal to its shape
    times its type's size (the runtime reads that many bytes into a buffer sized by the
    shape), unique names, aliases of existing variables and nothing after the aliases;
    Invalid otherwise."""
    st = _Stream(data)
    version = st.u("<I", "binary version")
    if not 1 <= version <= CT2_MAX_VERSION:
        raise Invalid(f"binary version {version} (the reader knows 1 to {CT2_MAX_VERSION})")
    spec = ""
    if version >= 2:
        spec = st.string("spec name")
        st.u("<I", "spec revision")
    if spec not in CT2_SPECS and not (version == 1 and spec == ""):
        raise Invalid(f"spec {spec!r} is not one the runtime registers")
    names: set[str] = set()
    for index in range(st.u("<I", "variable count")):
        _charge()
        name = st.string(f"variable {index} name")
        if name in names:
            raise Invalid(f"variable {name!r} appears twice")
        names.add(name)
        rank = st.u("<B", f"variable {name!r} rank")
        shape = struct.unpack(f"<{rank}I", st.take(4 * rank, f"variable {name!r} shape"))
        if version >= 4:
            dtype = st.u("<B", f"variable {name!r} type")
            if dtype >= len(CT2_ITEM_SIZES):
                raise Invalid(f"variable {name!r}: data type {dtype} is not one the runtime knows")
            item = CT2_ITEM_SIZES[dtype]
            length = st.u("<I", f"variable {name!r} size")
        else:
            item = st.u("<B", f"variable {name!r} item size")
            if item not in (1, 2, 4):
                raise Invalid(f"variable {name!r}: item size {item} is not one the runtime knows")
            length = st.u("<I", f"variable {name!r} size") * item
        if length != math.prod(shape) * item:
            raise Invalid(f"variable {name!r}: {length} bytes for shape {list(shape)} of {item}-byte items")
        st.take(length, f"variable {name!r} data")
    aliases = 0
    if version >= 3:
        aliases = st.u("<I", "alias count")
        for index in range(aliases):
            _charge()
            alias = st.string(f"alias {index}")
            target = st.string(f"alias {alias!r} target")
            if alias in names or target not in names:
                raise Invalid(f"alias {alias!r} -> {target!r} does not name one existing variable by a new name")
            names.add(alias)
    if st.pos != len(data):
        raise Invalid(f"{len(data) - st.pos} bytes after the aliases (trailing data)")
    return {"bytes": len(data), "binary_version": version, "spec": spec, "variables": len(names) - aliases}


# --- whisper.cpp legacy ggml model ------------------------------------------------------

GGML_MAGIC = b"lmgg"  # GGML_FILE_MAGIC 0x67676d6c, little-endian
# ggml_type -> (block size, bytes per block) for the types whisper.cpp stores
GGML_TYPES = {0: (1, 4), 1: (1, 2), 2: (32, 18), 3: (32, 20), 6: (32, 22), 7: (32, 24), 8: (32, 34),
              10: (256, 84), 11: (256, 110), 12: (256, 144), 13: (256, 176), 14: (256, 210)}
# ggml_ftype -> the weights' ggml_type (ggml_ftype_to_ggml_type); other ftypes are not read here
GGML_FTYPES = {0: 0, 1: 1, 2: 2, 3: 3, 7: 8, 8: 6, 9: 7, 10: 10, 11: 11, 12: 12, 13: 13, 14: 14}
# English-only, multilingual and large-v3 vocabularies: whisper.cpp derives the language
# count from n_vocab and indexes its language table with it
WHISPER_VOCABS = (51864, 51865, 51866)
_I32_MAX = 2 ** 31 - 1


def looks_like_ggml_whisper(data: bytes) -> bool:
    """A whisper.cpp ggml model: the ggml magic, then hyperparameters with a vocabulary size
    and weight type whisper.cpp knows."""
    if len(data) < 48 or not data.startswith(GGML_MAGIC):
        return False
    n_vocab, ftype = struct.unpack_from("<i", data, 4)[0], struct.unpack_from("<i", data, 44)[0]
    return n_vocab in WHISPER_VOCABS and ftype >= 0 and ftype % 1000 in GGML_FTYPES


def _whisper_tensors(h: dict, wtype: int) -> dict[str, tuple[tuple[int, ...], int]]:
    """name -> (ne padded to 3, ggml_type), as whisper_model_load creates them."""
    f32, vtype = 0, 0 if wtype == 0 else 1
    a, t = h["n_audio_state"], h["n_text_state"]
    out = {"encoder.positional_embedding": ((a, h["n_audio_ctx"], 1), f32),
           "encoder.conv1.weight": ((3, h["n_mels"], a), vtype), "encoder.conv1.bias": ((1, a, 1), f32),
           "encoder.conv2.weight": ((3, a, a), vtype), "encoder.conv2.bias": ((1, a, 1), f32),
           "encoder.ln_post.weight": ((a, 1, 1), f32), "encoder.ln_post.bias": ((a, 1, 1), f32),
           "decoder.positional_embedding": ((t, h["n_text_ctx"], 1), f32),
           "decoder.token_embedding.weight": ((t, h["n_vocab"], 1), wtype),
           "decoder.ln.weight": ((t, 1, 1), f32), "decoder.ln.bias": ((t, 1, 1), f32)}

    def block(prefix: str, n: int, attn: tuple[str, ...]) -> None:
        out.update({f"{prefix}.mlp_ln.weight": ((n, 1, 1), f32), f"{prefix}.mlp_ln.bias": ((n, 1, 1), f32),
                    f"{prefix}.mlp.0.weight": ((n, 4 * n, 1), wtype), f"{prefix}.mlp.0.bias": ((4 * n, 1, 1), f32),
                    f"{prefix}.mlp.2.weight": ((4 * n, n, 1), wtype), f"{prefix}.mlp.2.bias": ((n, 1, 1), f32)})
        for kind in attn:
            out.update({f"{prefix}.{kind}_ln.weight": ((n, 1, 1), f32), f"{prefix}.{kind}_ln.bias": ((n, 1, 1), f32)})
            for part in ("query", "key", "value", "out"):
                out[f"{prefix}.{kind}.{part}.weight"] = ((n, n, 1), wtype)
                if part != "key":
                    out[f"{prefix}.{kind}.{part}.bias"] = ((n, 1, 1), f32)

    for i in range(h["n_audio_layer"]):
        block(f"encoder.blocks.{i}", a, ("attn",))
    for i in range(h["n_text_layer"]):
        block(f"decoder.blocks.{i}", t, ("attn", "cross_attn"))
    return out


_WHISPER_HPARAMS = ("n_vocab", "n_audio_ctx", "n_audio_state", "n_audio_head", "n_audio_layer", "n_text_ctx",
                    "n_text_state", "n_text_head", "n_text_layer", "n_mels", "ftype")


def check_ggml_whisper(data: bytes) -> dict:
    """Facts of a valid whisper.cpp ggml model: what ``whisper_model_load`` reads (magic,
    hyperparameters, mel filters, vocabulary, then tensors up to the end of the file),
    with every tensor one the model has, of its shape and type, each exactly once, and no
    bytes after the last one; Invalid otherwise. The reader writes up to four dimensions
    into a four-element array and multiplies element counts in 32 bits, so more than four
    dimensions or a count past 2**31 is refused before anything else."""
    st = _Stream(data)
    if st.take(4, "magic") != GGML_MAGIC:
        raise Invalid("no ggml magic")
    h = dict(zip(_WHISPER_HPARAMS, struct.unpack("<11i", st.take(44, "hyperparameters"))))
    if h["n_vocab"] not in WHISPER_VOCABS:
        raise Invalid(f"vocabulary size {h['n_vocab']} is not a whisper one")
    if any(h[k] <= 0 for k in _WHISPER_HPARAMS[:10]) or h["n_text_state"] != h["n_audio_state"]:
        raise Invalid("hyperparameters are not positive, or the text and audio widths differ")
    if h["ftype"] < 0 or h["ftype"] % 1000 not in GGML_FTYPES:
        raise Invalid(f"ftype {h['ftype']} is not one this reader knows")
    if max(h["n_audio_layer"], h["n_text_layer"]) > 1024 or 4 * h["n_audio_state"] * h["n_audio_state"] > _I32_MAX:
        raise Invalid("hyperparameters describe tensors past the reader's 32-bit counts")
    wtype = GGML_FTYPES[h["ftype"] % 1000]
    n_mel, n_fft = struct.unpack("<ii", st.take(8, "mel filter size"))
    if n_mel < 0 or n_fft < 0:
        raise Invalid("negative mel filter size")
    st.take(4 * n_mel * n_fft, "mel filters")
    n_vocab = st.u("<i", "vocabulary count")
    if not 0 <= n_vocab <= h["n_vocab"]:
        raise Invalid(f"{n_vocab} vocabulary entries for a vocabulary of {h['n_vocab']}")
    for index in range(n_vocab):
        if index % 1024 == 0:
            _charge()
        st.take(st.u("<I", f"token {index} length"), f"token {index}")
    expected = _whisper_tensors(h, wtype)
    seen: set[str] = set()
    while st.pos < len(data):
        _charge()
        n_dims, length, ttype = struct.unpack("<iii", st.take(12, "tensor header"))
        if not 1 <= n_dims <= 4 or length <= 0:
            raise Invalid(f"tensor header at offset {st.pos - 12}: {n_dims} dimensions, name of {length} bytes")
        ne = struct.unpack(f"<{n_dims}i", st.take(4 * n_dims, "tensor shape"))
        name = st.take(length, "tensor name").decode("ascii", "replace")
        if name not in expected or name in seen:
            raise Invalid(f"tensor {name!r} is not one the model has, or appears twice")
        seen.add(name)
        shape, want = expected[name]
        if any(n <= 0 for n in ne) or math.prod(ne) > _I32_MAX or tuple((*ne, 1, 1, 1)[:3]) != shape \
                or math.prod(ne) != math.prod(shape):
            raise Invalid(f"tensor {name!r}: shape {list(ne)}, expected {list(shape)}")
        if ttype != want:
            raise Invalid(f"tensor {name!r}: type {ttype}, the model reads type {want}")
        block, size = GGML_TYPES[want]
        if shape[0] % block:
            raise Invalid(f"tensor {name!r}: rows of {shape[0]} are not whole blocks of {block}")
        st.take(math.prod(shape) // block * size, f"tensor {name!r} data")
    if seen and seen != set(expected):
        raise Invalid(f"{len(expected) - len(seen)} of the model's tensors are missing")
    return {"bytes": len(data), "tensors": len(seen)}


CHECKS = {ONNX: check_onnx, TFLITE: check_tflite, MSGPACK: check_msgpack, COREML_WEIGHTS: check_coreml_weights,
          CTRANSLATE2: check_ctranslate2, GGML_WHISPER: check_ggml_whisper}
LOADERS = {ONNX: "onnx.load / onnxruntime.InferenceSession", TFLITE: "tf.lite.Interpreter",
           MSGPACK: "flax.serialization.msgpack_restore", OPENVINO_XML: "openvino.Core.read_model",
           OPENVINO_BIN: "openvino.Core.read_model (weights of the .xml beside it)",
           COREML_WEIGHTS: "Core ML runtime (MIL blob storage weight.bin of an ML Program)",
           CTRANSLATE2: "ctranslate2 runtime (model.bin of a converted model)",
           GGML_WHISPER: "whisper.cpp (legacy ggml model file)"}

__all__ = ["CHECKS", "LOADERS", "NO_CODE_REASON", "Unverifiable", "check_coreml_weights", "check_ctranslate2", "check_ggml_whisper", "check_msgpack", "check_onnx",
           "check_openvino_xml", "check_tflite", "external_location_problem", "looks_like_coreml_weights", "looks_like_ctranslate2", "looks_like_ggml_whisper",
           "looks_like_onnx", "looks_like_openvino_xml"]
