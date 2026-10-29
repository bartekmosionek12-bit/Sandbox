"""Write the small model files ``tests/test_model_formats.py`` starts from (0.10.0;
development time only, the fixtures are committed).

    pip install onnx flatbuffers tflite msgpack numpy openvino   # a scratch venv
    python tools/make_model_format_fixtures.py tests/fixtures/model_formats

Every file is built with the format's own writer (onnx.helper, the TFLite schema's
flatbuffer builders, msgpack with Flax's ext types, openvino.save_model) from numbers
written here; nothing is downloaded and no model is loaded from anywhere. The tests make
their malformed, custom-operator and polyglot variants from these bytes.
"""
from __future__ import annotations

import os
import sys

import numpy as np


def onnx_files(out: str) -> None:
    import onnx
    from onnx import TensorProto, helper, numpy_helper

    weight = numpy_helper.from_array(np.arange(6, dtype=np.float32).reshape(2, 3), "W")
    x = helper.make_tensor_value_info("X", TensorProto.FLOAT, [1, 2])
    y = helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 3])
    graph = helper.make_graph([helper.make_node("MatMul", ["X", "W"], ["Y"])], "tiny", [x], [y], [weight])
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)], producer_name="safeloadai-tests")
    onnx.checker.check_model(model)
    onnx.save(model, os.path.join(out, "tiny.onnx"))
    # a node of a custom domain
    custom = helper.make_graph([helper.make_node("FancyOp", ["X", "W"], ["Y"], domain="com.example")], "custom",
                               [x], [y], [weight])
    onnx.save(helper.make_model(custom, opset_imports=[helper.make_opsetid("", 17),
                                                       helper.make_opsetid("com.example", 1)]),
              os.path.join(out, "tiny_custom_domain.onnx"))
    # a model-local function in its own domain, made of standard operators
    function = helper.make_function("local.fns", "Double", ["A"], ["B"], [helper.make_node("Add", ["A", "A"], ["B"])],
                                    [helper.make_opsetid("", 17)])
    fgraph = helper.make_graph([helper.make_node("Double", ["X"], ["Y"], domain="local.fns")], "fn",
                               [x], [helper.make_tensor_value_info("Y", TensorProto.FLOAT, [1, 2])])
    fmodel = helper.make_model(fgraph, functions=[function], opset_imports=[helper.make_opsetid("", 17),
                                                                            helper.make_opsetid("local.fns", 1)])
    onnx.checker.check_model(fmodel)
    onnx.save(fmodel, os.path.join(out, "tiny_function.onnx"))
    # external data in a file beside the model
    ext = onnx.load(os.path.join(out, "tiny.onnx"))
    onnx.save(ext, os.path.join(out, "tiny_external.onnx"), save_as_external_data=True, all_tensors_to_one_file=True,
              location="tiny_external.onnx.data", size_threshold=0)


def tflite_files(out: str) -> None:
    import importlib

    import flatbuffers

    # the schema's builder functions live in the modules; tflite/__init__.py binds the classes
    Buffer, Model, Operator, OperatorCode, SubGraph, Tensor = (
        importlib.import_module(f"tflite.{name}") for name in ("Buffer", "Model", "Operator", "OperatorCode",
                                                                "SubGraph", "Tensor"))

    def build(custom: str | None) -> bytes:
        b = flatbuffers.Builder(1024)
        name = b.CreateString("x")
        custom_name = b.CreateString(custom) if custom else None
        Buffer.BufferStart(b)
        empty = Buffer.BufferEnd(b)
        data = b.CreateByteVector(bytes(range(16)))
        Buffer.BufferStart(b)
        Buffer.BufferAddData(b, data)
        weights = Buffer.BufferEnd(b)
        Model.ModelStartBuffersVector(b, 2)
        b.PrependUOffsetTRelative(weights)
        b.PrependUOffsetTRelative(empty)
        buffers = b.EndVector()
        tensors = []
        for buffer in (0, 1, 0):
            Tensor.TensorStartShapeVector(b, 1)
            b.PrependInt32(4)
            shape = b.EndVector()
            Tensor.TensorStart(b)
            Tensor.TensorAddShape(b, shape)
            Tensor.TensorAddType(b, 0)
            Tensor.TensorAddBuffer(b, buffer)
            Tensor.TensorAddName(b, name)
            tensors.append(Tensor.TensorEnd(b))
        SubGraph.SubGraphStartTensorsVector(b, 3)
        for t in reversed(tensors):
            b.PrependUOffsetTRelative(t)
        tensor_vec = b.EndVector()

        def ints(values):
            b.StartVector(4, len(values), 4)
            for v in reversed(values):
                b.PrependInt32(v)
            return b.EndVector()

        op_in, op_out, sg_in, sg_out = ints([0, 1]), ints([2]), ints([0]), ints([2])
        Operator.OperatorStart(b)
        Operator.OperatorAddOpcodeIndex(b, 0)
        Operator.OperatorAddInputs(b, op_in)
        Operator.OperatorAddOutputs(b, op_out)
        op = Operator.OperatorEnd(b)
        SubGraph.SubGraphStartOperatorsVector(b, 1)
        b.PrependUOffsetTRelative(op)
        ops = b.EndVector()
        SubGraph.SubGraphStart(b)
        SubGraph.SubGraphAddTensors(b, tensor_vec)
        SubGraph.SubGraphAddInputs(b, sg_in)
        SubGraph.SubGraphAddOutputs(b, sg_out)
        SubGraph.SubGraphAddOperators(b, ops)
        subgraph = SubGraph.SubGraphEnd(b)
        OperatorCode.OperatorCodeStart(b)
        OperatorCode.OperatorCodeAddDeprecatedBuiltinCode(b, 32 if custom else 0)
        OperatorCode.OperatorCodeAddBuiltinCode(b, 32 if custom else 0)
        if custom_name is not None:
            OperatorCode.OperatorCodeAddCustomCode(b, custom_name)
        OperatorCode.OperatorCodeAddVersion(b, 1)
        code = OperatorCode.OperatorCodeEnd(b)
        Model.ModelStartOperatorCodesVector(b, 1)
        b.PrependUOffsetTRelative(code)
        codes = b.EndVector()
        Model.ModelStartSubgraphsVector(b, 1)
        b.PrependUOffsetTRelative(subgraph)
        subgraphs = b.EndVector()
        description = b.CreateString("safeloadai-tests")
        Model.ModelStart(b)
        Model.ModelAddVersion(b, 3)
        Model.ModelAddOperatorCodes(b, codes)
        Model.ModelAddSubgraphs(b, subgraphs)
        Model.ModelAddDescription(b, description)
        Model.ModelAddBuffers(b, buffers)
        b.Finish(Model.ModelEnd(b), file_identifier=b"TFL3")
        return bytes(b.Output())

    with open(os.path.join(out, "tiny.tflite"), "wb") as fh:
        fh.write(build(None))
    with open(os.path.join(out, "tiny_custom.tflite"), "wb") as fh:
        fh.write(build("MyFancyOp"))


def msgpack_files(out: str) -> None:
    import msgpack

    def ndarray(a: np.ndarray) -> msgpack.ExtType:  # flax/serialization.py _ndarray_to_bytes
        return msgpack.ExtType(1, msgpack.packb((a.shape, a.dtype.name, a.tobytes()), use_bin_type=True))

    state = {"params": {"Dense_0": {"kernel": ndarray(np.ones((3, 2), np.float32)),
                                    "bias": ndarray(np.zeros((2,), np.float32))}},
             "step": msgpack.ExtType(3, msgpack.packb(((), "int32", np.int32(7).tobytes()), use_bin_type=True)),
             "opt_state": {"0": {"count": ndarray(np.array(5, np.int32))}, "1": None}}
    with open(os.path.join(out, "flax_model.msgpack"), "wb") as fh:
        fh.write(msgpack.packb(state, use_bin_type=True))


def openvino_files(out: str) -> None:
    import openvino as ov
    from openvino import opset13 as ops

    x = ops.parameter([1, 4], np.float32, name="x")
    weight = ops.constant(np.arange(4, dtype=np.float32).reshape(1, 4))
    model = ov.Model([ops.result(ops.add(x, weight))], [x], "tiny")
    ov.save_model(model, os.path.join(out, "openvino_model.xml"), compress_to_fp16=False)


def main() -> int:
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    onnx_files(out)
    tflite_files(out)
    msgpack_files(out)
    openvino_files(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
