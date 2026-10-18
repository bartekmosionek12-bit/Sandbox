"""Build the legacy Keras HDF5 fixtures in tests/fixtures/h5/ (developer tool, not a test).

The fixtures are written by the real frameworks so the reader is tested against
files libhdf5 produced, not against our own writer:

* ``--keras2``: tf.keras 2.x (run in a venv with ``tensorflow-cpu==2.15.*``);
* ``--keras3``: Keras 3 ``model.save("x.h5")`` (run with ``keras h5py jax``);
* ``--structure``: plain h5py files with the HDF5 features the reader refuses or
  must survive (external links and data, virtual datasets, dense storage, a
  soft link, a hard-link cycle), carrying the root attributes of
  ``k2_sequential.h5`` (run after ``--keras2``, with ``h5py numpy``).

Nothing here loads a model file. Payload fixtures are made by writing a config
into our own freshly written file: the payload's code object is compiled and
marshalled, never called, and it only runs ``echo MARKER``. Usage::

    python tools/make_h5_fixtures.py --keras2 tests/fixtures/h5
    KERAS_BACKEND=jax python tools/make_h5_fixtures.py --keras3 tests/fixtures/h5
    python tools/make_h5_fixtures.py --structure tests/fixtures/h5
"""
from __future__ import annotations

import argparse
import base64
import json
import marshal
import os
import sys

MARKER_LAMBDA = "lambda x: (__import__('subprocess').getoutput('echo MARKER'), x)[1]"


def _marker_code_b64() -> str:
    # The outer code object of an eval-mode compile holds the lambda's code as a constant.
    outer = compile(MARKER_LAMBDA, "<marker>", "eval")
    code = next(c for c in outer.co_consts if hasattr(c, "co_code"))
    return base64.b64encode(marshal.dumps(code)).decode()


def _rewrite_config(h5py, path: str, edit) -> None:
    """Replace the model_config attribute of a file this script just wrote."""
    with h5py.File(path, "r+") as f:
        raw = f.attrs["model_config"]
        config = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
        edit(config)
        new = json.dumps(config)
        f.attrs["model_config"] = new.encode() if isinstance(raw, bytes) else new


def _rewrite_training(h5py, path: str, edit) -> None:
    with h5py.File(path, "r+") as f:
        raw = f.attrs["training_config"]
        config = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
        edit(config)
        new = json.dumps(config)
        f.attrs["training_config"] = new.encode() if isinstance(raw, bytes) else new


def _copy_latest(h5py, src: str, dst: str) -> None:
    """Same content, written with libver='latest' (superblock v3, v2 object headers, link messages)."""
    with h5py.File(src, "r") as fin, h5py.File(dst, "w", libver="latest") as fout:
        for key, value in fin.attrs.items():
            fout.attrs[key] = value
        for name in fin:
            fin.copy(fin[name], fout, name=name)


def _layers(config: dict) -> list:
    return config["config"]["layers"]


def keras2(out: str) -> None:
    import h5py
    import numpy
    import tensorflow as tf

    keras = tf.keras
    seq = keras.Sequential([keras.Input((4,)), keras.layers.Dense(8, activation="relu"), keras.layers.Dense(1)])
    seq.compile(optimizer="adam", loss="mse", metrics=["mae", "accuracy"])
    seq.save(f"{out}/k2_sequential.h5")

    inp = keras.Input((16, 16, 3))
    x = keras.layers.Conv2D(4, 3, padding="same", kernel_regularizer=keras.regularizers.l2(1e-4))(inp)
    x = keras.layers.BatchNormalization()(x)
    x = keras.layers.ReLU()(x)
    x = keras.layers.MaxPooling2D()(x)
    a = keras.layers.GlobalAveragePooling2D()(x)
    b = keras.layers.Flatten()(x)
    b = keras.layers.Dropout(0.2)(b)
    b = keras.layers.Dense(4, activation="tanh")(b)
    y = keras.layers.Concatenate()([a, b])
    y = keras.layers.Dense(3, activation="softmax")(y)
    cnn = keras.Model(inp, y)
    cnn.compile(optimizer=keras.optimizers.SGD(learning_rate=0.01, momentum=0.9),
                loss="categorical_crossentropy", metrics=["accuracy"])
    cnn.save(f"{out}/k2_functional_cnn.h5")

    rnn = keras.Sequential([keras.Input((10,)), keras.layers.Embedding(50, 8),
                            keras.layers.Bidirectional(keras.layers.LSTM(4)),
                            keras.layers.Dense(1, activation="sigmoid")])
    rnn.save(f"{out}/k2_rnn_uncompiled.h5", include_optimizer=False)

    lam_in = keras.Input((4,))
    lam = keras.Model(lam_in, keras.layers.Lambda(lambda t: t * 2.0)(keras.layers.Dense(4)(lam_in)))
    lam.save(f"{out}/k2_lambda_benign.h5")

    # CVE-2024-3660 rebuild: a Lambda whose marshalled code runs a marker command.
    lam.save(f"{out}/k2_lambda_marker.h5")
    code = _marker_code_b64()

    def put_marker(config):
        for layer in _layers(config):
            if layer["class_name"] == "Lambda":
                layer["config"]["function"] = [code, None, None]
    _rewrite_config(h5py, f"{out}/k2_lambda_marker.h5", put_marker)

    # Keras 2 resolves a named Lambda function in the globals of config["module"].
    lam.save(f"{out}/k2_lambda_os_system.h5")

    def put_named(config):
        for layer in _layers(config):
            if layer["class_name"] == "Lambda":
                layer["config"].update(function="system", function_type="function", module="os")
    _rewrite_config(h5py, f"{out}/k2_lambda_os_system.h5", put_named)

    # A custom layer and a custom loss: loading needs custom_objects.
    seq.save(f"{out}/k2_custom_objects.h5")

    def put_custom(config):
        _layers(config)[1]["class_name"] = "MyDense"
    _rewrite_config(h5py, f"{out}/k2_custom_objects.h5", put_custom)
    _rewrite_training(h5py, f"{out}/k2_custom_objects.h5", lambda t: t.update(loss="my_custom_loss"))

    seq.save(f"{out}/k2_custom_loss.h5")
    _rewrite_training(h5py, f"{out}/k2_custom_loss.h5", lambda t: t.update(loss="my_custom_loss"))

    _copy_latest(h5py, f"{out}/k2_functional_cnn.h5", f"{out}/k2_functional_cnn_latest.h5")

    # Keras < 2.4 wrote the root attributes as bytes, which h5py stores as fixed-length strings.
    seq.save_weights(f"{out}/k2_weights_only.h5")

    # A config larger than one sandbox evidence record (sent back in chunks).
    deep = keras.Sequential([keras.Input((2,))] + [keras.layers.Dense(2, name=f"d{i}") for i in range(120)])
    deep.save(f"{out}/k2_many_layers.h5", include_optimizer=False)

    seq.save(f"{out}/k2_sequential_fixedstr.h5")
    with h5py.File(f"{out}/k2_sequential_fixedstr.h5", "r+") as f:
        for key in list(f.attrs):
            f.attrs[key] = numpy.bytes_(str(f.attrs[key]).encode())


def keras3(out: str) -> None:
    import h5py
    import keras

    seq = keras.Sequential([keras.Input((4,)), keras.layers.Dense(8, activation="relu"), keras.layers.Dense(1)])
    seq.compile(optimizer="adam", loss="mse", metrics=["mae"])
    seq.save(f"{out}/k3_sequential.h5")

    inp = keras.Input((8,))
    x = keras.layers.Dense(4)(inp)
    x = keras.layers.Lambda(lambda t: t * 2.0, output_shape=(4,))(x)
    keras.Model(inp, x).save(f"{out}/k3_lambda_benign.h5")
    _copy_latest(h5py, f"{out}/k3_sequential.h5", f"{out}/k3_sequential_latest.h5")


def structure(out: str) -> None:
    import h5py
    import numpy

    with h5py.File(f"{out}/k2_sequential.h5", "r") as f:
        attrs = dict(f.attrs)

    def new(name, **kwargs):
        f = h5py.File(f"{out}/{name}", "w", **kwargs)
        for key, value in attrs.items():
            f.attrs[key] = value
        f.create_dataset("model_weights/dense/kernel", data=numpy.zeros((4, 8), "f4"))
        return f

    with new("s_external_link.h5") as f:
        f["model_weights/elsewhere"] = h5py.ExternalLink("other.h5", "/data")
    with new("s_external_data.h5") as f:
        f.create_dataset("model_weights/ext", shape=(4,), dtype="f4", external=[("weights.bin", 0, 16)])
    with new("s_virtual_dataset.h5", libver="latest") as f:
        layout = h5py.VirtualLayout(shape=(4,), dtype="f4")
        layout[:] = h5py.VirtualSource("other.h5", "data", shape=(4,))
        f.create_virtual_dataset("model_weights/vds", layout)
    with new("s_soft_link.h5") as f:
        f["model_weights/alias"] = h5py.SoftLink("/model_weights/dense")
    with new("s_hardlink_cycle.h5") as f:
        f["model_weights/dense/parent"] = f["model_weights"]
    with new("s_dense_attrs.h5", libver="latest") as f:
        for i in range(20):
            f.attrs[f"extra{i}"] = i
    with new("s_dense_links.h5", libver="latest") as f:
        for i in range(20):
            f.create_group(f"model_weights/layer{i}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--keras2", action="store_true")
    group.add_argument("--keras3", action="store_true")
    group.add_argument("--structure", action="store_true")
    parser.add_argument("out")
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)
    (keras2 if args.keras2 else keras3 if args.keras3 else structure)(args.out)
    print(f"written to {args.out} with Python {sys.version.split()[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
