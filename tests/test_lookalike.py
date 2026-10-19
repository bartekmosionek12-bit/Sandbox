"""Module names that imitate an allowlisted module are RISKY, never UNVERIFIABLE, and
cannot be overridden. An ordinary unknown name stays UNVERIFIABLE."""
from __future__ import annotations

import io
import json
import zipfile

import pytest
from corpus.build_corpus import P2, STOP, call, g, s

from safeloadai import UnsafeModelError, Verdict, override, safe_load, scan
from safeloadai.static.lookalike import imitates, skeleton

wasi = pytest.mark.wasi


@pytest.mark.parametrize("module, ref", [
    ("kerasx", "keras"), ("keras_x.layers", "keras"), ("tf_evil_pkg", "tf"), ("tensorflowx", "tensorflow"),
    ("sklearn2", "sklearn"), ("numpy_", "numpy"), ("_numpy", "numpy"), ("nunpy", "numpy"),
    ("nmupy", "numpy"), ("skleran.base", "sklearn"), ("t0rch", "torch"), ("pytorch", "torch"),
    ("kеras", "keras"),  # Cyrillic e
    ("nοmpy", "numpy"),  # Greek omicron, one edit away
    ("ｋｅｒａｓ", "keras"),  # fullwidth letters
    ("jobIib", "joblib"), ("collections_extra", "collections"), ("np_utils", "np"),
])
def test_lookalike_names_are_recognised(module, ref):
    assert imitates(module) == ref


@pytest.mark.parametrize("module", [
    None, "", "keras", "keras.src.layers.custom", "tensorflow.python.ops", "numpy.core", "mycompany",
    "mycompany.layers", "mycompany.keras_layers", "transformers", "torchvision.models.resnet",
    "keras_hub.layers", "fractions", "custom_layers", "tfa", "ops",
])
def test_ordinary_names_are_not_lookalikes(module):
    assert imitates(module) is None


def test_skeleton_folds_homoglyphs():
    assert skeleton("kеrаs") == "keras"
    assert skeleton("toгch") != "torch"  # a Cyrillic ghe is not a look-alike of r
    assert skeleton("rnodel") == "model"


def _keras_file(module: str, class_name: str) -> bytes:
    layer = {"module": module, "class_name": class_name, "config": {}, "registered_name": class_name}
    config = {"module": "keras", "class_name": "Functional", "registered_name": None,
              "config": {"layers": [layer]}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", '{"keras_version": "3.15.1"}')
    return buf.getvalue()


@wasi
@pytest.mark.parametrize("module", ["kerasx.layers", "keras_x", "tf_evil_pkg.layers", "tensorflowx"])
def test_k_prefix_module_keras_is_risky_and_cannot_be_overridden(tmp_path, module):
    path = tmp_path / "k_prefix_module.keras"
    path.write_bytes(_keras_file(module, "Dense"))
    report = scan(path)
    assert report.verdict is Verdict.SUSPICIOUS
    assert report.category == "RISKY" and not report.unverifiable_only
    assert report.unverifiable_items == []
    assert any("imitates the allowlisted module" in f["text"] and f["category"] == "RISKY"
               for f in report.findings), report.findings
    assert not override.apply(report, [f"{module}.Dense"], how="api")
    assert report.override["accepted"] is False and not report.accepted
    with pytest.raises(UnsafeModelError, match="override refused"):
        safe_load(path, accept_unverified=[f"{module}.Dense"])


@wasi
def test_ordinary_unknown_keras_class_stays_unverifiable(tmp_path):
    path = tmp_path / "custom.keras"
    path.write_bytes(_keras_file("mycompany.layers", "Foo"))
    report = scan(path)
    assert report.category == "UNVERIFIABLE" and report.unverifiable_only
    assert report.unverifiable_items == ["mycompany.layers.Foo"]
    assert override.apply(report, ["mycompany.layers.Foo"], how="api") and report.accepted


@wasi
@pytest.mark.parametrize("module", ["sklearn2", "numpy_", "nunpy"])
def test_lookalike_pickle_global_is_risky_and_cannot_be_overridden(tmp_path, module):
    path = tmp_path / "lookalike.pkl"
    path.write_bytes(P2 + call(g(module, "Thing"), s("x")) + STOP)
    report = scan(path)
    assert report.verdict is Verdict.SUSPICIOUS and report.category == "RISKY"
    assert all(f["category"] != "UNVERIFIABLE" for f in report.findings), report.findings
    with pytest.raises(UnsafeModelError, match="override refused"):
        safe_load(path, accept_unverified=[f"{module}.Thing"])


@wasi
@pytest.mark.parametrize("module, class_name, registered, category", [
    ("subprocess", "Popen", None, "MALICIOUS"),
    ("importlib", "import_module", None, "MALICIOUS"),
    ("shutil", "rmtree", None, "MALICIOUS"),
    ("mycompany.layers", "Foo", "subprocess>Popen", "MALICIOUS"),
    ("numpy.testing._private.utils", "runstring", None, "RISKY"),  # known gadget
    ("mycompany.layers", "eval", None, "RISKY"),  # sink name outside a sink module
])
def test_keras_class_naming_a_sink_or_gadget_cannot_be_overridden(tmp_path, module, class_name, registered,
                                                                  category):
    path = tmp_path / "sink_class.keras"
    layer = {"module": module, "class_name": class_name, "config": {}, "registered_name": registered or class_name}
    config = {"module": "keras", "class_name": "Sequential", "registered_name": None,
              "config": {"layers": [layer]}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", '{"keras_version": "3.15.1"}')
    path.write_bytes(buf.getvalue())
    report = scan(path)
    assert report.category == category and not report.unverifiable_only, report.findings
    assert not any(f["category"] == "UNVERIFIABLE" and "Foo" not in f["text"] for f in report.findings)
    items = [f"{module}.{class_name}"] + ([registered] if registered else []) + report.unverifiable_items
    assert not override.apply(report, items, how="api")
    with pytest.raises(UnsafeModelError, match="override refused"):
        safe_load(path, accept_unverified=items)
