"""Allowlist growth from the 2026-10-18 false-positive review, and the regressions that
must stay flagged next to it (evaluation/results/false-positives-20261018.md).

Benign objects are only pickled (dumped) here, never loaded. Malicious variants are
assembled opcode by opcode and only ever scanned.
"""
from __future__ import annotations

import io
import json
import pickle
import zipfile

import pytest
from corpus.build_corpus import P2, P4, STOP, call, g, s, sg, tup

from safeloadai import Verdict, scan
from safeloadai.static import allowlists
from safeloadai.static.h5_static import parse_h5_metadata
from safeloadai.static.keras_static import parse_keras
from safeloadai.static.pickle_static import parse_pickle

wasi = pytest.mark.wasi
NP_PICKLE = "numpy.random._pickle"
GEN, RS, BITGEN = (NP_PICKLE, "__generator_ctor"), (NP_PICKLE, "__randomstate_ctor"), (NP_PICKLE,
                                                                                        "__bit_generator_ctor")

NEW_PAIRS = [
    ("numpy", "float64"),
    ("numpy.random._pcg64", "PCG64"),
    GEN,
    ("sklearn._loss._loss", "CyHalfBinomialLoss"),
    ("sklearn._loss._loss", "CyHalfSquaredError"),
    ("sklearn._loss.link", "IdentityLink"),
    ("sklearn._loss.link", "LogitLink"),
    ("sklearn._loss.loss", "HalfBinomialLoss"),
    ("sklearn._loss.loss", "HalfSquaredError"),
    ("sklearn.compose._column_transformer", "ColumnTransformer"),
    ("sklearn.dummy", "DummyRegressor"),
    ("sklearn.ensemble._gb", "GradientBoostingRegressor"),
    ("sklearn.ensemble._hist_gradient_boosting.binning", "_BinMapper"),
    ("sklearn.ensemble._hist_gradient_boosting.gradient_boosting", "HistGradientBoostingClassifier"),
    ("sklearn.ensemble._hist_gradient_boosting.predictor", "TreePredictor"),
    ("sklearn.feature_extraction.text", "TfidfVectorizer"),
    ("sklearn.feature_extraction.text", "TfidfTransformer"),
    ("sklearn.linear_model._ridge", "Ridge"),
    ("sklearn.linear_model._sgd_fast", "Hinge"),
    ("sklearn.linear_model._stochastic_gradient", "SGDClassifier"),
    ("sklearn.neural_network._multilayer_perceptron", "MLPClassifier"),
    ("sklearn.neural_network._stochastic_optimizers", "AdamOptimizer"),
    ("sklearn.preprocessing._encoders", "OneHotEncoder"),
    ("sklearn.preprocessing._label", "LabelBinarizer"),
    ("sklearn.preprocessing._label", "LabelEncoder"),
]


def test_reviewed_pairs_are_on_the_allowlist_exactly():
    for pair in NEW_PAIRS:
        assert pair in allowlists.PICKLE_GLOBALS, pair
    # exact pairs, never a module grant
    assert ("sklearn.preprocessing._function_transformer", "FunctionTransformer") not in allowlists.PICKLE_GLOBALS
    assert ("sklearn.compose._column_transformer", "make_column_transformer") not in allowlists.PICKLE_GLOBALS
    assert ("numpy", "float32") not in allowlists.PICKLE_GLOBALS


def _risk(data: bytes) -> tuple[str, list[str]]:
    report = parse_pickle(data)
    return report["static_risk"], report["reasons"]


# --- numpy random ctor helpers -------------------------------------------------------

@pytest.mark.parametrize("proto", [2, 4, 5])
def test_numpy_generator_and_random_state_pickles_are_clean(proto):
    np = pytest.importorskip("numpy")
    for obj in (np.random.default_rng(0), np.random.RandomState(0), {"g": np.random.default_rng(1)}):
        risk, reasons = _risk(pickle.dumps(obj, protocol=proto))
        assert risk == "clean", reasons


def _bitgen(cls=("numpy.random._pcg64", "PCG64")) -> bytes:
    return call(g(*BITGEN), g(*cls))


@pytest.mark.parametrize("data", [
    P2 + call(g(*GEN), _bitgen()) + STOP,  # numpy 2.x form
    P2 + call(g(*GEN), s("MT19937"), g(*BITGEN)) + STOP,  # legacy name + ctor form
    P2 + call(g(*GEN), s("PCG64")) + STOP,
    P4 + call(sg(*GEN), call(sg(*BITGEN), sg("numpy.random._mt19937", "MT19937"))) + STOP,
])
def test_generator_ctor_in_numpy_forms_is_clean(data):
    risk, reasons = _risk(data)
    assert risk == "clean", reasons


@pytest.mark.parametrize("data", [
    # second argument is another (allowlisted) callable: __generator_ctor calls it
    P2 + call(g(*GEN), s("/tmp/safeloadai_marker"), g("collections", "OrderedDict")) + STOP,
    P2 + call(g(*GEN), s("MT19937"), g("numpy", "float64")) + STOP,
    P2 + call(g(*RS), s("MT19937"), g("_codecs", "encode")) + STOP,
    # first argument not a numpy bit generator
    P2 + call(g(*GEN), s("echo MARKER")) + STOP,
    P2 + call(g(*GEN), call(g("collections", "OrderedDict"))) + STOP,
    # __bit_generator_ctor calls a class it is given
    P2 + call(g(*GEN), call(g(*BITGEN), g("collections", "OrderedDict"))) + STOP,
    P2 + call(g(*BITGEN), g("numpy", "float64")) + STOP,
    # nested: the generator ctor handed to another ctor as its "bit generator ctor"
    P2 + call(g(*RS), s("MT19937"), g(*GEN)) + STOP,
    # used as a class or passed around as a value
    P2 + g(*GEN) + tup(s("MT19937")) + b"\x81" + STOP,
    P2 + call(g("collections", "OrderedDict"), tup(tup(s("k"), g(*GEN)))) + STOP,
    P2 + call(g(*GEN), _bitgen(), g(*BITGEN), s("extra")) + STOP,
])
def test_generator_ctor_invoking_another_callable_stays_flagged(data):
    risk, reasons = _risk(data)
    assert risk != "clean", reasons
    assert any("numpy.random._pickle" in r for r in reasons), reasons


@wasi
def test_generator_ctor_call_primitive_is_flagged_end_to_end(tmp_path):
    path = tmp_path / "gen.pkl"
    path.write_bytes(P2 + call(g(*GEN), s("/tmp/safeloadai_marker"), g("collections", "OrderedDict")) + STOP)
    assert scan(path).verdict is not Verdict.CLEAN


# --- scikit-learn ----------------------------------------------------------------------

def _sklearn_models():
    np = pytest.importorskip("numpy")
    pytest.importorskip("sklearn")
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import GradientBoostingRegressor, HistGradientBoostingClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import Ridge, SGDClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler

    rng = np.random.default_rng(0)
    x, y = rng.normal(size=(40, 3)), rng.integers(0, 2, size=40)
    cats = np.array([["a"], ["b"]] * 20, dtype=object)
    columns = ColumnTransformer([("num", StandardScaler(), [0, 1, 2]), ("cat", OneHotEncoder(), [3])])
    return {
        "gbr": GradientBoostingRegressor(n_estimators=3).fit(x, x[:, 0]),
        "hgb": HistGradientBoostingClassifier(max_iter=3).fit(x, y),
        "ridge": Ridge().fit(x, x[:, 0]),
        "sgd": SGDClassifier(max_iter=5, tol=None).fit(x, y),
        "mlp": MLPClassifier(hidden_layer_sizes=(3,), max_iter=5).fit(x, y),
        "label": LabelEncoder().fit(["a", "b"]),
        "columns": make_pipeline(columns, SGDClassifier(max_iter=5, tol=None)).fit(
            np.concatenate([x, cats], axis=1), y),
        "tfidf": make_pipeline(TfidfVectorizer(), SGDClassifier(max_iter=5, tol=None)).fit(
            ["good model", "bad model"] * 10, [0, 1] * 10),
    }


@pytest.mark.filterwarnings("ignore")
def test_reviewed_sklearn_estimators_are_clean_statically(monkeypatch):
    joblib = pytest.importorskip("joblib")
    # The host guard refuses subprocesses; loky would spawn one to count cores.
    monkeypatch.setenv("LOKY_MAX_CPU_COUNT", "1")
    with joblib.parallel_config(backend="sequential"):
        models = _sklearn_models()
    for name, model in models.items():
        risk, reasons = _risk(pickle.dumps(model, protocol=4))
        assert risk == "clean", (name, reasons)


def test_function_transformer_with_marker_function_stays_flagged():
    pytest.importorskip("sklearn")
    from _marker_func import write_marker
    from sklearn.compose import ColumnTransformer
    from sklearn.preprocessing import FunctionTransformer

    for model in (FunctionTransformer(func=write_marker),
                  ColumnTransformer([("f", FunctionTransformer(func=write_marker), [0])])):
        risk, reasons = _risk(pickle.dumps(model, protocol=4))
        assert risk == "suspicious", reasons
        assert any("FunctionTransformer" in r for r in reasons), reasons
        assert any("_marker_func.write_marker" in r for r in reasons), reasons


def test_function_transformer_with_a_sink_is_malicious():
    state = b"}" + s("func") + g("posix", "system") + b"s"
    transformer = g("sklearn.preprocessing._function_transformer", "FunctionTransformer") + b")\x81" + state + b"b"
    data = P2 + g("sklearn.compose._column_transformer", "ColumnTransformer") + b")\x81" + b"}" \
        + s("transformers") + b"]" + tup(s("f"), transformer, b"]") + b"a" + b"sb" + STOP
    risk, reasons = _risk(data)
    assert risk == "malicious", reasons


# --- Keras -----------------------------------------------------------------------------

def _keras_file(*layers: dict) -> bytes:
    config = {"module": "keras", "class_name": "Functional", "registered_name": None,
              "config": {"layers": list(layers)}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", '{"keras_version": "3.15.1"}')
    return buf.getvalue()


def _layer(module, class_name, config=None, registered=None):
    return {"module": module, "class_name": class_name, "config": config or {}, "registered_name": registered}


TF_OP_MODULE = "keras.src.layers.core.tf_op_layer"


@pytest.mark.parametrize("layer", [
    _layer("keras.src.applications.convnext", "LayerScale", {"init_values": 1e-6, "projection_dim": 96},
           "LayerScale"),
    _layer("keras.src.ops.numpy", "Add"),
    _layer("keras.src.ops.numpy", "Multiply"),
    _layer(TF_OP_MODULE, "TFOpLambda", {"function": "math.multiply"}, "TFOpLambda"),
    _layer(TF_OP_MODULE, "TFOpLambda", {"function": "__operators__.add"}),
])
def test_reviewed_keras_pairs_are_clean(layer):
    report = parse_keras(_keras_file(layer))
    assert report["static_risk"] == "clean", report["reasons"]


@pytest.mark.parametrize("layer", [
    _layer("keras.src.ops.numpy", "Subtract"),  # added one by one, not keras.src.ops.*
    _layer("keras.src.ops.core", "Add"),
    _layer("keras.src.applications.resnet", "LayerScale"),
    _layer(TF_OP_MODULE, "Dense", {"units": 2}),  # a pair, not a module grant
    _layer("evil.tf_op_layer", "TFOpLambda", {"function": "math.multiply"}),
    _layer(TF_OP_MODULE, "TFOpLambda", {"function": "raw_ops.MatMul"}),
    _layer(TF_OP_MODULE, "TFOpLambda", {}),
    _layer(TF_OP_MODULE, "SlicingOpLambda", {"function": "__operators__.getitem"}),
    _layer(TF_OP_MODULE, "TFOpLambda", {"function": "math.multiply"}, "mypkg>Evil"),
])
def test_near_misses_stay_suspicious(layer):
    report = parse_keras(_keras_file(layer))
    assert report["static_risk"] == "suspicious", report["reasons"]


@pytest.mark.parametrize("op", ["io.write_file", "io.gfile.GFile", "py_function", "numpy_function"])
def test_tfoplambda_naming_a_file_writer_stays_malicious(op):
    report = parse_keras(_keras_file(_layer(TF_OP_MODULE, "TFOpLambda", {"function": op})))
    assert report["static_risk"] == "malicious", report["reasons"]
    h5 = parse_h5_metadata(_h5_meta({"class_name": "TFOpLambda", "config": {"function": op}}))
    assert h5["static_risk"] == "malicious", h5["reasons"]


def _h5_meta(*layers: dict) -> dict:
    config = {"class_name": "Functional", "config": {"name": "m", "layers": list(layers)}}
    values = {"model_config": json.dumps(config).encode(), "keras_version": b"2.15.0"}
    return {"superblock_version": 0, "root_attr_names": list(values), "values": values,
            "counts": {}, "problems": [], "notes": []}


def test_keras2_tfoplambda_with_allowed_op_is_clean():
    report = parse_h5_metadata(_h5_meta({"class_name": "TFOpLambda", "config": {"function": "math.multiply"}}))
    assert report["static_risk"] == "clean", report["reasons"]


@pytest.mark.parametrize("class_name", ["LayerScale", "MyCustomLayer", "keras.src.applications.convnext.LayerScale"])
def test_bare_custom_class_in_keras2_h5_stays_suspicious(class_name):
    report = parse_h5_metadata(_h5_meta({"class_name": class_name, "config": {"init_values": 1e-6}}))
    assert report["static_risk"] == "suspicious", report["reasons"]
