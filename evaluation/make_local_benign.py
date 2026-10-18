"""Write benign model files from libraries installed locally (numpy, scikit-learn,
joblib, torch, keras / tf.keras), for false-positive measurement without network access.

    python evaluation/make_local_benign.py OUT_DIR

Objects are built and saved here (save/dump only, nothing is loaded). Libraries
that are not installed are skipped and listed.
"""
from __future__ import annotations

import os
import pickle
import sys


def _numpy(out: str) -> list[str]:
    import numpy as np

    rng = np.random.default_rng(0)
    objs = {"np_array_f32": rng.normal(size=(16, 8)).astype("float32"),
            "np_array_i64": np.arange(100), "np_dict": {"w": rng.normal(size=4), "b": np.zeros(2)}}
    written = []
    for name, obj in objs.items():
        for proto in (2, 4, 5):
            path = os.path.join(out, f"{name}_p{proto}.pkl")
            with open(path, "wb") as fh:
                pickle.dump(obj, fh, protocol=proto)
            written.append(path)
    return written


def _sklearn(out: str) -> list[str]:
    import numpy as np
    from sklearn.cluster import KMeans
    from sklearn.decomposition import PCA
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LinearRegression, LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.tree import DecisionTreeClassifier

    rng = np.random.default_rng(0)
    x, y = rng.normal(size=(60, 4)), rng.integers(0, 2, size=60)
    models = {
        "sk_logreg": LogisticRegression().fit(x, y),
        "sk_linreg": LinearRegression().fit(x, y),
        "sk_tree": DecisionTreeClassifier(max_depth=3).fit(x, y),
        "sk_forest": RandomForestClassifier(n_estimators=5, max_depth=3, random_state=0).fit(x, y),
        "sk_kmeans": KMeans(n_clusters=2, n_init=2, random_state=0).fit(x),
        "sk_pca": PCA(n_components=2).fit(x),
        "sk_pipeline": make_pipeline(StandardScaler(), LogisticRegression()).fit(x, y),
    }
    models.update(_more_sklearn(np, rng, x, y))
    written = []
    for name, model in models.items():
        path = os.path.join(out, f"{name}.pkl")
        with open(path, "wb") as fh:
            pickle.dump(model, fh, protocol=4)
        written.append(path)
        try:
            import joblib

            jpath = os.path.join(out, f"{name}.joblib")
            joblib.dump(model, jpath)
            written.append(jpath)
        except ImportError:
            pass
    return written


def _more_sklearn(np, rng, x, y) -> dict:
    """Common estimators beyond the allowlist's tuning corpus (expected to show gaps)."""
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import GradientBoostingRegressor, HistGradientBoostingClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import Ridge, SGDClassifier
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler
    from sklearn.svm import SVC

    cats = np.array([["a", "x"], ["b", "y"], ["a", "y"], ["c", "x"]] * 15, dtype=object)
    mixed = np.concatenate([x, cats], axis=1)
    columns = ColumnTransformer([("num", StandardScaler(), [0, 1, 2, 3]), ("cat", OneHotEncoder(), [4, 5])])
    texts = ["good model", "bad model", "safe file", "unsafe file"] * 15
    return {
        "sk_gbr": GradientBoostingRegressor(n_estimators=5).fit(x, x[:, 0]),
        "sk_hgb": HistGradientBoostingClassifier(max_iter=5).fit(x, y),
        "sk_ridge": Ridge().fit(x, x[:, 0]),
        "sk_sgd": SGDClassifier(max_iter=5, tol=None).fit(x, y),
        "sk_knn": KNeighborsClassifier(n_neighbors=3).fit(x, y),
        "sk_mlp": MLPClassifier(hidden_layer_sizes=(4,), max_iter=20).fit(x, y),
        "sk_svc": SVC().fit(x, y),
        "sk_label_encoder": LabelEncoder().fit(["cat", "dog", "bird"]),
        "sk_column_transformer": make_pipeline(columns, SGDClassifier(max_iter=5, tol=None)).fit(mixed, y),
        "sk_tfidf": make_pipeline(TfidfVectorizer(), SGDClassifier(max_iter=5, tol=None)).fit(texts, y),
    }


def _keras_applications(out: str) -> list[str]:
    """Real architectures from keras.applications with weights=None (nothing is downloaded),
    saved as .keras and as legacy .h5, by tf.keras 2.x if installed, else Keras 3."""
    try:
        import tensorflow as tf

        keras, tag = tf.keras, "k2"
    except ImportError:
        import keras

        tag = "k3"
    apps = keras.applications
    builders = {
        "mobilenet_v2": lambda: apps.MobileNetV2(alpha=0.35, weights=None, input_shape=(96, 96, 3)),
        "mobilenet_v3_small": lambda: apps.MobileNetV3Small(weights=None, input_shape=(96, 96, 3)),
        "efficientnet_b0": lambda: apps.EfficientNetB0(weights=None),
        "densenet121": lambda: apps.DenseNet121(weights=None),
        "nasnet_mobile": lambda: apps.NASNetMobile(weights=None),
        "convnext_tiny": lambda: apps.ConvNeXtTiny(weights=None),
    }
    text = keras.Sequential([keras.Input((20,)), keras.layers.Embedding(1000, 16),
                             keras.layers.Bidirectional(keras.layers.GRU(8)), keras.layers.Dropout(0.1),
                             keras.layers.Dense(3, activation="softmax")])
    text.compile(optimizer="rmsprop", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    written = []
    models = {"text_gru": lambda: text, **builders}
    for name, build in models.items():
        try:
            model = build()
        except Exception as exc:  # noqa: BLE001 - an architecture missing from this version
            print(f"  {name}: {exc}")
            continue
        for ext in (".keras", ".h5"):
            path = os.path.join(out, f"{tag}_{name}{ext}")
            try:
                model.save(path)
                written.append(path)
            except Exception as exc:  # noqa: BLE001
                print(f"  {name}{ext}: {exc}")
    return written


def _torch(out: str) -> list[str]:
    import torch

    model = torch.nn.Sequential(torch.nn.Linear(4, 8), torch.nn.ReLU(), torch.nn.Linear(8, 2))
    paths = [os.path.join(out, "torch_state_dict.pt"), os.path.join(out, "torch_state_dict_legacy.pt")]
    torch.save(model.state_dict(), paths[0])
    torch.save(model.state_dict(), paths[1], _use_new_zipfile_serialization=False)
    return paths


def _keras(out: str) -> list[str]:
    import keras

    model = keras.Sequential([keras.Input((4,)), keras.layers.Dense(8, activation="relu"), keras.layers.Dense(2)])
    path = os.path.join(out, "keras_dense.keras")
    model.save(path)
    return [path]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    out = argv[0]
    os.makedirs(out, exist_ok=True)
    builders = (("numpy", _numpy), ("scikit-learn", _sklearn), ("torch", _torch), ("keras", _keras),
                ("keras applications", _keras_applications))
    for name, builder in builders:
        try:
            written = builder(out)
            print(f"{name}: {len(written)} files")
        except ImportError as exc:
            print(f"{name}: skipped ({exc})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
