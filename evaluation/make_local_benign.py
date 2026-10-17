"""Write benign model files from libraries installed locally (numpy, scikit-learn,
joblib, torch, keras), for false-positive measurement without network access.

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
    for name, builder in (("numpy", _numpy), ("scikit-learn", _sklearn), ("torch", _torch), ("keras", _keras)):
        try:
            written = builder(out)
            print(f"{name}: {len(written)} files")
        except ImportError as exc:
            print(f"{name}: skipped ({exc})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
