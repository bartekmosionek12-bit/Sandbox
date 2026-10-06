"""Pomiar warstwy statycznej na wygenerowanym korpusie.

Co mierzy: wyłącznie heurystykę parsera (static_risk) dla pickle'i —
bez detonacji i bez sędziego. To NIE jest skuteczność całego narzędzia.

Korpus powstaje w locie i niczego nie wczytuje:
  * łagodne: modele scikit-learn, tablice numpy i zwykłe struktury,
    każdy zapisany protokołami 2, 4 i 5,
  * złośliwe: ten sam kształt ładunku (__reduce__ albo ręcznie złożone
    OBJ/INST) z różnymi callable'ami uruchamiającymi kod, w tym warianty
    z ukryciem nazw w memo. Pliki są tylko serializowane (pickle.dumps
    zapisuje nazwę funkcji, nie wywołuje jej) i parsowane.

Uruchomienie: python -m tools.eval_static   (potrzebne numpy i scikit-learn)
Opcjonalnie: --compare SCIEZKA_DO_STAREGO_parser.py
"""
from __future__ import annotations

import argparse
import warnings
import collections
import importlib.util
import os
import pickle
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbox_rce import parser  # noqa: E402

PROTOCOLS = (2, 4, 5)


def benign_corpus():
    import numpy as np
    from sklearn.cluster import KMeans
    from sklearn.decomposition import PCA
    from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
    from sklearn.linear_model import LinearRegression, LogisticRegression
    from sklearn.naive_bayes import GaussianNB
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import SVC
    from sklearn.tree import DecisionTreeClassifier

    rng = np.random.default_rng(0)
    X = rng.random((60, 4))
    y = np.array([0, 1, 2] * 20)
    objects = {
        "LogisticRegression": LogisticRegression(max_iter=200).fit(X, y),
        "LinearRegression": LinearRegression().fit(X, y),
        "RandomForest": RandomForestClassifier(n_estimators=5, random_state=0).fit(X, y),
        "GradientBoosting": GradientBoostingClassifier(n_estimators=5).fit(X, y),
        "DecisionTree": DecisionTreeClassifier().fit(X, y),
        "SVC": SVC().fit(X, y),
        "KNeighbors": KNeighborsClassifier().fit(X, y),
        "GaussianNB": GaussianNB().fit(X, y),
        "KMeans": KMeans(n_clusters=3, n_init=2, random_state=0).fit(X),
        "PCA": PCA(n_components=2).fit(X),
        "Pipeline(Scaler+LR)": make_pipeline(StandardScaler(), LogisticRegression()).fit(X, y),
        "numpy.ndarray": rng.random((8, 8)),
        "dict[str, ndarray]": {"w": rng.random(4), "b": np.zeros(2)},
        "dict/list/str": {"classes": ["a", "b"], "shape": [1, 3]},
        "set/frozenset/bytes": {"s": {1, 2}, "f": frozenset({3}), "b": b"x", "c": 1 + 2j},
    }
    for name, obj in objects.items():
        for proto in PROTOCOLS:
            yield f"{name} p{proto}", pickle.dumps(obj, protocol=proto)


def holdout_corpus():
    """Łagodne modele, których NIE było w korpusie, gdy powstawała lista
    dozwolonych importów w parserze. Wynik na nich jest uczciwszy niż na
    benign_corpus, do którego listę dopasowano."""
    import numpy as np
    from scipy import sparse
    from sklearn.ensemble import AdaBoostClassifier, ExtraTreesClassifier, HistGradientBoostingClassifier, IsolationForest
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import Lasso, Ridge, SGDClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import LabelEncoder, OneHotEncoder

    rng = np.random.default_rng(1)
    X = rng.random((60, 4))
    y = np.array([0, 1, 2] * 20)
    objects = {
        "MLPClassifier": MLPClassifier(hidden_layer_sizes=(4,), max_iter=50).fit(X, y),
        "IsolationForest": IsolationForest(n_estimators=5, random_state=0).fit(X),
        "ExtraTrees": ExtraTreesClassifier(n_estimators=5).fit(X, y),
        "AdaBoost": AdaBoostClassifier(n_estimators=5).fit(X, y),
        "HistGradientBoosting": HistGradientBoostingClassifier(max_iter=5).fit(X, y),
        "SGDClassifier": SGDClassifier().fit(X, y),
        "Ridge": Ridge().fit(X, y),
        "Lasso": Lasso().fit(X, y),
        "TfidfVectorizer": TfidfVectorizer().fit(["ala ma kota", "kot ma ale"]),
        "LabelEncoder": LabelEncoder().fit(["a", "b"]),
        "OneHotEncoder": OneHotEncoder().fit([["a"], ["b"]]),
        "scipy.sparse.csr": sparse.random(5, 5, density=0.3, format="csr", random_state=0),
    }
    for name, obj in objects.items():
        for proto in PROTOCOLS:
            yield f"{name} p{proto}", pickle.dumps(obj, protocol=proto)


def _su(text):
    raw = text.encode()
    return b"\x8c" + bytes([len(raw)]) + raw


def malicious_corpus():
    import builtins
    import posix
    import pydoc
    import runpy
    import socket
    import subprocess
    import timeit
    import webbrowser

    payloads = {
        "posix.system": (posix.system, ("id",)),
        "subprocess.Popen": (subprocess.Popen, (["id"],)),
        "subprocess.check_output": (subprocess.check_output, (["id"],)),
        "builtins.eval": (builtins.eval, ("1+1",)),
        "builtins.exec": (builtins.exec, ("x=1",)),
        "socket.create_connection": (socket.create_connection, (("x.invalid", 1),)),
        "runpy.run_path": (runpy.run_path, ("/tmp/x.py",)),
        "pydoc.pipepager": (pydoc.pipepager, ("x", "id")),
        "timeit.timeit": (timeit.timeit, ("x=1",)),
        "webbrowser.open": (webbrowser.open, ("http://x.invalid",)),
    }

    class Payload:
        def __init__(self, spec):
            self.spec = spec

        def __reduce__(self):
            return self.spec

    for name, spec in payloads.items():
        for proto in PROTOCOLS:
            yield f"__reduce__ {name} p{proto}", pickle.dumps(Payload(spec), protocol=proto)

    # Warianty złożone ręcznie: nazwy schowane w memo, OBJ i INST zamiast REDUCE.
    for module, symbol in (("posix", "system"), ("subprocess", "getoutput"), ("timeit", "timeit")):
        yield f"memo/BINGET {module}.{symbol}", (
            b"\x80\x04" + _su(module) + b"\x94" + _su(symbol) + b"\x94"
            + _su("a") + _su("b") + b"00" + b"h\x00h\x01\x93" + _su("id") + b"\x85R."
        )
        yield f"OBJ {module}.{symbol}", (
            b"\x80\x04(" + f"c{module}\n{symbol}\n".encode() + _su("id") + b"o."
        )
        yield f"INST {module}.{symbol}", (
            b"(S'id'\n" + f"i{module}\n{symbol}\n".encode() + b"."
        )


def _load_parser(path):
    spec = importlib.util.spec_from_file_location("parser_compare", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(module, corpus):
    counts = collections.Counter()
    rows = []
    for name, data in corpus:
        risk = module.parse_pickle(data, file_name=name)["static_risk"]
        counts[risk] += 1
        rows.append((name, risk))
    return counts, rows


def main(argv=None):
    warnings.filterwarnings("ignore")
    ap = argparse.ArgumentParser()
    ap.add_argument("--compare", help="ścieżka do innej wersji parser.py")
    ap.add_argument("--rows", action="store_true", help="wypisz wynik dla każdego pliku")
    args = ap.parse_args(argv)

    benign = list(benign_corpus())
    holdout = list(holdout_corpus())
    evil = list(malicious_corpus())
    parsers = [("bieżący", parser)]
    if args.compare:
        parsers.append(("porównywany", _load_parser(args.compare)))

    for label, module in parsers:
        print(f"== parser {label} ==")
        for title, corpus in (
            ("łagodne (strojenie)", benign),
            ("łagodne (kontrolne)", holdout),
            ("złośliwe", evil),
        ):
            counts, rows = _run(module, corpus)
            summary = ", ".join(f"{k}={counts.get(k, 0)}" for k in ("clean", "suspicious", "malicious"))
            print(f"  {title} ({len(corpus)} plików): {summary}")
            if args.rows:
                for name, risk in rows:
                    print(f"      {risk:<10} {name}")


if __name__ == "__main__":
    main()
