"""Write the joblib seed files under fuzz/seeds/pickle/ (run once; the output is committed).

joblib and numpy are used here only to WRITE small arrays; nothing is loaded.
"""
from __future__ import annotations

import os

import joblib
import numpy as np

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeds", "pickle")


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    values = {
        "joblib_float.joblib": np.arange(6, dtype="f8").reshape(2, 3),
        "joblib_struct.joblib": np.zeros(2, dtype=[("a", "<i4"), ("b", "<f2", (2,))]),
        "joblib_object.joblib": {"x": np.array(["a", 1, None], dtype=object), "y": np.arange(3)},
    }
    for name, value in values.items():
        joblib.dump(value, os.path.join(OUT, name))


if __name__ == "__main__":
    main()
