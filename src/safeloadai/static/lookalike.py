"""Module names that imitate an allowlisted module.

A name such as ``kerasx``, ``keras_x``, ``tf_evil_pkg``, ``sklearn2``, ``numpy_``, ``nunpy``
or ``kеras`` (Cyrillic ``е``) is chosen to pass for a module safeloadai trusts. An unknown
object from such a module is RISKY, never UNVERIFIABLE, so it can never be overridden.

Only the top-level package is compared: that is the package an import would load. A
module whose top-level package is exactly an allowlisted one (``keras.src.foo``) is not
a look-alike; it is the real package, and an unknown class in it stays UNVERIFIABLE.
"""
from __future__ import annotations

import unicodedata

from .allowlists import (
    KERAS_CLASS_PAIRS,
    KERAS_FUNCTIONS,
    KERAS_MODULES,
    KNOWN_GADGETS,
    PICKLE_GLOBALS,
    TORCH_GLOBALS,
)

# Top-level packages of every allowlisted module, plus the framework names users import.
# Private names (``_codecs``) are left out: nothing legitimate is named after them.
REFERENCE = frozenset(
    m.split(".")[0]
    for pairs in (PICKLE_GLOBALS, TORCH_GLOBALS, KERAS_CLASS_PAIRS, KERAS_FUNCTIONS, KNOWN_GADGETS)
    for m, _ in pairs
) | frozenset(m.split(".")[0] for m in KERAS_MODULES) | frozenset({
    "tensorflow", "tf", "tf_keras", "np", "scipy", "pandas", "safetensors",
})
REFERENCE = frozenset(name for name in REFERENCE if not name.startswith("_"))

# Real, well-known packages that share a prefix with a reference name. They are not
# trusted (their objects stay UNVERIFIABLE); they are only not called look-alikes.
GENUINE = frozenset({
    "torchvision", "torchaudio", "torchtext", "keras_nlp", "keras_cv", "keras_hub", "keras_tuner",
    "tensorflow_hub", "tensorflow_text", "tensorflow_addons", "tensorflow_probability",
    "numba", "sympy", "pytorch_lightning", "sentence_transformers",
})

_SEPARATORS = "_-"
# Latin, Cyrillic and Greek letters and ASCII digits that render like a Latin letter.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "к": "k", "м": "m",
    "т": "t", "н": "h", "в": "b", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "ɡ": "g",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "κ": "k", "τ": "t", "ι": "i", "υ": "u", "ϲ": "c",
    "ı": "i", "ℓ": "l", "0": "o", "1": "l", "3": "e", "5": "s", "|": "l",
})


def skeleton(name: str) -> str:
    """The name with compatibility forms folded, accents dropped and look-alike letters
    replaced by the Latin letter they imitate."""
    folded = unicodedata.normalize("NFKD", name.casefold())
    folded = "".join(ch for ch in folded if not unicodedata.combining(ch))
    return folded.translate(_CONFUSABLES).replace("rn", "m").replace("vv", "w")


def _distance(a: str, b: str) -> int:
    """Edit distance with adjacent transpositions (optimal string alignment)."""
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def _resembles(candidate: str, ref: str) -> bool:
    if len(ref) >= 4 and (candidate.startswith(ref) or candidate.endswith(ref)):
        return True
    if any(candidate.startswith(ref + s) or candidate.endswith(s + ref) for s in _SEPARATORS):
        return True
    return len(ref) >= 5 and _distance(candidate, ref) <= 2


def imitates(module: str | None) -> str | None:
    """The allowlisted package ``module``'s top-level package imitates, or None."""
    if not module:
        return None
    top = str(module).split(".")[0]
    if top in REFERENCE or top in GENUINE:
        return None
    variants = {top.casefold(), skeleton(top)}
    for ref in sorted(REFERENCE):
        if any(v == ref or _resembles(v, ref) for v in variants):
            return ref
    return None


def reason(module: str, ref: str) -> str:
    return f"module name {module!r} imitates the allowlisted module {ref!r}"
