"""scikit-learn's Cython losses under the module name ``_loss`` (0.10.0).

scikit-learn 1.5 to 1.8 (built with meson) compile ``sklearn/_loss/_loss.pyx`` as an
extension module named ``_loss``: its classes have ``__module__ == "_loss"``, so a
pickle names them ``_loss.CyHalfBinomialLoss``, and the extension registers itself in
``sys.modules`` as ``_loss`` when it is imported. ``pickle.load`` then resolves
``_loss.X`` to scikit-learn's class only because an earlier global of the same stream
imported a scikit-learn module that imports ``sklearn._loss._loss``; in a fresh
interpreter ``import _loss`` searches ``sys.path`` instead (scikit-learn 1.9 names the
module ``sklearn._loss._loss`` again and registers no ``_loss``).

Checked on PyPI wheels of 1.5.1, 1.6.1, 1.7.2 and 1.8.0 in a fresh interpreter each:
importing any module in ``TRIGGERS`` puts scikit-learn's extension in
``sys.modules["_loss"]``; ``sklearn``, ``sklearn.base`` and ``sklearn.pipeline`` do not
(DECISIONS.md, "scikit-learn ``_loss`` alias").

So ``_loss.X`` is cleared (mechanism ``sklearn-loss-alias``) only when X is a class or
unpickle helper already reviewed as ``sklearn._loss._loss.X`` and every ``_loss`` global
of the file comes after a global from a module in ``TRIGGERS``. It is then checked like
``sklearn._loss._loss.X``. ``safe_load`` resolves it only to the module registered as
both ``_loss`` and ``sklearn._loss._loss`` (api.py).
"""
from __future__ import annotations

from .allowlists import PICKLE_GLOBALS

MODULE = "_loss"
REAL_MODULE = "sklearn._loss._loss"
MECHANISM = "sklearn-loss-alias"
NAMES = frozenset(name for module, name in PICKLE_GLOBALS if module == REAL_MODULE)
TRIGGERS = frozenset({
    "sklearn._loss.loss",
    "sklearn.linear_model._stochastic_gradient",
    "sklearn.linear_model._logistic",
    "sklearn.ensemble._gb",
    "sklearn.ensemble._hist_gradient_boosting.gradient_boosting",
})


def clear(report: dict, extra: dict) -> None:
    """Add every ``_loss`` pair of the file to ``extra`` when the alias rule holds."""
    imports = [i for i in report["imports"] if i.get("resolved")]
    first_alias = min((i["pos"] for i in imports if i["module"] == MODULE), default=None)
    if first_alias is None:
        return
    triggers = [i for i in imports if i["module"] in TRIGGERS and i["pos"] < first_alias]
    if not triggers:
        return
    by = triggers[0]
    for imp in imports:
        if imp["module"] == MODULE and imp["symbol"] in NAMES:
            extra.setdefault((MODULE, imp["symbol"]), (
                MECHANISM, f"scikit-learn 1.5-1.8 name for {REAL_MODULE}.{imp['symbol']}; "
                           f"{by['module']} (imported at {by['pos']}) registers that module as _loss first"))
