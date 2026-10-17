"""safeloadai: decide whether a model file is safe to load, without loading it."""

__version__ = "0.3.0.dev0"

from .api import UnsafeModelError, safe_load, scan  # noqa: E402
from .report import LayerResult, Report, Verdict  # noqa: E402

__all__ = ["LayerResult", "Report", "UnsafeModelError", "Verdict", "safe_load", "scan"]
