"""In-tree PEP 517 backend: setuptools, plus a hard check that the pinned runtime is
present and intact before any sdist or wheel is written.

It never downloads. Run ``fetch_runtime.py`` first; a missing or altered ``.wasm``
fails the build instead of producing a package without (or with the wrong) runtime.
"""
from __future__ import annotations

import fetch_runtime
from setuptools import build_meta as _orig
from setuptools.build_meta import *  # noqa: F403


def _require_runtime() -> None:
    problem = fetch_runtime.verify(fetch_runtime.TARGET)
    if problem:
        raise RuntimeError(
            f"safeloadai-runtime: pinned WASI runtime missing or altered: {problem}. "
            "Run `python packages/safeloadai-runtime/fetch_runtime.py` before building."
        )


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _require_runtime()
    return _orig.build_wheel(wheel_directory, config_settings, metadata_directory)


def build_sdist(sdist_directory, config_settings=None):
    _require_runtime()
    return _orig.build_sdist(sdist_directory, config_settings)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    _require_runtime()
    return _orig.build_editable(wheel_directory, config_settings, metadata_directory)
