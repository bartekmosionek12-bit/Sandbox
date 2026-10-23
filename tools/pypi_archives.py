"""Read released library sources from PyPI archives (development and evaluation time only).

    from tools.pypi_archives import Archives
    archives = Archives()                         # cache: ~/.cache/safeloadai-upstream/pypi
    archives.versions("scikit-learn")             # releases, oldest first
    src = archives.source("scikit-learn", "0.21.3")
    src.has_module("sklearn.ensemble.forest")     # True
    src.read("sklearn.ensemble.forest")           # (source text, is_package)

What this does is ``pip download --no-deps --only-binary=:all:`` without pip: one archive
of one release is fetched from files.pythonhosted.org, checked against the sha256 that
PyPI's JSON API lists for it, and read as a zip (wheel) or tar (sdist, only when a release
has no wheel) archive. Nothing is installed, built, extracted to disk, imported or run;
an sdist's ``setup.py`` is never executed (pip would run it to read the metadata, which is
why pip is not used for sdists). The smallest wheel of a release is taken: the Python
files are the same in every wheel of a release, only compiled extensions differ, and
those are only listed (``has_module``), never read.
"""
from __future__ import annotations

import hashlib
import json
import os
import tarfile
import urllib.request
import zipfile
from dataclasses import dataclass, field

DEFAULT_CACHE = os.path.join(os.path.expanduser("~"), ".cache", "safeloadai-upstream", "pypi")
MAX_ARCHIVE_BYTES = 450 * 1024 * 1024


def _module_of(path: str) -> tuple[str, bool] | None:
    """'a/b/c.py' -> ('a.b.c', False), 'a/b/__init__.py' -> ('a.b', True), a compiled
    extension 'a/_c.cpython-312-x86_64-linux-gnu.so' or 'a/_c.pyd' -> ('a._c', False),
    Cython 'a/_c.pyx' -> ('a._c', False); None for anything else."""
    if ".dist-info/" in path or ".egg-info/" in path:
        return None
    base, ext = os.path.splitext(path)
    if ext in (".so", ".pyd"):  # _c.cpython-312-x86_64-linux-gnu.so, _c.cp312-win_amd64.pyd, _c.so
        head, _, name = path.rpartition("/")
        base = (head + "/" if head else "") + name.split(".", 1)[0]
    elif ext not in (".py", ".pyx"):
        return None
    parts = base.split("/")
    package = parts[-1] == "__init__"
    if package:
        parts = parts[:-1]
    if not parts or not all(p.isidentifier() for p in parts):
        return None
    return ".".join(parts), package


@dataclass
class Source:
    """The modules of one released archive."""

    distribution: str
    version: str
    archive: str
    sha256: str
    modules: dict[str, tuple[str, bool]] = field(default_factory=dict)  # module -> (member, is_package)
    _data: object = None

    def has_module(self, module: str) -> bool:
        return module in self.modules

    def top_levels(self) -> set[str]:
        return {m.split(".")[0] for m in self.modules}

    def read(self, module: str) -> tuple[str, bool] | None:
        """Source text of a ``.py`` module (never of a compiled extension)."""
        found = self.modules.get(module)
        if not found or not found[0].endswith(".py"):
            return None
        return self._read_member(found[0]).decode("utf-8", errors="replace"), found[1]

    def _read_member(self, member: str) -> bytes:
        if self.archive.endswith(".whl") or self.archive.endswith(".zip"):
            with zipfile.ZipFile(self._data) as zf:
                return zf.read(member)
        with tarfile.open(self._data) as tf:
            extracted = tf.extractfile(member)
            return extracted.read() if extracted else b""


class Archives:
    def __init__(self, cache: str = DEFAULT_CACHE, index: str = "https://pypi.org/pypi"):
        self.cache = cache
        self.index = index
        self._json: dict[str, dict | None] = {}
        self._sources: dict[tuple[str, str], Source | None] = {}

    def project(self, distribution: str) -> dict | None:
        """PyPI's JSON for a project, or None when PyPI has no such project."""
        if distribution not in self._json:
            path = os.path.join(self.cache, "json", f"{distribution.lower()}.json")
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    self._json[distribution] = json.load(fh)
            else:
                try:
                    with urllib.request.urlopen(f"{self.index}/{distribution}/json", timeout=60) as resp:
                        data = json.load(resp)
                except urllib.error.HTTPError as exc:
                    if exc.code == 404:
                        data = None
                    else:
                        raise
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(data, fh)
                self._json[distribution] = data
        return self._json[distribution]

    def versions(self, distribution: str) -> list[str]:
        """Releases that have at least one file, oldest first (by first upload time),
        yanked releases included (old files that were published are what users have)."""
        data = self.project(distribution) or {}
        dated = []
        for version, files in (data.get("releases") or {}).items():
            if files:
                dated.append((min(f["upload_time_iso_8601"] for f in files), version))
        return [v for _, v in sorted(dated)]

    def latest(self, distribution: str) -> str | None:
        data = self.project(distribution)
        return data["info"]["version"] if data else None

    def _pick(self, distribution: str, version: str) -> dict | None:
        data = self.project(distribution) or {}
        files = (data.get("releases") or {}).get(version) or []
        wheels = [f for f in files if f["filename"].endswith(".whl") and f["size"] <= MAX_ARCHIVE_BYTES]
        sdists = [f for f in files if f["packagetype"] == "sdist" and f["size"] <= MAX_ARCHIVE_BYTES
                  and f["filename"].endswith((".tar.gz", ".tgz", ".tar.bz2", ".zip"))]
        pool = wheels or sdists
        return min(pool, key=lambda f: f["size"]) if pool else None

    def source(self, distribution: str, version: str) -> Source | None:
        key = (distribution, version)
        if key in self._sources:
            return self._sources[key]
        chosen = self._pick(distribution, version)
        if chosen is None:
            self._sources[key] = None
            return None
        path = os.path.join(self.cache, "files", chosen["filename"])
        expected = chosen["digests"]["sha256"]
        if not os.path.exists(path) or _sha256(path) != expected:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with urllib.request.urlopen(chosen["url"], timeout=900) as resp, open(path + ".part", "wb") as out:
                while chunk := resp.read(1 << 20):
                    out.write(chunk)
            if _sha256(path + ".part") != expected:
                os.remove(path + ".part")
                raise ValueError(f"{chosen['filename']}: sha256 differs from PyPI's {expected}")
            os.replace(path + ".part", path)
        src = Source(distribution, version, chosen["filename"], expected, _data=path)
        src.modules = _members(path, chosen["filename"])
        self._sources[key] = src
        return src


def _members(path: str, filename: str) -> dict[str, tuple[str, bool]]:
    """module -> (archive member, is_package). An sdist's members lose their first path
    part (``name-version/``) and a leading ``src/`` or ``lib/`` directory."""
    out: dict[str, tuple[str, bool]] = {}
    if filename.endswith((".whl", ".zip")):
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    else:
        with tarfile.open(path) as tf:
            names = [m.name for m in tf.getmembers() if m.isfile()]
    sdist = not filename.endswith(".whl")
    for member in names:
        rel = member
        if sdist:
            rel = member.split("/", 1)[1] if "/" in member else member
            for prefix in ("src/", "lib/", "python/"):
                if rel.startswith(prefix):
                    rel = rel[len(prefix):]
                    break
        found = _module_of(rel)
        if found is None:
            continue
        module, package = found
        # a .py beats a .pyx/.so of the same name (it is what can be read)
        if module not in out or member.endswith(".py"):
            out[module] = (member, package)
    return out


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def spread(versions: list[str], count: int) -> list[str]:
    """``count`` releases spread evenly over ``versions`` (first and last included)."""
    if len(versions) <= count:
        return list(versions)
    step = (len(versions) - 1) / (count - 1)
    return sorted({versions[round(i * step)] for i in range(count)}, key=versions.index)


__all__ = ["Archives", "Source", "spread"]
