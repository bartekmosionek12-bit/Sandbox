"""Runtime watch: is there a newer WASI CPython build or a newer wasmtime major?

    python tools/runtime_watch.py [--out runtime.md] [--github-output FILE]

Compares the pinned sandbox runtime (``safeloadai_runtime``: CPython for WASI from
VMware Wasm Labs' webassembly-language-runtimes releases) and the wasmtime pin in
``pyproject.toml`` with the latest upstream releases. Run weekly by the
``runtime-watch`` workflow, which opens an issue when something newer exists.

It only reads release metadata. Nothing is downloaded or installed and no pin is
changed: updating the runtime is the manual, reviewed procedure in
docs/UPDATING_RUNTIME.md. Exit code 0 in every case where the check ran (the
result is in ``newer=true|false`` for the workflow); 2 if upstream could not be read.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNTIME_RELEASES = "https://api.github.com/repos/vmware-labs/webassembly-language-runtimes/releases?per_page=100"
WASMTIME_PYPI = "https://pypi.org/pypi/wasmtime/json"
# python/3.12.0+20231211-040d5a6
_TAG = re.compile(r"python/(\d+)\.(\d+)\.(\d+)\+(\d{8})-[0-9a-f]+\Z")
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)\Z")


def parse_tag(tag: str) -> tuple[tuple[int, int, int], str] | None:
    match = _TAG.match(tag)
    if not match:
        return None
    major, minor, patch, date = match.groups()
    return (int(major), int(minor), int(patch)), date


def pinned_runtime() -> tuple[tuple[int, int, int], str, str]:
    sys.path.insert(0, os.path.join(ROOT, "packages", "safeloadai-runtime", "src"))
    import safeloadai_runtime as spec

    tag = spec.SOURCE_URL.split("/download/", 1)[1].split("/", 1)[0].replace("%2F", "/").replace("%2B", "+")
    parsed = parse_tag(tag)
    if parsed is None:
        raise ValueError(f"cannot read the pinned runtime tag from {spec.SOURCE_URL}")
    return parsed[0], parsed[1], tag


def pinned_wasmtime_upper() -> int:
    """The exclusive upper major of the wasmtime requirement in pyproject.toml (``<50`` -> 50)."""
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as fh:
        match = re.search(r'"wasmtime>=[\d.]+,<(\d+)"', fh.read())
    if not match:
        raise ValueError("no wasmtime>=X,<N requirement in pyproject.toml")
    return int(match.group(1))


def newer_runtimes(tags: list[str], pinned: tuple[tuple[int, int, int], str]) -> list[str]:
    """Release tags of CPython builds newer than the pinned one (higher version, or same version, later build)."""
    out = []
    for tag in tags:
        parsed = parse_tag(tag)
        if parsed and (parsed[0], parsed[1]) > pinned:
            out.append(tag)
    return sorted(out, key=lambda t: parse_tag(t), reverse=True)


def newer_wasmtime(releases: list[str], upper_major: int) -> list[str]:
    """Final wasmtime releases at or above the major the requirement excludes."""
    out = []
    for version in releases:
        match = _VERSION.match(version)
        if match and int(match.group(1)) >= upper_major:
            out.append(version)
    return sorted(out, key=lambda v: tuple(int(x) for x in v.split(".")), reverse=True)


def _get_json(url: str):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "safeloadai-runtime-watch"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as resp:  # noqa: S310 - fixed https URLs
        return json.load(resp)


def report(runtime_tags: list[str], wasmtime_versions: list[str]) -> tuple[str, bool]:
    version, date, tag = pinned_runtime()
    upper = pinned_wasmtime_upper()
    runtimes = newer_runtimes(runtime_tags, (version, date))
    majors = newer_wasmtime(wasmtime_versions, upper)
    lines = ["Weekly check of the sandbox runtime against upstream releases. Nothing was changed: follow "
             "docs/UPDATING_RUNTIME.md to update, with a new pinned sha256, the full test suite and the evaluation.",
             "", f"- pinned WASI CPython: `{tag}`",
             f"- wasmtime requirement: `<{upper}` (pyproject.toml)", ""]
    lines += ["## Newer WASI CPython builds", ""]
    lines += [f"- `{t}`: https://github.com/vmware-labs/webassembly-language-runtimes/releases/tag/"
              f"{t.replace('/', '%2F').replace('+', '%2B')}" for t in runtimes] or ["None."]
    lines += ["", "## wasmtime releases outside the requirement", ""]
    lines += [f"- {v}: https://pypi.org/project/wasmtime/{v}/" for v in majors[:10]] or ["None."]
    return "\n".join(lines) + "\n", bool(runtimes or majors)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out")
    parser.add_argument("--github-output", help="append newer=true|false here (the workflow's $GITHUB_OUTPUT)")
    args = parser.parse_args(argv)
    try:
        tags = [r.get("tag_name", "") for r in _get_json(RUNTIME_RELEASES) if not r.get("prerelease")]
        pypi = _get_json(WASMTIME_PYPI)
        versions = [v for v, files in pypi.get("releases", {}).items() if files and not all(
            f.get("yanked") for f in files)]
    except OSError as exc:
        print(f"runtime-watch: could not read upstream releases: {exc}", file=sys.stderr)
        return 2
    text, newer = report(tags, versions)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as fh:
            fh.write(f"newer={'true' if newer else 'false'}\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
