"""Confirm candidate scanner bypasses by loading each file inside deep mode's container.

    python evaluation/confirm_bypasses.py --misses private/third-party-misses/results/misses.json \
        --corpus LAB_DIR --corpus MUTATIONS_DIR --out private/third-party-misses/results

Reads the ``clean`` (c) rows written by ``third_party_misses.py``. For each one, the
file is loaded with the loader the scanner is meant to protect (``pickle.load``,
``joblib.load`` or ``torch.load``, default arguments) inside the deep-mode detoner
image, with deep mode's isolation flags: no network, read-only root, only this one
file mounted read-only, no capabilities, memory/pid/file-size limits, wall-clock kill.

Inside the container an audit hook records what the payload did (process start,
``exec``, file operations on ``/tmp/safeloadai_marker``, ``socket.connect``) and the
harness checks the marker's own effects (``MARKER`` on stdout, the marker file
written or removed). A candidate is **confirmed** when an effect was observed and the
scanner said clean. Nothing here runs a loader on the host: the host only starts
``docker run``. Results go to ``--out``, which must be git-ignored.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [HERE, os.path.join(ROOT, "src")]

import guard  # noqa: E402

PROFILES = {
    # loader -> (docker_sandbox profile, image tag); torch needs its own image
    "pickle": ("pickle", None),
    "joblib": ("pickle", None),
    "torch": (None, "safeloadai-confirm-torch:latest"),
    "torch_full": (None, "safeloadai-confirm-torch:latest"),  # weights_only=False, torch < 2.6's default
}
TIMEOUT_S = 60
DOCKER = shutil.which("docker") or "docker"
RESULT = "@@CONFIRM@@"

# Runs inside the container only (python -I -c GUEST FILE LOADER).
GUEST = r'''
import json, os, sys
path, loader = sys.argv[1], sys.argv[2]
MARK = "/tmp/safeloadai_marker"
with open(MARK, "w") as fh:
    fh.write("PRE")
if loader.startswith("torch"):
    import torch
elif loader == "joblib":
    import joblib
for name in ("numpy", "sklearn"):
    try:
        __import__(name)
    except Exception:
        pass
effects = []
loading = [True]
WATCH = {"os.system", "subprocess.Popen", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "exec",
         "os.remove", "os.unlink", "os.rmdir", "shutil.rmtree", "os.rename", "socket.connect",
         "ctypes.dlopen", "ctypes.dlsym", "webbrowser.open", "os.kill"}
def hook(event, args):
    if not loading[0]:
        return
    if event == "exec":
        code = args[0]
        if getattr(code, "co_filename", "<").startswith("<"):  # imported modules are not payload code
            effects.append([event, getattr(code, "co_filename", "?")])
    elif event in WATCH:
        effects.append([event, repr(args)[:300]])
    elif event == "open" and "safeloadai_marker" in str(args[0]):
        effects.append([event, repr(args)[:300]])
    elif event == "import" and "safeloadai_marker" in str(args[0]):
        effects.append([event, repr(args)[:300]])
sys.addaudithook(hook)
error = None
try:
    if loader == "torch":
        torch.load(path)
    elif loader == "torch_full":
        torch.load(path, weights_only=False)
    elif loader == "joblib":
        joblib.load(path)
    else:
        import pickle
        with open(path, "rb") as fh:
            pickle.load(fh)
except BaseException as exc:
    error = type(exc).__name__ + ": " + str(exc)[:300]
loading[0] = False
state = "removed"
if os.path.exists(MARK):
    with open(MARK) as fh:
        state = "untouched" if fh.read() == "PRE" else "written"
versions = {}
for name in ("torch", "joblib", "numpy"):
    if name in sys.modules:
        versions[name] = getattr(sys.modules[name], "__version__", "?")
versions["python"] = sys.version.split()[0]
sys.stdout.flush()
print("@@CONFIRM@@ " + json.dumps({"effects": effects, "marker_file": state, "error": error,
                                   "versions": versions}), flush=True)
'''


def loader_for(tool: str, name: str, fmt: str) -> str:
    """The loader the scanner is meant to protect, for this file."""
    ext = os.path.splitext(name)[1].lower()
    if tool == "fickling":  # --check-safety reads raw pickle streams: it protects pickle.load
        return "pickle"
    if fmt in ("torch", "zip") or ext in (".pt", ".pth", ".bin", ".ckpt"):
        return "torch"
    return "joblib" if ext == ".joblib" else "pickle"


def other_loaders(loader: str, fmt: str) -> list[str]:
    """Loaders tried for information only: they never decide "confirmed"."""
    if loader == "torch":
        return ["torch_full"]
    return ["torch", "torch_full"] if fmt in ("torch", "zip") else []


def image_for(loader: str) -> str:
    from safeloadai import docker_sandbox

    profile, tag = PROFILES[loader]
    if profile:
        docker_sandbox.ensure_image(profile=profile)
        return docker_sandbox._PROFILES[profile]["image_tag"]
    probe = subprocess.run([DOCKER, "image", "inspect", tag], capture_output=True)
    if probe.returncode != 0:
        raise SystemExit(f"image {tag} is missing; build it from evaluation/confirm_torch.Dockerfile")
    return tag


def detonate(path: str, loader: str, image: str) -> dict:
    """Same isolation flags as safeloadai.docker_sandbox.detonate_in_docker."""
    name = f"safeloadai-confirm-{uuid.uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory() as staging:
        sample = "sample" + os.path.splitext(path)[1].lower()
        staged = os.path.join(staging, sample)
        shutil.copyfile(path, staged)
        os.chmod(staged, 0o444)
        os.chmod(staging, 0o755)  # the image runs as an unprivileged user
        cmd = [DOCKER, "run", "--rm", "--name", name, "--network=none", "--read-only",
               "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", "--cap-drop=ALL",
               "--security-opt=no-new-privileges", "--ipc=none", "--memory=2g", "--memory-swap=2g",
               "--pids-limit=128", "--cpus=1", "--ulimit", "nofile=256:256", "--ulimit", "fsize=16777216",
               "-v", f"{staging}:/target:ro", "--entrypoint", "python", image,
               "-I", "-u", "-c", GUEST, f"/target/{sample}", loader]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=TIMEOUT_S,
                                  cwd=staging)  # cwd also keeps subprocess off posix_spawn, which the guard refuses
            out, timed_out = proc.stdout + proc.stderr, False
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            timed_out = True
            subprocess.run([DOCKER, "kill", name], capture_output=True, cwd=staging)
    lines = out.splitlines()
    results = [json.loads(line[len(RESULT):]) for line in lines if line.startswith(RESULT + " ")]
    result = results[-1] if len(results) == 1 else {"effects": [], "marker_file": None,
                                                     "error": f"{len(results)} result lines"}
    echoed = any(line.strip() == "MARKER" for line in lines)
    # exec of "<string>" code is also what dataclasses and namedtuple do, so it is
    # recorded as context only; an effect is a process, a file operation, a socket.
    executed = [e for e in result["effects"] if e[0] not in ("import", "exec")]
    ran = bool(echoed or executed or result.get("marker_file") in ("written", "removed"))
    return dict(result, loader=loader, timed_out=timed_out, marker_echoed=echoed, marker_ran=ran,
                import_attempt_only=not ran and (any(e[0] == "import" for e in result["effects"])
                                     or "safeloadai_marker" in str(result.get("error"))),
                log=[line for line in lines if not line.startswith(RESULT)][-20:])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--misses", required=True, help="misses.json from third_party_misses.py")
    parser.add_argument("--corpus", action="append", required=True)
    parser.add_argument("--out", required=True, help="private output directory (git-ignored)")
    args = parser.parse_args(argv)
    if subprocess.run(["git", "check-ignore", "-q", args.out], cwd=ROOT).returncode != 0:
        parser.error(f"{args.out} is not ignored by git; results about other projects must stay private")
    corpora = {os.path.basename(os.path.normpath(c)): c for c in args.corpus}
    with open(args.misses, encoding="utf-8") as fh:
        rows = json.load(fh)
    needed = set()
    for r in rows:
        for t, scan in r["scanners"].items():
            if scan["cls"] == "clean":
                loader = loader_for(t, r["file"], r["format"])
                needed |= {loader, *other_loaders(loader, r["format"])}
    images = {loader: image_for(loader) for loader in sorted(needed)}  # docker build runs before the guard
    guard.activate((DOCKER,))
    cache: dict[tuple[str, str], dict] = {}
    confirmed = []
    for row in rows:
        for tool, scan in row["scanners"].items():
            if scan["cls"] != "clean":
                continue
            path = os.path.join(corpora[row["corpus"]], row["file"])
            loader = loader_for(tool, row["file"], row["format"])
            for each in (loader, *other_loaders(loader, row["format"])):
                if (row["sha256"], each) not in cache:
                    cache[(row["sha256"], each)] = detonate(path, each, images[each])
            result = cache[(row["sha256"], loader)]
            others = {each: {k: cache[(row["sha256"], each)][k] for k in ("marker_ran", "effects", "error")}
                      for each in other_loaders(loader, row["format"])}
            confirmed.append({"file": row["file"], "corpus": row["corpus"], "sha256": row["sha256"],
                              "format": row["format"], "technique": row["technique"], "scanner": tool,
                              "scanner_version": scan["version"], "scanner_outcome": scan["outcome"],
                              "confirmed": result["marker_ran"], "other_loaders": others, **result})
            print(row["file"], tool, loader, "CONFIRMED" if result["marker_ran"] else "not confirmed",
                  {k: v["marker_ran"] for k, v in others.items()}, file=sys.stderr)
    with open(os.path.join(args.out, "confirmed.json"), "w", encoding="utf-8") as fh:
        json.dump(confirmed, fh, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
