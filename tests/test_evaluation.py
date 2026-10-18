"""Evaluation scripts: the host guard, the Hub fetcher (with a fake hub), run_eval's
bookkeeping and the before/after table. Nothing here touches the network."""
import hashlib
import importlib.util
import json
import os
import pickle
import socket
import subprocess
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL = os.path.join(ROOT, "evaluation")


def _load(name):
    if EVAL not in sys.path:
        sys.path.insert(0, EVAL)
    spec = importlib.util.spec_from_file_location(f"_eval_{name}", os.path.join(EVAL, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = _load("guard")


@pytest.fixture
def active_guard():
    if any(m.split(".")[0] in guard.BLOCKED_MODULES for m in sys.modules):
        pytest.skip("a framework module is already imported in this process")
    deactivate = guard.activate()
    yield
    deactivate()


def test_guard_refuses_unpickling_processes_and_network(active_guard):
    with pytest.raises(guard.GuardError):
        pickle.loads(b"\x80\x04K\x01.")
    with pytest.raises(guard.GuardError):
        os.system("echo MARKER")
    with pytest.raises(guard.GuardError):
        subprocess.Popen([sys.executable, "-c", "pass"])
    with pytest.raises(guard.GuardError):
        socket.socket().connect(("192.0.2.1", 80))


def test_guard_blocks_framework_imports(active_guard):
    for name in ("h5py", "torch.serialization", "joblib"):
        with pytest.raises(guard.GuardError):
            __import__(name)


def test_guard_deactivate_restores_everything():
    if any(m.split(".")[0] in guard.BLOCKED_MODULES for m in sys.modules):
        pytest.skip("a framework module is already imported in this process")
    before = (pickle.loads, os.system, subprocess.Popen, socket.socket.connect, list(sys.meta_path))
    guard.activate()()
    assert (pickle.loads, os.system, subprocess.Popen, socket.socket.connect, list(sys.meta_path)) == before


def test_guard_refuses_to_start_after_a_framework_import(monkeypatch):
    monkeypatch.setitem(sys.modules, "numpy", types.ModuleType("numpy"))
    with pytest.raises(guard.GuardError, match="already imported"):
        guard.activate()


# --- fetch_benign_hf with a fake hub -------------------------------------------------

def _fake_hub(files):
    """files: {(repo, name): bytes}. Returns a module-like object with HfApi and hf_hub_download."""
    sib = types.SimpleNamespace
    repos = sorted({repo for repo, _ in files})

    class HfApi:
        def list_models(self, library, sort, limit):
            return [sib(id=r, downloads=10, private=False, gated=False) for r in repos]

        def model_info(self, repo_id, files_metadata):
            siblings = [sib(rfilename=n, size=len(d), lfs=sib(sha256=hashlib.sha256(d).hexdigest()))
                        for (r, n), d in files.items() if r == repo_id]
            siblings.append(sib(rfilename="modeling_custom.py", size=10, lfs=None))
            return sib(sha="a" * 40, siblings=siblings, gated=False, disabled=False, downloads=10)

    def hf_hub_download(repo_id, filename, revision, local_dir):
        assert revision == "a" * 40
        assert not filename.endswith(".py")
        path = os.path.join(local_dir, filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(files[(repo_id, filename)])
        return path

    return types.SimpleNamespace(HfApi=HfApi, hf_hub_download=hf_hub_download)


def test_fetch_discovers_weight_files_and_records_hashes(tmp_path):
    fetch = _load("fetch_benign_hf")
    files = {("org/a", "pytorch_model.bin"): b"torch-bytes", ("org/b", "model.h5"): b"h5-bytes"}
    fetched = fetch.discover(_fake_hub(files), str(tmp_path), 1 << 20, {"torch", "h5"}, set(), 0.01)
    assert fetched == 2
    manifest = fetch.read_manifest(str(tmp_path))
    by_name = {e["filename"]: e for e in manifest}
    assert set(by_name) == {"pytorch_model.bin", "model.h5"}
    for entry in manifest:
        data = (tmp_path / entry["path"]).read_bytes()
        assert entry["sha256"] == entry["lfs_sha256"] == hashlib.sha256(data).hexdigest()
        assert entry["revision"] == "a" * 40
    assert not list(tmp_path.rglob("*.py"))


def test_fetch_rejects_a_sha256_mismatch(tmp_path):
    fetch = _load("fetch_benign_hf")
    hub = _fake_hub({("org/a", "model.pkl"): b"x"})
    with pytest.raises(ValueError, match="does not match"):
        fetch.download(hub, str(tmp_path), "org/a", "a" * 40, "model.pkl", "0" * 64)
    assert not list(tmp_path.rglob("model.pkl"))


def test_fetch_refuses_an_output_folder_inside_the_repo(monkeypatch):
    fetch = _load("fetch_benign_hf")
    monkeypatch.setitem(sys.modules, "huggingface_hub", types.ModuleType("huggingface_hub"))
    with pytest.raises(SystemExit):
        fetch.main(["--out", os.path.join(ROOT, "hf_corpus")])


# --- run_eval bookkeeping and compare_eval ----------------------------------------------

def _entry(name, label, fmt, verdict, missing=()):
    result = {"outcome": "clean" if verdict == "CLEAN" else "flagged", "verdict": verdict, "seconds": 0.1}
    if verdict != "CLEAN":
        result["missing"] = list(missing)
    return {"file": name, "label": label, "format": fmt, "source": "lab", "category": "x",
            "expected": "CLEAN" if label == "benign" else "MALICIOUS", "results": {"safeloadai": result}}


def test_run_eval_loads_an_hf_manifest(tmp_path):
    run_eval = _load("run_eval")
    (tmp_path / "files").mkdir()
    (tmp_path / "manifest.jsonl").write_text(json.dumps({
        "repo_id": "org/a", "filename": "model.h5", "path": "files/org__a/model.h5", "format": "h5",
        "revision": "b" * 40, "sha256": "c" * 64, "size": 3}) + "\n")
    [entry] = run_eval.load_entries(None, str(tmp_path), [])
    assert entry["label"] == "benign" and entry["format"] == "h5" and entry["revision"] == "b" * 40


def test_run_eval_summary_and_false_positive_list():
    run_eval = _load("run_eval")
    entries = [_entry("m.pkl", "malicious", "pickle", "MALICIOUS"),
               _entry("b1.joblib", "benign", "joblib", "SUSPICIOUS", ["sklearn.x.Y"]),
               _entry("b2.joblib", "benign", "joblib", "CLEAN")]
    summary = run_eval.summarise(entries, [])["safeloadai"]
    assert (summary["detected"], summary["malicious"]) == (1, 1)
    assert (summary["false_positives"], summary["benign"]) == (1, 2)
    assert summary["per_format"]["joblib"]["false_positives"] == 1
    fps = run_eval.false_positives(entries)
    assert "sklearn.x.Y" in json.dumps(fps)


def test_compare_lists_verdict_changes():
    run_eval = _load("run_eval")
    compare = _load("compare_eval")
    before = [_entry("b.h5", "benign", "h5", "SUSPICIOUS"), _entry("m.pt", "malicious", "torch", "CLEAN")]
    after = [_entry("b.h5", "benign", "h5", "CLEAN"), _entry("m.pt", "malicious", "torch", "MALICIOUS")]
    runs = [{"label": label, "summary": run_eval.summarise(e, []), "entries": e}
            for label, e in (("before", before), ("after", after))]
    text = compare.compare(*runs)
    assert "## Verdict changes (2)" in text
    assert "| b.h5 | benign | SUSPICIOUS | CLEAN |" in text
    assert "| h5 |" in text


def test_unverifiable_false_positives_are_their_own_column():
    run_eval = _load("run_eval")
    compare = _load("compare_eval")
    entries = [_entry("m.keras", "malicious", "keras", "SUSPICIOUS"),
               _entry("b1.h5", "benign", "h5", "SUSPICIOUS"),
               _entry("b2.h5", "benign", "h5", "SUSPICIOUS")]
    entries[0]["results"]["safeloadai"]["unverifiable_only"] = True
    entries[1]["results"]["safeloadai"]["unverifiable_only"] = True
    summary = run_eval.summarise(entries, [])
    s = summary["safeloadai"]
    # still counted as false positives; the UNVERIFIABLE count is a column next to them
    assert (s["false_positives"], s["unverifiable_fp"], s["unverifiable_detected"]) == (2, 1, 1)
    assert s["per_format"]["h5"]["unverifiable_fp"] == 1
    text = run_eval.markdown(summary, run_eval.false_positives(entries), entries, [],
                             {"label": "x", "created": "t", "safeloadai": "v", "python": "p", "platform": "q"})
    assert "of which UNVERIFIABLE" in text and "| safeloadai | 1 / 1 | 2 / 2 | 1 |" in text
    run = {"label": "x", "summary": summary, "entries": entries}
    assert "FP UNVERIFIABLE after" in compare.compare(run, run)
