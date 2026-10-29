# Updating the sandbox runtime

The sandbox runs an unmodified CPython build for WASI, pinned by SHA-256, under
`wasmtime`. Neither is ever updated automatically. The `runtime-watch` workflow
opens an issue when upstream has something newer; this page is the manual,
reviewed procedure that follows.

Two things can change:

- **the WASI CPython build** (VMware Wasm Labs, `webassembly-language-runtimes`
  releases tagged `python/X.Y.Z+DATE-HASH`): a new `safeloadai-runtime` version;
- **wasmtime**: a change to the `wasmtime>=A,<B` requirement in `pyproject.toml`.

Do one at a time, in its own PR, so a failure points at one cause.

## 1. A new WASI CPython build

1. **Read the release.** Check the release notes and the build's licence files. A
   new CPython minor (3.12 to 3.13) changes the bytecode format, so read the next
   step carefully.
2. **Get the file and its hash on a trusted machine.** Download the `.wasm` from
   the release page and compute its SHA-256 and size yourself:

   ```bash
   curl -LO <release asset URL>
   sha256sum python-X.Y.Z.wasm && stat -c %s python-X.Y.Z.wasm
   ```

   Compare the hash with the one the release page or its checksum file publishes,
   if there is one. The hash you pin is the trust decision: everything later
   checks against it.
3. **Pin it in both places.** They must agree (`tests/test_runtime_integrity.py`
   checks that):
   - `packages/safeloadai-runtime/src/safeloadai_runtime/__init__.py`:
     `PYTHON_VERSION`, `FILE_NAME`, `SHA256`, `SIZE`, `SOURCE_URL`, `BUILD` and
     `__version__` (a new `safeloadai-runtime` version, for example 0.2.0);
   - `src/safeloadai/sandbox/runtime.py`: `PINNED` (same values, and
     `package_version` = the new `safeloadai-runtime` version).

   Then update `packages/safeloadai-runtime/pyproject.toml` (`version`, the
   "Runtime source" URL), `packages/safeloadai-runtime/MANIFEST.in` (the file
   name), `NOTICE` and `LICENSES/` if the build's components changed, and the
   cache key in `.github/workflows/ci.yml` (file name and sha256).
4. **Pin the new runtime package exactly** in `pyproject.toml`:
   `safeloadai-runtime==<new version>`.
5. **Rebuild `safeloadai-runtime`.** `fetch_runtime.py` refuses a file whose size
   or SHA-256 differs from the pin, and the build backend checks it again:

   ```bash
   python packages/safeloadai-runtime/fetch_runtime.py
   python -m build packages/safeloadai-runtime --outdir dist
   python -m build . --outdir dist
   ```

6. **Check what depends on the guest's CPython version.** Lambda emulation
   accepts only bytecode that is valid for the guest interpreter (DECISIONS C13,
   C15, C22), and the lab corpus compiles its Lambda payloads inside the guest.
   With a new minor, re-read `sandbox/guest/emulate.py` (prologue opcodes, inline
   caches) and the stdlib modules the guest code uses, and rebuild the lab corpus.
7. **Run the full test suite against the installed wheels**, with the runtime
   required:

   ```bash
   python -m venv /tmp/v && /tmp/v/bin/pip install --no-index --find-links dist safeloadai-runtime
   /tmp/v/bin/pip install "$(ls dist/safeloadai-*-py3-none-any.whl)[test]"
   SAFELOADAI_REQUIRE_WASI=1 SAFELOADAI_EXPECT_INSTALLED=1 /tmp/v/bin/python -m pytest -q -p no:cacheprovider
   /tmp/v/bin/safeloadai doctor
   ```

8. **Run the evaluation, before and after,** on the same files (see
   `evaluation/results/README.md`):

   ```bash
   python -m tests.corpus.build_corpus /tmp/lab
   python evaluation/make_local_benign.py /tmp/benign
   python evaluation/run_eval.py --lab /tmp/lab --benign /tmp/benign --label after
   python evaluation/compare_eval.py <before.json> <after.json>
   ```

   Detection must not drop. Any change in a verdict is explained in the PR.
9. **Release as a new version.** Add a CHANGELOG entry for both packages, bump
   `safeloadai`'s version, and publish with the manual `publish` workflow:
   `safeloadai-runtime` first, then `safeloadai`. Publishing is the owner's
   decision.

## 2. A new wasmtime major

1. Read wasmtime's release notes for changes to WASI preview 1, fuel, epochs,
   memory limits and the Python API that `sandbox/runner.py` uses.
2. Check that the compiled-module cache key still holds the wasmtime version
   (`sandbox/runner.py`, `compiled_cache_key`; `tests/test_compiled_cache.py`).
3. Widen the requirement in `pyproject.toml` by one major
   (`wasmtime>=A.0.0,<N+1`), with `WASMTIME_RANGE` in `doctor.py` and the
   `wasmtime` axis of the test matrix in `.github/workflows/ci.yml` (one entry per
   admitted major). `tests/test_automation.py` checks that they agree. Drop the
   oldest major only in its own change.
4. Run steps 7 and 8 above (installed wheels, full suite, `safeloadai doctor`,
   evaluation before and after) on the new major.
5. Release as a new `safeloadai` version, with a CHANGELOG entry.

## What never happens

- No workflow downloads a new runtime, changes a pin or opens a PR that does.
- A runtime whose SHA-256 differs from the pin never runs: the scan stops with
  `RuntimeIntegrityError` (CLI exit code 4).
