# WIP handoff: 0.7.0 FP reduction and release (paused 2026-10-19)

This file is temporary. Delete it before the PR is marked ready.

## Done
- Part 5, the UNSUPPORTED verdict. Commit 8348e37 (703 tests passed then).
- Part 1/2 infrastructure (this WIP commit):
  - `src/safeloadai/static/sources.py`: the ast analyzer for module inertness and the state-only class/MRO analysis. It has `REVIEWED_HOOKS` (9 hooks reviewed, each pinned by sha256) and wheel/installed readers.
  - `tools/upstream_pins.json` and `tools/gen_policies.py`: generate `src/safeloadai/static/upstream/{inert_modules.json, policies.json, REVIEW.md}`. Run with `python3 tools/gen_policies.py --wheels /tmp/wheels`; it downloads into `~/.cache/safeloadai-upstream` if the wheels are missing.
  - `src/safeloadai/static/upstream/__init__.py`: the loaders.
  - `src/safeloadai/static/clearance.py`: the referenced-vs-used walk (`used_globals`), `referenced_ok`, and `Clearance` (pinned policies; an `installed` slot for trust_inert_from).
  - `pickle_vm.py`: records `machine.globals` (pos -> Global) and `machine.uses` (append/setitem into an Obj, dict keys, set members, persid).
  - `pickle_static.py`: `_cleared_import` and `report["cleared"]`. Policy classes are checked like `STATE_ONLY_CLASSES` (NEWOBJ () + dict BUILD only).
  - `pipeline.cleared_pairs`: adds cleared pairs to the emulation allowlist. `behaviour.classify(referenced=...)`: the import of a referenced pair is no finding, but a call to it is still RISKY.

## Fixed
- FunctionTransformer, TransformedTargetRegressor and Booster are excluded via `policy_exclude`; adversarial tests are in tests/test_clearance.py; safe_load resolves cleared pairs (750 tests green).

## Next steps
3. The `trust_inert_from` option: options.py, api, CLI `--trust-inert-from`, docs/OPTIONS.md, using `sources.installed_reader`.
4. `tools/gen_torch_safe_globals.py` (torch 2.14.1 `_weights_only_unpickler.py`) and the weights_only semantics checker.
5. Part 3 (profiles: training_args.bin needs accelerate.state.PartialState and the TrainingArguments classes), Part 4 (known-good hashes, tune only), Part 6 (run_eval), Part 7 (release, LICENSE).
6. The pinned corpus (`/tmp/hf_corpus` and `/tmp/hf_malicious`, from `evaluation/fetch_pinned_hf.py`) lives in /tmp and may be gone. Re-fetch it.
7. Consider pinning older sklearn versions as well: for example, `_passthrough_scorer` (7 tune FPs) no longer exists in 1.9.1.
