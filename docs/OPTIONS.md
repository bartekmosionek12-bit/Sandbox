# safeloadai options

Plain `scan(path)` and `safeloadai scan FILE` use only the defaults below. Every
default is the strictest behaviour: no user allowlist, no accepted UNVERIFIABLE items,
no deep detonation and no config file.

Every option that can make a verdict less strict follows these rules:

- It names exact items: pickle `(module, qualname)` pairs, UNVERIFIABLE items, or file
  hashes. There is no "allow all" or "disable checks" switch anywhere.
- It is never turned on by an environment variable.
- A config file can turn it on only when you name that file with `--config`. The CLI
  then prints which file set which option.
- It is recorded in every Report, in `options`. Each entry gives the option's name,
  value, source and direction.
- The CLI announces it with a one-line warning on stderr before the results, and the
  verdict line shows `CLEAN (with options: ...)` instead of a bare `CLEAN`.

Options that only make scanning stricter may be set freely. They are still recorded.
Options that change how an enabled option runs, such as which deep sandbox is used,
are recorded too.

`safeloadai options` prints the table below and the effective settings, and says
whether a `safeloadai.toml` is in the current directory. It also says that such a
file is not used unless you name it.

| option | default | makes scanning stricter or looser | risk level |
|---|---|---|---|
| [`allow`](#allow) | `()` (none) | looser | high |
| [`accept_unverified`](#accept_unverified) | `None` (none) | looser | medium |
| [`trust_inert_from`](#trust_inert_from) (experimental) | `()` (none) | looser | medium |
| [`validate_boosters`](#validate_boosters) | `False` | looser | medium |
| [`known_good`](#known_good) | `True` (shipped list used) | stricter when turned off | low |
| [`deep`](#deep) | `False` | stricter (but runs the file's code) | high |
| [`limits`](#limits) | `None` (built-in limits) | neutral (lower limits are stricter) | low |
| [`deep_backend`](#deep_backend) | `None` (first available) | neutral | low |
| [`runtime_path`](#runtime_path) | `None` (bundled runtime) | neutral | none |
| [`prompt`](#prompt) | `True` (ask on a terminal, default No) | stricter when turned off | low |
| [config file](#config-file) | not read | depends on what it sets | as the options it sets |

Every entry in `Report.options` looks like this:

```json
{"name": "allow", "value": ["mypkg.models:Net"], "source": "CLI flag --allow", "direction": "looser"}
```

`source` is one of the following:

- `argument` (Python API);
- `CLI flag --...`;
- `config file PATH`;
- `environment variable NAME`;
- `interactive prompt`.

---

## `allow`

1. **What it does.** It treats extra pickle globals, named as exact
   `(module, qualname)` pairs, as if they were on the built-in allowlist.
2. **Risk you accept.** Loading a pickle imports every global it names and may call
   it. An attacker who controls the file can call your allowed class with arguments
   they choose. If that class runs code from its arguments, or reads or writes
   files, so will the file. safeloadai refuses known sinks, known gadgets,
   `builtins.getattr` and wildcards in `allow`, so this option can never turn
   evidence of code execution into CLEAN.
3. **When to use it, and when not to.**
   - **Use it** for your own classes in your own models, when you know their
     constructor, `__setstate__` and `__reduce__` do nothing but store data.
   - **Do not use it** for a class you have not read, or for a model from someone
     else just to make a warning go away.
4. **How to use it.**
   ```python
   from safeloadai import scan, safe_load
   report = scan("model.pkl", allow=[("mypkg.models", "Net")])
   model = safe_load("model.pkl", allow=[("mypkg.models", "Net")])
   ```
   ```bash
   safeloadai scan model.pkl --allow mypkg.models:Net
   ```
5. **How to check it in the report.** Look for `report.options[*]` with
   `name == "allow"`. Its `value` lists the pairs, and its `source` says where they
   came from. The static layer's `details.imports` still lists every import.
6. **Safer alternative.**
   - Ask the publisher for `.safetensors` weights and a config file.
   - Or re-save the model so it holds only allowlisted types, such as a `state_dict`
     of tensors.
   - Or, for one file, accept the item with [`accept_unverified`](#accept_unverified).
     That acceptance is bound to the file's sha256.

## `accept_unverified`

1. **What it does.** It accepts named UNVERIFIABLE items for one file, bound to that
   file's sha256. It works only when every reason on the file is UNVERIFIABLE.
2. **Risk you accept.** An UNVERIFIABLE item is code the scanner cannot see, such as
   a custom class, Keras layer or loss. If the author's code, or a library that
   reuses its name, is malicious, it runs when you load the file. The override is
   refused if the file has any RISKY or MALICIOUS reason, and the file stays
   SUSPICIOUS in the Report.
3. **When to use it, and when not to.**
   - **Use it** when you know the exact code each item names, for example your own
     custom loss, and you load with the same code.
   - **Do not use it** in bulk, for items you cannot identify, or for files you
     have not looked at.
4. **How to use it.**
   ```python
   from safeloadai import safe_load
   model = safe_load("convnext.h5", accept_unverified=["LayerScale"])                 # this file only
   model = safe_load("model.pkl", accept_unverified={"<sha256>": ["mypkg.models.Thing"]})  # pinned
   ```
   ```bash
   safeloadai scan convnext.h5 --accept-unverified LayerScale
   safeloadai scan models/ --accept-unverified <sha256>:LayerScale
   ```
5. **How to check it in the report.** Look at:
   - `report.override`: `accepted`, `items`, `requested`, `sha256`, `time`, `how`
     and `refused_because`;
   - `report.options[*]` with `name == "accept_unverified"`;
   - `report.accepted`, which is True only when the override was accepted.
6. **Safer alternative.**
   - Re-save a Keras model as `.keras`, which records each class's module, or
     without custom objects.
   - Ask the publisher for `.safetensors`.
   - For xgboost (item `xgboost.core.Booster`, whose raw bytes go to libxgboost's
     native parser): ask for the model saved with xgboost's own format,
     `booster.save_model("model.json")` or `booster.save_model("model.ubj")`, and
     load it with `xgboost.Booster(model_file="model.json")`. That format holds no
     pickle, so no Python object is rebuilt. It is still parsed by libxgboost.

## `trust_inert_from`

**Experimental. It has not yet loosened a verdict on any evaluated file.** On tune, tune-2, held-out, held-out-2, held-out-3 and held-out-4, with scikit-learn, transformers and torch named, no file the default finds SUSPICIOUS becomes CLEAN with it. That is not because it is disconnected: a pickle of a state-only class from an installed distribution that is not pinned is SUSPICIOUS without it and CLEAN with it (`tests/test_trust_inert_from.py`). The Hub files simply never reach a class it could add: every class that reaches the question fails the same rule the pinned analysis applies (point 8). Before 0.11.0 it could also make a verdict *stricter*, a bug now fixed (point 8).

1. **What it does.** For each named distribution that is installed where the scan
   runs, it reads that distribution's own Python files and decides which of its classes
   are state-only. It finds the files through the distribution's file list
   (`importlib.metadata`) and reads them with `ast`, so nothing is imported or run.
   - **Which classes count as state-only.** Rebuilding the class from a dict state
     (`NEWOBJ ()` + `BUILD`) runs none of its own code. Nothing in its MRO may define
     `__reduce__`, `__reduce_ex__`, `__setstate__`, `__new__`, `__setattr__`,
     `__getattr__`, `__getattribute__` or `__delattr__`, or a property setter, unless
     that exact implementation is a reviewed hook. Every base must be readable Python
     source, and every module on its import path must be inert.
   - **What the scan then accepts.** A pickle may rebuild such a class from a dict
     state. It may not call the class, use a slot state, or call the rebuilt instance.
   - **What it adds.** For the named distributions, this analysis is asked only about
     classes the pinned policies that ship with safeloadai (`static/upstream/policies.json`,
     with their table of old module paths) do not accept. It removes a class the pinned
     policies accept only when your installed version gives that class, or a base, code of
     its own that runs on load (a `__setstate__` or other hook, a property setter, a
     metaclass, a decorator, slots) that the pinned review did not see (0.11.0).
   - **What it never accepts.** Classes the owner's review keeps out
     (`excluded` in `static/upstream/policies.json`: for example scikit-learn's
     `FunctionTransformer` and `TransformedTargetRegressor`, which store a callable,
     and xgboost's `Booster`) stay outside, whatever the installed source says.
2. **Risk you accept.** The decision relies on the source installed on your machine.
   If that installation was tampered with, or a hook does something the analysis
   cannot see, loading may run that code. Only distributions you name are affected.
3. **When to use it, and when not to.**
   - **Use it** for files produced by a library you have installed in a newer or
     older version than the pinned one, for example your own scikit-learn version.
   - **Do not use it** for distributions you did not install from a source you trust.
4. **How to use it.**
   ```python
   report = scan("model.pkl", trust_inert_from=["scikit-learn"])
   ```
   ```bash
   safeloadai scan model.pkl --trust-inert-from scikit-learn --trust-inert-from torch
   ```
5. **How to check it in the report.** Look at:
   - `report.options[*]` with `name == "trust_inert_from"`;
   - `report.cleared[*]` with `mechanism == "inert-class"`, whose `detail` reads
     `CLEAN by inert-class rule (scikit-learn X.Y.Z)`.
6. **Safer alternative.** Leave it off. The pinned policies cover the versions listed
   in `static/upstream/REVIEW.md`.
7. **What it changes in practice (0.8.0).** The 0.7.x evaluation showed no file whose
   verdict changed with the option. There were three reasons:
   - **A bug, fixed in 0.8.0.** A reviewed hook (for example scikit-learn's
     `BaseEstimator.__setstate__`, which every estimator inherits, or torch's
     `Module.__setstate__`) was matched by the sha256 of its source text. The pinned
     wheels it was reviewed from are Windows builds, whose files have CRLF line
     endings. The same function installed on Linux or macOS has LF endings, so it never
     matched, and no scikit-learn or torch class could be cleared there. Line endings
     are normalised now; the reviewed text is unchanged.
   - **A rule that was too narrow, fixed in 0.8.0.** A class body that edits a dict it
     has just made (scikit-learn's `_parameter_constraints.pop("l1_ratio")`) made its
     whole module "not inert", so `ElasticNet`, `LassoCV`, `CountVectorizer`,
     `RandomForestClassifier`, `LogisticRegression`, `SVC` and about 90 other classes
     were not accepted, by the pinned policies or by the option. A builtin method of a
     dict, list, set, tuple or constant that the class body itself made, with plain
     data as arguments, no longer counts as a call. Any other call still does.
   - **By design.** The evaluation named scikit-learn, transformers and torch at the
     same versions as the pins. The option then gives the same answer as the pinned
     policies; it only changes a verdict for a distribution that is not pinned, or for a
     class that exists in your installed version and not in the pinned one. The
     remaining flagged Hub files need something else: their classes come from packages
     that were not installed or are not on PyPI (`dabl`, `tornet`, a project's own
     `models` module, Keras custom objects in `.h5`/`.keras`, which are not pickles),
     from classes the owner's review keeps out (`FunctionTransformer`,
     `xgboost.core.Booster`), or they are functions or `REDUCE` calls (pandas'
     `_unpickle_block`, `average_precision_score` inside a scorer), which the rule does
     not cover because it only accepts classes rebuilt from a dict state.
   `tests/test_trust_inert_from.py` shows the option changing a verdict on a lab
   pickle that rebuilds `threadpoolctl.ThreadpoolController` (installed with
   scikit-learn, not pinned): SUSPICIOUS by default, CLEAN with
   `--trust-inert-from threadpoolctl`, and still SUSPICIOUS when only scikit-learn is
   named.
8. **What it changes in practice (0.11.0).**
   - **A bug, fixed in 0.11.0: it made verdicts stricter.** Until 0.10.0 the installed
     analysis *replaced* the pinned policies for a named distribution. At the pinned
     versions it refused 230 classes that the pinned policies accept: 224 old scikit-learn
     module paths (only the pinned table of old paths maps them; the installed source no
     longer has those modules), `joblib`'s `Parallel` and DeepSpeed configuration classes.
     In the 0.10.0 evaluation 12 tune-2 `training_args.bin` files were CLEAN by default and
     SUSPICIOUS with the option. The evaluation did not show it, because its column scanned
     again only the files the default had not found CLEAN; it now scans every file. None of
     the 230 was refused for a hook: each was a limit of the installed analysis. A hook
     your installed version adds to a pinned class still makes it refused (point 1).
   - **Why it still loosens nothing on the Hub files.** 60 classes outside the pinned
     policies reach the question on tune, tune-2, held-out and held-out-2. None qualifies, and for the same
     reasons the pinned analysis gives: a module on the class's import path runs code at
     import (scikit-learn's `KNeighborsRegressor` module appends to a dict at top level), a
     hook the review has not seen (`MultiheadAttention.__setstate__`, a `theta` property
     setter on every Gaussian-process kernel), a function or `REDUCE` target rather than a
     class (`accuracy_score`, `_rebuild_tensor_v2`), a compiled module with no Python
     source (`_gb_losses`, `_ball_tree`, `sgd_fast`), or an owner exclusion
     (`FunctionTransformer`). The option is for classes your installed version has and the
     pinned one lacks, or for distributions safeloadai does not pin; the evaluation has
     neither. Measured with every file scanned again, 0.11.0 with the option gives the
     default verdict on every benign file of held-out, held-out-2, held-out-3 and the
     blind held-out-4; 0.10.0 was stricter on 2, 14, 8 and 5 of them.

## `validate_boosters`

1. **What it does.** A pickled gradient-boosting model (`xgboost.core.Booster`,
   `lightgbm.basic.Booster`, `catboost.core.CatBoost`, `CatBoostClassifier`,
   `CatBoostRegressor`, `CatBoostRanker`) carries its model as bytes that the library's
   native parser reads on unpickling. By default such a file is SUSPICIOUS
   (UNVERIFIABLE): the scanner cannot see that native code. With this option the
   scanner reads each payload with a strict validator of its own, inside the WASI
   sandbox, and clears the class only when every payload of that class is a model the
   validator fully understands:
   - XGBoost: the JSON or UBJSON model (gbtree or dart, from 1.0 to 3.x), with every
     tree's arrays, node links, split features and categorical segments in range;
   - LightGBM: the text model (`_handle` or `handle`), with `tree_sizes` that frame
     each tree exactly, every tree's arrays of the declared length and nothing the
     reader would skip over except the feature importances and parameters sections;
   - CatBoost: the CBM file whose flatbuffer core is the whole file, with oblivious
     trees over float and one-hot features only.

   The pickle around the payload must still be plain: the class may be built only as
   `NEWOBJ ()` and get one `BUILD` with a dict of string keys that is not changed after
   it, and nothing may call the class or the instance. Anything else stays as without
   the option. The option never turns MALICIOUS into anything else.
2. **Risk you accept.** The library's native parser still reads the bytes when you
   load the file, and it does not check everything the validator checks: XGBoost's
   UBJSON reader copies strings without a bounds check and indexes nodes by the file's
   values; LightGBM's reader trusts `tree_sizes` and reads numbers past a line's end;
   CatBoost indexes `BinFeatures` by the file's split indices. A file the validator
   accepts has none of these defects as far as the validator can tell, but a bug in
   the native parser that a well-formed model can still reach, or a validator bug,
   would not be caught. Categorical XGBoost models (a non-empty `cats` container),
   CatBoost models with CTR, text, embedding or non-symmetric trees and LightGBM
   files with a `parser:` section are never cleared.
3. **When to use it, and when not to.**
   - **Use it** when you load XGBoost, LightGBM or CatBoost models from pickles and
     need a CLEAN verdict for plain models from sources you otherwise trust.
   - **Do not use it** for files from sources you do not trust at all: prefer the
     library's own format (`Booster.save_model` to `.ubj`/`.json`, LightGBM `.txt`,
     CatBoost `.cbm`), which needs no pickle.
4. **How to use it.**
   ```python
   report = scan("model.pkl", validate_boosters=True)
   ```
   ```bash
   safeloadai scan model.pkl --validate-boosters
   ```
   or `validate_boosters = true` in a config file named with `--config`.
5. **How to check it in the report.** Look at:
   - `report.options[*]` with `name == "validate_boosters"`;
   - the static layer's `cleared` entries with mechanism `validated-booster`, and its
     `boosters` details: one entry per Booster class with `validated` and either the
     validator's summary of each model (library, encoding, version, booster, trees) or
     the reason it was refused.
6. **Safer alternative.** Leave it off and save the model in the library's own format
   rather than pickling it.

## `known_good`

1. **What it does.** It controls the shipped list of reviewed benign files: exact
   sha256 values of files from the evaluation's tune split, each with a reviewer note.
   - **When it is on (the default).** A file whose sha256 is on the list is CLEAN,
     with the reason `known reviewed file <repo/file>`. Only RISKY or UNVERIFIABLE
     findings are cleared this way. A MALICIOUS finding or an UNSUPPORTED file is
     never cleared.
   - **When it is turned off.** Nothing is cleared by hash.
2. **Risk you accept.** None beyond trusting the review: a file that differs by even
   one byte does not match.
3. **When to use it, and when not to.**
   - **Turn it off** for measurements, or if you want verdicts from analysis alone.
4. **How to use it.**
   ```python
   report = scan("model.pkl", known_good=False)
   ```
   ```bash
   safeloadai scan model.pkl --no-known-good
   ```
5. **How to check it in the report.** Look at:
   - `report.options[*]` with `name == "known_good"`;
   - `report.cleared[*]` with `mechanism == "known-file"`.
6. **Safer alternative.** Not applicable: turning it off is the stricter setting.

## `deep`

1. **What it does.** It also loads the file with the real framework inside a
   Docker, bwrap or nsjail sandbox and records what it does. The result can only
   raise the verdict.
2. **Risk you accept.** The file's own code really runs, contained only by the
   sandbox. A sandbox escape, a misconfigured container or a kernel bug would
   expose the machine. It also needs Docker or a namespace tool and takes much
   longer.
3. **When to use it, and when not to.**
   - **Use it** on a dedicated, disposable machine when you want behavioural
     evidence about a file that static analysis and emulation already call
     SUSPICIOUS.
   - **Never use it** on a workstation with secrets, or in CI that holds
     credentials.
4. **How to use it.**
   ```python
   report = scan("model.pt", deep=True)
   ```
   ```bash
   safeloadai scan model.pt --deep
   ```
5. **How to check it in the report.** Look at:
   - `report.options[*]` with `name == "deep"`;
   - the layer named `deep`, with `ran`, `verdict`, `details` (backend, events) and
     `evidence`.
6. **Safer alternative.** Leave it off. The default static and WASI-emulation layers
   never run the file's code on the host. For more certainty, ask the publisher for
   `.safetensors`.

## `limits`

1. **What it does.** It sets the resource limits of the WASI emulation: memory,
   fuel, wall time and evidence size.
2. **Risk you accept.** Lower limits only make more files SUSPICIOUS, because
   emulation that does not finish fails closed. Higher limits let a hostile file use
   more CPU, memory and time on your machine during a scan, but cannot make a
   verdict less strict.
3. **When to use it, and when not to.**
   - **Lower the limits** for bulk scanning on small machines.
   - **Raise them** only for very large, legitimate models that time out.
4. **How to use it.** This option has no CLI flag.
   ```python
   from safeloadai import scan
   from safeloadai.sandbox.host import Limits
   report = scan("model.pkl", limits=Limits(wall_seconds=10.0))
   ```
5. **How to check it in the report.** Look at:
   - `report.options[*]` with `name == "limits"`, where `value` holds every limit;
   - the `emulation` layer's `details.status`: `fuel_exhausted` or `timeout` means
     a limit was hit.
6. **Safer alternative.** The defaults.

## `deep_backend`

1. **What it does.** It picks the sandbox `--deep` uses (`docker`, `bwrap` or
   `nsjail`) through `SAFELOADAI_DEEP_BACKEND`. It has an effect only when `deep` is on.
2. **Risk you accept.** The backends isolate differently. bwrap and nsjail share
   the host kernel more directly than a Docker container with its own seccomp
   profile.
3. **When to use it, and when not to.** Use it when the machine has several
   backends and you have hardened one of them.
4. **How to use it.** This option is only an environment variable. It never turns
   `deep` on.
   ```python
   import os; os.environ["SAFELOADAI_DEEP_BACKEND"] = "docker"
   report = scan("model.pt", deep=True)
   ```
   ```bash
   SAFELOADAI_DEEP_BACKEND=docker safeloadai scan model.pt --deep
   ```
5. **How to check it in the report.** Look at:
   - `report.options[*]` with `name == "deep_backend"` and
     `source == "environment variable SAFELOADAI_DEEP_BACKEND"`;
   - the `deep` layer's `details`.
6. **Safer alternative.** Do not use `deep`.

## `runtime_path`

1. **What it does.** It points the scanner at another copy of the WASI runtime
   through `SAFELOADAI_WASI_PYTHON`.
2. **Risk you accept.** None for verdicts. The file must still match the pinned
   size and sha256, or the scan stops with `RuntimeIntegrityError` (CLI exit 4).
3. **When to use it, and when not to.** Use it on machines where the
   `safeloadai-runtime` package cannot be installed but the pinned file can be
   copied in.
4. **How to use it.**
   ```python
   import os; os.environ["SAFELOADAI_WASI_PYTHON"] = "/opt/safeloadai/python-3.12.0.wasm"
   report = scan("model.pkl")
   ```
   ```bash
   SAFELOADAI_WASI_PYTHON=/opt/safeloadai/python-3.12.0.wasm safeloadai scan model.pkl
   ```
5. **How to check it in the report.** Look at:
   - `report.options[*]` with `name == "runtime_path"`;
   - the `emulation` layer's `details.runtime`.

   `safeloadai doctor` also reports it.
6. **Safer alternative.** The bundled runtime (`pip install safeloadai`).

## `prompt`

1. **What it does.** On a terminal, when every reason on a file is UNVERIFIABLE,
   the CLI asks whether to accept those items for that file. The default answer is
   No. `--no-input` turns the question off.
2. **Risk you accept.** Answering `y` accepts the listed items, as with
   [`accept_unverified`](#accept_unverified). The answer is recorded as
   `how: "cli-prompt"` and with the source `interactive prompt`. The CLI never asks
   in scripts, in CI, with `--json` or when stdin or stdout is not a terminal.
3. **When to use it, and when not to.**
   - **Keep the prompt** for interactive use.
   - **Pass `--no-input`** for the strictest behaviour, so that nothing is accepted
     unless `--accept-unverified` names it.
4. **How to use it.** This option has no Python API setting; the API never asks.
   ```python
   report = scan("model.pkl")
   ```
   ```bash
   safeloadai scan model.pkl --no-input
   ```
5. **How to check it in the report.** Look at `report.override.how == "cli-prompt"`
   and `report.options[*].source == "interactive prompt"`.
6. **Safer alternative.** `--no-input`.

## Config file

1. **What it does.** `safeloadai scan --config FILE` reads `allow`,
   `accept_unverified`, `deep`, `trust_inert_from`, `known_good` and `validate_boosters` from the `[scan]` table of a TOML file.
   The file adds to the CLI flags and never removes one.
2. **Risk you accept.** A config file can make every scan that names it less
   strict, for the options it sets. That is why it is never read unless named. A
   `safeloadai.toml` sitting next to downloaded models is ignored. When a file is
   named, the CLI prints `reading options from config file FILE` and one warning per
   option, naming the file. Unknown keys, unknown tables, wrong types, wildcards and
   sinks are usage errors (exit 2).
3. **When to use it, and when not to.**
   - **Use it** for a reviewed, version-controlled list of your own classes or
     accepted items in CI.
   - **Do not use it** for a file you did not write, or one that came with the
     models.
4. **How to use it.**
   ```toml
   # safeloadai.toml
   [scan]
   allow = ["mypkg.models:Net"]
   accept_unverified = ["<sha256>:LayerScale"]
   ```
   ```bash
   safeloadai scan models/ --config safeloadai.toml
   safeloadai options --config safeloadai.toml     # shows what the file sets
   ```
   ```python
   # the Python API does not read config files; pass the same values as arguments
   report = scan("model.pkl", allow=[("mypkg.models", "Net")])
   ```
5. **How to check it in the report.** Each option the file set appears in
   `report.options` with `source == "config file <path>"`. Accepted items also have
   `report.override.how == "config"`.
6. **Safer alternative.** Name the exact items on the command line in the CI job
   itself, where the review happens.

## Compiled-module cache

This is not a scan option: it never changes a verdict and is not recorded in
`Report.options`. It only decides where the compiled WASI runtime is kept so that
scans after the first one start fast.

- **Where it lives.** In `compiled/` under the first usable directory of:
  - `$SAFELOADAI_HOME`, when set (then the only candidate);
  - Windows: `%LOCALAPPDATA%\safeloadai`, then `%APPDATA%\safeloadai`, then
    `%TEMP%\safeloadai-<user>` (`%TEMP%` is per user on Windows);
  - macOS: `~/Library/Caches/safeloadai`;
  - Linux and others: `$XDG_CACHE_HOME/safeloadai` (an absolute path only), then
    `~/.cache/safeloadai`. A shared temporary directory such as `/tmp` is never used.
- **What makes a location usable.** It can be created and written, and on POSIX it
  and its parent are owned by you and not writable by group or others (a compiled
  module is native code that wasmtime loads without verification).
- **When none is usable.** Every scan compiles the runtime in memory. Verdicts are the
  same; scans are slower.
- **How to check it.** `safeloadai doctor` prints the directory in use, or `warn` with
  each location it tried and the error it got, for example
  `C:\Users\me\AppData\Local\safeloadai\compiled: PermissionError [WinError 5] Access is denied`.
  The cache never makes the doctor fail.
- **Cache entries** are keyed by the runtime's sha256, the engine configuration and the
  wasmtime version, so an entry from another runtime or wasmtime version is never used.
