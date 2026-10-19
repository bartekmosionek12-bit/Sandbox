# safeloadai options

Plain `scan(path)` and `safeloadai scan FILE` use only the defaults below. Every
default is the strictest behaviour: no user allowlist, no accepted UNVERIFIABLE items,
no deep detonation, no LLM judge and no config file.

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
| [`deep`](#deep) | `False` | stricter (but runs the file's code) | high |
| [`judge`](#judge) | `False` | stricter (but sends data out) | medium |
| [`limits`](#limits) | `None` (built-in limits) | neutral (lower limits are stricter) | low |
| [`deep_backend`](#deep_backend) | `None` (first available) | neutral | low |
| [`judge_model`](#judge_model) | `None` (built-in model) | neutral | low |
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

## `judge`

1. **What it does.** It sends the static and emulation evidence to an LLM judge,
   which can only raise the verdict.
2. **Risk you accept.** File names, import names, strings and other evidence from
   the file leave your machine for the Anthropic API, which needs
   `ANTHROPIC_API_KEY`. The judge cannot lower a verdict, so it cannot make a file
   look safer.
3. **When to use it, and when not to.**
   - **Use it** for a second opinion on files you are allowed to share.
   - **Do not use it** for confidential models, or where data must not leave the
     network.
4. **How to use it.**
   ```python
   report = scan("model.pkl", judge=True)
   ```
   ```bash
   safeloadai scan model.pkl --judge
   ```
5. **How to check it in the report.** Look at:
   - `report.options[*]` with `name == "judge"`;
   - the layer named `judge`, with `details` (the judge's answer) and `verdict`.
6. **Safer alternative.** Leave it off, and read the categorised `findings` yourself.

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

## `judge_model`

1. **What it does.** It picks which Claude model the judge asks, through
   `SAFELOADAI_JUDGE_MODEL`. It has an effect only when `judge` is on.
2. **Risk you accept.** A weaker model may miss things, but the judge can only
   raise a verdict, so nothing becomes less strict.
3. **When to use it, and when not to.** Use it when your organisation requires a
   specific model.
4. **How to use it.** This option is only an environment variable. It never turns
   `judge` on.
   ```python
   import os; os.environ["SAFELOADAI_JUDGE_MODEL"] = "claude-sonnet-5-5"
   report = scan("model.pkl", judge=True)
   ```
   ```bash
   SAFELOADAI_JUDGE_MODEL=claude-sonnet-5-5 safeloadai scan model.pkl --judge
   ```
5. **How to check it in the report.** Look at `report.options[*]` with
   `name == "judge_model"`, and the `judge` layer's `details`.
6. **Safer alternative.** The default model.

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
   `accept_unverified`, `deep` and `judge` from the `[scan]` table of a TOML file.
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
