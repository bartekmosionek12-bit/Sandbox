# Errors and verdicts

safeloadai answers two different questions, and keeps the answers apart:

- **A verdict** says something about the *file*: CLEAN, UNSUPPORTED, SUSPICIOUS or
  MALICIOUS.
- **An error** says that *safeloadai itself* could not finish: the file could not
  be read, a parser raised an exception it does not expect, a sandbox crashed or
  ran out of time, the runtime failed its integrity check, or the options were
  invalid.

## The rule

| Outcome | Meaning | Examples |
|---|---|---|
| **UNSUPPORTED** | The bytes are in no format safeloadai reads. Nothing was analysed. | OpenVINO `.bin` weights, random bytes, a text file |
| **SUSPICIOUS** | safeloadai read the file, and something in it is risky or cannot be verified. This includes a file that is corrupt in a way a loader would also reject. | a truncated pickle; a pickle that refers to a memo entry it never stored; an import outside the allowlist; trailing data |
| **MALICIOUS** | Evidence of a known sink, or of tampering. | `posix.system` imported and called |
| **ERROR** | safeloadai failed. There is no verdict. | file not found; permission denied; the pickle walker raised `KeyError`; the WASI sandbox crashed or timed out |

ERROR is never CLEAN, never loadable by `safe_load`, never accepted by an override
(`--accept-unverified`), never turned CLEAN by the known-file list, and never mixed
into UNSUPPORTED. It is a statement about the tool, so fixing it is our job: please
report an ERROR you can reproduce (see SECURITY.md if it lets a file pass).

One exception: **MALICIOUS evidence found before a failure still decides.** A file
whose static layer found a sink call is MALICIOUS even if the sandbox crashed
afterwards. The report then has `status: "ok"`, the MALICIOUS verdict, and the
failure listed under `errors`.

### A walk failure: file or tool?

The pickle walker stops at the first point a real unpickler would reject or read
differently. Where it stops decides the outcome:

- It stopped on something in the bytes (the walker raised its own `VMError`, or
  `pickletools` could not decode an opcode): **SUSPICIOUS**, with the reason in
  plain words, for example
  `pickle is not readable: it refers to stored object 101 that it never stored
  (pickle.load fails there)` or `pickle is not readable: it is truncated: ...`.
  Exceeding a reading limit (more opcodes or pickles than safeloadai reads) is
  also SUSPICIOUS.
- It stopped on a gap in safeloadai (an opcode it does not model) or on any
  other exception (`KeyError`, `AttributeError`, `RecursionError`, ...):
  **ERROR `E201`**.

The same split applies to the HDF5 reader: a structure it refuses is a SUSPICIOUS
reason, an exception that escapes it is `E203`.

Every walk failure in the 0.7.0/0.7.1 evaluation (`evaluation/results/eval-v07*-*.json`)
was decided case by case:

| Failure as 0.7.x reported it | Files | Decision |
|---|---|---|
| `ValueError: not enough data in stream to read uint4` | 3 Hub malicious | file: truncated pickle, SUSPICIOUS (`pickle.load` fails there too) |
| `VMError: GLOBAL at N crosses the end of its frame` | 3 Hub malicious | file: inconsistent framing, SUSPICIOUS |
| `ValueError: at position N, opcode b'\xff' unknown` | 1 lab | file: not a pickle opcode, SUSPICIOUS |
| `VMError: NumpyArrayWrapper at N: unexpected numpy.dtype arguments` | 1 Hub benign (held-out) | **tool gap, fixed**: old numpy pickled `dtype('f8', 0, 1)` instead of `dtype('f8', False, True)`; both are read now |
| `VMError: memo key N not found` | (none in 0.7.x; seen in earlier runs) | file: refers to a memo entry it never stored, SUSPICIOUS |

## Report fields

Every report (`Report.to_dict()`, `safeloadai scan --json`) has:

| Field | When `status` is `"ok"` | When `status` is `"error"` |
|---|---|---|
| `status` | `"ok"` | `"error"` |
| `verdict` | `CLEAN`, `UNSUPPORTED`, `SUSPICIOUS` or `MALICIOUS` | `null` |
| `error` | `null` | `{"code", "message", "layer"}` (the first failure) |
| `errors` | failures next to MALICIOUS evidence, usually `[]` | every failure seen |
| `reasons`, `findings` | why the verdict | what was found before the failure (informational only) |

In Python, `report.verdict` is `None` for an error, `report.ok` is `False`, and
`report.outcome` is `"ERROR"` (otherwise the verdict's name). `safe_load` raises
`UnsafeModelError`; its `.error` holds the error and `.verdict` is `None`.

Schema version 3.0 introduced `status`, `error` and `errors`.

## Error codes

Codes are stable: a code is never reused for a different failure. `layer` says
where it happened (`io`, `static`, `emulation`, `deep`, `runtime`, `options`).

### E1xx: reading the file

| Code | Meaning | What to do |
|---|---|---|
| `E101` | file not found | check the path |
| `E102` | file could not be read (permission denied, I/O error) | check permissions and the disk |
| `E103` | file too large to read (over 4 GiB) | out of scope for this version |
| `E104` | path is not a regular file (a directory, socket, device) | pass a file, or a directory to `safeloadai scan` |
| `E105` | resource limit reached: the static analysis on the host needs more memory than one scan may hold (512 MiB plus twice the file's size, at most 4 GiB of string and bytes data plus 64 bytes per opcode) | the file asks for far more memory than its size explains; it is not loaded. Treat it as you would a SUSPICIOUS file |

### E2xx: a parser raised an exception it does not expect

These are bugs in safeloadai. Please report them with the file's sha256 (and the
file, if you may share it).

| Code | Meaning |
|---|---|
| `E200` | internal error in the static analysis outside a format reader |
| `E201` | internal error in the pickle walker (also: an opcode the walker does not model) |
| `E202` | internal error in the Keras reader |
| `E203` | internal error in the HDF5 metadata reader (inside the WASI sandbox) |
| `E204` | internal error in the PyTorch archive reader |
| `E205` | internal error in the joblib reader |

### E3xx: the sandboxes

| Code | Meaning | What to do |
|---|---|---|
| `E300` | internal error in the emulation layer | report it |
| `E301` | WASI sandbox unavailable (runtime missing, wasmtime missing) | run `safeloadai doctor` |
| `E302` | WASI sandbox crashed (wasm trap, non-zero exit, runner failure) | report it if it repeats |
| `E303` | WASI sandbox timed out (wall-clock limit) | retry on a less loaded machine |
| `E304` | WASI sandbox ran out of its compute budget (fuel). By default the budget grows with the pickle data and its opcode count, up to 250 billion fuel, 120 s and 2 GiB of guest memory | the file asks for more work than the ceiling allows; report it with the file's sha256 |
| `E310` | deep sandbox did not run (no backend, no detoner for the format, no result) | see `--deep` in docs/OPTIONS.md |
| `E311` | deep sandbox timed out | |

A timeout or a crash can be provoked by a file (a pickle that builds a huge object,
for example). That is still an ERROR, not a verdict: it blocks the file just the
same, and its exit code ranks above SUSPICIOUS.

### E4xx: runtime integrity

| Code | Meaning | What to do |
|---|---|---|
| `E401` | the WASI runtime is not the pinned build (sha256 mismatch) | reinstall `safeloadai-runtime`; run `safeloadai doctor` |

No result of a scan with `E401` is trusted, so no verdict is given, not even
MALICIOUS.

### E5xx: options and usage

| Code | Meaning |
|---|---|
| `E501` | invalid scan option passed to `scan()` / `safe_load()` (for example `allow=[("builtins", "exec")]`, or a `trust_inert_from` distribution that is not installed) |

The CLI checks options before it scans anything and exits 2 on a usage error, so
`E501` appears in reports from the Python API.

### Not errors

- An unavailable LLM judge (`--judge`): the judge can only raise severity, so its
  absence changes nothing; the judge layer says why it did not run.
- A loader inside the deep sandbox that rejects the file: that is a statement about
  the file (SUSPICIOUS).

## CLI exit codes

Every file gets its own result; a failure on one file does not stop the others.
The exit code of `safeloadai scan` is the first that applies:

| Exit | Meaning |
|---|---|
| 1 | at least one file is MALICIOUS |
| 4 | ERROR: the WASI runtime failed its integrity check (`E401`) |
| 6 | ERROR: safeloadai failed on at least one file (any other code) |
| 3 | at least one file is SUSPICIOUS (without an accepted override) |
| 5 | at least one file is UNSUPPORTED |
| 0 | every file is CLEAN, or SUSPICIOUS with an accepted override |
| 2 | usage error (invalid options or config file), or nothing to scan; nothing was scanned |

Precedence: **MALICIOUS > ERROR > SUSPICIOUS > UNSUPPORTED > CLEAN.** A CI job that
fails on any non-zero exit therefore fails on every ERROR.

With `--sarif FILE` an ERROR is a result of its own (rule `safeloadai/error`, level
`error`, the code in its message and in `properties.errorCode`), never a missing
result: a code-scanning view never shows an unscanned file as passed.

### `--malicious-only` (binary output)

For integrations that need a yes/no answer, `safeloadai scan --malicious-only` prints
`MALICIOUS` or `NOT-MALICIOUS` per file and exits **1** when a file is MALICIOUS, **4**
or **6** when safeloadai could not scan a file (an ERROR is never reported as
NOT-MALICIOUS), and **0** otherwise. SUSPICIOUS and UNSUPPORTED files therefore exit 0.

It is an output mode only. The verdict does not change: `--json` and `--report` carry
the full Report, a warning on stderr says what the mode hides, and `safe_load` still
refuses every file that is not CLEAN. Use it only where a SUSPICIOUS file is handled
some other way (it is still not loadable). Measured on the evaluation sets with
`evaluation/malicious_only.py`.
