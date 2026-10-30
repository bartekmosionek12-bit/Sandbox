# The evidence channel: design and limits

How the WASI guest reports what it saw, what a hostile file can do to that report, what
0.8.0 changed, and what moving the recorder out of the guest would take. Threat model
boundary B2 in [THREAT_MODEL.md](THREAT_MODEL.md).

## How it works today

- The guest is a stock CPython 3.12 build for WASI (`safeloadai-runtime`, pinned by
  sha256), run by wasmtime in a child process with fuel, a memory cap, a wall-clock
  kill, no network and one read-only directory.
- `fd_write` is implemented by the host (`sandbox/runner.py`), not by WASI. Writes to
  fd 3 are evidence records; the host stores each one as raw bytes in arrival order.
  Stdout and stderr are kept for debugging and never interpreted.
- The guest's bootstrap takes a random per-scan nonce out of the environment before it
  touches the file. Every record carries the nonce and a sequence number. The host
  (`sandbox/host.py`) rejects a record without the nonce (tampering, MALICIOUS), needs
  sequence numbers 0, 1, 2, ... and exactly one final `done` record.

## Who can write to the channel

Two kinds of input reach the guest:

- **Data that only drives our code.** A pickle in emulation can only call the fake
  classes the emulator gives it (`guest/fakes.py`). It cannot run Python of its own
  unless it escapes the fakes, which is a bug we would treat as a vulnerability.
- **Code that runs.** A Keras Lambda layer's marshalled bytecode and a dill-pickled
  function's code object are called on fake tensors and fake arguments. That code runs
  in the same interpreter as the recorder. It can find the recorder (through `gc`, for
  example), learn the nonce from it, and call it.

So the question is what code running in the guest can do to the evidence:

| What the code does | Effect | Since 0.8.0 |
|---|---|---|
| Writes to fd 3 without the nonce | tampering: MALICIOUS | unchanged |
| Appends well-formed records | more alarms (noise), never fewer | unchanged |
| Removes records already written | impossible: the host already holds them | unchanged |
| Closes fd 3 | nothing: the host keys on the number | unchanged |
| Writes a forged `done` and leaves with `os._exit(0)` | looked complete | **incomplete**: the runner sees `proc_exit` outside the guest (below) |
| Writes a forged `done` and raises `SystemExit` | two `done` records: incomplete | unchanged |
| Behaves differently in the sandbox (checks `sys.platform`, patches the recorder before its own suspicious step) | the log shows nothing | **still possible**, see "What is left" |

## What 0.8.0 changed

The bootstrap always returns from the module's `_start` function, and for exit status
0 wasi-libc's `_start` then returns without calling the WASI `proc_exit` import
(measured with the pinned runtime: a script that ends normally returns, `os._exit(0)`
and `sys.exit(0)` call `proc_exit(0)`). The runner, which lives outside the guest,
now treats every `proc_exit` as status `exit`, so a run that ended that way is never
complete, whatever records it wrote. A guest cannot forge this: the observation is
made by the host code that calls `_start`.

Tests: `tests/test_wasi_sandbox.py::test_forged_done_then_exit_is_not_a_complete_run`.

## Why not record from host functions only (not feasible now)

The request was to move the recorder out of the guest interpreter, so that code in the
guest cannot append forged records: the host would record through WASI host functions
only.

1. **The guest cannot call a custom host function from Python.** A wasm module calls
   only the imports it was compiled with. The pinned runtime is an unmodified CPython
   build that imports WASI functions and nothing else. Exposing a new import to
   Python code means compiling a C extension module into CPython for WASI, which is a
   new runtime build: new binary, new sha256 pin, new `safeloadai-runtime` release
   with its own supply-chain review (docs/UPDATING_RUNTIME.md).
2. **Even then, the code in the guest could call it.** Whatever Python function wraps
   the host import is in the same interpreter as the Lambda's code. Host functions
   change where records are stored, not who can produce them. Records would still be
   forgeable, so the gain over fd 3 (which the host already owns) is nil.
3. **What the host can record without the guest's help is what crosses the WASI
   boundary:** file opens and reads, clock and random reads, `poll_oneoff` (sleep),
   `proc_exit`. wasmtime implements these on the host, and the runner can wrap them
   (as it does `fd_write`). That record is unforgeable. But with no network, no
   processes and one read-only directory, a payload's interesting behaviour (calling
   `os.system`, which does not exist on WASI; touching a fake) happens at the Python
   level and never crosses the boundary.

## What would separate them (proposed for 0.9, partly decided)

- **Two instances.** Run code-carrying inputs (Lambda, dill code) in a second wasm
  instance with its own store and memory, separate from the instance that parses data.
  One instance cannot read the other's memory, so code in the second cannot learn the
  first one's nonce or touch its records.
- **Evidence from code can raise severity, never clear.** Whatever the code instance
  reports can only raise severity: it may make a file SUSPICIOUS or MALICIOUS,
  never CLEAN. Host-observed WASI calls from it are recorded as host evidence.
- **Consequence, decided and in force since 0.8.0 (DECISIONS.md L1):** a Keras Lambda
  or dill function is never CLEAN on emulation alone; it is at least SUSPICIOUS
  (RISKY). The owner's earlier Lambda rule (CLEAN when static analysis succeeds,
  emulation completes and nothing is recorded) is superseded. Measured cost: of the
  216 benign Keras files (`.keras`, `.h5`) in the tune and held-out splits that 0.8.0
  reports CLEAN, none needs Lambda emulation to be CLEAN (rescanned 2026-10-22), so the
  stricter rule would add no false positive on that corpus.

## What is left (LIMITATIONS)

Code that runs in the guest (Keras Lambda bytecode, dill code objects) shares the
interpreter with the recorder. It can add records, and it can stop its own later
behaviour from being recorded or simply behave harmlessly when it sees the sandbox.
It can no longer fake a complete run by exiting early, and since 0.8.0 such a file is
never CLEAN (DECISIONS.md L1), so hiding from the recorder can at most keep it from
being MALICIOUS. `safe_load` loads Keras only with `safe_mode=True`, which refuses
Lambda layers.
