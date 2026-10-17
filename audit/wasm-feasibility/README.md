# WebAssembly feasibility check (audit, milestone 1)

Throwaway scripts used to produce the numbers in `AUDIT.md` §5. Not product code.

Runtime under test (test only, not for shipping):

- `wasmtime` (PyPI) 49.0.0
- CPython 3.12.0 for WASI, VMware Wasm Labs build, stdlib embedded
  - URL: `https://github.com/vmware-labs/webassembly-language-runtimes/releases/download/python%2F3.12.0%2B20231211-040d5a6/python-3.12.0.wasm`
  - sha256 `e5dc5a398b07b54ea8fdb503bf68fb583d533f10ec3f930963e02b9505f7a763`, 26,267,204 bytes

Artefacts used by `guest_scan.py` (directory passed with `--ro-dir`, mounted read-only as `/in`):

- `sample.pkl`: bytes `\x80\x02cposix\nsystem\nX\x0b\x00\x00\x00echo MARKER\x85R.` (built by hand, never loaded on the host)
- `lambda313.b64`: base64 of `marshal.dumps(compile('lambda x: __import__("os").system("echo MARKER") or x', '<l>', 'eval'))` produced on host CPython 3.13 (dumps only)

Examples:

```
python -I run.py python-3.12.0.wasm "print(1)" --mem-mb 64
python -I run.py python-3.12.0.wasm "$(cat guest_scan.py)" --ro-dir art --fuel 4000000000 --mem-mb 256 --cache fuel.cwasm
python -I run.py python-3.12.0.wasm "while True: pass" --epoch-ms 1000 --cache epoch.cwasm
```

A compiled-module cache is only valid for the same engine config (fuel / epoch on or off).
