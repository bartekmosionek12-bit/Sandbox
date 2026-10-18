# safeloadai-runtime

The pinned CPython 3.12.0 for WASI that [safeloadai](https://github.com/bartekmosionek12-bit/Sandbox)
runs its sandbox in, shipped as package data. You do not install this package yourself:
`pip install safeloadai` pulls in the exact version it was tested with.

```python
import safeloadai_runtime
safeloadai_runtime.path()     # Path to python-3.12.0.wasm inside the installed package
safeloadai_runtime.SHA256     # pinned SHA-256 of that file
```

The package never downloads anything at install time or at run time. The binary is
fetched once, when the package is built, and the build fails if its SHA-256 does not
match. safeloadai checks the hash again, against its own pinned copy, before it uses
the file.

Building:

```bash
python packages/safeloadai-runtime/fetch_runtime.py   # download + verify (build machine only)
python -m build packages/safeloadai-runtime           # refuses to build without a verified .wasm
```

Licences: CPython (PSF-2.0) and the VMware Wasm Labs WASI build (Apache-2.0). Details,
including the statically linked libraries, are in `NOTICE` and `LICENSES/`.
