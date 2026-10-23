# Releasing safeloadai

How a release is made, what protects the path from this repository to PyPI, and how
users verify what they install. Threat T14 in [THREAT_MODEL.md](THREAT_MODEL.md).

## What protects the release path

| Control | Where | Status |
|---|---|---|
| Every GitHub Action pinned by commit SHA | `.github/workflows/*.yml`; `tests/test_automation.py` fails otherwise | on |
| Dependabot for pip and actions, weekly | `.github/dependabot.yml` | on |
| PyPI **Trusted Publishing** (OIDC, no API token stored anywhere) | `.github/workflows/publish.yml` | on; pending publishers set up once on pypi.org |
| **PEP 740 attestations** on every uploaded file | `publish.yml` (`attestations: true`) | on |
| A real upload only from `main` | `publish.yml` refuses another ref for `target: pypi` | on |
| The `pypi` environment needs a **required reviewer** | repository settings → Environments | **owner to check** (steps below) |
| A **second maintainer** reviews, with **"Prevent self-review"** | repository settings → Environments | **target**, needs a second maintainer |
| Tags `v*` protected (only maintainers create them; nobody moves or deletes them) | repository settings → Rules → Rulesets | **owner to set up** (steps below) |
| `main` protected (pull requests, green CI, no force push) | repository settings → Rules → Rulesets | **owner to check** (steps below) |
| OpenSSF Scorecard, weekly and on push to `main` | `.github/workflows/scorecard.yml`; results in Security → Code scanning | on |
| The WASI runtime pinned by sha256, checked at every use | `safeloadai-runtime`, `sandbox/runtime.py` | on |

The settings marked "owner" cannot be changed from a pull request. They are listed as
exact steps below.

## Release procedure

1. All changes for the release are merged into `main`; CI is green on `main`.
2. Version bumped in `pyproject.toml` (and in `packages/safeloadai-runtime` if the
   runtime changed); `CHANGELOG.md` has the section for the version, dated.
3. Dry run: Actions → **publish** → Run workflow → branch `main`, target `testpypi`.
   Install from TestPyPI in a clean venv and run `safeloadai doctor`.
4. Real run: Actions → **publish** → Run workflow → branch `main`, target `pypi`. The
   run stops at the `pypi` environment until a required reviewer approves it.
5. Verify in a clean venv: `pip install -U safeloadai`, `safeloadai --version`,
   `safeloadai doctor`, and the attestations (next section).
6. Tag and release: create tag `vX.Y.Z` on the released commit, and a GitHub Release
   from it with the changelog section. (The tag ruleset below allows only maintainers to
   create it, and nobody to move it.)
7. Security releases follow [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) as well.

## How users verify a release

Every file on PyPI carries a PEP 740 attestation: a Sigstore-signed statement that this
exact file was built and uploaded by this repository's `publish.yml` workflow. PyPI
checks it at upload; anyone can check it again.

- **On pypi.org:** the project's *Download files* page shows, per file, "Provenance"
  with the repository and the workflow that published it.
- **With the command line** (`pip install pypi-attestations`):

  ```bash
  pypi-attestations verify pypi --repository https://github.com/bartekmosionek12-bit/Sandbox \
      pypi:safeloadai-0.8.0-py3-none-any.whl
  ```

  It downloads the file and its attestation from PyPI and checks the signature and that
  the signing identity is this repository. Do the same for
  `pypi:safeloadai_runtime-<version>-py3-none-any.whl`.
- **Raw:** `https://pypi.org/integrity/safeloadai/<version>/<file name>/provenance`
  returns the provenance JSON (PyPI Integrity API).

Pin by hash in production (`pip install --require-hashes -r requirements.txt` with the
sha256 from PyPI), and remember that `safeloadai-runtime` is installed with it.

## Settings for the owner (exact UI steps)

These change repository protection, so they are made by the owner by hand.

### 1. Required reviewer on the `pypi` environment

1. Repository → **Settings** → **Environments** → **pypi** (create it with **New
   environment** if it does not exist).
2. Tick **Required reviewers**, add yourself (and later the second maintainer).
3. Leave **Prevent self-review** *unticked* while you are the only maintainer;
   otherwise nobody can approve your own release runs. Tick it as soon as a second
   maintainer is a reviewer: then the person who starts a release cannot also approve
   it.
4. Under **Deployment branches and tags**, choose **Selected branches and tags** →
   **Add deployment branch or tag rule** → branch `main`. Save.
5. Do the same for **testpypi** without reviewers if you want dry runs unattended.

**Target:** two maintainers, both required reviewers, **Prevent self-review** on. Until
then, the reviewer step still stops an accidental or hijacked workflow run, but not a
compromised owner account; turning on 2FA with a security key or passkey on GitHub and
PyPI covers that part.

### 2. Protect tags `v*`

1. Repository → **Settings** → **Rules** → **Rulesets** → **New ruleset** → **New tag
   ruleset**.
2. **Ruleset name:** `release tags`. **Enforcement status:** Active.
3. **Bypass list:** add **Repository admin** (only admins may create release tags).
4. **Target tags** → **Add target** → **Include by pattern** → `v*`.
5. **Rules:** tick **Restrict creations**, **Restrict updates**, **Restrict
   deletions** and **Block force pushes**.
6. **Create**.

(The older "Tags → Protected tags" page is deprecated; rulesets replace it.)

### 3. Protect `main`

If `main` has no ruleset or branch protection yet:

1. **Settings** → **Rules** → **Rulesets** → **New ruleset** → **New branch ruleset**.
2. Name `main`, Active, **Target branches** → **Include default branch**.
3. Rules: **Restrict deletions**, **Block force pushes**, **Require a pull request
   before merging** (0 approvals while you are alone, 1 with a second maintainer, and
   **Dismiss stale approvals** on), **Require status checks to pass** → add the CI
   checks `lint`, `build` and the `test (...)` jobs.
4. **Create**. Scorecard's *Branch-Protection* check reads this.

### 4. Account security

- GitHub: 2FA with a passkey or security key; review **Settings → Developer settings**
  for old tokens.
- PyPI: 2FA, no API tokens (Trusted Publishing needs none); the pending publishers for
  `safeloadai` and `safeloadai-runtime` name exactly this repository, `publish.yml` and
  the environment.
