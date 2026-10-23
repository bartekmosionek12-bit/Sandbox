"""Write docs/EVALUATION.md from an evaluation result file (run_eval.py's JSON).

Every number in the page comes from the JSON; nothing is typed by hand.

    python evaluation/make_evaluation_doc.py                                  # the default result file
    python evaluation/make_evaluation_doc.py evaluation/results/eval-v070-20261020T063605Z.json
    python evaluation/make_evaluation_doc.py --check                          # exit 1 if a page is stale
    python evaluation/make_evaluation_doc.py AFTER.json --before BEFORE.json  # with the before/after section

It also writes the results block of README.md, between ``<!-- evaluation:start -->`` and
``<!-- evaluation:end -->``.

Definitions (also stated in the page):

* A file's prediction is **positive** when the tool blocks it for a reason about the file:
  for safeloadai SUSPICIOUS or MALICIOUS, for another scanner "flagged".
* **UNSUPPORTED** (the tool reads no format in the file) and **ERROR** (the tool failed)
  are counted in their own columns. They are never a detection and never a miss, and
  they are left out of precision, recall and FPR.
* TP: malicious and positive. FN: malicious and CLEAN. FP: benign and positive.
  TN: benign and CLEAN. Files labelled "unclear" are counted apart.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RESULT = os.path.join(ROOT, "evaluation", "results", "eval-v080-20261022T132827Z.json")
DEFAULT_BEFORE = os.path.join(ROOT, "evaluation", "results", "eval-v080-before-v071-20261022T132812Z.json")
OUT = os.path.join(ROOT, "docs", "EVALUATION.md")
README = os.path.join(ROOT, "README.md")
README_START, README_END = "<!-- evaluation:start -->", "<!-- evaluation:end -->"
SPLITS = os.path.join(ROOT, "evaluation", "splits")
GROUP_ORDER = ("lab", "mutations", "hf-malicious", "hf-unsafe", "hf-tune", "hf-heldout", "hf-heldout2")
HELD_OUT = ("hf-heldout", "hf-heldout2")
DEFAULT, TRUST, UPPER = "safeloadai", "safeloadai trust-inert-from", "safeloadai upper bound"
VARIANTS = {DEFAULT: "default", TRUST: "`--trust-inert-from`", UPPER: "upper bound (not recommended)"}
BLOCKS = ("clean", "soft", "hard", "unsupported", "error")
GROUP_TEXT = {
    "lab": "Lab corpus: marker payloads and benign controls built by `tests/corpus/build_corpus.py`",
    "mutations": "Mutations of the lab payloads (encodings, containers, nesting) by `tests/corpus/mutate.py`",
    "hf-malicious": "Hub files the Hub's own scanners flag (`evaluation/fetch_malicious_hf.py`)",
    "hf-tune": "Benign Hub corpus, tune half (the only half the allowlist reviews looked at)",
    "hf-heldout": "Benign Hub corpus, held-out half (never looked at while tuning)",
    "hf-unsafe": "Further Hub files the Hub's scanners flag, scanned in batches and deleted (`evaluation/batch_hf.py`)",
    "hf-heldout2": "Second benign held-out set: repositories no earlier corpus used, scanned in batches and deleted "
                   "(`evaluation/batch_hf.py`); never used for tuning",
}
LABEL_ORIGIN = {
    "lab": "by construction (we wrote the payload or the benign control)",
    "mutations": "by construction (a mutation keeps its source file's label)",
    "hf-malicious": "Hub scanner evidence plus manual review of that evidence (`evaluation/hf_malicious_labels.tsv`); "
                    "never safeloadai's verdict",
    "hf-tune": "benign by selection (popular repositories of known libraries); files the Hub flags were reviewed "
               "by hand and relabelled",
    "hf-heldout": "same as hf-tune",
    "hf-unsafe": "Hub scanner evidence plus manual review (`evaluation/hf_batches_labels.tsv`); never safeloadai's "
                 "verdict; unclear until reviewed",
    "hf-heldout2": "benign by selection; files the Hub flags are unclear until reviewed by hand "
                   "(`evaluation/hf_batches_labels.tsv`, rules in `evaluation/review_heldout2_labels.py`)",
}
POSITIVE = {"SUSPICIOUS", "MALICIOUS"}
# batch_hf.declared_poc: a benign-by-selection file from a repository whose name declares a
# proof of concept or a scanner test is labelled unclear. Every label-dependent table is
# also given without that rule (owner's decision of 2026-10-23).
POC_REASON = "repository name declares a proof of concept"
NO_RULE = "without PoC rule"


def wilson(k: int, n: int, z: float = 1.96) -> str:
    """95 % Wilson score interval of k/n, as "[lo, hi]"."""
    if n == 0:
        return "-"
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return f"[{max(0.0, centre - half):.3f}, {min(1.0, centre + half):.3f}]"


def ratio(k: int, n: int) -> str:
    return f"{k / n:.3f}" if n else "-"


def rate(k: int, n: int) -> str:
    """k/n with its interval, or "-" when there is nothing to measure."""
    return f"{ratio(k, n)} {wilson(k, n)}" if n else "-"


def without_rule(entries: list[dict]) -> list[dict]:
    """The entries with the repository-name rule undone: its files are benign again."""
    return [dict(e, label="benign") if POC_REASON in (e.get("label_reason") or "") else e for e in entries]


def rule_count(entries: list[dict]) -> Counter:
    return Counter(e["group"] for e in entries if POC_REASON in (e.get("label_reason") or ""))


def outcome(result: dict, own: bool) -> str:
    """positive / clean / unsupported / error / skipped for one tool's result on one file."""
    if own:
        if result.get("outcome") == "error" or result.get("block") == "error":
            return "error"
        verdict = result.get("verdict")
        if verdict == "UNSUPPORTED":
            return "unsupported"
        if verdict == "CLEAN":
            return "clean"
        return "positive" if verdict in POSITIVE else "error"
    value = result.get("outcome", "error")
    return {"flagged": "positive"}.get(value, value)


def matrix(entries: list[dict], tool: str) -> dict:
    own = tool.startswith("safeloadai")
    m = Counter()
    for entry in entries:
        result = entry["results"].get(tool)
        if result is None:
            continue
        got = outcome(result, own)
        label = entry["label"]
        if label == "unclear":
            m["unclear_" + ("positive" if got == "positive" else "other")] += 1
        elif got in ("unsupported", "error", "skipped"):
            m[f"{label}_{got}"] += 1
        elif label == "malicious":
            m["tp" if got == "positive" else "fn"] += 1
        else:
            m["fp" if got == "positive" else "tn"] += 1
    return m


def matrix_row(name: str, m: Counter) -> str:
    tp, fn, fp, tn = m["tp"], m["fn"], m["fp"], m["tn"]
    unsupported = m["malicious_unsupported"] + m["benign_unsupported"]
    errors = m["malicious_error"] + m["benign_error"]
    skipped = m["malicious_skipped"] + m["benign_skipped"]
    return (f"| {name} | {tp} | {fn} | {fp} | {tn} | {ratio(tp, tp + fp)} | {rate(tp, tp + fn)} | "
            f"{rate(fp, fp + tn)} | {unsupported} | {errors} | {skipped} |")


def matrix_rows(name: str, entries: list[dict], tool: str = "safeloadai") -> list[str]:
    """The row with the PoC rule and the row without it."""
    return [matrix_row(name, matrix(entries, tool)),
            matrix_row(f"{name}, {NO_RULE}", matrix(without_rule(entries), tool))]


MATRIX_HEAD = ("| {first} | TP | FN | FP | TN | precision | recall [95 % CI] | FPR [95 % CI] | UNSUPPORTED | "
               "ERROR | skipped |\n|---|---|---|---|---|---|---|---|---|---|---|")


def by_group(entries: list[dict]) -> dict[str, list[dict]]:
    groups = defaultdict(list)
    for entry in entries:
        groups[entry["group"]].append(entry)
    return {g: groups[g] for g in GROUP_ORDER if g in groups}


def split_repos() -> dict[str, int]:
    out = {}
    for name in ("hf-tune", *HELD_OUT):
        path = os.path.join(SPLITS, f"{name}.txt")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                out[name] = sum(1 for line in fh if line.strip() and not line.startswith("#"))
    return out


COMPARISON_NOTE = ("A detailed per-format comparison is withheld until coordinated disclosure with the affected "
                   "projects is complete.")


def comparison(data: dict, tools: list[str]) -> list[str]:
    """Other scanners: one table over all files, from the run's totals, and nothing finer."""
    if not tools:
        return []
    lines = ["## Compared with other scanners (all files)", "",
             "Every labelled file of the run, whatever its format; \"detected\" is any verdict other than CLEAN "
             "(\"flagged\" for the other scanners). Errors, unsupported and skipped files are counted apart and are "
             "neither a detection nor a miss.", "",
             "| tool | detected / malicious | false positives / benign | errors | unsupported | skipped |",
             "|---|---|---|---|---|---|"]
    summary = data.get("summary") or {}
    # Other scanners' per-file results are withheld from the committed file, so their totals
    # without the PoC rule come from redact_results.py, computed before the redaction.
    plain = data.get("summary_without_poc_rule") or {}
    for tool in ["safeloadai", *tools]:
        for name, t in ((tool, summary.get(tool)),
                        (f"{tool}, {NO_RULE}", plain.get(tool) or totals(without_rule(data["entries"]), tool))):
            if t:
                lines.append(f"| {name} | {t['detected']} / {t['malicious']} | {t['false_positives']} / "
                             f"{t['benign']} | {t['errors']} | {t['unsupported']} | {t['skipped']} |")
    return lines + ["", COMPARISON_NOTE, ""]


def totals(entries: list[dict], tool: str) -> dict | None:
    """The all-files comparison for one tool, from the entries (run_eval.py's summary)."""
    rows = [(e["label"], e["results"][tool]) for e in entries if tool in e["results"]]
    if not rows:
        return None
    t = Counter(malicious=sum(label == "malicious" for label, _ in rows),
                benign=sum(label == "benign" for label, _ in rows))
    for label, result in rows:
        t["detected"] += label == "malicious" and result.get("outcome") == "flagged"
        t["false_positives"] += label == "benign" and result.get("outcome") == "flagged"
    for key in ("error", "unsupported", "skipped"):
        t[key + "s" if key == "error" else key] = sum(r.get("outcome") == key for _, r in rows)
    return dict(t)


def blocks_of(entries: list[dict], tool: str) -> Counter:
    """What a user meets on benign files: CLEAN, a soft block (UNVERIFIABLE reasons only,
    acceptable item by item), a hard block, UNSUPPORTED or ERROR."""
    return Counter((e["results"].get(tool) or {}).get("block") or "error"
                   for e in entries if e["label"] == "benign" and tool in e["results"])


def blocks_row(name: str, c: Counter, plain: Counter) -> str:
    """One configuration with the PoC rule (``c``) and without it (``plain``)."""
    def fpr(x: Counter) -> str:
        return rate(x["soft"] + x["hard"], x["clean"] + x["soft"] + x["hard"])

    return (f"| {name} | " + " | ".join(str(c[b]) for b in BLOCKS) +
            f" | {sum(c.values())} | {fpr(c)} | {sum(plain.values())} | {fpr(plain)} |")


def blocks_rows(name: str, entries: list[dict], tool: str) -> str:
    return blocks_row(name, blocks_of(entries, tool), blocks_of(without_rule(entries), tool))


BLOCKS_HEAD = ("| {first} | CLEAN | soft block | hard block | UNSUPPORTED | ERROR | benign files | "
               "FPR on readable files [95 % CI] | benign files, " + NO_RULE + " | FPR, " + NO_RULE + " |\n"
               "|---|---|---|---|---|---|---|---|---|---|")


def held_out_section(entries: list[dict], before: dict | None, version: str) -> list[str]:
    lines = ["## What a user meets on held-out benign files", "",
             "A false positive is not one thing. A *soft block* has only UNVERIFIABLE reasons and can be accepted "
             "item by item for that file; a *hard block* has a RISKY or MALICIOUS reason and cannot. The FPR here "
             "is soft plus hard blocks over the files in a format safeloadai reads (CLEAN, soft or hard).", "",
             "- **default**: no options.",
             "- **`--trust-inert-from`**: `--trust-inert-from scikit-learn transformers torch`, reading those "
             "libraries' source (the evaluation reads unpacked distributions, `run_eval.py --opt-in-site`).",
             "- **upper bound**: every UNVERIFIABLE item of every file accepted. Not a switch and not recommended: "
             "it is the most any override could clear.", ""]
    old = {(e["group"], e["file"]): e for e in (before or {}).get("entries", [])}
    for group in HELD_OUT:
        rows = [e for e in entries if e["group"] == group]
        if not rows:
            continue
        lines += [f"### {group}", ""]
        if old:
            paired = [e for e in rows if (group, e["file"]) in old]
            prior = [old[(group, e["file"])] for e in paired]
            lines += [f"The same {sum(1 for e in paired if e['label'] == 'benign')} benign files (same commit and "
                      f"sha256) with safeloadai {before['safeloadai']} (before) and {version} (after).", "",
                      BLOCKS_HEAD.format(first="configuration")]
            for tool, name in VARIANTS.items():
                lines.append(blocks_rows(f"before: {name}", prior, tool))
                lines.append(blocks_rows(f"**after: {name}**", paired, tool))
        else:
            lines += [BLOCKS_HEAD.format(first="configuration")]
            lines += [blocks_rows(name, rows, tool) for tool, name in VARIANTS.items()]
        lines.append("")
    return lines


def malicious_only_section(entries: list[dict]) -> list[str]:
    """``--malicious-only`` prints MALICIOUS or NOT-MALICIOUS from the same verdict, so its
    numbers follow from the recorded verdicts (``evaluation/malicious_only.py``)."""
    lines = ["## `--malicious-only`", "",
             "`safeloadai scan --malicious-only` blocks only a MALICIOUS verdict (exit 1); SUSPICIOUS, CLEAN and "
             "UNSUPPORTED pass. The verdict is the same as by default, so these numbers come from the same scans. "
             "Detection: malicious files blocked; FP: benign files blocked. ERROR exits 4 or 6 in both modes and is "
             "counted apart.", "",
             "| group | detection, default | detection, --malicious-only | FP, default | FP, --malicious-only | "
             f"FP, default, {NO_RULE} | FP, --malicious-only, {NO_RULE} | errors |",
             "|---|---|---|---|---|---|---|---|"]
    for group, rows in [*by_group(entries).items(), ("all", entries)]:
        c, n = malicious_only_counts(rows), malicious_only_counts(without_rule(rows))
        name = "**all**" if group == "all" else group
        lines.append(f"| {name} | {frac(c['malicious_default'], c['malicious'])} | "
                     f"{frac(c['malicious_binary'], c['malicious'])} | {frac(c['benign_default'], c['benign'])} | "
                     f"{frac(c['benign_binary'], c['benign'])} | {frac(n['benign_default'], n['benign'])} | "
                     f"{frac(n['benign_binary'], n['benign'])} | {c['errors']} |")
    passed = Counter(e["group"] for e in entries if e["label"] == "malicious"
                     and e["results"]["safeloadai"].get("verdict") not in ("MALICIOUS", None))
    if passed:
        lines += ["", f"Malicious-labelled files that `--malicious-only` lets through (SUSPICIOUS by default): "
                      f"{sum(passed.values())} (" + ", ".join(f"{g}: {passed[g]}" for g in GROUP_ORDER if passed[g])
                  + "). A per-file account is kept with the private results."]
    return lines + [""]


def malicious_only_counts(rows: list[dict]) -> Counter:
    c = Counter()
    for e in rows:
        label, result = e["label"], e["results"]["safeloadai"]
        if label not in ("malicious", "benign"):
            continue
        c[label] += 1
        if result.get("outcome") == "error" or result.get("verdict") is None:
            c["errors"] += 1
            continue
        c[label + "_default"] += result["verdict"] != "CLEAN"
        c[label + "_binary"] += result["verdict"] == "MALICIOUS"
    return c


def skipped_note(data: dict) -> list[str]:
    """Files planned but not scanned because this machine ran out of memory on them."""
    rows = data.get("skipped_files") or []
    if not rows:
        return []
    return [f"- {len(rows)} planned file(s) could not be scanned on the evaluation machine (15 GB of memory; "
            "safeloadai ran out of memory) and are left out of every table: " +
            ", ".join(f"`{r['file']}` ({r['size'] // 2 ** 20} MiB)" for r in rows) +
            ". Peak memory on large pickles is a known issue."]


def poc_rule_section(entries: list[dict]) -> list[str]:
    counts = rule_count(entries)
    if not counts:
        return []
    return ["", "### Repository-name rule for proofs of concept", "",
            "A Hub file is benign by selection: it comes from a popular-library stratum and the Hub's scanners do "
            "not flag it. That says nothing about a repository whose name declares a vulnerability proof of "
            "concept or a scanner test (words such as `poc`, `exploit`, `bypass`, `malicious`, `rce`, `payload`, "
            "`huntr` between separators in the repository id; `evaluation/batch_hf.py: DECLARED_POC`). Such a "
            "file is labelled unclear instead of benign. The rule looks at the repository name only, never at a "
            "verdict, but it was written after the first pass over hf-heldout2, when its results were known, so "
            "it is not blind. Every table that depends on labels is therefore also given without the rule (rows "
            f"or columns marked \"{NO_RULE}\"), where these files count as benign.", "",
            "| group | files the rule labels unclear |", "|---|---|",
            *[f"| {g} | {counts[g]} |" for g in GROUP_ORDER if counts[g]],
            f"| **all** | **{sum(counts.values())}** |"]


# Bugs in the code (not allowlist tuning) that the held-out sets surfaced in 0.8.0. Each was
# reproduced on a synthetic file, fixed generally and tested (owner's decision of 2026-10-23).
HELDOUT_BUGS = (
    ("host memory", "a large dill pickle made the static analysis on the host hold more than 13 GB "
                    "(the listing for the dashboard); now bounded, and running out is ERROR E105",
     "tests/test_resource_limits.py"),
    ("cloudpickle", "a function or class pickled by cloudpickle was MALICIOUS without any sink "
                    "(`builtins.type`, `staticmethod` and cloudpickle's helpers were treated as sinks); now the "
                    "path of dill functions and Keras Lambdas", "tests/test_cloudpickle.py"),
    ("dill arrays", "dill's `_create_array` (numpy array reconstruction) was a code-execution sink; now judged "
                    "by its first argument", "tests/test_cloudpickle.py"),
    ("dill globals", "dill's `__builtin__.__main__` (the globals of a pickled function) was a sink",
     "tests/test_cloudpickle.py"),
    ("emulation budget", "large pickles ran out of the emulation's compute budget (ERROR E304); the budget now "
                         "grows with the file, up to a fixed ceiling", "tests/test_emulation.py"),
)


def heldout_bugs_section() -> list[str]:
    return ["", "### Bugs the held-out sets surfaced", "",
            "The held-out rule (nothing is tuned on held-out files) is about the allowlists, policies and the "
            "known-file list. Bugs in the code that the held-out files showed were fixed: each was reproduced on "
            "a synthetic file of our own (a marker, never the Hub file), fixed in general and covered by a test. "
            "For files of these kinds the held-out measurement is no longer blind.", "",
            "| kind | what was wrong | test |", "|---|---|---|",
            *[f"| {kind} | {what} | `{test}` |" for kind, what, test in HELDOUT_BUGS]]


def frac(k: int, n: int) -> str:
    return f"{k} / {n}" if n else "-"


def render(data: dict, source: str, before: dict | None = None) -> str:
    entries = data["entries"]
    tools = [t for t in data["tools"] if not t.startswith("safeloadai")]
    groups = by_group(entries)
    lines = [
        "# Evaluation",
        "",
        f"<!-- Generated by evaluation/make_evaluation_doc.py from {source}. Do not edit by hand. -->",
        "",
        f"Numbers from `{source}`: safeloadai {data['safeloadai']}, Python {data['python']}, "
        f"{data['platform']}, {len(entries)} files, run {data['created']}. Every number on this page is "
        "generated from that file by `evaluation/make_evaluation_doc.py`; CI checks that the page is current.",
        "",
        "## How to read the numbers",
        "",
        "- **Positive** means the tool blocks the file for a reason about the file: SUSPICIOUS or MALICIOUS for "
        "safeloadai, \"flagged\" for the other scanners.",
        "- **UNSUPPORTED** (the tool reads no format in the file) and **ERROR** (the tool itself failed; "
        "[ERRORS.md](ERRORS.md)) have their own columns. They are never a detection and never a miss, and they are "
        "left out of precision, recall and FPR. \"skipped\" is a file a scanner chose not to open.",
        "- **TP** malicious and positive, **FN** malicious and CLEAN (a miss), **FP** benign and positive, **TN** "
        "benign and CLEAN. Files whose label is unclear are counted apart.",
        "- precision = TP / (TP + FP), recall = TP / (TP + FN), FPR = FP / (FP + TN). The intervals are 95 % "
        "Wilson score intervals: with a few dozen files per cell they are wide, and they say so.",
        "- safeloadai runs with its defaults (no options, the shipped known-file list on).",
        "",
        "## Data",
        "",
        "### Where the files come from",
        "",
        "| group | what it is | how the label was decided | malicious | benign | unclear |",
        "|---|---|---|---|---|---|",
    ]
    for group, rows in groups.items():
        labels = Counter(e["label"] for e in rows)
        lines.append(f"| {group} | {GROUP_TEXT.get(group, group)} | {LABEL_ORIGIN.get(group, '-')} | "
                     f"{labels['malicious']} | {labels['benign']} | {labels['unclear']} |")
    total = Counter(e["label"] for e in entries)
    lines.append(f"| **all** | | | **{total['malicious']}** | **{total['benign']}** | **{total['unclear']}** |")
    plain = Counter(e["label"] for e in without_rule(entries))
    lines.append(f"| all, {NO_RULE} | | | {plain['malicious']} | {plain['benign']} | {plain['unclear']} |")

    formats = sorted({e["format"] for e in entries})
    lines += ["", "### Files per group and format", "",
              "| group | " + " | ".join(formats) + " | total |", "|---|" + "---|" * (len(formats) + 1)]
    for group, rows in groups.items():
        count = Counter(e["format"] for e in rows)
        lines.append(f"| {group} | " + " | ".join(str(count[f]) for f in formats) + f" | {len(rows)} |")

    benign_groups = [g for g in ("hf-tune", *HELD_OUT) if g in groups]
    hub = [e for e in entries if e["group"] in benign_groups]
    if hub:
        libraries = sorted({e.get("library") or "-" for e in hub})
        lines += ["", "### Benign Hub files per library stratum", "",
                  "| stratum | " + " | ".join(benign_groups) + " |", "|---|" + "---|" * len(benign_groups)]
        for lib in libraries:
            lines.append(f"| {lib} | " + " | ".join(
                str(sum(1 for e in groups[g] if (e.get("library") or "-") == lib)) for g in benign_groups) + " |")

    lines += poc_rule_section(entries)
    own_made = sum(1 for e in entries if e["label"] == "malicious" and e["group"] in ("lab", "mutations"))
    lines += [
        "",
        "### An honest note on the malicious side",
        "",
        f"{own_made} of the {total['malicious']} malicious files ({ratio(own_made, total['malicious'])}) are our own "
        "lab payloads and their mutations. They are built to cover every technique we know of (public scanner "
        "bypasses rebuilt with marker payloads, every pickle encoding, every container), so they measure coverage "
        "of known techniques, not how often real attacks are caught. The real-world malicious files are the Hub "
        "files the Hub's scanners flag; there are few, many are proofs of concept rather than attacks, and their "
        "labels come from the Hub's evidence, not from ground truth. A recall of 1.0 on this corpus is therefore "
        "not a claim that safeloadai catches every attack: it says no file in this corpus got through.",
    ]

    repos = split_repos()
    lines += [
        "",
        "### Tune and held-out split (overfitting)",
        "",
        "The benign Hub corpus is split in two by a hash of the repository id "
        "(`evaluation/fetch_benign_hf.py: split_of`), so every file of one repository is on the same side and a "
        "repository's sibling files cannot leak into the other half. Allowlist reviews, policies, profiles and the "
        "known-file list were built from the tune half only (`evaluation/splits/hf-tune.txt`). The held-out half "
        "(`evaluation/splits/hf-heldout.txt`) is the false-positive rate we report. A large gap between the two "
        "FPRs is what overfitting to the tune half looks like. hf-heldout2 is a second held-out set from "
        "repositories no earlier corpus used, measured once with the final release.",
        "",
        f"| split | repositories | files | benign | FPR (safeloadai) [95 % CI] | benign, {NO_RULE} | "
        f"FPR, {NO_RULE} |",
        "|---|---|---|---|---|---|---|",
    ]
    for group in benign_groups:
        rows = groups[group]
        m, n = matrix(rows, "safeloadai"), matrix(without_rule(rows), "safeloadai")
        repo_count = repos.get(group) or len({e.get("repo_id") or e["file"].rsplit("/", 1)[0] for e in rows})
        lines.append(f"| {group} | {repo_count} | {len(rows)} | "
                     f"{sum(1 for e in rows if e['label'] == 'benign')} | {rate(m['fp'], m['fp'] + m['tn'])} | "
                     f"{n['fp'] + n['tn'] + n['benign_unsupported'] + n['benign_error']} | "
                     f"{rate(n['fp'], n['fp'] + n['tn'])} |")

    lines += heldout_bugs_section()
    lines += ["", "## Confusion matrix per group", "",
              "Precision depends on each group's mix of malicious and benign files. The benign Hub groups hold "
              "only a handful of malicious files, so their precision says little; read their FPR. The lab, "
              "mutation and hf-malicious groups are mostly malicious; read their recall.", "",
              "### all labelled files", "", MATRIX_HEAD.format(first="tool"), *matrix_rows("safeloadai", entries), ""]
    for group, rows in groups.items():
        lines += [f"### {group}", "", MATRIX_HEAD.format(first="tool"), *matrix_rows("safeloadai", rows)]
        unclear = matrix(rows, "safeloadai")
        if unclear["unclear_positive"] or unclear["unclear_other"]:
            lines.append("")
            lines.append(f"Unclear labels in this group: {unclear['unclear_positive'] + unclear['unclear_other']} "
                         f"(safeloadai positive on {unclear['unclear_positive']}).")
        lines.append("")
    lines += comparison(data, tools)

    lines += ["## safeloadai per group and format", "", MATRIX_HEAD.format(first="group / format")]
    for group, rows in groups.items():
        for fmt in sorted({e["format"] for e in rows}):
            lines += matrix_rows(f"{group} / {fmt}", [e for e in rows if e["format"] == fmt])

    lines += [""] + held_out_section(entries, before, data["safeloadai"]) + malicious_only_section(entries) + [
        "## Limits of this evaluation",
        "",
        "- The other scanners are measured on every file here, including formats they do not read; their "
        "errors, unsupported and skipped columns show that part. " + COMPARISON_NOTE,
        *skipped_note(data),
        "- Model backdoors and poisoned weights (OWASP LLM04) are not measured: a file scanner cannot see them "
        "([THREAT_MODEL.md](THREAT_MODEL.md)).",
        "- Regenerate this page after a new run: `python evaluation/make_evaluation_doc.py RESULT.json`.",
        "",
    ]
    return "\n".join(lines)


def day(created: str) -> str:
    """2026-10-22 from an ISO time or a 20261022T120000Z stamp."""
    return f"{created[:4]}-{created[4:6]}-{created[6:8]}" if created[:8].isdigit() else created[:10]


def readme_block(data: dict, source: str, before: dict | None) -> str:
    """The results section of README.md: headline numbers only, every one from the JSON."""
    entries = data["entries"]
    groups = by_group(entries)
    lines = [README_START,
             "<!-- Generated by evaluation/make_evaluation_doc.py. Do not edit by hand. -->", "",
             f"Run of {day(data['created'])}, safeloadai {data['safeloadai']}, Python {data['python']}, in a "
             "disposable cloud container with `evaluation/guard.py` on and no `--deep`. Every number here is "
             f"generated from [`{os.path.basename(source)}`]({source}) by `evaluation/make_evaluation_doc.py`. "
             "Confusion matrices with 95 % intervals, the data, the splits and the all-files comparison with other "
             "scanners: [docs/EVALUATION.md](docs/EVALUATION.md).", "",
             "**Detection.** \"Detected\" means any verdict other than CLEAN; `--malicious-only` counts MALICIOUS "
             "only.", "",
             "| set | " + " | ".join(VARIANTS.values()) + " | `--malicious-only` |", "|---|---|---|---|---|"]
    for group, rows in groups.items():
        malicious = [e for e in rows if e["label"] == "malicious"]
        if not malicious:
            continue
        cells = [frac(matrix(malicious, tool)["tp"], len(malicious)) for tool in VARIANTS]
        binary = sum(1 for e in malicious if e["results"]["safeloadai"].get("verdict") == "MALICIOUS")
        lines.append(f"| {group} | " + " | ".join(cells) + f" | {frac(binary, len(malicious))} |")
    held_all = [e for e in entries if e["group"] in HELD_OUT]
    held = [e for e in held_all if e["label"] == "benign"]
    worst = sum(1 for e in held if any((e["results"].get(t) or {}).get("verdict") == "MALICIOUS" for t in VARIANTS))
    sizes = Counter(e["group"] for e in held)
    lines += ["", "**Benign held-out files** (" + ", ".join(f"{g}: {sizes[g]}" for g in HELD_OUT if sizes[g]) +
              f"; no allowlist review looked at them). Benign files MALICIOUS in any configuration: {worst}.", "",
              BLOCKS_HEAD.format(first="set and configuration")]
    old = {(e["group"], e["file"]): e for e in (before or {}).get("entries", [])}
    for group in HELD_OUT:
        rows = [e for e in held_all if e["group"] == group]
        if not rows:
            continue
        if old:
            paired = [e for e in rows if (group, e["file"]) in old]
            prior = [old[(group, e["file"])] for e in paired]
            for tool, name in VARIANTS.items():
                lines.append(blocks_rows(f"{group}, {before['safeloadai']}, {name}", prior, tool))
                lines.append(blocks_rows(f"**{group}, {data['safeloadai']}, {name}**", paired, tool))
        else:
            lines += [blocks_rows(f"{group}, {name}", rows, tool) for tool, name in VARIANTS.items()]
    missing = Counter(item for e in held if e["results"]["safeloadai"].get("block") in ("soft", "hard")
                      for item in set(e["results"]["safeloadai"].get("missing") or []))
    if missing:
        top = sorted(missing.items(), key=lambda item: (-item[1], item[0]))[:6]
        lines += ["", "What still blocks held-out files most often (by default; files that need the item): " +
                  ", ".join(f"`{name}` ({n})" for name, n in top) + "."]
    lines += ["", "**Other scanners**: see the all-files comparison in [docs/EVALUATION.md](docs/EVALUATION.md). " +
              COMPARISON_NOTE, README_END]
    return "\n".join(lines)


def with_readme_block(readme: str, block: str) -> str:
    start, end = readme.index(README_START), readme.index(README_END) + len(README_END)
    return readme[:start] + block + readme[end:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("result", nargs="?", default=DEFAULT_RESULT, help="run_eval.py JSON")
    parser.add_argument("--out", default=OUT)
    parser.add_argument("--before", default=DEFAULT_BEFORE,
                        help="run_eval.py JSON of the release before, on the same held-out files")
    parser.add_argument("--readme", default=README, help="README with the evaluation markers")
    parser.add_argument("--check", action="store_true", help="exit 1 if a page differs from what would be written")
    args = parser.parse_args(argv)
    with open(args.result, encoding="utf-8") as fh:
        data = json.load(fh)
    before = None
    if args.before:
        with open(args.before, encoding="utf-8") as fh:
            before = json.load(fh)
    source = os.path.relpath(args.result, ROOT).replace(os.sep, "/")
    pages = {args.out: render(data, source, before)}
    if args.readme and os.path.exists(args.readme):
        with open(args.readme, encoding="utf-8") as fh:
            readme = fh.read()
        if README_START in readme:
            pages[args.readme] = with_readme_block(readme, readme_block(data, source, before))
    stale = False
    for path, text in pages.items():
        current = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
        if args.check:
            if current != text:
                print(f"{path} is stale: run python evaluation/make_evaluation_doc.py", file=sys.stderr)
                stale = True
        elif current != text:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"wrote {path}")
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main())
