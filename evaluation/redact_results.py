"""Keep the comparison with other scanners aggregated in the committed results.

    python evaluation/redact_results.py evaluation/results/eval-*.json evaluation/results/eval-*.md

Until coordinated disclosure with the affected projects is complete, the public results
compare safeloadai with picklescan, Fickling and modelscan only as one "all files" table.
This script rewrites results files in place:

* JSON: each file's ``results`` keeps only the safeloadai columns; ``groups`` keeps only
  safeloadai; ``summary`` keeps every tool's totals but drops their per-format and
  per-library breakdowns; ``summary_without_poc_rule`` keeps their totals without the
  repository-name PoC rule (make_evaluation_doc.py); a ``comparison_note`` says what was
  left out.
* Markdown run reports (``eval-*.md``): the first table (all files) is kept as it is; in
  every other table, rows for another scanner and columns named after one are removed.

The full files are kept outside the repository (``private/``, git-ignored) and can be
published unchanged after disclosure. Run ``run_eval.py`` output through this before
committing it.
"""
from __future__ import annotations

import argparse
import json
import sys

OTHER_TOOLS = ("picklescan", "fickling", "modelscan")
NOTE = ("A detailed per-format comparison is withheld until coordinated disclosure with the affected projects "
        "is complete.")


def own(tool: str) -> bool:
    return tool.startswith("safeloadai")


def redact_run(run: dict) -> dict:
    from make_evaluation_doc import totals, without_rule

    # Totals without the repository-name PoC rule, while the per-file results are still here.
    plain = without_rule(run.get("entries", []))
    computed = {tool: totals(plain, tool) for tool in OTHER_TOOLS}
    run.setdefault("summary_without_poc_rule", {}).update({k: v for k, v in computed.items() if v})
    for entry in run.get("entries", []):
        entry["results"] = {k: v for k, v in entry.get("results", {}).items() if own(k)}
    if isinstance(run.get("groups"), dict):
        run["groups"] = {g: {t: v for t, v in per.items() if own(t)} for g, per in run["groups"].items()}
    for tool, stats in (run.get("summary") or {}).items():
        if not own(tool) and isinstance(stats, dict):
            for key in ("per_format", "per_library", "per_group"):
                stats.pop(key, None)
    run["comparison_note"] = NOTE
    return run


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _is_other(cell: str) -> bool:
    name = cell.lower().strip("*` ")
    return any(name == t or name.startswith(t + " ") for t in OTHER_TOOLS)


def redact_markdown(text: str, keep_first_table: bool = True) -> str:
    out, table, tables_seen, drop_cols = [], False, 0, set()
    for line in text.splitlines():
        if line.lstrip().startswith("|"):
            cells = _cells(line)
            if not table:  # header row
                table, tables_seen = True, tables_seen + 1
                drop_cols = {i for i, c in enumerate(cells) if _is_other(c)}
                if keep_first_table and tables_seen == 1:
                    drop_cols = set()
            elif any(_is_other(c) for c in cells) and not (keep_first_table and tables_seen == 1):
                continue
            if drop_cols:
                cells = [c for i, c in enumerate(cells) if i not in drop_cols]
                line = "| " + " | ".join(cells) + " |"
            out.append(line)
            continue
        if table and keep_first_table and tables_seen == 1:
            out += ["", NOTE]
        table = False
        out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("paths", nargs="+")
    parser.add_argument("--all-tables", action="store_true",
                        help="Markdown: redact the first table too (a document whose first table is not all files)")
    args = parser.parse_args(argv)
    for path in args.paths:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        if path.endswith(".json"):
            text = json.dumps(redact_run(json.loads(text)), indent=2) + "\n"
        elif path.endswith(".md"):
            if NOTE in text:
                continue  # already redacted
            text = redact_markdown(text, keep_first_table=not args.all_tables)
        else:
            print(f"skipped {path}: not .json or .md", file=sys.stderr)
            continue
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"redacted {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
