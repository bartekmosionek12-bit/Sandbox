"""Command line: ``safeloadai scan <file|dir>... [--json] [--judge] [--deep]``.

Exit codes (stable, for CI):
    0  every file is CLEAN
    1  at least one file is MALICIOUS
    2  usage error, or no file to scan
    3  at least one file is SUSPICIOUS and none is MALICIOUS
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .parsing.detect import EXTENSION_HINTS
from .pipeline import scan
from .report import Report, Verdict

EXIT_CLEAN, EXIT_MALICIOUS, EXIT_USAGE, EXIT_SUSPICIOUS = 0, 1, 2, 3
SUPPORTED = tuple(EXTENSION_HINTS)


def _collect(paths: list[str]) -> tuple[list[str], list[str]]:
    files, missing = [], []
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, names in os.walk(path):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                files.extend(os.path.join(root, n) for n in sorted(names) if n.lower().endswith(SUPPORTED))
        elif os.path.isfile(path):
            files.append(path)
        else:
            missing.append(path)
    return files, missing


def _allow_pair(text: str) -> tuple[str, str]:
    module, sep, name = text.partition(":")
    if not sep or not module or not name:
        raise argparse.ArgumentTypeError("expected module:qualname, e.g. mypkg.models:MyModel")
    return module, name


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="safeloadai", description="Decide whether model files are safe to load.")
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="scan files or directories without loading them")
    s.add_argument("paths", nargs="+", help="files or directories")
    s.add_argument("--json", action="store_true", help="print the Report JSON (a list for several files)")
    s.add_argument("--judge", action="store_true", help="ask the LLM judge (escalate only; needs ANTHROPIC_API_KEY)")
    s.add_argument("--deep", action="store_true", help="also detonate in the deep sandbox (Docker)")
    s.add_argument("--allow", action="append", type=_allow_pair, default=[], metavar="MODULE:QUALNAME",
                   help="extra exact pickle global to allow (repeatable)")
    s.add_argument("--report", metavar="FILE", help="also write the Report JSON to FILE")
    s.add_argument("-q", "--quiet", action="store_true", help="no per-file text output")
    return parser


def _print_text(report: Report) -> None:
    print(f"{report.verdict.value:<10} {report.path}  ({report.file_format}, {report.timings_ms.get('total')} ms)")
    for reason in report.reasons[:20]:
        print(f"    {reason}")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE if exc.code else EXIT_CLEAN
    files, missing = _collect(args.paths)
    for path in missing:
        print(f"safeloadai: no such file or directory: {path}", file=sys.stderr)
    if missing or not files:
        if not files:
            print("safeloadai: nothing to scan", file=sys.stderr)
        return EXIT_USAGE

    reports = [scan(f, judge=args.judge, deep=args.deep, allow=args.allow) for f in files]
    payload = [r.to_dict() for r in reports]
    document = payload[0] if len(payload) == 1 else payload
    if args.json:
        print(json.dumps(document, indent=2, default=str))
    elif not args.quiet:
        for report in reports:
            _print_text(report)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(document, fh, indent=2, default=str)

    verdicts = {r.verdict for r in reports}
    if Verdict.MALICIOUS in verdicts:
        return EXIT_MALICIOUS
    if Verdict.SUSPICIOUS in verdicts:
        return EXIT_SUSPICIOUS
    return EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
