"""Command line.

    safeloadai scan <file|dir>... [--json] [--judge] [--deep] [--accept-unverified [SHA256:]ITEM]...
    safeloadai doctor [--json]

A SUSPICIOUS file whose every reason is UNVERIFIABLE can be accepted, item by item,
for that file's sha256 only: with ``--accept-unverified``, or at an interactive
prompt (only when stdin and stdout are a terminal; the default answer is No).
Anything else (CI, scripts, pipes) refuses unless the flag names every item.

Exit codes of ``scan`` (stable, for CI):
    0  every file is CLEAN, or SUSPICIOUS with an accepted override
    1  at least one file is MALICIOUS
    2  usage error, or no file to scan
    3  at least one file is SUSPICIOUS and none is MALICIOUS
    4  the WASI runtime failed its integrity check; nothing was scanned

``doctor`` exits 0 when every check passes and 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

from . import override
from .parsing.detect import EXTENSION_HINTS
from .pipeline import scan
from .report import Report, Verdict
from .sandbox.runtime import RuntimeIntegrityError

EXIT_CLEAN, EXIT_MALICIOUS, EXIT_USAGE, EXIT_SUSPICIOUS, EXIT_INTEGRITY = 0, 1, 2, 3, 4
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


_SCOPED_ITEM = re.compile(r"([0-9a-fA-F]{64}):(.+)\Z")


def _accept_item(text: str) -> tuple[str | None, str]:
    """``ITEM`` or ``SHA256:ITEM``."""
    match = _SCOPED_ITEM.match(text)
    if match:
        return match.group(1).lower(), match.group(2)
    if not text:
        raise argparse.ArgumentTypeError("expected ITEM or SHA256:ITEM")
    return None, text


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
    s.add_argument("--accept-unverified", action="append", type=_accept_item, default=[],
                   metavar="[SHA256:]ITEM",
                   help="accept one UNVERIFIABLE item for one file (repeatable); with several files, "
                        "prefix the file's sha256. Refused if the file has any MALICIOUS or RISKY reason")
    s.add_argument("--no-input", action="store_true", help="never prompt, even on a terminal")
    s.add_argument("--report", metavar="FILE", help="also write the Report JSON to FILE")
    s.add_argument("-q", "--quiet", action="store_true", help="no per-file text output")
    d = sub.add_parser("doctor", help="check the sandbox runtime and explain how to fix problems")
    d.add_argument("--json", action="store_true", help="print the checks as JSON")
    return parser


def _print_text(report: Report) -> None:
    status = report.verdict.value
    if not report.clean and report.accepted:
        status += f" (accepted: {', '.join(report.override['items'])})"
    print(f"{status:<10} {report.path}  ({report.file_format}, {report.timings_ms.get('total')} ms)")
    for finding in report.findings[:20]:
        print(f"    [{finding['category']}] {finding['text']}")
    if report.unverifiable_only and not report.accepted:
        print(f"    every reason is UNVERIFIABLE; to accept this file (sha256 {report.sha256}) name each item:")
        for item in report.unverifiable_items:
            print(f"      --accept-unverified {report.sha256}:{item}")
    refused = (report.override or {}).get("refused_because")
    if refused:
        print(f"    override refused: {refused}")


def _interactive() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _prompt(report: Report) -> bool:
    """Ask on the terminal; anything but y/yes (including EOF) is No."""
    err = sys.stderr
    print(f"\n{report.path} is SUSPICIOUS, and every reason is UNVERIFIABLE:", file=err)
    seen = set()
    for finding in report.findings:
        if finding["category"] == "UNVERIFIABLE" and finding["item"] not in seen:
            seen.add(finding["item"])
            print(f"  - {finding['item']}: {finding['explanation']}", file=err)
    print(f"Accept {', '.join(report.unverifiable_items)} for this file only (sha256 {report.sha256})? [y/N] ",
          end="", file=err, flush=True)
    try:
        answer = sys.stdin.readline()
    except (OSError, ValueError):
        return False
    return answer.strip().lower() in ("y", "yes")


def _overrides(reports: list[Report], accepts: list[tuple[str | None, str]], *, may_prompt: bool) -> None:
    by_sha: dict[str, list[str]] = {}
    for sha, item in accepts:
        by_sha.setdefault(sha or reports[0].sha256, []).append(item)
    for sha in sorted(set(by_sha) - {r.sha256 for r in reports}):
        print(f"safeloadai: --accept-unverified names sha256 {sha}, which matches no scanned file; ignored",
              file=sys.stderr)
    for report in reports:
        if report.clean:
            continue
        if report.sha256 in by_sha:
            override.apply(report, by_sha[report.sha256], how="cli-flag")
        elif may_prompt and report.unverifiable_only:
            if _prompt(report):
                override.apply(report, report.unverifiable_items, how="cli-prompt")
            else:
                override.apply(report, [], how="cli-prompt")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE if exc.code else EXIT_CLEAN
    if args.command == "doctor":
        from . import doctor

        return doctor.main(as_json=args.json)
    files, missing = _collect(args.paths)
    for path in missing:
        print(f"safeloadai: no such file or directory: {path}", file=sys.stderr)
    if missing or not files:
        if not files:
            print("safeloadai: nothing to scan", file=sys.stderr)
        return EXIT_USAGE

    if len(files) > 1 and any(sha is None for sha, _ in args.accept_unverified):
        print("safeloadai: with several files, --accept-unverified needs SHA256:ITEM (the file's sha256)",
              file=sys.stderr)
        return EXIT_USAGE

    try:
        reports = [scan(f, judge=args.judge, deep=args.deep, allow=args.allow) for f in files]
    except RuntimeIntegrityError as exc:
        print(f"safeloadai: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY
    _overrides(reports, args.accept_unverified, may_prompt=not args.no_input and not args.json and _interactive())
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
    if any(r.verdict is Verdict.SUSPICIOUS and not r.accepted for r in reports):
        return EXIT_SUSPICIOUS
    return EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
