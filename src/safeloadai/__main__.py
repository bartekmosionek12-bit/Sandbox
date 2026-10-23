"""Command line.

    safeloadai scan <file|dir>... [--json] [--judge] [--deep] [--allow MODULE:QUALNAME]...
                    [--accept-unverified [SHA256:]ITEM]... [--config FILE] [--sarif FILE]
    safeloadai options [--config FILE]
    safeloadai doctor [--json]

Plain ``safeloadai scan FILE`` uses only the strictest defaults. Every non-default
option is announced with a one-line warning on stderr before the results, recorded in
the Report's ``options`` section, and shown on the verdict line ("CLEAN (with options:
...)"). A config file is read only when named with ``--config``; ``docs/OPTIONS.md``
documents every option.

A SUSPICIOUS file whose every reason is UNVERIFIABLE can be accepted, item by item,
for that file's sha256 only: with ``--accept-unverified``, or at an interactive
prompt (only when stdin and stdout are a terminal; the default answer is No).
Anything else (CI, scripts, pipes) refuses unless the flag names every item.

Every file gets its own result: a file that cannot be read, or on which safeloadai
itself fails, is reported as ERROR with a stable code (docs/ERRORS.md) and the other
files are still scanned.

Exit codes of ``scan`` (stable, for CI). With several files, the first that applies wins
(MALICIOUS > ERROR > SUSPICIOUS > UNSUPPORTED > CLEAN):
    1  at least one file is MALICIOUS
    4  ERROR: the WASI runtime failed its integrity check (E401) for at least one file
    6  ERROR: safeloadai failed on at least one file (any other error code)
    3  at least one file is SUSPICIOUS (without an accepted override)
    5  at least one file is UNSUPPORTED (in no format safeloadai reads); such a file is
       never loadable by safe_load
    0  every file is CLEAN, or SUSPICIOUS with an accepted override
    2  usage error (invalid options or config file), or no file to scan; nothing scanned

``--sarif FILE`` also writes a SARIF 2.1.0 log (one result per file that is not CLEAN,
see ``sarif.py``) for code-scanning tools; the verdicts and the exit code are the same.

``doctor`` exits 0 when every check passes and 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

from . import options as options_mod
from . import override
from .parsing.detect import EXTENSION_HINTS
from .pipeline import scan
from .report import Report, Verdict

EXIT_CLEAN, EXIT_MALICIOUS, EXIT_USAGE, EXIT_SUSPICIOUS, EXIT_INTEGRITY, EXIT_UNSUPPORTED = 0, 1, 2, 3, 4, 5
EXIT_ERROR = 6
SUPPORTED = tuple(EXTENSION_HINTS)


def _collect(paths: list[str]) -> list[str]:
    """Files to scan, in the order given. A path that is neither a directory nor a regular
    file stays in the list: its scan reports it (ERROR E101 or E104), the others go on."""
    files = []
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, names in os.walk(path):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                files.extend(os.path.join(root, n) for n in sorted(names) if n.lower().endswith(SUPPORTED))
        else:
            files.append(path)
    return files


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
    s.add_argument("--trust-inert-from", action="append", default=[], metavar="DISTRIBUTION",
                   help="judge classes of this installed distribution from its installed source (read, never "
                        "imported); a class whose rebuild runs no code of its own is accepted (repeatable)")
    s.add_argument("--no-known-good", action="store_true",
                   help="do not use the shipped list of reviewed benign files (only makes verdicts stricter)")
    s.add_argument("--no-input", action="store_true", help="never prompt, even on a terminal")
    s.add_argument("--report", metavar="FILE", help="also write the Report JSON to FILE")
    s.add_argument("--sarif", metavar="FILE",
                   help="also write a SARIF 2.1.0 log to FILE (one result per file that is not CLEAN)")
    s.add_argument("-q", "--quiet", action="store_true", help="no per-file text output")
    s.add_argument("--config", metavar="FILE",
                   help=f"read options from this {options_mod.CONFIG_NAME} (never read unless named here)")
    o = sub.add_parser("options", help="print every option, its default and the effective settings")
    o.add_argument("--config", metavar="FILE", help="also show what this config file sets")
    d = sub.add_parser("doctor", help="check the sandbox runtime and explain how to fix problems")
    d.add_argument("--json", action="store_true", help="print the checks as JSON")
    return parser


def _print_text(report: Report) -> None:
    if not report.ok:
        print(f"{'ERROR':<10} {report.path}  ({report.error['code']}, layer {report.error['layer']})")
        print(f"    [{report.error['code']}] {report.error['message']}")
        for other in report.errors[1:5]:
            print(f"    [{other['code']}] {other['message']}")
        return
    status = report.verdict.value
    if not report.clean and report.accepted:
        status += f" (accepted: {', '.join(report.override['items'])})"
    if report.options:
        status += f" (with options: {', '.join(o['name'] for o in report.options)})"
    print(f"{status:<10} {report.path}  ({report.file_format}, {report.timings_ms.get('total')} ms)")
    for finding in report.findings[:20]:
        print(f"    [{finding['category']}] {finding['text']}")
    for entry in report.cleared:
        if entry["mechanism"] != "referenced":
            print(f"    [accepted] {entry['item']}: {entry['detail']}")
    if report.unverifiable_only and not report.accepted:
        print(f"    every reason is UNVERIFIABLE; to accept this file (sha256 {report.sha256}) name each item:")
        for item in report.unverifiable_items:
            print(f"      --accept-unverified {report.sha256}:{item}")
    refused = (report.override or {}).get("refused_because")
    if refused:
        print(f"    override refused: {refused}")
    for other in report.errors:  # a tool failure next to MALICIOUS evidence
        print(f"    [{other['code']}] {other['message']} (the MALICIOUS evidence above decides)")


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


def _overrides(reports: list[Report], accepts: list[tuple[str | None, str, str]], *, may_prompt: bool) -> None:
    by_sha: dict[str, list[str]] = {}
    origin: dict[str, str] = {}
    for sha, item, source in accepts:
        key = sha or reports[0].sha256
        by_sha.setdefault(key, []).append(item)
        origin[key] = source
    for sha in sorted(set(by_sha) - {r.sha256 for r in reports}):
        print(f"safeloadai: --accept-unverified names sha256 {sha}, which matches no scanned file; ignored",
              file=sys.stderr)
    for report in reports:
        if report.sha256 in by_sha:
            source = origin[report.sha256]
            how = "config" if source.startswith(options_mod.CONFIG) else "cli-flag"
            override.apply(report, by_sha[report.sha256], how=how,
                           config_path=source[len(options_mod.CONFIG) + 1:] if how == "config" else None)
            continue
        if report.clean:
            continue
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
    if args.command == "options":
        return _options_command(args.config)
    try:
        settings = _settings(args)
    except (options_mod.OptionError, OSError, argparse.ArgumentTypeError) as exc:
        print(f"safeloadai: {exc}", file=sys.stderr)
        return EXIT_USAGE
    files = _collect(args.paths)
    if not files:
        print("safeloadai: nothing to scan", file=sys.stderr)
        return EXIT_USAGE

    if len(files) > 1 and any(sha is None for sha, _item, _source in settings["accept_unverified"]):
        print("safeloadai: with several files, --accept-unverified needs SHA256:ITEM (the file's sha256)",
              file=sys.stderr)
        return EXIT_USAGE

    for line in _announce(settings):
        print(line, file=sys.stderr)
    reports = []
    for path in files:
        report = scan(path, judge=settings["judge"], deep=settings["deep"], allow=settings["allow"],
                      trust_inert_from=settings["trust_inert_from"], known_good=settings["known_good"],
                      option_sources=settings["sources"])
        if not report.ok:
            print(f"safeloadai: {path}: {report.error['code']} {report.error['message']}", file=sys.stderr)
        reports.append(report)
    _overrides(reports, settings["accept_unverified"],
               may_prompt=not args.no_input and not args.json and _interactive())
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
    if args.sarif:
        from .sarif import to_sarif

        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(to_sarif(reports), fh, indent=2, default=str)

    return exit_code(reports)


def exit_code(reports: list[Report]) -> int:
    """MALICIOUS > ERROR (integrity 4, other 6) > SUSPICIOUS > UNSUPPORTED > CLEAN."""
    verdicts = {r.verdict for r in reports if r.ok}
    if Verdict.MALICIOUS in verdicts:
        return EXIT_MALICIOUS
    failed = [r for r in reports if not r.ok]
    if failed:
        return EXIT_INTEGRITY if any(r.error["code"].startswith("E4") for r in failed) else EXIT_ERROR
    if any(r.verdict is Verdict.SUSPICIOUS and not r.accepted for r in reports):
        return EXIT_SUSPICIOUS
    if Verdict.UNSUPPORTED in verdicts:
        return EXIT_UNSUPPORTED
    return EXIT_CLEAN


def _settings(args) -> dict:
    """Effective scan options: CLI flags, then the config file named with --config (a
    flag and the file are combined; the file never removes a flag). ``sources`` says
    where each non-default option came from."""
    settings = {"allow": list(args.allow), "judge": args.judge, "deep": args.deep,
                "trust_inert_from": list(args.trust_inert_from), "known_good": not args.no_known_good,
                "accept_unverified": [(sha, item, "CLI flag --accept-unverified")
                                      for sha, item in args.accept_unverified],
                "sources": {}, "config": None}
    flag_sources = {"allow": "CLI flag --allow", "judge": "CLI flag --judge", "deep": "CLI flag --deep",
                    "trust_inert_from": "CLI flag --trust-inert-from"}
    for name, source in flag_sources.items():
        if settings[name]:
            settings["sources"][name] = source
    if not settings["known_good"]:
        settings["sources"]["known_good"] = "CLI flag --no-known-good"
    if args.config:
        config = options_mod.load_config(args.config)
        source = f"{options_mod.CONFIG} {args.config}"
        settings["config"] = args.config
        for text in config.get("allow", []):
            settings["allow"].append(_allow_pair(text))
        for text in config.get("accept_unverified", []):
            sha, item = _accept_item(text)
            settings["accept_unverified"].append((sha, item, source))
        for name in ("judge", "deep"):
            if config.get(name):
                settings[name] = True
        settings["trust_inert_from"] += config.get("trust_inert_from", [])
        if config.get("known_good") is False:
            settings["known_good"] = False
            settings["sources"]["known_good"] = source
        for name in ("allow", "judge", "deep", "trust_inert_from"):
            if config.get(name):
                settings["sources"][name] = (settings["sources"][name] + " and " + source
                                             if name in settings["sources"] else source)
        if config.get("accept_unverified"):
            settings["sources"]["accept_unverified"] = source
    settings["allow"] = list(options_mod.validate_allow(settings["allow"]))
    settings["trust_inert_from"] = list(options_mod.validate_trust_inert_from(settings["trust_inert_from"]))
    return settings


def _announce(settings: dict) -> list[str]:
    """One warning per non-default option, before any result; a config file says which
    option it set."""
    lines = []
    if settings["config"]:
        lines.append(f"safeloadai: reading options from config file {settings['config']}")
    entries = [options_mod.record(name, settings[name], settings["sources"][name])
               for name in ("allow", "trust_inert_from", "known_good", "deep", "judge")
               if not options_mod.is_default(name, settings[name])]
    if settings["accept_unverified"]:
        sources = sorted({source for _sha, _item, source in settings["accept_unverified"]})
        entries.append(options_mod.record("accept_unverified",
                                          [f"{sha}:{item}" if sha else item
                                           for sha, item, _s in settings["accept_unverified"]],
                                          " and ".join(sources)))
    lines += [options_mod.warning(entry) for entry in entries]
    return lines


def _options_command(config: str | None) -> int:
    print(options_mod.summary_table())
    print("\nEffective settings for `safeloadai scan`:")
    for option in options_mod.OPTIONS:
        value = os.environ.get(option.env) if option.env else None
        where = f" (from environment variable {option.env})" if value else ""
        print(f"  {option.name} = {value if value else repr(option.default)}{where}")
    found = options_mod.find_config()
    if config:
        try:
            values = options_mod.load_config(config)
        except (options_mod.OptionError, OSError) as exc:
            print(f"safeloadai: {exc}", file=sys.stderr)
            return EXIT_USAGE
        print(f"\nConfig file {config} (used only with `safeloadai scan --config {config}`) sets:")
        for key, value in values.items():
            print(f"  {key} = {value!r}")
    elif found:
        print(f"\nConfig file found: {found}. It is NOT used: plain `safeloadai scan` reads no config file; "
              f"pass --config {found} to use it.")
    else:
        print(f"\nNo {options_mod.CONFIG_NAME} in the current directory (none is read unless named with --config).")
    print("\nEvery option is documented in docs/OPTIONS.md.")
    return EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
