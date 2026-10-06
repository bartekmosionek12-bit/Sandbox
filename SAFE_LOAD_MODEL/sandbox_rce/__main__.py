"""Wiersz poleceń: python -m sandbox_rce scan <plik|katalog>... (albo: safeloadai scan ...).

Kody wyjścia (stabilne, do użycia w CI):
    0  wszystkie pliki przeszły bramkę (te same reguły co safe_load_model)
    1  co najmniej jeden plik zablokowany werdyktem (malicious/suspicious/unknown)
    2  błędne wywołanie albo brak plików do sprawdzenia
    3  nie udało się potwierdzić czystości (brak detonacji, limit czasu,
       nieudane wczytanie w kontenerze, błąd analizy) — i nic nie zablokowano
       werdyktem
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from sandbox_rce import api

EXIT_OK, EXIT_BLOCKED, EXIT_USAGE, EXIT_UNCONFIRMED = 0, 1, 2, 3
SUPPORTED = api.PICKLE_EXTENSIONS + api.KERAS_EXTENSIONS


def _collect(paths: list[str]) -> tuple[list[str], list[str]]:
    """Rozwija katalogi rekurencyjnie do obsługiwanych plików."""
    files, missing = [], []
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, names in os.walk(path):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for name in sorted(names):
                    if name.lower().endswith(SUPPORTED):
                        files.append(os.path.join(root, name))
        elif os.path.isfile(path):
            files.append(path)
        else:
            missing.append(path)
    return files, missing


def _color(text: str, ok: bool) -> str:
    if not sys.stderr.isatty() or os.environ.get("NO_COLOR"):
        return text
    return f"\033[{'92' if ok else '91'}m{text}\033[0m"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safeloadai",
        description="Skanuje pliki modeli (.pkl, .pickle, .keras) bez ich wczytywania.",
        epilog="Kody wyjścia: 0 przeszło, 1 zablokowane, 2 błędne wywołanie, "
               "3 nie dało się potwierdzić czystości.",
    )
    parser.add_argument("command", nargs="?", help="'scan' (można pominąć)")
    parser.add_argument("paths", nargs="*", help="pliki lub katalogi")
    parser.add_argument("--no-detonate", action="store_true",
                        help="bez detonacji w Dockerze (tylko parser i sędzia)")
    parser.add_argument("--allow-no-detonation", action="store_true",
                        help="nie traktuj braku pełnej detonacji jako porażki "
                             "(odpowiednik require_detonation=False)")
    parser.add_argument("--json", action="store_true",
                        help="pełne raporty JSON na stdout")
    parser.add_argument("--report", metavar="PLIK",
                        help="zapisz pełne raporty JSON do pliku")
    parser.add_argument("--cache-dir", metavar="KATALOG",
                        help="cache wyników po skrócie pliku (albo SAFELOADAI_CACHE_DIR)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="bez komunikatów o postępie")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    paths = list(args.paths)
    # Zgodność wstecz: "python -m sandbox_rce plik.pkl" bez słowa scan.
    if args.command and args.command != "scan":
        paths.insert(0, args.command)
    if not paths:
        _build_parser().print_usage(sys.stderr)
        print("Podaj co najmniej jeden plik albo katalog.", file=sys.stderr)
        return EXIT_USAGE

    files, missing = _collect(paths)
    for path in missing:
        print(f"[!] Nie ma takiego pliku ani katalogu: {path}", file=sys.stderr)
    if missing:
        return EXIT_USAGE
    if not files:
        print("[!] Brak plików .pkl, .pickle ani .keras do sprawdzenia.", file=sys.stderr)
        return EXIT_USAGE

    reports, worst = [], EXIT_OK
    for path in files:
        progress = None if args.quiet else (lambda m, p=path: print(f"[*] {os.path.basename(p)}: {m}", file=sys.stderr))
        try:
            report = api.scan_model(
                path,
                detonate=not args.no_detonate,
                require_detonation=not args.allow_no_detonation,
                cache_dir=args.cache_dir,
                progress=progress,
            )
        except Exception as exc:  # noqa: BLE001 — jeden zły plik nie przerywa reszty
            report = {
                "file_name": os.path.basename(path),
                "final_verdict": "unknown",
                "gate": {"allowed": False, "code": "error",
                         "reason": f"Błąd analizy: {type(exc).__name__}: {exc}"},
            }
        report["path"] = path
        reports.append(report)

        gate = report["gate"]
        if gate["allowed"]:
            status = _color("PRZESZEDŁ", True)
        elif gate["code"] == api.BLOCKED_VERDICT:
            status = _color("ZABLOKOWANY", False)
            worst = EXIT_BLOCKED
        else:
            status = _color("NIEPOTWIERDZONY", False)
            if worst == EXIT_OK:
                worst = EXIT_UNCONFIRMED
        cached = " [cache]" if (report.get("cache") or {}).get("hit") else ""
        print(
            f"{status}  {path}  werdykt={report.get('final_verdict')}{cached}\n"
            f"    {gate['reason']}",
            file=sys.stderr,
        )

    payload = reports[0] if len(reports) == 1 else reports
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
    return worst


if __name__ == "__main__":
    sys.exit(main())
