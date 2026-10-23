"""Run one fuzz target for a bounded time (0.8.0).

    pip install atheris hypothesis
    python fuzz/run.py pickle --seconds 300
    python fuzz/run.py --replay            # every saved regression input, all targets

With atheris (coverage-guided, libFuzzer) when it is installed, otherwise Hypothesis
(random bytes, shrunk on failure). The host-execution guard (evaluation/guard.py) is
on for the whole run: nothing may unpickle with ``pickle``, import a framework loader,
start a process or connect out.

A crashing input is written to ``fuzz/regressions/<target>/<sha256>`` (the directory
``tests/test_fuzz.py`` replays) and the run exits 1. Commit it with the fix.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [HERE, os.path.join(ROOT, "evaluation")]

import guard  # noqa: E402
from targets import REGRESSIONS, TARGETS, regression_inputs  # noqa: E402


def save(target: str, data: bytes) -> str:
    folder = os.path.join(REGRESSIONS, target)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, hashlib.sha256(data).hexdigest())
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def run_atheris(name: str, check, seconds: int, seeds: list[bytes]) -> int:
    import atheris

    def one(data: bytes) -> None:
        try:
            check(data)
        except Exception:
            print(f"finding saved to {save(name, data)}", file=sys.stderr)
            raise

    corpus = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"safeloadai-fuzz-{name}")
    os.makedirs(corpus, exist_ok=True)
    for seed in seeds:
        with open(os.path.join(corpus, hashlib.sha256(seed).hexdigest()), "wb") as fh:
            fh.write(seed)
    argv = [sys.argv[0], corpus, f"-max_total_time={seconds}", "-rss_limit_mb=4096", "-timeout=30",
            "-max_len=65536", "-print_final_stats=1"]
    atheris.instrument_all()
    atheris.Setup(argv, one)
    atheris.Fuzz()  # exits the process: 0 when time is up, non-zero on a finding
    return 0


def run_hypothesis(name: str, check, seconds: int, seeds: list[bytes]) -> int:
    from hypothesis import HealthCheck, Phase, given, settings
    from hypothesis import strategies as st

    for seed in seeds:
        check(seed)
    deadline = time.monotonic() + seconds
    rounds = 0
    found: list[bytes] = []

    @settings(max_examples=2000, deadline=None, database=None, derandomize=False,
              phases=[Phase.generate, Phase.shrink], suppress_health_check=list(HealthCheck))
    @given(st.one_of(st.binary(max_size=4096),
                     st.sampled_from(seeds).flatmap(lambda s: st.binary(max_size=64).map(
                         lambda tail, s=s: s[:len(s) // 2] + tail + s[len(s) // 2 + len(tail):]))))
    def prop(data: bytes) -> None:
        try:
            check(data)
        except Exception:
            found.append(data)
            raise

    while time.monotonic() < deadline:
        rounds += 1
        try:
            prop()
        except Exception as exc:  # noqa: BLE001 - report and keep the smallest input
            print(f"finding saved to {save(name, found[-1])}: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
    print(f"{name}: {rounds} Hypothesis rounds, no finding", file=sys.stderr)
    return 0


def replay() -> int:
    failed = 0
    for name, check in TARGETS.items():
        for path in regression_inputs(name):
            with open(path, "rb") as fh:
                data = fh.read()
            try:
                check(data)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                print(f"{name} {os.path.basename(path)}: {type(exc).__name__}: {exc}", file=sys.stderr)
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", nargs="?", help="pickle, zipsafe, hdf5, joblib_layout or decompress")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--engine", choices=("auto", "atheris", "hypothesis"), default="auto")
    parser.add_argument("--replay", action="store_true", help="replay fuzz/regressions and exit")
    args = parser.parse_args(argv)
    guard.activate()
    if args.replay:
        return replay()
    from seeds import seeds_for

    if args.target not in TARGETS:
        parser.error(f"target must be one of {', '.join(TARGETS)}")
    check, seeds = TARGETS[args.target], seeds_for(args.target)
    engine = args.engine
    if engine == "auto":
        try:
            import atheris  # noqa: F401
            engine = "atheris"
        except ImportError:
            engine = "hypothesis"
    print(f"fuzzing {args.target} with {engine} for {args.seconds}s ({len(seeds)} seeds)", file=sys.stderr)
    runner = run_atheris if engine == "atheris" else run_hypothesis
    return runner(args.target, check, args.seconds, seeds)


if __name__ == "__main__":
    raise SystemExit(main())
