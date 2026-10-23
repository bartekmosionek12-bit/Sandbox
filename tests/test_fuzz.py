"""0.8.0: the fuzz targets (fuzz/targets.py) as tests. Every input a fuzzing run found
(fuzz/regressions/<target>/) is replayed, and each target gets a short Hypothesis run
over random and seed-derived bytes. Longer runs: fuzz/run.py and .github/workflows/fuzz.yml."""
from __future__ import annotations

import os

import pytest

from fuzz.seeds import seeds_for
from fuzz.targets import TARGETS, regression_inputs

CASES = [(name, path) for name in TARGETS for path in regression_inputs(name)]


@pytest.mark.parametrize("name, path", CASES, ids=[f"{n}-{os.path.basename(p)[:12]}" for n, p in CASES])
def test_fuzz_regression(name, path):
    with open(path, "rb") as fh:
        TARGETS[name](fh.read())


@pytest.mark.parametrize("name", list(TARGETS))
def test_seeds_pass(name):
    for seed in seeds_for(name):
        TARGETS[name](seed)


@pytest.mark.parametrize("name", list(TARGETS))
def test_random_bytes(name):
    hypothesis = pytest.importorskip("hypothesis")
    from hypothesis import strategies as st

    seeds = seeds_for(name)
    data = st.one_of(st.binary(max_size=2048), st.sampled_from(seeds).flatmap(
        lambda s: st.tuples(st.integers(0, len(s)), st.binary(max_size=32)).map(
            lambda cut: s[:cut[0]] + cut[1] + s[cut[0] + len(cut[1]):])))

    @hypothesis.settings(max_examples=int(os.environ.get("SAFELOADAI_FUZZ_EXAMPLES", "150")), deadline=None,
                         database=None, suppress_health_check=list(hypothesis.HealthCheck))
    @hypothesis.given(data)
    def run(blob):
        TARGETS[name](blob)

    run()
