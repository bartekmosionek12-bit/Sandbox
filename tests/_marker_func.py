"""Harmless module for tests: a function a pickle can name. It is never called."""


def write_marker(x):
    with open("/tmp/safeloadai_marker", "w") as fh:  # never runs: tests only pickle a reference to it
        fh.write("MARKER")
    return x
