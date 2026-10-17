"""Guest tasks. Runs INSIDE the WASI sandbox only.

``selftest``: records one event; used to check the channel end to end.
``python``: executes a code string from the task file with empty globals. It is
the harness the test suite uses to play the role of a payload inside the sandbox;
production scans use the pickle and keras tasks.
``pickle`` / ``keras_lambda``: see ``emulate.py``.
"""
import time


def _no_sleep(record):
    def sleep(seconds=0):
        # Blocking calls are not interrupted by fuel or epochs, and a payload that
        # waits is itself a signal (dormant / time-gated). Record and return.
        record("anomaly", what="time.sleep called", seconds=repr(seconds)[:50])

    return sleep


def run(task, record):
    time.sleep = _no_sleep(record)
    kind = task.get("kind")
    if kind == "selftest":
        record("event", category="selftest", detail="channel works")
    elif kind == "python":
        exec(compile(task["code"], "<payload>", "exec"), {"__name__": "payload"})  # noqa: S102
    elif kind == "pickle":
        import emulate

        emulate.run_pickle(task, record)
    elif kind == "keras_lambda":
        import emulate

        emulate.run_keras_lambda(task, record)
    else:
        raise ValueError("unknown task kind: " + repr(kind))
