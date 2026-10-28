"""Guest tasks. Runs INSIDE the WASI sandbox only.

``selftest``: records one event; used to check the channel end to end.
``python``: executes a code string from the task file with empty globals. It is
the harness the test suite uses to play the role of a payload inside the sandbox;
production scans use the pickle and keras tasks.
``pickle`` / ``keras_lambda``: see ``emulate.py``.
``h5_meta``: reads the metadata of a legacy Keras HDF5 file with the shared
``hdf5_meta`` reader and sends the root attributes back in chunks. No code from
the file runs here; the reader only parses bytes.
``booster_check``: validates the model bytes of gradient-boosting Boosters with the
shared ``booster_check`` module (``--validate-boosters``) and records one result per
item. Nothing is loaded; the validator only parses bytes.
"""
import base64
import os
import time

H5_CHUNK = 45 * 1024  # raw bytes per record: base64 plus JSON stays under 64 KiB


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
    elif kind == "h5_meta":
        _h5_meta(task, record)
    elif kind == "booster_check":
        _booster_check(task, record)
    else:
        raise ValueError("unknown task kind: " + repr(kind))


def _h5_meta(task, record):
    import hdf5_meta

    with open("/in/artefacts/" + task["file"], "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        try:
            meta = hdf5_meta.read_metadata(fh, size, limits=task.get("limits"))
        except hdf5_meta.Refused as exc:
            record("h5_meta", refused=str(exc)[:2000])
            return
    values = meta.pop("values")
    sizes = {}
    for name, value in values.items():
        sizes[name] = len(value)
        for index, start in enumerate(range(0, len(value), H5_CHUNK)):
            record("h5_attr", name=name, index=index,
                   data=base64.b64encode(value[start:start + H5_CHUNK]).decode("ascii"))
    meta["sizes"] = sizes
    record("h5_meta", meta=meta)


def _booster_check(task, record):
    import booster_check

    for index, item in enumerate(task["items"]):
        with open("/in/artefacts/" + item["file"], "rb") as fh:
            payload = fh.read()
        if item["library"] == "lightgbm":
            try:
                payload = payload.decode("utf-8")
            except UnicodeDecodeError:
                record("booster", index=index, invalid="the model string is not UTF-8")
                continue
        try:
            summary = booster_check.check(item["library"], payload)
        except booster_check.Invalid as exc:
            record("booster", index=index, invalid=str(exc)[:500])
        else:
            record("booster", index=index, summary=summary)
