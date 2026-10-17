"""Guest entry point. Runs INSIDE the WASI sandbox (CPython 3.12), never on the host.

Keep this file compatible with the guest's Python version and the standard
library only. It sets up the evidence recorder, removes the per-scan nonce from
the environment before any untrusted byte is touched, runs the task described in
``/in/.guest/task.json`` and finishes with a ``done`` record. A run without a
``done`` record (payload exited, crashed or closed the channel) is treated as
incomplete by the host, which fails closed.
"""
import json
import os
import sys
import traceback

EVIDENCE_FD = 3
GUEST_DIR = "/in/.guest"


def _make_recorder(nonce):
    prefix = b"SLAI1 " + nonce.encode("ascii") + b" "
    state = {"seq": 0}
    write = os.write

    def record(kind, **fields):
        fields["kind"] = kind
        fields["seq"] = state["seq"]
        state["seq"] += 1
        try:
            payload = json.dumps(fields, default=repr, ensure_ascii=True)
        except Exception as exc:  # noqa: BLE001
            payload = json.dumps({"kind": "anomaly", "seq": fields["seq"],
                                  "what": "unserialisable evidence", "detail": repr(exc)})
        write(EVIDENCE_FD, prefix + payload.encode("ascii"))

    return record


def main():
    nonce = os.environ.pop("SAFELOADAI_NONCE", "")
    os.environ.clear()
    record = _make_recorder(nonce)
    del nonce
    sys.path.insert(0, GUEST_DIR)

    with open(GUEST_DIR + "/task.json", encoding="utf-8") as fh:
        task = json.load(fh)
    record("start", python=sys.version.split()[0], task=task.get("kind"))

    status = "ok"
    try:
        import tasks

        tasks.run(task, record)
    except BaseException as exc:  # noqa: BLE001 - SystemExit from a payload included
        status = "error"
        record("anomaly", what="guest task raised", error=type(exc).__name__,
               detail=str(exc)[:500], traceback=traceback.format_exc()[-2000:])
    record("done", status=status)


main()
