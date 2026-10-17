"""The host-execution guard from conftest.py is active in every test (audit S13)."""
import os
import pickle
import socket
import subprocess

import pytest
from conftest import HostExecutionError


@pytest.mark.parametrize(
    "call",
    [
        lambda: os.system("echo MARKER"),
        lambda: subprocess.run(["echo", "MARKER"], check=False),
        lambda: pickle.loads(b"\x80\x02N."),
        lambda: socket.socket().connect(("192.0.2.1", 9)),
    ],
    ids=["os.system", "subprocess", "pickle.loads", "network"],
)
def test_guard_refuses_host_execution(call):
    with pytest.raises(HostExecutionError):
        call()
