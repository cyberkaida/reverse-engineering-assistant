"""
End-to-end tests for mcp-reva shutdown on SIGINT, SIGTERM and SIGHUP.

A supervisor (systemd, mcp-proxy) keeps mcp-reva's stdin open while it stops
the process, so these tests hold the stdin pipe open too. Without that, the
MCP SDK's stdin reader sees EOF and the process exits whether or not the
signal handler works.
"""

import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.cli,
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.timeout(180),
]

STARTUP_TIMEOUT = 120
EXIT_TIMEOUT = 30
SETTLE_SECONDS = 3


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP],
                         ids=lambda s: signal.Signals(s).name)
def test_signal_stops_server_with_stdin_open(tmp_path, signum):
    """mcp-reva cleans up and exits on a signal while its client is still connected"""
    # Run the module with this interpreter rather than `uv run`, so the signal
    # reaches mcp-reva itself and not a wrapper process.
    proc = subprocess.Popen(
        [sys.executable, "-m", "reva_cli"],
        cwd=tmp_path,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stderr_lines = []
    ready = threading.Event()

    def read_stderr():
        for line in proc.stderr:
            stderr_lines.append(line.rstrip())
            if "Bridge ready" in line:
                ready.set()

    reader = threading.Thread(target=read_stderr, daemon=True)
    reader.start()

    try:
        assert ready.wait(STARTUP_TIMEOUT), (
            "mcp-reva did not start:\n" + "\n".join(stderr_lines)
        )
        project_line = next(l for l in stderr_lines if l.startswith("Project location: "))
        project_dir = Path(project_line.removeprefix("Project location: ")).parent
        assert project_dir.exists()

        # Give the stdio transport time to start blocking on stdin, which is
        # where a supervisor's stop signal normally finds it.
        time.sleep(SETTLE_SECONDS)
        os.kill(proc.pid, signum)
        try:
            returncode = proc.wait(EXIT_TIMEOUT)
        except subprocess.TimeoutExpired:
            pytest.fail(
                f"mcp-reva still running {EXIT_TIMEOUT}s after "
                f"{signal.Signals(signum).name}:\n" + "\n".join(stderr_lines)
            )
        reader.join(5)

        assert returncode == 0, "\n".join(stderr_lines)
        assert any(re.search(r"Cleanup complete", l) for l in stderr_lines)
        assert not project_dir.exists(), f"temporary project left behind: {project_dir}"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdin.close()
