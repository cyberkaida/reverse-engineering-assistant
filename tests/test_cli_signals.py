"""Unit tests for mcp-reva's signal handler."""

import signal
from unittest.mock import MagicMock

import pytest

from reva_cli import __main__ as cli_main
from reva_cli.__main__ import ReVaCLI

pytestmark = [pytest.mark.unit]


class _Exited(BaseException):
    """Stands in for os._exit so the test process survives.

    A BaseException, so cleanup's `except Exception` blocks cannot swallow it
    any more than they could stop a real os._exit.
    """


@pytest.fixture
def handler(monkeypatch):
    """Install ReVaCLI's handlers, yield (cli, SIGTERM handler, exit codes), then restore."""
    saved = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    exits = []

    def fake_exit(code):
        exits.append(code)
        raise _Exited()

    monkeypatch.setattr(cli_main.os, "_exit", fake_exit)
    cli = ReVaCLI(launcher=MagicMock(), project_manager=MagicMock(), server_port=0)
    try:
        cli.setup_signal_handlers()
        yield cli, signal.getsignal(signal.SIGTERM), exits
    finally:
        for s, h in saved.items():
            signal.signal(s, h)


def test_signal_cleans_up_then_exits_process(handler):
    """The first signal stops the server and ends the process with os._exit"""
    cli, on_signal, exits = handler

    with pytest.raises(_Exited):
        on_signal(signal.SIGTERM, None)

    cli.launcher.stop.assert_called_once()
    cli.project_manager.cleanup.assert_called_once()
    assert exits == [0]


def test_signal_during_cleanup_exits_immediately(handler):
    """A second signal while cleanup is running exits without cleaning up again"""
    cli, on_signal, exits = handler

    def stop_interrupted():
        on_signal(signal.SIGINT, None)

    cli.launcher.stop.side_effect = stop_interrupted

    with pytest.raises(_Exited):
        on_signal(signal.SIGTERM, None)

    cli.launcher.stop.assert_called_once()
    assert exits == [0]
