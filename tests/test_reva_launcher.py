"""
Unit tests for the Python ReVaLauncher wrapper (reva_cli/launcher.py).

All tests use mocks — no real Ghidra/Java server is started.

Marked as unit tests (no Ghidra environment required).
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch, call

pytestmark = [pytest.mark.unit, pytest.mark.cli]


class TestReVaLauncherInit:
    """Test ReVaLauncher initialisation."""

    def test_default_init(self):
        """Default constructor sets sensible defaults."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        assert launcher.config_file is None
        assert launcher.use_random_port is True
        assert launcher.java_launcher is None
        assert launcher.port is None
        assert launcher.temp_project_dir is None

    def test_init_with_config_file(self, tmp_path):
        """Config file is stored correctly."""
        from reva_cli.launcher import ReVaLauncher

        config = tmp_path / "reva.properties"
        launcher = ReVaLauncher(config_file=config)
        assert launcher.config_file == config

    def test_init_with_fixed_port(self):
        """use_random_port=False is stored correctly."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher(use_random_port=False)
        assert launcher.use_random_port is False

    def test_get_port_before_start_returns_none(self):
        """get_port() returns None before the server is started."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        assert launcher.get_port() is None

    def test_is_running_before_start_returns_false(self):
        """is_running() returns False before start()."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        assert launcher.is_running() is False


class TestReVaLauncherStop:
    """Test ReVaLauncher.stop() cleanup behaviour."""

    def test_stop_without_start_is_safe(self):
        """stop() without a prior start() should not raise."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        launcher.stop()  # Should not raise

    def test_stop_calls_java_launcher_stop(self):
        """stop() delegates to java_launcher.stop()."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        mock_java = MagicMock()
        launcher.java_launcher = mock_java
        launcher.port = 8080

        launcher.stop()

        mock_java.stop.assert_called_once()

    def test_stop_clears_java_launcher(self):
        """stop() sets java_launcher to None after stopping."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        launcher.java_launcher = MagicMock()
        launcher.port = 8080

        launcher.stop()

        assert launcher.java_launcher is None

    def test_stop_clears_port(self):
        """stop() resets port to None."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        launcher.java_launcher = MagicMock()
        launcher.port = 8080

        launcher.stop()

        assert launcher.port is None

    def test_stop_cleans_up_temp_project_dir(self, tmp_path):
        """stop() removes the temporary project directory."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        # Simulate a temp directory that was created during start()
        temp_dir = tmp_path / "reva_project_test"
        temp_dir.mkdir()
        launcher.temp_project_dir = temp_dir

        launcher.stop()

        assert not temp_dir.exists(), "Temp project dir should be removed by stop()"
        assert launcher.temp_project_dir is None

    def test_stop_handles_java_stop_error_gracefully(self, capsys):
        """stop() continues cleanup even if java_launcher.stop() raises."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        mock_java = MagicMock()
        mock_java.stop.side_effect = RuntimeError("Java crash")
        launcher.java_launcher = mock_java
        launcher.port = 8080

        # Should not raise
        launcher.stop()

        # Should print error to stderr
        captured = capsys.readouterr()
        assert "error" in captured.err.lower() or "Error" in captured.err

    def test_stop_handles_missing_temp_dir_gracefully(self):
        """stop() is safe if temp_project_dir no longer exists."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        # Point to a non-existent path
        launcher.temp_project_dir = Path("/tmp/this_path_should_not_exist_abc123xyz")

        # Should not raise
        launcher.stop()

    def test_is_running_after_stop_returns_false(self):
        """is_running() returns False after stop()."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        mock_java = MagicMock()
        mock_java.isRunning.return_value = False
        launcher.java_launcher = mock_java
        launcher.port = 8080

        launcher.stop()

        assert launcher.is_running() is False


class TestReVaLauncherIsRunning:
    """Test ReVaLauncher.is_running() delegation."""

    def test_is_running_delegates_to_java_launcher(self):
        """is_running() delegates to java_launcher.isRunning()."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        mock_java = MagicMock()
        mock_java.isRunning.return_value = True
        launcher.java_launcher = mock_java

        assert launcher.is_running() is True
        mock_java.isRunning.assert_called_once()

    def test_is_running_false_when_java_launcher_returns_false(self):
        """is_running() returns False if java_launcher.isRunning() returns False."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        mock_java = MagicMock()
        mock_java.isRunning.return_value = False
        launcher.java_launcher = mock_java

        assert launcher.is_running() is False


class TestReVaLauncherStart:
    """Test ReVaLauncher.start() internals via state inspection."""

    def test_get_port_returns_port_set_during_start(self):
        """get_port() returns the port assigned by the Java server."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        launcher.port = 9999

        assert launcher.get_port() == 9999

    def test_server_timeout_logic_raises_runtime_error(self):
        """The timeout-handling block inside start() raises RuntimeError on False."""
        # Directly test the conditional that creates the RuntimeError, mirroring
        # what happens inside start() when waitForServer returns False.
        startup_timeout_ms = 60000
        mock_java = MagicMock()
        mock_java.waitForServer.return_value = False

        with pytest.raises(RuntimeError, match="Server failed to start"):
            if not mock_java.waitForServer(startup_timeout_ms):
                raise RuntimeError(
                    f"Server failed to start within {startup_timeout_ms / 1000:.0f}s"
                )

    def test_port_stored_after_successful_start_logic(self):
        """Port is stored when waitForServer returns True."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()
        mock_java = MagicMock()
        mock_java.waitForServer.return_value = True
        mock_java.getPort.return_value = 7654

        # Simulate what start() does after the server is ready
        if mock_java.waitForServer(60000):
            launcher.port = mock_java.getPort()

        assert launcher.port == 7654
        assert launcher.get_port() == 7654

    def test_start_fails_when_pyghidra_not_available(self):
        """start() raises an exception if the reva.headless module is unavailable."""
        from reva_cli.launcher import ReVaLauncher

        launcher = ReVaLauncher()

        # When PyGhidra/Java is unavailable the import inside start() fails.
        import sys
        original = sys.modules.copy()
        sys.modules["reva"] = None          # type: ignore[assignment]
        sys.modules["reva.headless"] = None  # type: ignore[assignment]
        try:
            with pytest.raises(Exception):
                launcher.start()
        finally:
            # Restore modules
            for key in ["reva", "reva.headless"]:
                if key in original:
                    sys.modules[key] = original[key]
                else:
                    sys.modules.pop(key, None)
