"""
Test RevaHeadlessLauncher lifecycle management.

Verifies that:
- Launcher can start and stop
- Server becomes ready within timeout
- Configuration options are respected
- Multiple start/stop cycles work
"""

import pytest
from pathlib import Path


class TestLauncherLifecycle:
    """Test ReVa headless launcher lifecycle"""

    def test_launcher_starts_and_stops(self, ghidra_initialized):
        """Launcher can start and stop cleanly"""
        from reva.headless import RevaHeadlessLauncher

        launcher = RevaHeadlessLauncher()

        # Should not be running initially
        assert not launcher.isRunning()
        assert not launcher.isServerReady()

        # Start server
        launcher.start()

        # Wait for server to be ready
        ready = launcher.waitForServer(30000)
        assert ready, "Server failed to become ready within 30 seconds"

        # Verify status
        assert launcher.isRunning()
        assert launcher.isServerReady()

        # Should have valid port
        port = launcher.getPort()
        assert 1024 < port < 65535

        # Stop server
        launcher.stop()

        # Should not be running after stop
        assert not launcher.isRunning()

    def test_launcher_timeout_on_wait(self, ghidra_initialized):
        """waitForServer returns False if called before start"""
        from reva.headless import RevaHeadlessLauncher

        launcher = RevaHeadlessLauncher()

        # Should timeout immediately since server not started
        ready = launcher.waitForServer(1000)
        assert not ready

    def test_server_fixture_provides_ready_server(self, server):
        """Server fixture provides a running and ready server"""
        assert server.isRunning()
        assert server.isServerReady()

        port = server.getPort()
        assert 1024 < port < 65535


class TestLauncherConfiguration:
    """Test launcher configuration options"""

    def test_launcher_with_default_config(self, ghidra_initialized):
        """Launcher works with default configuration"""
        from reva.headless import RevaHeadlessLauncher

        launcher = RevaHeadlessLauncher()
        launcher.start()

        assert launcher.waitForServer(30000)

        # Default port should be 8080
        port = launcher.getPort()
        assert port == 8080

        launcher.stop()

    def test_launcher_with_custom_config(self, ghidra_initialized, tmp_path):
        """Launcher respects configuration file"""
        from reva.headless import RevaHeadlessLauncher

        # Create config file with custom port
        config_file = tmp_path / "test.properties"
        config_file.write_text(
            "reva.server.options.server.port=9999\n"
            "reva.server.options.server.host=127.0.0.1\n"
        )

        # Create launcher with config file
        launcher = RevaHeadlessLauncher(str(config_file))
        launcher.start()

        assert launcher.waitForServer(30000)

        # Should use configured port
        port = launcher.getPort()
        assert port == 9999

        launcher.stop()

    def test_launcher_with_invalid_config_file(self, ghidra_initialized, tmp_path):
        """Launcher handles missing config file gracefully"""
        from reva.headless import RevaHeadlessLauncher

        # Try to create launcher with non-existent config
        nonexistent = tmp_path / "does_not_exist.properties"

        # Should raise IOException (wrapped by Python)
        with pytest.raises(Exception):  # Could be IOException or IOError
            launcher = RevaHeadlessLauncher(str(nonexistent))
