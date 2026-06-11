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

        # Use random port to avoid conflicts with other tests
        launcher = RevaHeadlessLauncher(None, True)

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
        assert 0 < port <= 65535

        # Stop server
        launcher.stop()

        # Should not be running after stop
        assert not launcher.isRunning()

    def test_launcher_timeout_on_wait(self, ghidra_initialized):
        """waitForServer returns False if called before start"""
        from reva.headless import RevaHeadlessLauncher

        # Random port to avoid conflicts (never actually starts)
        launcher = RevaHeadlessLauncher(None, True)

        # Should timeout immediately since server not started
        ready = launcher.waitForServer(1000)
        assert not ready

    def test_server_fixture_provides_ready_server(self, server):
        """Server fixture provides a running and ready server"""
        assert server.isRunning()
        assert server.isServerReady()

        port = server.getPort()
        assert 0 < port <= 65535


class TestLauncherConfiguration:
    """Test launcher configuration options"""

    def test_launcher_with_default_config(self, ghidra_initialized):
        """Default in-memory configuration uses port 8080.

        Asserts the configured default without starting the server: binding
        port 8080 would collide with any GUI Ghidra or other ReVa instance
        on the machine. launcher.getPort() is only valid after start(), so
        the default is read from ConfigManager (the same in-memory config a
        no-args launcher uses).
        """
        from reva.headless import RevaHeadlessLauncher
        from reva.plugin import ConfigManager

        launcher = RevaHeadlessLauncher()
        assert not launcher.isRunning()

        config = ConfigManager()
        try:
            assert config.getServerPort() == 8080
        finally:
            config.dispose()

    def test_launcher_with_custom_config(self, ghidra_initialized, tmp_path):
        """Launcher respects configuration file"""
        import socket

        from reva.headless import RevaHeadlessLauncher

        # Pick a dynamically free port so the test cannot collide with
        # other servers on the machine (or a parallel xdist worker).
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            custom_port = sock.getsockname()[1]

        # Create config file with the custom port
        config_file = tmp_path / "test.properties"
        config_file.write_text(
            f"reva.server.options.server.port={custom_port}\n"
            "reva.server.options.server.host=127.0.0.1\n"
        )

        # Create launcher with config file
        launcher = RevaHeadlessLauncher(str(config_file))
        launcher.start()

        assert launcher.waitForServer(30000)

        # Should use configured port
        port = launcher.getPort()
        assert port == custom_port

        launcher.stop()

    def test_launcher_with_missing_config_file(self, ghidra_initialized, tmp_path):
        """Launcher handles missing config file gracefully with defaults"""
        from reva.headless import RevaHeadlessLauncher
        from java.io import File

        # Create launcher with non-existent config and random port
        nonexistent = File(str(tmp_path / "does_not_exist.properties"))
        launcher = RevaHeadlessLauncher(nonexistent, True)  # useRandomPort=True

        # Should start successfully with default config
        launcher.start()
        assert launcher.waitForServer(30000)

        # Should have a valid port (random)
        port = launcher.getPort()
        assert 0 < port <= 65535

        launcher.stop()
