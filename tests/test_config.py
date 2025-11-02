"""
Test ReVa configuration file loading and options.

Verifies that:
- Configuration files can be loaded
- Options are applied correctly
- Invalid configs are handled gracefully
"""

import pytest
from pathlib import Path


class TestConfigurationLoading:
    """Test configuration file loading"""

    def test_default_configuration(self, ghidra_initialized):
        """Launcher works with default in-memory configuration"""
        from reva.headless import RevaHeadlessLauncher
        from reva.plugin import ConfigManager

        # Create default config manager
        config = ConfigManager()

        # Should have default port
        port = config.getPort()
        assert port == 8080

    def test_file_configuration_loading(self, ghidra_initialized, tmp_path):
        """Configuration can be loaded from properties file"""
        from reva.plugin import ConfigManager

        # Create config file
        config_file = tmp_path / "test.properties"
        config_file.write_text(
            "reva.server.options.server.port=7777\n"
            "reva.server.options.server.host=localhost\n"
        )

        # Load config from file
        config = ConfigManager(str(config_file))

        # Should use configured port
        port = config.getPort()
        assert port == 7777

    def test_config_file_with_multiple_options(self, ghidra_initialized, tmp_path):
        """Configuration file supports multiple options"""
        from reva.plugin import ConfigManager

        config_file = tmp_path / "full.properties"
        config_file.write_text("""
# Server options
reva.server.options.server.port=8888
reva.server.options.server.host=127.0.0.1

# Debug options
reva.server.options.debug.mode=true
""")

        config = ConfigManager(str(config_file))

        # Verify port loaded correctly
        assert config.getPort() == 8888


class TestConfigurationEdgeCases:
    """Test configuration edge cases"""

    def test_missing_config_file(self, ghidra_initialized, tmp_path):
        """Missing config file raises exception"""
        from reva.plugin import ConfigManager

        nonexistent = tmp_path / "missing.properties"

        with pytest.raises(Exception):  # IOException
            config = ConfigManager(str(nonexistent))

    def test_empty_config_file(self, ghidra_initialized, tmp_path):
        """Empty config file uses defaults"""
        from reva.plugin import ConfigManager

        config_file = tmp_path / "empty.properties"
        config_file.write_text("")

        config = ConfigManager(str(config_file))

        # Should use default port
        port = config.getPort()
        assert port == 8080

    def test_config_file_with_comments(self, ghidra_initialized, tmp_path):
        """Config file handles comments correctly"""
        from reva.plugin import ConfigManager

        config_file = tmp_path / "commented.properties"
        config_file.write_text("""
# This is a comment
reva.server.options.server.port=6666
# Another comment
""")

        config = ConfigManager(str(config_file))

        # Should parse port despite comments
        assert config.getPort() == 6666
