"""Integration test: toggling a tool group on the live server is reflected over MCP.

Uses the in-process `server` fixture (real RevaHeadlessLauncher + Jetty) and a real
StreamableHTTP MCP tools/list. Proves the live add/remove path and the ConfigManager
cache stay consistent across the config-thread / server-thread boundary.
"""

import pytest

from tests.helpers import list_mcp_tools

pytestmark = [pytest.mark.integration, pytest.mark.slow]


def _tool_names(port):
    tools = list_mcp_tools(port, timeout=15)
    assert tools is not None, "tools/list returned None"
    return {t.name for t in tools}


def test_scripting_group_toggle_is_visible_over_mcp(server):
    from reva.plugin import ToolGroup

    port = server.getPort()
    config = server.getConfigManager()

    # Baseline: all groups enabled by default -> run-script present.
    assert "run-script" in _tool_names(port)
    assert config.isToolGroupEnabled(ToolGroup.SCRIPTING)

    # Disable the Scripting group. InMemoryBackend notifies synchronously, so by the
    # time this call returns the tool has been removed from the live MCP registry.
    config.setToolGroupEnabled(ToolGroup.SCRIPTING, False)
    assert not config.isToolGroupEnabled(ToolGroup.SCRIPTING)
    names = _tool_names(port)
    assert "run-script" not in names, "run-script must disappear when Scripting disabled"
    # A core-analysis tool must still be present (only the one group was toggled).
    assert any(n.startswith("get-") for n in names), f"core tools missing: {sorted(names)}"

    # Re-enable -> run-script returns.
    config.setToolGroupEnabled(ToolGroup.SCRIPTING, True)
    assert config.isToolGroupEnabled(ToolGroup.SCRIPTING)
    assert "run-script" in _tool_names(port)


def test_disabling_advanced_group_keeps_core(server):
    from reva.plugin import ToolGroup

    port = server.getPort()
    config = server.getConfigManager()

    before = _tool_names(port)
    assert "run-script" in before  # sanity: Scripting still on from prior default

    config.setToolGroupEnabled(ToolGroup.ADVANCED_ANALYSIS, False)
    after = _tool_names(port)
    # Core + scripting unaffected; the set strictly shrank.
    assert "run-script" in after
    assert after < before, "disabling a group should only remove tools"

    config.setToolGroupEnabled(ToolGroup.ADVANCED_ANALYSIS, True)
    assert _tool_names(port) == before
