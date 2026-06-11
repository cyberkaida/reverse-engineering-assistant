"""
Validate the HTTP streamable transport and tool registration of the
in-process RevaHeadlessLauncher.

The `server` fixture starts a launcher with NO active Ghidra project, so
project-dependent tools return MCP error payloads here. These tests pin
down exactly that contract:
- tools/list over streamable HTTP exposes the full tool catalog
- tool errors propagate through the transport as isError=True with
  human-readable text

Tool behavior against real programs is covered by the e2e suite
(test_cli_e2e.py, test_e2e_workflow.py).
"""

import pytest

from tests.helpers import list_mcp_tools

# Mark all tests in this file as integration tests (require server)
pytestmark = pytest.mark.integration


# Representative tools spanning several provider packages (project,
# functions, strings, decompiler, analysis, xrefs).
EXPECTED_TOOLS = {
    "list-project-files",
    "get-functions",
    "get-strings",
    "get-decompilation",
    "analyze-program",
    "find-cross-references",
}


def _content_text(response):
    """Concatenate the text of all content items in a make_mcp_request response."""
    return "\n".join(
        getattr(item, "text", "") or "" for item in (response.get("content") or [])
    )


class TestToolRegistration:
    """Verify the tool catalog exposed over the streamable HTTP transport."""

    def test_expected_tools_are_registered(self, server):
        """tools/list includes the representative tools and a full catalog"""
        tools = list_mcp_tools(server.getPort())

        assert tools is not None, "tools/list request failed"

        tool_names = {tool.name for tool in tools}
        missing = EXPECTED_TOOLS - tool_names
        assert not missing, (
            f"Expected tools not registered: {sorted(missing)}. "
            f"Registered tools: {sorted(tool_names)}"
        )

        # ReVa registers a large catalog across 19 provider packages.
        assert len(tools) > 40, f"Expected > 40 tools, got {len(tools)}"


class TestHttpTransportErrors:
    """Verify tool errors surface through the transport as readable payloads.

    The in-process server has no active project, so these are the error
    paths project-dependent tools are guaranteed to hit.
    """

    def test_list_project_files_without_project_returns_error(self, mcp_client):
        """list-project-files reports the missing project, not a transport failure"""
        response = mcp_client.call_tool("list-project-files", {"folderPath": "/"})

        assert response is not None, "Server did not respond"
        assert response["isError"] is True, (
            f"Expected error payload with no active project, got: {response}"
        )
        text = _content_text(response)
        assert "No active project" in text, (
            f"Error text should mention the missing project: {text!r}"
        )

    def test_get_strings_unknown_program_returns_error(self, mcp_client):
        """get-strings reports the unresolvable programPath in the error text"""
        response = mcp_client.call_tool("get-strings", {
            "programPath": "/NonexistentProgram",
            "maxCount": 5
        })

        assert response is not None, "Server did not respond"
        assert response["isError"] is True, (
            f"Expected error payload for unknown program, got: {response}"
        )
        text = _content_text(response)
        assert "/NonexistentProgram" in text, (
            f"Error text should mention the requested program path: {text!r}"
        )
        assert "not found" in text.lower(), (
            f"Error text should say the program was not found: {text!r}"
        )
