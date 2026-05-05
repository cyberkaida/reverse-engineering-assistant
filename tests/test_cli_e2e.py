"""
End-to-end tests for mcp-reva CLI with stdio transport.

Tests the complete CLI workflow using the official MCP Python SDK's stdio_client.
These tests verify that the CLI can:
- Start successfully via stdio
- Initialize an MCP session
- List and call MCP tools
- Handle multiple requests
- Shut down cleanly

All tests use real PyGhidra and Ghidra integration.
"""

import json

import pytest

# Mark all tests in this file
# E2E tests need longer timeout due to PyGhidra initialization (10-30s) + server startup
pytestmark = [
    pytest.mark.cli,
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio,
    pytest.mark.timeout(180)  # 3 minutes for full subprocess + PyGhidra + server startup
]


class TestCLIStartup:
    """Test CLI startup and initialization via stdio."""

    async def test_cli_initializes_successfully(self, mcp_stdio_client):
        """CLI starts and initializes MCP session successfully"""
        # mcp_stdio_client fixture already initializes
        # If we got here, initialization succeeded
        assert mcp_stdio_client is not None

    async def test_server_info_is_correct(self, mcp_stdio_client):
        """Server reports correct name and version"""
        # Initialize already happened in fixture, but we can check the info
        # by calling initialize again (it's idempotent in MCP)
        result = await mcp_stdio_client.initialize()

        assert result.serverInfo.name == "ReVa"
        assert result.serverInfo.version == "1.21.0"  # MCP SDK protocol version

    async def test_server_capabilities(self, mcp_stdio_client):
        """Server reports expected capabilities"""
        result = await mcp_stdio_client.initialize()

        # ReVa supports tools, resources, and prompts
        assert result.capabilities.tools is not None
        assert result.capabilities.resources is not None
        assert result.capabilities.prompts is not None


class TestMCPToolCalls:
    """Test MCP tool calls via stdio."""

    async def test_list_tools(self, mcp_stdio_client):
        """Can list all available MCP tools"""
        result = await mcp_stdio_client.list_tools()

        # ReVa has 40+ tools
        assert len(result.tools) > 40

        # Check for some essential tools
        tool_names = [tool.name for tool in result.tools]
        assert "list-project-files" in tool_names
        # Note: Tool names may vary, just ensure we have a substantial list
        assert len([name for name in tool_names if "function" in name.lower()]) > 0

    async def test_call_list_programs_tool(self, mcp_stdio_client, test_binary, ghidra_initialized):
        """Can call list-project-files tool"""
        # The test_binary fixture creates a binary in isolated_workspace
        # The ProjectManager should have auto-imported it

        result = await mcp_stdio_client.call_tool(
            "list-project-files",
            arguments={"folderPath": "/"}
        )

        # Should get a response (even if no files in project yet)
        assert result is not None
        assert hasattr(result, 'content')

    async def test_list_resources(self, mcp_stdio_client):
        """Can list MCP resources"""
        result = await mcp_stdio_client.list_resources()

        # ReVa provides program list resource
        assert result.resources is not None

    async def test_sequential_tool_calls(self, mcp_stdio_client):
        """Can make multiple sequential tool calls"""
        # Call list_tools twice
        result1 = await mcp_stdio_client.list_tools()
        result2 = await mcp_stdio_client.list_tools()

        # Should get same results
        assert len(result1.tools) == len(result2.tools)


class TestProjectCreation:
    """Test that mcp-reva creates Ghidra project in .reva/."""

    async def test_does_not_create_reva_directory(self, mcp_stdio_client, isolated_workspace, test_binary):
        """CLI does NOT create .reva directory in stdio mode (lazy initialization prevents unnecessary creation)"""
        reva_dir = isolated_workspace / ".reva"

        # After CLI starts, .reva should NOT exist (lazy initialization)
        assert not reva_dir.exists(), ".reva directory should not exist at startup"

        # Even after using MCP tools, .reva should NOT be created
        # (MCP tools use Java-side project management, not Python ProjectManager)
        await mcp_stdio_client.call_tool(
            "import-file",
            arguments={"path": str(test_binary)}
        )

        # .reva still should NOT exist (ProjectManager.import_binary() was never called)
        assert not reva_dir.exists(), ".reva directory should not be created by MCP tools in stdio mode"

    async def test_lazy_initialization_prevents_directory_creation(self, mcp_stdio_client, isolated_workspace):
        """ProjectManager lazy initialization prevents .reva directory creation at startup"""
        reva_dir = isolated_workspace / ".reva"

        # The mcp_stdio_client fixture starts the CLI which creates a ProjectManager
        # With lazy initialization, .reva should NOT be created
        assert not reva_dir.exists(), ".reva directory should not be created by CLI startup"

        # Verify this remains true after a short delay
        import asyncio
        await asyncio.sleep(0.5)
        assert not reva_dir.exists(), ".reva directory should still not exist after CLI is running"


class TestBinaryImportRoundTrip:
    """Verify a CLI-initiated import round-trips through list-project-files.

    The 'auto-import from cwd' behavior the previous test asserted does not exist
    in stdio mode (see test_does_not_create_reva_directory, which proves
    ProjectManager.import_binary() is never called). Instead we exercise the
    real CLI path: explicit import-file then list-project-files.
    """

    async def test_explicit_import_appears_in_listing(
        self, mcp_stdio_client, isolated_workspace, ghidra_initialized
    ):
        """import-file followed by list-project-files reflects the imported program."""
        from pathlib import Path

        fixture = Path(__file__).parent / "fixtures" / "test_arm64"
        if not fixture.exists():
            pytest.skip(f"Test fixture not found: {fixture}")

        import_result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": str(fixture),
                "enableVersionControl": False,
                "analyzeAfterImport": False,
            },
        )

        assert import_result is not None
        assert not getattr(import_result, "isError", False), (
            f"Import failed: {import_result.content[0].text if import_result.content else 'no content'}"
        )

        import_data = json.loads(import_result.content[0].text)
        assert import_data.get("success") is True
        imported = import_data.get("importedPrograms", [])
        assert len(imported) == 1, f"Expected 1 imported program, got {imported}"
        program_path = imported[0]

        list_result = await mcp_stdio_client.call_tool(
            "list-project-files",
            arguments={"folderPath": "/", "recursive": True},
        )

        assert list_result is not None
        assert not getattr(list_result, "isError", False)
        assert len(list_result.content) > 0

        # Parse the multi-content response: metadata + entries
        metadata = json.loads(list_result.content[0].text)
        entries = []
        for content in list_result.content[1:]:
            try:
                entries.append(json.loads(content.text))
            except (json.JSONDecodeError, AttributeError):
                continue

        # Locate the imported program by programPath in the listing.
        # Filter out None paths before the endswith fallback -- otherwise
        # `endswith("")` is always True and the assertion is vacuous.
        listed_paths = [e.get("programPath") or e.get("path") for e in entries]
        non_null_paths = [p for p in listed_paths if p]
        assert program_path in listed_paths or any(
            program_path.endswith(p) for p in non_null_paths
        ), (
            f"Imported program {program_path!r} not found in listing. "
            f"itemCount={metadata.get('itemCount')}, entries={entries}"
        )


def _result_error_text(result) -> str:
    """Concatenate text content from a CallToolResult, or empty string."""
    if not getattr(result, "content", None):
        return ""
    parts = []
    for item in result.content:
        text = getattr(item, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


class TestErrorHandling:
    """Test error handling in CLI.

    Server must signal failure either by raising an MCP exception (e.g., McpError)
    or by returning a CallToolResult with isError=True. A silent success on a
    nonexistent tool or missing required args would be a regression.
    """

    async def test_handles_unknown_tool(self, mcp_stdio_client):
        """Unknown tool name surfaces as isError or McpError, never silent success."""
        from mcp.shared.exceptions import McpError

        try:
            result = await mcp_stdio_client.call_tool(
                "nonexistent-tool",
                arguments={}
            )
        except McpError as exc:
            # Acceptable: SDK surfaced server-side method/tool-not-found
            assert "nonexistent-tool" in str(exc) or "tool" in str(exc).lower(), (
                f"McpError did not mention the unknown tool: {exc}"
            )
            return

        assert result is not None, "Server must respond, even for unknown tools"
        assert getattr(result, "isError", False) is True, (
            f"Unknown tool must return isError=True, got result={result}"
        )
        error_text = _result_error_text(result)
        assert error_text, "Error result must include human-readable error text"

    async def test_handles_invalid_tool_arguments(self, mcp_stdio_client):
        """Calling get-functions without required programPath surfaces a clear error."""
        from mcp.shared.exceptions import McpError

        try:
            result = await mcp_stdio_client.call_tool(
                "get-functions",
                arguments={}  # missing required programPath
            )
        except McpError as exc:
            # Acceptable: SDK surfaced schema-validation rejection
            assert "programPath" in str(exc) or "required" in str(exc).lower(), (
                f"McpError must mention the missing argument: {exc}"
            )
            return

        assert result is not None
        assert getattr(result, "isError", False) is True, (
            f"Missing required programPath must return isError=True, got result={result}"
        )
        error_text = _result_error_text(result)
        assert error_text, "Validation error must include text content"
        assert "programPath" in error_text or "required" in error_text.lower(), (
            f"Validation error should mention programPath or 'required': {error_text}"
        )
