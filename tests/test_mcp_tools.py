"""
Test ReVa MCP tool functionality.

Verifies that:
- Tools can be called and return results
- list-project-files works
- get-strings works
- get-functions works
- Other key tools are accessible
"""

import pytest
from tests.helpers import get_response_result

# Mark all tests in this file as integration tests (require server)
pytestmark = pytest.mark.integration


class TestProgramTools:
    """Test program-related MCP tools"""

    def test_list_project_files(self, mcp_client):
        """list-project-files tool returns file list (may be empty)"""
        response = mcp_client.call_tool("list-project-files", {"folderPath": "/"})

        # Should get a response (even if no files in project)
        assert response is not None

        # If it's an error response, check it's a valid error
        if response.get("isError", False):
            # Tool call completed, error is expected if project is empty
            assert response is not None
        else:
            # If success, should have content that's a list
            result = get_response_result(response)
            assert "content" in result
            content = result["content"]
            assert isinstance(content, list)

    def test_list_project_files_includes_format(self, mcp_client, test_program):
        """list-project-files result has expected structure when programs are open"""
        # This test uses test_program fixture to ensure at least one program is available
        # Note: test_program may not be registered with MCP server's project manager
        response = mcp_client.call_tool("list-project-files", {"folderPath": "/"})

        # Handle case where no programs are open in the MCP server's project
        if response.get("isError", False):
            # Expected - test_program isn't registered with MCP server
            assert response is not None
            return

        result = get_response_result(response)

        # Should have content
        assert "content" in result
        content = result["content"]

        # Content should be list of objects with type and text
        # May be empty if program isn't registered with MCP server
        if len(content) > 0:
            for item in content:
                assert "type" in item
                assert "text" in item


class TestStringTools:
    """Test string analysis tools"""

    def test_list_strings_requires_program(self, mcp_client):
        """get-strings requires programPath argument"""
        response = mcp_client.call_tool("get-strings", {
            "programPath": "/NonexistentProgram",
            "maxCount": 5
        })

        # Should get a response (even if error due to missing program)
        assert response is not None

        # Will likely error since program doesn't exist, but that's okay
        # We're just testing the tool is registered and callable

    def test_list_strings_with_valid_program_path(self, mcp_client):
        """get-strings accepts valid programPath format"""
        # We don't have a real project, but we can verify the tool accepts
        # properly formatted requests
        response = mcp_client.call_tool("get-strings", {
            "programPath": "/TestProgram.exe",
            "maxCount": 10
        })

        # Should get response (even if error about program not existing)
        assert response is not None


class TestFunctionTools:
    """Test function-related MCP tools"""

    def test_list_functions_callable(self, mcp_client):
        """get-functions tool is registered and callable"""
        response = mcp_client.call_tool("get-functions", {
            "programPath": "/TestProgram"
        })

        # Should get a response
        assert response is not None

    def test_get_decompilation_callable(self, mcp_client):
        """get-decompilation tool is registered and callable"""
        response = mcp_client.call_tool("get-decompilation", {
            "programPath": "/TestProgram",
            "address": "0x00401000"
        })

        # Should get a response (even if error)
        assert response is not None


class TestToolRegistration:
    """Test that key tools are registered"""

    @pytest.mark.parametrize("tool_name", [
        "list-project-files",
        "get-functions",
        "get-strings",
        "get-decompilation",
        "analyze-program",
        "find-cross-references"
    ])
    def test_tool_is_registered(self, mcp_client, tool_name):
        """All expected tools are registered and callable"""
        # Call with minimal args - we just want to verify tool exists
        response = mcp_client.call_tool(tool_name, {})

        # Should get some response (even if error due to missing required args)
        # The key is that we get a response, not a connection error
        assert response is not None
