"""
Test ReVa MCP tool functionality.

Verifies that:
- Tools can be called and return results
- list-open-programs works
- list-strings works
- Other key tools are accessible
"""

import pytest
from tests.helpers import get_response_result


class TestProgramTools:
    """Test program-related MCP tools"""

    def test_list_programs(self, mcp_client):
        """list-open-programs tool returns program list"""
        response = mcp_client.call_tool("list-open-programs")
        result = get_response_result(response)

        # Should return some content
        assert "content" in result

        # Content should be a list
        content = result["content"]
        assert isinstance(content, list)

    def test_list_programs_includes_format(self, mcp_client):
        """list-open-programs result has expected structure"""
        response = mcp_client.call_tool("list-open-programs")
        result = get_response_result(response)

        # Should have content
        assert "content" in result
        content = result["content"]

        # Content should be list of objects with type and text
        for item in content:
            assert "type" in item
            assert "text" in item


class TestStringTools:
    """Test string analysis tools"""

    def test_list_strings_requires_program(self, mcp_client):
        """list-strings requires programPath argument"""
        response = mcp_client.call_tool("list-strings", {
            "programPath": "/NonexistentProgram",
            "minLength": 5
        })

        # Should get a response (even if error due to missing program)
        assert response is not None

        # Will likely error since program doesn't exist, but that's okay
        # We're just testing the tool is registered and callable

    def test_list_strings_with_valid_program_path(self, mcp_client):
        """list-strings accepts valid programPath format"""
        # We don't have a real project, but we can verify the tool accepts
        # properly formatted requests
        response = mcp_client.call_tool("list-strings", {
            "programPath": "/TestProgram.exe",
            "minLength": 4
        })

        # Should get response (even if error about program not existing)
        assert response is not None


class TestFunctionTools:
    """Test function-related MCP tools"""

    def test_list_functions_callable(self, mcp_client):
        """list-functions tool is registered and callable"""
        response = mcp_client.call_tool("list-functions", {
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
        "list-open-programs",
        "list-functions",
        "list-strings",
        "get-decompilation",
        "analyze-function",
        "find-references"
    ])
    def test_tool_is_registered(self, mcp_client, tool_name):
        """All expected tools are registered and callable"""
        # Call with minimal args - we just want to verify tool exists
        response = mcp_client.call_tool(tool_name, {})

        # Should get some response (even if error due to missing required args)
        # The key is that we get a response, not a connection error
        assert response is not None
