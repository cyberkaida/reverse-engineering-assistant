"""
End-to-end tests for VS Code MCP client compatibility (Issue #249).

Tests that the ReVa MCP server correctly handles initialize requests from
VS Code's MCP client, which uses protocol version 2025-11-25 with additional
capability fields not yet supported by the MCP Java SDK.

The specific issue is that VS Code sends:
{
  "capabilities": {
    "elicitation": {"form": {}, "url": {}},
    "tasks": {...}
  }
}

These fields cause the MCP Java SDK to fail with:
  "Unrecognized field \"form\" (class ...Elicitation)"

This is tracked upstream as:
  https://github.com/modelcontextprotocol/java-sdk/issues/724

The workaround in ReVa configures Jackson ObjectMapper with
FAIL_ON_UNKNOWN_PROPERTIES=false.
"""

import pytest
import httpx
import json

# Mark all tests in this file
pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio,
    pytest.mark.timeout(120)
]


# The exact initialize request from VS Code MCP client (from issue #249 logs)
VSCODE_INITIALIZE_REQUEST = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {
            "roots": {"listChanged": True},
            "sampling": {},
            "elicitation": {
                "form": {},
                "url": {}
            },
            "tasks": {
                "list": {},
                "cancel": {},
                "requests": {
                    "sampling": {"createMessage": {}},
                    "elicitation": {"create": {}}
                }
            }
        },
        "clientInfo": {
            "name": "Visual Studio Code",
            "version": "1.107.1"
        }
    }
}

# The exact headers from VS Code MCP client (from issue #249 logs)
VSCODE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "text/event-stream, application/json",
    "User-Agent": "Visual Studio Code/1.107.1",
    "Connection": "keep-alive",
    "Accept-Language": "*",
    "Accept-Encoding": "gzip, deflate",
}


class TestVSCodeMCPClientCompatibility:
    """Test compatibility with VS Code MCP client's initialize request."""

    async def test_accepts_vscode_initialize_request(self, server):
        """
        Server should accept VS Code's initialize request with unknown fields.

        This tests the fix for issue #249 where VS Code sends protocol 2025-11-25
        with capability fields like elicitation.form and tasks that the MCP SDK
        doesn't recognize.

        Uses the exact request body and headers from the issue #249 logs.
        """
        port = server.getPort()
        url = f"http://localhost:{port}/mcp/message"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=VSCODE_INITIALIZE_REQUEST,
                headers=VSCODE_HEADERS,
                timeout=30.0
            )

            # Should NOT return 400 Bad Request
            assert response.status_code != 400, (
                f"Server rejected VS Code initialize request with {response.status_code}: "
                f"{response.text}"
            )

            # Should return 200 OK
            assert response.status_code == 200, (
                f"Expected 200 OK, got {response.status_code}: {response.text}"
            )

            # Parse response - may be JSON-RPC response or SSE event
            content_type = response.headers.get("content-type", "")

            if "application/json" in content_type:
                result = response.json()
                # Should be a valid JSON-RPC response
                assert "jsonrpc" in result, f"Not a valid JSON-RPC response: {result}"
                assert result.get("id") == 1, f"Wrong response ID: {result}"

                # Should have a result (success) not an error
                if "error" in result:
                    pytest.fail(
                        f"Server returned JSON-RPC error: {result['error']}"
                    )

                assert "result" in result, f"Missing result in response: {result}"

                # Validate initialize result structure
                init_result = result["result"]
                assert "protocolVersion" in init_result
                assert "serverInfo" in init_result
                assert init_result["serverInfo"]["name"] == "ReVa"

            elif "text/event-stream" in content_type:
                # SSE response - parse events
                events = response.text.strip().split("\n\n")
                found_result = False

                for event in events:
                    if event.startswith("data:"):
                        data = event[5:].strip()
                        if data:
                            parsed = json.loads(data)
                            if parsed.get("id") == 1 and "result" in parsed:
                                found_result = True
                                init_result = parsed["result"]
                                assert "protocolVersion" in init_result
                                assert "serverInfo" in init_result
                                break

                assert found_result, f"No valid result in SSE response: {response.text}"

    async def test_rejects_unknown_fields_error_message(self, server):
        """
        Verify the specific error from issue #249 does NOT occur.

        Before the fix, the server would return:
        "Unrecognized field \"form\" (class ...Elicitation)"
        """
        port = server.getPort()
        url = f"http://localhost:{port}/mcp/message"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=VSCODE_INITIALIZE_REQUEST,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                timeout=30.0
            )

            response_text = response.text.lower()

            # These error patterns should NOT appear
            assert "unrecognized field" not in response_text, (
                f"Server still rejecting unknown fields: {response.text}"
            )
            assert "form" not in response_text or response.status_code == 200, (
                f"Server complaining about 'form' field: {response.text}"
            )
            assert "not marked as ignorable" not in response_text, (
                f"Jackson serialization error: {response.text}"
            )

    async def test_handles_elicitation_with_subfields(self, server):
        """
        Test that elicitation capability with form/url subfields is accepted.

        VS Code's elicitation capability includes nested objects that aren't
        in the MCP SDK schema yet.
        """
        port = server.getPort()
        url = f"http://localhost:{port}/mcp/message"

        # Minimal request focusing on the elicitation issue
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",  # Use supported version
                "capabilities": {
                    "elicitation": {
                        "form": {},
                        "url": {}
                    }
                },
                "clientInfo": {"name": "TestClient", "version": "1.0"}
            }
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=request,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream, application/json"
                },
                timeout=30.0
            )

            # Should succeed
            assert response.status_code == 200, (
                f"Failed with elicitation subfields: {response.text}"
            )

    async def test_handles_tasks_capability(self, server):
        """
        Test that tasks capability with nested requests is accepted.

        VS Code includes a tasks capability that isn't in the SDK schema.
        """
        port = server.getPort()
        url = f"http://localhost:{port}/mcp/message"

        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {
                    "tasks": {
                        "list": {},
                        "cancel": {},
                        "requests": {
                            "sampling": {"createMessage": {}},
                            "elicitation": {"create": {}}
                        }
                    }
                },
                "clientInfo": {"name": "TestClient", "version": "1.0"}
            }
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=request,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream, application/json"
                },
                timeout=30.0
            )

            # Should succeed
            assert response.status_code == 200, (
                f"Failed with tasks capability: {response.text}"
            )

    async def test_handles_future_unknown_capabilities(self, server):
        """
        Test that completely unknown top-level capabilities are handled.

        Future MCP protocol versions may add new capability categories.
        The server should gracefully ignore them.
        """
        port = server.getPort()
        url = f"http://localhost:{port}/mcp/message"

        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {
                    "roots": {"listChanged": True},
                    "sampling": {},
                    # Unknown future capabilities
                    "futureCapability": {"enabled": True},
                    "anotherNewFeature": {
                        "nested": {"deeply": {"value": 42}}
                    }
                },
                "clientInfo": {"name": "FutureClient", "version": "2.0"}
            }
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=request,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream, application/json"
                },
                timeout=30.0
            )

            # Should succeed - unknown capabilities are ignored
            assert response.status_code == 200, (
                f"Failed with unknown capabilities: {response.text}"
            )


class TestProtocolVersionNegotiation:
    """Test protocol version negotiation with various client versions."""

    async def test_accepts_2025_11_25_protocol_version(self, server):
        """
        Server should accept protocol version 2025-11-25 even if not fully supported.

        The server may negotiate down to a supported version, but shouldn't reject
        the request outright.
        """
        port = server.getPort()
        url = f"http://localhost:{port}/mcp/message"

        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "TestClient", "version": "1.0"}
            }
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=request,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream, application/json"
                },
                timeout=30.0
            )

            # Should not fail due to unsupported version
            assert response.status_code == 200, (
                f"Rejected protocol version 2025-11-25: {response.text}"
            )

    async def test_negotiates_to_supported_version(self, server):
        """
        Server should negotiate to a mutually supported protocol version.
        """
        port = server.getPort()
        url = f"http://localhost:{port}/mcp/message"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=VSCODE_INITIALIZE_REQUEST,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream, application/json"
                },
                timeout=30.0
            )

            assert response.status_code == 200, (
                f"Failed to negotiate version: {response.text}"
            )

            # Parse response to check negotiated version
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                result = response.json()
                if "result" in result:
                    negotiated_version = result["result"].get("protocolVersion")
                    # Should be one of the supported versions
                    supported_versions = [
                        "2024-11-05", "2025-03-26", "2025-06-18"
                    ]
                    assert negotiated_version in supported_versions, (
                        f"Unexpected negotiated version: {negotiated_version}"
                    )
