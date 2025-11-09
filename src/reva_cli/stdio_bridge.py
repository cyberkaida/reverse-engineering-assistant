"""
Stdio to HTTP MCP bridge using official MCP SDK Server abstraction.

Provides a proper MCP Server that forwards all requests to ReVa's StreamableHTTP endpoint.
Uses the MCP SDK's stdio transport and Pydantic serialization - no manual JSON-RPC handling.
"""

import sys
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.client.streamable_http import streamablehttp_client
from mcp import ClientSession
from mcp.types import (
    Tool,
    Resource,
    Prompt,
    TextContent,
    ImageContent,
    EmbeddedResource,
)


class ReVaStdioBridge:
    """
    MCP Server that bridges stdio to ReVa's StreamableHTTP endpoint.

    Acts as a transparent proxy - forwards all MCP requests to the ReVa backend
    and returns responses. The MCP SDK handles all JSON-RPC serialization.
    """

    def __init__(self, port: int):
        """
        Initialize the stdio bridge.

        Args:
            port: ReVa server port to connect to
        """
        self.port = port
        self.url = f"http://localhost:{port}/mcp/message"
        self.server = Server("ReVa")
        self.backend_session: ClientSession | None = None

        # Register handlers
        self._register_handlers()

    def _register_handlers(self):
        """Register MCP protocol handlers that forward to ReVa backend."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """Forward list_tools request to ReVa backend."""
            if not self.backend_session:
                raise RuntimeError("Backend session not initialized")

            result = await self.backend_session.list_tools()
            return result.tools

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent | ImageContent | EmbeddedResource]:
            """Forward call_tool request to ReVa backend."""
            if not self.backend_session:
                raise RuntimeError("Backend session not initialized")

            result = await self.backend_session.call_tool(name, arguments)
            return result.content

        @self.server.list_resources()
        async def list_resources() -> list[Resource]:
            """Forward list_resources request to ReVa backend."""
            if not self.backend_session:
                raise RuntimeError("Backend session not initialized")

            result = await self.backend_session.list_resources()
            return result.resources

        @self.server.read_resource()
        async def read_resource(uri: str) -> str | bytes:
            """Forward read_resource request to ReVa backend."""
            if not self.backend_session:
                raise RuntimeError("Backend session not initialized")

            result = await self.backend_session.read_resource(uri)
            # Return the first content item's text or blob
            if result.contents and len(result.contents) > 0:
                content = result.contents[0]
                if hasattr(content, 'text') and content.text:
                    return content.text
                elif hasattr(content, 'blob') and content.blob:
                    return content.blob
            return ""

        @self.server.list_prompts()
        async def list_prompts() -> list[Prompt]:
            """Forward list_prompts request to ReVa backend."""
            if not self.backend_session:
                raise RuntimeError("Backend session not initialized")

            result = await self.backend_session.list_prompts()
            return result.prompts

    async def run(self):
        """
        Run the stdio bridge.

        Connects to ReVa backend via StreamableHTTP, initializes the session,
        then exposes the MCP server via stdio transport.
        """
        print(f"Connecting to ReVa backend at {self.url}...", file=sys.stderr)

        try:
            # Connect to ReVa backend
            async with streamablehttp_client(self.url, timeout=300.0) as (read_stream, write_stream, get_session_id):
                async with ClientSession(read_stream, write_stream) as session:
                    self.backend_session = session

                    # Initialize backend session
                    print("Initializing ReVa backend session...", file=sys.stderr)
                    init_result = await session.initialize()
                    print(f"Connected to {init_result.serverInfo.name} v{init_result.serverInfo.version}", file=sys.stderr)

                    # Run MCP server with stdio transport
                    print("Bridge ready - stdio transport active", file=sys.stderr)
                    async with stdio_server() as (read_stream, write_stream):
                        await self.server.run(
                            read_stream,
                            write_stream,
                            self.server.create_initialization_options()
                        )

        except Exception as e:
            print(f"Bridge error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            raise
        finally:
            self.backend_session = None
            print("Bridge stopped", file=sys.stderr)

    def stop(self):
        """Stop the bridge (handled by context managers)."""
        # Cleanup is handled by async context managers
        pass
