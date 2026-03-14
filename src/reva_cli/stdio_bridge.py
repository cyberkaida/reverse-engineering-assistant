"""
Stdio to HTTP MCP bridge using official MCP SDK Server abstraction.

Provides a proper MCP Server that forwards all requests to ReVa's StreamableHTTP endpoint.
Uses the MCP SDK's stdio transport and Pydantic serialization - no manual JSON-RPC handling.

Includes a ReconnectingBackend that automatically reconnects to the ReVa server on
connection failures, and disables HTTP keepalive to avoid stale TCP connections.
"""

import sys
from contextlib import AsyncExitStack
from typing import Any

import httpx
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


def _no_keepalive_httpx_factory(headers=None, timeout=None, auth=None):
    """Create an httpx client with keepalive connections disabled.

    Prevents stale TCP connection reuse after SSE responses, which can
    cause 'Server disconnected without sending a response' errors.
    """
    return httpx.AsyncClient(
        headers=headers,
        timeout=timeout,
        auth=auth,
        limits=httpx.Limits(max_keepalive_connections=0),
    )


class ReconnectingBackend:
    """
    Manages a connection to the ReVa StreamableHTTP backend with automatic reconnection.

    Uses AsyncExitStack to manage the streamablehttp_client and ClientSession lifecycle.
    On backend failure, disconnects, reconnects (new connection + initialize), and retries.
    """

    def __init__(self, url: str):
        self.url = url
        self._session: ClientSession | None = None
        self._stack: AsyncExitStack | None = None

    async def connect(self):
        """Connect to the backend and initialize the MCP session."""
        self._stack = AsyncExitStack()
        await self._stack.__aenter__()

        read_stream, write_stream, _ = await self._stack.enter_async_context(
            streamablehttp_client(
                self.url,
                timeout=300.0,
                httpx_client_factory=_no_keepalive_httpx_factory,
            )
        )

        self._session = await self._stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )

        init_result = await self._session.initialize()
        print(f"Connected to {init_result.serverInfo.name} v{init_result.serverInfo.version}", file=sys.stderr)

    async def disconnect(self):
        """Disconnect from the backend, cleaning up all resources."""
        if self._stack:
            try:
                await self._stack.aclose()
            except Exception:
                pass
            self._stack = None
            self._session = None

    async def forward(self, method: str, *args, **kwargs):
        """Forward a method call to the backend session, reconnecting on failure.

        On the first failure, disconnects, reconnects, and retries once.
        """
        if not self._session:
            raise RuntimeError("Backend not connected")

        try:
            return await getattr(self._session, method)(*args, **kwargs)
        except Exception as e:
            print(f"Backend call failed ({method}): {e}, reconnecting...", file=sys.stderr)
            await self.disconnect()
            await self.connect()
            return await getattr(self._session, method)(*args, **kwargs)


class ReVaStdioBridge:
    """
    MCP Server that bridges stdio to ReVa's StreamableHTTP endpoint.

    Acts as a transparent proxy - forwards all MCP requests to the ReVa backend
    and returns responses. The MCP SDK handles all JSON-RPC serialization.

    Uses ReconnectingBackend for resilient connection management.
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
        self.backend: ReconnectingBackend | None = None

        # Register handlers
        self._register_handlers()

    def _register_handlers(self):
        """Register MCP protocol handlers that forward to ReVa backend."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """Forward list_tools request to ReVa backend."""
            if not self.backend:
                raise RuntimeError("Backend not initialized")

            result = await self.backend.forward("list_tools")
            return result.tools

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent | ImageContent | EmbeddedResource]:
            """Forward call_tool request to ReVa backend."""
            if not self.backend:
                raise RuntimeError("Backend not initialized")

            result = await self.backend.forward("call_tool", name, arguments)
            return result.content

        @self.server.list_resources()
        async def list_resources() -> list[Resource]:
            """Forward list_resources request to ReVa backend."""
            if not self.backend:
                raise RuntimeError("Backend not initialized")

            result = await self.backend.forward("list_resources")
            return result.resources

        @self.server.read_resource()
        async def read_resource(uri: str) -> str | bytes:
            """Forward read_resource request to ReVa backend."""
            if not self.backend:
                raise RuntimeError("Backend not initialized")

            result = await self.backend.forward("read_resource", uri)
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
            if not self.backend:
                raise RuntimeError("Backend not initialized")

            result = await self.backend.forward("list_prompts")
            return result.prompts

    async def run(self):
        """
        Run the stdio bridge.

        Connects to ReVa backend via ReconnectingBackend, then exposes
        the MCP server via stdio transport.
        """
        print(f"Connecting to ReVa backend at {self.url}...", file=sys.stderr)

        self.backend = ReconnectingBackend(self.url)
        try:
            await self.backend.connect()

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
            await self.backend.disconnect()
            self.backend = None
            print("Bridge stopped", file=sys.stderr)

    def stop(self):
        """Stop the bridge (handled by context managers)."""
        # Cleanup is handled by async context managers
        pass
