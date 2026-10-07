"""
Stdio to HTTP MCP bridge using the official MCP SDK Server abstraction.

Provides a proper MCP Server that forwards all requests to ReVa's StreamableHTTP endpoint.
Uses the MCP SDK's stdio transport and Pydantic serialization - no manual JSON-RPC handling.

Includes a ReconnectingBackend that automatically reconnects to the ReVa server on
connection failures, and disables HTTP keepalive to avoid stale TCP connections.

Migrated to MCP Python SDK v2:
- lowlevel Server handlers are constructor on_* params returning full result types
  (v1 decorator registration and automatic return wrapping are gone)
- streamablehttp_client -> streamable_http_client, which takes a pre-built
  httpx2.AsyncClient instead of timeout/httpx_client_factory params and yields a
  2-tuple (the get_session_id callback was removed)
- McpError -> MCPError; protocol-model fields are snake_case (server_info, is_error)
- request timeouts surface as MCPError(-32001 REQUEST_TIMEOUT) instead of raw
  httpx exceptions, so the reconnect classifier checks the JSON-RPC code
"""

import sys
from contextlib import AsyncExitStack
from typing import Any

import httpx2
from mcp import ClientSession, MCPError
from mcp.client.streamable_http import streamable_http_client
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    REQUEST_TIMEOUT,
    CallToolRequestParams,
    CallToolResult,
    ListPromptsResult,
    ListResourcesResult,
    ListToolsResult,
    PaginatedRequestParams,
    ReadResourceRequestParams,
    ReadResourceResult,
    TextContent,
)

from reva_cli import __version__


def _make_http_client(api_key: str | None = None, timeout: float = 300.0) -> httpx2.AsyncClient:
    """Build the httpx2 client handed to streamable_http_client.

    MCP v2 replaced the v1 timeout/headers/httpx_client_factory parameters with a
    single pre-built client. Keepalive is disabled to avoid stale TCP connections
    after SSE responses; the API key, when set, rides on every request as a
    client-level default header (the transport's own per-request headers — Accept,
    MCP-Protocol-Version, session id — are merged over these, not replaced).
    """
    headers = {"X-API-Key": api_key} if api_key else None
    return httpx2.AsyncClient(
        headers=headers,
        timeout=httpx2.Timeout(timeout),
        limits=httpx2.Limits(max_keepalive_connections=0),
    )


def _is_transport_error(e: Exception) -> bool:
    """Check if an exception is a transport-level error that warrants reconnection.

    MCP-level errors (like tool not found) are valid protocol responses and should
    NOT trigger reconnection. Only network/transport failures should reconnect.

    In MCP SDK v2, request timeouts and non-2xx HTTP responses surface as MCPError
    carrying a JSON-RPC code instead of raw httpx exceptions; a REQUEST_TIMEOUT
    (-32001) is still a transport-level failure worth reconnecting for.
    """
    if isinstance(e, MCPError):
        return getattr(getattr(e, "error", None), "code", None) == REQUEST_TIMEOUT
    if isinstance(e, (httpx2.HTTPError, ConnectionError, OSError, TimeoutError)):
        return True
    return False


class ReconnectingBackend:
    """
    Manages a connection to the ReVa StreamableHTTP backend with automatic reconnection.

    Uses AsyncExitStack to manage the streamable_http_client and ClientSession lifecycle.
    On backend failure, disconnects, reconnects (new connection + initialize), and retries.
    """

    def __init__(self, url: str, api_key: str | None = None):
        self.url = url
        self.api_key = api_key
        self._session: ClientSession | None = None
        self._stack: AsyncExitStack | None = None

    async def connect(self):
        """Connect to the backend and initialize the MCP session."""
        self._stack = AsyncExitStack()
        await self._stack.__aenter__()

        http_client = _make_http_client(self.api_key)
        # The transport does not own the caller-provided client; close it after the
        # transport context unwinds (aclose is idempotent if the SDK ever closes too).
        self._stack.push_async_callback(http_client.aclose)

        read_stream, write_stream = await self._stack.enter_async_context(
            streamable_http_client(self.url, http_client=http_client)
        )

        self._session = await self._stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )

        init_result = await self._session.initialize()
        print(f"Connected to {init_result.server_info.name} v{init_result.server_info.version}", file=sys.stderr)

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

        Only reconnects on transport errors (network failures, timeouts).
        MCP-level errors (tool not found, invalid params) propagate as-is.
        """
        if not self._session:
            raise RuntimeError("Backend not connected")

        try:
            return await getattr(self._session, method)(*args, **kwargs)
        except Exception as e:
            if _is_transport_error(e):
                print(f"Backend transport error ({method}): {e}, reconnecting...", file=sys.stderr)
                await self.disconnect()
                await self.connect()
                return await getattr(self._session, method)(*args, **kwargs)
            raise


class ReVaStdioBridge:
    """
    MCP Server that bridges stdio to ReVa's StreamableHTTP endpoint.

    Acts as a transparent proxy - forwards all MCP requests to the ReVa backend
    and returns responses. The MCP SDK handles all JSON-RPC serialization.

    Uses ReconnectingBackend for resilient connection management.
    """

    def __init__(self, port: int, api_key: str | None = None):
        """
        Initialize the stdio bridge.

        Args:
            port: ReVa server port to connect to
            api_key: Optional API key sent as X-API-Key on every backend request
        """
        self.port = port
        self.api_key = api_key
        self.url = f"http://localhost:{port}/mcp/message"
        self.backend: ReconnectingBackend | None = None
        # MCP SDK v2: lowlevel handlers are constructor on_* params (v1 decorator
        # registration is gone). An explicit version is required — v2 reports an
        # empty string for unversioned servers instead of the SDK version.
        self.server = Server(
            "ReVa",
            version=__version__,
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
            on_list_resources=self._list_resources,
            on_read_resource=self._read_resource,
            on_list_prompts=self._list_prompts,
        )

    async def _backend(self) -> ReconnectingBackend:
        if not self.backend:
            raise RuntimeError("Backend not initialized")
        return self.backend

    async def _list_tools(
        self, ctx: ServerRequestContext, params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        """Forward list_tools request to ReVa backend."""
        backend = await self._backend()
        result = await backend.forward("list_tools")
        return ListToolsResult(tools=result.tools)

    async def _call_tool(
        self, ctx: ServerRequestContext, params: CallToolRequestParams
    ) -> CallToolResult:
        """Forward call_tool request to ReVa backend.

        Returns the backend's CallToolResult verbatim — content + is_error +
        structured_content — so that errors raised via createErrorResult on the Java
        side propagate with their is_error=True flag intact.

        v2 no longer converts handler exceptions into is_error results (they become
        top-level JSON-RPC errors that most clients just raise, hiding the text from
        the LLM), so this handler does that wrapping itself to keep v1 behavior:
        local/backend failures stay LLM-visible and self-correctable.
        """
        try:
            backend = await self._backend()
            return await backend.forward("call_tool", params.name, params.arguments or {})
        except Exception as e:
            return CallToolResult(
                content=[TextContent(type="text", text=str(e))],
                is_error=True,
            )

    async def _list_resources(
        self, ctx: ServerRequestContext, params: PaginatedRequestParams | None
    ) -> ListResourcesResult:
        """Forward list_resources request to ReVa backend."""
        backend = await self._backend()
        result = await backend.forward("list_resources")
        return ListResourcesResult(resources=result.resources)

    async def _read_resource(
        self, ctx: ServerRequestContext, params: ReadResourceRequestParams
    ) -> ReadResourceResult:
        """Forward read_resource request to ReVa backend.

        Passes the backend's ReadResourceResult through verbatim (v1 unwrapped the
        first content item to str/bytes and let the decorator re-wrap it, losing
        mime types and extra contents; v2 removed that wrapping, and pass-through
        is both simpler and more faithful).
        """
        backend = await self._backend()
        return await backend.forward("read_resource", params.uri)

    async def _list_prompts(
        self, ctx: ServerRequestContext, params: PaginatedRequestParams | None
    ) -> ListPromptsResult:
        """Forward list_prompts request to ReVa backend."""
        backend = await self._backend()
        result = await backend.forward("list_prompts")
        return ListPromptsResult(prompts=result.prompts)

    async def run(self):
        """
        Run the stdio bridge.

        Connects to ReVa backend via ReconnectingBackend, then exposes
        the MCP server via stdio transport.
        """
        print(f"Connecting to ReVa backend at {self.url}...", file=sys.stderr)

        self.backend = ReconnectingBackend(self.url, api_key=self.api_key)
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
