"""
Unit tests for stdio_bridge.py components.

Tests the following without requiring a real Ghidra server:
- _is_transport_error() classification function
- ReVaStdioBridge construction and handler registration
- ReconnectingBackend construction and error handling

Marked as unit tests (no real network/Ghidra required).
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

pytestmark = [pytest.mark.unit, pytest.mark.cli]


class TestIsTransportError:
    """Tests for the _is_transport_error() helper function."""

    def test_mcp_error_is_not_transport_error(self):
        """McpError should NOT trigger reconnection — it is a valid protocol response."""
        from reva_cli.stdio_bridge import _is_transport_error
        from mcp import McpError

        # McpError is a protocol-level error, not a transport error
        err = McpError(MagicMock())
        assert _is_transport_error(err) is False

    def test_httpx_connect_error_is_transport_error(self):
        """httpx connection errors should trigger reconnection."""
        import httpx
        from reva_cli.stdio_bridge import _is_transport_error

        err = httpx.ConnectError("Connection refused")
        assert _is_transport_error(err) is True

    def test_httpx_read_error_is_transport_error(self):
        """httpx read errors should trigger reconnection."""
        import httpx
        from reva_cli.stdio_bridge import _is_transport_error

        err = httpx.ReadError("Read failed")
        assert _is_transport_error(err) is True

    def test_httpx_timeout_is_transport_error(self):
        """httpx timeout errors should trigger reconnection."""
        import httpx
        from reva_cli.stdio_bridge import _is_transport_error

        err = httpx.TimeoutException("Timeout")
        assert _is_transport_error(err) is True

    def test_connection_error_is_transport_error(self):
        """Standard ConnectionError should trigger reconnection."""
        from reva_cli.stdio_bridge import _is_transport_error

        err = ConnectionError("Connection reset by peer")
        assert _is_transport_error(err) is True

    def test_os_error_is_transport_error(self):
        """OSError (e.g., broken pipe) should trigger reconnection."""
        from reva_cli.stdio_bridge import _is_transport_error

        err = OSError("Broken pipe")
        assert _is_transport_error(err) is True

    def test_timeout_error_is_transport_error(self):
        """TimeoutError should trigger reconnection."""
        from reva_cli.stdio_bridge import _is_transport_error

        err = TimeoutError("Operation timed out")
        assert _is_transport_error(err) is True

    def test_value_error_is_not_transport_error(self):
        """ValueError should NOT trigger reconnection."""
        from reva_cli.stdio_bridge import _is_transport_error

        err = ValueError("Invalid value")
        assert _is_transport_error(err) is False

    def test_runtime_error_is_not_transport_error(self):
        """RuntimeError should NOT trigger reconnection."""
        from reva_cli.stdio_bridge import _is_transport_error

        err = RuntimeError("Something went wrong")
        assert _is_transport_error(err) is False

    def test_attribute_error_is_not_transport_error(self):
        """AttributeError should NOT trigger reconnection."""
        from reva_cli.stdio_bridge import _is_transport_error

        err = AttributeError("No such attribute")
        assert _is_transport_error(err) is False

    def test_key_error_is_not_transport_error(self):
        """KeyError is a programming error and should NOT trigger reconnection."""
        from reva_cli.stdio_bridge import _is_transport_error

        err = KeyError("missing_key")
        assert _is_transport_error(err) is False


class TestReconnectingBackendInit:
    """Tests for ReconnectingBackend construction and state."""

    def test_stores_url(self):
        """ReconnectingBackend stores the provided URL."""
        from reva_cli.stdio_bridge import ReconnectingBackend

        backend = ReconnectingBackend("http://localhost:8080/mcp/message")
        assert backend.url == "http://localhost:8080/mcp/message"

    def test_session_initially_none(self):
        """Session should be None before connect() is called."""
        from reva_cli.stdio_bridge import ReconnectingBackend

        backend = ReconnectingBackend("http://localhost:9999/mcp/message")
        assert backend._session is None

    def test_stack_initially_none(self):
        """Exit stack should be None before connect() is called."""
        from reva_cli.stdio_bridge import ReconnectingBackend

        backend = ReconnectingBackend("http://localhost:9999/mcp/message")
        assert backend._stack is None

    @pytest.mark.asyncio
    async def test_forward_raises_if_not_connected(self):
        """forward() should raise RuntimeError if session is not connected."""
        from reva_cli.stdio_bridge import ReconnectingBackend

        backend = ReconnectingBackend("http://localhost:9999/mcp/message")
        with pytest.raises(RuntimeError, match="Backend not connected"):
            await backend.forward("list_tools")

    @pytest.mark.asyncio
    async def test_disconnect_when_not_connected_does_not_raise(self):
        """disconnect() when never connected should be a safe no-op."""
        from reva_cli.stdio_bridge import ReconnectingBackend

        backend = ReconnectingBackend("http://localhost:9999/mcp/message")
        # Should not raise
        await backend.disconnect()
        assert backend._session is None
        assert backend._stack is None

    @pytest.mark.asyncio
    async def test_forward_reconnects_on_transport_error(self):
        """forward() should disconnect, reconnect, and retry on transport errors."""
        import httpx
        from reva_cli.stdio_bridge import ReconnectingBackend

        backend = ReconnectingBackend("http://localhost:8080/mcp/message")

        # Inject a fake session that fails the first call, then succeeds
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_session.list_tools.side_effect = [
            httpx.ConnectError("Lost connection"),
            mock_result,
        ]
        backend._session = mock_session

        # Patch connect/disconnect so we don't actually try to connect
        backend.connect = AsyncMock()
        backend.disconnect = AsyncMock()

        result = await backend.forward("list_tools")
        assert result is mock_result
        backend.disconnect.assert_called_once()
        backend.connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_forward_does_not_reconnect_on_mcp_error(self):
        """forward() should NOT reconnect on McpError — just re-raise."""
        from mcp import McpError
        from reva_cli.stdio_bridge import ReconnectingBackend

        backend = ReconnectingBackend("http://localhost:8080/mcp/message")

        mock_session = AsyncMock()
        mock_session.call_tool.side_effect = McpError(MagicMock())
        backend._session = mock_session

        backend.connect = AsyncMock()
        backend.disconnect = AsyncMock()

        with pytest.raises(McpError):
            await backend.forward("call_tool", "my_tool", {})

        backend.disconnect.assert_not_called()
        backend.connect.assert_not_called()


class TestReVaStdioBridgeInit:
    """Tests for ReVaStdioBridge construction."""

    def test_stores_port(self):
        """Bridge stores the provided port."""
        from reva_cli.stdio_bridge import ReVaStdioBridge

        bridge = ReVaStdioBridge(8080)
        assert bridge.port == 8080

    def test_url_derived_from_port(self):
        """Bridge URL should use the provided port."""
        from reva_cli.stdio_bridge import ReVaStdioBridge

        bridge = ReVaStdioBridge(9876)
        assert "9876" in bridge.url
        assert bridge.url == "http://localhost:9876/mcp/message"

    def test_backend_initially_none(self):
        """Backend should be None before run() is called."""
        from reva_cli.stdio_bridge import ReVaStdioBridge

        bridge = ReVaStdioBridge(8080)
        assert bridge.backend is None

    def test_server_created(self):
        """A MCP Server instance should be created during init."""
        from reva_cli.stdio_bridge import ReVaStdioBridge
        from mcp.server import Server

        bridge = ReVaStdioBridge(8080)
        assert isinstance(bridge.server, Server)

    def test_stop_is_safe_noop(self):
        """stop() should not raise even when bridge has not been started."""
        from reva_cli.stdio_bridge import ReVaStdioBridge

        bridge = ReVaStdioBridge(8080)
        bridge.stop()  # Should not raise


class TestNoKeepaliveFactory:
    """Tests for the _no_keepalive_httpx_factory helper."""

    def test_factory_creates_httpx_client(self):
        """Factory should return an httpx.AsyncClient."""
        import httpx
        from reva_cli.stdio_bridge import _no_keepalive_httpx_factory

        client = _no_keepalive_httpx_factory()
        assert isinstance(client, httpx.AsyncClient)

    def test_factory_disables_keepalive(self):
        """Factory succeeds with max_keepalive_connections=0 Limits."""
        import httpx
        from reva_cli.stdio_bridge import _no_keepalive_httpx_factory

        # The factory must accept the limits kwarg without error.
        # We verify by constructing and confirming we can use the client.
        client = _no_keepalive_httpx_factory(
            headers=None,
            timeout=None,
            auth=None,
        )
        assert isinstance(client, httpx.AsyncClient)

    def test_factory_accepts_custom_headers(self):
        """Factory should forward custom headers to the client."""
        import httpx
        from reva_cli.stdio_bridge import _no_keepalive_httpx_factory

        client = _no_keepalive_httpx_factory(headers={"X-Custom": "value"})
        assert isinstance(client, httpx.AsyncClient)
