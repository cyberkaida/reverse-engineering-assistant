"""Unit tests for mcp-reva auto-API-key generation and header injection."""

import pytest

from reva_cli.stdio_bridge import _make_http_client, ReVaStdioBridge, ReconnectingBackend

pytestmark = [pytest.mark.unit]


@pytest.mark.asyncio
async def test_client_injects_api_key_header():
    # MCP v2: the bridge hands the transport a pre-built httpx2 client; the API key
    # is a client-level default header, and the transport's own per-request headers
    # (Accept, MCP-Protocol-Version, session id) merge over it.
    client = _make_http_client("ReVa-abc")
    async with client:
        # httpx2.Headers is case-insensitive
        assert client.headers["X-API-Key"] == "ReVa-abc"


@pytest.mark.asyncio
async def test_client_without_key_adds_no_header():
    client = _make_http_client(None)
    async with client:
        assert "X-API-Key" not in client.headers


def test_bridge_passes_key_to_backend():
    bridge = ReVaStdioBridge(12345, api_key="ReVa-xyz")
    assert bridge.api_key == "ReVa-xyz"


def test_reconnecting_backend_stores_key():
    backend = ReconnectingBackend("http://localhost:1/mcp/message", api_key="ReVa-xyz")
    assert backend.api_key == "ReVa-xyz"


@pytest.mark.asyncio
async def test_backend_key_produces_injecting_client():
    backend = ReconnectingBackend("http://localhost:1/mcp/message", api_key="ReVa-xyz")
    client = _make_http_client(backend.api_key)
    async with client:
        assert client.headers["X-API-Key"] == "ReVa-xyz"
