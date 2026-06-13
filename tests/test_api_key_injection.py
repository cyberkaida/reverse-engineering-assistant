"""Unit tests for mcp-reva auto-API-key generation and header injection."""

import httpx
import pytest

from reva_cli.stdio_bridge import _make_httpx_factory, ReVaStdioBridge, ReconnectingBackend

pytestmark = [pytest.mark.unit]


@pytest.mark.asyncio
async def test_factory_injects_api_key_header():
    factory = _make_httpx_factory("ReVa-abc")
    client = factory(headers={"Content-Type": "application/json"})
    async with client:
        # httpx.Headers is case-insensitive
        assert client.headers["X-API-Key"] == "ReVa-abc"
        assert client.headers["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_factory_without_key_adds_no_header():
    factory = _make_httpx_factory(None)
    client = factory(headers={"Content-Type": "application/json"})
    async with client:
        assert "x-api-key" not in client.headers


def test_bridge_passes_key_to_backend():
    bridge = ReVaStdioBridge(12345, api_key="ReVa-xyz")
    assert bridge.api_key == "ReVa-xyz"


def test_reconnecting_backend_stores_key():
    backend = ReconnectingBackend("http://localhost:1/mcp/message", api_key="ReVa-xyz")
    assert backend.api_key == "ReVa-xyz"
