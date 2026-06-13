"""End-to-end test: `mcp-reva --disable-tool-group` actually omits the group's tools.

Spawns a real mcp-reva subprocess with the flag, runs a genuine MCP tools/list over
stdio, and asserts the disabled group's tools are absent — proving the full path
CLI flag -> ReVaLauncher -> JPype -> RevaHeadlessLauncher.setDisabledToolGroups ->
ConfigManager -> tool registration.
"""

import os
import asyncio

import pytest

pytestmark = [
    pytest.mark.cli,
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio(loop_scope="session"),
    pytest.mark.timeout(180),
]


async def _list_tools_with_args(workspace, extra_args, init_timeout: float = 150.0):
    """Spawn `uv run mcp-reva <extra_args>` and return the set of tool names."""
    from mcp.client.stdio import stdio_client, StdioServerParameters
    from mcp import ClientSession
    import anyio

    server_params = StdioServerParameters(
        command="uv",
        args=["run", "mcp-reva", *extra_args],
        cwd=str(workspace),
        env=os.environ.copy(),
    )

    try:
        async with stdio_client(server_params) as (read_stream, write_stream):
            session = ClientSession(read_stream, write_stream)
            await session.__aenter__()
            try:
                await asyncio.wait_for(session.initialize(), timeout=init_timeout)
                result = await session.list_tools()
                return {t.name for t in result.tools}
            finally:
                try:
                    await session.__aexit__(None, None, None)
                except RuntimeError as e:
                    if "cancel scope" not in str(e):
                        raise
                except (anyio.ClosedResourceError, anyio.BrokenResourceError):
                    pass
    except RuntimeError as e:
        # Known pytest-asyncio/anyio teardown race — benign.
        if "cancel scope" not in str(e):
            raise
        return set()


async def test_disable_scripting_group_omits_run_script(tmp_path):
    names = await _list_tools_with_args(tmp_path, ["--disable-tool-group", "scripting"])
    assert names, "tools/list returned no tools"
    assert "run-script" not in names, f"run-script must be disabled; got {sorted(names)}"
    # A core-analysis tool must still be present (only Scripting was disabled).
    assert any(n.startswith("get-") for n in names), f"core tools missing: {sorted(names)}"
