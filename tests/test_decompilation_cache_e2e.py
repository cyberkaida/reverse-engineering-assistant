"""E2E checks of the decompilation cache through mcp-reva (PyGhidra, real programs).

- The cache counters are reachable from the MCP surface: ``capture-reva-debug-info`` writes a zip whose
  ``debug-info.json`` carries ``reva.decompilationCache``.
- A ``run-script`` change invalidates the cache: the Java integration harness cannot drive run-script (no
  PyGhidra runtime), so its invalidation test lives here. Every other change source is covered by
  src/test.slow/java/reva/decompiler/DecompilationCacheInvalidationIntegrationTest.java.
"""

import json
import zipfile
from pathlib import Path

import pytest

from tests.test_run_script_e2e import _import_test_program, _parse

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio(loop_scope="session"),
    pytest.mark.timeout(240),
]

NEW_NAME = "reva_cache_invalidated"


async def _first_function(client, program_path: str) -> tuple[str, str]:
    """Name and entry address of a non-external function, via a read-only run-script."""
    result = await client.call_tool(
        "run-script",
        arguments={
            "programPath": program_path,
            "code": (
                "for f in currentProgram.getFunctionManager().getFunctions(True):\n"
                "    if not f.isExternal() and not f.isThunk():\n"
                "        print('FN=' + f.getName() + ' ' + str(f.getEntryPoint()))\n"
                "        break\n"
            ),
            "timeoutSeconds": 30,
        },
    )
    data = _parse(result)
    assert data["success"] is True, f"function lookup failed: {data}"
    name, address = data["stdout"].split("FN=", 1)[1].split()[:2]
    return name, f"0x{address}"


async def _read(client, program_path: str, address: str) -> dict:
    result = await client.call_tool(
        "get-decompilation",
        arguments={
            "programPath": program_path,
            "functionNameOrAddress": address,
            "includeIncomingReferences": False,
            "limit": 200,
        },
    )
    return _parse(result)


async def _cache_counters(client) -> dict:
    result = await client.call_tool("capture-reva-debug-info", arguments={})
    zip_path = Path(_parse(result)["debugZipPath"])
    try:
        with zipfile.ZipFile(zip_path) as zf:
            entry = next(n for n in zf.namelist() if n.endswith("/debug-info.json"))
            info = json.loads(zf.read(entry))
    finally:
        zip_path.unlink(missing_ok=True)
    if "decompilationCache" not in info["reva"]:
        pytest.fail(
            "The ReVa build loaded by mcp-reva predates the decompilation cache: capture-reva-debug-info "
            "has no reva.decompilationCache. The e2e suite runs whatever ReVa extension is installed in "
            "GHIDRA_INSTALL_DIR, not this checkout. Run it against a scratch Ghidra copy carrying this "
            "checkout's extension; see 'Running the e2e suite against this checkout' in tests/README.md. "
            f"Loaded build's reva section: {info['reva']}"
        )
    return info["reva"]["decompilationCache"]


class TestDecompilationCacheHeadless:
    async def test_decompilation_cache_headless(self, mcp_stdio_client_isolated):
        """Two reads of one function cost one decompile and one cache hit."""
        client = mcp_stdio_client_isolated
        program_path = await _import_test_program(client, analyze=True)
        _, address = await _first_function(client, program_path)

        first = await _read(client, program_path, address)
        second = await _read(client, program_path, address)
        assert first["decompilation"] == second["decompilation"]
        assert first["decompilation"], f"empty decompilation: {first}"

        counters = await _cache_counters(client)
        assert counters["hits"] >= 1, counters
        assert counters["decompiles"] == 1, counters
        assert counters["entries"] == 1, counters
        assert counters["failures"] == 0, counters

    async def test_run_script_change_gives_fresh_text(self, mcp_stdio_client_isolated):
        """A run-script rename shows in the next read, which decompiles afresh."""
        client = mcp_stdio_client_isolated
        program_path = await _import_test_program(client, analyze=True)
        old_name, address = await _first_function(client, program_path)

        before = await _read(client, program_path, address)
        assert old_name in before["decompilation"], before["decompilation"]
        assert NEW_NAME not in before["decompilation"]
        cached = await _read(client, program_path, address)
        assert cached["decompilation"] == before["decompilation"]
        decompiles_before = (await _cache_counters(client))["decompiles"]

        result = await client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": (
                    "from ghidra.program.model.symbol import SourceType\n"
                    f"f = currentProgram.getFunctionManager().getFunctionAt("
                    f"currentProgram.getAddressFactory().getAddress('{address}'))\n"
                    f"f.setName('{NEW_NAME}', SourceType.USER_DEFINED)\n"
                ),
                "timeoutSeconds": 30,
            },
        )
        assert _parse(result)["success"] is True

        after = await _read(client, program_path, address)
        assert NEW_NAME in after["decompilation"], after["decompilation"]
        assert old_name not in after["decompilation"]
        assert (await _cache_counters(client))["decompiles"] >= decompiles_before + 1
