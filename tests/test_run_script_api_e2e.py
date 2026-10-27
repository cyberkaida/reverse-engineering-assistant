import json

import pytest

from tests.test_run_script_e2e import _import_test_program, _parse

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio(loop_scope="session"),
    pytest.mark.timeout(240),
]

_FIND_FN_SNIPPET = (
    "def _find_fn(name):\n"
    "    fm = currentProgram.getFunctionManager()\n"
    "    for f in fm.getFunctions(True):\n"
    "        if f.getName().lstrip('_') == name:\n"
    "            return f\n"
    "    return None\n"
)


class TestRunScriptGhidraAPI:
    """Round-trip tests: a first script mutates program state via the Ghidra
    API, a second script reads the result back. Proves that (a) FlatProgramAPI
    helpers and the Ghidra object graph are reachable from PyGhidra scripts,
    (b) transactions opened by the script actually commit, and (c) the program
    state persists between two independent run-script calls in the same MCP
    session."""

    async def test_rename_function_persists_across_script_calls(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Script 1 renames `add` → `add_reva_e2e`; Script 2 looks it up by
        the new name and prints its address. Also cross-checked via get-functions."""
        program_path = await _import_test_program(mcp_stdio_client, analyze=True)
        new_name = "add_reva_e2e"

        rename_code = (
            "from ghidra.program.model.symbol import SourceType\n"
            + _FIND_FN_SNIPPET +
            "target = _find_fn('add')\n"
            "assert target is not None, 'add function not found'\n"
            f"tx = currentProgram.startTransaction('reva e2e rename')\n"
            "try:\n"
            f"    target.setName('{new_name}', SourceType.USER_DEFINED)\n"
            "finally:\n"
            "    currentProgram.endTransaction(tx, True)\n"
            "print('OLD_ENTRY=' + str(target.getEntryPoint()))\n"
        )
        rename = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": rename_code,
                "timeoutSeconds": 30,
            },
        )
        rdata = _parse(rename)
        assert rdata["success"] is True, f"rename failed: {rdata}"
        assert "OLD_ENTRY=" in rdata["stdout"]
        old_entry = rdata["stdout"].split("OLD_ENTRY=", 1)[1].split()[0]

        verify_code = (
            f"matches = currentProgram.getFunctionManager().getFunctions(True)\n"
            f"hit = next((f for f in matches if f.getName() == '{new_name}'), None)\n"
            "assert hit is not None, 'renamed function not visible'\n"
            "print('NEW_ENTRY=' + str(hit.getEntryPoint()))\n"
            "print('NEW_NAME=' + hit.getName())\n"
        )
        verify = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": verify_code,
                "timeoutSeconds": 30,
            },
        )
        vdata = _parse(verify)
        assert vdata["success"] is True, f"verify failed: {vdata}"
        assert f"NEW_NAME={new_name}" in vdata["stdout"]
        assert f"NEW_ENTRY={old_entry}" in vdata["stdout"], (
            f"rename moved the function unexpectedly: "
            f"old={old_entry!r} stdout={vdata['stdout']!r}"
        )

        # Cross-check via get-functions. After the wire-format standardisation
        # the response is a single content item with a `functions` field.
        listing = await mcp_stdio_client.call_tool(
            "get-functions",
            arguments={
                "programPath": program_path,
                "filterDefaultNames": False,
                "maxCount": 500,
            },
        )
        listing_payload = json.loads(listing.content[0].text)
        names = [f.get("name") for f in listing_payload.get("functions", [])]
        assert new_name in names, (
            f"get-functions didn't surface rename; names={names}"
        )

    async def test_set_and_read_plate_comment_round_trip(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Script 1 sets a plate comment on `multiply`; Script 2 reads it back."""
        program_path = await _import_test_program(mcp_stdio_client, analyze=True)
        sentinel = "REVA_E2E_PLATE_COMMENT_XYZZY"

        write_code = (
            _FIND_FN_SNIPPET +
            "target = _find_fn('multiply')\n"
            "assert target is not None, 'multiply function not found'\n"
            "tx = currentProgram.startTransaction('reva e2e comment')\n"
            "try:\n"
            f"    target.setComment('{sentinel}')\n"
            "finally:\n"
            "    currentProgram.endTransaction(tx, True)\n"
            "print('WROTE')\n"
        )
        w = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": write_code,
                "timeoutSeconds": 30,
            },
        )
        assert _parse(w)["success"] is True, f"write failed: {_parse(w)}"

        read_code = (
            _FIND_FN_SNIPPET +
            "target = _find_fn('multiply')\n"
            "assert target is not None\n"
            "print('PLATE=' + (target.getComment() or '<none>'))\n"
        )
        r = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": read_code,
                "timeoutSeconds": 30,
            },
        )
        rdata = _parse(r)
        assert rdata["success"] is True, f"read failed: {rdata}"
        assert f"PLATE={sentinel}" in rdata["stdout"], (
            f"comment didn't round-trip; stdout={rdata['stdout']!r}"
        )

    async def test_extract_bytes_from_executable_block(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Reads the first 8 bytes of an executable memory block and prints
        them as hex. Proves getBytes() works and Java byte[] crosses the bridge."""
        program_path = await _import_test_program(mcp_stdio_client)

        code = (
            "mem = currentProgram.getMemory()\n"
            "exec_block = next((b for b in mem.getBlocks() if b.isExecute()), None)\n"
            "assert exec_block is not None, 'no executable block found'\n"
            "raw = getBytes(exec_block.getStart(), 8)\n"
            "hexes = ' '.join('%02x' % (raw[i] & 0xff) for i in range(len(raw)))\n"
            "print('START=' + str(exec_block.getStart()))\n"
            "print('BYTES=' + hexes)\n"
        )
        result = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": code,
                "timeoutSeconds": 30,
            },
        )
        data = _parse(result)
        assert data["success"] is True, f"failure: {data}"
        assert "BYTES=" in data["stdout"]
        hex_line = next(
            ln for ln in data["stdout"].splitlines() if ln.startswith("BYTES=")
        )
        hex_bytes = hex_line.removeprefix("BYTES=").split()
        assert len(hex_bytes) == 8, f"expected 8 bytes, got {hex_bytes!r}"
        # Each token must be a 2-char hex value; non-zero bytes must exist
        # (an all-zero executable prologue would be a fixture corruption).
        for tok in hex_bytes:
            assert len(tok) == 2 and all(c in "0123456789abcdef" for c in tok)
        assert any(tok != "00" for tok in hex_bytes), (
            f"all-zero exec bytes is implausible: {hex_bytes!r}"
        )

    async def test_create_label_then_resolve_by_name(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Script 1 creates a primary label at a known address; Script 2
        resolves the label by name and prints the address back."""
        program_path = await _import_test_program(mcp_stdio_client)
        label = "reva_e2e_label_marker"

        create_code = (
            "mem = currentProgram.getMemory()\n"
            "exec_block = next((b for b in mem.getBlocks() if b.isExecute()), None)\n"
            "assert exec_block is not None\n"
            "addr = exec_block.getStart()\n"
            "tx = currentProgram.startTransaction('reva e2e label')\n"
            "try:\n"
            f"    createLabel(addr, '{label}', True)\n"
            "finally:\n"
            "    currentProgram.endTransaction(tx, True)\n"
            "print('LABEL_AT=' + str(addr))\n"
        )
        c = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": create_code,
                "timeoutSeconds": 30,
            },
        )
        cdata = _parse(c)
        assert cdata["success"] is True, f"create failed: {cdata}"
        created_addr = cdata["stdout"].split("LABEL_AT=", 1)[1].split()[0]

        lookup_code = (
            "symtab = currentProgram.getSymbolTable()\n"
            f"syms = list(symtab.getSymbols('{label}'))\n"
            "assert syms, 'symbol not found'\n"
            "print('FOUND_AT=' + str(syms[0].getAddress()))\n"
        )
        l = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": lookup_code,
                "timeoutSeconds": 30,
            },
        )
        ldata = _parse(l)
        assert ldata["success"] is True, f"lookup failed: {ldata}"
        assert f"FOUND_AT={created_addr}" in ldata["stdout"], (
            f"label resolved to wrong address; created={created_addr} "
            f"stdout={ldata['stdout']!r}"
        )
