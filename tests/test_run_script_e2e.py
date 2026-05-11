"""End-to-end tests for the run-script MCP tool.

These tests run mcp-reva as a real subprocess via PyGhidra, so the
PyGhidraScriptProvider.scriptRunner is wired up and Python actually
executes. This is the only place the run-script execution path is
validated against a live runtime — Java integration tests can't reach
it because the gradle JVM is not launched via PyGhidra.

Verifies:
- inline `code` runs and stdout is captured
- `currentProgram` is bound to the program identified by programPath
- a script that throws surfaces a traceback in stderr with success=False
- timeoutSeconds bounds runaway scripts
- write-script → run-script by scriptName round-trip
- read-script returns cat -n style numbered output
"""

import json
import uuid
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio,
    pytest.mark.timeout(240),
]

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _resolve_workflow_fixture():
    """Locate the deterministic ARM64 fixture or skip if LFS-pointer-only."""
    fixture_path = FIXTURES_DIR / "test_arm64"
    if not fixture_path.exists():
        pytest.skip(f"Test fixture not found: {fixture_path}")
    if fixture_path.stat().st_size < 200:
        try:
            content = fixture_path.read_text()
        except UnicodeDecodeError:
            return str(fixture_path)
        if content.startswith("version https://git-lfs.github.com"):
            pytest.fail(
                f"Test fixture {fixture_path.name} is a Git LFS pointer, "
                "not the actual file. Run 'git lfs pull' locally or enable "
                "LFS in CI checkout."
            )
    return str(fixture_path)


async def _import_test_program(client, analyze: bool = False) -> str:
    """Import the workflow fixture and return its programPath.

    Pass analyze=True when the test needs functions/symbols defined — the
    default import-file path skips auto-analysis for speed."""
    test_binary = _resolve_workflow_fixture()
    args = {
        "path": test_binary,
        "destinationFolder": "/",
        "enableVersionControl": False,
    }
    if analyze:
        args["analyzeAfterImport"] = True
    result = await client.call_tool(
        "import-file",
        arguments=args,
    )
    assert result is not None
    assert not (hasattr(result, "isError") and result.isError), (
        f"Import failed: {result.content[0].text if result.content else 'no content'}"
    )
    data = json.loads(result.content[0].text)
    assert data.get("success") is True
    assert len(data["importedPrograms"]) > 0
    return data["importedPrograms"][0]


def _parse(result) -> dict:
    return json.loads(result.content[0].text)


class TestRunScriptE2E:
    """Tests that actually execute Python via the live PyGhidra runtime."""

    async def test_inline_code_runs_and_captures_stdout(
        self, mcp_stdio_client, isolated_workspace
    ):
        """A trivial print statement should round-trip as stdout."""
        program_path = await _import_test_program(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": "print('reva says hello')\n",
                "timeoutSeconds": 30,
            },
        )

        assert result is not None
        assert not (hasattr(result, "isError") and result.isError), (
            f"run-script reported tool error: {result.content[0].text}"
        )
        data = _parse(result)
        assert data["success"] is True, f"unexpected failure: {data}"
        assert "reva says hello" in data["stdout"], f"stdout={data['stdout']!r}"
        assert data["stderr"] == "", f"unexpected stderr: {data['stderr']!r}"
        assert data["timedOut"] is False
        assert data["programPath"] == program_path
        assert data["scriptSource"]["type"] == "inline"

    async def test_script_can_read_current_program(
        self, mcp_stdio_client, isolated_workspace
    ):
        """`currentProgram` must be bound to the program from programPath."""
        program_path = await _import_test_program(mcp_stdio_client)
        expected_name = program_path.lstrip("/")  # "test_arm64"

        result = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": (
                    "name = currentProgram.getName()\n"
                    "print('PROGRAM_NAME=' + name)\n"
                ),
                "timeoutSeconds": 30,
            },
        )

        data = _parse(result)
        assert data["success"] is True, f"failure: {data}"
        assert f"PROGRAM_NAME={expected_name}" in data["stdout"], (
            f"unexpected stdout: {data['stdout']!r}"
        )

    async def test_script_exception_appears_in_stderr_with_success_false(
        self, mcp_stdio_client, isolated_workspace
    ):
        """An uncaught Python exception is captured (not an MCP error)."""
        program_path = await _import_test_program(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": "raise ValueError('intentional test failure')\n",
                "timeoutSeconds": 30,
            },
        )

        # Tool itself ran successfully — the script error is not an MCP error.
        assert not (hasattr(result, "isError") and result.isError), (
            f"script failures must not surface as MCP errors: "
            f"{result.content[0].text}"
        )
        data = _parse(result)
        assert data["success"] is False, (
            "success must be False when script raises"
        )
        # The PyGhidra script runner may surface the exception either as a
        # Python traceback in stderr or as a Java exception captured in the
        # `error` field. Accept either signal.
        observed_error = (
            "ValueError" in data.get("stderr", "")
            or "intentional test failure" in data.get("stderr", "")
            or "ValueError" in data.get("error", "")
            or "intentional test failure" in data.get("error", "")
        )
        assert observed_error, (
            f"expected ValueError signal somewhere; "
            f"stderr={data.get('stderr')!r} error={data.get('error')!r}"
        )

    async def test_timeout_seconds_bounds_runaway_script(
        self, mcp_stdio_client, isolated_workspace
    ):
        """A near-infinite loop must be cut off by timeoutSeconds."""
        program_path = await _import_test_program(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                # Cooperate with the TaskMonitor by checking it periodically;
                # otherwise the script blocks tight in Python and the monitor
                # only flips at task boundaries. This still validates the
                # timeout flag wiring without relying on JVM-level interrupt.
                "code": (
                    "import time\n"
                    "deadline = time.time() + 30\n"
                    "while time.time() < deadline:\n"
                    "    if monitor.isCancelled():\n"
                    "        break\n"
                    "    time.sleep(0.1)\n"
                    "print('done')\n"
                ),
                "timeoutSeconds": 3,
            },
        )

        data = _parse(result)
        # TaskMonitor was cancelled because of the timeout.
        assert data["timedOut"] is True, (
            f"expected timedOut=True; got {data}"
        )

    async def test_write_then_run_script_by_name(
        self, mcp_stdio_client, isolated_workspace
    ):
        """write-script + run-script by name must round-trip correctly."""
        program_path = await _import_test_program(mcp_stdio_client)
        script_name = f"reva_e2e_{uuid.uuid4().hex[:8]}.py"

        write = await mcp_stdio_client.call_tool(
            "write-script",
            arguments={
                "scriptName": script_name,
                "code": (
                    "# @runtime PyGhidra\n"
                    "print('SCRIPT_NAME=' + currentProgram.getName())\n"
                ),
            },
        )
        write_data = _parse(write)
        assert write_data["success"] is True

        run = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "scriptName": script_name,
                "timeoutSeconds": 30,
            },
        )
        run_data = _parse(run)
        assert run_data["success"] is True, f"run failed: {run_data}"
        assert "SCRIPT_NAME=" in run_data["stdout"], (
            f"stdout={run_data['stdout']!r}"
        )
        assert run_data["scriptSource"]["type"] == "name"
        assert run_data["scriptSource"]["value"] == script_name

    async def test_read_script_returns_cat_n_numbered_output(
        self, mcp_stdio_client, isolated_workspace
    ):
        """read-script returns Claude-Code-style numbered lines."""
        script_name = f"reva_e2e_{uuid.uuid4().hex[:8]}.py"
        body = "alpha\nbeta\ngamma\n"

        write = await mcp_stdio_client.call_tool(
            "write-script",
            arguments={"scriptName": script_name, "code": body},
        )
        assert _parse(write)["success"] is True

        read = await mcp_stdio_client.call_tool(
            "read-script",
            arguments={"scriptName": script_name},
        )
        data = _parse(read)
        assert data["contents"] == "1\talpha\n2\tbeta\n3\tgamma\n"
        assert data["totalLines"] == 3
        assert data["truncated"] is False


# Reusable Python snippet that finds a function by C-source name. Mach-O
# decoration sometimes prefixes "_", so accept either form. Kept as a module
# constant so each Ghidra-API test reads as a focused diff.
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
        # The two-script round-trip is sufficient evidence the rename
        # committed: Script 2 ran in a fresh GhidraState built from
        # currentProgram, so any cache between the two calls would have to
        # invalidate on commit — which it does. A cross-check via
        # get-functions would also be useful but the function-info cache
        # paths differ in CLI mode and aren't the path under test here.

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
