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
- list-scripts surfaces a freshly written script with its directory metadata
- edit-script replaces text in place and the edited script still executes
"""

import json
import uuid
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio(loop_scope="session"),
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
    assert not (hasattr(result, "is_error") and result.is_error), (
        f"Import failed: {result.content[0].text if result.content else 'no content'}"
    )
    data = json.loads(result.content[0].text)
    assert data.get("success") is True
    assert len(data["importedPrograms"]) > 0
    return data["importedPrograms"][0]


def _parse(result) -> dict:
    """Parse a tool result's JSON body, failing loudly on tool-level errors.

    Every call site expects a non-error result (script-level failures are
    reported inside the JSON as success=False, not as MCP errors), so an
    isError result here means the tool itself broke — surface its error text
    instead of a downstream KeyError/JSONDecodeError.
    """
    assert not getattr(result, "is_error", False), (
        f"tool returned an error result: "
        f"{result.content[0].text if getattr(result, 'content', None) else 'no content'}"
    )
    return json.loads(result.content[0].text)


async def _label_count(client, program_path: str, label: str) -> int:
    """Count a symbol by name in the imported program via a read-only run."""
    result = await client.call_tool(
        "run-script",
        arguments={
            "programPath": program_path,
            "code": (
                f"syms = list(currentProgram.getSymbolTable().getSymbols({label!r}))\n"
                "print('LABEL_COUNT=' + str(len(syms)))\n"
            ),
            "timeoutSeconds": 30,
        },
    )
    data = _parse(result)
    assert data["success"] is True, f"label check failed: {data}"
    marker = "LABEL_COUNT="
    assert marker in data["stdout"], f"unexpected stdout: {data['stdout']!r}"
    return int(data["stdout"].split(marker, 1)[1].split()[0])


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
        assert not (hasattr(result, "is_error") and result.is_error), (
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

        # Compare the bound program's project pathname, not its display name:
        # in a shared project repeated imports of the same fixture get a
        # uniquifying counter suffix on the DomainFile (e.g. /test_arm64.3)
        # while the program's internal name stays "test_arm64".
        result = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": (
                    "path = currentProgram.getDomainFile().getPathname()\n"
                    "print('PROGRAM_PATH=' + path)\n"
                ),
                "timeoutSeconds": 30,
            },
        )

        data = _parse(result)
        assert data["success"] is True, f"failure: {data}"
        assert f"PROGRAM_PATH={program_path}" in data["stdout"], (
            f"unexpected stdout: {data['stdout']!r}"
        )

    async def test_script_exception_appears_in_stderr_with_success_false(
        self, mcp_stdio_client, isolated_workspace
    ):
        """An uncaught Python exception is captured (not an MCP error) and
        rolls back the edits the script made before raising."""
        program_path = await _import_test_program(mcp_stdio_client)
        label = "reva_e2e_rolled_back_label"

        # The label is created inside the run's parent transaction; PyGhidra
        # swallows the Python exception (traceback in stderr), so only the
        # traceback-driven rollback can keep the label out of the program.
        result = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": (
                    "mem = currentProgram.getMemory()\n"
                    "block = next((b for b in mem.getBlocks() if b.isExecute()), None)\n"
                    "assert block is not None, 'no executable block'\n"
                    f"createLabel(block.getStart(), '{label}', True)\n"
                    "raise ValueError('intentional test failure')\n"
                ),
                "timeoutSeconds": 30,
            },
        )

        # Tool itself ran successfully — the script error is not an MCP error.
        assert not (hasattr(result, "is_error") and result.is_error), (
            f"script failures must not surface as MCP errors: "
            f"{result.content[0].text}"
        )
        data = _parse(result)
        assert data["success"] is False, (
            "success must be False when script raises"
        )
        assert data["transaction"] == "rolled back", (
            f"a Python failure must roll the run back; got {data}"
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
        assert await _label_count(mcp_stdio_client, program_path, label) == 0, (
            "the label created before the raise survived the rollback"
        )

    async def test_timeout_seconds_bounds_runaway_script(
        self, mcp_stdio_client, isolated_workspace
    ):
        """A near-infinite loop must be cut off by timeoutSeconds, and the
        cancelled run's edits must be rolled back."""
        program_path = await _import_test_program(mcp_stdio_client)
        label = "reva_e2e_timeout_rolled_back"

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
                    "mem = currentProgram.getMemory()\n"
                    "block = next((b for b in mem.getBlocks() if b.isExecute()), None)\n"
                    "assert block is not None, 'no executable block'\n"
                    f"createLabel(block.getStart(), '{label}', True)\n"
                    "deadline = time.time() + 30\n"
                    "while time.time() < deadline:\n"
                    "    monitor.checkCancelled()\n"
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
        assert data["error"] == "IllegalStateException: script timed out after 3 seconds", data
        assert data["success"] is False, f"a cancelled run is a failure: {data}"
        assert data["transaction"] == "rolled back", (
            f"a timeout must roll the run back; got {data}"
        )
        assert await _label_count(mcp_stdio_client, program_path, label) == 0, (
            "the label created before the timeout survived the rollback"
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


class TestScriptFileManagementE2E:
    """list-scripts and edit-script against the live script directories."""

    async def test_list_scripts_includes_written_script(
        self, mcp_stdio_client, isolated_workspace
    ):
        """A script written via write-script must appear in list-scripts.

        Filters by the unique name so the assertion is immune to whatever
        else lives in the user/system script directories.
        """
        script_name = f"reva_e2e_{uuid.uuid4().hex[:8]}.py"

        write = await mcp_stdio_client.call_tool(
            "write-script",
            arguments={"scriptName": script_name, "code": "print('listed')\n"},
        )
        write_data = _parse(write)
        assert write_data["success"] is True, f"write failed: {write_data}"

        listing = await mcp_stdio_client.call_tool(
            "list-scripts",
            arguments={"nameFilter": script_name},
        )
        data = _parse(listing)
        assert data["total"] >= 1, (
            f"list-scripts must find the freshly written script; got {data!r}"
        )
        entries = [s for s in data["scripts"] if s.get("name") == script_name]
        assert entries, (
            f"Expected exactly our script under nameFilter={script_name!r}; "
            f"got {data['scripts']!r}"
        )
        entry = entries[0]
        assert entry["absolutePath"] == write_data["absolutePath"], (
            f"list-scripts path must match where write-script wrote: "
            f"entry={entry!r} write={write_data!r}"
        )
        assert entry["writeable"] is True, (
            f"Script in the default write directory must be writeable: {entry!r}"
        )
        assert entry["directory"], f"Entry must carry its directory: {entry!r}"

    async def test_edit_script_replaces_text_and_script_still_runs(
        self, mcp_stdio_client, isolated_workspace
    ):
        """write -> edit -> read-back -> run: the edit lands and executes."""
        program_path = await _import_test_program(mcp_stdio_client)
        script_name = f"reva_e2e_{uuid.uuid4().hex[:8]}.py"
        token = uuid.uuid4().hex[:8]
        original_marker = f"MARKER_ORIGINAL_{token}"
        edited_marker = f"MARKER_EDITED_{token}"

        write = await mcp_stdio_client.call_tool(
            "write-script",
            arguments={
                "scriptName": script_name,
                "code": (
                    "# @runtime PyGhidra\n"
                    f"print('{original_marker}')\n"
                ),
            },
        )
        assert _parse(write)["success"] is True

        edit = await mcp_stdio_client.call_tool(
            "edit-script",
            arguments={
                "scriptName": script_name,
                "old_string": original_marker,
                "new_string": edited_marker,
            },
        )
        edit_data = _parse(edit)
        assert edit_data["success"] is True, f"edit failed: {edit_data}"
        assert edit_data["replacements"] == 1, (
            f"Exactly one occurrence should have been replaced: {edit_data!r}"
        )

        read = await mcp_stdio_client.call_tool(
            "read-script",
            arguments={"scriptName": script_name},
        )
        read_data = _parse(read)
        assert edited_marker in read_data["contents"], (
            f"Edited marker missing from read-back: {read_data['contents']!r}"
        )
        assert original_marker not in read_data["contents"], (
            f"Original marker should be gone after edit: {read_data['contents']!r}"
        )

        run = await mcp_stdio_client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "scriptName": script_name,
                "timeoutSeconds": 30,
            },
        )
        run_data = _parse(run)
        assert run_data["success"] is True, f"edited script failed to run: {run_data}"
        assert edited_marker in run_data["stdout"], (
            f"Edited script must print the new marker; stdout={run_data['stdout']!r}"
        )

    async def test_edit_script_errors_when_old_string_missing(
        self, mcp_stdio_client, isolated_workspace
    ):
        """edit-script must error (not silently no-op) when old_string is absent."""
        script_name = f"reva_e2e_{uuid.uuid4().hex[:8]}.py"
        write = await mcp_stdio_client.call_tool(
            "write-script",
            arguments={"scriptName": script_name, "code": "print('stable')\n"},
        )
        assert _parse(write)["success"] is True

        edit = await mcp_stdio_client.call_tool(
            "edit-script",
            arguments={
                "scriptName": script_name,
                "old_string": "text_that_is_not_in_the_script",
                "new_string": "anything",
            },
        )
        assert getattr(edit, "is_error", False), (
            f"edit-script with a missing old_string must be an error; got: "
            f"{edit.content[0].text if getattr(edit, 'content', None) else 'no content'}"
        )


