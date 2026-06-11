"""
End-to-end tests for the diff-* MCP tools (binary diffing via Version Tracking).

Strategy: import the deterministic test_arm64 fixture TWICE (Ghidra uniquifies
the second DomainFile name), rename one function in the destination copy, then
self-diff the pair. That gives exact ground truth:
- the renamed function still matches (exact-bytes correlator on identical code),
- its caller (entry) is flagged changed via the 'callees' lens, with the old
  name in calleeChanges.removed and the new name in calleeChanges.added,
- every other matched function lands in the identical bucket.

Covers the full session lifecycle (create -> status poll -> list-sessions ->
summary -> list-functions -> function -> cancel-after-terminal -> delete) plus
the error paths for diff-status / diff-cancel / session-less reads.
"""

import json
import time
import uuid
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.cli,
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio(loop_scope="session"),
    pytest.mark.timeout(300),
]

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Terminal states of the background diff job machinery (JobStatus.isTerminal()).
TERMINAL_STATUSES = {"completed", "failed", "cancelled", "timed_out"}

# Hard cap on the diff-status poll loop. Correlating the tiny fixture takes
# seconds; the cap only bounds a hung job.
POLL_DEADLINE_SECONDS = 120


def _validate_fixture(name: str) -> str:
    fixture_path = FIXTURES_DIR / name
    if not fixture_path.exists():
        pytest.skip(f"Test fixture not found: {fixture_path}")
    if fixture_path.stat().st_size < 200:
        try:
            content = fixture_path.read_text()
        except UnicodeDecodeError:
            return str(fixture_path)
        if content.startswith("version https://git-lfs.github.com"):
            pytest.fail(
                f"Test fixture {name} is a Git LFS pointer, not the actual file. "
                "Run 'git lfs pull' locally or enable LFS in CI checkout."
            )
    return str(fixture_path)


def _result_text(result) -> str:
    """Safely render a CallToolResult's first text content for error messages."""
    if result is None:
        return "(no result)"
    content = getattr(result, "content", None) or []
    if not content:
        return "(empty content)"
    return getattr(content[0], "text", None) or "(no text)"


def _parse(result, context: str) -> dict:
    """Assert the tool call succeeded, then parse its JSON body."""
    assert result is not None, f"{context}: returned None — server unreachable?"
    assert not getattr(result, "isError", False), (
        f"{context} failed: {_result_text(result)}"
    )
    return json.loads(result.content[0].text)


async def _import_analyzed_copy(client) -> str:
    """Import the fixture with auto-analysis and return its unique programPath.

    Each call yields a distinct DomainFile (Ghidra appends a uniquifying
    counter for duplicate names), so two calls produce a diffable pair.
    """
    fixture = _validate_fixture("test_arm64")
    result = await client.call_tool(
        "import-file",
        arguments={
            "path": fixture,
            "destinationFolder": "/",
            "enableVersionControl": False,
            "analyzeAfterImport": True,
        },
    )
    data = _parse(result, "import-file")
    assert data.get("success") is True, f"Import unsuccessful: {data}"
    imported = data.get("importedPrograms", [])
    assert imported, f"No programs imported: {data}"
    return imported[0]


async def _rename_add_function(client, program_path: str, new_name: str) -> None:
    """Rename the fixture's add() function in `program_path` via run-script.

    Verified two ways: the script prints the post-rename name, and
    get-functions independently surfaces the new name afterwards.
    """
    rename_code = (
        "from ghidra.program.model.symbol import SourceType\n"
        "fm = currentProgram.getFunctionManager()\n"
        "target = next((f for f in fm.getFunctions(True)"
        " if f.getName().lstrip('_') == 'add'), None)\n"
        "assert target is not None, 'add function not found'\n"
        "tx = currentProgram.startTransaction('reva diff e2e rename')\n"
        "try:\n"
        f"    target.setName('{new_name}', SourceType.USER_DEFINED)\n"
        "finally:\n"
        "    currentProgram.endTransaction(tx, True)\n"
        "print('RENAMED=' + target.getName())\n"
    )
    result = await client.call_tool(
        "run-script",
        arguments={
            "programPath": program_path,
            "code": rename_code,
            "timeoutSeconds": 30,
        },
    )
    data = _parse(result, "run-script (rename)")
    assert data.get("success") is True, f"rename script failed: {data}"
    assert f"RENAMED={new_name}" in data.get("stdout", ""), (
        f"rename did not land; stdout={data.get('stdout')!r}"
    )

    listing = await client.call_tool(
        "get-functions",
        arguments={
            "programPath": program_path,
            "filterDefaultNames": False,
            "maxCount": 500,
        },
    )
    names = [
        f.get("name")
        for f in _parse(listing, "get-functions (rename check)").get("functions", [])
    ]
    assert new_name in names, (
        f"get-functions does not show renamed function {new_name!r}; names={names!r}"
    )


async def _poll_diff_job_until_terminal(client, job_id: str) -> dict:
    """Long-poll diff-status until the job is terminal; fail with the last payload."""
    deadline = time.monotonic() + POLL_DEADLINE_SECONDS
    last = None
    while time.monotonic() < deadline:
        result = await client.call_tool(
            "diff-status",
            arguments={"jobId": job_id, "waitSeconds": 5},
        )
        last = _parse(result, "diff-status")
        if last.get("status") in TERMINAL_STATUSES:
            return last
    pytest.fail(
        f"Diff job {job_id} did not reach a terminal state within "
        f"{POLL_DEADLINE_SECONDS}s; last status payload: {last!r}"
    )


async def _list_session_pairs(client) -> list[tuple[str, str]]:
    result = await client.call_tool("diff-list-sessions", arguments={})
    data = _parse(result, "diff-list-sessions")
    assert data.get("success") is True, f"diff-list-sessions not success: {data!r}"
    return [
        (s.get("sourceProgramPath"), s.get("destinationProgramPath"))
        for s in data.get("sessions", [])
    ]


class TestDiffSessionLifecycle:
    """Full create -> poll -> read -> delete cycle on a mutated self-diff pair."""

    async def test_self_diff_lifecycle_finds_renamed_callee(
        self, mcp_stdio_client, isolated_workspace
    ):
        client = mcp_stdio_client
        new_name = "reva_diff_e2e_renamed_add"

        # a. Two analyzed copies of the same binary, distinct project paths.
        src_path = await _import_analyzed_copy(client)
        dst_path = await _import_analyzed_copy(client)
        assert src_path != dst_path, (
            f"Second import must get a uniquified path; both were {src_path!r}"
        )

        # b. Mutate the destination: rename _add so entry's callee set differs.
        await _rename_add_function(client, dst_path, new_name)

        pair = {"sourceProgramPath": src_path, "destinationProgramPath": dst_path}
        try:
            # c. Create the session as a background job and poll to terminal.
            create = await client.call_tool(
                "diff-create-session",
                arguments={**pair, "waitSeconds": 0},
            )
            create_data = _parse(create, "diff-create-session")
            job_id = create_data.get("jobId")
            assert job_id, f"diff-create-session must return a jobId: {create_data!r}"

            final = await _poll_diff_job_until_terminal(client, job_id)
            assert final.get("status") == "completed", (
                f"Correlation job should complete; final payload: {final!r}"
            )
            assert final.get("kind") == "correlate", (
                f"Job kind should be correlate: {final!r}"
            )

            # Terminal diff-status carries the full session summary.
            assert final.get("success") is True, f"Summary not success: {final!r}"
            matched = final.get("matched") or {}
            assert isinstance(matched.get("identical"), int), (
                f"matched.identical missing/not int: {final!r}"
            )
            assert isinstance(matched.get("changed"), int), (
                f"matched.changed missing/not int: {final!r}"
            )
            # Self-diff of identical code: most functions match identically...
            assert matched["identical"] >= 1, (
                f"Expected >=1 identical matched function in self-diff: {final!r}"
            )
            # ...and the rename makes entry's callee set differ => >=1 changed.
            assert matched["changed"] >= 1, (
                f"Expected >=1 changed matched function (entry, via callees lens): {final!r}"
            )
            assert final.get("correlatorsRun"), (
                f"correlatorsRun should list the executed correlators: {final!r}"
            )
            # Same binary imported and analyzed identically on both sides.
            assert final.get("sourceFunctions") == final.get("destinationFunctions"), (
                f"Self-diff pair should have equal function counts: {final!r}"
            )
            assert final.get("sourceFunctions", 0) > 0, (
                f"Analyzed fixture must have functions: {final!r}"
            )

            # diff-cancel on a finished job is a documented no-op.
            cancel = await client.call_tool("diff-cancel", arguments={"jobId": job_id})
            cancel_data = _parse(cancel, "diff-cancel (terminal job)")
            assert cancel_data.get("success") is True, f"diff-cancel: {cancel_data!r}"
            assert cancel_data.get("alreadyTerminal") is True, (
                f"Cancel of a finished job must report alreadyTerminal: {cancel_data!r}"
            )
            assert cancel_data.get("status") == "completed", (
                f"Cancel must report the job's terminal status: {cancel_data!r}"
            )

            # d1. The session is listed.
            assert (src_path, dst_path) in await _list_session_pairs(client), (
                "diff-list-sessions must include the freshly created session"
            )

            # d2. diff-summary agrees with the job result and ranks entry as changed.
            summary = await client.call_tool("diff-summary", arguments=dict(pair))
            summary_data = _parse(summary, "diff-summary")
            assert summary_data.get("success") is True, f"summary: {summary_data!r}"
            s_matched = summary_data.get("matched") or {}
            assert s_matched.get("changed", 0) >= 1, (
                f"diff-summary must report >=1 changed function: {summary_data!r}"
            )
            most_changed = summary_data.get("mostChanged", [])
            assert most_changed, (
                f"mostChanged teaser must be non-empty when changed>=1: {summary_data!r}"
            )
            entry_rows = [r for r in most_changed if r.get("sourceName") == "entry"]
            assert entry_rows, (
                f"entry (caller of the renamed function) must appear in mostChanged; "
                f"got sourceNames={[r.get('sourceName') for r in most_changed]!r}"
            )
            assert "callees" in entry_rows[0].get("changeTypes", []), (
                f"entry must be changed via the callees lens: {entry_rows[0]!r}"
            )

            # d3. diff-list-functions category=changed pins the exact callee delta.
            changed_list = await client.call_tool(
                "diff-list-functions",
                arguments={**pair, "category": "changed"},
            )
            changed_data = _parse(changed_list, "diff-list-functions (changed)")
            assert changed_data.get("success") is True, f"{changed_data!r}"
            changed_rows = changed_data.get("functions", [])
            entry_changed = [r for r in changed_rows if r.get("sourceName") == "entry"]
            assert entry_changed, (
                f"entry must be in the changed category; rows={changed_rows!r}"
            )
            callee_changes = entry_changed[0].get("calleeChanges") or {}
            assert "_add" in callee_changes.get("removed", []), (
                f"calleeChanges.removed must contain the old callee name '_add': "
                f"{entry_changed[0]!r}"
            )
            assert new_name in callee_changes.get("added", []), (
                f"calleeChanges.added must contain the new callee name {new_name!r}: "
                f"{entry_changed[0]!r}"
            )

            # d4. The identical category is populated and its rows fired no lenses.
            identical_list = await client.call_tool(
                "diff-list-functions",
                arguments={**pair, "category": "identical"},
            )
            identical_data = _parse(identical_list, "diff-list-functions (identical)")
            identical_rows = identical_data.get("functions", [])
            assert identical_rows, (
                f"Self-diff must yield identical matched functions: {identical_data!r}"
            )
            for row in identical_rows:
                assert row.get("changeTypes") == [], (
                    f"identical rows must have empty changeTypes: {row!r}"
                )
                assert row.get("sourceAddress") and row.get("destAddress"), (
                    f"matched row must carry both addresses: {row!r}"
                )

            # d5. Decompiler drill-down on the changed caller.
            fn_diff = await client.call_tool(
                "diff-function",
                arguments={**pair, "function": "entry"},
            )
            fn_data = _parse(fn_diff, "diff-function")
            assert fn_data.get("success") is True, f"diff-function: {fn_data!r}"
            assert fn_data.get("sourceName") == "entry", f"{fn_data!r}"
            assert fn_data.get("destName") == "entry", f"{fn_data!r}"
            diff_payload = fn_data.get("diff") or {}
            assert diff_payload.get("hasChanges") is True, (
                f"Decompilation of entry must differ (renamed callee): {fn_data!r}"
            )
            assert diff_payload.get("changedLineCount", 0) >= 1, (
                f"Expected >=1 changed decompilation line: {diff_payload!r}"
            )
            assert "callees" in fn_data.get("changeTypes", []), (
                f"diff-function profile must show the callees lens: {fn_data!r}"
            )
            # Identical instruction bytes at identical addresses: the rename is
            # symbol-table-only, so the always-on body-bytes check must be clean.
            assert fn_data.get("bodyBytesChanged") is False, (
                f"Self-diff bodies are byte-identical: {fn_data!r}"
            )

            # e. Delete the session and confirm it is gone.
            delete = await client.call_tool("diff-delete-session", arguments=dict(pair))
            delete_data = _parse(delete, "diff-delete-session")
            assert delete_data.get("success") is True, f"{delete_data!r}"
            assert delete_data.get("deleted") is True, (
                f"delete must report the session was removed: {delete_data!r}"
            )
            assert (src_path, dst_path) not in await _list_session_pairs(client), (
                "Session must not be listed after diff-delete-session"
            )
        finally:
            # Idempotent safety net: ensure the persisted session does not leak
            # into the shared project if an assertion above failed.
            await client.call_tool("diff-delete-session", arguments=dict(pair))


class TestDiffErrorPaths:
    """Error contracts that need no session."""

    async def test_diff_status_unknown_job_id_is_error(
        self, mcp_stdio_client, isolated_workspace
    ):
        bogus = f"diff-bogus-{uuid.uuid4().hex[:8]}"
        result = await mcp_stdio_client.call_tool(
            "diff-status", arguments={"jobId": bogus}
        )
        assert getattr(result, "isError", False), (
            f"diff-status with unknown jobId must be an error; got: {_result_text(result)}"
        )
        assert "No diff job" in _result_text(result), (
            f"Error should name the missing job: {_result_text(result)!r}"
        )

    async def test_diff_cancel_unknown_job_id_is_error(
        self, mcp_stdio_client, isolated_workspace
    ):
        bogus = f"diff-bogus-{uuid.uuid4().hex[:8]}"
        result = await mcp_stdio_client.call_tool(
            "diff-cancel", arguments={"jobId": bogus}
        )
        assert getattr(result, "isError", False), (
            f"diff-cancel with unknown jobId must be an error; got: {_result_text(result)}"
        )
        assert "No diff job" in _result_text(result), (
            f"Error should name the missing job: {_result_text(result)!r}"
        )

    async def test_diff_summary_without_session_is_error(
        self, mcp_stdio_client, isolated_workspace
    ):
        token = uuid.uuid4().hex[:8]
        result = await mcp_stdio_client.call_tool(
            "diff-summary",
            arguments={
                "sourceProgramPath": f"/no_such_src_{token}",
                "destinationProgramPath": f"/no_such_dst_{token}",
            },
        )
        assert getattr(result, "isError", False), (
            f"diff-summary without a session must be an error; got: {_result_text(result)}"
        )
        assert "diff-create-session" in _result_text(result), (
            f"Error should point at diff-create-session: {_result_text(result)!r}"
        )
