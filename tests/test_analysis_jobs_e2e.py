"""
End-to-end tests for the background analysis job protocol:
analyze-program (async submit) -> analysis-status (long-poll) -> analysis-cancel.

The happy path imports the fixture WITHOUT auto-analysis, starts an analysis
job with waitSeconds=0 (forcing the pollable-job path even though the fixture
is tiny), polls analysis-status to a terminal state, validates the terminal
result payload, and then cross-checks real program state via get-function-count.
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
    pytest.mark.timeout(240),
]

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Terminal states of the analysis job machinery (JobStatus.isTerminal()).
TERMINAL_STATUSES = {"completed", "failed", "cancelled", "timed_out"}

# Hard cap on the analysis-status poll loop; the fixture analyzes in seconds.
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
    assert not getattr(result, "is_error", False), (
        f"{context} failed: {_result_text(result)}"
    )
    return json.loads(result.content[0].text)


async def _import_unanalyzed(client) -> str:
    """Import the fixture without analysis and return its unique programPath."""
    fixture = _validate_fixture("test_arm64")
    result = await client.call_tool(
        "import-file",
        arguments={
            "path": fixture,
            "destinationFolder": "/",
            "enableVersionControl": False,
            "analyzeAfterImport": False,
        },
    )
    data = _parse(result, "import-file")
    assert data.get("success") is True, f"Import unsuccessful: {data}"
    imported = data.get("importedPrograms", [])
    assert imported, f"No programs imported: {data}"
    return imported[0]


async def _poll_analysis_until_terminal(client, job_id: str) -> dict:
    """Long-poll analysis-status until terminal; fail with the last payload."""
    deadline = time.monotonic() + POLL_DEADLINE_SECONDS
    last = None
    while time.monotonic() < deadline:
        result = await client.call_tool(
            "analysis-status",
            arguments={"jobId": job_id, "waitSeconds": 5},
        )
        last = _parse(result, "analysis-status")
        if last.get("status") in TERMINAL_STATUSES:
            return last
    pytest.fail(
        f"Analysis job {job_id} did not reach a terminal state within "
        f"{POLL_DEADLINE_SECONDS}s; last status payload: {last!r}"
    )


async def _poll_analysis_with_log(client, job_id: str) -> tuple[dict, list[str]]:
    """Poll to a terminal state, returning the payload and every job log line."""
    deadline = time.monotonic() + POLL_DEADLINE_SECONDS
    since = 0
    messages: list[str] = []
    last = None
    while time.monotonic() < deadline:
        result = await client.call_tool(
            "analysis-status",
            arguments={
                "jobId": job_id,
                "waitSeconds": 5,
                "sinceLogSeq": since,
                "maxLogEntries": 500,
            },
        )
        last = _parse(result, "analysis-status")
        for entry in last.get("log", []):
            messages.append(entry.get("message", ""))
        since = last.get("logCursor", since)
        if last.get("status") in TERMINAL_STATUSES and not last.get("truncated"):
            return last, messages
    pytest.fail(
        f"Analysis job {job_id} did not reach a terminal state within "
        f"{POLL_DEADLINE_SECONDS}s; last status payload: {last!r}"
    )


class TestAnalysisJobLifecycle:
    """Submit, poll to completion, then exercise cancel's terminal no-op."""

    async def test_analyze_program_job_completes_and_cancel_is_noop(
        self, mcp_stdio_client, isolated_workspace
    ):
        client = mcp_stdio_client
        program_path = await _import_unanalyzed(client)

        # Submit with waitSeconds=0 so the call returns a job handle instead of
        # blocking inline — this is the path that exercises analysis-status.
        start = await client.call_tool(
            "analyze-program",
            arguments={
                "programPath": program_path,
                "forceFullAnalysis": True,
                "waitSeconds": 0,
            },
        )
        start_data = _parse(start, "analyze-program")
        job_id = start_data.get("jobId")
        assert job_id, f"analyze-program must return a jobId: {start_data!r}"
        assert start_data.get("programPath") == program_path, (
            f"Job must be bound to the requested program: {start_data!r}"
        )

        final = await _poll_analysis_until_terminal(client, job_id)
        assert final.get("status") == "completed", (
            f"Analysis job should complete; final payload: {final!r}"
        )
        assert final.get("jobId") == job_id, f"{final!r}"
        assert final.get("programPath") == program_path, (
            f"Status must report the analyzed program: {final!r}"
        )
        # Terminal status carries the runner's full result map.
        job_result = final.get("result") or {}
        assert job_result.get("success") is True, (
            f"Terminal result must report success: {final!r}"
        )
        assert job_result.get("programPath") == program_path, (
            f"Result must mention the program: {job_result!r}"
        )
        assert job_result.get("analyzed") is True, (
            f"Program must be marked analyzed after the job: {job_result!r}"
        )
        assert job_result.get("cancelled") is False, f"{job_result!r}"
        assert job_result.get("timedOut") is False, f"{job_result!r}"

        # Independent state check: analysis actually populated functions.
        count_res = await client.call_tool(
            "get-function-count", arguments={"programPath": program_path}
        )
        count_data = _parse(count_res, "get-function-count")
        assert count_data.get("count", 0) >= 4, (
            f"Analyzed fixture must have >=4 functions (entry/_add/_multiply/stub); "
            f"got {count_data!r}"
        )

        # analysis-cancel on the finished job is a documented no-op.
        cancel = await client.call_tool("analysis-cancel", arguments={"jobId": job_id})
        cancel_data = _parse(cancel, "analysis-cancel (terminal job)")
        assert cancel_data.get("success") is True, f"{cancel_data!r}"
        assert cancel_data.get("alreadyTerminal") is True, (
            f"Cancel of a finished job must report alreadyTerminal: {cancel_data!r}"
        )
        assert cancel_data.get("status") == "completed", (
            f"Cancel must report the job's terminal status: {cancel_data!r}"
        )
        assert "nothing to cancel" in cancel_data.get("message", ""), (
            f"Cancel no-op must say so: {cancel_data!r}"
        )


class TestAnalysisJobErrorPaths:
    """Error contracts for unknown jobs and bad identifier combinations."""

    async def test_analysis_status_unknown_job_id_is_error(
        self, mcp_stdio_client, isolated_workspace
    ):
        bogus = f"analysis-bogus-{uuid.uuid4().hex[:8]}"
        result = await mcp_stdio_client.call_tool(
            "analysis-status", arguments={"jobId": bogus}
        )
        assert getattr(result, "is_error", False), (
            f"analysis-status with unknown jobId must be an error; "
            f"got: {_result_text(result)}"
        )
        assert "No job" in _result_text(result), (
            f"Error should name the missing job: {_result_text(result)!r}"
        )

    async def test_analysis_cancel_unknown_job_id_is_error(
        self, mcp_stdio_client, isolated_workspace
    ):
        bogus = f"analysis-bogus-{uuid.uuid4().hex[:8]}"
        result = await mcp_stdio_client.call_tool(
            "analysis-cancel", arguments={"jobId": bogus}
        )
        assert getattr(result, "is_error", False), (
            f"analysis-cancel with unknown jobId must be an error; "
            f"got: {_result_text(result)}"
        )
        assert "No job" in _result_text(result), (
            f"Error should name the missing job: {_result_text(result)!r}"
        )

    async def test_analysis_status_both_identifiers_rejected_and_neither_resolves(
        self, mcp_stdio_client, isolated_workspace
    ):
        # Documented contract (tool schema, project/CLAUDE.md): both identifiers
        # at once is always an error; with neither, the sole open program is
        # used (none open: the project's only program; several: the error lists
        # them). The session-scoped server shares one project across modules,
        # so the with-neither call may legitimately take either branch.
        both = await mcp_stdio_client.call_tool(
            "analysis-status",
            arguments={"jobId": "analysis-1", "programPath": "/whatever"},
        )
        assert getattr(both, "is_error", False), (
            f"analysis-status with both identifiers must be an error; "
            f"got: {_result_text(both)}"
        )
        assert "not both" in _result_text(both), (
            f"Error should reject providing both identifiers: {_result_text(both)!r}"
        )

        neither = await mcp_stdio_client.call_tool("analysis-status", arguments={})
        if getattr(neither, "is_error", False):
            assert "programPath is required when several programs are open" in _result_text(
                neither
            ), f"the with-neither error must list the candidates: {_result_text(neither)!r}"
        else:
            data = json.loads(_result_text(neither))
            assert data.get("success") is True and data.get("programPath"), (
                f"sole-program resolution should return that program's job: {data!r}"
            )


class TestDefaultSnapshotConfiguration:
    """Default ReVa must not create, hide, or refuse any snapshot folder."""

    async def test_default_config_creates_no_snapshot_and_user_baselines_is_ordinary(
        self, mcp_stdio_client_isolated, isolated_workspace
    ):
        client = mcp_stdio_client_isolated
        program_path = await _import_unanalyzed(client)

        start = await client.call_tool(
            "analyze-program",
            arguments={
                "programPath": program_path,
                "forceFullAnalysis": True,
                "waitSeconds": 0,
            },
        )
        start_data = _parse(start, "analyze-program")
        job_id = start_data.get("jobId")
        assert job_id, f"analyze-program must return a jobId: {start_data!r}"

        final, log_messages = await _poll_analysis_with_log(client, job_id)
        assert final.get("status") == "completed", (
            f"analysis should complete; final payload: {final!r}"
        )
        assert not any("Analysis snapshot" in line for line in log_messages), (
            f"default-off analysis must not log snapshot activity: {log_messages!r}"
        )
        assert "snapshot" not in (final.get("result") or {}), (
            f"the analysis result leaked a snapshot: {final!r}"
        )

        root = _parse(
            await client.call_tool(
                "list-project-files",
                arguments={"folderPath": "/", "recursive": False},
            ),
            "list-project-files (default root)",
        )
        root_items = root.get("items", [])
        folders = [item for item in root_items if item.get("type") == "folder"]
        assert folders == [], (
            f"default analysis must not create or hide a snapshot folder; got {folders!r}"
        )
        assert not any(
            "snapshot-" in (item.get("programPath") or item.get("folderPath") or "")
            for item in root_items
        ), f"default analysis must not create a snapshot file: {root_items!r}"

        # A user folder named /baselines is ordinary project state: nothing is
        # reserved, hidden, or refused when no snapshot folder is configured.
        create = await client.call_tool(
            "run-script",
            arguments={
                "programPath": program_path,
                "code": (
                    "from ghidra.util.task import TaskMonitor\n"
                    "root = currentProgram.getDomainFile().getParent()"
                    ".getProjectData().getRootFolder()\n"
                    "folder = root.getFolder('baselines')\n"
                    "if folder is None:\n"
                    "    folder = root.createFolder('baselines')\n"
                    "copy = currentProgram.getDomainFile().copyTo("
                    "folder, TaskMonitor.DUMMY)\n"
                    "print('COPY_PATH=' + copy.getPathname())\n"
                ),
                "timeoutSeconds": 30,
            },
        )
        create_data = _parse(create, "run-script create user baselines")
        assert create_data.get("success") is True, (
            f"creating a user /baselines folder must succeed: {create_data!r}"
        )
        assert "COPY_PATH=" in create_data.get("stdout", ""), (
            f"the copy's path should be reported: {create_data!r}"
        )
        copy_path = create_data["stdout"].split("COPY_PATH=", 1)[1].split()[0]
        assert copy_path.startswith("/baselines/"), copy_path

        root = _parse(
            await client.call_tool(
                "list-project-files",
                arguments={"folderPath": "/", "recursive": False},
            ),
            "list-project-files (user baselines present)",
        )
        assert any(
            item.get("type") == "folder"
            and (item.get("folderPath") or "").strip("/") == "baselines"
            for item in root.get("items", [])
        ), f"a user /baselines folder must be listed ordinarily: {root!r}"

        recursive = _parse(
            await client.call_tool(
                "list-project-files",
                arguments={"folderPath": "/", "recursive": True},
            ),
            "list-project-files (recursive)",
        )
        listed_paths = [
            item.get("programPath") for item in recursive.get("items", [])
        ]
        assert copy_path in listed_paths, (
            f"the user file under /baselines must be listed: {listed_paths!r}"
        )

        explicit = await client.call_tool(
            "list-project-files", arguments={"folderPath": "/baselines"}
        )
        assert not getattr(explicit, "is_error", False), (
            f"explicitly listing a user /baselines folder must succeed: "
            f"{_result_text(explicit)}"
        )
        explicit_data = _parse(explicit, "list-project-files /baselines")
        assert explicit_data.get("itemCount", 0) >= 1, explicit_data

        count = await client.call_tool(
            "get-function-count", arguments={"programPath": copy_path}
        )
        count_data = _parse(count, f"get-function-count {copy_path}")
        assert count_data.get("count", 0) >= 1, (
            f"a user file under /baselines must be addressable: {count_data!r}"
        )
