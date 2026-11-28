"""
End-to-end workflow tests for ReVa.

Tests the complete workflow:
1. Import binary with version control
2. Open program (auto-checkout)
3. Make changes
4. Commit changes
5. Close program
6. Reopen program (auto-checkout again)
7. Verify changes persist

These tests verify:
- Auto-checkout functionality when opening versioned programs
- Cache release mechanism during checkin
- Changes persist after close/reopen cycle
"""

import asyncio
import json
import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path

import pytest
import pytest_asyncio

from tests.helpers import fresh_fixture_copy

# Mark all tests in this file
pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio(loop_scope="session"),
    pytest.mark.timeout(240)  # 4 minutes for full workflow
]


@pytest_asyncio.fixture(loop_scope="session")
async def mcp_stdio_client_snapshot(isolated_workspace):
    """Fresh mcp-reva server with analysis snapshots enabled.

    The e2e subprocess reads REVA_CONFIG_PATH before it starts, so this fixture
    writes a properties file with a snapshot folder and prefix, points the
    environment at it only for this server's lifetime, and removes both at
    teardown. Scoping the config to a dedicated fixture keeps snapshots off for
    every other e2e test in the suite.
    """
    from tests.conftest import _stdio_mcp_session

    config_dir = tempfile.mkdtemp(prefix="reva-snapshot-config-")
    config_file = os.path.join(config_dir, "reva.properties")
    with open(config_file, "w") as handle:
        handle.write("reva.server.options.snapshot.folder=baseline\n")
        handle.write("reva.server.options.snapshot.prefix=baseline-\n")
    previous = os.environ.get("REVA_CONFIG_PATH")
    os.environ["REVA_CONFIG_PATH"] = config_file
    try:
        async with _stdio_mcp_session(isolated_workspace) as session:
            yield session
    finally:
        if previous is None:
            os.environ.pop("REVA_CONFIG_PATH", None)
        else:
            os.environ["REVA_CONFIG_PATH"] = previous
        shutil.rmtree(config_dir, ignore_errors=True)


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _resolve_workflow_fixture():
    """Return path to the deterministic workflow fixture, skipping if missing/LFS pointer."""
    fixture_path = FIXTURES_DIR / "test_arm64"
    if not fixture_path.exists():
        pytest.skip(f"Test fixture not found: {fixture_path}")
    if fixture_path.stat().st_size < 200:
        try:
            content = fixture_path.read_text()
        except UnicodeDecodeError:
            return fresh_fixture_copy(fixture_path)
        if content.startswith("version https://git-lfs.github.com"):
            pytest.fail(
                f"Test fixture {fixture_path.name} is a Git LFS pointer, not the actual file. "
                "Run 'git lfs pull' locally or enable LFS in CI checkout."
            )
    return fresh_fixture_copy(fixture_path)


def _tool_payload(result, label):
    """Return a tool result's parsed JSON body, failing loudly on tool errors."""
    assert result is not None, f"{label}: no result"
    content = getattr(result, "content", None)
    assert content, f"{label}: empty content"
    text = content[0].text
    assert not getattr(result, "is_error", False), f"{label} failed: {text}"
    return json.loads(text)


async def _assert_annotations_present(
    client, program_path, range_start, range_end, bookmark_comments, comment_texts, *,
    context,
):
    """Read every acknowledged annotation back through the MCP tools."""
    bookmarks_payload = _tool_payload(
        await client.call_tool(
            "get-bookmarks",
            arguments={
                "programPath": program_path,
                "type": "Note",
                "category": "Evidence",
                "maxResults": 200,
            },
        ),
        f"get-bookmarks ({context})",
    )
    found_bookmarks = {
        (bookmark.get("type"), bookmark.get("category"), bookmark.get("comment"))
        for bookmark in bookmarks_payload.get("bookmarks", [])
    }
    for comment in bookmark_comments:
        assert ("Note", "Evidence", comment) in found_bookmarks, (
            f"bookmark {comment!r} missing {context}: {sorted(found_bookmarks)}"
        )

    comments_payload = _tool_payload(
        await client.call_tool(
            "get-comments",
            arguments={
                "programPath": program_path,
                "addressRange": {"start": range_start, "end": range_end},
            },
        ),
        f"get-comments ({context})",
    )
    found_comments = {
        comment.get("comment") for comment in comments_payload.get("comments", [])
    }
    for comment in comment_texts:
        assert comment in found_comments, (
            f"comment {comment!r} missing {context}: {sorted(found_comments)}"
        )


_SAVED_DUMP_SCRIPT = """\
import json

from java.lang import Object
from ghidra.framework.model import DomainFile
from ghidra.program.model.listing import CommentType
from ghidra.util.task import TaskMonitor

# Commit an in-memory bookmark without saving it. The read-only copy opened
# below must not contain it: that proves this dump reads the saved database
# instead of the live program the tools are writing to.
sentinel = currentProgram.getAddressFactory().getAddress(%(sentinel)r)
currentProgram.getBookmarkManager().setBookmark(
    sentinel, "Note", "Sentinel", "memory only")

consumer = Object()
saved = currentProgram.getDomainFile().getReadOnlyDomainObject(
    consumer, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY)
try:
    bookmarks = []
    for bookmark in list(saved.getBookmarkManager().getBookmarksIterator()):
        bookmarks.append({
            "address": str(bookmark.getAddress()),
            "type": bookmark.getTypeString(),
            "category": bookmark.getCategory(),
            "comment": bookmark.getComment(),
        })
    comments = []
    listing = saved.getListing()
    for address in list(listing.getCommentAddressIterator(saved.getMemory(), True)):
        for comment_type in (CommentType.EOL, CommentType.PRE, CommentType.POST,
                             CommentType.PLATE, CommentType.REPEATABLE):
            comment = listing.getComment(comment_type, address)
            if comment:
                comments.append(comment)
finally:
    saved.release(consumer)

import os
import tempfile

fd, path = tempfile.mkstemp(prefix="reva-saved-dump-", suffix=".json")
os.close(fd)
with open(path, "w") as handle:
    json.dump({"bookmarks": bookmarks, "comments": comments}, handle)
print("SAVED_DUMP_PATH=" + path)
"""


async def _dump_saved_annotations(client, program_path, sentinel_address):
    """Open a read-only copy of the saved domain file and dump its annotations.

    The copy comes from the stored database, not the live program: an unsaved
    sentinel bookmark is committed to memory first and must be absent from the
    dump or the read-back is not proving persistence.
    """
    result = await client.call_tool(
        "run-script",
        arguments={
            "programPath": program_path,
            "code": _SAVED_DUMP_SCRIPT % {"sentinel": sentinel_address},
            "timeoutSeconds": 60,
        },
    )
    data = _tool_payload(result, "saved-database dump")
    assert data.get("success") is True, f"saved-database dump failed: {data}"
    marker = "SAVED_DUMP_PATH="
    assert marker in data["stdout"], f"unexpected stdout: {data['stdout']!r}"
    dump_path = data["stdout"].split(marker, 1)[1].splitlines()[0].strip()
    try:
        with open(dump_path) as handle:
            payload = json.load(handle)
    finally:
        try:
            os.remove(dump_path)
        except OSError:
            pass
    assert not any(
        bookmark.get("comment") == "memory only"
        for bookmark in payload.get("bookmarks", [])
    ), (
        "saved-database dump saw committed-but-unsaved state; it is not a "
        f"disk read-back: {payload!r}"
    )
    return payload


_PROJECT_FILE_DUMP_SCRIPT = """\
import json

from java.lang import Object
from ghidra.framework.model import DomainFile
from ghidra.program.model.listing import CommentType
from ghidra.util.task import TaskMonitor

# A configured analysis snapshot is not addressable through the MCP tools, so
# open its DomainFile directly from the project and dump the saved database.
# The script runs on the addressable target program; only the read happens on
# the requested project file.
project_data = currentProgram.getDomainFile().getParent().getProjectData()
target = project_data.getFile(%(project_file_path)r)
if target is None:
    raise RuntimeError("project file not found: " + %(project_file_path)r)

consumer = Object()
saved = target.getReadOnlyDomainObject(
    consumer, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY)
try:
    bookmarks = []
    for bookmark in list(saved.getBookmarkManager().getBookmarksIterator()):
        bookmarks.append({
            "address": str(bookmark.getAddress()),
            "type": bookmark.getTypeString(),
            "category": bookmark.getCategory(),
            "comment": bookmark.getComment(),
        })
    comments = []
    listing = saved.getListing()
    for address in list(listing.getCommentAddressIterator(saved.getMemory(), True)):
        for comment_type in (CommentType.EOL, CommentType.PRE, CommentType.POST,
                             CommentType.PLATE, CommentType.REPEATABLE):
            comment = listing.getComment(comment_type, address)
            if comment:
                comments.append(comment)
finally:
    saved.release(consumer)

import os
import tempfile

fd, path = tempfile.mkstemp(prefix="reva-project-file-dump-", suffix=".json")
os.close(fd)
with open(path, "w") as handle:
    json.dump({
        "path": target.getPathname(),
        "bookmarks": bookmarks,
        "comments": comments,
    }, handle)
print("PROJECT_FILE_DUMP_PATH=" + path)
"""


async def _dump_project_file_annotations(client, target_program_path, project_file_path):
    """Dump a saved project file's annotations without addressing it as a program.

    Configured analysis snapshots are refused as tool program paths, so the
    baseline is read from the target program's script context by opening the
    snapshot's DomainFile directly. This is the independent baseline proof the
    verification document cites: the target dump shows the intended removals
    survived, and this dump shows the baseline never held them.
    """
    result = await client.call_tool(
        "run-script",
        arguments={
            "programPath": target_program_path,
            "code": _PROJECT_FILE_DUMP_SCRIPT % {"project_file_path": project_file_path},
            "timeoutSeconds": 60,
        },
    )
    data = _tool_payload(result, "project-file dump")
    assert data.get("success") is True, f"project-file dump failed: {data}"
    marker = "PROJECT_FILE_DUMP_PATH="
    assert marker in data["stdout"], f"unexpected stdout: {data['stdout']!r}"
    dump_path = data["stdout"].split(marker, 1)[1].splitlines()[0].strip()
    try:
        with open(dump_path) as handle:
            return json.load(handle)
    finally:
        try:
            os.remove(dump_path)
        except OSError:
            pass


async def _poll_analysis_to_terminal(client, job_id, deadline_seconds=600):
    """Poll a background analysis job until it reaches a terminal state."""
    deadline = time.monotonic() + deadline_seconds
    since = 0
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
        last = _tool_payload(result, "analysis-status")
        since = last.get("logCursor", since)
        if last.get("status") in {"completed", "failed", "cancelled", "timed_out"}:
            if not last.get("truncated"):
                return last
    pytest.fail(
        f"Analysis job {job_id} did not reach a terminal state within "
        f"{deadline_seconds}s; last payload: {last!r}"
    )


class TestE2EWorkflow:
    """End-to-end workflow tests."""

    async def test_import_change_save_and_reread_workflow(self, mcp_stdio_client, isolated_workspace):
        """
        Workflow: import -> open -> change -> save -> re-read same session.

        Tests that import-file, set-comment, checkin-program, and
        get-comments work together within a single MCP session. With
        keepCheckedOut=False, checkin-program calls
        RevaProgramManager.releaseProgramFromCache(program) — so the
        final get-comments has to re-open the program (Ghidra reloads
        the domain file's listing), which means it really is reading
        the comment back from the saved-to-disk state, not from the
        in-memory object the comment was written to.

        What this test does NOT verify: cross-process persistence. The
        whole flow runs against a single mcp-reva subprocess, so a fresh
        process opening the same project independently would need either
        a close-program tool or a two-process harness — neither exists
        today.
        """
        test_binary = _resolve_workflow_fixture()

        print("\n=== STEP 1: Import binary ===")
        import_result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": test_binary,
                "destinationFolder": "/",
                "enableVersionControl": False  # Skip version control in test environment
            }
        )

        # Verify import succeeded
        assert import_result is not None
        assert hasattr(import_result, 'content'), "Result missing content attribute"
        assert len(import_result.content) > 0, "Result content is empty"

        # Check if it's an error
        if hasattr(import_result, 'is_error') and import_result.is_error:
            error_text = import_result.content[0].text if import_result.content else "Unknown error"
            pytest.fail(f"Import failed: {error_text}")

        content_text = import_result.content[0].text
        print(f"Content text ({len(content_text)} chars): {content_text[:200]}...")

        assert content_text, (
            "Import returned empty content. The installed ReVa extension may be outdated; "
            "run 'gradle install' to install the development version."
        )

        import_data = json.loads(content_text)
        print(f"Import response: {json.dumps(import_data, indent=2)}")

        assert import_data.get("success") is True
        assert "importedPrograms" in import_data
        assert len(import_data["importedPrograms"]) > 0

        # Get the first imported program path
        program_path = import_data["importedPrograms"][0]
        print(f"Imported program: {program_path}")

        print("\n=== STEP 2: Get decompilation (triggers auto-checkout) ===")
        # Getting decompilation will open the program via getProgramByPath
        # which should trigger auto-checkout
        decomp_result = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": "entry",
                "offset": 1,
                "limit": 10
            }
        )

        assert decomp_result is not None
        assert not getattr(decomp_result, "is_error", False), (
            f"get-decompilation failed: "
            f"{decomp_result.content[0].text if decomp_result.content else 'no content'}"
        )
        decomp_data = json.loads(decomp_result.content[0].text)
        print(f"Initial decompilation response: {json.dumps(decomp_data, indent=2)[:200]}...")
        assert decomp_data.get("decompilation"), (
            f"Expected non-empty decompilation for 'entry': {decomp_data}"
        )

        # The program should now be checked out automatically
        # We can't directly verify checkout status via MCP, but the next step
        # (making changes) will fail if not checked out

        print("\n=== STEP 3: Make a change (set a comment) ===")
        # Set a comment - this will fail if the program isn't checked out
        comment_result = await mcp_stdio_client.call_tool(
            "set-comment",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": "entry",
                "comment": "E2E Test Comment - Auto-Checkout Verification"
            }
        )

        assert comment_result is not None
        comment_data = json.loads(comment_result.content[0].text)
        print(f"Set comment response: {json.dumps(comment_data, indent=2)}")

        assert comment_data.get("success") is True
        print("✓ Successfully set comment (program was checked out)")

        print("\n=== STEP 4: Save changes ===")
        # Save the changes via checkin tool (will just save without version control)
        checkin_result = await mcp_stdio_client.call_tool(
            "checkin-program",
            arguments={
                "programPath": program_path,
                "message": "E2E test: Added comment",
                "keepCheckedOut": False
            }
        )

        assert checkin_result is not None
        checkin_data = json.loads(checkin_result.content[0].text)
        print(f"Checkin response: {json.dumps(checkin_data, indent=2)}")

        assert checkin_data.get("success") is True
        # The CLI's stdio project is repo-backed, so the file is not yet
        # versioned at this point and checkin-program promotes it via
        # addToVersionControl. Assert the exact deterministic action so a
        # regression (e.g., tool returning a stale "saved" without writing)
        # surfaces. If the project setup ever changes to non-repo, update
        # this to == "saved".
        assert checkin_data.get("action") == "added_to_version_control", (
            f"Expected action=added_to_version_control on first checkin in "
            f"a repo-backed project; got {checkin_data!r}"
        )
        print("✓ Successfully saved changes")

        print("\n=== STEP 5: Reopen program and verify changes ===")
        # Get comments to verify persistence - this will reopen the program
        # and should auto-checkout again
        get_comments_result = await mcp_stdio_client.call_tool(
            "get-comments",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": "entry"
            }
        )

        assert get_comments_result is not None
        comments_data = json.loads(get_comments_result.content[0].text)
        print(f"Get comments response: {json.dumps(comments_data, indent=2)}")

        # get-comments returns {comments: [], count: N} without "success" field
        assert "comments" in comments_data
        assert "count" in comments_data

        # Verify our comment is there
        comments = comments_data["comments"]
        comment_found = False
        for comment in comments:
            if "E2E Test Comment" in comment.get("comment", ""):
                comment_found = True
                print(f"✓ Found persisted comment: {comment['comment']}")
                break

        assert comment_found, "Comment did not persist after reopen"
        print("✓ Changes persisted after close/reopen cycle")

        print("\n=== SUCCESS: Complete workflow verified ===")

    async def test_label_creation_persists_in_symbol_table(self, mcp_stdio_client, isolated_workspace):
        """
        Verify create-label actually creates a queryable symbol.

        Earlier this test was named test_auto_checkout_on_first_open and
        asserted only that label_data["success"] is True. With
        enableVersionControl=False there is nothing to "auto-checkout";
        what the call actually exercises is whether create-label both
        succeeds and produces a symbol that get-symbols can find.
        """
        test_binary = _resolve_workflow_fixture()

        print("\n=== Import binary ===")
        import_result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": test_binary,
                "destinationFolder": "/",
                "enableVersionControl": False
            }
        )

        assert import_result is not None
        assert hasattr(import_result, 'content'), "Result missing content attribute"
        assert len(import_result.content) > 0, "Result content is empty"

        if hasattr(import_result, 'is_error') and import_result.is_error:
            error_text = import_result.content[0].text if import_result.content else "Unknown error"
            pytest.fail(f"Import failed: {error_text}")

        content_text = import_result.content[0].text
        assert content_text, (
            "Import returned empty content. The installed ReVa extension may be outdated; "
            "run 'gradle install' to install the development version."
        )

        import_data = json.loads(content_text)
        assert import_data.get("success") is True

        program_path = import_data["importedPrograms"][0]
        print(f"Imported program: {program_path}")

        print("\n=== Create label ===")
        label_name = "reva_e2e_label_creation_test"
        label_result = await mcp_stdio_client.call_tool(
            "create-label",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": "entry",
                "labelName": label_name,
            },
        )

        label_data = json.loads(label_result.content[0].text)
        print(f"Create label response: {json.dumps(label_data, indent=2)}")
        assert label_data.get("success") is True, f"create-label failed: {label_data}"

        print("\n=== Verify label appears in symbol table ===")
        symbols_result = await mcp_stdio_client.call_tool(
            "get-symbols",
            arguments={
                "programPath": program_path,
                "maxCount": 500,
            },
        )
        assert not getattr(symbols_result, "is_error", False), (
            f"get-symbols failed: {symbols_result.content[0].text if symbols_result.content else 'no content'}"
        )

        symbols_payload = json.loads(symbols_result.content[0].text)
        symbol_names = [s.get("name") for s in symbols_payload.get("symbols", [])]

        assert label_name in symbol_names, (
            f"Label {label_name!r} created successfully but not found in get-symbols output. "
            f"Symbols (first 20): {symbol_names[:20]}"
        )
        print(f"✓ Label {label_name!r} present in symbol table")

    async def test_checkin_with_keep_checked_out_succeeds(self, mcp_stdio_client, isolated_workspace):
        """
        Verify checkin-program with keepCheckedOut=True returns success.

        Earlier this test was named test_cache_release_during_checkin and
        claimed to verify cache handling. In stdio mode the program stays
        in the in-memory cache regardless of keepCheckedOut, so the test
        cannot verify cache release. What it actually exercises is that
        modify-then-checkin with keepCheckedOut=True does not error.
        """
        test_binary = _resolve_workflow_fixture()

        print("\n=== Import and open program ===")
        import_result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": test_binary,
                "destinationFolder": "/",
                "enableVersionControl": False
            }
        )

        assert import_result is not None
        assert len(import_result.content) > 0
        if hasattr(import_result, 'is_error') and import_result.is_error:
            pytest.fail(f"Import failed: {import_result.content[0].text}")

        content_text = import_result.content[0].text
        assert content_text, (
            "Import returned empty content. The installed ReVa extension may be outdated; "
            "run 'gradle install' to install the development version."
        )

        import_data = json.loads(content_text)
        program_path = import_data["importedPrograms"][0]

        # Open the program by getting decompilation (this caches it)
        decomp_result = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": "entry",
                "limit": 5
            }
        )
        assert not getattr(decomp_result, "is_error", False), (
            f"get-decompilation failed: "
            f"{decomp_result.content[0].text if decomp_result.content else 'no content'}"
        )
        # get-decompilation has no "success" field; a non-empty decompilation
        # body is the success signal.
        decomp_data = json.loads(decomp_result.content[0].text)
        assert decomp_data.get("decompilation"), (
            f"Expected non-empty decompilation for 'entry': {decomp_data}"
        )
        print("✓ Program opened and cached")

        print("\n=== Make changes ===")
        comment_result = await mcp_stdio_client.call_tool(
            "set-comment",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": "entry",
                "comment": "Cache release test"
            }
        )
        assert not getattr(comment_result, "is_error", False), (
            f"set-comment failed: "
            f"{comment_result.content[0].text if comment_result.content else 'no content'}"
        )
        comment_data = json.loads(comment_result.content[0].text)
        assert comment_data.get("success") is True, f"set-comment failed: {comment_data}"
        print("✓ Changes made")

        print("\n=== Save (tests cache handling) ===")
        # This should handle the program cache correctly during save
        # If cache handling doesn't work, we'd get "program in use" error
        checkin_result = await mcp_stdio_client.call_tool(
            "checkin-program",
            arguments={
                "programPath": program_path,
                "message": "Test cache release",
                "keepCheckedOut": True
            }
        )

        checkin_data = json.loads(checkin_result.content[0].text)
        print(f"Checkin response: {json.dumps(checkin_data, indent=2)}")

        # Success means cache was handled correctly
        assert checkin_data.get("success") is True
        print("✓ Save succeeded - cache was handled correctly")

    async def test_blocked_checkin_recovery_preserves_annotations(
        self, mcp_stdio_client_isolated, isolated_workspace
    ):
        """A transient run-script blocker must not cost acknowledged annotations.

        Regression for the failed-checkin cache release: checkin-program used
        to drop the cached program even when ProgramPersistenceUtil returned
        SKIP (a transaction was still open), closing the last headless
        consumer and discarding every committed-but-unsaved bookmark/comment.
        This test holds a real run-script transaction across the checkin wait,
        requires the checkin to be refused, then proves the annotations survive
        in memory, after a successful checkin, and in a packed GZF export.

        The `_dump_saved_annotations` helper reads the saved database directly
        (opening a read-only DomainObject copy) and supplies the disk-read-back
        guarantee independently; reopening the program is not required for that
        proof. A failed checkin after a successful save retains the cached
        program so a retry can save the post-save mutation; the program is not
        released on a failed checkin and stays cached until manager cleanup.

        If the MCP transport serializes the two calls the overlap never
        happens; the test fails with an explicit INCONCLUSIVE message instead
        of passing vacuously.
        """
        client = mcp_stdio_client_isolated
        test_binary = _resolve_workflow_fixture()

        print("\n=== Import and analyze fixture ===")
        import_data = _tool_payload(
            await client.call_tool(
                "import-file",
                arguments={
                    "path": test_binary,
                    "destinationFolder": "/",
                    "enableVersionControl": False,
                    "analyzeAfterImport": True,
                },
            ),
            "import-file",
        )
        assert import_data.get("success") is True, f"import failed: {import_data}"
        program_path = import_data["importedPrograms"][0]
        print(f"Imported and analyzed: {program_path}")

        print("\n=== Pick three analyzed function entry points ===")
        address_data = _tool_payload(
            await client.call_tool(
                "run-script",
                arguments={
                    "programPath": program_path,
                    "code": (
                        "addrs = []\n"
                        "for func in currentProgram.getFunctionManager().getFunctions(True):\n"
                        "    addrs.append(str(func.getEntryPoint()))\n"
                        "    if len(addrs) == 3:\n"
                        "        break\n"
                        "print('ANNOTATION_ADDRS=' + ','.join(addrs))\n"
                    ),
                    "timeoutSeconds": 60,
                },
            ),
            "run-script address discovery",
        )
        assert address_data.get("success") is True, f"address discovery failed: {address_data}"
        marker = "ANNOTATION_ADDRS="
        assert marker in address_data["stdout"], (
            f"unexpected stdout: {address_data['stdout']!r}"
        )
        addresses = address_data["stdout"].split(marker, 1)[1].split()[0].split(",")
        assert len(addresses) == 3, (
            "fixture analysis produced fewer than three function entry points: "
            f"{addresses!r}"
        )
        ordered = sorted(addresses, key=lambda address: int(address, 16))
        range_start, range_end = ordered[0], ordered[-1]

        print("\n=== Create three Note/Evidence bookmarks and two comments ===")
        bookmark_comments = [
            "blocked-checkin bookmark alpha",
            "blocked-checkin bookmark beta",
            "blocked-checkin bookmark gamma",
        ]
        for address, comment in zip(addresses, bookmark_comments):
            payload = _tool_payload(
                await client.call_tool(
                    "set-bookmark",
                    arguments={
                        "programPath": program_path,
                        "addressOrSymbol": address,
                        "type": "Note",
                        "category": "Evidence",
                        "comment": comment,
                    },
                ),
                f"set-bookmark {comment!r}",
            )
            assert payload.get("success") is True, f"set-bookmark failed: {payload}"

        comment_texts = [
            "blocked-checkin eol comment",
            "blocked-checkin pre comment",
        ]
        for address, comment_type, comment in zip(
            addresses, ("eol", "pre"), comment_texts
        ):
            payload = _tool_payload(
                await client.call_tool(
                    "set-comment",
                    arguments={
                        "programPath": program_path,
                        "addressOrSymbol": address,
                        "commentType": comment_type,
                        "comment": comment,
                    },
                ),
                f"set-comment {comment!r}",
            )
            assert payload.get("success") is True, f"set-comment failed: {payload}"
        print("✓ All acknowledged writes succeeded")

        print("\n=== Start a long run-script, then checkin while its transaction is open ===")
        script_task = asyncio.create_task(
            client.call_tool(
                "run-script",
                arguments={
                    "programPath": program_path,
                    "code": "import time\ntime.sleep(20)\nprint('script complete')",
                    "timeoutSeconds": 30,
                },
            )
        )
        try:
            # Let the run-script reach its sleep so its parent transaction is
            # definitely open when checkin starts.
            await asyncio.sleep(2.0)
            blocked = await client.call_tool(
                "checkin-program",
                arguments={
                    "programPath": program_path,
                    "message": "blocked checkin",
                    "keepCheckedOut": False,
                },
            )
            blocked_text = blocked.content[0].text if blocked.content else ""
            blocked_is_error = bool(getattr(blocked, "is_error", False))
        finally:
            script_result = await script_task

        assert blocked_is_error, (
            "INCONCLUSIVE: checkin-program did not return an error while "
            "run-script held its transaction (the transport may have "
            f"serialized the calls); it returned: {blocked_text!r}"
        )
        assert "a transaction is still open" in blocked_text, (
            "INCONCLUSIVE: transport serialized checkin after run-script; no "
            "blocked checkin occurred. checkin-program returned: "
            f"{blocked_text!r}"
        )
        print(f"✓ Checkin was refused: {blocked_text}")

        print("\n=== Verify annotations still readable after the blocker ends ===")
        await _assert_annotations_present(
            client,
            program_path,
            range_start,
            range_end,
            bookmark_comments,
            comment_texts,
            context="after the blocked checkin",
        )

        script_data = _tool_payload(script_result, "blocking run-script")
        assert script_data.get("success") is True, (
            f"blocking run-script failed: {script_data}"
        )
        assert script_data.get("timedOut") is False, (
            f"blocking script timed out: {script_data}"
        )
        assert "script complete" in script_data["stdout"], (
            f"blocking script did not complete: {script_data['stdout']!r}"
        )

        print("\n=== Retry checkin and verify the saved database ===")
        retry = _tool_payload(
            await client.call_tool(
                "checkin-program",
                arguments={
                    "programPath": program_path,
                    "message": "recovered checkin",
                    "keepCheckedOut": False,
                },
            ),
            "recovery checkin-program",
        )
        assert retry.get("success") is True, f"recovery checkin failed: {retry}"
        print(f"✓ Recovery checkin succeeded: {retry}")

        saved = await _dump_saved_annotations(client, program_path, ordered[2])
        saved_bookmarks = {
            (bookmark.get("type"), bookmark.get("category"), bookmark.get("comment"))
            for bookmark in saved.get("bookmarks", [])
        }
        for comment in bookmark_comments:
            assert ("Note", "Evidence", comment) in saved_bookmarks, (
                f"bookmark {comment!r} missing from the saved database: "
                f"{sorted(saved_bookmarks)}"
            )
        saved_comments = set(saved.get("comments", []))
        for comment in comment_texts:
            assert comment in saved_comments, (
                f"comment {comment!r} missing from the saved database: "
                f"{sorted(saved_comments)}"
            )
        print(f"✓ Saved database read-back: {saved}")

        print("\n=== Re-read after the successful cache release ===")
        await _assert_annotations_present(
            client,
            program_path,
            range_start,
            range_end,
            bookmark_comments,
            comment_texts,
            context="after the successful checkin",
        )

        print("\n=== Export the saved domain file to GZF ===")
        gzf_path = Path(f"/tmp/reva-blocked-checkin-{uuid.uuid4().hex}.gzf")
        try:
            export_data = _tool_payload(
                await client.call_tool(
                    "run-script",
                    arguments={
                        "programPath": program_path,
                        "code": (
                            "from java.io import File\n"
                            "from ghidra.util.task import TaskMonitor\n"
                            f"out = File({str(gzf_path)!r})\n"
                            "currentProgram.getDomainFile().packFile("
                            "out, TaskMonitor.DUMMY)\n"
                            "print('GZF_PATH=' + out.getAbsolutePath())\n"
                            "print('GZF_SIZE=' + str(out.length()))\n"
                        ),
                        "timeoutSeconds": 60,
                    },
                ),
                "GZF export run-script",
            )
            assert export_data.get("success") is True, (
                f"GZF export failed: {export_data}"
            )
            assert gzf_path.exists(), f"GZF was not written: {gzf_path}"
            assert gzf_path.stat().st_size > 0, f"GZF is empty: {gzf_path}"
            print(f"✓ GZF export: {gzf_path} ({gzf_path.stat().st_size} bytes)")
        finally:
            gzf_path.unlink(missing_ok=True)

    @pytest.mark.timeout(900)
    async def test_blocked_checkin_post_save_removal_retention(
        self, mcp_stdio_client_snapshot, isolated_workspace
    ):
        """A post-save checkin failure must retain the removal for a retry.

        Forces the exact save→checkin→mutation interleaving through the
        ProgramPersistenceUtil post-save seam: the seam removes a bookmark in a
        committed transaction immediately after save and before checkin. The
        first checkin must fail with "unsaved changes"; the retry must save the
        retained removal. The target must keep the two surviving bookmarks and
        lose the removed one, while the analysis baseline (created before any
        test write) must contain none of them.
        """
        client = mcp_stdio_client_snapshot
        gzf_path = (
            "/home/kaida/.cache/reva-big-run/grading/results/"
            "s4-f2-report-r3/s4-f2-report-r3-report-qwen-qwen3-8-27b-0000/gzf/"
            "88b0ee7273a91d92c3570dbc67896e15b53ca118d2b45e49a3489605cc26bf24.gzf"
        )
        if not Path(gzf_path).exists():
            pytest.skip(f"Panda GZF artifact not found: {gzf_path}")

        print("\n=== Import the preserved Panda GZF without analysis ===")
        import_data = _tool_payload(
            await client.call_tool(
                "import-file",
                arguments={
                    "path": gzf_path,
                    "destinationFolder": "/",
                    "analyzeAfterImport": False,
                },
            ),
            "import-file",
        )
        assert import_data.get("success") is True, f"import failed: {import_data}"
        program_path = import_data["importedPrograms"][0]
        print(f"Imported: {program_path}")

        print("\n=== Run default analyze-program so a baseline is created ===")
        analyze_data = _tool_payload(
            await client.call_tool(
                "analyze-program",
                arguments={"programPath": program_path, "waitSeconds": 120},
            ),
            "analyze-program",
        )
        assert analyze_data.get("success") is True, f"analysis failed: {analyze_data}"
        if analyze_data.get("status") == "running":
            job_id = analyze_data.get("jobId")
            assert job_id, f"running analysis without a jobId: {analyze_data!r}"
            analyze_data = await _poll_analysis_to_terminal(client, job_id)
            assert analyze_data.get("status") == "completed", (
                f"analysis did not complete: {analyze_data!r}"
            )
        print(f"Analysis completed: {analyze_data}")

        print("\n=== Resolve the program name and baseline path ===")
        name_data = _tool_payload(
            await client.call_tool(
                "run-script",
                arguments={
                    "programPath": program_path,
                    "code": "print('PROGRAM_NAME=' + currentProgram.getName())",
                    "timeoutSeconds": 60,
                },
            ),
            "run-script program name",
        )
        assert name_data.get("success") is True, f"name lookup failed: {name_data}"
        program_name = name_data["stdout"].split("PROGRAM_NAME=")[1].strip()
        baseline_path = f"/baseline/baseline-{program_name}"
        print(f"Baseline path: {baseline_path}")

        print("\n=== Pick three analyzed function entry addresses ===")
        addr_data = _tool_payload(
            await client.call_tool(
                "run-script",
                arguments={
                    "programPath": program_path,
                    "code": (
                        "addrs = []\n"
                        "for f in currentProgram.getFunctionManager().getFunctions(True):\n"
                        "    addrs.append(str(f.getEntryPoint()))\n"
                        "    if len(addrs) >= 3:\n"
                        "        break\n"
                        "print('ADDRS=' + ','.join(addrs))\n"
                    ),
                    "timeoutSeconds": 60,
                },
            ),
            "run-script address discovery",
        )
        assert addr_data.get("success") is True, f"address discovery failed: {addr_data}"
        addresses = addr_data["stdout"].split("ADDRS=")[1].strip().split(",")
        assert len(addresses) >= 3, f"expected at least 3 addresses: {addresses!r}"

        print("\n=== Create three Note/RaceRegression bookmarks ===")
        for index, address in enumerate(addresses[:3]):
            bookmark_data = _tool_payload(
                await client.call_tool(
                    "set-bookmark",
                    arguments={
                        "programPath": program_path,
                        "addressOrSymbol": address,
                        "type": "Note",
                        "category": "RaceRegression",
                        "comment": f"race regression bookmark {index}",
                    },
                ),
                f"set-bookmark {index}",
            )
            assert bookmark_data.get("success") is True, (
                f"set-bookmark {index} failed: {bookmark_data}"
            )
        print("✓ Three RaceRegression bookmarks created")

        print("\n=== Install the post-save removal seam ===")
        hook_data = _tool_payload(
            await client.call_tool(
                "run-script",
                arguments={
                    "programPath": program_path,
                    "code": (
                        "from reva.util import ProgramPersistenceUtil\n"
                        "from java.util.function import Consumer\n"
                        "from jpype import JImplements, JOverride\n"
                        "\n"
                        "@JImplements(Consumer)\n"
                        "class RemoveRaceRegression:\n"
                        "    @JOverride\n"
                        "    def accept(self, program):\n"
                        "        tx = program.startTransaction('post-save removal')\n"
                        "        try:\n"
                        "            bm = program.getBookmarkManager()\n"
                        "            for bookmark in bm.getBookmarksIterator():\n"
                        "                if (bookmark.getCategory() == 'RaceRegression'\n"
                        "                        and bookmark.getComment() == 'race regression bookmark 1'):\n"
                        "                    bm.removeBookmark(bookmark)\n"
                        "                    break\n"
                        "        finally:\n"
                        "            program.endTransaction(tx, True)\n"
                        "\n"
                        "ProgramPersistenceUtil.setPostSaveHookForTesting(\n"
                        "    RemoveRaceRegression())\n"
                        "print('HOOK_SET')\n"
                    ),
                    "timeoutSeconds": 60,
                },
            ),
            "run-script install hook",
        )
        assert hook_data.get("success") is True, f"hook install failed: {hook_data}"
        assert "HOOK_SET" in hook_data["stdout"], hook_data["stdout"]

        print("\n=== Capture the loaded ProgramPersistenceUtil protection domain ===")
        pd_data = _tool_payload(
            await client.call_tool(
                "run-script",
                arguments={
                    "programPath": program_path,
                    "code": (
                        "from java.lang import Class\n"
                        "cls = Class.forName('reva.util.ProgramPersistenceUtil')\n"
                        "location = cls.getProtectionDomain().getCodeSource().getLocation()\n"
                        "print('PD=' + str(location))\n"
                    ),
                    "timeoutSeconds": 60,
                },
            ),
            "run-script protection domain",
        )
        assert pd_data.get("success") is True, f"protection domain lookup failed: {pd_data}"
        protection_domain = pd_data["stdout"].split("PD=")[1].strip()
        print(f"✓ Protection domain: {protection_domain}")

        try:
            print("\n=== First checkin must fail with unsaved changes ===")
            blocked = await client.call_tool(
                "checkin-program",
                arguments={"programPath": program_path, "message": "race"},
            )
            blocked_text = blocked.content[0].text if blocked.content else ""
            blocked_is_error = bool(getattr(blocked, "is_error", False))
            assert blocked_is_error, (
                "expected a failed checkin; it returned: " + repr(blocked_text)
            )
            assert "unsaved changes" in blocked_text, (
                "expected 'unsaved changes' in the refusal: " + repr(blocked_text)
            )
            print(f"✓ First checkin refused: {blocked_text}")

            print("\n=== Reset the seam and retry the checkin ===")
            reset_data = _tool_payload(
                await client.call_tool(
                    "run-script",
                    arguments={
                        "programPath": program_path,
                        "code": (
                            "from reva.util import ProgramPersistenceUtil\n"
                            "ProgramPersistenceUtil.setPostSaveHookForTesting(None)\n"
                            "print('HOOK_RESET')\n"
                        ),
                        "timeoutSeconds": 60,
                    },
                ),
                "run-script reset hook",
            )
            assert reset_data.get("success") is True, f"hook reset failed: {reset_data}"
            assert "HOOK_RESET" in reset_data["stdout"], reset_data["stdout"]

            retry = _tool_payload(
                await client.call_tool(
                    "checkin-program",
                    arguments={"programPath": program_path, "message": "retry"},
                ),
                "retry checkin-program",
            )
            assert retry.get("success") is True, f"retry checkin failed: {retry}"
            print(f"✓ Retry checkin succeeded: {retry}")
        finally:
            # Always clear the seam so a failed assertion cannot leak it into
            # later tests sharing the same server process.
            await client.call_tool(
                "run-script",
                arguments={
                    "programPath": program_path,
                    "code": (
                        "from reva.util import ProgramPersistenceUtil\n"
                        "ProgramPersistenceUtil.setPostSaveHookForTesting(None)\n"
                    ),
                    "timeoutSeconds": 60,
                },
            )

        print("\n=== Dump the target and the baseline ===")
        target_dump = await _dump_saved_annotations(client, program_path, addresses[0])
        baseline_dump = await _dump_project_file_annotations(
            client, program_path, baseline_path
        )
        print(f"Target dump path: {program_path}")
        print(f"Baseline dump path: {baseline_path}")
        print(f"Baseline dump reported path: {baseline_dump.get('path')}")

        target_race = [
            bookmark
            for bookmark in target_dump.get("bookmarks", [])
            if bookmark.get("category") == "RaceRegression"
        ]
        baseline_race = [
            bookmark
            for bookmark in baseline_dump.get("bookmarks", [])
            if bookmark.get("category") == "RaceRegression"
        ]

        removed_address = addresses[1]
        removed_comment = "race regression bookmark 1"
        expected_survivors = {
            (addresses[0], "race regression bookmark 0"),
            (addresses[2], "race regression bookmark 2"),
        }
        actual_survivors = {
            (bookmark.get("address"), bookmark.get("comment"))
            for bookmark in target_race
        }

        assert removed_address not in {
            bookmark.get("address") for bookmark in target_race
        }, (
            f"the removed bookmark at {removed_address} was resurrected: "
            f"{target_race!r}"
        )
        assert removed_comment not in {
            bookmark.get("comment") for bookmark in target_race
        }, f"the removed bookmark comment was resurrected: {target_race!r}"
        assert actual_survivors == expected_survivors, (
            "target must keep exactly the two surviving RaceRegression bookmarks: "
            f"expected {expected_survivors!r}, got {actual_survivors!r}"
        )
        assert len(baseline_race) == 0, (
            "the analysis baseline must contain no RaceRegression bookmarks: "
            f"{baseline_race!r}"
        )
        print(
            f"✓ Removed RaceRegression bookmark absent: "
            f"{removed_address} / {removed_comment}"
        )
        print(f"✓ Target RaceRegression survivors: {sorted(actual_survivors)}")
        print(f"✓ Baseline RaceRegression bookmarks: {baseline_race}")
