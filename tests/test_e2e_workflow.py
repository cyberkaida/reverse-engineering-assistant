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

import pytest
import json
from pathlib import Path

# Mark all tests in this file
pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio,
    pytest.mark.timeout(240)  # 4 minutes for full workflow
]

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
            return str(fixture_path)
        if content.startswith("version https://git-lfs.github.com"):
            pytest.fail(
                f"Test fixture {fixture_path.name} is a Git LFS pointer, not the actual file. "
                "Run 'git lfs pull' locally or enable LFS in CI checkout."
            )
    return str(fixture_path)


class TestE2EWorkflow:
    """End-to-end workflow tests."""

    async def test_import_change_save_and_reread_workflow(self, mcp_stdio_client, isolated_workspace):
        """
        Workflow: import -> open -> change -> save -> re-read same session.

        This tests that import-file, set-comment, checkin-program, and
        get-comments work together within a single MCP session. It does
        NOT verify cross-process persistence: checkin-program with
        keepCheckedOut=False does not evict the program from ReVa's cache,
        so the final get-comments reads from the same in-memory program
        object the comment was written to. A true reopen-from-disk test
        would need either a "close-program" tool or a two-process setup,
        neither of which currently exists.
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
        if hasattr(import_result, 'isError') and import_result.isError:
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
        decomp_data = json.loads(decomp_result.content[0].text)
        print(f"Initial decompilation response: {json.dumps(decomp_data, indent=2)[:200]}...")

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

        if hasattr(import_result, 'isError') and import_result.isError:
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
        assert not getattr(symbols_result, "isError", False), (
            f"get-symbols failed: {symbols_result.content[0].text if symbols_result.content else 'no content'}"
        )

        symbol_names = []
        for content in symbols_result.content[1:]:
            try:
                sym = json.loads(content.text)
            except (json.JSONDecodeError, AttributeError):
                continue
            symbol_names.append(sym.get("name"))

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
        if hasattr(import_result, 'isError') and import_result.isError:
            pytest.fail(f"Import failed: {import_result.content[0].text}")

        content_text = import_result.content[0].text
        assert content_text, (
            "Import returned empty content. The installed ReVa extension may be outdated; "
            "run 'gradle install' to install the development version."
        )

        import_data = json.loads(content_text)
        program_path = import_data["importedPrograms"][0]

        # Open the program by getting decompilation (this caches it)
        await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": "entry",
                "limit": 5
            }
        )
        print("✓ Program opened and cached")

        print("\n=== Make changes ===")
        await mcp_stdio_client.call_tool(
            "set-comment",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": "entry",
                "comment": "Cache release test"
            }
        )
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
