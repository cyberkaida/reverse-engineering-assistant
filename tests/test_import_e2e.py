"""
End-to-end tests for the import-file MCP tool.

Tests archive import, fat Mach-O slice extraction, progress tracking,
and new response fields from PR #241.

Test Fixtures:
- test_archive.zip: Contains test_arm64, test_x86_64, and test_fat_binary
- test_fat_binary: Fat Mach-O with arm64 + x86_64 slices
- test_arm64, test_x86_64: Single-architecture binaries
"""

import pytest
import json
import re
from pathlib import Path

# Mark all tests in this file
pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio(loop_scope="session"),
    pytest.mark.timeout(240)  # 4 minutes for full workflow
]

# Path to test fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def validate_fixture(fixture_name: str):
    """Validate fixture exists and is not an LFS pointer.

    Skips test if fixture is missing, fails if it's an LFS pointer file.
    Returns the fixture path as a string if valid.
    """
    fixture_path = FIXTURES_DIR / fixture_name
    if not fixture_path.exists():
        pytest.skip(f"Test fixture not found: {fixture_path}")

    # Check if it's an LFS pointer file (small text file starting with "version")
    file_size = fixture_path.stat().st_size
    if file_size < 200:  # LFS pointers are ~130 bytes
        try:
            content = fixture_path.read_text()
            if content.startswith("version https://git-lfs.github.com"):
                pytest.fail(
                    f"Test fixture {fixture_name} is a Git LFS pointer, not the actual file. "
                    "Run 'git lfs pull' locally or enable LFS in CI checkout."
                )
        except UnicodeDecodeError:
            pass  # Binary file, not a pointer

    return str(fixture_path)


class TestArchiveImport:
    """Tests for importing zip archives containing multiple binaries."""

    async def test_import_zip_archive(self, mcp_stdio_client, isolated_workspace):
        """
        Import a zip archive containing multiple binaries.

        The archive contains 3 source files (arm64, x86_64, fat binary), but
        BatchInfo counts each fat Mach-O slice as its own discovered file (the
        fat container itself is not counted), so filesDiscovered == 4:
        test_arm64, test_x86_64, and the fat binary's arm64 + x86_64 slices.
        Each discovered file imports as one program, so exactly 4 programs.
        """
        archive_path = validate_fixture("test_archive.zip")

        print(f"\n=== Importing archive: {archive_path} ===")
        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": archive_path,
                "enableVersionControl": False
            }
        )

        assert result is not None
        assert hasattr(result, 'content'), "Result missing content attribute"
        assert len(result.content) > 0, "Result content is empty"

        if hasattr(result, 'isError') and result.isError:
            error_text = result.content[0].text if result.content else "Unknown error"
            pytest.fail(f"Import failed: {error_text}")

        content_text = result.content[0].text
        data = json.loads(content_text)
        print(f"Import response: {json.dumps(data, indent=2)}")

        assert data.get("success") is True, "Import should succeed"

        # BatchInfo counts each fat slice separately: arm64 + x86_64 + 2 slices = 4
        files_discovered = data.get("filesDiscovered", 0)
        assert files_discovered == 4, f"Should discover exactly 4 files, got {files_discovered}"

        # Each discovered file imports as exactly one program
        imported_programs = data.get("importedPrograms", [])
        assert len(imported_programs) == 4, \
            f"Should have exactly 4 imported programs, got {len(imported_programs)}: {imported_programs}"

        print(f"✓ Archive imported: {files_discovered} discovered, {len(imported_programs)} programs imported")
        print(f"✓ Programs: {imported_programs}")

    async def test_import_archive_response_fields(self, mcp_stdio_client, isolated_workspace):
        """Verify all expected response fields are present when importing an archive."""
        archive_path = validate_fixture("test_archive.zip")

        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": archive_path,
                "enableVersionControl": False
            }
        )

        assert result is not None
        assert not getattr(result, "isError", False), (
            f"Import failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)
        assert data.get("success") is True, f"Import should succeed: {data}"

        # Required fields returned by the import-file tool
        required_fields = [
            "success",
            "importedFrom",
            "destinationFolder",
            "filesDiscovered",
            "filesImported",
            "importedPrograms",
        ]

        for field in required_fields:
            assert field in data, f"Missing required field: {field}"
            print(f"✓ Field present: {field} = {data[field]}")


class TestFatMachoBinaryImport:
    """Tests for importing fat Mach-O binaries with multiple architecture slices."""

    async def test_import_fat_binary_extracts_slices(self, mcp_stdio_client, isolated_workspace):
        """
        Import a fat Mach-O binary and verify both slices are extracted.

        The fat binary contains arm64 and x86_64 architectures.
        Expected: 2 programs imported (one per slice).
        """
        fat_binary_path = validate_fixture("test_fat_binary")

        print(f"\n=== Importing fat binary: {fat_binary_path} ===")
        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": fat_binary_path,
                "enableVersionControl": False
            }
        )

        assert result is not None
        assert hasattr(result, 'content'), "Result missing content attribute"

        if hasattr(result, 'isError') and result.isError:
            error_text = result.content[0].text if result.content else "Unknown error"
            pytest.fail(f"Import failed: {error_text}")

        data = json.loads(result.content[0].text)
        print(f"Import response: {json.dumps(data, indent=2)}")

        assert data.get("success") is True, "Import should succeed"

        # Verify both architectures are represented in importedPrograms
        imported_programs = data.get("importedPrograms", [])
        # Fat binary should produce 2 programs (arm64 + x86_64)
        assert len(imported_programs) == 2, f"Fat binary should produce 2 programs, got {len(imported_programs)}"

        # Check architecture names (Ghidra uses various naming conventions)
        programs_str = " ".join(imported_programs).lower()
        has_arm = "arm" in programs_str or "aarch" in programs_str
        # Use specific x86 patterns to avoid matching "aarch64"
        x86_markers = ("x86", "x86_64", "x86-64", "amd64", "i386", "i686")
        has_x86 = any(marker in programs_str for marker in x86_markers)

        print(f"✓ Fat binary slices extracted: {imported_programs}")
        print(f"  Has ARM: {has_arm}, Has x86: {has_x86}")

        assert has_arm and has_x86, "Fat binary should have both ARM and x86 architectures"


class TestImportedFilesInProject:
    """Tests verifying imported files appear correctly in list-project-files."""

    async def test_archive_files_appear_in_project(self, mcp_stdio_client_isolated, isolated_workspace):
        """
        After importing an archive, verify all programs appear in list-project-files.

        This tests the integration between import-file and list-project-files,
        ensuring imported programs are accessible for further analysis.
        """
        archive_path = validate_fixture("test_archive.zip")

        # First, import the archive
        import_result = await mcp_stdio_client_isolated.call_tool(
            "import-file",
            arguments={
                "path": archive_path,
                "enableVersionControl": False
            }
        )

        assert import_result is not None
        import_data = json.loads(import_result.content[0].text)
        assert import_data.get("success") is True, "Import should succeed"

        imported_programs = import_data.get("importedPrograms", [])
        print(f"\n=== Imported {len(imported_programs)} programs ===")
        for prog in imported_programs:
            print(f"  - {prog}")

        # Now verify files appear in list-project-files
        list_result = await mcp_stdio_client_isolated.call_tool(
            "list-project-files",
            arguments={"folderPath": "/", "recursive": True}
        )

        assert list_result is not None
        assert hasattr(list_result, 'content'), "list-project-files should return content"

        # list-project-files returns one JSON content item with:
        #   {folderPath, folderName, isRecursive, itemCount, items: [...]}
        print(f"\n=== Project files response ===")
        metadata = json.loads(list_result.content[0].text)
        item_count = metadata.get("itemCount", 0)
        file_entries = metadata.get("items", [])
        print(f"Metadata: {json.dumps({k: v for k, v in metadata.items() if k != 'items'}, indent=2)}")
        print(f"Item count from metadata: {item_count}")
        for i, entry in enumerate(file_entries, 1):
            print(f"  [{i}] {entry}")

        # Verify we got files matching the import count
        assert item_count >= len(imported_programs), \
            f"Should have at least {len(imported_programs)} items, got {item_count}"

        # Identity check: every imported program must appear in the listing by path.
        listed_paths = [e.get("programPath") for e in file_entries]
        for prog in imported_programs:
            assert prog in listed_paths, (
                f"Imported program {prog!r} not in listing: {listed_paths}"
            )

        print(f"\n✓ Project listing shows {item_count} items after importing {len(imported_programs)} programs")

    async def test_fat_binary_slices_appear_separately(self, mcp_stdio_client_isolated, isolated_workspace):
        """
        After importing a fat binary, verify both architecture slices appear in project.

        Fat Mach-O binaries produce multiple programs (one per architecture).
        This verifies each slice is independently accessible.
        """
        fat_binary_path = validate_fixture("test_fat_binary")

        # Import the fat binary
        import_result = await mcp_stdio_client_isolated.call_tool(
            "import-file",
            arguments={
                "path": fat_binary_path,
                "enableVersionControl": False
            }
        )

        assert import_result is not None
        import_data = json.loads(import_result.content[0].text)
        assert import_data.get("success") is True, "Import should succeed"

        imported_programs = import_data.get("importedPrograms", [])
        assert len(imported_programs) == 2, f"Fat binary should produce 2 programs, got {len(imported_programs)}"

        print(f"\n=== Imported fat binary slices ===")
        for prog in imported_programs:
            print(f"  - {prog}")

        # Verify files appear in list-project-files
        list_result = await mcp_stdio_client_isolated.call_tool(
            "list-project-files",
            arguments={"folderPath": "/", "recursive": True}
        )

        assert list_result is not None

        # list-project-files returns one JSON content item with itemCount + items.
        metadata = json.loads(list_result.content[0].text)
        item_count = metadata.get("itemCount", 0)
        entries = metadata.get("items", [])

        print(f"\n=== Project files after fat binary import ===")
        print(f"Metadata: {json.dumps({k: v for k, v in metadata.items() if k != 'items'}, indent=2)}")
        print(f"Item count: {item_count}")

        # Verify we have 2 files (one per architecture)
        assert item_count >= 2, f"Should have at least 2 files (one per arch), got {item_count}"

        # Identity check: every imported slice must appear in the listing by path.
        listed_paths = [e.get("programPath") for e in entries]
        for prog in imported_programs:
            assert prog in listed_paths, (
                f"Imported slice {prog!r} not in listing: {listed_paths}"
            )

        for i, entry in enumerate(entries, 1):
            print(f"  [{i}] {entry}")

        print(f"\n✓ Fat binary slices appear in project ({item_count} items)")


class TestSingleBinaryImport:
    """Tests for importing single-architecture binaries."""

    async def test_import_single_arm64_binary(self, mcp_stdio_client, isolated_workspace):
        """Import a single ARM64 binary."""
        binary_path = validate_fixture("test_arm64")

        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": binary_path,
                "enableVersionControl": False
            }
        )

        assert result is not None
        data = json.loads(result.content[0].text)

        assert data.get("success") is True
        imported = data.get("importedPrograms", [])
        assert len(imported) == 1, f"Should import exactly 1 program, got {len(imported)}"

        print(f"✓ Single ARM64 binary imported: {imported}")

    async def test_import_single_x86_64_binary(self, mcp_stdio_client, isolated_workspace):
        """Import a single x86_64 binary."""
        binary_path = validate_fixture("test_x86_64")

        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": binary_path,
                "enableVersionControl": False
            }
        )

        assert result is not None
        data = json.loads(result.content[0].text)

        assert data.get("success") is True
        imported = data.get("importedPrograms", [])
        assert len(imported) == 1, f"Should import exactly 1 program, got {len(imported)}"

        print(f"✓ Single x86_64 binary imported: {imported}")


class TestImportWithAnalysis:
    """Tests for the analyzeAfterImport parameter."""

    async def test_import_with_analysis_enabled(self, mcp_stdio_client, isolated_workspace):
        """
        Import with analyzeAfterImport=true and verify analysis runs.

        Expected: analyzedPrograms field populated, filesAnalyzed > 0
        """
        binary_path = validate_fixture("test_arm64")

        print(f"\n=== Importing with analysis: {binary_path} ===")
        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": binary_path,
                "enableVersionControl": False,
                "analyzeAfterImport": True
            }
        )

        assert result is not None
        data = json.loads(result.content[0].text)
        print(f"Import response: {json.dumps(data, indent=2)}")

        assert data.get("success") is True

        # When analysis requested, should have analyzedPrograms
        assert "analyzedPrograms" in data, "Should have analyzedPrograms when analyzeAfterImport=true"

        analyzed = data.get("analyzedPrograms", [])
        assert len(analyzed) > 0, "Should have analyzed at least one program"

        files_analyzed = data.get("filesAnalyzed", 0)
        assert files_analyzed > 0, "filesAnalyzed should be > 0"
        assert files_analyzed == len(analyzed), "filesAnalyzed should match analyzedPrograms length"

        print(f"✓ Analysis completed: {files_analyzed} programs analyzed")

    async def test_analysis_discovers_functions(self, mcp_stdio_client, isolated_workspace):
        """
        Verify that analysis actually discovers functions in the imported binary.

        This confirms the full import-analyze-query workflow works end-to-end.
        """
        binary_path = validate_fixture("test_arm64")

        # Import with analysis
        print(f"\n=== Importing and analyzing: {binary_path} ===")
        import_result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": binary_path,
                "enableVersionControl": False,
                "analyzeAfterImport": True
            }
        )

        assert import_result is not None
        import_data = json.loads(import_result.content[0].text)
        assert import_data.get("success") is True, "Import should succeed"

        # Get the program path from import result
        imported_programs = import_data.get("importedPrograms", [])
        assert len(imported_programs) > 0, "Should have imported at least one program"
        program_path = imported_programs[0]
        print(f"Imported program: {program_path}")

        # Query functions in the analyzed program
        print(f"\n=== Querying functions in {program_path} ===")
        functions_result = await mcp_stdio_client.call_tool(
            "get-functions",
            arguments={
                "programPath": program_path,
                "maxCount": 50
            }
        )

        assert functions_result is not None
        assert hasattr(functions_result, 'content'), "get-functions should return content"

        # Single JSON content item: {totalCount, actualCount, ..., functions: [...]}
        payload = json.loads(functions_result.content[0].text)
        function_count = payload.get("totalCount", payload.get("actualCount", 0))
        functions = payload.get("functions", [])

        print(f"Functions discovered: {function_count}")
        if functions:
            print("Sample functions:")
            for func in functions[:5]:
                name = func.get("name", "unknown")
                addr = func.get("address", "unknown")
                print(f"  - {name} @ {addr}")

        # test_arm64 is built from add+multiply+main+printf. A full Ghidra analysis
        # discovers all four (Mach-O preserves leading underscores: _add, _multiply;
        # main collapses into the entry-point function). analyzeAfterImport=true
        # must match what an explicit analyze-program forceFullAnalysis pass would
        # produce -- otherwise the import path is silently doing a partial analysis.
        function_names = [f.get("name") for f in functions]
        assert function_count >= 4, (
            f"Analysis should discover at least entry, _printf, _add, _multiply "
            f"in {binary_path}; got count={function_count}, names={function_names}"
        )
        assert any(n == "entry" for n in function_names), (
            f"Expected 'entry' function in {binary_path}; got names={function_names}"
        )
        assert any("printf" in (n or "") for n in function_names), (
            f"Expected a printf-related function (import thunk) in {binary_path}; "
            f"got names={function_names}"
        )
        assert any(n == "_add" for n in function_names), (
            f"Expected '_add' function in {binary_path}; got names={function_names}. "
            "If only entry/printf appear, the import-time analysis is not running a full "
            "pass (likely missing initializeOptions/reAnalyzeAll)."
        )
        assert any(n == "_multiply" for n in function_names), (
            f"Expected '_multiply' function in {binary_path}; got names={function_names}"
        )

        print(f"\n✓ Analysis correctly discovered {function_count} functions: {function_names}")

    async def test_fat_binary_analysis_discovers_functions_in_both_slices(
        self, mcp_stdio_client, isolated_workspace
    ):
        """
        Import and analyze a fat binary, verify functions discovered in both slices.

        This ensures multi-architecture binaries are properly analyzed.
        """
        fat_binary_path = validate_fixture("test_fat_binary")

        # Import with analysis
        print(f"\n=== Importing and analyzing fat binary: {fat_binary_path} ===")
        import_result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": fat_binary_path,
                "enableVersionControl": False,
                "analyzeAfterImport": True
            }
        )

        assert import_result is not None
        import_data = json.loads(import_result.content[0].text)
        assert import_data.get("success") is True, "Import should succeed"

        imported_programs = import_data.get("importedPrograms", [])
        assert len(imported_programs) == 2, \
            f"Fat binary should produce 2 programs, got {len(imported_programs)}"

        # Query functions in each architecture slice
        for program_path in imported_programs:
            print(f"\n=== Querying functions in {program_path} ===")

            functions_result = await mcp_stdio_client.call_tool(
                "get-functions",
                arguments={
                    "programPath": program_path,
                    "maxCount": 20
                }
            )

            assert functions_result is not None

            payload = json.loads(functions_result.content[0].text)
            function_count = payload.get("totalCount", payload.get("actualCount", 0))
            functions = payload.get("functions", [])

            print(f"  Functions in {program_path}: {function_count}")
            if functions:
                for func in functions[:3]:
                    print(f"    - {func.get('name', 'unknown')} @ {func.get('address', 'unknown')}")

            assert function_count > 0, \
                f"Each slice should have at least one function, got {function_count} in {program_path}"

        print(f"\n✓ Both architecture slices analyzed correctly")

    async def test_import_without_analysis(self, mcp_stdio_client, isolated_workspace):
        """
        Import with analyzeAfterImport=false (overriding default=true) and verify no analysis.

        Expected: analyzedPrograms field NOT present
        """
        binary_path = validate_fixture("test_arm64")

        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": binary_path,
                "enableVersionControl": False,
                "analyzeAfterImport": False
            }
        )

        assert result is not None
        data = json.loads(result.content[0].text)

        assert data.get("success") is True

        # When analysis not requested, should NOT have analyzedPrograms
        assert "analyzedPrograms" not in data, "Should NOT have analyzedPrograms when analyzeAfterImport=false"

        print("✓ No analysis performed as expected")


class TestImportResponseFields:
    """Tests verifying all new response fields from PR #241."""

    async def test_all_response_fields_present(self, mcp_stdio_client, isolated_workspace):
        """Verify all expected response fields are present."""
        binary_path = validate_fixture("test_arm64")

        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": binary_path,
                "enableVersionControl": False
            }
        )

        assert result is not None
        assert not getattr(result, "isError", False), (
            f"Import failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)
        assert data.get("success") is True, f"Import should succeed: {data}"

        # Core fields that should always be present
        required_fields = [
            "success",
            "importedFrom",
            "destinationFolder",
            "filesDiscovered",
            "filesImported",
            "importedPrograms",
        ]

        for field in required_fields:
            assert field in data, f"Missing required field: {field}"
            print(f"✓ {field}: {data[field]}")

        # Optional/conditional fields - just log their presence
        optional_fields = [
            "message",
            "filesAddedToVersionControl",
            "filesAnalyzed",
        ]

        for field in optional_fields:
            if field in data:
                print(f"  {field}: {data[field]}")

    async def test_path_handling_parameters_work(self, mcp_stdio_client, isolated_workspace):
        """stripLeadingPath/stripAllContainerPath visibly change project paths.

        Path semantics (ProjectToolProvider.fsrlToPath, mirroring Ghidra's
        ImportBatchTask):
        - stripLeadingPath=True drops the source file's directory components,
          so project paths start at the archive name; False keeps them, so the
          source directory (.../tests/fixtures/...) appears in the path.
        - stripAllContainerPath=True flattens interior container paths, so the
          fat binary's slices lose their "test_fat_binary" component.
        Project names are sanitized ('/' becomes '_'), so path components show
        up as underscore-joined segments of a flat name, not nested folders.
        These effects are only observable with a container input, hence the
        archive fixture rather than a plain single binary.
        """
        archive_path = validate_fixture("test_archive.zip")

        default_result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": archive_path,
                "enableVersionControl": False,
                "analyzeAfterImport": False,
                "stripLeadingPath": True,
                "stripAllContainerPath": False,
            }
        )
        assert not getattr(default_result, "isError", False), (
            f"Import failed: {default_result.content[0].text if default_result.content else 'no content'}"
        )
        default_data = json.loads(default_result.content[0].text)
        assert default_data.get("success") is True, f"Import should succeed: {default_data}"
        default_paths = default_data.get("importedPrograms", [])
        assert len(default_paths) == 4, f"Expected 4 programs, got {default_paths}"
        # Leading source directories stripped: paths start at the archive name
        # (a duplicate-name counter suffix may follow on a shared project).
        assert all(p.startswith("/test_archive.zip") for p in default_paths), default_paths
        # Interior container path kept: both fat slices carry the fat binary component.
        assert sum("test_fat_binary" in p for p in default_paths) == 2, default_paths

        stripped_result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": archive_path,
                "enableVersionControl": False,
                "analyzeAfterImport": False,
                "stripLeadingPath": False,
                "stripAllContainerPath": True,
            }
        )
        assert not getattr(stripped_result, "isError", False), (
            f"Import failed: {stripped_result.content[0].text if stripped_result.content else 'no content'}"
        )
        stripped_data = json.loads(stripped_result.content[0].text)
        assert stripped_data.get("success") is True, f"Import should succeed: {stripped_data}"
        stripped_paths = stripped_data.get("importedPrograms", [])
        assert len(stripped_paths) == 4, f"Expected 4 programs, got {stripped_paths}"
        # Leading path kept: the fixture directory appears in every project path.
        assert all("fixtures" in p for p in stripped_paths), stripped_paths
        assert not any(p.startswith("/test_archive.zip") for p in stripped_paths), stripped_paths
        # Interior container path flattened: no slice keeps the fat binary component.
        assert not any("test_fat_binary" in p for p in stripped_paths), stripped_paths

        print(f"✓ stripLeadingPath=True, stripAllContainerPath=False: {default_paths}")
        print(f"✓ stripLeadingPath=False, stripAllContainerPath=True: {stripped_paths}")


class TestImportErrorHandling:
    """Tests for import error handling."""

    async def test_import_nonexistent_file(self, mcp_stdio_client, isolated_workspace):
        """Verify proper error response for non-existent file.

        The server must signal failure unambiguously: either isError=True with
        a non-empty message, or success=False JSON, or a non-JSON error text
        body. The one outcome we reject is a JSON success=True response,
        which would indicate the import silently succeeded for a path that
        does not exist.
        """
        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": "/nonexistent/path/to/file.bin",
                "enableVersionControl": False
            }
        )

        assert result is not None, "Server returned no result"
        assert result.content and result.content[0].text, (
            f"Error response must include a non-empty content body; got {result}"
        )
        body = result.content[0].text

        if getattr(result, "isError", False):
            # MCP error response is acceptable; the body is the error message.
            return

        # Non-error response: must be JSON success=False, NOT success=True.
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            # Non-JSON error text from the tool is also acceptable as a
            # "this clearly didn't succeed" signal; just confirm it isn't
            # an empty placeholder.
            assert body.strip(), "Non-JSON error body must not be whitespace-only"
            return
        assert data.get("success") is False, (
            f"Import of nonexistent file must fail; got success={data.get('success')!r}, "
            f"data={data}"
        )


class TestImportProgressMessages:
    """Tests verifying progress message fields are correctly populated."""

    async def test_import_response_contains_message(self, mcp_stdio_client, isolated_workspace):
        """
        Verify the import response includes a human-readable message field.

        The message should summarize the import operation results.
        """
        binary_path = validate_fixture("test_arm64")

        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": binary_path,
                "enableVersionControl": False
            }
        )

        assert result is not None
        data = json.loads(result.content[0].text)
        assert data.get("success") is True, "Import should succeed"

        # Verify message field is present and meaningful
        assert "message" in data, "Response should include 'message' field"
        message = data["message"]

        # Message must state the actual counts in the tool's completion
        # phrasing ("Import completed. N of M files imported..."). A bare
        # substring digit check could match digits from file paths instead.
        assert "Import completed" in message or "imported" in message.lower(), \
            f"Message should mention import completion: {message}"
        files_imported = data.get("filesImported", 0)
        assert re.search(rf"\b{files_imported} of \d+ files imported\b", message), (
            f"Message should state '{files_imported} of <total> files imported': {message}"
        )

        print(f"✓ Import message: {message}")

    async def test_archive_import_message_shows_counts(self, mcp_stdio_client, isolated_workspace):
        """
        Verify archive import message shows discovered and imported file counts.

        When importing an archive with multiple files, the message should
        accurately reflect the number of files processed.
        """
        archive_path = validate_fixture("test_archive.zip")

        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": archive_path,
                "enableVersionControl": False
            }
        )

        assert result is not None
        data = json.loads(result.content[0].text)
        assert data.get("success") is True, "Import should succeed"

        # Verify counts are present
        files_discovered = data.get("filesDiscovered", 0)
        files_imported = data.get("filesImported", 0)
        imported_programs = len(data.get("importedPrograms", []))

        assert files_discovered >= 3, f"Should discover at least 3 files, got {files_discovered}"
        assert files_imported >= 3, f"Should import at least 3 files, got {files_imported}"

        # Verify message states the counts in the tool's completion phrasing
        # ("Import completed. N of M files imported...")
        message = data.get("message", "")
        assert re.search(
            rf"\b{files_imported} of {files_discovered} files imported\b", message
        ), (
            f"Message should state '{files_imported} of {files_discovered} "
            f"files imported': {message}"
        )

        print(f"✓ Archive import message: {message}")
        print(f"  Discovered: {files_discovered}, Imported: {files_imported}, Programs: {imported_programs}")

    async def test_import_with_analysis_message_shows_analysis_count(
        self, mcp_stdio_client, isolated_workspace
    ):
        """
        Verify import with analysis shows analysis count in message.

        When analyzeAfterImport=true, the message should mention how many
        files were analyzed.
        """
        binary_path = validate_fixture("test_arm64")

        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": binary_path,
                "enableVersionControl": False,
                "analyzeAfterImport": True
            }
        )

        assert result is not None
        data = json.loads(result.content[0].text)
        assert data.get("success") is True, "Import should succeed"

        # Verify analysis was performed
        analyzed_count = data.get("filesAnalyzed", 0)
        assert analyzed_count > 0, "Should have analyzed at least one file"

        # Verify message states the analysis count in the tool's phrasing
        # (", N analyzed")
        message = data.get("message", "")
        assert re.search(rf"\b{analyzed_count} analyzed\b", message), \
            f"Message should state '{analyzed_count} analyzed' when analyzeAfterImport=true: {message}"

        print(f"✓ Import with analysis message: {message}")
        print(f"  Files analyzed: {analyzed_count}")
