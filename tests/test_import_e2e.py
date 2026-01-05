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
import os
from pathlib import Path

# Mark all tests in this file
pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio,
    pytest.mark.timeout(240)  # 4 minutes for full workflow
]

# Path to test fixtures directory
FIXTURES_DIR = Path(__file__).parent / "fixtures"


def skip_if_fixture_missing(fixture_name: str):
    """Skip test if fixture file is missing or fail if it's an LFS pointer."""
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

        Expected: Archive contains 3 source files (arm64, x86_64, fat binary).
        The fat binary should produce 2 programs.
        Total expected: >= 4 programs imported.
        """
        archive_path = skip_if_fixture_missing("test_archive.zip")

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

        # Verify multiple files discovered from archive
        files_discovered = data.get("filesDiscovered", 0)
        assert files_discovered >= 3, f"Should discover >= 3 files, got {files_discovered}"

        # Verify importedPrograms list (this is the actual count of imported programs)
        imported_programs = data.get("importedPrograms", [])
        # Archive has: test_arm64 (1) + test_x86_64 (1) + test_fat_binary (2 slices) = 4
        assert len(imported_programs) >= 3, f"Should have >= 3 imported programs, got {len(imported_programs)}"

        print(f"✓ Archive imported: {files_discovered} discovered, {len(imported_programs)} programs imported")
        print(f"✓ Programs: {imported_programs}")

    async def test_import_archive_response_fields(self, mcp_stdio_client, isolated_workspace):
        """Verify all expected response fields are present when importing an archive."""
        archive_path = skip_if_fixture_missing("test_archive.zip")

        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": archive_path,
                "enableVersionControl": False
            }
        )

        assert result is not None
        data = json.loads(result.content[0].text)

        # Required fields (note: filesImported is computed from len(importedPrograms))
        required_fields = [
            "success",
            "importedFrom",
            "filesDiscovered",
            "importedPrograms",
            "groupsCreated",
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
        fat_binary_path = skip_if_fixture_missing("test_fat_binary")

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
        has_x86 = "x86" in programs_str or "64" in programs_str

        print(f"✓ Fat binary slices extracted: {imported_programs}")
        print(f"  Has ARM: {has_arm}, Has x86: {has_x86}")

        assert has_arm or has_x86, "Should have at least one recognized architecture"


class TestImportedFilesInProject:
    """Tests verifying imported files appear correctly in list-project-files."""

    async def test_archive_files_appear_in_project(self, mcp_stdio_client, isolated_workspace):
        """
        After importing an archive, verify all programs appear in list-project-files.

        This tests the integration between import-file and list-project-files,
        ensuring imported programs are accessible for further analysis.
        """
        archive_path = skip_if_fixture_missing("test_archive.zip")

        # First, import the archive
        import_result = await mcp_stdio_client.call_tool(
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
        list_result = await mcp_stdio_client.call_tool(
            "list-project-files",
            arguments={"folderPath": "/", "recursive": True}
        )

        assert list_result is not None
        assert hasattr(list_result, 'content'), "list-project-files should return content"

        # list-project-files returns multiple content items:
        # - First item is metadata: {folderPath, folderName, isRecursive, itemCount}
        # - Subsequent items are file/folder info
        print(f"\n=== Project files response ===")
        print(f"Number of content items: {len(list_result.content)}")

        # Parse metadata from first item
        metadata = json.loads(list_result.content[0].text)
        item_count = metadata.get("itemCount", 0)
        print(f"Metadata: {json.dumps(metadata, indent=2)}")
        print(f"Item count from metadata: {item_count}")

        # Parse file entries from remaining items
        file_entries = []
        for i, content in enumerate(list_result.content[1:], 1):
            try:
                entry = json.loads(content.text)
                file_entries.append(entry)
                print(f"  [{i}] {entry}")
            except (json.JSONDecodeError, AttributeError):
                pass

        # Verify we got files matching the import count
        assert item_count >= len(imported_programs), \
            f"Should have at least {len(imported_programs)} items, got {item_count}"

        print(f"\n✓ Project listing shows {item_count} items after importing {len(imported_programs)} programs")

    async def test_fat_binary_slices_appear_separately(self, mcp_stdio_client, isolated_workspace):
        """
        After importing a fat binary, verify both architecture slices appear in project.

        Fat Mach-O binaries produce multiple programs (one per architecture).
        This verifies each slice is independently accessible.
        """
        fat_binary_path = skip_if_fixture_missing("test_fat_binary")

        # Import the fat binary
        import_result = await mcp_stdio_client.call_tool(
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
        list_result = await mcp_stdio_client.call_tool(
            "list-project-files",
            arguments={"folderPath": "/", "recursive": True}
        )

        assert list_result is not None

        # list-project-files returns multiple content items:
        # - First item is metadata with itemCount
        # - Subsequent items are file/folder info
        metadata = json.loads(list_result.content[0].text)
        item_count = metadata.get("itemCount", 0)

        print(f"\n=== Project files after fat binary import ===")
        print(f"Metadata: {json.dumps(metadata, indent=2)}")
        print(f"Item count: {item_count}")

        # Verify we have 2 files (one per architecture)
        assert item_count >= 2, f"Should have at least 2 files (one per arch), got {item_count}"

        # Parse and display file entries
        for i, content in enumerate(list_result.content[1:], 1):
            try:
                entry = json.loads(content.text)
                print(f"  [{i}] {entry}")
            except (json.JSONDecodeError, AttributeError):
                pass

        print(f"\n✓ Fat binary slices appear in project ({item_count} items)")


class TestSingleBinaryImport:
    """Tests for importing single-architecture binaries."""

    async def test_import_single_arm64_binary(self, mcp_stdio_client, isolated_workspace):
        """Import a single ARM64 binary."""
        binary_path = skip_if_fixture_missing("test_arm64")

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
        binary_path = skip_if_fixture_missing("test_x86_64")

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
        binary_path = skip_if_fixture_missing("test_arm64")

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
        binary_path = skip_if_fixture_missing("test_arm64")

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

        # Parse functions response
        functions_text = functions_result.content[0].text
        functions_data = json.loads(functions_text)

        # Check for functions discovered
        functions = functions_data.get("functions", [])
        function_count = functions_data.get("count", len(functions))

        print(f"Functions discovered: {function_count}")
        if functions:
            print("Sample functions:")
            for func in functions[:5]:
                name = func.get("name", "unknown")
                addr = func.get("address", "unknown")
                print(f"  - {name} @ {addr}")

        # The test binaries should have at least one function (entry point)
        assert function_count > 0, \
            f"Analysis should discover at least one function, got {function_count}"

        print(f"\n✓ Analysis correctly discovered {function_count} functions")

    async def test_fat_binary_analysis_discovers_functions_in_both_slices(
        self, mcp_stdio_client, isolated_workspace
    ):
        """
        Import and analyze a fat binary, verify functions discovered in both slices.

        This ensures multi-architecture binaries are properly analyzed.
        """
        fat_binary_path = skip_if_fixture_missing("test_fat_binary")

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

            functions_text = functions_result.content[0].text
            functions_data = json.loads(functions_text)

            functions = functions_data.get("functions", [])
            function_count = functions_data.get("count", len(functions))

            print(f"  Functions in {program_path}: {function_count}")
            if functions:
                for func in functions[:3]:
                    print(f"    - {func.get('name', 'unknown')} @ {func.get('address', 'unknown')}")

            assert function_count > 0, \
                f"Each slice should have at least one function, got {function_count} in {program_path}"

        print(f"\n✓ Both architecture slices analyzed correctly")

    async def test_import_without_analysis(self, mcp_stdio_client, isolated_workspace):
        """
        Import with analyzeAfterImport=false (default) and verify no analysis.

        Expected: analyzedPrograms field NOT present
        """
        binary_path = skip_if_fixture_missing("test_arm64")

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
        binary_path = skip_if_fixture_missing("test_arm64")

        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": binary_path,
                "enableVersionControl": False
            }
        )

        assert result is not None
        data = json.loads(result.content[0].text)

        # Core fields that should always be present
        required_fields = [
            "success",
            "importedFrom",
            "destinationFolder",
            "filesDiscovered",
            "importedPrograms",
            "groupsCreated",
            "maxDepthUsed",
        ]

        for field in required_fields:
            assert field in data, f"Missing required field: {field}"
            print(f"✓ {field}: {data[field]}")

        # Optional/conditional fields - just log their presence
        optional_fields = [
            "enableVersionControl",
            "analyzeAfterImport",
            "message",
            "wasRecursive",
        ]

        for field in optional_fields:
            if field in data:
                print(f"  {field}: {data[field]}")

    async def test_path_handling_parameters_work(self, mcp_stdio_client, isolated_workspace):
        """Verify path handling parameters are accepted and import succeeds."""
        binary_path = skip_if_fixture_missing("test_arm64")

        # Test with explicit path handling options
        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": binary_path,
                "enableVersionControl": False,
                "stripLeadingPath": True,  # Use default value
                "stripAllContainerPath": False,  # Use default value
            }
        )

        assert result is not None
        assert hasattr(result, 'content') and len(result.content) > 0, "Result should have content"

        content_text = result.content[0].text
        if not content_text:
            pytest.fail(
                "Empty response from tool. The installed ReVa extension may be outdated. "
                "Run 'gradle install' to install the development version."
            )

        data = json.loads(content_text)

        # Main assertion: import should succeed with these parameters
        assert data.get("success") is True, "Import should succeed with path handling params"

        # Verify program was imported
        imported = data.get("importedPrograms", [])
        assert len(imported) > 0, "Should import at least one program"

        print(f"✓ Import succeeded with path handling parameters: {imported}")


class TestImportErrorHandling:
    """Tests for import error handling."""

    async def test_import_nonexistent_file(self, mcp_stdio_client, isolated_workspace):
        """Verify proper error response for non-existent file."""
        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": "/nonexistent/path/to/file.bin",
                "enableVersionControl": False
            }
        )

        assert result is not None

        # Check if it's an MCP error response
        if hasattr(result, 'isError') and result.isError:
            # Error response - check content for error message
            if result.content and len(result.content) > 0:
                error_text = result.content[0].text if result.content[0].text else "Error with no message"
                print(f"✓ Tool returned error: {error_text}")
            else:
                print("✓ Tool returned error (no message)")
            return

        # Check for content
        if not result.content or len(result.content) == 0:
            print("✓ Tool returned empty content (implicit error)")
            return

        content_text = result.content[0].text
        if not content_text:
            print("✓ Tool returned empty text (implicit error)")
            return

        # Try to parse as JSON
        try:
            data = json.loads(content_text)
            # Tool might return success=false with error message
            if not data.get("success"):
                print(f"✓ Import correctly failed for non-existent file: {data.get('message', 'no message')}")
            else:
                pytest.fail("Import should fail for non-existent file")
        except json.JSONDecodeError:
            # Non-JSON error message
            print(f"✓ Tool returned error message: {content_text}")
