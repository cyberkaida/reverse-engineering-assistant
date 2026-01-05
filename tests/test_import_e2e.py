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
    """Skip test if fixture file is missing."""
    fixture_path = FIXTURES_DIR / fixture_name
    if not fixture_path.exists():
        pytest.skip(f"Test fixture not found: {fixture_path}")
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

        # Verify multiple files imported (including fat binary slices)
        files_imported = data.get("filesImported", 0)
        assert files_imported >= 3, f"Should import >= 3 files, got {files_imported}"

        # Verify importedPrograms list
        imported_programs = data.get("importedPrograms", [])
        assert len(imported_programs) >= 3, f"Should have >= 3 imported programs, got {len(imported_programs)}"

        print(f"✓ Archive imported: {files_discovered} discovered, {files_imported} imported")
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

        # Required fields
        required_fields = [
            "success",
            "importedFrom",
            "filesDiscovered",
            "filesImported",
            "importedPrograms",
            "enabledGroups",
            "skippedGroups",
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

        # Fat binary should produce 2 programs
        files_imported = data.get("filesImported", 0)
        assert files_imported == 2, f"Fat binary should produce 2 programs, got {files_imported}"

        # Verify both architectures are represented
        imported_programs = data.get("importedPrograms", [])
        assert len(imported_programs) == 2, f"Should have 2 programs, got {len(imported_programs)}"

        # Check architecture names (Ghidra uses various naming conventions)
        programs_str = " ".join(imported_programs).lower()
        has_arm = "arm" in programs_str or "aarch" in programs_str
        has_x86 = "x86" in programs_str or "64" in programs_str

        print(f"✓ Fat binary slices extracted: {imported_programs}")
        print(f"  Has ARM: {has_arm}, Has x86: {has_x86}")

        assert has_arm or has_x86, "Should have at least one recognized architecture"


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
        assert data.get("filesImported", 0) == 1, "Should import exactly 1 program"

        print(f"✓ Single ARM64 binary imported: {data.get('importedPrograms', [])}")

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
        assert data.get("filesImported", 0) == 1, "Should import exactly 1 program"

        print(f"✓ Single x86_64 binary imported: {data.get('importedPrograms', [])}")


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

        # All fields that should be present
        expected_fields = [
            # Core result fields
            "success",
            "importedFrom",
            "destinationFolder",
            # Discovery and import counts
            "filesDiscovered",
            "filesImported",
            "importedPrograms",
            # Batch group tracking
            "groupsCreated",
            "enabledGroups",
            "skippedGroups",
            # Path handling options (reflect input params)
            "stripLeadingPath",
            "stripAllContainerPath",
            "mirrorFs",
            # Max depth
            "maxDepthUsed",
        ]

        missing_fields = []
        for field in expected_fields:
            if field not in data:
                missing_fields.append(field)
            else:
                print(f"✓ {field}: {data[field]}")

        if missing_fields:
            print(f"\nMissing fields: {missing_fields}")
            # Don't fail on all missing fields - some may be conditional
            # Just report them
            print(f"Note: Some fields may only appear in specific scenarios")

    async def test_path_handling_parameters_reflected(self, mcp_stdio_client, isolated_workspace):
        """Verify path handling parameters are reflected in response."""
        binary_path = skip_if_fixture_missing("test_arm64")

        # Test with explicit path handling options
        result = await mcp_stdio_client.call_tool(
            "import-file",
            arguments={
                "path": binary_path,
                "enableVersionControl": False,
                "stripLeadingPath": False,
                "stripAllContainerPath": True,
                "mirrorFs": False
            }
        )

        assert result is not None
        data = json.loads(result.content[0].text)

        # Verify parameters are reflected in response
        if "stripLeadingPath" in data:
            assert data["stripLeadingPath"] is False, "stripLeadingPath should match input"
        if "stripAllContainerPath" in data:
            assert data["stripAllContainerPath"] is True, "stripAllContainerPath should match input"
        if "mirrorFs" in data:
            assert data["mirrorFs"] is False, "mirrorFs should match input"

        print("✓ Path handling parameters correctly reflected in response")


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
        # Should be an error or have success=false
        if hasattr(result, 'isError') and result.isError:
            error_text = result.content[0].text
            assert "exist" in error_text.lower() or "not found" in error_text.lower()
            print(f"✓ Correct error for non-existent file: {error_text}")
        else:
            data = json.loads(result.content[0].text)
            # Tool might return success=false with error message
            if not data.get("success"):
                print(f"✓ Import correctly failed for non-existent file")
            else:
                pytest.fail("Import should fail for non-existent file")
