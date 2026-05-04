"""
End-to-end correctness tests over a deterministic fixture.

Unlike the lifecycle workflow tests in test_e2e_workflow.py, these verify that
ReVa's analysis tools produce correct, semantically meaningful output for a
known input binary (tests/fixtures/test_arm64). The fixture is built from
test_program.c, which contains add(), multiply(), and main() that calls
printf, add, and multiply.

These tests answer "did the tool give the right answer?", not just
"did the tool respond?".
"""

import json
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio,
    pytest.mark.timeout(240),
]

FIXTURES_DIR = Path(__file__).parent / "fixtures"


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


async def _import_and_analyze(client, fixture_name: str = "test_arm64") -> str:
    """Import the fixture and run a full analysis, returning the program path.

    Imports without analyzeAfterImport, then explicitly runs analyze-program
    with forceFullAnalysis=true. This guarantees that the Mach-O symbol-table
    analyzer has applied function symbols, rather than relying on whatever
    subset analyzeAfterImport happened to run.
    """
    fixture = _validate_fixture(fixture_name)
    result = await client.call_tool(
        "import-file",
        arguments={
            "path": fixture,
            "enableVersionControl": False,
            "analyzeAfterImport": False,
        },
    )
    assert result is not None and not getattr(result, "isError", False), (
        f"Import failed: {result.content[0].text if result.content else 'no content'}"
    )
    data = json.loads(result.content[0].text)
    assert data.get("success") is True, f"Import unsuccessful: {data}"
    imported = data.get("importedPrograms", [])
    assert imported, f"No programs imported: {data}"
    program_path = imported[0]

    analyze_result = await client.call_tool(
        "analyze-program",
        arguments={
            "programPath": program_path,
            "forceFullAnalysis": True,
        },
    )
    assert analyze_result is not None and not getattr(analyze_result, "isError", False), (
        f"analyze-program failed: {analyze_result.content[0].text if analyze_result.content else 'no content'}"
    )
    return program_path


async def _find_function(client, program_path: str, name_substr: str) -> dict:
    """Return the first function whose name contains name_substr (case-insensitive).

    Returns a dict with at least 'name' and 'address' keys.

    Tries with default-name filter on first (i.e., user-named functions only),
    then disables filter as a fallback. Includes diagnostic dump of what was
    actually returned when no match is found.
    """
    needle = name_substr.lower()
    seen_names: list[str] = []

    for filter_default in (True, False):
        result = await client.call_tool(
            "get-functions",
            arguments={
                "programPath": program_path,
                "maxCount": 500,
                "filterDefaultNames": filter_default,
            },
        )
        assert result is not None and not getattr(result, "isError", False), (
            f"get-functions failed: {result.content[0].text if result.content else 'no content'}"
        )
        funcs_this_round = []
        for content in result.content[1:]:
            try:
                func = json.loads(content.text)
            except (json.JSONDecodeError, AttributeError):
                continue
            funcs_this_round.append(func)
            name = (func.get("name") or "").lower()
            if needle in name:
                return func
        seen_names.extend(f.get("name", "?") for f in funcs_this_round)

    pytest.fail(
        f"No function matching {name_substr!r} found in {program_path}. "
        f"Functions returned (any filter): {seen_names}"
    )


class TestDecompilationCorrectness:
    """Verify get-decompilation produces semantically correct output."""

    async def test_entry_decompilation_contains_known_calls(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Decompiled entry function must reference printf and the helper functions.

        The fixture's main() (which Ghidra surfaces as 'entry' for this Mach-O)
        calls printf, add(2,3), and multiply(4,5). All three callees must appear
        in the decompiled C output.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        entry_func = await _find_function(mcp_stdio_client, program_path, "entry")

        decomp_result = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": entry_func["name"],
                "limit": 200,
            },
        )

        assert decomp_result is not None and not getattr(decomp_result, "isError", False), (
            f"get-decompilation failed: {decomp_result.content[0].text if decomp_result.content else 'no content'}"
        )

        data = json.loads(decomp_result.content[0].text)
        decompilation = data.get("decompilation", "")
        assert decompilation, f"Empty decompilation in response: {data}"

        # Decompilation should reference printf and the two helper functions.
        # Mach-O preserves leading underscores: _add, _multiply, _printf.
        text = decompilation.lower()
        assert "printf" in text, (
            f"Expected 'printf' call in entry decompilation; got:\n{decompilation}"
        )
        assert "add" in text, (
            f"Expected reference to 'add' in entry decompilation; got:\n{decompilation}"
        )
        assert "multiply" in text, (
            f"Expected reference to 'multiply' in entry decompilation; got:\n{decompilation}"
        )


class TestCrossReferenceDiscovery:
    """Verify find-cross-references discovers known caller relationships."""

    async def test_add_function_has_entry_as_caller(
        self, mcp_stdio_client, isolated_workspace
    ):
        """find-cross-references on _add should report entry as an incoming caller.

        In the fixture, main() calls add(2, 3); Ghidra labels main as 'entry'
        for this Mach-O. find-cross-references with direction=to on _add must
        produce a referencesTo entry whose fromFunction is entry.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        add_func = await _find_function(mcp_stdio_client, program_path, "add")

        xref_result = await mcp_stdio_client.call_tool(
            "find-cross-references",
            arguments={
                "programPath": program_path,
                "location": add_func["address"],
                "direction": "to",
                "includeFlow": True,
                "includeData": False,
            },
        )

        assert xref_result is not None and not getattr(xref_result, "isError", False), (
            f"find-cross-references failed: {xref_result.content[0].text if xref_result.content else 'no content'}"
        )

        data = json.loads(xref_result.content[0].text)
        refs_to = data.get("referencesTo", [])
        assert refs_to, (
            f"Expected at least one incoming reference to {add_func['name']}, got none. "
            f"Full response: {json.dumps(data, indent=2)}"
        )

        # At least one reference must have fromFunction.name == 'entry' (Ghidra's name for main).
        caller_names = []
        for ref in refs_to:
            from_func = ref.get("fromFunction") or {}
            fn_name = from_func.get("name", "")
            caller_names.append(fn_name)
            if fn_name == "entry" or "main" in fn_name.lower():
                return  # success

        pytest.fail(
            f"Expected entry/main among callers of {add_func['name']}; found callers: {caller_names}. "
            f"Full referencesTo: {json.dumps(refs_to, indent=2)}"
        )


class TestVariableRenamePersistence:
    """Verify rename-variables persists across save and reopen."""

    async def test_renamed_variable_persists_after_save_and_reopen(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Rename a parameter on _add, save, reopen, and confirm the new name.

        Walks the full LLM modification flow:
          1. import + analyze
          2. get-decompilation (mandatory before rename)
          3. rename-variables on a parameter of _add (it has 2 params)
          4. checkin-program (saves and releases cache)
          5. get-decompilation again (forces reload)
          6. assert renamed variable appears

        _add is chosen because the entry function has no locals/params after
        the compiler's optimizations strip argc/argv.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        target_func = await _find_function(mcp_stdio_client, program_path, "add")

        # 1. Read decompilation (required by rename-variables read-before-modify guard).
        first_decomp = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": target_func["name"],
                "limit": 200,
            },
        )
        assert not getattr(first_decomp, "isError", False), (
            f"Initial get-decompilation failed: {first_decomp.content[0].text}"
        )
        first_data = json.loads(first_decomp.content[0].text)
        original_text = first_data.get("decompilation", "")
        assert original_text, "Empty initial decompilation"

        # _add(int, int) without source symbols decompiles with synthesized names.
        # Try the common Ghidra parameter naming conventions in order.
        candidates = ["param_1", "iParm1", "param1", "arg1", "in_w0"]
        original_name = next((c for c in candidates if c in original_text), None)
        if original_name is None:
            pytest.fail(
                f"Could not find a known variable name to rename in {target_func['name']}; "
                f"decompilation:\n{original_text}"
            )
        new_name = f"reva_e2e_renamed_{original_name}"

        # 2. Rename
        rename_result = await mcp_stdio_client.call_tool(
            "rename-variables",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": target_func["name"],
                "variableMappings": {original_name: new_name},
            },
        )
        assert not getattr(rename_result, "isError", False), (
            f"rename-variables failed: {rename_result.content[0].text}"
        )
        rename_data = json.loads(rename_result.content[0].text)
        assert rename_data.get("variablesRenamed") is True, (
            f"variablesRenamed flag not true: {rename_data}"
        )
        assert rename_data.get("renamedCount", 0) >= 1, (
            f"renamedCount must be >= 1, got: {rename_data}"
        )

        # 3. Save and release cache
        checkin = await mcp_stdio_client.call_tool(
            "checkin-program",
            arguments={
                "programPath": program_path,
                "message": f"e2e rename test: {original_name} -> {new_name}",
                "keepCheckedOut": False,
            },
        )
        assert not getattr(checkin, "isError", False), (
            f"checkin-program failed: {checkin.content[0].text}"
        )
        checkin_data = json.loads(checkin.content[0].text)
        assert checkin_data.get("success") is True, f"checkin not successful: {checkin_data}"

        # 4. Force reload by re-reading decompilation
        second_decomp = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": target_func["name"],
                "limit": 200,
            },
        )
        assert not getattr(second_decomp, "isError", False), (
            f"Second get-decompilation failed: {second_decomp.content[0].text}"
        )
        second_data = json.loads(second_decomp.content[0].text)
        second_text = second_data.get("decompilation", "")
        assert second_text, "Empty decompilation after reopen"

        assert new_name in second_text, (
            f"Renamed variable {new_name!r} did not persist after save/reopen.\n"
            f"Reloaded decompilation:\n{second_text}"
        )
