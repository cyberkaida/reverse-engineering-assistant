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
import pytest_asyncio

# Every test in this module runs against the session-scoped mcp-reva
# subprocess (see mcp_stdio_client override below), so all tests must
# share the same event loop the session fixture lives on. loop_scope
# defaults to "function" otherwise, which would prevent the cross-test
# session fixture from working.
pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio(loop_scope="session"),
    pytest.mark.timeout(240),
]


# Override conftest.py's function-scoped mcp_stdio_client for this module
# with the session-scoped variant. The 66 tests here only need a working
# MCP client — none depend on per-test workspace state. Each test isolates
# itself by importing under a unique destinationFolder, allocated by the
# autouse _set_test_program_folder fixture and consumed below in
# _import_and_analyze.
@pytest_asyncio.fixture(loop_scope="session")
async def mcp_stdio_client(mcp_stdio_client_session):
    yield mcp_stdio_client_session

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


def _result_text(result) -> str:
    """Safely render a CallToolResult's first text content for error messages.

    Many assertion-failure messages want to show the tool's body, but the
    natural form (`result.content[0].text`) raises AttributeError if the
    result is None or its content list is empty — masking the real
    assertion failure with a confusing chained exception. Use this helper
    whenever building an assertion-failure message that mentions a result.
    """
    if result is None:
        return "(no result)"
    content = getattr(result, "content", None) or []
    if not content:
        return "(empty content)"
    return getattr(content[0], "text", None) or "(no text)"


async def _import_and_analyze(client, fixture_name: str = "test_arm64") -> str:
    """Import the fixture and run a full analysis, returning the program path.

    Imports without analyzeAfterImport, then explicitly runs analyze-program
    with forceFullAnalysis=true. This guarantees that the Mach-O symbol-table
    analyzer has applied function symbols, rather than relying on whatever
    subset analyzeAfterImport happened to run.

    Each test imports into a unique destinationFolder (allocated by the
    autouse _set_test_program_folder fixture in conftest.py) so the
    session-scoped mcp-reva subprocess doesn't accumulate name collisions.
    import-file auto-creates the folder.
    """
    from tests.conftest import reva_test_program_folder

    fixture = _validate_fixture(fixture_name)
    result = await client.call_tool(
        "import-file",
        arguments={
            "path": fixture,
            "destinationFolder": reva_test_program_folder(),
            "enableVersionControl": False,
            "analyzeAfterImport": False,
        },
    )
    assert result is not None, "import-file returned None — server unreachable?"
    assert not getattr(result, "isError", False), (
        f"Import failed: {_result_text(result)}"
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
    assert analyze_result is not None, "analyze-program returned None — server unreachable?"
    assert not getattr(analyze_result, "isError", False), (
        f"analyze-program failed: {_result_text(analyze_result)}"
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
        assert result is not None, "get-functions returned None — server unreachable?"
        assert not getattr(result, "isError", False), (
            f"get-functions failed: {_result_text(result)}"
        )
        funcs_this_round = json.loads(result.content[0].text).get("functions", [])
        for func in funcs_this_round:
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
        # Mach-O preserves leading underscores: _add, _multiply, _printf. Match
        # on the call form ("_name(") to avoid the substring "add" hitting
        # "address" or "loaded" in the surrounding C output.
        assert "_printf(" in decompilation, (
            f"Expected '_printf(' call in entry decompilation; got:\n{decompilation}"
        )
        assert "_add(" in decompilation, (
            f"Expected '_add(' call in entry decompilation; got:\n{decompilation}"
        )
        assert "_multiply(" in decompilation, (
            f"Expected '_multiply(' call in entry decompilation; got:\n{decompilation}"
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


class TestStructureWorkflow:
    """Verify the parse-c-structure -> list-structures -> apply-structure cycle."""

    async def test_struct_create_apply_and_query(
        self, mcp_stdio_client, isolated_workspace
    ):
        """End-to-end struct workflow:

        1. parse-c-structure to create a named struct with known fields
        2. list-structures to confirm the struct is present with the
           expected component count
        3. apply-structure at a data address (the literal pool referenced
           from main) and confirm the response carries the matching
           structure name and a non-zero size

        This exercises three packages in one workflow: structures, data,
        and (transitively) the data-type manager. None of these tools
        had real e2e coverage before this test.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        struct_name = "RevaE2EStruct"
        c_def = (
            "struct " + struct_name + " {"
            "    int magic;"
            "    int version;"
            "    int flags;"
            "    int padding;"
            "};"
        )

        # 1. Create the struct
        parse_result = await mcp_stdio_client.call_tool(
            "parse-c-structure",
            arguments={
                "programPath": program_path,
                "cDefinition": c_def,
            },
        )
        assert not getattr(parse_result, "isError", False), (
            f"parse-c-structure failed: {parse_result.content[0].text if parse_result.content else 'no content'}"
        )
        parse_data = json.loads(parse_result.content[0].text)
        assert parse_data.get("name") == struct_name, (
            f"Expected struct name {struct_name!r}, got {parse_data!r}"
        )
        assert parse_data.get("size") == 16, (
            f"Expected size 16 (4 ints x 4 bytes), got size={parse_data.get('size')!r} "
            f"in response {parse_data!r}"
        )

        # 2. Confirm via list-structures with name filter
        list_result = await mcp_stdio_client.call_tool(
            "list-structures",
            arguments={
                "programPath": program_path,
                "nameFilter": struct_name,
            },
        )
        assert not getattr(list_result, "isError", False), (
            f"list-structures failed: {list_result.content[0].text if list_result.content else 'no content'}"
        )
        list_data = json.loads(list_result.content[0].text)
        struct_names = [s.get("name") for s in list_data.get("structures", [])]
        assert struct_name in struct_names, (
            f"Expected {struct_name!r} in list-structures output; got {struct_names!r}, "
            f"full response: {list_data!r}"
        )

        # 3. Apply the struct at a known data address (the literal pool
        #    referenced from main; otool shows strings starting at 0x100000530).
        target_addr = "0x100000530"
        apply_result = await mcp_stdio_client.call_tool(
            "apply-structure",
            arguments={
                "programPath": program_path,
                "structureName": struct_name,
                "addressOrSymbol": target_addr,
                "clearExisting": True,
            },
        )
        assert not getattr(apply_result, "isError", False), (
            f"apply-structure failed: {apply_result.content[0].text if apply_result.content else 'no content'}"
        )
        apply_data = json.loads(apply_result.content[0].text)
        assert apply_data.get("structureName") == struct_name, (
            f"apply-structure should report structureName={struct_name!r}; got {apply_data!r}"
        )
        assert apply_data.get("size") == 16, (
            f"apply-structure should report size=16 for our 4-int struct; got {apply_data!r}"
        )


class TestSearchDecompilation:
    """Verify search-decompilation finds known patterns across functions."""

    async def test_search_finds_printf_call_in_entry(
        self, mcp_stdio_client, isolated_workspace
    ):
        """search-decompilation for '_printf(' should hit the entry function.

        The fixture's entry function makes three printf calls. A regex
        search across decompilations must find at least one match and
        report the function name and line number for it.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "search-decompilation",
            arguments={
                "programPath": program_path,
                "pattern": r"_printf\(",
                "maxResults": 50,
                "caseSensitive": True,
            },
        )
        assert not getattr(result, "isError", False), (
            f"search-decompilation failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        results = data.get("results", [])
        assert results, (
            f"Expected at least one match for '_printf('; "
            f"got resultsCount={data.get('resultsCount')}, full response={data!r}"
        )

        # Each result must include functionName, functionAddress, lineNumber, lineContent.
        for entry in results:
            for field in ("functionName", "functionAddress", "lineNumber", "lineContent"):
                assert field in entry, (
                    f"Search result missing required field {field!r}: {entry!r}"
                )

        # At least one match must be in the entry function (which calls printf).
        callers = {r.get("functionName") for r in results}
        assert "entry" in callers, (
            f"Expected 'entry' among functions matching '_printf('; got callers={callers!r}"
        )

        # And the matched line content must actually contain the pattern.
        entry_lines = [r["lineContent"] for r in results if r.get("functionName") == "entry"]
        assert any("_printf(" in line for line in entry_lines), (
            f"Match lines for entry must contain '_printf('; got {entry_lines!r}"
        )


class TestSetFunctionPrototype:
    """Verify set-function-prototype updates parameter names visible in decompilation."""

    async def test_prototype_update_changes_parameter_names(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Setting an explicit prototype on _add propagates to decompilation.

        After analysis _add decompiles with synthesized parameter names
        like param_1 / param_2. Calling set-function-prototype with
        named parameters (alpha, beta) and re-decompiling must show
        those exact names in the new C output.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        add_func = await _find_function(mcp_stdio_client, program_path, "add")

        # Read the original decompilation so the read-before-modify guard
        # (used by other decompiler-modifying tools) is satisfied. Also
        # gives us a "before" snapshot for the assertion.
        before = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": add_func["name"],
                "limit": 100,
            },
        )
        assert not getattr(before, "isError", False), (
            f"Initial get-decompilation failed: {before.content[0].text}"
        )
        before_text = json.loads(before.content[0].text).get("decompilation", "")
        assert "alpha" not in before_text and "beta" not in before_text, (
            f"Sanity check failed: 'alpha'/'beta' already in unmodified decompilation:\n{before_text}"
        )

        # Apply the new prototype.
        prototype = "int _add(int alpha, int beta)"
        proto_result = await mcp_stdio_client.call_tool(
            "set-function-prototype",
            arguments={
                "programPath": program_path,
                "location": add_func["address"],
                "signature": prototype,
            },
        )
        assert not getattr(proto_result, "isError", False), (
            f"set-function-prototype failed: {proto_result.content[0].text if proto_result.content else 'no content'}"
        )
        proto_data = json.loads(proto_result.content[0].text)
        assert proto_data.get("success") is True, (
            f"set-function-prototype should report success=True; got {proto_data!r}"
        )

        # Re-decompile and assert the new parameter names appear.
        after = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": add_func["name"],
                "limit": 100,
            },
        )
        assert not getattr(after, "isError", False), (
            f"Post-prototype get-decompilation failed: {after.content[0].text}"
        )
        after_text = json.loads(after.content[0].text).get("decompilation", "")
        assert "alpha" in after_text and "beta" in after_text, (
            f"Expected 'alpha' and 'beta' in decompilation after prototype set; got:\n{after_text}"
        )


class TestStringDiscovery:
    """Verify get-strings exposes the binary's known literals."""

    async def test_regex_filter_finds_known_literal(
        self, mcp_stdio_client, isolated_workspace
    ):
        """get-strings with regexPattern='ReVa' must return the test program banner.

        The fixture's main() prints "ReVa Test Program\\n" via printf, so a
        regex filter on the literal must surface that string with non-zero
        length and the expected content. Verifies the result schema
        (address, content, length, dataType) at the same time.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "get-strings",
            arguments={
                "programPath": program_path,
                "regexPattern": "ReVa",
                "maxCount": 50,
            },
        )
        assert not getattr(result, "isError", False), (
            f"get-strings failed: {result.content[0].text if result.content else 'no content'}"
        )

        # get-strings packs metadata + entries into a single JSON array
        # in one TextContent (unlike get-functions/get-symbols which use
        # multiple TextContent items). The first element is pagination
        # metadata; the rest are string entries.
        assert result.content and result.content[0].text, "Empty response body"
        items = json.loads(result.content[0].text)
        assert isinstance(items, list) and len(items) >= 2, (
            f"Expected JSON array of [metadata, ...entries]; got {items!r}"
        )

        metadata, *strings = items
        assert metadata.get("actualCount", 0) >= 1, (
            f"Expected at least one string match for 'ReVa'; metadata={metadata!r}"
        )

        # Every entry must have the documented schema.
        for s in strings:
            for field in ("address", "content", "length", "dataType"):
                assert field in s, f"String entry missing {field!r}: {s!r}"

        # And the banner must be among them.
        contents = [s.get("content", "") for s in strings]
        assert any("ReVa Test Program" in c for c in contents), (
            f"Expected 'ReVa Test Program' banner in get-strings output; got {contents!r}"
        )


class TestCallersDecompiled:
    """Verify get-callers-decompiled returns decompilation of every known caller."""

    async def test_callers_of_add_includes_entry(
        self, mcp_stdio_client, isolated_workspace
    ):
        """get-callers-decompiled on _add must include entry with its full decompilation.

        In the fixture, only the entry function calls _add. The tool must
        return entry's decompilation plus the call-site address that
        targets _add, not just an empty caller list.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        add_func = await _find_function(mcp_stdio_client, program_path, "add")

        result = await mcp_stdio_client.call_tool(
            "get-callers-decompiled",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": add_func["name"],
                "maxCallers": 10,
                "includeCallContext": True,
            },
        )
        assert not getattr(result, "isError", False), (
            f"get-callers-decompiled failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        callers = data.get("callers", [])
        assert callers, (
            f"Expected at least one caller of {add_func['name']}; got empty list. "
            f"Full response: {data!r}"
        )

        # The entry function must be among them.
        entry_callers = [c for c in callers if c.get("functionName") == "entry"]
        assert entry_callers, (
            f"Expected 'entry' in callers; got functionNames={[c.get('functionName') for c in callers]!r}"
        )

        entry_caller = entry_callers[0]
        assert entry_caller.get("success") is True, (
            f"entry caller decompilation should succeed; got {entry_caller!r}"
        )
        decompilation = entry_caller.get("decompilation", "")
        assert "_add(" in decompilation, (
            f"entry caller decompilation should contain '_add('; got:\n{decompilation}"
        )
        # callLineNumbers requested via includeCallContext=True must be populated.
        assert entry_caller.get("callLineNumbers"), (
            f"Expected callLineNumbers populated for entry; got {entry_caller!r}"
        )


class TestImportReferences:
    """Verify find-import-references discovers all use sites of an external symbol."""

    async def test_printf_references_include_entry(
        self, mcp_stdio_client, isolated_workspace
    ):
        """find-import-references on '_printf' must find the calls inside entry.

        The fixture's main() (analysed as entry) calls printf three times.
        Even after Ghidra collapses adjacent calls, at least one reference
        from inside entry must show up.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        # Mach-O imports keep the leading underscore: '_printf'.
        result = await mcp_stdio_client.call_tool(
            "find-import-references",
            arguments={
                "programPath": program_path,
                "importName": "_printf",
                "maxResults": 100,
            },
        )
        assert not getattr(result, "isError", False), (
            f"find-import-references failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        assert data.get("matchedImports"), (
            f"Expected to find at least one import named '_printf'; got {data!r}"
        )
        assert data.get("referenceCount", 0) >= 1, (
            f"Expected at least 1 reference to _printf; got {data!r}"
        )

        references = data.get("references", [])
        # Each reference must carry the documented schema.
        for ref in references:
            for field in ("fromAddress", "referenceType", "isCall"):
                assert field in ref, f"Reference missing {field!r}: {ref!r}"

        # At least one reference must originate from inside the entry function.
        entry_refs = [r for r in references if r.get("function") == "entry"]
        assert entry_refs, (
            f"Expected entry among functions referencing _printf; got "
            f"{[r.get('function') for r in references]!r}"
        )


class TestCallGraph:
    """Verify get-call-graph reports the known direct callees of a function."""

    async def test_entry_callees_include_printf_add_multiply(
        self, mcp_stdio_client, isolated_workspace
    ):
        """get-call-graph on entry must list the three known callees.

        The fixture's entry calls printf, add, and multiply directly. With
        depth=1 the callees field must include all three by name.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        entry_func = await _find_function(mcp_stdio_client, program_path, "entry")

        result = await mcp_stdio_client.call_tool(
            "get-call-graph",
            arguments={
                "programPath": program_path,
                "functionAddress": entry_func["address"],
                "depth": 1,
            },
        )
        assert not getattr(result, "isError", False), (
            f"get-call-graph failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        center = data.get("centerFunction") or {}
        assert center.get("name") == "entry", (
            f"centerFunction.name should be 'entry'; got {center!r}"
        )
        assert data.get("calleeCount", 0) >= 3, (
            f"Expected calleeCount >= 3 (printf + add + multiply); got {data!r}"
        )

        callee_names = [c.get("name") for c in data.get("callees", [])]
        assert "_printf" in callee_names, (
            f"Expected '_printf' in callees; got {callee_names!r}"
        )
        assert "_add" in callee_names, (
            f"Expected '_add' in callees; got {callee_names!r}"
        )
        assert "_multiply" in callee_names, (
            f"Expected '_multiply' in callees; got {callee_names!r}"
        )


class TestListImports:
    """Verify list-imports surfaces the binary's external symbols."""

    async def test_list_imports_includes_printf(
        self, mcp_stdio_client, isolated_workspace
    ):
        """list-imports must report _printf for the test_arm64 fixture.

        Uses groupByLibrary=False so the response shape is the simpler
        flat-imports form. Asserts the documented per-import schema
        (name, library, address) and that _printf is present.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "list-imports",
            arguments={
                "programPath": program_path,
                "groupByLibrary": False,
                "maxResults": 100,
            },
        )
        assert not getattr(result, "isError", False), (
            f"list-imports failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        assert data.get("totalCount", 0) >= 1, (
            f"Expected at least one import in test_arm64; got totalCount={data.get('totalCount')!r}"
        )
        imports = data.get("imports", [])
        assert imports, f"imports list empty: {data!r}"

        for imp in imports:
            for field in ("name", "library"):
                assert field in imp, f"Import missing {field!r}: {imp!r}"

        names = [i.get("name") for i in imports]
        assert "_printf" in names, (
            f"Expected '_printf' in imports list; got {names!r}"
        )


class TestFunctionTags:
    """Verify the function-tags add/list/filter cycle."""

    async def test_tag_round_trip(self, mcp_stdio_client, isolated_workspace):
        """Tag _add, list tags, then filter get-functions by that tag.

        Exercises three function-tags modes (add, list) plus get-functions'
        filterByTag parameter -- the canonical LLM workflow for grouping
        functions by category.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        add_func = await _find_function(mcp_stdio_client, program_path, "add")

        tag_name = "reva-e2e-tag"

        # 1. Add tag to _add
        add_result = await mcp_stdio_client.call_tool(
            "function-tags",
            arguments={
                "programPath": program_path,
                "function": add_func["name"],
                "mode": "add",
                "tags": [tag_name],
            },
        )
        assert not getattr(add_result, "isError", False), (
            f"function-tags add failed: {add_result.content[0].text}"
        )
        add_data = json.loads(add_result.content[0].text)
        assert add_data.get("success") is True, f"function-tags add not success: {add_data!r}"
        assert tag_name in add_data.get("tags", []), (
            f"Tag {tag_name!r} should appear in updated tag list; got {add_data!r}"
        )

        # 2. List program-wide tags; ours must be present with count >= 1.
        list_result = await mcp_stdio_client.call_tool(
            "function-tags",
            arguments={
                "programPath": program_path,
                "mode": "list",
            },
        )
        assert not getattr(list_result, "isError", False), (
            f"function-tags list failed: {list_result.content[0].text}"
        )
        list_data = json.loads(list_result.content[0].text)
        all_tags = {t.get("name"): t for t in list_data.get("tags", [])}
        assert tag_name in all_tags, (
            f"Expected {tag_name!r} in program-wide tag list; got {list(all_tags)!r}"
        )
        assert all_tags[tag_name].get("count", 0) >= 1, (
            f"Tag {tag_name!r} should have count >= 1; got {all_tags[tag_name]!r}"
        )

        # 3. Use get-functions with filterByTag to find tagged functions.
        filtered = await mcp_stdio_client.call_tool(
            "get-functions",
            arguments={
                "programPath": program_path,
                "filterByTag": tag_name,
                "maxCount": 50,
            },
        )
        assert not getattr(filtered, "isError", False), (
            f"get-functions with filterByTag failed: {filtered.content[0].text}"
        )
        filtered_names = [
            f.get("name")
            for f in json.loads(filtered.content[0].text).get("functions", [])
        ]
        assert add_func["name"] in filtered_names, (
            f"Tagged function {add_func['name']!r} should appear when filtering by tag "
            f"{tag_name!r}; got {filtered_names!r}"
        )


class TestReadMemory:
    """Verify read-memory returns the expected bytes for a known string literal."""

    async def test_read_known_string_bytes(
        self, mcp_stdio_client, isolated_workspace
    ):
        """read-memory at the 'ReVa Test Program' literal returns the expected bytes.

        otool shows the literal pool starts at 0x100000530 with the bytes
        for 'ReVa Test Program\\n\\0'. The hex output must contain the hex
        encoding of that prefix.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "read-memory",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": "0x100000530",
                "length": 19,  # "ReVa Test Program\n\0"
                "format": "both",
            },
        )
        assert not getattr(result, "isError", False), (
            f"read-memory failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        assert data.get("length") == 19, f"Expected length=19; got {data!r}"

        # 'R'=0x52 'e'=0x65 'V'=0x56 'a'=0x61 -> "ReVa" in hex prefix.
        # MemoryUtil.formatHexString separates bytes with spaces.
        hex_str = data.get("hex", "")
        assert hex_str.lower().startswith("52 65 56 61"), (
            f"Expected hex to start with 'ReVa' bytes (52 65 56 61); got {hex_str!r}"
        )

        # bytes field should reconstruct to the literal text via chr().
        byte_list = data.get("bytes", [])
        assert byte_list, f"bytes field missing or empty: {data!r}"
        text = "".join(chr(b) for b in byte_list if b != 0)
        assert "ReVa Test Program" in text, (
            f"Decoded bytes should contain 'ReVa Test Program'; got {text!r}"
        )


class TestBookmarkWorkflow:
    """Verify set-bookmark / get-bookmarks / search-bookmarks / remove-bookmark cycle."""

    async def test_full_bookmark_lifecycle(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Set, query, search, and remove a bookmark on _add.

        Exercises four bookmark tools in one workflow -- the canonical
        navigation/annotation cycle an LLM would use to mark interesting
        addresses for follow-up.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        add_func = await _find_function(mcp_stdio_client, program_path, "add")

        bookmark_comment = "ReVa e2e bookmark sentinel"

        # 1. Set bookmark
        set_result = await mcp_stdio_client.call_tool(
            "set-bookmark",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": add_func["address"],
                "type": "Note",
                "category": "e2e",
                "comment": bookmark_comment,
            },
        )
        assert not getattr(set_result, "isError", False), (
            f"set-bookmark failed: {set_result.content[0].text}"
        )
        set_data = json.loads(set_result.content[0].text)
        assert set_data.get("success") is True, f"set-bookmark not success: {set_data!r}"
        assert set_data.get("comment") == bookmark_comment, (
            f"Bookmark comment should round-trip; got {set_data!r}"
        )
        bookmark_id = set_data.get("id")
        assert bookmark_id is not None, f"Bookmark response missing id: {set_data!r}"

        # 2. get-bookmarks at the address must return our entry
        get_result = await mcp_stdio_client.call_tool(
            "get-bookmarks",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": add_func["address"],
            },
        )
        assert not getattr(get_result, "isError", False), (
            f"get-bookmarks failed: {get_result.content[0].text}"
        )
        get_data = json.loads(get_result.content[0].text)
        comments = [b.get("comment") for b in get_data.get("bookmarks", [])]
        assert bookmark_comment in comments, (
            f"Expected our bookmark comment in get-bookmarks; got {comments!r}"
        )

        # 3. search-bookmarks by comment text must find it.
        # Note: search-bookmarks returns the entries under 'results',
        # whereas get-bookmarks uses 'bookmarks'. Inconsistent on the
        # server side but stable, so the test pins the actual key.
        search_result = await mcp_stdio_client.call_tool(
            "search-bookmarks",
            arguments={
                "programPath": program_path,
                "searchText": "ReVa e2e bookmark",
            },
        )
        assert not getattr(search_result, "isError", False), (
            f"search-bookmarks failed: {search_result.content[0].text}"
        )
        search_data = json.loads(search_result.content[0].text)
        search_comments = [b.get("comment") for b in search_data.get("results", [])]
        assert bookmark_comment in search_comments, (
            f"search-bookmarks should find our bookmark by text; got {search_comments!r}"
        )

        # 4. remove-bookmark
        remove_result = await mcp_stdio_client.call_tool(
            "remove-bookmark",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": add_func["address"],
                "type": "Note",
                "category": "e2e",
            },
        )
        assert not getattr(remove_result, "isError", False), (
            f"remove-bookmark failed: {remove_result.content[0].text}"
        )

        # 5. After remove, the bookmark is gone.
        post_remove = await mcp_stdio_client.call_tool(
            "get-bookmarks",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": add_func["address"],
            },
        )
        post_data = json.loads(post_remove.content[0].text)
        post_comments = [b.get("comment") for b in post_data.get("bookmarks", [])]
        assert bookmark_comment not in post_comments, (
            f"Bookmark should be gone after remove; still see {post_comments!r}"
        )


class TestCallTree:
    """Verify get-call-tree traverses callees recursively from a root."""

    async def test_callee_tree_from_entry(
        self, mcp_stdio_client, isolated_workspace
    ):
        """get-call-tree direction=callees from entry must include the helpers.

        Unlike get-call-graph (which goes both directions to a fixed depth),
        get-call-tree walks one direction with cycle marking. From entry,
        depth=2 callees should include _printf, _add, _multiply.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        entry_func = await _find_function(mcp_stdio_client, program_path, "entry")

        result = await mcp_stdio_client.call_tool(
            "get-call-tree",
            arguments={
                "programPath": program_path,
                "functionAddress": entry_func["address"],
                "direction": "callees",
                "maxDepth": 2,
            },
        )
        assert not getattr(result, "isError", False), (
            f"get-call-tree failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)
        assert data.get("direction") == "callees", (
            f"Expected direction=callees; got {data!r}"
        )

        tree = data.get("tree") or {}
        assert tree.get("name") == "entry", (
            f"Tree root should be entry; got {tree!r}"
        )

        # Walk the tree's immediate callees (depth 1 from root).
        immediate = tree.get("callees", [])
        immediate_names = [c.get("name") for c in immediate]
        for expected in ("_printf", "_add", "_multiply"):
            assert expected in immediate_names, (
                f"Expected {expected!r} in entry's immediate callees; got {immediate_names!r}"
            )


class TestFindVariableAccesses:
    """Verify find-variable-accesses lists reads/writes of a known parameter."""

    async def test_param_1_accesses_in_add(
        self, mcp_stdio_client, isolated_workspace
    ):
        """find-variable-accesses on param_1 of _add must report at least one READ.

        _add(int a, int b) decompiles with synthesized name 'param_1' for
        the first argument. Ghidra's HighFunction may model parameter
        instances as input-only (no WRITE pcode op corresponding to the
        synthetic def), so we don't require a WRITE entry; what we do
        require is that the access list is non-empty, every entry has
        the documented schema, and at least one access is a READ.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        add_func = await _find_function(mcp_stdio_client, program_path, "add")

        # Confirm param_1 is the synthesized name in the unmodified decompilation.
        decomp = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": add_func["name"],
                "limit": 100,
            },
        )
        decomp_text = json.loads(decomp.content[0].text).get("decompilation", "")
        if "param_1" not in decomp_text:
            pytest.skip(
                f"Ghidra synthesised a different parameter name; cannot verify accesses. "
                f"Decompilation:\n{decomp_text}"
            )

        result = await mcp_stdio_client.call_tool(
            "find-variable-accesses",
            arguments={
                "programPath": program_path,
                "functionAddress": add_func["address"],
                "variableName": "param_1",
            },
        )
        assert not getattr(result, "isError", False), (
            f"find-variable-accesses failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        accesses = data.get("accesses", [])
        assert accesses, f"Expected at least one access of param_1; got {data!r}"
        for a in accesses:
            for field in ("address", "accessType"):
                assert field in a, f"Access entry missing {field!r}: {a!r}"

        access_types = {a.get("accessType") for a in accesses}
        assert "READ" in access_types, (
            f"Expected at least one READ of param_1; got accessTypes={access_types!r}"
        )


class TestDataFlowBackward:
    """Verify trace-data-flow-backward returns a populated slice."""

    async def test_backward_trace_in_add_returns_operations(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Backward slice from inside _add must contain operations and metadata.

        Slicing seeds at 0x100000474 (`add w0, w8, w9` inside _add). The
        response must report direction=backward, identify the containing
        function, and list at least one operation with the documented
        per-op schema (address, opcode, optional inputs/output). We do
        not assert specific terminator types: PARAMETER terminators
        require HighParam outputs which Ghidra does not always synthesize
        for register parameters in this fixture, and the test would be
        brittle. The op-list assertion is the stronger signal that the
        slicer ran and produced data.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        # _add is at 0x100000460; +0x14 = 0x100000474 (the `add w0, w8, w9` op).
        result = await mcp_stdio_client.call_tool(
            "trace-data-flow-backward",
            arguments={
                "programPath": program_path,
                "address": "0x100000474",
            },
        )
        assert not getattr(result, "isError", False), (
            f"trace-data-flow-backward failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        assert data.get("direction") == "backward", (
            f"Expected direction=backward; got {data!r}"
        )
        assert data.get("function") in ("_add", "add"), (
            f"Expected containing function _add/add; got {data!r}"
        )
        op_count = data.get("operationCount", 0)
        operations = data.get("operations", [])
        assert op_count >= 1, (
            f"Expected at least one operation in slice; got operationCount={op_count!r}, "
            f"operations={operations!r}"
        )
        assert len(operations) == op_count, (
            f"operations length should match operationCount; got len={len(operations)} vs {op_count}"
        )

        # Every op must have address + opcode at minimum.
        for op in operations:
            assert "address" in op, f"Operation missing address: {op!r}"
            assert "opcode" in op, f"Operation missing opcode: {op!r}"


class TestChangeVariableDatatypes:
    """Verify change-variable-datatypes propagates to decompilation."""

    async def test_change_param_1_to_short_visible_in_decomp(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Changing param_1 of _add to 'short' must appear in re-decompilation.

        Sister to TestSetFunctionPrototype but exercises the variable-level
        type change tool instead of the whole-prototype tool. After the
        change, the second decompilation must show 'short' as the type
        of the first parameter.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        add_func = await _find_function(mcp_stdio_client, program_path, "add")

        # Read decompilation to satisfy the read-before-modify guard and
        # confirm 'param_1' is the synthesized name.
        before = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": add_func["name"],
                "limit": 100,
            },
        )
        before_text = json.loads(before.content[0].text).get("decompilation", "")
        if "param_1" not in before_text:
            pytest.skip(
                f"Synthesised name was not 'param_1'; cannot exercise this scenario. "
                f"Decompilation:\n{before_text}"
            )

        # Apply the type change
        change_result = await mcp_stdio_client.call_tool(
            "change-variable-datatypes",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": add_func["name"],
                "datatypeMappings": {"param_1": "short"},
            },
        )
        assert not getattr(change_result, "isError", False), (
            f"change-variable-datatypes failed: {change_result.content[0].text}"
        )
        change_data = json.loads(change_result.content[0].text)
        assert change_data.get("variablesChanged") is True or change_data.get("changedCount", 0) >= 1, (
            f"Expected variablesChanged=True or changedCount>=1; got {change_data!r}"
        )

        # Re-decompile and verify 'short' appears as a type for param_1
        after = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": add_func["name"],
                "limit": 100,
            },
        )
        after_text = json.loads(after.content[0].text).get("decompilation", "")
        assert "short" in after_text, (
            f"Expected 'short' in decompilation after type change; got:\n{after_text}"
        )


class TestCommentSearch:
    """Verify the set-comment / search-comments / remove-comment cycle."""

    async def test_comment_search_and_remove(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Set a unique comment, find it via search-comments, then remove it.

        Complements the test_e2e_workflow lifecycle test (which only
        verifies set + get-comments) by exercising search-comments and
        remove-comment, plus confirms removal evicts the comment.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        add_func = await _find_function(mcp_stdio_client, program_path, "add")

        sentinel = "ReVa-e2e-comment-sentinel-DEC2025"

        # 1. Set the comment (default eol type)
        set_result = await mcp_stdio_client.call_tool(
            "set-comment",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": add_func["address"],
                "comment": sentinel,
            },
        )
        assert not getattr(set_result, "isError", False), (
            f"set-comment failed: {set_result.content[0].text}"
        )
        set_data = json.loads(set_result.content[0].text)
        assert set_data.get("success") is True, f"set-comment not success: {set_data!r}"

        # 2. search-comments must surface our sentinel.
        search_result = await mcp_stdio_client.call_tool(
            "search-comments",
            arguments={
                "programPath": program_path,
                "searchText": "ReVa-e2e-comment-sentinel",
                "caseSensitive": False,
            },
        )
        assert not getattr(search_result, "isError", False), (
            f"search-comments failed: {search_result.content[0].text}"
        )
        search_data = json.loads(search_result.content[0].text)
        # search-comments returns hits under 'results' (consistent with search-bookmarks).
        results = search_data.get("results", [])
        assert any(sentinel in r.get("comment", "") for r in results), (
            f"Expected sentinel comment in search-comments results; got {results!r}"
        )

        # 3. remove-comment
        remove_result = await mcp_stdio_client.call_tool(
            "remove-comment",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": add_func["address"],
                "commentType": "eol",
            },
        )
        assert not getattr(remove_result, "isError", False), (
            f"remove-comment failed: {remove_result.content[0].text}"
        )

        # 4. Verify the comment is gone via search.
        post_search = await mcp_stdio_client.call_tool(
            "search-comments",
            arguments={
                "programPath": program_path,
                "searchText": "ReVa-e2e-comment-sentinel",
            },
        )
        post_data = json.loads(post_search.content[0].text)
        post_results = post_data.get("results", [])
        assert not any(sentinel in r.get("comment", "") for r in post_results), (
            f"Comment should be gone after remove; still see {post_results!r}"
        )


class TestCounts:
    """Verify the *-count tools return non-zero numbers for an analyzed program."""

    async def test_function_symbol_string_counts(
        self, mcp_stdio_client, isolated_workspace
    ):
        """get-function-count, get-symbols-count, get-strings-count all return >=1.

        Each count tool exposes a different facet of the program. After
        analysis the test_arm64 fixture has at least 4 functions, plenty
        of symbols (entry/_add/_multiply/_printf/__mh_execute_header...),
        and at least one defined string (the printf format strings).
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        async def _count(tool: str, args: dict | None = None) -> int:
            payload = {"programPath": program_path}
            if args:
                payload.update(args)
            res = await mcp_stdio_client.call_tool(tool, arguments=payload)
            assert not getattr(res, "isError", False), (
                f"{tool} failed: {res.content[0].text if res.content else 'no content'}"
            )
            data = json.loads(res.content[0].text)
            assert "count" in data, f"{tool} response missing count field: {data!r}"
            return data["count"]

        function_count = await _count("get-function-count")
        assert function_count >= 4, (
            f"Expected >=4 functions in test_arm64; got {function_count}"
        )

        symbol_count = await _count("get-symbols-count", {"includeExternal": False})
        assert symbol_count >= 4, (
            f"Expected >=4 symbols in test_arm64; got {symbol_count}"
        )

        string_count = await _count("get-strings-count")
        assert string_count >= 1, (
            f"Expected >=1 defined string in test_arm64; got {string_count}"
        )


class TestUndefinedFunctionCandidates:
    """Verify get-undefined-function-candidates responds cleanly."""

    async def test_returns_well_formed_response(
        self, mcp_stdio_client, isolated_workspace
    ):
        """get-undefined-function-candidates must return a valid candidate list.

        After the explicit forceFullAnalysis pass our helper runs, the
        fixture should have all reachable functions defined, so the
        candidate list is expected to be empty or very small. The
        important assertion is that the tool runs without error and
        returns the documented schema.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "get-undefined-function-candidates",
            arguments={"programPath": program_path},
        )
        assert not getattr(result, "isError", False), (
            f"get-undefined-function-candidates failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        # Required top-level fields
        assert "candidates" in data, f"Missing 'candidates' field: {data!r}"
        assert isinstance(data["candidates"], list), (
            f"'candidates' must be a list; got {type(data['candidates']).__name__}"
        )
        # Each candidate must carry the documented per-entry schema.
        for cand in data["candidates"]:
            assert "address" in cand, f"Candidate missing address: {cand!r}"
            assert "hasCallReference" in cand or "hasDataReference" in cand, (
                f"Candidate missing reference flag: {cand!r}"
            )


class TestResolveThunk:
    """Verify resolve-thunk follows a thunk chain to its target."""

    async def test_resolve_printf_stub(
        self, mcp_stdio_client, isolated_workspace
    ):
        """resolve-thunk on the printf stub must yield _printf as the final target.

        The Mach-O __stubs section contains a thunk for _printf at
        0x100000524 (visible in otool output as 'symbol stub for: _printf').
        Resolving the thunk must walk to the external _printf symbol
        and return isResolved=true.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "resolve-thunk",
            arguments={
                "programPath": program_path,
                "address": "0x100000524",
            },
        )
        assert not getattr(result, "isError", False), (
            f"resolve-thunk failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        chain = data.get("chain", [])
        assert chain, f"Expected non-empty thunk chain; got {data!r}"

        for entry in chain:
            assert "name" in entry, f"Chain entry missing name: {entry!r}"

        names = [c.get("name") for c in chain]
        assert any("printf" in (n or "").lower() for n in names), (
            f"Expected '_printf' in resolved thunk chain; got names={names!r}"
        )
        assert data.get("isResolved") is True, (
            f"Expected isResolved=True for printf stub; got {data!r}"
        )


class TestGetData:
    """Verify get-data describes a defined data item."""

    async def test_get_data_at_string_literal(
        self, mcp_stdio_client, isolated_workspace
    ):
        """get-data at the literal pool offset must report a string with ReVa text.

        At 0x100000530 the binary holds 'ReVa Test Program\\n\\0', and
        Ghidra's analyser turns this into a TerminatedCString. get-data
        must surface a non-empty representation containing 'ReVa Test'
        plus length and dataType fields.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "get-data",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": "0x100000530",
            },
        )
        assert not getattr(result, "isError", False), (
            f"get-data failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        for field in ("address", "dataType", "length"):
            assert field in data, f"get-data response missing {field!r}: {data!r}"

        # length is 19 bytes for "ReVa Test Program\n\0".
        assert data.get("length") == 19, (
            f"Expected length=19 for the banner string; got {data!r}"
        )
        # dataType should mention 'string' or 'char' (Ghidra: TerminatedCString).
        dt = (data.get("dataType") or "").lower()
        assert "string" in dt or "char" in dt, (
            f"Expected string-like dataType; got {data.get('dataType')!r}"
        )
        # representation or value must contain the banner text.
        rep = data.get("representation") or data.get("value") or ""
        assert "ReVa Test Program" in rep, (
            f"Expected banner text in get-data representation; got {rep!r} (full data: {data!r})"
        )


class TestSetDecompilationComment:
    """Verify set-decompilation-comment attaches a comment that survives re-decompile."""

    async def test_decomp_line_comment_round_trip(
        self, mcp_stdio_client, isolated_workspace
    ):
        program_path = await _import_and_analyze(mcp_stdio_client)
        add_func = await _find_function(mcp_stdio_client, program_path, "add")

        # Read decompilation first (required by the read-before-modify guard).
        # Also use the line count to pick a valid body line: line 1 is the
        # function signature and has no code address, so we target the last
        # line of the function body instead.
        decomp_read = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": add_func["name"],
                "limit": 100,
            },
        )
        assert decomp_read.content and decomp_read.content[0].text, (
            f"get-decompilation returned no content: {decomp_read!r}"
        )
        decomp_read_data = json.loads(decomp_read.content[0].text)
        # Pick the first code body line.  The decompiler output is:
        #   line 1: (blank)  line 2: signature  line 3: (blank)  line 4: {
        #   line 5+: body statements  line N: }
        # Lines 1-4 have no code address; we need line 5 or later.
        decompilation_text = decomp_read_data.get("decompilation", "")
        display_lines = decompilation_text.split("\n")
        target_line = None
        for raw_line in display_lines:
            # Each line is formatted as "   N\tcontent"
            if "\t" in raw_line:
                parts = raw_line.split("\t", 1)
                try:
                    ln = int(parts[0].strip())
                except ValueError:
                    continue
                content = parts[1].strip() if len(parts) > 1 else ""
                # Skip blank, signature (contains '('), braces
                if content and content not in ("{", "}") and "(" not in content:
                    target_line = ln
                    break
                # Accept lines with '(' if they look like code (contain '=' or 'return')
                if content and ("return" in content or "=" in content):
                    target_line = ln
                    break
        if target_line is None:
            # Last resort: use line 5 (first likely body line for most functions)
            target_line = 5

        sentinel = "ReVa-e2e-decomp-line-sentinel"
        set_result = await mcp_stdio_client.call_tool(
            "set-decompilation-comment",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": add_func["name"],
                "lineNumber": target_line,
                "comment": sentinel,
            },
        )
        assert set_result.content and set_result.content[0].text, (
            f"set-decompilation-comment returned no content"
        )
        set_text = set_result.content[0].text
        # set-decompilation-comment now falls back to the nearest addressable
        # line (LineAddressMatch in DecompilerToolProvider), so it should
        # almost always return a JSON success body. A plain-text error here
        # would mean the function has no addressable code at all, which is
        # a real failure — surface it explicitly rather than masking it.
        if getattr(set_result, "isError", False):
            pytest.fail(
                f"set-decompilation-comment returned isError=True: {set_text!r}"
            )
        try:
            set_data = json.loads(set_text)
        except json.JSONDecodeError:
            pytest.fail(
                f"set-decompilation-comment returned non-JSON content: {set_text!r}"
            )
        assert set_data.get("success") is True, f"set not success: {set_data!r}"

        decomp = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": add_func["name"],
                "limit": 100,
                "includeComments": True,
            },
        )
        assert not getattr(decomp, "isError", False), (
            f"get-decompilation failed: {decomp.content[0].text}"
        )
        decomp_data = json.loads(decomp.content[0].text)
        decomp_text = decomp_data.get("decompilation", "")
        comments_list = decomp_data.get("comments", []) or []
        comment_strs = [c.get("comment", "") if isinstance(c, dict) else str(c) for c in comments_list]
        found = sentinel in decomp_text or any(sentinel in s for s in comment_strs)
        assert found, (
            f"Expected sentinel in decompilation or comments after set-decompilation-comment; "
            f"decomp_text=\n{decomp_text}\ncomments={comment_strs!r}"
        )


class TestFunctionsBySimilarity:
    """Verify get-functions-by-similarity ranks the matching function highest."""

    async def test_search_add_ranks_underscore_add_first(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Searching for 'add' must rank _add at the top of similarity results.

        With test_arm64's small function inventory (entry, _add,
        _multiply, _printf), a similarity search for 'add' should put
        _add ahead of unrelated names. Asserts the schema (similarity
        field) and that _add appears in the top-N.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "get-functions-by-similarity",
            arguments={
                "programPath": program_path,
                "searchString": "add",
                "maxCount": 10,
            },
        )
        assert not getattr(result, "isError", False), (
            f"get-functions-by-similarity failed: {result.content[0].text if result.content else 'no content'}"
        )

        funcs = json.loads(result.content[0].text).get("functions", [])
        assert funcs, f"Expected at least one similarity result; got {result.content!r}"

        for f in funcs:
            assert "similarity" in f, f"Result missing similarity score: {f!r}"
            assert "name" in f, f"Result missing name: {f!r}"

        names = [f.get("name") for f in funcs]
        assert "_add" in names, (
            f"Expected '_add' in similarity results for query 'add'; got {names!r}"
        )
        # _add should be ranked among the top results (within the maxCount returned).
        add_idx = names.index("_add")
        assert add_idx <= 2, (
            f"Expected '_add' near the top of similarity results; ranked at index {add_idx} "
            f"in {names!r}"
        )


class TestValidateCStructure:
    """Verify validate-c-structure parses-without-creating, and rejects bad input."""

    async def test_valid_struct_returns_metadata(self, mcp_stdio_client):
        """A well-formed C struct definition validates and reports its metadata.

        validate-c-structure parses against a temporary standalone DTM and
        does not require a programPath -- the schema explicitly omits it.
        """
        c_def = "struct ValidProbe { int a; int b; char c; };"
        result = await mcp_stdio_client.call_tool(
            "validate-c-structure",
            arguments={
                "cDefinition": c_def,
            },
        )
        assert not getattr(result, "isError", False), (
            f"validate-c-structure failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)
        assert data.get("valid") is True, f"Expected valid=True for well-formed struct; got {data!r}"
        assert data.get("parsedType") == "ValidProbe", (
            f"Expected parsedType=ValidProbe; got {data!r}"
        )
        assert data.get("fieldCount") >= 3, (
            f"Expected fieldCount>=3 (a,b,c); got {data!r}"
        )

    async def test_invalid_struct_returns_validation_error(self, mcp_stdio_client):
        """Garbage input must not pretend to be valid; expect valid=False or isError."""
        result = await mcp_stdio_client.call_tool(
            "validate-c-structure",
            arguments={
                "cDefinition": "this is not C at all },,, ,",
            },
        )
        # Tool may return isError=True OR valid=False JSON. Both are acceptable;
        # the unacceptable outcome is a JSON body with valid=True.
        if getattr(result, "isError", False):
            return
        data = json.loads(result.content[0].text)
        assert data.get("valid") is False, (
            f"Garbage struct must be reported invalid; got {data!r}"
        )


class TestFindCommonCallers:
    """Verify find-common-callers identifies functions that call multiple targets."""

    async def test_entry_is_common_caller_of_add_and_multiply(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Entry calls both _add and _multiply, so it must be the common caller.

        The fixture's main (surfaced as 'entry' for this Mach-O) calls
        _add(2,3) and _multiply(4,5). find-common-callers on those two
        functions must return 'entry' in the common-caller list.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "find-common-callers",
            arguments={
                "programPath": program_path,
                "functionAddresses": ["_add", "_multiply"],
            },
        )
        assert not getattr(result, "isError", False), (
            f"find-common-callers failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        common = data.get("commonCallers", [])
        common_names = [c.get("name") for c in common]
        assert "entry" in common_names, (
            f"Expected 'entry' as common caller of _add and _multiply; got {common_names!r}, "
            f"full response: {data!r}"
        )


class TestListAnalyzers:
    """Verify list-analyzers returns the configured analyzer set."""

    async def test_list_includes_known_analyzer(
        self, mcp_stdio_client, isolated_workspace
    ):
        """list-analyzers must report at least one analyzer with required fields.

        Ghidra ships with many analyzers (DWARF, Demangler, function start
        identification, etc.). The exact set is processor-specific, but
        a populated response is the minimum guarantee.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "list-analyzers",
            arguments={"programPath": program_path},
        )
        assert not getattr(result, "isError", False), (
            f"list-analyzers failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        analyzers = data.get("analyzers", [])
        assert analyzers, f"Expected non-empty analyzer list; got {data!r}"

        for entry in analyzers:
            assert "name" in entry, f"Analyzer entry missing name: {entry!r}"
            # Each analyzer should have the documented schema fields.
            for field in ("type", "priority"):
                assert field in entry, f"Analyzer {entry.get('name')!r} missing {field!r}: {entry!r}"


class TestFindConstantUses:
    """Verify find-constant-uses surfaces immediate operands."""

    async def test_find_uses_of_constant_two(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Constant 2 is loaded as a parameter to _add(2, 3); must appear as a result.

        entry contains `mov w0, #0x2` before the `bl _add` call. The tool
        should report at least one match with the documented schema
        (address, mnemonic, value).
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "find-constant-uses",
            arguments={
                "programPath": program_path,
                "value": "2",
                "maxResults": 100,
            },
        )
        assert not getattr(result, "isError", False), (
            f"find-constant-uses failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        assert data.get("resultCount", 0) >= 1, (
            f"Expected >= 1 use of constant 2 (mov w0, #0x2 in entry); got {data!r}"
        )
        results = data.get("results", [])
        for entry in results:
            for field in ("address", "mnemonic"):
                assert field in entry, f"Result entry missing {field!r}: {entry!r}"


class TestFindConstantsInRange:
    """Verify find-constants-in-range surfaces constants in a numeric window."""

    async def test_find_small_constants_2_through_5(
        self, mcp_stdio_client, isolated_workspace
    ):
        """The fixture passes 2,3,4,5 as arguments to add and multiply.

        A range query for [2,5] must surface multiple unique values within
        that band (entry's call setup uses each).
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "find-constants-in-range",
            arguments={
                "programPath": program_path,
                "minValue": "2",
                "maxValue": "5",
                "maxResults": 200,
            },
        )
        assert not getattr(result, "isError", False), (
            f"find-constants-in-range failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        assert data.get("totalOccurrences", 0) >= 2, (
            f"Expected at least 2 constants in [2,5] for the fixture; got {data!r}"
        )

        unique = data.get("uniqueValues", [])
        unique_decimals = {u.get("decimal") for u in unique}
        # The fixture explicitly uses 2 (add), 3 (add), 4 (multiply), 5 (multiply).
        # Allow some leeway -- the lower constants may map to different operand
        # representations under aarch64. Require at least two of the four to
        # show up so a regression that drops the constant search would still
        # be visible.
        expected = {2, 3, 4, 5}
        observed = expected & unique_decimals
        assert len(observed) >= 2, (
            f"Expected at least 2 of {expected!r} in unique values; got {unique_decimals!r}"
        )


class TestApplyDataType:
    """Verify apply-data-type retypes a memory location."""

    async def test_apply_char_array_to_string_literal(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Apply 'char[19]' to 0x100000530 and verify get-data reflects the new type.

        After analysis the literal pool offset already carries a string type;
        apply-data-type with clearExisting semantics should replace it with
        the requested char-array type. Confirms via a follow-up get-data
        call that the new dataType reports an array of chars with length 19.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        apply_result = await mcp_stdio_client.call_tool(
            "apply-data-type",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": "0x100000530",
                "dataTypeString": "char[19]",
            },
        )
        assert not getattr(apply_result, "isError", False), (
            f"apply-data-type failed: {apply_result.content[0].text if apply_result.content else 'no content'}"
        )
        apply_data = json.loads(apply_result.content[0].text)
        assert apply_data.get("success") is True, f"apply-data-type not success: {apply_data!r}"
        assert apply_data.get("length") == 19, (
            f"Expected length=19 for char[19]; got {apply_data!r}"
        )

        # Verify with get-data that the type is now an array form.
        check = await mcp_stdio_client.call_tool(
            "get-data",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": "0x100000530",
            },
        )
        check_data = json.loads(check.content[0].text)
        dt = (check_data.get("dataType") or "").lower()
        assert "char" in dt and ("[" in dt or "array" in dt), (
            f"Expected array-of-char type after apply-data-type; got dataType={check_data.get('dataType')!r}"
        )
        assert check_data.get("length") == 19, (
            f"get-data length should be 19 after applying char[19]; got {check_data!r}"
        )


@pytest.mark.skip(
    reason="get-current-program is GUI-only; ProjectToolProvider.registerTools "
    "guards it behind `if (!headlessMode)`, so it is not registered in stdio "
    "mode. Kept for documentation of the intentional limitation."
)
class TestGetCurrentProgram:
    """Verify get-current-program reports the imported program's metadata."""

    async def test_returns_imported_program_info(
        self, mcp_stdio_client, isolated_workspace
    ):
        """After import+analyze, get-current-program must describe the open program.

        Asserts the response carries the documented fields (programPath,
        language, functionCount, etc.) and that functionCount matches the
        analysed binary's actual function count from get-function-count.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "get-current-program",
            arguments={},
        )
        assert not getattr(result, "isError", False), (
            f"get-current-program failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        for field in ("programPath", "language", "compilerSpec", "functionCount", "symbolCount"):
            assert field in data, f"get-current-program response missing {field!r}: {data!r}"

        assert data.get("programPath") == program_path, (
            f"Expected programPath={program_path!r}; got {data.get('programPath')!r}"
        )
        # AArch64 Mach-O fixture
        lang = data.get("language", "").lower()
        assert "aarch64" in lang or "arm" in lang, (
            f"Expected ARM64-ish language id; got {data.get('language')!r}"
        )
        assert data.get("functionCount", 0) >= 4, (
            f"Expected >=4 functions; got functionCount={data.get('functionCount')!r}"
        )


@pytest.mark.skip(
    reason="list-open-programs is GUI-only; ProjectToolProvider.registerTools "
    "guards it behind `if (!headlessMode)`, so it is not registered in stdio "
    "mode. Kept for documentation of the intentional limitation."
)
class TestListOpenPrograms:
    """Verify list-open-programs surfaces the freshly-imported program."""

    async def test_imported_program_appears_in_open_list(
        self, mcp_stdio_client, isolated_workspace
    ):
        """After import+analyze, the program must appear in list-open-programs.

        Validates the multi-content response shape (metadata first, then
        per-program entries) and asserts the imported programPath is among
        the open entries.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "list-open-programs",
            arguments={},
        )
        assert not getattr(result, "isError", False), (
            f"list-open-programs failed: {result.content[0].text if result.content else 'no content'}"
        )

        assert result.content, "Empty response from list-open-programs"
        payload = json.loads(result.content[0].text)
        assert payload.get("count", 0) >= 1, (
            f"Expected count>=1 in payload; got {payload!r}"
        )

        programs = payload.get("programs", [])
        program_paths = [p.get("programPath") for p in programs]
        assert program_path in program_paths, (
            f"Expected {program_path!r} in open programs list; got {program_paths!r}"
        )


class TestStructureDeletion:
    """Verify the parse-c-structure / get-structure-info / delete-structure cycle."""

    async def test_create_inspect_delete_struct(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Parse a struct, inspect its layout, delete it, and confirm it's gone.

        Exercises three structure tools (parse-c-structure, get-structure-info,
        delete-structure) plus list-structures as the post-delete check. The
        struct is unreferenced (never applied), so delete should succeed
        without needing force=True.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        struct_name = "RevaE2EDeletable"
        c_def = (
            "struct " + struct_name + " {"
            "    char tag[4];"
            "    int size;"
            "};"
        )

        # 1. Create
        parse_result = await mcp_stdio_client.call_tool(
            "parse-c-structure",
            arguments={
                "programPath": program_path,
                "cDefinition": c_def,
            },
        )
        assert not getattr(parse_result, "isError", False), (
            f"parse-c-structure failed: {parse_result.content[0].text}"
        )

        # 2. get-structure-info should report the layout
        info_result = await mcp_stdio_client.call_tool(
            "get-structure-info",
            arguments={
                "programPath": program_path,
                "structureName": struct_name,
            },
        )
        assert not getattr(info_result, "isError", False), (
            f"get-structure-info failed: {info_result.content[0].text}"
        )
        info_data = json.loads(info_result.content[0].text)
        assert info_data.get("name") == struct_name, (
            f"Expected name={struct_name!r}; got {info_data!r}"
        )
        # tag[4] + int = 8 bytes
        assert info_data.get("size") == 8, (
            f"Expected size=8 (char[4] + int); got {info_data!r}"
        )
        field_names = [f.get("fieldName") for f in info_data.get("fields", [])]
        assert "tag" in field_names and "size" in field_names, (
            f"Expected tag,size in fields; got {field_names!r}"
        )

        # 3. delete-structure (no references -> no force needed)
        delete_result = await mcp_stdio_client.call_tool(
            "delete-structure",
            arguments={
                "programPath": program_path,
                "structureName": struct_name,
            },
        )
        assert not getattr(delete_result, "isError", False), (
            f"delete-structure failed: {delete_result.content[0].text}"
        )

        # 4. Confirm gone via list-structures with name filter
        list_result = await mcp_stdio_client.call_tool(
            "list-structures",
            arguments={
                "programPath": program_path,
                "nameFilter": struct_name,
            },
        )
        list_data = json.loads(list_result.content[0].text)
        names = [s.get("name") for s in list_data.get("structures", [])]
        assert struct_name not in names, (
            f"Struct should be deleted but still appears in list-structures: {names!r}"
        )


class TestMemoryBlocks:
    """Verify get-memory-blocks returns the Mach-O segments with sane fields."""

    async def test_returns_text_segment_with_executable_flag(
        self, mcp_stdio_client, isolated_workspace
    ):
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "get-memory-blocks",
            arguments={"programPath": program_path},
        )
        assert not getattr(result, "isError", False), (
            f"get-memory-blocks failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        blocks = data.get("blocks", [])
        assert blocks, f"Expected at least one memory block; got {data!r}"

        # Required fields per MemoryToolProvider response shape.
        for block in blocks:
            for key in ("name", "start", "end", "size", "readable", "writable",
                        "executable", "initialized"):
                assert key in block, f"Block missing {key!r}: {block!r}"
            assert block["start"].startswith("0x"), (
                f"Address should be 0x-prefixed: {block['start']!r}"
            )

        # Mach-O ARM64 binaries have a __TEXT segment with executable code.
        # Match on common Mach-O segment/section names.
        executable_blocks = [b for b in blocks if b.get("executable")]
        assert executable_blocks, (
            f"Expected at least one executable block on Mach-O; got names={[b['name'] for b in blocks]}"
        )


class TestDataTypeArchives:
    """Verify get-data-type-archives lists at least the program and built-in archives."""

    async def test_lists_program_and_builtin_archives(
        self, mcp_stdio_client, isolated_workspace
    ):
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "get-data-type-archives",
            arguments={"programPath": program_path},
        )
        assert not getattr(result, "isError", False), (
            f"get-data-type-archives failed: {result.content[0].text}"
        )

        # Response packs metadata + entries; collect from all content items
        # the same way many ReVa tools do.
        archives: list[dict] = []
        for content in result.content:
            try:
                payload = json.loads(content.text)
            except (json.JSONDecodeError, AttributeError):
                continue
            if isinstance(payload, list):
                archives.extend(p for p in payload if isinstance(p, dict))
            elif isinstance(payload, dict):
                if "archives" in payload:
                    archives.extend(payload["archives"])
                else:
                    archives.append(payload)

        assert archives, f"Expected at least one archive entry; got {result.content!r}"

        types_seen = {a.get("type") for a in archives if isinstance(a, dict)}
        assert "BUILT_IN" in types_seen, (
            f"Expected BUILT_IN archive in results; got types={types_seen!r}"
        )
        assert "PROGRAM" in types_seen, (
            f"Expected PROGRAM archive in results; got types={types_seen!r}"
        )


class TestDataTypeByString:
    """Verify get-data-type-by-string parses common type strings."""

    async def test_parses_int_pointer(self, mcp_stdio_client, isolated_workspace):
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "get-data-type-by-string",
            arguments={
                "programPath": program_path,
                "dataTypeString": "int *",
            },
        )
        assert not getattr(result, "isError", False), (
            f"get-data-type-by-string('int *') failed: {result.content[0].text}"
        )
        data = json.loads(result.content[0].text)
        # DataTypeParserUtil.createDataTypeInfo populates name + length at minimum.
        assert "name" in data, f"Expected 'name' in response; got {data!r}"
        # Pointer width is architecture-dependent; ARM64 -> 8 bytes.
        if "length" in data:
            assert data["length"] == 8, (
                f"int* on ARM64 should be 8 bytes; got {data['length']}"
            )


class TestListExports:
    """Verify list-exports finds Mach-O exported symbols."""

    async def test_test_arm64_exports_include_main_or_start(
        self, mcp_stdio_client, isolated_workspace
    ):
        """The test_arm64 fixture is a Mach-O executable, which exports its
        entry point under names like '_main', 'start', or '_mh_execute_header'.
        Mach-O always has at least one export; if list-exports returns 0,
        either the tool is broken or Mach-O export collection regressed.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "list-exports",
            arguments={"programPath": program_path},
        )
        assert not getattr(result, "isError", False), (
            f"list-exports failed: {result.content[0].text}"
        )
        data = json.loads(result.content[0].text)

        assert "totalCount" in data, f"Missing totalCount: {data!r}"
        assert data["totalCount"] >= 1, (
            f"Mach-O executable should have at least one export; got totalCount={data['totalCount']}"
        )
        exports = data.get("exports", [])
        assert exports, f"exports list should be non-empty: {data!r}"

        names = [e.get("name", "") for e in exports]
        # Mach-O executables export at least _main or start or _mh_execute_header.
        # Lower-case match to handle future capitalization changes.
        names_lower = [n.lower() for n in names]
        assert any(
            "main" in n or "start" in n or "mh_execute_header" in n
            for n in names_lower
        ), f"Expected main/start/mh_execute_header in exports; got {names!r}"


class TestListBookmarkCategories:
    """Verify list-bookmark-categories surfaces a category we just created."""

    async def test_set_bookmark_then_list_includes_category(
        self, mcp_stdio_client, isolated_workspace
    ):
        program_path = await _import_and_analyze(mcp_stdio_client)

        bookmark_category = "ReVa-e2e-categories-test"
        bookmark_type = "Note"
        set_result = await mcp_stdio_client.call_tool(
            "set-bookmark",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": "entry",
                "type": bookmark_type,
                "category": bookmark_category,
                "comment": "category lookup smoke test",
            },
        )
        assert not getattr(set_result, "isError", False), (
            f"set-bookmark failed: {set_result.content[0].text}"
        )

        list_result = await mcp_stdio_client.call_tool(
            "list-bookmark-categories",
            arguments={
                "programPath": program_path,
                "type": bookmark_type,
            },
        )
        assert not getattr(list_result, "isError", False), (
            f"list-bookmark-categories failed: {list_result.content[0].text}"
        )
        data = json.loads(list_result.content[0].text)

        assert data.get("type") == bookmark_type
        categories = data.get("categories", [])
        names = [c.get("name") for c in categories]
        assert bookmark_category in names, (
            f"Expected our category in list; got {names!r}"
        )

        # The matching entry should have count >= 1.
        match = next((c for c in categories if c.get("name") == bookmark_category), None)
        assert match and match.get("count", 0) >= 1, (
            f"Category entry should report count>=1; got {match!r}"
        )


class TestListCommonConstants:
    """Verify list-common-constants returns a structured response (may be empty for tiny binaries)."""

    async def test_response_shape_is_well_formed(
        self, mcp_stdio_client, isolated_workspace
    ):
        """The test_arm64 fixture is small enough that not every default-filtered
        constant tier may be hit, so this test focuses on the response *shape*
        being well-formed: programPath echoed, a list under the documented key,
        and consistent counts. We also pin includeSmallValues=True to make this
        reliable across architectures and optimization levels.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "list-common-constants",
            arguments={
                "programPath": program_path,
                "topN": 20,
                "includeSmallValues": True,
            },
        )
        assert not getattr(result, "isError", False), (
            f"list-common-constants failed: {result.content[0].text}"
        )
        data = json.loads(result.content[0].text)

        assert data.get("programPath") == program_path, (
            f"programPath should be echoed back; got {data!r}"
        )
        # Either "constants" or "results" — pin the actual key so a regression
        # (or a refactor that changes it) surfaces. We accept either, then
        # assert it was non-empty.
        constants_key = next(
            (k for k in ("constants", "results", "topConstants") if k in data),
            None,
        )
        assert constants_key, (
            f"Response missing constants list under known keys; got keys={list(data.keys())}"
        )
        constants = data[constants_key]
        assert isinstance(constants, list), (
            f"Constants payload should be a list; got {type(constants)}"
        )

        # With includeSmallValues=True, even a tiny ARM64 binary has a few
        # immediates worth reporting. Allow 0 to keep this resilient on
        # exotic targets but flag a likely regression.
        if not constants:
            pytest.fail(
                f"Expected at least one common constant on test_arm64 with "
                f"includeSmallValues=True; got empty list. Full response: {data!r}"
            )


class TestParseCHeader:
    """Verify parse-c-header creates a structure that becomes queryable via list-structures."""

    async def test_parse_simple_struct_appears_in_listing(
        self, mcp_stdio_client, isolated_workspace
    ):
        program_path = await _import_and_analyze(mcp_stdio_client)

        struct_name = "ReVaParseHeaderTest"
        header = (
            f"struct {struct_name} {{\n"
            f"    int field_a;\n"
            f"    int field_b;\n"
            f"}};\n"
        )
        parse_result = await mcp_stdio_client.call_tool(
            "parse-c-header",
            arguments={
                "programPath": program_path,
                "headerContent": header,
            },
        )
        assert not getattr(parse_result, "isError", False), (
            f"parse-c-header failed: {parse_result.content[0].text}"
        )
        parse_data = json.loads(parse_result.content[0].text)
        assert parse_data.get("createdCount", 0) >= 1, (
            f"Expected >=1 created type; got {parse_data!r}"
        )

        # Verify via list-structures with a name filter.
        list_result = await mcp_stdio_client.call_tool(
            "list-structures",
            arguments={
                "programPath": program_path,
                "nameFilter": struct_name,
            },
        )
        assert not getattr(list_result, "isError", False), (
            f"list-structures failed: {list_result.content[0].text}"
        )
        list_data = json.loads(list_result.content[0].text)
        names = [s.get("name") for s in list_data.get("structures", [])]
        assert struct_name in names, (
            f"Struct {struct_name!r} not found after parse-c-header. Names seen: {names!r}"
        )


class TestGetReferencersDecompiled:
    """Verify get-referencers-decompiled returns the calling function for a known import."""

    async def test_referencers_of_printf_include_entry(
        self, mcp_stdio_client, isolated_workspace
    ):
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "get-referencers-decompiled",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": "_printf",
                "maxReferencers": 10,
            },
        )
        assert not getattr(result, "isError", False), (
            f"get-referencers-decompiled failed: {result.content[0].text}"
        )

        # Response collects metadata + per-referencer decompilations across
        # multiple content items. We just need to find one entry that names
        # the calling function (entry, _main, start, etc).
        all_text = "\n".join(c.text for c in result.content if hasattr(c, "text"))
        assert "entry" in all_text or "_main" in all_text or "start" in all_text, (
            f"Expected entry function in printf referencers output; got:\n{all_text[:1000]}"
        )


async def _find_symbol_matching(client, program_path: str, needle: str, max_count: int = 1500) -> dict | None:
    """Return the first symbol whose name contains needle (case-insensitive).

    Helper for tests that need to look up addresses for symbols Ghidra
    auto-creates (e.g. demangled C++ vtable / typeinfo names) without
    knowing the exact mangled or demangled form up-front.
    """
    needle_l = needle.lower()
    result = await client.call_tool(
        "get-symbols",
        arguments={"programPath": program_path, "maxCount": max_count},
    )
    if getattr(result, "isError", False):
        return None
    for sym in json.loads(result.content[0].text).get("symbols", []):
        name = (sym.get("name") or "").lower()
        if needle_l in name:
            return sym
    return None


class TestVtablesOnCppFixture:
    """Verify vtable tools work on a real C++ binary (test_cpp_arm64).

    The fixture is built from tests/fixtures/test_cpp_program.cpp:
    Animal (abstract) <- Dog, Cat, with an indirect dispatch helper.
    Compiled with clang++ -O0 -fno-inline -arch arm64.
    """

    async def test_analyze_dog_vtable_lists_virtual_methods(
        self, mcp_stdio_client, isolated_workspace
    ):
        """analyze-vtable returns entries naming Dog's virtual method overrides.

        The Itanium C++ ABI vtable layout begins with a top-offset
        (signed integer, 8 bytes on 64-bit) followed by a typeinfo
        pointer; the function pointer block starts 0x10 bytes after the
        symbol address Ghidra exports for "_ZTV3Dog" / "vtable for Dog".
        analyze-vtable's heuristic walks raw memory and gives up after a
        couple of non-function pointers, so calling it at the symbol
        address yields just the top-offset slot. Probe both the symbol
        address and symbol+0x10 and accept whichever gives us entries
        with real function names — that way the test stays valid even if
        a future Ghidra version exports the function-pointer block as
        the primary vtable symbol.
        """
        program_path = await _import_and_analyze(mcp_stdio_client, "test_cpp_arm64")

        sym = await _find_symbol_matching(mcp_stdio_client, program_path, "vtable for Dog")
        if sym is None:
            # Mangled Itanium form. Ghidra emits this with double
            # underscore on Mach-O ("__ZTV3Dog"); substring match
            # on "_ZTV3Dog" finds either form.
            sym = await _find_symbol_matching(mcp_stdio_client, program_path, "_ZTV3Dog")
        assert sym is not None, (
            "Could not find Dog vtable symbol. Either Ghidra's RTTI/demangler "
            "analysis did not run, or the fixture changed."
        )

        # Try the symbol address and symbol+0x10 (post top-offset + typeinfo).
        symbol_addr = int(sym["address"], 16)
        candidates = [
            sym["address"],
            f"0x{symbol_addr + 0x10:x}",
        ]
        names: list[str] = []
        for addr in candidates:
            result = await mcp_stdio_client.call_tool(
                "analyze-vtable",
                arguments={
                    "programPath": program_path,
                    "vtableAddress": addr,
                    "maxEntries": 50,
                },
            )
            assert not getattr(result, "isError", False), (
                f"analyze-vtable @ {addr} failed: {result.content[0].text}"
            )
            data = json.loads(result.content[0].text)
            entries = data.get("entries", [])
            names = [
                (e.get("functionName") or "").lower()
                for e in entries
                if e.get("functionName")
            ]
            if names:
                break

        assert any("legs" in n for n in names), (
            f"Expected Dog::legs in vtable entries from one of {candidates!r}; "
            f"got names={names!r}"
        )
        assert any("speak" in n for n in names), (
            f"Expected Dog::speak in vtable entries from one of {candidates!r}; "
            f"got names={names!r}"
        )

    async def test_find_vtables_containing_dog_legs(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Dog::legs() is a virtual override; find-vtables-containing-function
        called on its address must find at least Dog's vtable.
        """
        program_path = await _import_and_analyze(mcp_stdio_client, "test_cpp_arm64")

        # Find Dog::legs by name. Ghidra's demangler produces names like
        # "Dog::legs" (or "Dog::legs(void) const" depending on version).
        sym = await _find_symbol_matching(mcp_stdio_client, program_path, "Dog::legs")
        if sym is None:
            sym = await _find_symbol_matching(mcp_stdio_client, program_path, "_ZNK3Dog4legsEv")
        assert sym is not None, (
            "Could not find Dog::legs symbol (demangled or mangled). Re-build fixture."
        )

        result = await mcp_stdio_client.call_tool(
            "find-vtables-containing-function",
            arguments={
                "programPath": program_path,
                "functionAddress": sym["address"],
            },
        )
        assert not getattr(result, "isError", False), (
            f"find-vtables-containing-function failed: {result.content[0].text}"
        )
        data = json.loads(result.content[0].text)

        vtables = data.get("vtables", [])
        assert vtables, (
            f"Expected at least one vtable containing Dog::legs; got {data!r}"
        )
        # Each entry must carry the documented schema: vtableAddress + slotIndex.
        for vt in vtables:
            assert "vtableAddress" in vt and "slotIndex" in vt, (
                f"Vtable entry missing required fields: {vt!r}"
            )

    @pytest.mark.parametrize(
        "fixture_name",
        ["test_cpp_arm64", "test_cpp_x86_64"],
        ids=["arm64", "x86_64"],
    )
    async def test_dispatch_decompilation_shows_both_virtual_calls(
        self, mcp_stdio_client, isolated_workspace, fixture_name
    ):
        """get-decompilation of dispatch() must produce a function body that
        renders both vtable indirect calls. Canonical Ghidra output for
        Itanium ABI vtable dispatch on this fixture is:

            iVar1 = (**(code **)(*(long *)param_1 + 0x10))();   // legs
            iVar2 = (**(code **)(*(long *)param_1 + 0x18))();   // speak

        We assert both vtable slot offsets (0x10 and 0x18) appear in the
        body — that's the strongest single-test signal that:
          * the decompiler ran without erroring
          * it identified the parameter as a pointer-to-vtable
          * it resolved both call sites at distinct slot offsets
        Skipping any of these would fail this assertion.
        """
        program_path = await _import_and_analyze(mcp_stdio_client, fixture_name)

        result = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": "dispatch",
                "limit": 100,
            },
        )
        assert not getattr(result, "isError", False), (
            f"get-decompilation failed on {fixture_name}: "
            f"{result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        body = data.get("decompilation", "")
        assert body, f"Empty decompilation for dispatch on {fixture_name}: {data!r}"

        # Both slot offsets must appear in the body. The decompiler may
        # render them as `0x10`/`0x18` or via decimal/struct-field syntax
        # depending on Ghidra version, so accept either notation.
        for offset_hex, offset_dec in [("0x10", "16"), ("0x18", "24")]:
            assert (offset_hex in body) or (offset_dec in body), (
                f"Expected slot offset {offset_hex} ({offset_dec}) to appear "
                f"in dispatch body on {fixture_name}; full body:\n{body}"
            )

        # The two distinct offsets imply two distinct call sites — match a
        # range of indirect-call rendering styles Ghidra emits.
        indirect_call_markers = ("(**(code", "(**(", "->", "(*pvt")
        marker_hits = sum(body.count(m) for m in indirect_call_markers)
        assert marker_hits >= 2, (
            f"Expected at least 2 indirect-call markers in dispatch body on "
            f"{fixture_name} (one per virtual method); got marker_hits={marker_hits} "
            f"in body:\n{body}"
        )

    @pytest.mark.parametrize(
        "fixture_name",
        ["test_cpp_arm64", "test_cpp_x86_64"],
        ids=["arm64", "x86_64"],
    )
    async def test_find_vtable_callers_finds_dispatch_site(
        self, mcp_stdio_client, isolated_workspace, fixture_name
    ):
        """find-vtable-callers on Dog::legs must find the dispatch() site
        on both ARM64 and x86_64.

        The fixture's dispatch() function calls a->legs() through an
        Animal* base pointer — the canonical vtable indirect call. The
        instruction patterns differ by ISA:

          ARM64:   ldr x8, [x9, #0x10]  ; load slot from vtable
                   blr x8               ; indirect call
          x86_64:  call qword ptr [rax + 0x10]   ; load+call inline

        Pcode-based offset extraction handles both: it walks the call's
        function-pointer varnode back through pcode (within the call
        instruction for x86/x64's inline form, across instructions in the
        same basic block for ARM64's split form) until it finds the LOAD
        whose address is `register [+ const]` and extracts that const.
        Running the same assertion across both fixtures is the canary
        that the extraction stays architecture-agnostic.
        """
        program_path = await _import_and_analyze(mcp_stdio_client, fixture_name)

        sym = await _find_symbol_matching(mcp_stdio_client, program_path, "Dog::legs")
        if sym is None:
            sym = await _find_symbol_matching(mcp_stdio_client, program_path, "_ZNK3Dog4legsEv")
        assert sym is not None, f"Could not find Dog::legs symbol in {fixture_name}"

        result = await mcp_stdio_client.call_tool(
            "find-vtable-callers",
            arguments={
                "programPath": program_path,
                "functionAddress": sym["address"],
                "maxResults": 50,
            },
        )
        assert not getattr(result, "isError", False), (
            f"find-vtable-callers failed on {fixture_name}: {result.content[0].text}"
        )
        data = json.loads(result.content[0].text)

        assert data.get("programPath") == program_path
        assert "vtables" in data and data["vtables"], (
            f"Expected at least one vtable for Dog::legs on {fixture_name}; got {data!r}"
        )
        callers = data.get("potentialCallers", [])
        assert callers, (
            f"Expected at least one potential caller on {fixture_name} "
            f"(dispatch() calls a->legs() indirectly through the Animal vtable); "
            f"got potentialCallers={callers!r}, full response: {data!r}"
        )

        caller_funcs = {c.get("function", "") for c in callers}
        assert any("dispatch" in (f or "") for f in caller_funcs), (
            f"Expected 'dispatch' among caller functions on {fixture_name}; "
            f"got {caller_funcs!r}"
        )


class TestChangeProcessorValidation:
    """Verify change-processor rejects an unknown languageId without altering state.

    Calling change-processor with a real, working language would mutate the
    fixture's analysis. Exercising the error path (invalid languageId) covers
    the parameter-validation and language-lookup branches without ever
    swapping the program's language out from under us.
    """

    async def test_rejects_unknown_language_id(
        self, mcp_stdio_client, isolated_workspace
    ):
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "change-processor",
            arguments={
                "programPath": program_path,
                "languageId": "NONEXISTENT:LE:64:default",
            },
        )
        assert getattr(result, "isError", False), (
            f"change-processor with bogus languageId should return isError=True; "
            f"got isError=False with body: "
            f"{result.content[0].text if result.content else 'no content'}"
        )

        # Sanity check: error message names something meaningful — the bogus id,
        # the word 'language', or 'not found'-style language-lookup failure.
        msg = (result.content[0].text if result.content else "").lower()
        assert (
            "nonexistent" in msg
            or "language" in msg
            or "not found" in msg
            or "invalid" in msg
        ), f"Error message should mention language/lookup failure; got {msg!r}"


class TestCaptureRevaDebugInfo:
    """Verify capture-reva-debug-info produces a debug zip and reports its path."""

    async def test_returns_debug_zip_path(
        self, mcp_stdio_client, isolated_workspace
    ):
        """The tool writes a zip to disk and reports the absolute path.
        We don't assert specific zip contents (those depend on environment)
        but we do require the path exists, points to a non-empty zip file,
        and the response carries the documented schema.
        """
        # No need to import a program; the tool captures global ReVa state.
        result = await mcp_stdio_client.call_tool(
            "capture-reva-debug-info",
            arguments={"message": "e2e characterization run"},
        )
        assert not getattr(result, "isError", False), (
            f"capture-reva-debug-info failed: {result.content[0].text}"
        )
        data = json.loads(result.content[0].text)

        assert data.get("success") is True, f"success=True expected; got {data!r}"
        zip_path = data.get("debugZipPath")
        assert zip_path, f"debugZipPath should be present; got {data!r}"

        path_obj = Path(zip_path)
        assert path_obj.exists(), f"Reported debug zip does not exist on disk: {zip_path}"
        assert path_obj.is_file(), f"Debug zip path is not a file: {zip_path}"
        assert path_obj.stat().st_size > 0, f"Debug zip is empty: {zip_path}"

        # The response also carries a human-readable message we can sanity-check.
        assert "captured" in (data.get("message") or "").lower(), (
            f"Expected 'captured' in message; got {data!r}"
        )

        # Best-effort cleanup so tests don't accumulate zips on disk.
        try:
            path_obj.unlink()
        except OSError:
            pass


class TestGetDataTypes:
    """Verify get-data-types lists fundamental built-in types."""

    async def test_builtin_archive_includes_int_and_char(
        self, mcp_stdio_client, isolated_workspace
    ):
        """The BUILT_IN data type manager must always have at least 'int' and
        'char' — these are sentinel types every Ghidra build ships with.
        Response is multi-JSON: metadata first, then per-type entries.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "get-data-types",
            arguments={
                "programPath": program_path,
                "archiveName": "BuiltInTypes",  # Built-in archive name
                "categoryPath": "/",
                "includeSubcategories": True,
                "maxCount": 500,
            },
        )
        assert not getattr(result, "isError", False), (
            f"get-data-types failed: {result.content[0].text if result.content else 'no content'}"
        )

        payload = json.loads(result.content[0].text)
        assert payload.get("archiveName") == "BuiltInTypes"
        assert payload.get("totalCount", 0) > 0, (
            f"BUILT_IN archive should have non-zero totalCount; got {payload!r}"
        )

        names = [
            entry.get("name", "")
            for entry in payload.get("dataTypes", [])
            if isinstance(entry, dict)
        ]

        # Built-in archive always carries fundamental scalar types.
        names_lower = [n.lower() for n in names]
        assert any("int" == n for n in names_lower) or any("int" in n for n in names_lower), (
            f"Expected 'int' in built-in types; got first 30: {names[:30]!r}"
        )
        assert any("char" == n for n in names_lower) or any("char" in n for n in names_lower), (
            f"Expected 'char' in built-in types; got first 30: {names[:30]!r}"
        )


class TestCreateFunctionValidation:
    """Verify create-function rejects requests at addresses where a function already exists."""

    async def test_rejects_existing_function_address(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Calling create-function on the entry point of an analyzed function
        must error with a clear message naming the existing function. This
        exercises the "function already exists" guard in
        FunctionToolProvider.registerCreateFunctionTool.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        add_func = await _find_function(mcp_stdio_client, program_path, "add")

        result = await mcp_stdio_client.call_tool(
            "create-function",
            arguments={
                "programPath": program_path,
                "address": add_func["address"],
            },
        )
        # Expecting an error path. With MCP isError convention the body is
        # plain text, so we only need to check isError + the error message.
        assert getattr(result, "isError", False), (
            f"create-function on an existing function should error; "
            f"got isError=False with body: {result.content[0].text if result.content else 'no content'}"
        )
        msg = result.content[0].text if result.content else ""
        assert "already exists" in msg.lower(), (
            f"Error should mention 'already exists'; got {msg!r}"
        )


class TestTraceDataFlowForward:
    """Verify trace-data-flow-forward returns a non-empty operations list inside _add."""

    async def test_forward_flow_from_add_instruction(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Forward slice from the `add w0, w8, w9` op at 0x100000474 inside _add.

        The function entry (0x100000460) is the prologue and has no varnodes
        to trace — the tool would correctly report "no data flow information"
        there. We seed at the same address as the backward-flow test so this
        pair exercises FORWARD/BACKWARD on a known instruction.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        # _add is at 0x100000460; +0x14 = 0x100000474 (the `add w0, w8, w9` op).
        result = await mcp_stdio_client.call_tool(
            "trace-data-flow-forward",
            arguments={
                "programPath": program_path,
                "address": "0x100000474",
            },
        )
        assert not getattr(result, "isError", False), (
            f"trace-data-flow-forward failed: {result.content[0].text if result.content else 'no content'}"
        )
        data = json.loads(result.content[0].text)

        assert data.get("direction") == "forward", (
            f"Expected direction=forward; got {data!r}"
        )
        assert data.get("function") in ("_add", "add"), (
            f"Expected containing function _add/add; got {data!r}"
        )
        operations = data.get("operations", [])
        op_count = data.get("operationCount", 0)
        assert op_count >= 1 and len(operations) == op_count, (
            f"Expected non-empty operations list with matching count; "
            f"got operationCount={op_count}, operations={operations!r}"
        )
        for op in operations:
            assert "address" in op and "opcode" in op, f"Op missing fields: {op!r}"


async def _import_two_and_analyze(client, fixture_a: str, fixture_b: str) -> tuple[str, str]:
    """Import two distinct fixtures into the same MCP session and analyze each.

    Returns (path_a, path_b). Used by multi-program isolation tests to
    verify that operations on one program never leak into the other —
    the canonical multi-program workflow ReVa is designed for.
    """
    path_a = await _import_and_analyze(client, fixture_a)
    path_b = await _import_and_analyze(client, fixture_b)
    assert path_a != path_b, (
        f"Both imports produced identical programPath {path_a!r}; "
        f"the project may have collapsed them into one program."
    )
    return path_a, path_b


class TestMultiProgramIsolation:
    """Verify operations are correctly scoped to programPath when multiple
    programs share the same MCP session.

    Picks two fixtures with overlapping symbol names (entry, _printf in
    test_arm64 vs test_x86_64) so naming alone can't disambiguate — only
    a real per-program lookup keeps them straight.
    """

    async def test_decompilation_returns_per_program_addresses(
        self, mcp_stdio_client, isolated_workspace
    ):
        """get-decompilation of `entry` in two programs must return distinct
        addresses and bodies. If the tool ever caches by symbol name without
        the programPath as part of the key, this test catches it.
        """
        path_a, path_b = await _import_two_and_analyze(
            mcp_stdio_client, "test_arm64", "test_x86_64"
        )

        async def decomp(path):
            r = await mcp_stdio_client.call_tool(
                "get-decompilation",
                arguments={"programPath": path, "functionNameOrAddress": "entry", "limit": 50},
            )
            assert not getattr(r, "isError", False), (
                f"get-decompilation failed on {path}: {r.content[0].text}"
            )
            return json.loads(r.content[0].text)

        a, b = await decomp(path_a), await decomp(path_b)
        assert a.get("address") != b.get("address"), (
            f"`entry` in two distinct programs returned identical address — "
            f"programPath was probably ignored. a={a.get('address')!r} "
            f"b={b.get('address')!r}"
        )
        # ARM64 and x86_64 produce decidedly different decompiled bodies
        # (different parameter shapes, different printf-call sites, etc).
        # If the tool returned the SAME body for both, that's a clear leak.
        body_a = a.get("decompilation", "")
        body_b = b.get("decompilation", "")
        assert body_a != body_b, (
            "Decompiled bodies of `entry` are identical across architectures — "
            "tool likely returned a cached result for the wrong program."
        )

    async def test_comments_do_not_bleed_across_programs(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Setting a comment on program A's `entry` must not change comments
        on program B's `entry`. ReVa's comment storage is in Ghidra's listing
        per-program, so this should hold — but if any layer ever caches by
        symbol or address without programPath qualification, this fails.
        """
        path_a, path_b = await _import_two_and_analyze(
            mcp_stdio_client, "test_arm64", "test_x86_64"
        )

        sentinel = "ReVa-isolation-test-comment-{0}".format(id(self))

        # Set comment in A only.
        set_r = await mcp_stdio_client.call_tool(
            "set-comment",
            arguments={
                "programPath": path_a,
                "addressOrSymbol": "entry",
                "comment": sentinel,
            },
        )
        assert not getattr(set_r, "isError", False), (
            f"set-comment failed on {path_a}: {set_r.content[0].text}"
        )

        # Comment should be present in A.
        comments_a = await mcp_stdio_client.call_tool(
            "get-comments",
            arguments={"programPath": path_a, "addressOrSymbol": "entry"},
        )
        a_data = json.loads(comments_a.content[0].text)
        a_strs = [c.get("comment", "") for c in a_data.get("comments", [])]
        assert any(sentinel in s for s in a_strs), (
            f"Comment did not appear in A after set-comment; got {a_strs!r}"
        )

        # Comment must NOT be present in B.
        comments_b = await mcp_stdio_client.call_tool(
            "get-comments",
            arguments={"programPath": path_b, "addressOrSymbol": "entry"},
        )
        b_data = json.loads(comments_b.content[0].text)
        b_strs = [c.get("comment", "") for c in b_data.get("comments", [])]
        assert not any(sentinel in s for s in b_strs), (
            f"Comment from program A leaked into program B's `entry` "
            f"comments: {b_strs!r}"
        )

    async def test_bookmarks_do_not_bleed_across_programs(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Bookmark created on program A must not appear in program B's
        bookmark search. Bookmark categories live in Ghidra's per-program
        BookmarkManager, but exercise it explicitly.
        """
        path_a, path_b = await _import_two_and_analyze(
            mcp_stdio_client, "test_arm64", "test_x86_64"
        )

        category = "ReVa-isolation-bookmarks"

        set_r = await mcp_stdio_client.call_tool(
            "set-bookmark",
            arguments={
                "programPath": path_a,
                "addressOrSymbol": "entry",
                "type": "Note",
                "category": category,
                "comment": "isolation canary",
            },
        )
        assert not getattr(set_r, "isError", False), (
            f"set-bookmark failed: {set_r.content[0].text}"
        )

        # Category must show up in A.
        a_cats = await mcp_stdio_client.call_tool(
            "list-bookmark-categories",
            arguments={"programPath": path_a, "type": "Note"},
        )
        a_data = json.loads(a_cats.content[0].text)
        a_names = [c.get("name") for c in a_data.get("categories", [])]
        assert category in a_names, f"Category not in A: {a_names!r}"

        # Category must NOT show up in B.
        b_cats = await mcp_stdio_client.call_tool(
            "list-bookmark-categories",
            arguments={"programPath": path_b, "type": "Note"},
        )
        b_data = json.loads(b_cats.content[0].text)
        b_names = [c.get("name") for c in b_data.get("categories", [])]
        assert category not in b_names, (
            f"Bookmark category from A leaked into B: {b_names!r}"
        )

    async def test_read_before_modify_tracker_per_program(
        self, mcp_stdio_client, isolated_workspace
    ):
        """The decompiler's read-before-modify guard tracks reads keyed by
        `programPath:address`. Reading function X in program A must NOT
        let you modify the same-named function in program B without first
        reading B's copy.
        """
        path_a, path_b = await _import_two_and_analyze(
            mcp_stdio_client, "test_arm64", "test_x86_64"
        )

        # Read A's `entry` decompilation. This stamps the tracker for A.
        r_a = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={"programPath": path_a, "functionNameOrAddress": "entry", "limit": 50},
        )
        assert not getattr(r_a, "isError", False), (
            f"get-decompilation A failed: {r_a.content[0].text}"
        )

        # Try to rename a variable in B's `entry` WITHOUT reading B first.
        # The guard must reject this even though we read program A.
        rename_r = await mcp_stdio_client.call_tool(
            "rename-variables",
            arguments={
                "programPath": path_b,
                "functionNameOrAddress": "entry",
                "variableMappings": {"_does_not_exist_": "_renamed_"},
            },
        )
        assert getattr(rename_r, "isError", False), (
            f"rename on B should have been rejected (B never read), "
            f"but got isError=False with body: "
            f"{rename_r.content[0].text if rename_r.content else 'no content'}"
        )
        msg = (rename_r.content[0].text if rename_r.content else "").lower()
        assert "read" in msg or "decompilation" in msg, (
            f"Error should mention read-before-modify; got {msg!r}"
        )


class TestRoundTripIntegrity:
    """Verify state-modifying tools return exactly what was written.

    These tests catch silent-truncation / silent-overwrite / silent-duplicate
    bugs where the tool reports success but the on-disk representation
    diverges from the input. Substring matches in earlier tests would miss
    these — these pin exact strings, ids, and counts.
    """

    async def test_set_comment_exact_text_round_trip(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Set a comment containing punctuation, unicode, and a newline; the
        retrieved comment must match byte-for-byte. Most existing tests use
        substring matches, which would miss truncation, escaping bugs, or
        normalization-on-write.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        # Tricky payload: ASCII + UTF-8 + literal newline + escaped chars.
        # Avoiding the JSON-RPC framing characters {"} but exercising the
        # MCP transport layer's round-trip fidelity.
        payload = "Round-trip: alpha=α, β=β, line1\nline2 — em-dash, tab\there."

        set_r = await mcp_stdio_client.call_tool(
            "set-comment",
            arguments={
                "programPath": program_path,
                "addressOrSymbol": "entry",
                "comment": payload,
            },
        )
        assert not getattr(set_r, "isError", False), (
            f"set-comment failed: {set_r.content[0].text}"
        )

        get_r = await mcp_stdio_client.call_tool(
            "get-comments",
            arguments={"programPath": program_path, "addressOrSymbol": "entry"},
        )
        data = json.loads(get_r.content[0].text)
        comments = [c.get("comment", "") for c in data.get("comments", [])]
        assert payload in comments, (
            f"Comment did not round-trip exactly. Wrote {payload!r}, "
            f"got back {comments!r}"
        )

    async def test_set_comment_twice_overwrites(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Setting two comments at the same address with the same commentType
        must overwrite, not accumulate. The Ghidra Listing.setComment API
        replaces the comment at that (address, type) pair; verify the tool
        does not accidentally bypass that by appending.

        Defaults: set-comment uses commentType=PRE if not specified — so two
        sequential calls hit the same slot and the second wins.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        first = "ReVa-roundtrip-first"
        second = "ReVa-roundtrip-second-overwrite"

        for text in (first, second):
            r = await mcp_stdio_client.call_tool(
                "set-comment",
                arguments={
                    "programPath": program_path,
                    "addressOrSymbol": "entry",
                    "comment": text,
                },
            )
            assert not getattr(r, "isError", False), (
                f"set-comment({text!r}) failed: {r.content[0].text}"
            )

        get_r = await mcp_stdio_client.call_tool(
            "get-comments",
            arguments={"programPath": program_path, "addressOrSymbol": "entry"},
        )
        comments = [
            c.get("comment", "")
            for c in json.loads(get_r.content[0].text).get("comments", [])
        ]
        assert second in comments, (
            f"Second comment missing after overwrite: {comments!r}"
        )
        # First comment must NOT linger. Either the slot was overwritten (no
        # `first` anywhere) or the tool incorrectly appended (both visible).
        assert first not in comments, (
            f"First comment still present after second set-comment — "
            f"tool is appending instead of overwriting. comments={comments!r}"
        )

    async def test_remove_bookmark_then_remove_again(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Removing a bookmark by (address, type, category) must succeed once;
        a second remove with the same args must return an error (the bookmark
        is gone). The tool keys removal on the lookup tuple — there's no
        bookmark id parameter — so the second call must surface "not found"
        rather than silently succeed.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        category = "ReVa-roundtrip-remove"
        bookmark_args = {
            "programPath": program_path,
            "addressOrSymbol": "entry",
            "type": "Note",
            "category": category,
        }

        # Create the bookmark.
        set_r = await mcp_stdio_client.call_tool(
            "set-bookmark",
            arguments={**bookmark_args, "comment": "to be removed"},
        )
        assert not getattr(set_r, "isError", False), (
            f"set-bookmark failed: {set_r.content[0].text}"
        )

        # First remove succeeds.
        rm1 = await mcp_stdio_client.call_tool(
            "remove-bookmark", arguments=bookmark_args
        )
        assert not getattr(rm1, "isError", False), (
            f"first remove-bookmark failed: {rm1.content[0].text}"
        )

        # Second remove must surface failure (isError=True). Silently
        # succeeding would mask state drift between the tool and Ghidra's
        # listing.
        rm2 = await mcp_stdio_client.call_tool(
            "remove-bookmark", arguments=bookmark_args
        )
        assert getattr(rm2, "isError", False), (
            f"Second remove-bookmark on a removed bookmark should error; "
            f"got isError=False with body: "
            f"{rm2.content[0].text if rm2.content else 'no content'}"
        )
        msg = (rm2.content[0].text if rm2.content else "").lower()
        assert "no bookmark" in msg or "not found" in msg, (
            f"Error should mention bookmark not found; got {msg!r}"
        )


class TestPaginationEdgeCases:
    """Verify pagination tools handle out-of-range and degenerate inputs.

    Most pagination bugs hide at boundaries — startIndex == totalCount,
    startIndex past the end, maxCount=0, maxCount > totalCount. These
    rarely surface in normal use but are common AI-generated args (the
    model picks a number, doesn't always check bounds).
    """

    async def test_get_functions_start_index_past_end(
        self, mcp_stdio_client, isolated_workspace
    ):
        """startIndex larger than totalCount must produce a clean empty page,
        not an error and not a wrap-around. The tool should still report
        totalCount accurately so the caller knows pagination is exhausted.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        # Capture totalCount on a normal call first.
        baseline = await mcp_stdio_client.call_tool(
            "get-functions",
            arguments={"programPath": program_path, "maxCount": 500},
        )
        assert not getattr(baseline, "isError", False), (
            f"baseline get-functions failed: {baseline.content[0].text}"
        )
        meta = json.loads(baseline.content[0].text)
        total = meta.get("totalCount") or meta.get("total") or 0
        assert total > 0, f"Fixture should have functions; got meta={meta!r}"

        # Now ask for a page well past the end.
        far_past = total + 10_000
        result = await mcp_stdio_client.call_tool(
            "get-functions",
            arguments={
                "programPath": program_path,
                "startIndex": far_past,
                "maxCount": 50,
            },
        )
        assert not getattr(result, "isError", False), (
            f"get-functions with startIndex past end should NOT error; got "
            f"isError=True with body: {result.content[0].text}"
        )

        m2 = json.loads(result.content[0].text)
        assert m2.get("totalCount") == total or m2.get("total") == total, (
            f"totalCount should be stable across pagination; baseline={total}, "
            f"far-past={m2!r}"
        )
        # No entries past the end, and the metadata's returnedCount must agree.
        entry_count = len(m2.get("functions", []))
        reported = m2.get("returnedCount", entry_count)
        assert entry_count == 0 and reported == 0, (
            f"Expected 0 returned items past end; got reported={reported}, "
            f"actual entries={entry_count}, meta={m2!r}"
        )

    async def test_get_functions_max_count_one_returns_exactly_one(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Boundary: maxCount=1 must return exactly one function entry, not
        zero (off-by-one in the loop bound) and not all of them (forgotten
        clamp).
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "get-functions",
            arguments={"programPath": program_path, "maxCount": 1},
        )
        assert not getattr(result, "isError", False), (
            f"get-functions maxCount=1 failed: {result.content[0].text}"
        )

        funcs = json.loads(result.content[0].text).get("functions", [])
        entry_count = sum(
            1 for entry in funcs if isinstance(entry, dict) and "name" in entry
        )
        assert entry_count == 1, (
            f"maxCount=1 should yield exactly one function entry; got {entry_count}"
        )

    async def test_get_strings_pagination_partition_matches_full_listing(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Pagination must be a strict partition of the full listing: when we
        slice the strings list into two halves via startIndex+maxCount and
        concatenate, we should recover (at least as a multiset) what a single
        large maxCount call returned. Catches duplication, skipped items,
        and stable-sort regressions.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        full_r = await mcp_stdio_client.call_tool(
            "get-strings",
            arguments={"programPath": program_path, "maxCount": 1000},
        )
        assert not getattr(full_r, "isError", False), (
            f"get-strings full failed: {full_r.content[0].text}"
        )
        # get-strings packs metadata + entries into a single JSON list in
        # content[0].text per the existing TestStringDiscovery pattern.
        full_payload = json.loads(full_r.content[0].text)
        if isinstance(full_payload, list):
            # First entry is metadata; rest are strings.
            full_strings = [
                e for e in full_payload[1:]
                if isinstance(e, dict) and "content" in e
            ]
        else:
            full_strings = full_payload.get("strings", [])

        if len(full_strings) < 2:
            pytest.skip(
                f"Fixture has only {len(full_strings)} strings; partition test "
                "needs at least 2 to be meaningful."
            )

        midpoint = len(full_strings) // 2

        async def page(start, count):
            r = await mcp_stdio_client.call_tool(
                "get-strings",
                arguments={
                    "programPath": program_path,
                    "startIndex": start,
                    "maxCount": count,
                },
            )
            assert not getattr(r, "isError", False), (
                f"get-strings(start={start}, count={count}) failed: "
                f"{r.content[0].text}"
            )
            payload = json.loads(r.content[0].text)
            if isinstance(payload, list):
                return [
                    e for e in payload[1:]
                    if isinstance(e, dict) and "content" in e
                ]
            return payload.get("strings", [])

        page_a = await page(0, midpoint)
        page_b = await page(midpoint, len(full_strings) - midpoint)

        # Concatenated pages must cover the full listing (as a multiset on
        # the `content` + `address` pair, which uniquely identifies a string).
        def key(s):
            return (s.get("address"), s.get("content"))

        full_keys = sorted(key(s) for s in full_strings)
        paged_keys = sorted(key(s) for s in (page_a + page_b))
        assert full_keys == paged_keys, (
            f"Pagination partition does not match full listing.\n"
            f"full ({len(full_keys)}): {full_keys[:5]}...\n"
            f"paged ({len(paged_keys)}): {paged_keys[:5]}...\n"
            f"missing from paged: {set(full_keys) - set(paged_keys)}\n"
            f"extras in paged: {set(paged_keys) - set(full_keys)}"
        )


class TestInputValidation:
    """Verify tools reject malformed input cleanly via isError=True.

    With the stdio bridge now propagating isError correctly, tools that
    used to "appear to succeed" with error text in body now properly
    surface validation failures. These tests pin that contract for the
    most common AI-generated mistakes: empty/nonexistent programPath,
    unknown function name, missing required parameter.
    """

    async def test_nonexistent_program_path_returns_helpful_error(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Per CLAUDE.md: 'When a program cannot be found, the error message
        will include suggestions of available programs.' Pin that contract.
        Imports a real program first so 'available programs' is non-empty.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)
        assert program_path  # imported, but we won't use this path

        bogus = "/this/program/definitely/does/not/exist"
        result = await mcp_stdio_client.call_tool(
            "get-functions",
            arguments={"programPath": bogus, "maxCount": 10},
        )
        assert getattr(result, "isError", False), (
            f"get-functions on a nonexistent programPath should return isError=True; "
            f"got isError=False with body: "
            f"{result.content[0].text if result.content else 'no content'}"
        )
        msg = (result.content[0].text if result.content else "").lower()
        assert "not found" in msg or "no program" in msg or bogus.lower() in msg, (
            f"Error should name the missing path or say 'not found'; got {msg!r}"
        )
        # CLAUDE.md promises suggestions of available programs are included.
        # The just-imported program's basename should appear in the body.
        basename = program_path.lstrip("/").lower()
        assert basename in msg, (
            f"Error message should suggest the available program {basename!r}; "
            f"got {msg!r}"
        )

    async def test_get_decompilation_unknown_function_returns_error(
        self, mcp_stdio_client, isolated_workspace
    ):
        """A clearly-bogus function name should produce isError=True with a
        message that names the missing function (so an AI caller can correct
        course rather than silently accept a default).
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        bogus = "_this_function_does_not_exist_zzz"
        result = await mcp_stdio_client.call_tool(
            "get-decompilation",
            arguments={
                "programPath": program_path,
                "functionNameOrAddress": bogus,
                "limit": 10,
            },
        )
        assert getattr(result, "isError", False), (
            f"get-decompilation on bogus function should error; got isError=False "
            f"with body: {result.content[0].text if result.content else 'no content'}"
        )
        msg = (result.content[0].text if result.content else "").lower()
        assert bogus.lower() in msg or "not found" in msg, (
            f"Error should name the missing function; got {msg!r}"
        )

    async def test_set_comment_missing_required_parameter_rejected(
        self, mcp_stdio_client, isolated_workspace
    ):
        """Omitting `addressOrSymbol` (required) must trip the input
        validator and return isError=True. The MCP SDK's jsonschema check
        runs before the handler, so the error names the missing field.
        """
        program_path = await _import_and_analyze(mcp_stdio_client)

        result = await mcp_stdio_client.call_tool(
            "set-comment",
            arguments={
                "programPath": program_path,
                # addressOrSymbol intentionally omitted.
                "comment": "should never land",
            },
        )
        assert getattr(result, "isError", False), (
            f"set-comment without addressOrSymbol should error; got isError=False "
            f"with body: {result.content[0].text if result.content else 'no content'}"
        )
        msg = (result.content[0].text if result.content else "").lower()
        assert "addressorsymbol" in msg or "required" in msg, (
            f"Error should mention the missing required field; got {msg!r}"
        )

    async def test_get_functions_empty_program_path_rejected(
        self, mcp_stdio_client, isolated_workspace
    ):
        """An empty-string programPath is functionally a missing parameter —
        it can't resolve to a program. Tool must reject, not silently
        operate on the first program in the cache.
        """
        # No need to import; empty-string lookup must fail regardless.
        result = await mcp_stdio_client.call_tool(
            "get-functions",
            arguments={"programPath": "", "maxCount": 10},
        )
        assert getattr(result, "isError", False), (
            f"get-functions with empty programPath should error; got isError=False "
            f"with body: {result.content[0].text if result.content else 'no content'}"
        )
