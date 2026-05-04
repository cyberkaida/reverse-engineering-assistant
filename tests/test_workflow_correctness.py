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
        # Multi-content shape: metadata + function entries.
        filtered_names = []
        for content in filtered.content[1:]:
            try:
                func = json.loads(content.text)
            except (json.JSONDecodeError, AttributeError):
                continue
            filtered_names.append(func.get("name"))
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
