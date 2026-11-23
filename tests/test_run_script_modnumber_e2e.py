"""E2E check that a run-script change moves Program.getModificationNumber().

The decompilation cache validates entries against the program modification
number. The Java integration harness cannot drive run-script (the Python
runtime is only wired up under PyGhidra), so this source is covered here.
See src/test.slow/java/reva/decompiler/ModificationNumberIntegrationTest.java
for every other change source.
"""

import pytest

from tests.test_run_script_e2e import _import_test_program, _parse

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.slow,
    pytest.mark.asyncio(loop_scope="session"),
    pytest.mark.timeout(240),
]

NEW_NAME = "reva_cache_renamed"


async def _run(client, program_path: str, code: str) -> dict:
    result = await client.call_tool(
        "run-script",
        arguments={"programPath": program_path, "code": code, "timeoutSeconds": 30},
    )
    return _parse(result)


async def _read_state(client, program_path: str) -> tuple[int, str]:
    data = await _run(
        client,
        program_path,
        "f = next(currentProgram.getFunctionManager().getFunctions(True))\n"
        "print('MODNUM=' + str(currentProgram.getModificationNumber()))\n"
        "print('FNAME=' + f.getName())\n",
    )
    assert data["success"] is True, f"state read failed: {data}"
    out = data["stdout"]
    modnum = int(out.split("MODNUM=", 1)[1].split()[0])
    name = out.split("FNAME=", 1)[1].split()[0]
    return modnum, name


class TestRunScriptModificationNumber:
    async def test_run_script_change_moves_number(
        self, mcp_stdio_client_isolated
    ):
        """A function rename made by run-script raises the modification number.

        Uses its own server and project (mcp_stdio_client_isolated): the rename is never undone, so it
        must not touch a program other tests share."""
        program_path = await _import_test_program(mcp_stdio_client_isolated, analyze=True)

        before, old_name = await _read_state(mcp_stdio_client_isolated, program_path)
        assert old_name != NEW_NAME

        data = await _run(
            mcp_stdio_client_isolated,
            program_path,
            "from ghidra.program.model.symbol import SourceType\n"
            "f = next(currentProgram.getFunctionManager().getFunctions(True))\n"
            f"f.setName('{NEW_NAME}', SourceType.USER_DEFINED)\n",
        )
        assert data["success"] is True, f"rename script failed: {data}"

        after, new_name = await _read_state(mcp_stdio_client_isolated, program_path)
        assert new_name == NEW_NAME, "the rename must really have happened"
        assert after > before, (
            f"modification number did not move: before={before} after={after}"
        )
