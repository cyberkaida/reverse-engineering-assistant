from typing import Any, ContextManager, List
from functools import cache
import mcp
from mcp.server.fastmcp import FastMCP

import pyghidra

if not pyghidra.started():
    pyghidra.start()

from ghidra.program.flatapi import FlatProgramAPI

# Initialize FastMCP server
mcp = FastMCP("RevA")

# Define some base tools

def open_file(file_path: str) -> ContextManager[FlatProgramAPI]:
    return pyghidra.open_program(file_path)

mcp.tool()
def get_program_strings(file_path: str) -> List[str]:
    """
    Analyze a program and return the strings for that program.
    """
    with open_file(file_path) as program:
        return list(program.getStrings())


def main():
    mcp.run(transport='stdio')

if __name__ == "__main__":
    # Initialize and run the server
    main()