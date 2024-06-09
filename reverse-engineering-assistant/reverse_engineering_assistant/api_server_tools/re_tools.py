"""
If you are looking here to see why your tool is not being loaded
you should check it is imported below. We import this file from
`assistant_api_server.py`, which is the thing launched by Ghidra.

When these classes are imported, it triggers the `register_tool`
decorator and this puts the tool in the global list of tools defined
in `assistant.py`.
"""

from reverse_engineering_assistant.api_server_tools.re_tool_box.decompilation import RevaDecompilation
from reverse_engineering_assistant.api_server_tools.re_tool_box.cross_reference import RevaCrossReferenceTool
from reverse_engineering_assistant.api_server_tools.re_tool_box.symbols import RevaGetSymbols, RevaSetSymbolName
from reverse_engineering_assistant.api_server_tools.re_tool_box.cursor import RevaGetCursor
from reverse_engineering_assistant.api_server_tools.re_tool_box.comment import RevaSetComment
from reverse_engineering_assistant.api_server_tools.re_tool_box.data import RevaData
from reverse_engineering_assistant.api_server_tools.re_tool_box.bookmarks import RevaBookmarks