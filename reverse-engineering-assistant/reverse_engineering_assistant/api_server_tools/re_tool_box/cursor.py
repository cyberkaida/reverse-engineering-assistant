from typing import Dict, List, Union
import logging

import grpc

from reverse_engineering_assistant.tool import AssistantProject
from reverse_engineering_assistant.assistant import AssistantProject, register_tool
from reverse_engineering_assistant.reva_exceptions import RevaToolException
from reverse_engineering_assistant.api_server_tools import RevaRemoteTool
from reverse_engineering_assistant.model import RevaModel
from reverse_engineering_assistant.protocol import RevaGetCursor_pb2, RevaGetCursor_pb2_grpc


@register_tool
class RevaGetCursor(RevaRemoteTool):

    def __init__(self, project: AssistantProject, llm: RevaModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for getting and setting the cursor or when the user mentions 'this'"

        self.tool_functions = [
            self.get_cursor,
        ]

    def get_cursor(self) -> Dict[str, Union[str, int]]:
        """
        Return the current location the user is looking at in the program.
        Use this to find the current function, symbol or address. When the user mentions "this",
        you should find the current location using this function.

        This method returns a dictionary with the keys "address", "symbol", and "function".
        Use other tools to gather context around this location. For example, decompile
        the function to find the exact code at this location in the listing or decompilation.
        """
        stub = RevaGetCursor_pb2_grpc.RevaGetCursorStub(self.channel)

        request = RevaGetCursor_pb2.RevaGetCursorRequest()

        response = stub.getCursor(request)

        return {
            "address": response.address,
            "symbol": response.symbol,
            "function": response.function,
        }
