from typing import Dict, List
import logging

import grpc

from reverse_engineering_assistant.tool import AssistantProject
from reverse_engineering_assistant.assistant import AssistantProject, register_tool
from reverse_engineering_assistant.reva_exceptions import RevaToolException
from reverse_engineering_assistant.api_server_tools import RevaRemoteTool
from langchain_core.language_models.base import BaseLanguageModel

from reverse_engineering_assistant.protocol import RevaGetDecompilation_pb2_grpc, RevaGetDecompilation_pb2
from reverse_engineering_assistant.protocol import RevaComment_pb2_grpc, RevaComment_pb2


@register_tool
class RevaSetComment(RevaRemoteTool):
    """
    A tool for setting comments on addresses, functions and symbols.
    """

    def __init__(self, project: AssistantProject, llm: BaseLanguageModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for setting comments on addresses, functions and symbols"

        self.tool_functions = [
            self.set_comment,
            self.set_multiple_comments,
        ]

    def set_multiple_comments(self, comments: Dict[str, str]) -> List[str]:
        """
        Set multiple comments at the same time.
        Keys are addresses or symbols, values are the comments to set at that location.
        This is more efficient than calling set_comment multiple times.
        """
        outputs: List[str] = []

        for address_or_symbol, comment in comments.items():
            outputs.append(self.set_comment(address_or_symbol=address_or_symbol, comment=comment))

        return outputs

    def set_comment(self, address_or_symbol: str, comment: str) -> str:
        """
        Set the comment at the given address, function or symbol to `comment`.
        Use this when you want to add an explanation or note to a specific part
        of the code.
        """
        stub = RevaComment_pb2_grpc.RevaCommentServiceStub(self.channel)

        request = RevaComment_pb2.RevaSetCommentRequest()
        request.comment = comment
        address, symbol = self.resolve_to_address_and_symbol(address_or_symbol)

        if address:
            request.address = address
        if symbol:
            request.symbol = symbol

        try:
            response: RevaComment_pb2.RevaSetCommentResponse = stub.SetComment(request)
        except grpc.RpcError as e:
            raise RevaToolException(f"Failed to set comment: {e}")
        return "Set comment successfully"
