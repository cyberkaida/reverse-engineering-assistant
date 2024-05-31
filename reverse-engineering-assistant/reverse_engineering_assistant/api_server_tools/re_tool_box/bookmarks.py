from typing import Dict, List
import logging

import grpc

from reverse_engineering_assistant.tool import AssistantProject
from reverse_engineering_assistant.assistant import AssistantProject, register_tool
from reverse_engineering_assistant.reva_exceptions import RevaToolException
from reverse_engineering_assistant.api_server_tools import RevaRemoteTool
from langchain_core.language_models.base import BaseLanguageModel
from reverse_engineering_assistant.protocol import RevaBookmark_pb2, RevaBookmark_pb2_grpc


@register_tool
class RevaBookmarks(RevaRemoteTool):

    def __init__(self, project: AssistantProject, llm: BaseLanguageModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for managing bookmarks in the program"

        self.tool_functions = [
            self.get_bookmarks,
            self.add_bookmark,
        ]

    def get_bookmarks(self) -> List[Dict[str, str]]:
        """
        Return a list of Ghidra bookmarks in the program.
        Use this to keep track of important locations in the program the user
        has marked.
        """
        stub = RevaBookmark_pb2_grpc.RevaBookmarkStub(self.channel)

        request = RevaBookmark_pb2.RevaGetBookmarksRequest()

        bookmarks: List[Dict[str, str]] = []
        for bookmark in stub.get_bookmarks(request):
            bookmarks.append({
                "address": bookmark.address,
                "category": bookmark.category,
                "description": bookmark.description,
            })
        return bookmarks

    def add_bookmark(self, address_or_symbol: str, category: str, description: str) -> str:
        """
        Add a Ghidra bookmark at the given address or symbol with the given category and description.
        If the category does not exist, it will be created. Use a category to group bookmarks together.
        Make sure your category is descriptive and useful to the user.
        """
        stub = RevaBookmark_pb2_grpc.RevaBookmarkStub(self.channel)

        request = RevaBookmark_pb2.RevaAddBookmarkRequest()
        request.category = f"ReVa.{category}"
        request.description = description
        request.address, _ = self.resolve_to_address_and_symbol(address_or_symbol)

        response = stub.add_bookmark(request)

        return "Added bookmark successfully"