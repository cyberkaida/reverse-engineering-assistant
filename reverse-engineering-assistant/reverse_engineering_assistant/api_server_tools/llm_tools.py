from typing import Dict, List, Optional
from ..assistant_api_server import register_message_handler, RevaMessageHandler, RevaCallbackHandler
from ..tool_protocol import (
    RevaExplain,
    RevaGetNewVariableName,
    RevaGetNewVariableNameResponse,
    RevaGetNewSymbolName,
    RevaGetNewSymbolNameResponse,
    RevaExplain,
    RevaExplainResponse,
    RevaLocation,
)

from ..reva_exceptions import RevaToolException
import threading
import logging


@register_message_handler
class HandleGetNewVariableName(RevaMessageHandler):
    handles_type = RevaGetNewVariableName
    def run(self, callback_handler: RevaCallbackHandler) -> RevaGetNewVariableNameResponse:
        # Extract the content and ask the LLM what it thinks...
        assert isinstance(callback_handler.message, RevaGetNewVariableName)
        message: RevaGetNewVariableName = callback_handler.message
        question = f"""
        Examine the function {message.function_name} in detail and rename the following variable:
        {message.variable}
        """
        # Block until ReVa finishes analysis.
        _ = self.assistant.query(question)
        response = RevaGetNewVariableNameResponse(response_to=message.message_id)
        return response

@register_message_handler
class HandleGetNewSymbolName(RevaMessageHandler):
    handles_type = RevaGetNewSymbolName
    def run(self, callback_handler: RevaCallbackHandler) -> RevaGetNewSymbolNameResponse:
        # Extract the content and ask the LLM what it thinks...
        assert isinstance(callback_handler.message, RevaGetNewSymbolName)
        message: RevaGetNewSymbolName = callback_handler.message
        question = f"""
        Examine {message.symbol_name} and rename it to something descriptive using the `set_sybmol_name` function.
        """
        # Block until ReVa finishes analysis.
        _ = self.assistant.query(question)
        response = RevaGetNewSymbolNameResponse(response_to=message.message_id)
        return response

@register_message_handler
class HandleExplain(RevaMessageHandler):
    handles_type = RevaExplain
    def run(self, callback_handler: RevaCallbackHandler) -> RevaExplainResponse:
        # Extract the content and ask the LLM what it thinks...
        assert isinstance(callback_handler.message, RevaExplain)
        message: RevaExplain = callback_handler.message
        question = f"""
        Explain the following location in detail, leave comments as needed.
        """

        location: RevaLocation = message.location

        if message.location is not None:
            question += f"\n{message.location}"
        # Block until ReVa finishes analysis.
        threading.Thread(target=self.assistant.query, args=(question,)).start()
        return RevaExplainResponse(response_to=message.message_id)