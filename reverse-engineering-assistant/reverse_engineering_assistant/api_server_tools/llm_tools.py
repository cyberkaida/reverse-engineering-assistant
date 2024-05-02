from typing import Dict, List, Optional

from sympy import N
from ..assistant_api_server import get_channel

from ..reva_exceptions import RevaToolException
import threading
import logging

from ..protocol.RevaChat_pb2_grpc import RevaChatServiceServicer
from ..protocol.RevaChat_pb2 import RevaChatMessage, RevaChatMessageResponse

from functools import cache
from ..assistant import ReverseEngineeringAssistant

class RevaChat(RevaChatServiceServicer):

    @cache
    def get_assistant(self, project: str) -> ReverseEngineeringAssistant:
        assistant = ReverseEngineeringAssistant(project)
        return assistant

    def sendMessageStream(self, request_iterator, context):
        # let's grab a reference to our assistant

        for request in request_iterator:
            assistant = self.get_assistant(request.project)
            print(request)

            llm_response = assistant.query(request.message)
            response = RevaChatMessageResponse()
            response.message = llm_response
            yield response


@register_message_handler
class HandleGetNewVariableName(RevaMessageHandler):
    handles_type = RevaGetNewVariableName
    def run(self, callback_handler: RevaCallbackHandler) -> RevaGetNewVariableNameResponse:
        # Extract the content and ask the LLM what it thinks...
        raise NotImplementedError("This function is not implemented yet.")
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