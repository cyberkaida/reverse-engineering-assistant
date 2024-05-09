

from ast import Call
import queue
import threading
from typing import Callable
from venv import logger

from ..protocol.RevaChat_pb2_grpc import RevaChatServiceServicer
from ..protocol.RevaChat_pb2 import RevaChatMessageResponse

from functools import cache
from ..assistant import ReverseEngineeringAssistant

import logging
module_logger = logging.getLogger("reva-server")

from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_core.agents import AgentAction, AgentFinish

class RevaActionCollector(BaseCallbackHandler):
    """
    A callback handler for logging agent actions in the reverse engineering assistant.

    This class logs agent actions and calls a callback. This is what prints the green
    thoughts from the model to the console. This is very useful for the analyst to understand
    what the model is doing (and is arguably the most important part of the assistant output!)

    Attributes:
        callback (Callable[[str], None]): The callback function to call when an agent action is performed.
        logger (logging.Logger): The logger instance for the reverse_engineering_assistant.RevaActionLogger class.
    """

    callback: Callable[[str], None]
    def __init__(self, callback: Callable[[str], None]) -> None:
        super().__init__()
        self.callback = callback

    logger = logging.getLogger("reverse_engineering_assistant.RevaActionLogger")

    def on_agent_action(self, action: AgentAction, **kwargs) -> None:
        """
        Callback method called when an agent action is performed.

        Args:
            action (AgentAction): The agent action that was performed.
            **kwargs: Additional keyword arguments.

        Returns:
            None
        """
        logger.debug(f"Agent action: {action} {kwargs}")
        # TODO: Should this be AgentAction?
        # TODO: Is `.action` still a thing?
        self.callback(str(action.log))


class RevaChat(RevaChatServiceServicer):
    logger = logging.getLogger("reva-server.RevaChat")

    def chat(self, request, context):
        self.logger.info(f"Received request: {request}")
        assistant = ReverseEngineeringAssistant(request.project)
        self.logger.info(f"Assistant: {assistant}")
        llm_response = assistant.query(request.message)
        self.logger.info(f"LLM Response: {llm_response}")
        response = RevaChatMessageResponse()
        response.message = llm_response
        return response

    def chatResponseStream(self, request, context):
        """
        Given a request, return a stream of responses including
        thoughts and a final message from the LLM.
        """
        self.logger.info(f"Received request: {request}")

        response_queue: queue.Queue = queue.Queue()

        def callback(message: str):
            # Called for intermediate thoughts
            response = RevaChatMessageResponse()
            response.thought = message
            response_queue.put(response)

        assistant = ReverseEngineeringAssistant(request.project, langchain_callbacks=[RevaActionCollector(callback)])
        self.logger.info(f"Assistant: {assistant}")

        def run_query(query: str):
            llm_response = assistant.query(query)
            self.logger.info(f"LLM Response: {llm_response}")
            response = RevaChatMessageResponse()
            response.message = llm_response
            response_queue.put(response)

        t = threading.Thread(target=run_query, args=[request.message])
        t.start()

        done = False
        while not done:
            response = response_queue.get()
            # We stop when we get a message and not thoughts
            if response.message and not response.thought:
                done = True
            yield response
        t.join()

    def chatStream(self, request_iterator, context):
        # TODO: This needs to be re-written to use the new callback system
        # let's grab a reference to our assistant
        raise NotImplementedError("chatStream is not implemented yet")
