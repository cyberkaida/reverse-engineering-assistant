#!/usr/bin/env python3

"""
This file holds the API server implementation.
This server listens on a port and accepts messages from the tool side.

It implements a simple REST API.

This will be started by a reva-serve command, and will provide a global server.
"""

from __future__ import annotations
from typing import List, Optional, Union, Dict, Any, Type
import json
import binascii

from langchain.llms.base import BaseLLM

import logging
import uuid
logger = logging.getLogger("reverse_engineering_assistant.assistant_api_server.RevaServer")

from flask import Flask, request, make_response

from .tool_protocol import RevaGetDataAtAddress, RevaGetDataAtAddressResponse, RevaGetNewVariableName, RevaGetNewVariableNameResponse, RevaHeartbeat, RevaHeartbeatResponse, RevaMessageResponse, RevaMessageToReva, RevaMessageToTool, RevaMessage
from .assistant import ReverseEngineeringAssistant, register_tool, RevaTool

from .tool import AssistantProject

from functools import cache
import threading

from .reva_exceptions import RevaToolException
from abc import ABC, abstractmethod
REVA_PORT=44916
"""The default port for the ReVa server"""

# Enable this logger for debugging
# message state issues
trace_logger = logging.getLogger("reverse_engineering_assistant.assistant_api_server.trace")
trace_logger.disabled = True


app = Flask(__name__)

@cache
def get_assistant_for_project(project_name: str) -> ReverseEngineeringAssistant:
    """
    Return the assistant for the given project
    """
    return ReverseEngineeringAssistant(project_name)




class RevaMessageHandler(ABC):
    handles_type: Type[RevaMessage]

    assistant: ReverseEngineeringAssistant
    def __init__(self, assistant: ReverseEngineeringAssistant):
        self.assistant = assistant

    @abstractmethod
    def run(self, callback_handler: RevaCallbackHandler) -> RevaMessageToTool:
        raise NotImplementedError()

# Things to be sent to the tool
from queue import Queue
from queue import Empty

to_send_to_tool: Queue = Queue()

# We are waiting on responses from the tool
waiting_on_tool: Queue = Queue()

# Things that are waiting to be sent back to the tool
waiting_on_reva: Queue = Queue()

class RevaCallbackHandler:
    """
    Given a message that expects a response, manage waiting.
    """
    project: AssistantProject
    """
    The project associated with this request
    """
    message: RevaMessage
    """
    The message that is expecting a response
    """
    response: Optional[RevaMessageResponse] = None
    """
    The response to the original message
    """
    _response_lock: threading.Lock
    """
    Lock to wait for the response
    """
    logger: logging.Logger

    def __init__(self, project: AssistantProject, message: RevaMessage):
        if not isinstance(project, AssistantProject):
            raise ValueError(f"project must be an AssistantProject, got {type(project)}")
        self.project = project
        self.message = message
        self.logger = logging.getLogger(f"reverse_engineering_assistant.RevaCallbackHandler.{self.project}.{self.message.message_id}")
        self.logger.debug(f"Created callback handler for {message.json()}")
        self._response_lock = threading.Lock()
        self._response_lock.acquire()

    def is_response_for_message(self, message: RevaMessageResponse | str | uuid.UUID) -> bool:
        if isinstance(message, RevaMessageResponse):
            message = message.response_to
        if isinstance(message, str):
            message = uuid.UUID(message)
        if isinstance(message, uuid.UUID):
            return self.message.message_id == message
        raise ValueError(f"message must be a RevaMessageResponse, str or UUID, got {type(message)}")

    def submit_response(self, response: RevaMessageResponse) -> None:
        assert self.message.message_id == response.response_to, f"Responding to the wrong message {response.response_to} != {self.message.message_id}"
        self.response = response
        self.logger.debug(f"Got response {response}. Unlocking.")
        self._response_lock.release()

    def wait(self) -> RevaMessage:
        self.logger.debug(f"Waiting for response...")
        self._response_lock.acquire()
        self.logger.debug(f"Releasing response {self.response}")
        if not self.response:
            raise ValueError("No response")
        return self.response

    def __repr__(self) -> str:
        return f"<RevaCallbackHandler for {self.project}: {self.message.message_id}>"


_reva_message_handlers: Dict[Type[RevaMessage], Type[RevaMessageHandler]] = {}
def register_message_handler(cls: Type[RevaMessageHandler]) ->Type[RevaMessageHandler]:
    logger = logging.getLogger("reverse_engineering_assistant.tool_protocol.register_message_handler")
    message_type = cls.handles_type
    _reva_message_handlers[message_type] = cls
    logger.debug(f"Registered message handler {cls} for {message_type}")
    return cls

def get_handler_for_message(message: RevaMessageToReva) -> Type[RevaMessageHandler]:
    logger = logging.getLogger("reverse_engineering_assistant.tool_protocol.get_handler_for_message")
    logger.debug(f"Getting handler for message {message}")
    try:
        handler_cls = _reva_message_handlers[type(message)]
        return handler_cls
    except KeyError as e:
        raise ValueError(f"No handler for message {message}. Registered handlers are {_reva_message_handlers}") from e

@register_message_handler
class HandleHeartbeat(RevaMessageHandler):
    handles_type = RevaHeartbeat
    def run(self, callback_handler: RevaCallbackHandler) -> RevaHeartbeatResponse:
        message = callback_handler.message
        response = RevaHeartbeatResponse(response_to=message.message_id)
        callback_handler.submit_response(response)
        return response


@register_tool
class RevaData(RevaTool):
    """
    Retrieve bytes from the program
    """
    description = "Used for retrieving data from the program"
    def __init__(self, project: AssistantProject, llm: BaseLLM) -> None:
        super().__init__(project, llm)
        self.tool_functions = [
            self.get_bytes_at_address,
        ]

    def get_bytes_at_address(self, address_or_symbol: int | str, size: int | str) -> Dict[str, str | int | bytes | None]:
        """
        Get length bytes at the given address. size must be > 0
        """
        if isinstance(address_or_symbol, int):
            address_or_symbol = hex(address_or_symbol)
        if isinstance(size, str):
            size = int(size)

        if size <= 0:
            raise RevaToolException("length must be > 0. You asked for {size}.")

        get_bytes_message = RevaGetDataAtAddress(address_or_symbol=address_or_symbol, size=size)
        callback_handler = RevaCallbackHandler(self.project, get_bytes_message)
        to_send_to_tool.put(callback_handler)
        response = callback_handler.wait()
        assert isinstance(response, RevaMessageResponse), "Incorrect type returned from callback handler."

        if response.error_message:
            raise RevaToolException(response.error_message)

        if not isinstance(response, RevaGetDataAtAddressResponse):
            raise ValueError(f"Expected a RevaGetDataAtAddressResponse, got {response}")

        return {
            "bytes_in_hex": response.data,
            "bytes_size": len(binascii.a2b_hex(response.data)),
            "address": hex(response.address),
            "symbol": response.symbol,
        }



@app.route('/project', methods=['GET'])
def get_projects() -> List[str]:
    """Return a list of project names"""
    logger.debug("Getting projects")
    return ReverseEngineeringAssistant.get_projects()

@app.route('/project/<project_name>/message/<message_id>', methods=['GET'])
def get_message_response(project_name: str, message_id: str):
    """
    Return a response to a task the tool asked the assistant to perform.
    This uses the waiting_on_reva queue.
    """
    message_id: uuid.UUID = uuid.UUID(message_id) # type: ignore

    trace_logger.debug(f"Getting message response from service -> tool for {project_name} - {message_id}")
    handler = None
    try:
        handler = waiting_on_reva.get_nowait()
    except Empty:
        pass
    if handler:
        assert isinstance(handler, RevaCallbackHandler)
        if handler.is_response_for_message(message_id):
            selected = handler
            if selected.response:
                return selected.response.json()
            else:
                waiting_on_reva.put(handler)
                return make_response('No responses', 204)
    return make_response(f'Unknown message', 404)

@app.route('/project/<project_name>/message', methods=['GET'])
def get_message(project_name: str):
    """
    Return a response we would like the tool to perform.
    This uses the to_send_to_tool queue.
    """
    trace_logger.debug(f"Sending message from service -> tool for {project_name}")

    handler = None
    try:
        handler = to_send_to_tool.get_nowait()
    except Empty:
        pass
    if handler:
        assert isinstance(handler, RevaCallbackHandler)
        message_project_name = handler.project.project
        logger.debug(f"Checking if message {message_project_name} is for our project {project_name}")
        if message_project_name == project_name:
            selected = handler
            logger.debug(f"Getting message for project {project_name} - {selected}")
            waiting_on_tool.put(selected)
            return selected.message.json()
        else:
            to_send_to_tool.put(handler)
            logger.debug(f"Skipping message for {message_project_name}, it is not our project {project_name}")
    return make_response('No messages', 204)

@app.route('/project/<project_name>/message', methods=['POST'])
def run_task(project_name: str):
    """
    Get a message from the tool that it would like us to perform.
    This uses the waiting_on_reva queue.
    """

    trace_logger.debug(f"Received message from tool -> service for {project_name}")

    message = request.json
    logger.debug(f"Received message JSON {message} on project {project_name}")

    project = get_assistant_for_project(project_name)

    reva_message = RevaMessage.to_specific_message(message) # type: ignore
    assert isinstance(reva_message, RevaMessageToReva)
    reva_message: RevaMessageToReva = reva_message

    logger.debug(f"Processing message {reva_message}")

    handler_class = get_handler_for_message(reva_message)
    callback = RevaCallbackHandler(get_assistant_for_project(project_name).project, reva_message)
    handler = handler_class(project)
    # Kick off a thread to handle this message
    logger.info(f"Starting handler thread for {reva_message}")
    threading.Thread(target=handler.run, args=(callback,), daemon=True).start()
    # handler.run(callback)
    waiting_on_reva.put(callback)
    return make_response('OK', 200)

@app.route('/project/<project_name>/message/<message_id>', methods=['POST'])
def submit_response_from_tool(project_name: str, message_id: str):
    """
    Submit a response to a message we asked the tool to perform.
    This uses the waiting_on_tool queue.
    """
    message_id: uuid.UUID = uuid.UUID(message_id) # type: ignore

    trace_logger.debug(f"Received message response from tool -> service for {project_name} - {message_id}")

    message = request.json
    logger.debug(f"Received message JSON {message} on project {project_name}")

    project = get_assistant_for_project(project_name)

    reva_message: RevaMessageResponse = RevaMessage.to_specific_message(message) # type: ignore
    assert isinstance(reva_message, RevaMessageResponse)

    logger.debug(f"Processing message {reva_message}")

    handler = None
    try:
        handler = waiting_on_tool.get_nowait()
    except Empty:
        pass
    if handler:
        assert isinstance(handler, RevaCallbackHandler)
        if handler.is_response_for_message(reva_message):
            handler.submit_response(reva_message)
            return make_response('OK', 200)
        else:
            waiting_on_tool.put(handler)
            return make_response("Not the message we are waiting for", 204)
    return make_response(f'Unknown message ID', 404)

def run_server(port: int = REVA_PORT) -> None:
    """
    Run the server on the given port
    """
    # This thing is annoying, so we'll disable its verbose logging
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    # Import these down here to avoid a circular import
    # We need to have all the handlers registered before we start
    from .api_server_tools import function_tools, llm_tools
    app.run(host='localhost', port=port, debug=False)

def main():
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument("--port", type=int, default=REVA_PORT, help="The port to listen on")

    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG)
    run_server(args.port)

if __name__ == "__main__":
    main()