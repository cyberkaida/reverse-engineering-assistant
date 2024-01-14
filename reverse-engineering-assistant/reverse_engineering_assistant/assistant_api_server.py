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


import logging
logger = logging.getLogger("reverse_engineering_assistant.assistant_api_server.RevaServer")

from flask import Flask, request, make_response

from .tool_protocol import RevaGetDataAtAddress, RevaGetDataAtAddressResponse, RevaHeartbeat, RevaHeartbeatResponse, RevaMessageResponse, RevaMessageToReva, RevaMessageToTool, RevaMessage
from .assistant import ReverseEngineeringAssistant, register_tool, RevaTool

from .tool import AssistantProject

from functools import cache
import threading

from abc import ABC, abstractmethod
REVA_PORT=44916
"""The default port for the ReVa server"""

@cache
def get_assistant_for_project(project_name: str) -> ReverseEngineeringAssistant:
    """
    Return the assistant for the given project
    """
    return ReverseEngineeringAssistant(project_name)


app = Flask(__name__)

class RevaMessageHandler(ABC):
    handles_type: Type[RevaMessage]

    assistant: ReverseEngineeringAssistant
    def __init__(self, assistant: ReverseEngineeringAssistant):
        self.assistant = assistant

    @abstractmethod
    def run(self, message: RevaMessageToReva) -> RevaMessageToTool:
        raise NotImplementedError()
    
queue_semaphore: threading.Semaphore = threading.Semaphore()
to_send_to_tool: List[RevaCallbackHandler] = []
waiting_on_tool: List[RevaCallbackHandler] = []

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
    _response_lock: threading.Lock = threading.Lock()
    """
    Lock to wait for the response
    """

    def __init__(self, project: AssistantProject, message: RevaMessage):
        self.project = project
        self.message = message
        self._response_lock.acquire()

    def is_response_for_message(self, message: RevaMessageResponse) -> bool:
        return self.message.message_id == message.response_to
    
    def submit_response(self, response: RevaMessageResponse) -> None:
        self.response = response
        self._response_lock.release()
    
    def wait(self) -> RevaMessage:
        self._response_lock.acquire()
        return self.response


_reva_message_handlers: Dict[Type[RevaMessage], RevaMessageHandler] = {}
def register_message_handler(cls: Type[RevaMessageHandler]) -> RevaMessageHandler:
    logger = logging.getLogger("reverse_engineering_assistant.tool_protocol.register_message_handler")
    message_type = cls.handles_type
    _reva_message_handlers[message_type] = cls
    logger.debug(f"Registered message handler {cls} for {message_type}")
    return cls

def get_handler_for_message(message: RevaMessageToReva) -> Type[RevaMessageHandler]:
    logger = logging.getLogger("reverse_engineering_assistant.tool_protocol.get_handler_for_message")
    logger.debug(f"Getting handler for message {message}")
    handler_cls = _reva_message_handlers[type(message)]
    return handler_cls

@register_message_handler
class HandleHeartbeat(RevaMessageHandler):
    handles_type = RevaHeartbeat
    def run(self, message: RevaHeartbeat) -> RevaHeartbeatResponse:
        return RevaHeartbeatResponse(message)

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

    def get_bytes_at_address(self, address: int | str, size: int | str) -> Dict[str, str]:
        """
        Get length bytes at the given address. size must be > 0
        """
        if isinstance(address, str):
            address = int(address, 16)
        if isinstance(size, str):
            size = int(size)
        if size <= 0:
            raise ValueError("length must be > 0")
        
        get_bytes_message = RevaGetDataAtAddress(address=address, size=size)
        callback_handler = RevaCallbackHandler(self.project, get_bytes_message)
        to_send_to_tool.append(callback_handler)
        response = callback_handler.wait()
        if not isinstance(response, RevaGetDataAtAddressResponse):
            raise ValueError(f"Expected a RevaGetDataAtAddressResponse, got {response}")
        if response.error_message:
            raise ValueError(response.error_message)

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

@app.route('/project/<project_name>/message', methods=['GET'])
def get_message(project_name: str) -> Optional[RevaMessage]:
    """
    Get a message for the given project for the tool to complete
    """
    with queue_semaphore:
        selected: Optional[RevaCallbackHandler] = None
        for message in to_send_to_tool:
            if message.project.project == project_name:
                selected = message
                break
        if selected:
            logger.debug(f"Getting message for project {project_name} - {selected}")
            to_send_to_tool.remove(selected)
            waiting_on_tool.append(selected)
            return selected.message.json()
    return make_response('No messages', 204)

@app.route('/project/<project_name>/message', methods=['POST'])
def run_task(project_name: str) -> Optional[RevaMessage]:
    """
    Run a message on the given project
    """
    message = request.json
    logger.debug(f"Received message JSON {message} on project {project_name}")

    project = get_assistant_for_project(project_name)

    reva_message = RevaMessage.to_specific_message(message)

    logger.debug(f"Processing message {reva_message}")

    if isinstance(reva_message, RevaMessageResponse):
        # This is a response to a message we sent
        with queue_semaphore:
            selected: Optional[RevaCallbackHandler] = None
            for message in waiting_on_tool:
                if message.is_response_for_message(reva_message):
                    selected = message
                    break
            if selected:
                waiting_on_tool.remove(selected)
                selected.submit_response(reva_message)
            else:
                logger.warning(f"Got response {reva_message} but no message was waiting for it")
                raise ValueError(f"Got response {reva_message} but no message was waiting for it")
    else:
        handler_class = get_handler_for_message(reva_message)
        handler = handler_class(project)
        with queue_semaphore:
            message = handler.run(reva_message)
            to_send_to_tool.append(message)

def run_server(port: int = REVA_PORT) -> None:
    """
    Run the server on the given port
    """
    app.run(host='localhost', port=port, debug=False)

def main():
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument("--port", type=int, default=REVA_PORT, help="The port to listen on")

    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG)
    app.run(host='localhost', port=args.port, debug=False)

if __name__ == "__main__":
    main()