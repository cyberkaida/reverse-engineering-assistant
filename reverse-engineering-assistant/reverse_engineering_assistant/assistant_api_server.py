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

import logging
logger = logging.getLogger("reverse_engineering_assistant.assistant_api_server.RevaServer")

from flask import Flask, request

from .tool_protocol import RevaHeartbeat, RevaHeartbeatResponse, RevaMessageToReva, RevaMessageToTool, RevaMessage
from .assistant import ReverseEngineeringAssistant

from .tool import AssistantProject

from functools import cache

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
        return RevaHeartbeatResponse()

@app.route('/project', methods=['GET'])
def get_projects() -> List[str]:
    """Return a list of project names"""
    logger.debug("Getting projects")
    return ReverseEngineeringAssistant.get_projects()

@app.route('/project/<project_name>/task', methods=['POST'])
def run_task(project_name: str) -> Optional[RevaMessage]:
    """
    Run a task on the given project
    """
    project = get_assistant_for_project(project_name)
    task = request.json

    reva_message = RevaMessage.to_specific_message(task)

    logger.debug(f"Running task {reva_message}")
    # TODO: Send the task the the right handler?

    handler_class = get_handler_for_message(reva_message)

    handler = handler_class(project)

    return handler.run(reva_message).json()

    #return project.run_task(task)

def main():
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument("--port", type=int, default=REVA_PORT, help="The port to listen on")

    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG)
    app.run(host='localhost', port=args.port, debug=False)

if __name__ == "__main__":
    main()