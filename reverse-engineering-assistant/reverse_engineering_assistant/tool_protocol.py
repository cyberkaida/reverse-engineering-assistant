#!/usr/bin/env python3

"""
This file contains the communications protocol for interacting between
the ReVa inference side and the reverse engineering tool.

This file is python3, but it should not interact with the inference
side directly. While BinaryNinja can use this directly, Ghidra will
reimplement this protocol in Java.

We will have integration tests that generate messages and attempt to
parse on both sides to make sure these do not diverge.

Some design notes:
- We need to include extra information in each response that could lead
  to new discoveries or links. This is to make sure the inference side
  stays curious.
- Every field needs docstrings to help the LLM reason about messages.
  In general these will be wrapped by methods in assistant.py when a
  tool is exposed to the LLM, if we need to send a response
  directly to the LLM, we need to make sure it can reason about the
  fields.
"""

from __future__ import annotations
from typing import List, Optional, Union, Dict, Any, Type, Annotated

from abc import ABC, abstractproperty, abstractmethod
from datetime import datetime

from uuid import UUID, uuid4
import json
from pathlib import Path
import logging

from pydantic import BaseModel, Field

try:
    from pydantic import validator
except ImportError:
    # TODO: I don't like this
    from pydantic.functional_validators import function_validator as validator

from pydantic.dataclasses import dataclass

import tempfile

_reva_message_types: Dict[str, Type[RevaMessage]] = {}

def register_message(cls: Type[RevaMessage]) -> Type[RevaMessage]:
    """
    Register a message type
    """
    _reva_message_types[cls.__name__] = cls
    return cls


class RevaMessage(BaseModel, ABC):
    """
    Base class for all messages sent between the inference side and the
    reverse engineering tool.
    """

    message_type: str = Field()
    """
    The type of this message. This is used to determine which class to
    deserialise the message into.

    Must be one of the subclasses of RevaMessage.
    """
    @validator("message_type")
    def validate_message_type(cls, value: str) -> str:
        assert value in _reva_message_types, f"Unknown message type {value}"
        return value


    message_id: UUID = Field(default_factory=uuid4)
    """
    Unique identifier for this message
    """

    @classmethod
    def to_specific_message(cls, thing: Dict) -> RevaMessage:
        """
        Convert this message to the specific message type
        """
        # First validate it is a ReVa message
        RevaMessage.parse_obj(thing)
        try:
            return _reva_message_types[thing["message_type"]].parse_obj(thing)
        except KeyError:
            raise ValueError(f"No message type in message, is this a ReVa message?")

    def send(self) -> None:
        """
        Send this message
        """
        raise NotImplementedError()
    
class RevaMessageToTool(RevaMessage):
    """
    Base class for messages sent to the tool
    """
    
    def send(self) -> None:
        """
        Send this message
        """
        raise NotImplementedError()

        
        

class RevaMessageToReva(RevaMessage):
    """
    Base class for messages sent to the inference side
    """

    def send(self) -> None:
        """
        Send this message
        """
        raise NotImplementedError()

# MARK: - Heartbeats



@register_message
class RevaHeartbeat(RevaMessageToReva):
    """
    A heartbeat message is sent periodically to ensure the connection
    is still alive.
    """
    message_type: str = "RevaHeartbeat"

class RevaHeartbeatResponse(RevaMessageToTool):
    """
    A heartbeat response is sent in response to a heartbeat message.
    """
    message_type: str = "RevaHeartbeatResponse"

# MARK: Simple state messages

class RevaGetCursor(RevaMessageToTool):
    """
    Request the current cursor position
    """
    pass

class RevaGetCursorResponse(RevaMessageToReva):
    """
    Response to a RevaGetCursor message
    """
    cursor_address: int = Field()
    """
    The current cursor position
    """
    symbol: Optional[str] = None
    """
    If the cursor is at a symbol, this is the name of the symbol
    """
    function: Optional[str] = None
    """
    If the cursor is in a function, this is the name of the function
    """
    # TODO: Add data type

# MARK: Memory related messages

class RevaGetDataAtAddress(RevaMessageToTool):
    """
    Request the data at a given address
    """
    address: int = Field()
    """
    The address to retrieve data from
    """
    size: int = Field()
    """
    The number of bytes to retrieve
    """

class RevaGetDataAtAddressResponse(RevaMessageToReva):
    """
    Response to a RevaGetDataAtAddress message
    """
    address: int = Field()
    """
    The address this data is at
    """
    data: bytes = Field()
    """
    The data at the given address
    """
    symbol: Optional[str] = None
    """
    If the address is a symbol, this is the name of the symbol
    """

# MARK: Decompilation and functions

class RevaGetDecompilation(RevaMessageToTool):
    """
    Request the decompilation of a given address
    """
    address: int = Field()
    """
    The address to decompile
    """
    function: Optional[str] = None
    """
    The function to decompile. If None, the function at the given
    address will be decompiled.
    """

class RevaGetDecompilationResponse(RevaMessageToReva):
    """
    Response to a RevaGetDecompilation message
    """
    address: int = Field()
    """
    The address this decompilation is at
    """
    decompilation: str = Field()
    """
    The decompilation of the given address
    """
    function: str = Field()
    """
    The function this decompilation is for
    """
    function_signature: str = Field()
    """
    The signature of the function
    """



