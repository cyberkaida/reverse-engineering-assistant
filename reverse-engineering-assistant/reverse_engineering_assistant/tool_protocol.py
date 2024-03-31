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

from click import Option
from pydantic import BaseModel, Field
import pydantic
import pydantic_core

try:
    from pydantic import validator
except ImportError:
    # Depending on the version we might have validator in another place
    from pydantic.functional_validators import function_validator as validator # type: ignore

from pydantic.dataclasses import dataclass

import tempfile

_reva_message_types: Dict[str, Type[RevaMessage]] = {}

def register_message(cls: Type[RevaMessage]) -> Type[RevaMessage]:
    """
    Register a message type
    """
    logging.getLogger("reverse_engineering_assistant.tool_protocol.register_message").debug(f"Registering message type {cls.__name__}")
    _reva_message_types[cls.__name__] = cls
    return cls


logger = logging.getLogger("reverse_engineering_assistant.tool_protocol")
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


        assert value in _reva_message_types, f"Unknown message type {value}, check the logs to make sure the `register_message` was called for this message type. Registered message types are {_reva_message_types.keys()}"
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
        RevaMessage.model_validate(thing)
        try:
            logger.debug(f"Converting message to specific type {thing['message_type']}")
            logger.debug(f"Checking for message type {thing['message_type']} in {_reva_message_types}")
            message_class = _reva_message_types[thing["message_type"]]
            logger.debug(f"Message class is {message_class}")
            try:
                return message_class.model_validate(thing)
            except pydantic_core.ValidationError:
                # If we fail to turn it into a specific type, make it a generic type
                # This allows us to extract things like error messages.
                if issubclass(message_class, RevaMessageResponse):
                    return RevaMessageResponse.model_validate(thing)
                else:
                    logger.exception(f"Failed to parse {thing} as {message_class}")
                return RevaMessage.model_validate(thing)
        except KeyError:
            raise ValueError("No message type in message, is this a ReVa message?")

    def send(self) -> None:
        """
        Send this message
        """
        raise NotImplementedError()

class RevaMessageResponse(RevaMessage, ABC):
    """
    Base class for all messages sent in response to a RevaMessage
    """
    response_to: UUID = Field()
    error_message: Optional[str] = Field(default=None)


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

@register_message
class RevaHeartbeatResponse(RevaMessageToTool, RevaMessageResponse):
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

@register_message
class RevaGetDataAtAddress(RevaMessageToTool):
    """
    Request the data at a given address
    """
    message_type: str = "RevaGetDataAtAddress"

    address_or_symbol: str = Field()
    """
    The address to retrieve data from
    """
    size: int = Field()
    """
    The number of bytes to retrieve
    """

@register_message
class RevaGetDataAtAddressResponse(RevaMessageToReva, RevaMessageResponse):
    """
    Response to a RevaGetDataAtAddress message
    """
    message_type: str = "RevaGetDataAtAddressResponse"

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

@register_message
class RevaGetDecompilation(RevaMessageToTool):
    """
    Request the decompilation of a given address
    """
    message_type: str = "RevaGetDecompilation"
    address: Optional[int] = Field()
    """
    The address to decompile
    """
    function: Optional[str] = None
    """
    The function to decompile. If None, the function at the given
    address will be decompiled.
    """

class RevaVariable(BaseModel):
    name: str = Field()
    storage: Optional[str] = Field(default=None)
    data_type: Optional[str] = Field(default=None)
    size: Optional[int] = Field(default=None)

@register_message
class RevaGetDecompilationResponse(RevaMessageToReva, RevaMessageResponse):
    """
    Response to a RevaGetDecompilation message
    """
    message_type: str = "RevaGetDecompilationResponse"
    address: int = Field()
    """
    The address this decompilation is at
    """
    decompilation: str = Field()
    """
    The decompilation of the given address
    """
    listing: Optional[str] = Field(default=None)
    """
    The disassebly listing of the function
    """
    function: str = Field()
    """
    The function this decompilation is for
    """
    function_signature: str = Field()
    """
    The signature of the function
    """
    incoming_calls: List[str] = Field()
    """
    The functions that call this function
    """
    outgoing_calls: List[str] = Field()
    """
    The functions that this function calls
    """
    variables: List[RevaVariable] = Field()
    """
    The variables in this function
    """

@register_message
class RevaGetFunctionCount(RevaMessageToTool):
    """
    Request the number of functions in the program
    """
    message_type: str = "RevaGetFunctionCount"
    pass

@register_message
class RevaGetFunctionCountResponse(RevaMessageToReva, RevaMessageResponse):
    """
    Response to a RevaGetFunctionCount message
    """
    message_type: str = "RevaGetFunctionCountResponse"
    function_count: int = Field()
    """
    The number of functions in the program
    """

@register_message
class RevaGetDefinedFunctionList(RevaMessageToTool):
    """
    Request a list of defined functions
    """
    message_type: str = "RevaGetDefinedFunctionList"
    page: int = Field()
    """
    The page number to retrieve. 1 indexed.
    """
    page_size: int = Field()
    """
    The number of functions to retrieve per page
    """

@register_message
class RevaGetDefinedFunctionListResponse(RevaMessageToReva, RevaMessageResponse):
    """
    Response to a RevaGetDefinedFunctionList message
    """
    message_type: str = "RevaGetDefinedFunctionListResponse"
    function_list: List[str] = Field()
    """
    A list of defined functions
    """

@register_message
class RevaGetReferences(RevaMessageToTool):
    """
    Request a list of references to a given address
    """
    message_type: str = "RevaGetReferences"
    address_or_symbol: str = Field()
    """
    The address to retrieve references to
    """

@register_message
class RevaGetReferencesResponse(RevaMessageToReva, RevaMessageResponse):
    """
    Response to a RevaGetReferences message
    """
    message_type: str = "RevaGetReferencesResponse"
    references_to: List[str] = Field()
    """
    A list of references to the given address
    """
    references_from: List[str] = Field()
    """
    A list of references from the given address
    """

@register_message
class RevaGetSymbols(RevaMessageToTool):
    """
    Request a list of symbols
    """
    message_type: str = "RevaGetSymbols"
    page: int = Field()
    """
    The page number to retrieve. 1 indexed.
    """
    page_size: int = Field()
    """
    The number of symbols to retrieve per page
    """

@register_message
class RevaSetSymbolName(RevaMessageToTool):
    """
    Set the name for a function or symbol,
    or create a label for an address.

    When setting the name for a variable in a functions
    please use RevaRenameVariable.
    """
    message_type: str = "RevaSetSymbolName"
    old_name_or_address: str = Field()
    new_name: str = Field()

@register_message
class RevaGetNewSymbolName(RevaMessageToReva):
    """
    Ask the model for a better name
    """
    message_type: str = "RevaGetNewSymbolName"
    symbol_name: str = Field()
    """
    The symbol to rename
    """

@register_message
class RevaGetNewSymbolNameResponse(RevaMessageToTool, RevaMessageResponse):
    """
    Response to a RevaGetNewSymbolName message.
    """
    message_type: str = "RevaGetNewSymbolNameResponse"

@register_message
class RevaSetSymbolNameResponse(RevaMessageToTool, RevaMessageResponse):
    """
    Response to a RevaSetSymbolName message
    """
    message_type: str = "RevaSetSymbolNameResponse"

@register_message
class RevaGetNewVariableName(RevaMessageToReva):
    """
    Ask the model for a better name
    """
    message_type: str = "RevaGetNewVariableName"
    variable: RevaVariable = Field()
    """
    The variable to rename
    """
    function_name: str = Field()
    """
    The function this variable is in
    """

@register_message
class RevaGetNewVariableNameResponse(RevaMessageToTool, RevaMessageResponse):
    """
    Response to a RevaGetNewVariableName message.
    """
    message_type: str = "RevaGetNewVariableNameResponse"

@register_message
class RevaRenameVariable(RevaMessageToTool):
    """
    Tell the tool to rename a variable
    """
    message_type: str = "RevaRenameVariable"
    variable: RevaVariable = Field()
    """
    The variable to rename
    """
    new_name: str = Field()
    """
    The new name to give the variable
    """
    function_name: str = Field()
    """
    The function this variable is in
    """

@register_message
class RevaRenameVariableResponse(RevaMessageToReva, RevaMessageResponse):
    """
    Response to a RevaRenameVariable message.

    A simple yes/no, not much to respond with.
    """
    message_type: str = "RevaRenameVariableResponse"

class RevaLocation(BaseModel):
    cursor_address: Optional[str] = Field(default=None)
    function_name: Optional[str] = Field(default=None)
    start_address: Optional[str] = Field(default=None)
    end_address: Optional[str] = Field(default=None)
    content: Optional[str] = Field(default=None)

@register_message
class RevaExplain(RevaMessageToReva):
    """
    Ask the model to explain something
    """
    message_type: str = "RevaExplain"
    location: RevaLocation = Field()
    """
    The location to explain
    """

@register_message
class RevaExplainResponse(RevaMessageToTool, RevaMessageResponse):
    """
    Response to a RevaExplain message
    """
    message_type: str = "RevaExplainResponse"

@register_message
class RevaSetComment(RevaMessageToTool):
    """
    Set a comment at a given address
    """
    message_type: str = "RevaSetComment"
    address_or_symbol: str = Field()
    comment: str = Field()

@register_message
class RevaSetCommentResponse(RevaMessageToReva, RevaMessageResponse):
    """
    Response to a RevaSetComment message
    """
    message_type: str = "RevaSetCommentResponse"
