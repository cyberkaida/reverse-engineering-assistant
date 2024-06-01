

from typing import List
from reverse_engineering_assistant.reva_exceptions import RevaToolException
from reverse_engineering_assistant.tool import AssistantProject
from reverse_engineering_assistant.assistant import RevaTool
from reverse_engineering_assistant.model import RevaModel
from reverse_engineering_assistant.api_server_tools.connection import get_channel
from typing import Optional, Tuple
import logging


class RevaMessageHandler(object):
    handles_type = None

_global_message_handlers: List[RevaMessageHandler] = []

__all__ = ['register_message_handler']

def register_message_handler(cls: RevaMessageHandler):
    _global_message_handlers.append(cls)
    return cls


class RevaRemoteTool(RevaTool):
    logger: logging.Logger

    def __init__(self, project: AssistantProject, llm: RevaModel) -> None:
        self.logger = logging.getLogger(f"reverse_engineering_assistant.RevaRemoteTool.{self.__class__.__name__}")
        self.logger.addHandler(logging.FileHandler(project.project_path / "reva.log"))
        super().__init__(project, llm)

    @property
    def channel(self):
        return get_channel()

    def resolve_to_address_and_symbol(self, thing: str) -> Tuple[str, Optional[str]]:
        """
        Resolve a string to an address and symbol.
        If it is an address it can be a namespaced address or a plain hex address.

        This helps reduce hallucinations and catch issues with symbols and namespaces early.

        Returns a tuple of (address, symbol).
        """
        self.logger.debug(f"Resolving {thing} to address and symbol")
        assert thing is not None
        address: Optional[str] = None
        symbol: Optional[str] = None
        try:
            # This is a plain address in the main namespace
            address = hex(int(thing, 16))
            self.logger.debug(f"Resolved {thing} to address: {address}")
        except ValueError:
            # This could also be a Ghidra namespaced address, so let's check that too!
            if "::" in thing:
                last_part = thing.split("::")[-1]
                try:
                    hex(int(last_part, 16))
                    # If the last part of the address is a hex number, then we can assume it is an address
                    address = thing
                except ValueError:
                    # Otherwise, it is a symbol
                    symbol = thing
            else:
                # This is a symbol
                symbol = thing

        # We can check if it is a symbol
        from ..protocol import RevaGetSymbols_pb2_grpc, RevaGetSymbols_pb2
        stub = RevaGetSymbols_pb2_grpc.RevaToolSymbolServiceStub(self.channel)
        request = RevaGetSymbols_pb2.RevaSymbolRequest()
        if address:
            request.address = address
        if symbol:
            request.name = symbol

        self.logger.debug(f"Getting symbol for {thing} request: {request}")
        response = stub.GetSymbol(request)
        self.logger.debug(f"Got symbol for {thing} response: {response}")

        if response.name:
            symbol = response.name
        if response.address:
            address = response.address

        if address is None and symbol is None:
            raise RevaToolException(message=f"Could not resolve {thing} to an address or symbol. Double check your symbol or address is correct.")
        self.logger.debug(f"Resolved {thing} to address: {address}, symbol: {symbol}")
        assert address is not None
        return address, symbol