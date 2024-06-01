from typing import Dict, List, Union, Optional
import logging

import grpc

from reverse_engineering_assistant.tool import AssistantProject
from reverse_engineering_assistant.assistant import AssistantProject, register_tool
from reverse_engineering_assistant.reva_exceptions import RevaToolException
from reverse_engineering_assistant.api_server_tools import RevaRemoteTool
from reverse_engineering_assistant.model import RevaModel
from reverse_engineering_assistant.protocol import RevaGetSymbols_pb2_grpc, RevaGetSymbols_pb2
from reverse_engineering_assistant.protocol import RevaGetSymbols_pb2_grpc, RevaGetSymbols_pb2
from reverse_engineering_assistant.protocol import RevaGetDecompilation_pb2_grpc, RevaGetDecompilation_pb2
from reverse_engineering_assistant.protocol import RevaGetSymbols_pb2_grpc, RevaGetSymbols_pb2

@register_tool
class RevaGetSymbols(RevaRemoteTool):
    """
    A tool for listing symbols in a program.
    These could be functions, global variables, or other named entities.
    """
    logger = logging.getLogger("reverse_engineering_assistant.RevaGetSymbols")


    def __init__(self, project: AssistantProject, llm: RevaModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for retrieving symbols in the program"

        self.tool_functions = [
            self.get_symbol_count,
            self.get_symbols,
            self.get_symbol,
            self.get_function_count,
            # self.get_functions, # Disabled for now, crashes the chain of thought when the context is too small, see issue #GH-56
            self.get_functions_paginated,
        ]

    def _get_symbol_list(self) -> List[str]:

        stub = RevaGetSymbols_pb2_grpc.RevaToolSymbolServiceStub(self.channel)

        request = RevaGetSymbols_pb2.RevaGetSymbolsRequest()

        try:
            response: RevaGetSymbols_pb2.RevaGetSymbolsResponse = stub.GetSymbols(request)
        except grpc.RpcError as e:
            raise RevaToolException(f"Failed to get symbols: {e}")

        return list(response.symbols)

    def _get_function_list(self) -> List[RevaGetDecompilation_pb2.RevaGetFunctionListResponse]:
        stub = RevaGetDecompilation_pb2_grpc.RevaDecompilationServiceStub(self.channel)

        request = RevaGetDecompilation_pb2.RevaGetDecompilationRequest()
        function_list = []
        for response in stub.GetFunctionList(request):
            function_list.append(response)
        return function_list

    def get_function_count(self) -> int:
        """
        Return the total number of functions in the program.
        Useful before calling get_functions.
        """
        return len(self._get_function_list())

    def get_functions_paginated(self, page: int = 1, page_size: int = 50) -> List[Dict[str, Union[str, List[str]]]]:
        """
        Return a paginated list of functions in the program.
        Use get_function_count to get the total number of functions.
        page is 1 indexed. To get the first page, set page to 1. Do not set page to 0.
        """
        functions = self.get_functions()
        start = (page - 1) * page_size
        end = start + page_size
        return functions[start:end]


    def get_functions(self) -> List[Dict[str, Union[str, List[str]]]]:
        """
        Return a list of functions in the program.
        Please check the total number of functions with get_function_count before calling this.
        If the function count is high, consider using get_functions_paginated.
        """

        function_list = self._get_function_list()

        function_details: List[Dict[str, Union[str, List[str]]]] = []
        for function in function_list:
            function_details.append({
                "function_name": function.function_name,
                "function_signature": function.function_signature,
                "entry_point": function.entry_point,
                "incoming_calls": list(function.incoming_calls),
                "outgoing_calls": list(function.outgoing_calls),
            })
        return function_details

    def get_symbol_count(self) -> int:
        """
        Return the total number of symbols in the program.
        Useful before calling get_symbols.
        """
        return len(self._get_symbol_list())

    def get_symbols(self) -> List[Dict[str, Optional[str]]]:
        """
        Return a list of symbols in the program.
        Please check the total number of symbols with get_symbol_count before calling this.
        """

        symbol_list = self._get_symbol_list()

        symbol_details: List[Dict[str, Optional[str]]] = []
        for symbol in symbol_list:
            symbol_details.append(self.get_symbol(symbol))
        return symbol_details

    def get_symbol(self, address_or_name: str) -> Dict[str, Optional[str]]:
        """
        Return information about the symbol at the given address or with the given name.
        Returns a dictionary with the keys "name", "address", and "type".
        """
        stub = RevaGetSymbols_pb2_grpc.RevaToolSymbolServiceStub(self.channel)

        request = RevaGetSymbols_pb2.RevaSymbolRequest()
        # TODO: This is not efficient, we are calling the same RPC two times
        address, name = self.resolve_to_address_and_symbol(address_or_name)
        if address:
            request.address = address
        if name:
            request.name = name

        self.logger.debug(f"Getting symbol {address_or_name} request: {request}")
        try:
            response: RevaGetSymbols_pb2.RevaSymbolResponse = stub.GetSymbol(request)
        except grpc.RpcError as e:
            raise RevaToolException(f"Failed to get symbol: {e}")
        self.logger.debug(f"Got symbol {address_or_name} response: {response}")
        response_dict = {
            "name": response.name,
            "address": response.address,
            "type": None,
        }

        if response.type:
            response_dict["type"] = RevaGetSymbols_pb2.SymbolType.Name(response.type)

        return response_dict


@register_tool
class RevaSetSymbolName(RevaRemoteTool):
    """
    A tool for creating or changing the name for a global symbol.
    This could be a function name, or a global variable name.
    """

    def __init__(self, project: AssistantProject, llm: RevaModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for setting names for global symbols"

        self.tool_functions = [
            self.set_symbol_name,
            self.set_multiple_symbol_names,
        ]

    def set_multiple_symbol_names(self, new_names: Dict[str, str]) -> List[Dict[str, str]]:
        """
        Change the names of multiple symbols to the new names specified in `new_names`.
        `new_names` is a dictionary where the keys are the old names or addresses and the values are the new names.

        If there are many symbols to rename, use this. It is more efficient than calling set_symbol_name multiple times.

        Use this for symbols, not variables in functions.
        """

        outputs: List[Dict[str, str]] = []
        for old_name, new_name in new_names.items():
            outputs.append(self.set_symbol_name(new_name, old_name))
        return outputs


    def set_symbol_name(self, new_name: str, old_name_or_address: str) -> Dict[str, str]:
        """
        Set the name of the symbol at the given address to `new_name`. If an old name is
        provided, rename the symbol to `new_name`.

        If this is a data symbol, try the set_global_data_type tool instead.
        """
        stub = RevaGetSymbols_pb2_grpc.RevaToolSymbolServiceStub(self.channel)

        request = RevaGetSymbols_pb2.RevaSetSymbolNameRequest()
        request.new_name = new_name
        old_address, old_name = self.resolve_to_address_and_symbol(old_name_or_address)
        if old_name:
            request.old_name = old_name
        if old_address:
            request.old_address = old_address

        try:
            response: RevaGetSymbols_pb2.RevaSetSymbolNameResponse = stub.SetSymbolName(request)
        except grpc.RpcError as e:
            raise RevaToolException(f"Failed to set symbol name: {e}")

        return {
            "old_name": request.old_name,
            "new_name": new_name,
        }
