from __future__ import annotations


from binascii import a2b_base64, a2b_hex, b2a_hex
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import grpc

from httpx import request
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.language_models.base import BaseLanguageModel
from numpy import add

from ..tool import AssistantProject
from ..assistant import AssistantProject, RevaTool, register_tool
from ..assistant_api_server import get_channel

from ..reva_exceptions import RevaToolException

from ..protocol import RevaGetDecompilation_pb2_grpc, RevaGetDecompilation_pb2

import logging

class RevaRemoteTool(RevaTool):
    logger: logging.Logger

    def __init__(self, project: AssistantProject, llm: BaseLanguageModel) -> None:
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


@register_tool
class RevaDecompilation(RevaRemoteTool):
    """
    A tool for interacting with the decompilation service.
    """
    index_name = "decompilation"
    description = "Used for retrieving decompiled functions"
    logger = logging.getLogger("reverse_engineering_assistant.RevaDecompilationIndex")

    def __init__(self, project: AssistantProject, llm: BaseLanguageModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for decompiling functions and interacting with the decompilation."
        self.tool_functions = [
            self.get_decompilation_for_function,
            #self.rename_multiple_variables_in_function,
            #self.rename_variable_in_function,
            #self.retype_multiple_variables_in_function,
            #self.retype_variable_in_function,
            self.update_multiple_variables_in_function,
            self.update_variable_in_function,
        ]

    def get_decompilation_for_function(self, function_name_or_address: str) -> Dict[str, str]:
        """
        Return the decompilation for the given function. The function can be specified by name or address.
        Hint: It is too slow to decompile _all_ functions, so use get_defined_function_list_paginated to get a list of functions
        and be sure to specify the function name or address exactly.
        """

        # First normalise the argument
        address, name = self.resolve_to_address_and_symbol(function_name_or_address)

        # Now we can create the message and call over the RPC
        from ..protocol import RevaGetDecompilation_pb2_grpc, RevaGetDecompilation_pb2
        stub = RevaGetDecompilation_pb2_grpc.RevaDecompilationServiceStub(self.channel)

        request = RevaGetDecompilation_pb2.RevaGetDecompilationRequest()

        if name:
            request.function = name
        if address:
            request.address = address

        try:
            response: RevaGetDecompilation_pb2.RevaGetDecompilationResponse = stub.GetDecompilation(request)
        except grpc.RpcError as e:
            raise RevaToolException(f"Failed to get decompilation: {e}")

        cleaned_decompilation = ""
        for line in response.decompilation.splitlines():
            # Remove this warning, this scares the large language model
            if line.strip().startswith("/* WARNING:") and line.strip().endswith("*/"):
                continue
            cleaned_decompilation += line + "\n"

        # Finally we can return the response
        return {
            "function": response.function,
            "function_signature": response.function_signature,
            "address": response.address,
            "decompilation": cleaned_decompilation,
            "listing": response.listing,
            "variables": response.variables, #type: ignore # We can ignore this because it can be serialised to a dict
            "incoming_calls": response.incoming_calls,
            "outgoing_calls": response.outgoing_calls,
        }

    def update_multiple_variables_in_function(self, updates: List[Dict[str, str]], containing_function: str) -> List[str]:
        """
        Update the names and types of multiple variables in the function `containing_function`.
        `updates` is a list of dictionaries where each dictionary has the keys "old_name", "new_name", and "new_type".

        If there are many variables to update in a function, use this. It is more efficient than calling update_variable_in_function multiple times.
        After calling this, you can confirm the changes by decompiling the function again.
        If there is a failure, retrying the operation will not help.

        `new_type` must be a string that can be passed to the "Set Data Type" dialog in Ghidra.
        Something like `int`, `char`, `long`, `unsigned int`, `char[0x10]` or `char[16]`, or `int*` should work,
        but you can use custom types from the program too.

        Use this to clean up the decompilation and make it more readable and easier for you to analyse.

        You can't define a _new_ data type here, only use existing ones.
        """
        outputs: List[str] = []
        for update in updates:
            if "old_name" not in update or "new_name" not in update or "new_type" not in update:
                raise RevaToolException("Each update must have the keys 'old_name', 'new_name', and 'new_type'")
            outputs.append(self.update_variable_in_function(update["old_name"], update["new_name"], update["new_type"], containing_function))
        return outputs

    def update_variable_in_function(self, variable_name: str, new_name: str, new_type: str,  containing_function: str) -> str:
        """
        Update the name and type of a variable in a function.

        `new_type` must be a string that can be passed to the "Set Data Type" dialog in Ghidra.
        Something like `int`, `char`, `long`, `unsigned int`, `char[0x10]` or `char[16]`, or `int*` should work,
        but you can use custom types from the program too.

        Use this to clean up the decompilation and make it more readable and easier for you to analyse.

        You can't define a _new_ data type here, only use existing ones.
        """
        self.rename_variable_in_function(new_name, variable_name, containing_function)
        self.retype_variable_in_function(new_name, new_type, containing_function)
        return f"Updated {variable_name} to {new_name} with type {new_type} in {containing_function}"


    def rename_multiple_variables_in_function(self, new_names: Dict[str, str], containing_function: str) -> List[str]:
        """
        Change the names of multiple variables in the function `containing_function` to the new names specified in `new_names`.
        `new_names` is a dictionary where the keys are the old names and the values are the new names.

        If there are many variables to rename in a function, use this. It is more efficient than calling rename_variable_in_function multiple times.
        After calling this, you can confirm the changes by decompiling the function again.
        If there is a failure, retrying the operation will not help.
        Don't use this for renaming symbols, use set_multiple_symbol_names instead.
        """
        outputs: List[str] = []
        for old_name, new_name in new_names.items():
            outputs.append(self.rename_variable_in_function(new_name, old_name, containing_function))
        return outputs

    def rename_variable_in_function(self, new_name: str, old_name: str, containing_function: str):
        """
        Change the name of the variable with the name `old_name` in `containing_function` to `new_name`.
        If the thing you want to rename is not in a function, you should use rename symbol instead,

        Use this to clean up the decompilation and make it more readable and easier for you to analyse.
        """
        from ..protocol import RevaGetDecompilation_pb2_grpc, RevaGetDecompilation_pb2
        stub = RevaGetDecompilation_pb2_grpc.RevaDecompilationServiceStub(self.channel)

        request = RevaGetDecompilation_pb2.RevaRenameFunctionVariableRequest()
        request.new_name = new_name
        request.old_name = old_name

        address, symbol = self.resolve_to_address_and_symbol(containing_function)
        if symbol is None:
            raise RevaToolException(f"Could not find function {containing_function}")
        request.function_name = symbol

        try:
            response: RevaGetDecompilation_pb2.RevaRenameFunctionVariableResponse = stub.RenameFunctionVariable(request)
        except grpc.RpcError as e:
            raise RevaToolException(f"Failed to rename variable: {e}")

        return f"Renamed {old_name} to {new_name} in {containing_function}"

    def retype_multiple_variables_in_function(self, new_types: Dict[str, str], containing_function: str) -> List[str]:
        """
        Change the types of multiple variables in the function `containing_function` to the new types specified in `new_types`.
        `new_types` is a dictionary where the keys are the variable names and the values are the new types.

        If there are many variables to retype in a function, use this. It is more efficient than calling retype_variable_in_function multiple times.
        After calling this, you can confirm the changes by decompiling the function again.
        If there is a failure, retrying the operation will not help.
        """
        outputs: List[str] = []
        for variable_name, new_type in new_types.items():
            outputs.append(self.retype_variable_in_function(variable_name, new_type, containing_function))
        return outputs

    def retype_variable_in_function(self, variable_name: str, new_type: str, containing_function: str):
        """
        Change the type of the variable with the name `variable_name` in `containing_function` to `new_type`.
        `new_type` must be a string that can be passed to the "Set Data Type" dialog in Ghidra.
        Something like `int`, `char`, `long`, `unsigned int`, `char[0x10]` or `char[16]`, or `int*` should work,
        but you can use custom types from the program too.

        Use this to clean up the decompilation and make it more readable and easier for you to analyse.

        You can't define a _new_ data type here, only use existing ones.
        """
        from ..protocol import RevaGetDecompilation_pb2_grpc, RevaGetDecompilation_pb2
        stub = RevaGetDecompilation_pb2_grpc.RevaDecompilationServiceStub(self.channel)

        request = RevaGetDecompilation_pb2.RevaSetFunctionVariableDataTypeRequest()
        request.data_type = new_type
        request.variable_name = variable_name

        address, symbol = self.resolve_to_address_and_symbol(containing_function)
        if symbol is None:
            raise RevaToolException(f"Could not find function {containing_function}")
        request.address = address

        try:
            response: RevaGetDecompilation_pb2.RevaSetFunctionVariableDataTypeResponse = stub.SetFunctionVariableDataType(request)
        except grpc.RpcError as e:
            raise RevaToolException(f"Failed to retype variable: {e}")

        return f"Retyped {variable_name} to {new_type} in {containing_function}"

@register_tool
class RevaCrossReferenceTool(RevaRemoteTool):
    """
    An tool to retrieve cross references, to and from, addresses.
    """
    index_directory: Path
    def __init__(self, project: AssistantProject, llm: BaseLanguageModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for retrieving cross references to and from addresses"

        self.tool_functions = [
            self.get_references,
            self.get_references_to,
            self.get_references_from,
        ]

    def get_references(self, address_or_symbol: str) -> Dict[str, Union[str, List[str]]]:
        """
        Return a list of references to and from the given address or symbol.
        These might be calls from/to other functions, or data references from/to this address.
        """
        from ..protocol import RevaReferences_pb2_grpc, RevaReferences_pb2

        stub = RevaReferences_pb2_grpc.RevaReferenceServiceStub(self.channel)

        request = RevaReferences_pb2.RevaGetReferencesRequest()

        address, symbol = self.resolve_to_address_and_symbol(address_or_symbol)
        request.address = address

        try:
            response: RevaReferences_pb2.RevaGetReferencesResponse = stub.get_references(request)
        except grpc.RpcError as e:
            raise RevaToolException(f"Failed to get references: {e}")

        result: Dict[str, Union[str, List[str]]] = {
            "address": address,
            "incoming_references": list(response.incoming_references),
            "outgoing_references": list(response.outgoing_references),
        }

        if symbol:
            result["symbol"] = symbol

        return result

    def get_references_to(self, address_or_symbol: str) -> List[str]:
        """
        Return a list of references to the given address or symbol.
        """
        references = self.get_references(address_or_symbol)
        return references.get("incoming_references", []) # type: ignore

    def get_references_from(self, address_or_symbol: str) -> List[str]:
        """
        Return a list of references from the given address or symbol.
        """
        references = self.get_references(address_or_symbol)
        return references.get("outgoing_references", []) # type: ignore

@register_tool
class RevaGetSymbols(RevaRemoteTool):
    """
    A tool for listing symbols in a program.
    These could be functions, global variables, or other named entities.
    """
    logger = logging.getLogger("reverse_engineering_assistant.RevaGetSymbols")


    def __init__(self, project: AssistantProject, llm: BaseLanguageModel) -> None:
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
        from ..protocol import RevaGetSymbols_pb2_grpc, RevaGetSymbols_pb2
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
        from ..protocol import RevaGetSymbols_pb2_grpc, RevaGetSymbols_pb2
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

    def __init__(self, project: AssistantProject, llm: BaseLanguageModel) -> None:
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
        """
        from ..protocol import RevaGetSymbols_pb2_grpc, RevaGetSymbols_pb2
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

@register_tool
class RevaSetComment(RevaRemoteTool):
    """
    A tool for setting comments on addresses, functions and symbols.
    """

    def __init__(self, project: AssistantProject, llm: BaseLanguageModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for setting comments on addresses, functions and symbols"

        self.tool_functions = [
            self.set_comment,
            self.set_multiple_comments,
        ]

    def set_multiple_comments(self, comments: Dict[str, str]) -> List[str]:
        """
        Set multiple comments at the same time.
        Keys are addresses or symbols, values are the comments to set at that location.
        This is more efficient than calling set_comment multiple times.
        """
        outputs: List[str] = []

        for address_or_symbol, comment in comments.items():
            outputs.append(self.set_comment(address_or_symbol=address_or_symbol, comment=comment))

        return outputs

    def set_comment(self, address_or_symbol: str, comment: str) -> str:
        """
        Set the comment at the given address, function or symbol to `comment`.
        Use this when you want to add an explanation or note to a specific part
        of the code.
        """
        from ..protocol import RevaComment_pb2_grpc, RevaComment_pb2
        stub = RevaComment_pb2_grpc.RevaCommentServiceStub(self.channel)

        request = RevaComment_pb2.RevaSetCommentRequest()
        request.comment = comment
        address, symbol = self.resolve_to_address_and_symbol(address_or_symbol)

        if address:
            request.address = address
        if symbol:
            request.symbol = symbol

        try:
            response: RevaComment_pb2.RevaSetCommentResponse = stub.SetComment(request)
        except grpc.RpcError as e:
            raise RevaToolException(f"Failed to set comment: {e}")
        return "Set comment successfully"

@register_tool
class RevaData(RevaRemoteTool):
    """
    A tool for getting and setting data
    """

    def __init__(self, project: AssistantProject, llm: BaseLanguageModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for getting and setting data"

        self.tool_functions = [
            self.list_strings,
            self.list_data,
            self.get_data,
        ]

    def list_strings(self) -> List[Dict[str, Union[str, List[str]]]]:
        """
        Return a list of defined strings in the program.
        """
        from ..protocol import RevaData_pb2_grpc, RevaData_pb2
        stub = RevaData_pb2_grpc.RevaDataServiceStub(self.channel)

        request = RevaData_pb2.RevaStringListRequest()

        defined_strings: List[Dict[str, Union[str, List[str]]]] = []
        for string in stub.getStringList(request):
            defined_strings.append({
                "address": string.address,
                "symbol": string.symbol,
                "value": string.value,
                "incoming_references": list(string.incoming_references),
                "outgoing_references": list(string.outgoing_references),
            })

        return defined_strings

    def list_data(self) -> List[Dict[str, Union[str, List[str]]]]:
        """
        Return a list of defined data in the program.
        This is not all data, only the data that has been defined in the Ghidra database.

        This function returns a list of dictionaries with the keys "address", "symbol", "type", "size", "incoming_references", and "outgoing_references".
        """

        from ..protocol import RevaData_pb2_grpc, RevaData_pb2
        stub = RevaData_pb2_grpc.RevaDataServiceStub(self.channel)

        request = RevaData_pb2.RevaDataListRequest()

        defined_data: List[Dict[str, Union[str, List[str]]]] = []
        for data in stub.getListData(request):
            defined_data.append({
                "address": data.address,
                "symbol": data.symbol,
                "type": data.type,
                "size": data.size,
                "incoming_references": list(data.incoming_references),
                "outgoing_references": list(data.outgoing_references),
            })

        return defined_data

    def get_data(self, address_or_symbol: str, size: Optional[int] = None) -> Dict[str, Union[str, List[str], int]]:
        """
        Return information about the data at the given address or with the given symbol.

        This function returns a dictionary with the keys "address", "symbol", "type", "size", "data", "incoming_references", and "outgoing_references".
        """
        from ..protocol import RevaData_pb2_grpc, RevaData_pb2
        stub = RevaData_pb2_grpc.RevaDataServiceStub(self.channel)
        request = RevaData_pb2.RevaGetDataAtAddressRequest()

        request.address, request.symbol = self.resolve_to_address_and_symbol(address_or_symbol)

        if size:
            request.size = size

        response = stub.getDataAtAddress(request)

        return {
            "address": response.address,
            "symbol": response.symbol,
            "type": response.type,
            "size": len(response.data),
            "data": b2a_hex(response.data).decode("utf-8"),
            "incoming_references": list(response.incoming_references),
            "outgoing_references": list(response.outgoing_references),
        }

@register_tool
class RevaGetCursor(RevaRemoteTool):

    def __init__(self, project: AssistantProject, llm: BaseLanguageModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for getting and setting the cursor or when the user mentions 'this'"

        self.tool_functions = [
            self.get_cursor,
        ]

    def get_cursor(self) -> Dict[str, Union[str, int]]:
        """
        Return the current location the user is looking at in the program.
        Use this to find the current function, symbol or address. When the user mentions "this",
        you should find the current location using this function.

        This method returns a dictionary with the keys "address", "symbol", and "function".
        Use other tools to gather context around this location. For example, decompile
        the function to find the exact code at this location in the listing or decompilation.
        """
        from ..protocol import RevaGetCursor_pb2, RevaGetCursor_pb2_grpc
        stub = RevaGetCursor_pb2_grpc.RevaGetCursorStub(self.channel)

        request = RevaGetCursor_pb2.RevaGetCursorRequest()

        response = stub.getCursor(request)

        return {
            "address": response.address,
            "symbol": response.symbol,
            "function": response.function,
        }

@register_tool
class RevaBookmarks(RevaRemoteTool):

    def __init__(self, project: AssistantProject, llm: BaseLanguageModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for managing bookmarks in the program"

        self.tool_functions = [
            self.get_bookmarks,
            self.add_bookmark,
        ]

    def get_bookmarks(self) -> List[Dict[str, str]]:
        """
        Return a list of Ghidra bookmarks in the program.
        Use this to keep track of important locations in the program the user
        has marked.
        """
        from ..protocol import RevaBookmark_pb2, RevaBookmark_pb2_grpc
        stub = RevaBookmark_pb2_grpc.RevaBookmarkStub(self.channel)

        request = RevaBookmark_pb2.RevaGetBookmarksRequest()

        bookmarks: List[Dict[str, str]] = []
        for bookmark in stub.get_bookmarks(request):
            bookmarks.append({
                "address": bookmark.address,
                "category": bookmark.category,
                "description": bookmark.description,
            })
        return bookmarks

    def add_bookmark(self, address_or_symbol: str, category: str, description: str) -> str:
        """
        Add a Ghidra bookmark at the given address or symbol with the given category and description.
        If the category does not exist, it will be created. Use a category to group bookmarks together.
        Make sure your category is descriptive and useful to the user.
        """
        from ..protocol import RevaBookmark_pb2, RevaBookmark_pb2_grpc
        stub = RevaBookmark_pb2_grpc.RevaBookmarkStub(self.channel)

        request = RevaBookmark_pb2.RevaAddBookmarkRequest()
        request.category = f"ReVa.{category}"
        request.description = description
        request.address, _ = self.resolve_to_address_and_symbol(address_or_symbol)

        response = stub.add_bookmark(request)

        return "Added bookmark successfully"