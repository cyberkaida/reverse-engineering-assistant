from typing import Dict, List, Optional, Union
from binascii import b2a_hex
import logging

import grpc

from reverse_engineering_assistant.tool import AssistantProject
from reverse_engineering_assistant.assistant import AssistantProject, register_tool
from reverse_engineering_assistant.reva_exceptions import RevaToolException
from reverse_engineering_assistant.api_server_tools import RevaRemoteTool
from reverse_engineering_assistant.model import RevaModel
from reverse_engineering_assistant.protocol import RevaGetDecompilation_pb2_grpc, RevaGetDecompilation_pb2
from reverse_engineering_assistant.protocol import RevaData_pb2_grpc, RevaData_pb2, RevaGetSymbols_pb2, RevaGetSymbols_pb2_grpc


@register_tool
class RevaData(RevaRemoteTool):
    """
    A tool for getting and setting data
    """

    def __init__(self, project: AssistantProject, llm: RevaModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for getting and setting data"

        self.tool_functions = [
            self.list_strings,
            self.list_data,
            self.get_data,
            self.set_global_data_type,
        ]

    def list_strings(self) -> List[Dict[str, Union[str, List[str]]]]:
        """
        Return a list of defined strings in the program.
        """
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

    def get_data(self, address_or_symbol: str, size: Optional[int] = None) -> Dict[str, Optional[Union[str, List[str], int]]]:
        """
        Return information about the data at the given address or with the given symbol.
        Don't set the size if you don't know it, Ghidra will try to figure it out.

        This function returns a dictionary with the keys "address", "symbol", "type", "size", "data", "incoming_references", and "outgoing_references".
        """
        stub = RevaData_pb2_grpc.RevaDataServiceStub(self.channel)
        request = RevaData_pb2.RevaGetDataAtAddressRequest()

        request.address, symbol = self.resolve_to_address_and_symbol(address_or_symbol)

        if size:
            request.size = size

        response = stub.getDataAtAddress(request)

        return {
            "address": response.address,
            "symbol": symbol,
            "type": response.type,
            "size": len(response.data),
            "data": b2a_hex(response.data).decode("utf-8"),
            "incoming_references": list(response.incoming_references),
            "outgoing_references": list(response.outgoing_references),
        }

    def set_global_data_type(self, address_or_symbol: str, data_type: Optional[str], new_name: Optional[str]) -> str:
        """
        Set the data type or name of the data at the given address or symbol to the given data type.

        `new_type` must be a string that can be passed to the "Set Data Type" dialog in Ghidra.
        Something like `int`, `char`, `string`, `long`, `unsigned int`, `char[0x10]` or `char[16]`, or `int*` should work,
        but you can use custom types from the program too.

        You can't define a _new_ data type here, only use existing ones.
        """
        if not data_type and not new_name:
            raise RevaToolException("You must provide either a data type or a new name")
        address, symbol = self.resolve_to_address_and_symbol(address_or_symbol)

        if data_type:
            stub = RevaData_pb2_grpc.RevaDataServiceStub(self.channel)
            request = RevaData_pb2.RevaSetGlobalDataTypeRequest()
            request.address = address
            request.data_type = data_type
            response = stub.setGlobalDataType(request)

        if new_name:
            symbol_stub = RevaGetSymbols_pb2_grpc.RevaToolSymbolServiceStub(self.channel)
            symbol_request = RevaGetSymbols_pb2.RevaSetSymbolNameRequest()
            if symbol:
                symbol_request.old_name = symbol
            symbol_request.new_name = new_name
            symbol_request.old_address = address
            symbol_response = symbol_stub.SetSymbolName(symbol_request)

        # TODO: Should we return truth to reduce hallucinations?
        return f"{address_or_symbol} has been updated successfully"
