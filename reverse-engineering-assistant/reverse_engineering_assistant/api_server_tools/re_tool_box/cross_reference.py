from typing import Dict, List, Union
import logging

import grpc

from reverse_engineering_assistant.tool import AssistantProject
from reverse_engineering_assistant.assistant import AssistantProject, register_tool
from reverse_engineering_assistant.reva_exceptions import RevaToolException
from reverse_engineering_assistant.api_server_tools import RevaRemoteTool
from reverse_engineering_assistant.model import RevaModel

@register_tool
class RevaCrossReferenceTool(RevaRemoteTool):
    """
    An tool to retrieve cross references, to and from, addresses.
    """
    def __init__(self, project: AssistantProject, llm: RevaModel) -> None:
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
        from reverse_engineering_assistant.protocol import RevaReferences_pb2_grpc, RevaReferences_pb2

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
