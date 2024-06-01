from typing import Dict, List
import logging

import grpc

from reverse_engineering_assistant.tool import AssistantProject
from reverse_engineering_assistant.assistant import AssistantProject, register_tool
from reverse_engineering_assistant.reva_exceptions import RevaToolException
from reverse_engineering_assistant.api_server_tools import RevaRemoteTool
from reverse_engineering_assistant.model import RevaModel
from reverse_engineering_assistant.protocol import RevaGetDecompilation_pb2_grpc, RevaGetDecompilation_pb2


@register_tool
class RevaDecompilation(RevaRemoteTool):
    """
    A tool for interacting with the decompilation service.
    """
    index_name = "decompilation"
    description = "Used for retrieving decompiled functions"
    logger = logging.getLogger("reverse_engineering_assistant.RevaDecompilationIndex")

    def __init__(self, project: AssistantProject, llm: RevaModel) -> None:
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
        from reverse_engineering_assistant.protocol import RevaGetDecompilation_pb2_grpc, RevaGetDecompilation_pb2
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
        from reverse_engineering_assistant.protocol import RevaGetDecompilation_pb2_grpc, RevaGetDecompilation_pb2
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
