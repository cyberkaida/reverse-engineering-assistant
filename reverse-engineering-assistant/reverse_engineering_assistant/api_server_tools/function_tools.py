
from pathlib import Path
from typing import Dict, List, Optional

from langchain.chat_models.base import BaseChatModel
from langchain.llms.base import BaseLLM

from ..tool import AssistantProject
from ..assistant import AssistantProject, RevaTool, BaseLLM, register_tool
from ..tool_protocol import RevaGetDecompilation, RevaGetDecompilationResponse, RevaGetFunctionCount, RevaGetFunctionCountResponse, RevaGetDefinedFunctionList, RevaGetDefinedFunctionListResponse

from ..reva_exceptions import RevaToolException

import logging


@register_tool
class RevaDecompilationIndex(RevaTool):
    """
    An index of decompiled functions available to the
    reverse engineering assistant.
    """
    index_name = "decompilation"
    description = "Used for retrieving decompiled functions"
    logger = logging.getLogger("reverse_engineering_assistant.RevaDecompilationIndex")

    def __init__(self, project: AssistantProject, llm: BaseLLM) -> None:
        super().__init__(project, llm)
        self.description = "Used for retrieveing decompiled functions"
        self.tool_functions = [
            self.get_decompilation_for_function,
            self.get_defined_function_list_paginated,
            self.get_defined_function_count,
        ]
    
    def get_decompilation_for_function(self, function_name_or_address: str | int) -> Dict[str, str]:
        """
        Return the decompilation for the given function. The function can be specified by name or address.
        Hint: It is too slow to decompile _all_ functions, so use get_defined_function_list_paginated to get a list of functions
        and be sure to specify the function name or address exactly.
        """
        from ..assistant_api_server import RevaCallbackHandler, to_send_to_tool


        # First normalise the argument
        address: Optional[int] = None
        name: Optional[str] = None
        try:
            address = int(function_name_or_address, 16)
            if address <= 0:
                raise RevaToolException("Address must be > 0 and in hex format")
        except ValueError:
            name = function_name_or_address
        
        if address is None and name is None:
            raise RevaToolException("function_name_or_address must be an address or function name")

        # Now we can ask the tool
        get_decompilation_message = RevaGetDecompilation(address=address, function=name)
        callback_handler = RevaCallbackHandler(self.project, get_decompilation_message)
        to_send_to_tool.put(callback_handler)
        self.logger.debug(f"Waiting for response to {get_decompilation_message.json()}")
        response: RevaGetDecompilationResponse = callback_handler.wait()

        if response.error_message:
            raise RevaToolException(response.error_message, send_to_llm=True)

        if not isinstance(response, RevaGetDecompilationResponse):
            raise ValueError(f"Expected a RevaGetDecompilationResponse, got {response}")
        
        # Finally we can return the response
        return {
            "function": response.function,
            "function_signature": response.function_signature,
            "address": hex(response.address),
            "decompilation": response.decompilation,
            "variables": response.variables,
        }

                
    def get_defined_function_list_paginated(self, page: int, page_size: int = 20) -> List[str]:
        """
        Return a paginated list of functions in the index. Use get_defined_function_count to get the total number of functions.
        page is 1 indexed. To get the first page, set page to 1. Do not set page to 0.
        """
        from ..assistant_api_server import RevaCallbackHandler, to_send_to_tool

        if isinstance(page, str):
            page = int(page)
        if isinstance(page_size, str):
            page_size = int(page_size)
        if page == 0:
            raise ValueError("`page` is 1 indexed, page cannot be 0")
        
        get_function_list_message = RevaGetDefinedFunctionList(page=page, page_size=page_size)
        callback_handler = RevaCallbackHandler(self.project, get_function_list_message)
        to_send_to_tool.put(callback_handler)
        
        self.logger.debug(f"Waiting for response to {get_function_list_message.json()}")
        response = callback_handler.wait()
        if response.error_message:
            raise RevaToolException(response.error_message, send_to_llm=True)

        if not isinstance(response, RevaGetDefinedFunctionListResponse):
            raise RevaToolException(f"Expected a RevaGetDefinedFunctionListResponse, got {response}")

        return response.function_list
    
    def get_defined_function_count(self) -> int:
        """
        Return the total number of defined functions in the program.
        """
        from ..assistant_api_server import RevaCallbackHandler, to_send_to_tool

        get_function_count_message = RevaGetFunctionCount()
        callback_handler = RevaCallbackHandler(self.project, get_function_count_message)
        to_send_to_tool.put(callback_handler)
        self.logger.debug(f"Waiting for response to {get_function_count_message.json()}")
        response = callback_handler.wait()

        if response.error_message:
            raise RevaToolException(response.error_message, send_to_llm=True)

        if not isinstance(response, RevaGetFunctionCountResponse):
            raise ValueError(f"Expected a RevaGetFunctionCountResponse, got {response}")

        return response.function_count

@register_tool
class RevaRenameFunctionVariable(RevaTool):
    """
    A tool for renaming variables used in functions
    """

    description = "Used for renaming variables used in functions"
    logger = logging.getLogger("reverse_engineering_assistant.RevaRenameFunctionVariable")

    def __init__(self, project: AssistantProject, llm: BaseLLM | BaseChatModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for renaming variables used in functions"
        self.tool_functions = [
            self.rename_variable_in_function
        ]

    def rename_variable_in_function(self, new_name: str, old_name: str, containing_function: str):
        """
        Change the name of the variable with the name `old_name` in `containing_function` to `new_name`.
        """
        from ..tool_protocol import RevaRenameVariable, RevaRenameVariableResponse, RevaVariable
        rename_variable_message = RevaRenameVariable(
            variable=RevaVariable(name=old_name),
              new_name=new_name,
              function_name=containing_function)

        from ..assistant_api_server import RevaCallbackHandler, to_send_to_tool

        callback_handler = RevaCallbackHandler(self.project, rename_variable_message)
        to_send_to_tool.put(callback_handler)
        self.logger.debug(f"Waiting for response to {rename_variable_message.json()}")
        response: RevaRenameVariableResponse = callback_handler.wait()
        assert isinstance(response, RevaRenameVariableResponse)
        if response.error_message:
            raise RevaToolException(response.error_message, send_to_llm=True)
        
        return f"Renamed {old_name} to {new_name} in {containing_function}"
