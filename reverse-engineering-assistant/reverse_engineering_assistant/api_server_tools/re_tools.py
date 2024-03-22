from __future__ import annotations


from pathlib import Path
from typing import Dict, List, Optional

from langchain.chat_models.base import BaseChatModel
from langchain.llms.base import BaseLLM

from ..tool import AssistantProject
from ..assistant import AssistantProject, RevaTool, BaseLLM, register_tool
from ..tool_protocol import RevaMessageToTool, RevaMessageToReva, RevaGetDecompilation, RevaGetDecompilationResponse, RevaGetFunctionCount, RevaGetFunctionCountResponse, RevaGetDefinedFunctionList, RevaGetDefinedFunctionListResponse, RevaMessageResponse, RevaGetImportedLibrariesCount, RevaGetImportedLibrariesCountResponse, RevaGetImportedLibrariesList, RevaGetReferencesResponse, RevaGetReferencesResponse,RevaGetImportedLibrariesListResponse

from ..reva_exceptions import RevaToolException

import logging

# TODO: I think the word tool is used too much in the project... It's a bit confusing...
class RevaRemoteTool(RevaTool):
    """
    Tool that performs its work in the RE tool.
    """
    def submit_to_tool(self, message: RevaMessageToTool) -> RevaMessageResponse:
        """
        Submit a message to the tool and wait for a response.
        """
        from ..assistant_api_server import RevaCallbackHandler, to_send_to_tool

        logger = logging.getLogger("reverse_engineering_assistant.RevaRemoteTool")
        logger.debug(f"Submitting message to tool: {message}")
        if isinstance(message, RevaMessageToReva):
            raise ValueError("You cannot send a RevaMessageToReva to the tool. You are likely sending the wrong direction.")
        assert isinstance(message, RevaMessageToTool), f"Incorrect type for message: {type(message)}. Should be a RevaMessageToTool"
        callback_handler = RevaCallbackHandler(self.project, message)

        # Here we queue the message to be sent to the tool
        logger.debug(f"Putting message in queue: {message}. {to_send_to_tool.qsize()} messages in queue.")
        to_send_to_tool.put(callback_handler)
        # Wait for the response to come back
        logger.debug(f"Waiting for response to {message}")
        response = callback_handler.wait()
        logger.debug(f"Got response to {message}: {response}")
        # Make sure it is a response type. If it is not, we might have a bug in the API queue
        # logic. If this happens check the code in assistant_api_server.py
        assert isinstance(response, RevaMessageResponse), "Incorrect type returned from callback handler."
        return response


@register_tool
class RevaDecompilationIndex(RevaRemoteTool):
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
        if isinstance(function_name_or_address, int):
                address = function_name_or_address
        elif isinstance(function_name_or_address, str):
            name = function_name_or_address

        if address is None and name is None:
            raise RevaToolException("function_name_or_address must be an address or function name")

        if address and address <= 0:
            raise RevaToolException("function_name_or_address must be a positive integer or a function name")

        # Now we can ask the tool
        get_decompilation_message = RevaGetDecompilation(address=address, function=name)
        response = self.submit_to_tool(get_decompilation_message)
        if response.error_message:
            raise RevaToolException(response.error_message)
        assert isinstance(response, RevaMessageResponse), "Incorrect type returned from callback handler."



        if not isinstance(response, RevaGetDecompilationResponse):
            raise RevaToolException(f"Expected a RevaGetDecompilationResponse, got {response}")

        response: RevaGetDecompilationResponse = response

        # Finally we can return the response
        return {
            "function": response.function,
            "function_signature": response.function_signature,
            "address": hex(response.address),
            "decompilation": response.decompilation,
            "listing": response.listing,
            "variables": response.variables, #type: ignore # We can ignore this because it can be serialised to a dict
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
        assert isinstance(response, RevaMessageResponse), "Incorrect type returned from callback handler."
        if response.error_message:
            raise RevaToolException(response.error_message)

        if not isinstance(response, RevaGetDefinedFunctionListResponse):
            raise RevaToolException(f"Expected a RevaGetDefinedFunctionListResponse, got {response}")

        return response.function_list

    def get_defined_function_count(self) -> int:
        """
        Return the total number of defined functions in the program.
        """

        response = self.submit_to_tool(RevaGetFunctionCount())
        assert isinstance(response, RevaMessageResponse), "Incorrect type returned from callback handler."

        if response.error_message:
            raise RevaToolException(response.error_message)

        if not isinstance(response, RevaGetFunctionCountResponse):
            raise ValueError(f"Expected a RevaGetFunctionCountResponse, got {response}")

        return response.function_count

@register_tool
class RevaRenameFunctionVariable(RevaRemoteTool):
    """
    A tool for renaming variables used in functions
    """

    description = "Used for renaming variables used in functions"
    logger = logging.getLogger("reverse_engineering_assistant.RevaRenameFunctionVariable")

    def __init__(self, project: AssistantProject, llm: BaseLLM | BaseChatModel) -> None:
        super().__init__(project, llm)
        self.description = "Used for renaming variables used in functions"
        self.tool_functions = [
            self.rename_multiple_variables_in_function,
            self.rename_variable_in_function
        ]

    def rename_multiple_variables_in_function(self, new_names: Dict[str, str], containing_function: str) -> List[str]:
        """
        Change the names of multiple variables in the function `containing_function` to the new names specified in `new_names`.
        `new_names` is a dictionary where the keys are the old names and the values are the new names.

        If there are many variables to rename in a function, use this. It is more efficient than calling rename_variable_in_function multiple times.
        After calling this, you can confirm the changes by decompiling the function again.
        If there is a failure, retrying the operation will not help.
        """
        outputs: List[str] = []
        for old_name, new_name in new_names.items():
            outputs.append(self.rename_variable_in_function(new_name, old_name, containing_function))
        return outputs

    def rename_variable_in_function(self, new_name: str, old_name: str, containing_function: str):
        """
        Change the name of the variable with the name `old_name` in `containing_function` to `new_name`.
        If the thing you want to rename is not in a function, you should use rename symbol instead,
        """
        from ..tool_protocol import RevaRenameVariable, RevaRenameVariableResponse, RevaVariable
        rename_variable_message = RevaRenameVariable(
            variable=RevaVariable(name=old_name),
              new_name=new_name,
              function_name=containing_function)

        response = self.submit_to_tool(rename_variable_message)
        assert isinstance(response, RevaMessageResponse), "Incorrect type returned from callback handler."
        if response.error_message:
            raise RevaToolException(response.error_message)

        return f"Renamed {old_name} to {new_name} in {containing_function}"


@register_tool
class RevaCrossReferenceTool(RevaRemoteTool):
    """
    An tool to retrieve cross references, to and from, addresses.
    """
    index_directory: Path
    def __init__(self, project: AssistantProject, llm: BaseLLM) -> None:
        super().__init__(project, llm)
        self.description = "Used for retrieving cross references to and from addresses"

        self.tool_functions = [
            self.get_references,
        ]

    def get_references(self, address_or_symbol: str) -> Optional[Dict[str, List[str]]]:
        """
        Return a list of references to and from the given address or symbol.
        These might be calls from/to other functions, or data references from/to this address.
        """
        from ..tool_protocol import RevaGetReferences, RevaGetReferencesResponse
        if isinstance(address_or_symbol, int):
            address_or_symbol = hex(address_or_symbol)
        if not isinstance(address_or_symbol, str):
            raise RevaToolException(f"address_or_symbol must be a string. Provided type was {type(address_or_symbol)}")
        get_references_message = RevaGetReferences(address_or_symbol=address_or_symbol)
        response = self.submit_to_tool(get_references_message)
        assert isinstance(response, RevaMessageResponse), "Incorrect type returned from callback handler."
        if response.error_message:
            raise RevaToolException(response.error_message)

        assert isinstance(response, RevaGetReferencesResponse), f"Expected a RevaGetReferencesResponse, got {response}"
        response: RevaGetReferencesResponse = response # type: ignore

        return {
            "references_to": response.references_to,
            "references_from": response.references_from,
        }

@register_tool
class RevaSetSymbolName(RevaRemoteTool):
    """
    A tool for creating or changing the name for a global symbol.
    This could be a function name, or a global variable name.
    """

    def __init__(self, project: AssistantProject, llm: BaseLLM) -> None:
        super().__init__(project, llm)
        self.description = "Used for retrieving cross references to and from addresses"

        self.tool_functions = [
            self.set_symbol_name,
        ]

    def set_symbol_name(self, new_name: str, old_name_or_address: str) -> Dict[str, str]:
        """
        Set the name of the symbol at the given address to `new_name`. If an old name is
        provided, rename the symbol to `new_name`.
        """
        from ..tool_protocol import RevaSetSymbolName, RevaSetSymbolNameResponse
        if isinstance(old_name_or_address, int):
            old_name_or_address = hex(old_name_or_address)

        set_symbol_name_message = RevaSetSymbolName(new_name=new_name, old_name_or_address=old_name_or_address)

        response = self.submit_to_tool(set_symbol_name_message)
        assert isinstance(response, RevaSetSymbolNameResponse), f"Expected a RevaSetSymbolNameResponse, got {response}"
        response: RevaSetSymbolNameResponse = response # type: ignore

        return {
            "old_name": old_name_or_address,
            "new_name": new_name,
        }

@register_tool
class RevaSetComment(RevaRemoteTool):
    """
    A tool for setting comments on addresses, functions and symbols.
    """

    def __init__(self, project: AssistantProject, llm: BaseLLM) -> None:
        super().__init__(project, llm)
        self.description = "Used for setting comments on addresses, functions and symbols"

        self.tool_functions = [
            self.set_comment,
        ]

    def set_comment(self, comment: str, address_or_symbol: str) -> Dict[str, str]:
        """
        Set the comment at the given address, function or symbol to `comment`.
        Use this when you want to add an explanation or note to a specific part
        of the code.
        """
        from ..tool_protocol import RevaSetComment, RevaSetCommentResponse
        set_comment_message: RevaMessageToTool = RevaSetComment(comment=comment, address_or_symbol=address_or_symbol)

        response = self.submit_to_tool(set_comment_message)
        assert isinstance(response, RevaSetCommentResponse), f"Expected a RevaSetCommentResponse, got {response}"
        response: RevaSetCommentResponse = response

        return response.model_dump()

@register_tool
class RevaLibraryImportIndex(RevaRemoteTool):
    """
    An index of imported libraries available to the
    reverse engineering assistant.
    """
    index_name = "imported_libraries"
    description = "Used for retrieving imported libraries"
    logger = logging.getLogger("reverse_engineering_assistant.RevaLibraryImportIndex")

    def __init__(self, project: AssistantProject, llm: BaseLLM) -> None:
        super().__init__(project, llm)
        self.description = "Used for retrieving imported libraries"
        self.tool_functions = [
            self.get_imported_libraries_list_paginated,
            self.get_imported_libraries_count,
        ]

    def get_imported_libraries_list_paginated(self, page: int, page_size: int = 20) -> List[str]:
        """
        Return a paginated list of imported libraries in the index. Use get_imported_libraries_count to get the total number of imported libraries.
        page is 1 indexed. To get the first page, set page to 1. Do not set page to 0.
        """
        from ..assistant_api_server import RevaCallbackHandler, to_send_to_tool

        if isinstance(page, str):
            page = int(page)
        if isinstance(page_size, str):
            page_size = int(page_size)
        if page == 0:
            raise ValueError("`page` is 1 indexed, page cannot be 0")

        get_imported_libraries_list_message = RevaGetImportedLibrariesList(page=page, page_size=page_size)
        callback_handler = RevaCallbackHandler(self.project, get_imported_libraries_list_message)
        to_send_to_tool.put(callback_handler)

        self.logger.debug(f"Waiting for response to {get_imported_libraries_list_message.model_dump_json()}")
        response = callback_handler.wait()
        assert isinstance(response, RevaMessageResponse), "Incorrect type returned from callback handler."
        if response.error_message:
            raise RevaToolException(response.error_message)

        if not isinstance(response, RevaGetImportedLibrariesListResponse):
            raise RevaToolException(f"Expected a RevaGetImportedLibrariesListResponse, got {response}")

        return response.list

    def get_imported_libraries_count(self) -> int:
        """
        Return the total number of imported libraries in the program.
        """

        response = self.submit_to_tool(RevaGetImportedLibrariesCount())
        assert isinstance(response, RevaMessageResponse), "Incorrect type returned from callback handler."

        if response.error_message:
            raise RevaToolException(response.error_message)

        if not isinstance(response, RevaGetImportedLibrariesCountResponse):
            raise ValueError(f"Expected a RevaGetImportedLibrariesCountResponse, got {response}")

        return response.count

