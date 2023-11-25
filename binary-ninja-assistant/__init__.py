#!/usr/bin/env python3
from binaryninja import BinaryView, PluginCommand, MessageBoxButtonSet, MessageBoxIcon, show_message_box

from typing import List, Generator

from pathlib import Path

from reverse_engineering_assistant.tool import ToolIntegration
from reverse_engineering_assistant.documents import AssistantDocument, DecompiledFunctionDocument, CrossReferenceDocument

class BinjaAssistant(ToolIntegration):

    @property
    def name(self) -> str:
        return Path(self.bv.file.filename).name

    bv: BinaryView

    def __init__(self, bv:BinaryView):
        self.bv = bv

        super().__init__(self.name)

    def normalise_function_name(self, function_name: str) -> str:
        # Take the left of the bracket to get the name and maybe the return type
        name = function_name.split('(', maxsplit=1)[0]

        possible_chunks = name.split(' ', maxsplit=1)
        if len(possible_chunks) == 2:
            name = possible_chunks[1]
        else:
            name = possible_chunks[0]

        return name

    def get_decompiled_functions(self) -> List[DecompiledFunctionDocument]:

        decompiled_functions: List[DecompiledFunctionDocument] = []
        for function in self.bv.functions:
            print(f"Processing decompilation for function {function.symbol.full_name}")
            decompilation = function.hlil

            if decompilation is None:
                continue
            decompilation = str(decompilation)

            callees = [self.normalise_function_name(x.symbol.full_name) for x in function.callees]
            callers = [self.normalise_function_name(x.symbol.full_name) for x in function.callers]
            
            prototype =  f"{function.symbol.full_name}"

            document: DecompiledFunctionDocument = DecompiledFunctionDocument(
                    function_name = self.normalise_function_name(function.symbol.full_name),
                    decompilation = decompilation,
                    function_signature = prototype,
                    function_start_address = hex(function.lowest_address),
                    function_end_address = hex(function.highest_address),
                    inbound_calls = callers,
                    outbound_calls = callees,
                    is_external = function.is_thunk,
                    is_generated_name = function.symbol.auto,
            )
            decompiled_functions.append(document)
        return decompiled_functions

    def get_function_cross_references(self) -> List[CrossReferenceDocument]:
        cross_reference_list: List[CrossReferenceDocument] = []
        for function in self.bv.functions:
            print(f"Processing cross references for function {function.symbol.full_name}")
            references_to = [hex(x.address) for x in function.caller_sites]
            references_from = [hex(x) for x in function.callee_addresses]

            document: CrossReferenceDocument = CrossReferenceDocument(
                address = function.lowest_address,
                symbol = self.normalise_function_name(function.symbol.full_name),
                references_to = references_to,
                references_from = references_from,
            )
            cross_reference_list.append(document)
        return cross_reference_list

    def get_documents(self) -> List[AssistantDocument]:
        documents: List[AssistantDocument] = []
        documents.extend(self.get_decompiled_functions())
        documents.extend(self.get_function_cross_references())
        return documents

def push_analysis(bv):
    assistant = BinjaAssistant(bv)
    assistant.save_documents()
    print("Saved documents")


PluginCommand.register("ReVA Push", "Pushes current analysis to ReVA", push_analysis)
