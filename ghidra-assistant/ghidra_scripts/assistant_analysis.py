#!/usr/bin/env python3

from typing import List, Generator
import ghidra
from ghidra.program.model.listing import Program

from reverse_engineering_assistant.tool import ToolIntegration
from reverse_engineering_assistant.documents import AssistantDocument, DecompiledFunctionDocument, CrossReferenceDocument

if not isinstance(currentProgram, ghidra.program.model.listing.Program):
    currentProgram = currentProgram()
if not isinstance(monitor, ghidra.util.task.TaskMonitor):
    monitor = monitor()

class GhidraAssistant(ToolIntegration):
    flat_api: ghidra.program.flatapi.FlatProgramAPI
    decompiler_api: ghidra.app.decompiler.flatapi.FlatDecompilerAPI
    program: Program
    def __init__(self, program: Program):
        # Get the name of the project in Ghidra
        project_name: str = program.getDomainFile().getProjectLocator().getName() 
        self.program = program

        self.flat_api = ghidra.program.flatapi.FlatProgramAPI(self.program)
        self.decompiler_api = ghidra.app.decompiler.flatapi.FlatDecompilerAPI(self.flat_api)
        self.decompiler_api.initialize()

        super().__init__(project_name)

    def _decompile_function(self, function: ghidra.program.model.listing.Function) -> str:
        # Use the FlatDecompilerAPI to decompile the function
        decompilation_result = self.decompiler_api.decompile(function, 30)
        return decompilation_result

    def get_decompiled_functions(self) -> List[DecompiledFunctionDocument]:
        documents: List[DecompiledFunctionDocument] = []
        for function in self.program.getListing().getFunctions(True):

            if function.isThunk():
                print(f"Skipping thunk function {function.getName()}")
                continue

            try:
                # TODO: Check that the function entry is within initialised memory to avoid
                # attempting to decompile thunks
                decompiled_function = self._decompile_function(function)
                # Strip out the calling convention warning. This scares the model and it becomes very
                # concerned about security when it sees this.
                decompiled_function = decompiled_function.replace("/* WARNING: Unknown calling convention -- yet parameter storage is locked */", "")
                if "/* WARNING: Control flow encountered bad instruction data */" in  decompiled_function:
                    print(f"Skipping function {function.getName()} due to bad instruction data")
                    continue
            except RuntimeError as e:
                print(f"Error creating document for function: {function.getName()} - {e}")
                continue

            # Use the function reference to get callees and callers
            references_to = function.getCallingFunctions(monitor)
            references_from = function.getCalledFunctions(monitor)

            document = DecompiledFunctionDocument(
                function_name=function.getName(),
                decompilation=decompiled_function,
                function_start_address=function.getEntryPoint().toString(),
                function_end_address=function.getBody().getMaxAddress().toString(),
                function_signature=str(function.getSignature(True)),
                namespace=function.getParentNamespace().getName(),
                is_external=function.isExternal(),
                inbound_calls=[ref.getName() for ref in references_to],
                outbound_calls=[ref.getName() for ref in references_from],
            )
            print(f"Decompilation: {document}")
            documents.append(document)
        return documents

    def get_function_cross_references(self) -> List[CrossReferenceDocument]:
        """
        Iterate through all defined functions and generate a CrossReferenceDocument for each
        this will allow us to give the AI model access to cross reference data for each function
        and aid in question formulation during the planning stage
        """
        cross_reference_list: List[CrossReferenceDocument] = []
        for function in self.program.getListing().getFunctions(True):
            # TODO: Use the ReferenceManager to get references including the function body
            references_to = self.flat_api.getReferencesTo(function.getEntryPoint())
            # This will be inaccurate
            references_from = self.flat_api.getReferencesFrom(function.getEntryPoint())

            reference_doc = CrossReferenceDocument(
                    address=function.getEntryPoint().toString(),
                    symbol=function.getName(),
                    references_to=[ref.toString() for ref in references_to],
                    references_from=[ref.toString() for ref in references_from],
            )
            print(f"Cross reference: {reference_doc}")
            cross_reference_list.append(reference_doc)
        return cross_reference_list

    def get_documents(self) -> List[AssistantDocument]:
        documents: List[AssistantDocument] = []
        for decompiled_function in self.get_decompiled_functions():
            documents.append(decompiled_function)
        for cross_reference in self.get_function_cross_references():
            documents.append(cross_reference)
        return documents

if __name__ == '__main__':
    print("Ghidra Assistant!")

    assistant = GhidraAssistant(currentProgram) 
    assistant.save_documents()
