#!/usr/bin/env python3

from typing import List, Generator
import ghidra
from ghidra.program.model.listing import Program

from reverse_engineering_assistant.tool import ToolIntegration
from reverse_engineering_assistant.documents import AssistantDocument, DecompiledFunctionDocument

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
            try:
                # TODO: Check that the function entry is withing initialised memory to avoid
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
            document = DecompiledFunctionDocument(
                function_name=function.getName(),
                decompilation=decompiled_function,
                function_start_address=function.getEntryPoint().toString(),
                function_signature=str(function),
                namespace=function.getParentNamespace().getName(),
                is_external=function.isExternal(),
            )
            documents.append(document)
        return documents

    def get_documents(self) -> List[AssistantDocument]:
        documents: List[AssistantDocument] = []
        for decompiled_function in self.get_decompiled_functions():
            documents.append(decompiled_function)
        return documents

if __name__ == '__main__':
    assistant = GhidraAssistant(currentProgram) 
    assistant.save_documents()
