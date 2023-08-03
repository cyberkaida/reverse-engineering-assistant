#!/usr/bin/env python3
from __future__ import annotations
from typing import Any, List, Optional
from llama_index import VectorStoreIndex
from llama_index.readers.base import BaseReader
from llama_index.schema import Document

from llama_index import ServiceContext

from langchain.llms import TextGen
from llama_index import ServiceContext
from llama_index.llms import LangChainLLM

import logging
logging.basicConfig(level=logging.INFO)

print("Loading LLM")
llm = TextGen(model_url="http://127.0.0.1:5000")

service_context = ServiceContext.from_defaults()

import ghidra

import os

class GhidraReader(BaseReader):
    program: ghidra.program.model.listing.Program
    flat_api: ghidra.program.flatapi.FlatProgramAPI
    decompiler_api: ghidra.app.decompiler.flatapi.FlatDecompilerAPI
    monitor: ghidra.util.task.TaskMonitor

    def __init__(self, program: ghidra.program.model.listing.Program):
        self.program = program
        self.flat_api = ghidra.program.flatapi.FlatProgramAPI(self.program)
        self.decompiler_api = ghidra.app.decompiler.flatapi.FlatDecompilerAPI(self.flat_api)
        self.decompiler_api.initialize()
        # Get the monitor from the FlatProgramAPI
        self.monitor = self.flat_api.getMonitor()


    def _decompile_function(self, function: ghidra.program.model.listing.Function) -> str:
        # Use the FlatDecompilerAPI to decompile the function
        decompilation_result = self.decompiler_api.decompile(function, 30)
        return decompilation_result

    def load_data(self) -> List[Document]:
        """
        Gather data from Ghidra and ouput a list of ``Document`` objects.
        """
        # First let's decompile all the functions and turn them
        # into Document objects
        documents = []
        # initialise the monitor to the number of functions
        self.monitor.initialize(self.program.getFunctionManager().getFunctionCount())
        documents: List[Document] = []
        for function in self.program.getListing().getFunctions(True):
            # Get the decompiled output and create a Document from it
            self.monitor.setMessage(f"Decompiling function: {function.getName()}")
            print(f"Decompiling function: {function.getName()} @ {function.getEntryPoint()}")
            try:
                decompiled_function = self._decompile_function(function)
            except RuntimeError as e:
                print(f"Error creating document for function: {function.getName()} - {e}")
                continue
            self.monitor.setMessage(f"Creating document for function: {function.getName()}")
            document = Document(
                name=str(function.getName()),
                text=decompiled_function,
                metadata={
                    'address': str(function.getEntryPoint()),
                    'function': str(function),
                }
            )
            documents.append(document)
        print(f"Created {len(documents)} documents")
        return documents


print("Creating index...")
documents = GhidraReader(currentProgram).load_data()
print("Creating embeddings")
index = VectorStoreIndex.from_documents(documents, service_context=service_context)
print("Creating query engine")
query_engine = index.as_query_engine()
print("Question time!")

def ask_question(question: str) -> str:
    response = query_engine.query(question)
    return response

while True:
    question = askString("Question", "What do you want to know?")
    response = ask_question(question)
    print(response)
