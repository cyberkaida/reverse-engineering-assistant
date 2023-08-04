#!/usr/bin/env python3
from __future__ import annotations
from operator import index
from typing import Any, List, Optional
from llama_index import StorageContext, VectorStoreIndex
from llama_index.indices.query.base import BaseQueryEngine
from llama_index.readers.base import BaseReader
from llama_index.schema import Document

from llama_index import ServiceContext

from langchain.llms import TextGen
from llama_index import ServiceContext, load_index_from_storage
from llama_index.llms import LangChainLLM

import logging
logging.basicConfig(level=logging.INFO)

print("Loading LLM")
llm = TextGen(model_url="http://127.0.0.1:5000")


import ghidra
from ghidra.app.plugin.core.interpreter import InterpreterConsole

# get the name of the sha256 of the current program
program_sha256 = currentProgram.getExecutableSHA256()

# ghidra-assistant storage directory
from pathlib import Path
storage_dir = Path.home() / ".config" / "ghidra-assistant"
index_dir = storage_dir / "index" / program_sha256
storage_dir.mkdir(parents=True, exist_ok=True)

service_context = ServiceContext.from_defaults()
storage_context = StorageContext.from_defaults()
if index_dir.exists():
    storage_context = StorageContext.from_defaults(persist_dir=str(index_dir))


# These are implemented in the Java side. We'll use These
# to talk to the plugin.
from ghidra_assistant import GhidraAssistantPluginRegistration, GhidraAssistantScript

import os


console: InterpreterConsole = getState().getTool().getService(GhidraAssistantPluginRegistration).getConsole()
def writeConsole(text: str):
    getState().getTool().getService(GhidraAssistantPluginRegistration).writeConsole(text + "\n")

def readConsole() -> str:
     return getState().getTool().getService(GhidraAssistantPluginRegistration).readConsole()

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
            self.monitor.incrementProgress(1)
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

should_stop = False

#class GhidraAssistantAnalysis(GhidraAssistantScript):
class GhidraAssistantAnalysis:
    query_engine: Optional[BaseQueryEngine] = None
    def updateEmbeddings(self):

        monitor = getMonitor()
        monitor.setIndeterminate(True)
        # First check if the index already exists
        if index_dir.exists():
            # Load the index from disk
            writeConsole(f"Loading index from {index_dir}...")
            index = load_index_from_storage(storage_context=storage_context, service_context=service_context)
        else:
            writeConsole("Creating index...")
            documents = GhidraReader(currentProgram).load_data()
            monitor.setMessage("Pondering...")
            writeConsole("Creating embeddings... This may take some time...")
            index = VectorStoreIndex.from_documents(documents, service_context=service_context)
            index.storage_context.persist(str(index_dir))

        monitor.setMessage("Creating query engine...")
        writeConsole("Creating query engine")
        self.query_engine = index.as_query_engine()
        writeConsole("Question time!")

    def askQuestion(self, question: str) -> str:
        if self.query_engine is None:
            self.updateEmbeddings()
        print(f"Querying: {question}")
        answer = self.query_engine.query(question)
        print(f"Answer: {answer}")
        return str(answer)

    def shutdown(self):
        self.query_engine = None
        should_stop = True

# Now we have our interface defined, let's tell the plugin about it
import jep

# We can't directly create a instance derived from a Java type
# but we can use the proxy to implement an interface.
# https://github.com/ninia/jep/blob/master/src/test/python/test_jproxy.py#L34
# https://github.com/mandiant/Ghidrathon/issues/55

#proxy = jep.jproxy(GhidraAssistantAnalysis(), ["ghidra_assistant.GhidraAssistantScript"])

print("Registering LLM interface with plugin")
#getState().getTool().getService(GhidraAssistantPluginRegistration).registerScript(proxy)

from  tempfile import TemporaryDirectory
from pathlib import Path
import time

assistant = GhidraAssistantAnalysis()

# Ascii art of a dragon
ascii_art = """
 *tap tap tap* Can I help you?
  /
🐉 
"""

assistant.updateEmbeddings()


writeConsole(ascii_art)
try:
    while True:
        question = readConsole()
        if question.strip() == "":
            time.sleep(1)
        else:
            print(f"Received question: '{question}'")
            answer = assistant.askQuestion(question)
            print(f"Answer: '{answer}'")
            writeConsole(answer)
except KeyboardInterrupt:
    pass

print("All done!")
