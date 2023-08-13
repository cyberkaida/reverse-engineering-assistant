#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import random
from typing import Any, List, Optional
from llama_index import StorageContext, VectorStoreIndex
from llama_index.indices.query.base import BaseQueryEngine
from llama_index.readers.base import BaseReader
from llama_index.schema import Document

from llama_index import ServiceContext

from langchain.llms import TextGen, LlamaCpp
from llama_index import ServiceContext, load_index_from_storage
from llama_index.llms import LangChainLLM

import logging
logging.basicConfig(level=logging.INFO)

print("Loading LLM")

# TODO: Pick the correct LLM based on a config option in Ghidra
# we can do this by asking the Ghidra plugin. Implement an option
# in `GhidraAssistantPluginRegistration` to get the LLM name.

# We can use any LLM supported by langchain (as this is what llama-index uses)
# https://python.langchain.com/docs/integrations/llms/

# Local mode
#langchain_llm = LlamaCpp(
#        model_path=str(Path.home() / "dev" / "models" / "Llama-2-7B-GGML" / "llama-2-7b-chat.ggmlv3.q4_0.bin"),
#    )

def get_llm_local() -> ServiceContext:
    from llama_index.llms import HuggingFaceLLM
    from llama_index.prompts.prompts import SimpleInputPrompt
    query_wrapper_prompt = SimpleInputPrompt(
        "Below is an instruction that describes a task. "
        "Write a response that appropriately completes the request.\n\n"
        "### Instruction:\n{query_str}\n\n### Response:"
    )
    import torch
    llm = HuggingFaceLLM(
        context_window=2048,
        max_new_tokens=256,
        generate_kwargs={"temperature": 0.25, "do_sample": False},
        query_wrapper_prompt=query_wrapper_prompt,
        tokenizer_name="Writer/camel-5b-hf",
        model_name="Writer/camel-5b-hf",
        device_map="auto",
        tokenizer_kwargs={"max_length": 2048},
        # uncomment this if using CUDA to reduce memory usage
        model_kwargs={"torch_dtype": torch.float16},
    )
    service_context = ServiceContext.from_defaults(chunk_size=512, llm=llm)
    return service_context


# TextGenUI mode
# TODO: Confirmed working, inference is not great, seems the embedding isn't working right?
def get_llm_textgen() -> ServiceContext:
    langchain_llm = TextGen(model_url="http://localhost:5000")
    llm = LangChainLLM(llm=langchain_llm)
    service_context = ServiceContext.from_defaults(llm=llm)
    return service_context


# OpenAI Mode
#llm = None # Default is OpenAPI and requires `OPENAI_API_KEY` to be set in the environment
def get_llm_openai() -> ServiceContext:
    return ServiceContext.from_defaults()

service_context = get_llm_openai()

import ghidra
from ghidra.app.plugin.core.interpreter import InterpreterConsole
from ghidra.program.util import DefinedDataIterator
from ghidra.program.model.data import StringDataInstance
from ghidra.program.model.listing import Program

# get the name of the sha256 of the current program
program_sha256 = currentProgram.getExecutableSHA256()

# ghidra-assistant storage directory
from pathlib import Path
# The embeddings are specific to an LLM, so we will regenerate them if the llm changes
storage_dir = Path.home() / ".config" / "ghidra-assistant" / service_context.llm.metadata.model_name
index_dir = storage_dir / "index" / program_sha256
document_directory = storage_dir / "documents" / program_sha256
document_directory.mkdir(parents=True, exist_ok=True)
# Note that we don't create the specific index directtory, we do that when we generate the
# index and call `.persist()`. This is to avoid loading an empty index.
# I don't know why the storage context doesn't do this for you. Maybe it's assumed you want
# to customise the index before saving?
storage_dir.mkdir(parents=True, exist_ok=True)

# If the index exists, load it. Otherwise go with the default in memory index and persist it
# once it is generated.
storage_context = StorageContext.from_defaults()
if index_dir.exists():
    storage_context = StorageContext.from_defaults(persist_dir=str(index_dir))

# These are implemented in the Java side. We'll use These
# to talk to the plugin.
from ghidra_assistant import GhidraAssistantPluginRegistration, GhidraAssistantScript

import os


# These are helper methods so we can talk to Ghidra's UI. I tried many ways to do this.
# - Subclassing a Java class from the python side. This failed because Jep can't dynamically create classes.
# - Implementing an interface from the Python side. This failed becase Jep can't dynamically create classes.
# - Using the Jep `jproxy` to implement an interface. This worked but ran into threading issues on the Java side.
# - Passing an object implementing an interface to the Java side, this failed because of threading
#   issues when calling back from Java to Python. Jep did not like when we called outside the python thread.
# Finally I just gave up and pull the Console object directly into Python using an interface implemented on our
# plugin. This was annoying because of the mix of Java and Python IO concepts with streams. So I implemented
# a simple read/write interface on the plugin class so we can just send simple strings. This works pretty well
# and is easy to use but I think it feels a little bad. Maybe we should instead implement a wrapper around the
# console object that accepts strings and pass that to python via the interface instead...
ghidra_assistant_plugin = getState().getTool().getService(GhidraAssistantPluginRegistration)
console: InterpreterConsole = ghidra_assistant_plugin.getConsole()
def writeConsole(text: str):
    ghidra_assistant_plugin.writeConsole(text + "\n")

def readConsole() -> str:
     return ghidra_assistant_plugin.readConsole()

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

        ## Add summary information like the architecture, imports, etc
        # TODO: for name in self.program.getOptions(Program.PROGRAM_INFO).getOptionNames():
        # ... getValueAsString(name)
        #program_info = self.program.getOptions(Program.PROGRAM_INFO)
        #program_summary_document = Document(
        #    name="Program Summary",
        #    text=str(program_info),
        #    metadata={
        #    }
        #)
        #self.monitor.setMessage(f"Program summary: {program_info}")
        #documents.append(program_summary_document)
        
        # Iterate over all defined strings in the program and generate a document for each
        # TODO: This seems to make the output significantly worse.
        #mega_string_list = [] 
        #for data_string in DefinedDataIterator.definedStrings(self.program):
        #    string = StringDataInstance.getStringDataInstance(data_string).getStringValue()
        #    mega_string_list.append(f"{data_string.getAddress} - {data_string.getLabel()}: {string!r}")
        #strings_document = Document(
        #    name="All Defined Strings",
        #    text="\n".join(mega_string_list),
        #    metadata={
        #    }
        #)
        #documents.append(strings_document)

        # Iterate over all the functions in the program and generate a document for each
        for function in self.program.getListing().getFunctions(True):
            # Get the decompiled output and create a Document from it
            #self.monitor.setMessage(f"Decompiling function: {function.getName()}")
            self.monitor.incrementProgress(1)
            print(f"Decompiling function: {function.getName()} @ {function.getEntryPoint()}")
            try:
                decompiled_function = self._decompile_function(function)
                # Strip out the calling convention warning. This scares the model and it becomes very
                # concerned about security when it sees this.
                decompiled_function = decompiled_function.replace("/* WARNING: Unknown calling convention -- yet parameter storage is locked */", "")
            except RuntimeError as e:
                print(f"Error creating document for function: {function.getName()} - {e}")
                continue
            self.monitor.setMessage(f"Creating document for function: {function.getName()}")
            # TODO:
            # - Add listing view
            # - Add cross references
            # - Ignore external thunks
            # - Add external flag
            # - Add namespace information
            document = Document(
                name=str(function.getName()),
                text=decompiled_function,
                metadata={
                    'address': str(function.getEntryPoint()),
                    'function': str(function),
                }
            )

            # Add the namespace to the metadata if one is present
            namespace = function.getParentNamespace()
            if namespace:
                document.metadata['namespace'] = str(namespace)
                document.metadata['is_external'] = str(namespace.isExternal())

            print(document.metadata)
            documents.append(document)


        # Get the text of the Listing view from Ghidra and
        # create a document from that

        # TODO: Should we do one document or many?


        print(f"Created {len(documents)} documents")

        for index, document in enumerate(documents):
            path = document_directory / f"{index}.txt"
            path.write_text(document.text)
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

from pathlib import Path
import time

assistant = GhidraAssistantAnalysis()

introduction_strings: List[str] = [
        "Can I help you?",
        "What can I do for you?",
        "How can I help?",
        "Pondering... 🧙🔮",
        "Reversing... 🚚 *beep* *beep* *beep*",
]

# Ascii art of a dragon
ascii_art = f"""
 *tap tap tap* {random.choice(introduction_strings)}
  /
🐉 
"""

assistant.updateEmbeddings()
# Our assistant's brain is primed with the information from the Ghidra database
# we can ask it questions!

writeConsole(ascii_art)
try:
    while True:
        question = readConsole()
        if question == "":
            # If we get nothing, we should just exit.
            # This is usually a signal that the plugin
            # is being disposed.
            time.sleep(1)
        else:
            print(f"Received question: '{question}'")
            answer = assistant.askQuestion(question)
            print(f"Answer: '{answer}'")
            writeConsole(answer)
except KeyboardInterrupt:
    pass

print("All done!")
