#!/usr/bin/env python3

"""
This file contains the main assistant logic.
It provides a number of APIs for
- embedding data into the model
- performing inference on the model
"""

from __future__ import annotations
from functools import cached_property, cache
from abc import ABC, abstractmethod
import logging
from pathlib import Path
import json

from typing import Any, List, Optional, Type

# TODO: This is terrible, we should delete llama-index :(
# Really we just use the LLM, we are hacking our own prompts anyways
# and the rest of this is just _complexity_ for no benefit.
from llama_index import PromptTemplate, ServiceContext
from llama_index import StorageContext, VectorStoreIndex
from llama_index.indices.base import BaseIndex
from llama_index.indices.loading import load_index_from_storage
from llama_index.indices.query.base import BaseQueryEngine
from llama_index.llms import ChatMessage
from llama_index.response_synthesizers.tree_summarize import TreeSummarize
from llama_index.schema import Document

# Agent
from llama_index.agent import ReActAgent
from llama_index.tools.query_engine import QueryEngineTool
from llama_index.tools.function_tool import FunctionTool


from .tool import AssistantProject
from .model import ModelType, get_model
from .configuration import load_configuration, AssistantConfiguration
from .documents import AssistantDocument, CrossReferenceDocument, DecompiledFunctionDocument

logger = logging.getLogger('reverse_engineering_assistant')

"""
List of RevaIndex classes to be registered with the assistant.
"""
_reva_index_list: List[Type[RevaIndex]] = []

def register_index(cls: Type[RevaIndex]) -> Type[RevaIndex]:
    _reva_index_list.append(cls)
    return cls


class RevaIndex(ABC):
    """
    An index of documents available to the
    reverse engineering assistant.
    """
    # The project we will operate on
    project: AssistantProject
    # Service context for the index
    service_context: ServiceContext

    index_name: str
    description: str

    index_directory: Path

    def __str__(self) -> str:
        return f"{self.index_name} @ {self.index_directory}"

    def __init__(self, project: AssistantProject, service_context: ServiceContext) -> None:
        self.project = project
        self.service_context = service_context
    
    @cached_property
    @abstractmethod
    def index(self) -> BaseIndex:
        # TODO: Refactor to call load, then update, then persist
        return self.update_embeddings()

    @abstractmethod
    def get_documents(self) -> List[AssistantDocument]:
        raise NotImplementedError()

    @cache
    def as_query_engine(self) -> BaseQueryEngine:
        """
        Return a query engine for this index
        """
        configuration = load_configuration()
        prompt = PromptTemplate(configuration.prompt_template.index_query_prompt)
        query_engine = self.index.as_query_engine(
                text_qa_template=prompt,
                service_context=self.service_context,
                similarity_top_k=5,
                show_progress=False,
                verbose=False,
        )

        return query_engine

    @cache
    def as_tool(self) -> QueryEngineTool:
        """
        Return a query engine tool for this index
        """
        tool = QueryEngineTool.from_defaults(
                query_engine=self.as_query_engine(),
                description=self.description,
        )
        return tool

    def update_embeddings(self) -> BaseIndex:
        index = self.load_index()
        if not index:
            logger.info(f"No index on disk. Generating...")
            documents = self.get_documents()
            index = self.persist_index(documents)
        return index

    def load_index(self) -> Optional[BaseIndex]:
        if self.index_directory.exists():
            # Load the index from disk
            logger.info(f"Loading index from {self.project.get_index_directory()}")
            storage_context = StorageContext.from_defaults(
                persist_dir=str(self.index_directory),
            )
            # load_index_from_storage passes its kwargs to the index constructor
            # if we don't pass service_context, we get the default AI model (OpenAI)
            index = load_index_from_storage(storage_context, service_context=self.service_context)
            return index

    def persist_index(self, documents: List[AssistantDocument]) -> BaseIndex:
        """
        Given a list of documents, create an index and persist it to disk,
        return the index.
        """
        embedding_documents: List[Document] = []
        for assistant_document in documents:
            # Transform from an AssistantDocument (our type) to a Document (llama-index type)
            document = Document(
                name=assistant_document.name,
                text=assistant_document.content,
                metadata=assistant_document.metadata,
            )
            embedding_documents.append(document)
        logger.info(f"Embedding {len(embedding_documents)} documents")
        # TODO: Do we want to store things differently?
        index = VectorStoreIndex(
                embedding_documents,
                service_context=self.service_context,
                show_progress=False,
        )
        logger.info(f"Saving index to {self.project.get_index_directory()}")
        self.index_directory.mkdir(parents=True, exist_ok=False)
        index.storage_context.persist(str(self.index_directory))
        return index




@register_index
class RevaDecompilationIndex(RevaIndex):
    """
    An index of decompiled functions available to the
    reverse engineering assistant.
    """
    index_name = "decompilation"
    description = "Used for retrieving decompiled functions"
    index_directory: Path
    def __init__(self, project: AssistantProject, service_context: ServiceContext) -> None:
        super().__init__(project, service_context)
        self.index_directory = self.project.get_index_directory() / "decompiled_functions"
        self.description = "Used for retrieveing decompiled functions"

    def get_documents(self) -> List[AssistantDocument]:
        """
        Filter documents in the project to just the DecompiledFunctionDocuments
        """
        assistant_documents = self.project.get_documents()
        decompiled_functions: List[AssistantDocument] = []
        for document in assistant_documents:
            logger.info(f"Checking {document}")
            if document.type == DecompiledFunctionDocument:
                decompiled_functions.append(document)
        return decompiled_functions

class RevaCrossReferenceIndex(RevaIndex):
    """
    An index of cross references, to and from, addresses.

    TODO: Make this a real tool the LLM can use
    """
    index_directory: Path
    def __init__(self, project: AssistantProject, service_context: ServiceContext) -> None:
        super().__init__(project, service_context)
        self.index_directory = self.project.get_index_directory() / "cross_references"
        self.description = "Used for retrieving cross references to and from addresses"

    def get_documents(self) -> List[AssistantDocument]:
        assistant_documents = self.project.get_documents()
        cross_references: List[AssistantDocument] = []
        for document in assistant_documents:
            if isinstance(document, CrossReferenceDocument):
                cross_references.append(document)
        return cross_references


class RevaSummaryIndex(RevaIndex):
    """
    An index of summaries available to the
    reverse engineering assistant.
    """
    index_directory: Path
    def __init__(self, project: AssistantProject, service_context: ServiceContext) -> None:
        super().__init__(project, service_context)
        self.index_directory = self.project.get_index_directory() / "summaries"
        self.description = "Used for retrieving summaries"

    def get_documents(self) -> List[AssistantDocument]:
        # Summaries the document and embed the summary into the vector store
        summeriser = TreeSummarize(
            service_context=self.service_context,
        ) 

        summarised_documents: List[AssistantDocument] = []

        for document in self.project.get_documents():
            if document.type == DecompiledFunctionDocument:
                summary = summeriser.get_response(
                        query_str="Summarise the following function",
                        text_chunks=[assistant_document.content],
                )
                logger.debug(f"Summary {assistant_document}: {summary}")

                # TODO: Implement the SummaryDocument type?
                raise NotImplementedError()


class ReverseEngineeringAssistant(object):
    project: AssistantProject
    service_context: ServiceContext

    query_engine: Optional[BaseQueryEngine] = None

    indexes: List[RevaIndex]

    def __init__(self, project: str | AssistantProject, model_type: Optional[ModelType] = None) -> None:
        if isinstance(project, str):
            self.project = AssistantProject(project)
        else:
            self.project = project

        self.service_context = get_model(model_type)

        # We take the registered index types and construct concrete indexes from them
        self.indexes = [ index_type(self.project, self.service_context) for index_type in _reva_index_list]
        
    def update_embeddings(self):
        # Summarise all summaries together, to try to derive a high level description of the program
        summeriser = TreeSummarize(
            service_context=self.service_context,
        ) 

        # Here I pull our own prompt

        configuration: AssistantConfiguration = load_configuration()

        # TODO: Add more tools
        # - Strings in the binary. This should use a high k of n value for the index search
        #   and return many results.
        # - Cross references. This should return a graph like view of the callers and callees of a function
        #   Similar to the function call tree in Ghidra
        from .llama_index_overrides import RevaSelectionOutputParser, REVA_SELECTION_OUTPUT_PARSER

        logger.debug("Building query engine")
        for index in self.indexes:
            logger.debug(f"Loading index: {index}")

        chat_history: List[ChatMessage] = [
             ChatMessage(role="system", content=configuration.prompt_template.system_prompt),
        ]
        import pdb; pdb.set_trace()

        self.query_engine = ReActAgent.from_tools(
            tools=[index.as_tool() for index in self.indexes],
            service_context=self.service_context,
            llm=self.service_context.llm,
            chat_history=chat_history,
            )

    def query(self, query: str) -> str:
        if not self.query_engine:
            self.update_embeddings()
        if not self.query_engine:
            raise Exception("No query engine available")
        try:
            answer = self.query_engine.query(query)
            return str(answer)
        except json.JSONDecodeError as e:
            logger.exception(f"Failed to parse JSON response from query engine: {e.doc}")
            return "Failed to parse JSON response from query engine"

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Reverse Engineering Assistant")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
    parser.add_argument("--project", required=True, type=str, help="Project name")
    # TODO: Model type from configuration

    args = parser.parse_args()
    logging_level = logging.DEBUG if args.verbose else logging.INFO

    try:
        import rich
        from rich.logging import RichHandler
        logging.basicConfig(level=logging_level, handlers=[RichHandler()])
    except ImportError:
        logging.basicConfig(level=logging_level)


    assistant = ReverseEngineeringAssistant(args.project)
    logger.info("Updating embeddings... this might take a while...")
    assistant.update_embeddings()

    # Enter into a loop answering questions
    try:
        while True:
            query = input("> ")
            print(assistant.query(query))
    except KeyboardInterrupt:
        print("Finished!")

if __name__ == '__main__':
    main()
