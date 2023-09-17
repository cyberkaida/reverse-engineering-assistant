#!/usr/bin/env python3

"""
This file contains the main assistant logic.
It provides a number of APIs for
- embedding data into the model
- performing inference on the model
"""

from __future__ import annotations
from functools import cached_property
import logging
from pathlib import Path

from typing import Any, List, Optional

from llama_index import LLMPredictor
from llama_index import ServiceContext
from llama_index import StorageContext, VectorStoreIndex
from llama_index.indices.base import BaseIndex
from llama_index.indices.loading import load_index_from_storage
from llama_index.indices.query.base import BaseQueryEngine
from llama_index.indices.query.query_transform.base import StepDecomposeQueryTransform, HyDEQueryTransform
from llama_index.indices.query.query_transform.prompts import StepDecomposeQueryTransformPrompt
from llama_index.prompts import Prompt
from llama_index.query_engine.multistep_query_engine import MultiStepQueryEngine
from llama_index.query_engine.sub_question_query_engine import SubQuestionQueryEngine
from llama_index.readers.base import BaseReader
from llama_index.response_synthesizers.tree_summarize import TreeSummarize
from llama_index.schema import Document
from llama_index.tools.query_engine import QueryEngineTool
from llama_index.selectors.pydantic_selectors import (
    PydanticMultiSelector,
    PydanticSingleSelector,
)
from llama_index.query_engine.router_query_engine import RouterQueryEngine


from .tool import AssistantProject
from .model import ModelType, get_model
from .configuration import load_configuration, AssistantConfiguration, QueryEngineType
from .documents import AssistantDocument, CrossReferenceDocument, DecompiledFunctionDocument

logger = logging.getLogger('reverse_engineering_assistant')


class RevaIndex(object):
    """
    An index of documents available to the
    reverse engineering assistant.
    """
    # The project we will operate on
    project: AssistantProject
    # Service context for the index
    service_context: ServiceContext

    description: str

    index_directory: Path

    def __init__(self, project: AssistantProject, service_context: ServiceContext) -> None:
        self.project = project
        self.service_context = service_context
    
    @cached_property
    def index(self) -> BaseIndex:
        # TODO: Refactor to call load, then update, then persist
        return self.update_embeddings()

    def get_documents(self) -> List[AssistantDocument]:
        raise NotImplementedError()

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




class RevaDecompilationIndex(RevaIndex):
    """
    An index of decompiled functions available to the
    reverse engineering assistant.
    """
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

    def __init__(self, project: str | AssistantProject, model_type: Optional[ModelType] = None) -> None:
        if isinstance(project, str):
            self.project = AssistantProject(project)
        else:
            self.project = project

        self.service_context = get_model(model_type)
        
    def update_embeddings(self):

        # Get the indexes
        decompilation_index = RevaDecompilationIndex(self.project, self.service_context).index
        cross_reference_index = RevaCrossReferenceIndex(self.project, self.service_context).index
        #summary_index = RevaSummaryIndex(self.project, self.service_context).index

        # Summarise all summaries together, to try to derive a high level description of the program
        summeriser = TreeSummarize(
            service_context=self.service_context,
        ) 

        #all_summaries = [x.get_content() for x in summary_index.docstore.docs.values()]
        
        # TODO: Move this to the project object

        #summary_path = self.project.project_path / "summary.txt"
        #if summary_path.exists():
        #    with open(summary_path, "r") as f:
        #        summary = f.read()
        #else:
        #    summary = summeriser.get_response(
        #            query_str="What are the most important facts about this program?",
        #            text_chunks=all_summaries
        #            )
        #    
        #    with open(self.project.project_path / "summary.txt", "w") as f:
        #        f.write(str(summary))

        #logger.info(f"Summary: {summary}")

        # TODO: Swap this to some index router
        #index = summary_index
        #index = decompilation_index


        # TODO: Investigate chat mode:
        # index.as_chat_engine()

        configuration: AssistantConfiguration = load_configuration()
        prompt_template = configuration.get("prompt")
        if prompt_template:
            logger.debug(f"Using prompt template: {prompt_template}")
            prompt_template = Prompt(prompt_template)

        decompilation_query_engine = decompilation_index.as_query_engine(
                text_qa_template=prompt_template,
                service_context=self.service_context,
                verbose=False,
        )
        decompilation_tool = QueryEngineTool.from_defaults(
                query_engine=decompilation_query_engine,
                description="Useful for retrieving decompilation",
        )

        # Cross references!
        cross_reference_query_engine = cross_reference_index.as_query_engine(
                text_qa_template=prompt_template,
                service_context=self.service_context,
                verbose=False,
        )
        cross_reference_tool = QueryEngineTool.from_defaults(
                query_engine=cross_reference_query_engine,
                description="Useful for retrieving cross references to and from addresses",
        )

        #summary_query_engine = summary_index.as_query_engine(
        #        text_qa_template=prompt_template,
        #        verbose=True,
        #        service_context=self.service_context,
        #)
        #summary_tool = QueryEngineTool.from_defaults(
        #        query_engine=summary_query_engine,
        #        description="Useful for retrieving descriptions of functions",
        #)

        # TODO: Add more tools
        # - Strings in the binary. This should use a high k of n value for the index search
        #   and return many results.
        # - Cross references. This should return a graph like view of the callers and callees of a function
        #   Similar to the function call tree in Ghidra

        # TODO: This uses OpenAI, can we not do that??
        #base_query_engine = RouterQueryEngine(
        #    selector=PydanticSingleSelector.from_defaults(
        #    ),
        #    query_engine_tools=[
        #        decompilation_tool,
        #        #summary_tool,
        #    ],
        #    service_context=self.service_context,
        #)

        base_query_engine = decompilation_query_engine


        if configuration.get("query_engine") == QueryEngineType.multi_step_query_engine:
            # The multi steap query engine decomposes the query into sub-questions
            # each sub question is then answered by the base query engine

            # TODO: The first question does not get a context, this causes the AI to talk about tennis
            # if the question is not _obviously_ about a program. When it is about a program, the AI
            # talks about an arbitrary program, then the context is provided to the second question
            # and it gets on track again.

            # BUG: The MultiStepQueryEngine doe not get the correct LLM based on the query engine
            # instead it defaults to OpenAI and then uses the default prompt, which in our case
            # makes the AI talk about tennis...
            # https://github.com/jerryjliu/llama_index/blob/0509763f179f841b7aea4e60a5bb5bcc4a38f660/llama_index/indices/query/query_transform/prompts.py#L35
            # We avoid this by manually creating a the summarizer with a service context, and passing
            # that to the query engine. This avoids the code path where the multi step engine discovers the summarizer
            # from the base query engine, which yields an incorrect value and causes the multi step engine to use OpenAI

            tree_summarizer = TreeSummarize(
                    service_context=self.service_context,
            )

            step_decompose_query_prompt = configuration.get("step_decompose_query_prompt")
            if step_decompose_query_prompt:
                logger.info("Using step decompose query prompt from configuration")
                step_decompose_query_prompt = StepDecomposeQueryTransformPrompt(
                        step_decompose_query_prompt,
                )
                #step_decompose_query_prompt = step_decompose_query_prompt.partial_format(program_context=summary)
            query_transformer = StepDecomposeQueryTransform(
                    llm_predictor=self.service_context.llm_predictor,
                    step_decompose_query_prompt=step_decompose_query_prompt,
                    verbose=False,
            )

            multi_step_engine = MultiStepQueryEngine(
                    query_engine=base_query_engine,
                    query_transform=query_transformer,
                    response_synthesizer=tree_summarizer,
            )
            self.query_engine = multi_step_engine
        else:
            self.query_engine = base_query_engine

    def query(self, query: str) -> str:
        if not self.query_engine:
            self.update_embeddings()
        if not self.query_engine:
            raise Exception("No query engine available")
        answer = self.query_engine.query(query)
        return str(answer)

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
