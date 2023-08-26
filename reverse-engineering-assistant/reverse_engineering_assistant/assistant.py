#!/usr/bin/env python3

"""
This file contains the main assistant logic.
It provides a number of APIs for
- embedding data into the model
- performing inference on the model
"""

from __future__ import annotations
import logging
from pathlib import Path

from typing import Any, List, Optional

from llama_index import ServiceContext
from llama_index import StorageContext, VectorStoreIndex
from llama_index.indices.loading import load_index_from_storage
from llama_index.indices.query.base import BaseQueryEngine
from llama_index.query_engine.multistep_query_engine import MultiStepQueryEngine
from llama_index.query_engine.sub_question_query_engine import SubQuestionQueryEngine
from llama_index.indices.query.query_transform.base import StepDecomposeQueryTransform, HyDEQueryTransform
from llama_index import LLMPredictor
from llama_index.readers.base import BaseReader
from llama_index.response_synthesizers.tree_summarize import TreeSummarize
from llama_index.schema import Document
from llama_index.prompts import Prompt

from .tool import AssistantProject
from .model import ModelType, get_model
from .configuration import load_configuration, AssistantConfiguration, QueryEngineType


logger = logging.getLogger('reverse_engineering_assistant')

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
        
    def load_embeddings(self):
        raise NotImplementedError()
    
    def update_embeddings(self):
        assistant_documents = self.project.get_documents()
        embedding_documents: List[Document] = []
        if self.project.get_index_directory().exists():
            # Load the index from disk
            logger.info(f"Loading index from {self.project.get_index_directory()}")
            storage_context = StorageContext.from_defaults(
                persist_dir=str(self.project.get_index_directory()),
            )
            # load_index_from_storage passes its kwargs to the index constructor
            # if we don't pass service_context, we get the default AI model (OpenAI)
            index = load_index_from_storage(storage_context, service_context=self.service_context)
        else:
            for assistant_document in assistant_documents:
                logger.debug(f"Embedding document {assistant_document.name}\n{assistant_document.metadata}\n{assistant_document.content}")
                if len(assistant_document.content) >= 5000:
                    logger.warning(f"Document {assistant_document.name} is too long, skipping")
                    continue
                document = Document(
                    name=assistant_document.name,
                    text=assistant_document.content,
                    metadata=assistant_document.metadata,
                )
                embedding_documents.append(document)
            logger.info(f"Embedding {len(embedding_documents)} documents")
            index = VectorStoreIndex(
                    embedding_documents,
                    service_context=self.service_context,
                    show_progress=False,
            )
            logger.info(f"Saving index to {self.project.get_index_directory()}")
            self.project.get_index_directory().mkdir(parents=True, exist_ok=False)
            index.storage_context.persist(str(self.project.get_index_directory()))

        # TODO: Investigate chat mode:
        # index.as_chat_engine()

        configuration: AssistantConfiguration = load_configuration()
        prompt_template = configuration.get("prompt")
        if prompt_template:
            logger.info(f"Using prompt template: {prompt_template}")
            prompt_template = Prompt(prompt_template)

        base_query_engine = index.as_query_engine(
                text_qa_template=prompt_template,
                verbose=True,
                service_context=self.service_context,
        )

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

            query_transformer = StepDecomposeQueryTransform(
                    llm_predictor=self.service_context.llm_predictor,
                    verbose=True,
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
    print("Updating embeddings this might take a while...")
    assistant.update_embeddings()
    print("Embeddings updated!")

    # Enter into a loop answering questions
    try:
        while True:
            query = input("> ")
            print(assistant.query(query))
    except KeyboardInterrupt:
        print("Finished!")

if __name__ == '__main__':
    main()
