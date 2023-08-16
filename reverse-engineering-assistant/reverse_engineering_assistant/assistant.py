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
from llama_index.indices.query.base import BaseQueryEngine
from llama_index.readers.base import BaseReader
from llama_index.schema import Document

from .tool import AssistantProject
from .model import ModelType, get_model

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
        index = VectorStoreIndex(embedding_documents, service_context=self.service_context)
        # TODO: Save the index, use the storage_context
        # TODO: Investigate chat mode:
        # index.as_chat_engine()
        self.query_engine = index.as_query_engine()

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
