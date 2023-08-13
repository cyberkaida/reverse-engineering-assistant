#!/usr/bin/env python3

"""
This file contains the main assistant logic.
It provides a number of APIs for
- embedding data into the model
- performing inference on the model
"""

from __future__ import annotations
from pathlib import Path

from typing import Any, List, Optional

from llama_index import ServiceContext
from llama_index import StorageContext, VectorStoreIndex
from llama_index.indices.query.base import BaseQueryEngine
from llama_index.readers.base import BaseReader
from llama_index.schema import Document

from tool import AssistantProject
import model
from model import ModelType

class ReverseEngineeringAssistant(object):
    project: AssistantProject
    service_context: ServiceContext

    query_engine: Optional[BaseQueryEngine] = None

    def __init__(self, project: str | AssistantProject, model_type: ModelType = ModelType.OpenAI) -> None:
        if isinstance(project, str):
            self.project = AssistantProject(project)
        else:
            self.project = project

        self.service_context = model.get_model(model_type)
        
    def load_embeddings(self):
        raise NotImplementedError()
    
    def update_embeddings(self):
        assistant_documents = self.project.get_documents()
        embedding_documents: List[Document] = []
        for assistant_document in assistant_documents:
            embedding_documents.append(Document(
                name=assistant_document.name,
                content=assistant_document.content,
                metadata=assistant_document.metadata,
            ))
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
    parser.add_argument("--project", type=str, help="Project name")
    # TODO: Model type from configuration

    args = parser.parse_args()

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
