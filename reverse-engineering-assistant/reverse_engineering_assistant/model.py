#!/usr/bin/env python3
from __future__ import annotations

from langchain.llms import TextGen, LlamaCpp
from llama_index import ServiceContext, load_index_from_storage
from llama_index.llms import LangChainLLM, OpenAI

from enum import Enum

class ModelType(Enum):
    OpenAI = "openai"
    LocalLMStudio = "local_lmstudio"
    LocalLlamaCpp = "local_llama_cpp"
    TextGenWebUI = "text_gen_web_ui"

def get_llm_openai() -> ServiceContext:
    from llama_index.embeddings import OpenAIEmbedding
    return ServiceContext.from_defaults(embed_model=OpenAIEmbedding())

def get_model(model_type: ModelType = ModelType.OpenAI) -> ServiceContext:
    #if model_type == ModelType.OpenAI:
    return get_llm_openai()

