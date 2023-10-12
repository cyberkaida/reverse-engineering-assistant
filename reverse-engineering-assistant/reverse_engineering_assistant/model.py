#!/usr/bin/env python3
from __future__ import annotations

from typing import Optional
from pathlib import Path

from langchain.llms import TextGen, LlamaCpp
from llama_index import ServiceContext, load_index_from_storage
from llama_index.llms import LangChainLLM, OpenAI

from enum import Enum

import logging
logger = logging.getLogger("reverse_engineering_assistant.model")

class ModelType(Enum):
    OpenAI = "openai"
    LocalLMStudio = "local_lmstudio"
    LocalLlamaCpp = "local_llama_cpp"
    TextGenWebUI = "text_gen_web_ui"

def get_llm_openai() -> ServiceContext:
    from llama_index.embeddings import OpenAIEmbedding
    #service_context = ServiceContext.from_defaults(embed_model=OpenAIEmbedding())
    service_context = ServiceContext.from_defaults(embed_model='local')

    return service_context

def get_llm_text_gen_web_ui() -> ServiceContext:
    from langchain import PromptTemplate, LLMChain
    from langchain.llms import TextGen
    from langchain.embeddings import HuggingFaceEmbeddings
    from .configuration import load_configuration, AssistantConfiguration, TextGenWebUIConfiguration

    config: AssistantConfiguration = load_configuration()
    text_gen_web_ui_url = config.text_gen_web_ui.text_gen_web_ui_url
    llm = TextGen(model_url=text_gen_web_ui_url)

    return ServiceContext.from_defaults(embed_model='local', llm=llm)

def get_llm_local_llama_cpp() -> ServiceContext:
    from llama_index.llms import LlamaCPP
    from llama_index.llms.llama_utils import messages_to_prompt, completion_to_prompt
    from .configuration import load_configuration, AssistantConfiguration, LlamaCPPConfiguration

    config: AssistantConfiguration = load_configuration()


    model_url = config.local_llama_cpp.model_url
    model_path = config.local_llama_cpp.model_path
    n_gpu_layers = config.local_llama_cpp.number_gpu_layers

    if not Path(model_path).exists():
        model_path = None

    llm = LlamaCPP(
            model_url=model_url,
            model_path=model_path,
            temperature=0.1,
            max_new_tokens=256,
            # llama2 has a context window of 4096 tokens, but we set it lower to allow for some wiggle room
            context_window=3900,
            # kwargs to pass to __call__()
            generate_kwargs={},
            # kwargs to pass to __init__()
            # set to at least 1 to use GPU
            model_kwargs={
                'n_gpu_layers': n_gpu_layers,
                },
            # transform inputs into Llama2 format
            messages_to_prompt=messages_to_prompt,
            completion_to_prompt=completion_to_prompt,
            verbose=False,
            )
    return ServiceContext.from_defaults(embed_model='local', llm=llm)

def get_model(model_type: Optional[ModelType] = None) -> ServiceContext:
    if not model_type:
        from .configuration import load_configuration, AssistantConfiguration
        config: AssistantConfiguration = load_configuration()
        model_type = config.type

    match model_type:
        case ModelType.OpenAI:
            return get_llm_openai()
        case ModelType.TextGenWebUI:
            return get_llm_text_gen_web_ui()
        case ModelType.LocalLlamaCpp:
            return get_llm_local_llama_cpp()
    raise ValueError(f"Unknown model type: {model_type}")

