#!/usr/bin/env python3
from __future__ import annotations

from typing import Optional
from pathlib import Path

from langchain.llms.base import BaseLLM

from enum import Enum

import logging
logger = logging.getLogger("reverse_engineering_assistant.model")

class ModelType(Enum):
    OpenAI = "openai"
    LocalLMStudio = "local_lmstudio"
    LocalLlamaCpp = "local_llama_cpp"
    TextGenWebUI = "text_gen_web_ui"
    Ollama = "ollama"

def get_llm_openai() -> BaseLLM:
    from langchain.chat_models import ChatOpenAI
    from .configuration import load_configuration, AssistantConfiguration
    import os
    config: AssistantConfiguration = load_configuration()
    model = config.openai.model
    if not model:
        model = "gpt-4-1106-preview"

    api_key = config.openai.openai_api_token
    if not api_key or api_key == 'null':
        api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OpenAI API key not set. Please set the OPENAI_API_KEY environment variable or set your key in the ReVA config.")

    llm = ChatOpenAI(model=model, api_key=api_key)
    return llm

def get_llm_ollama() -> BaseLLM:
    from langchain.llms.ollama import Ollama
    from langchain.embeddings import OllamaEmbeddings
    from .configuration import load_configuration, AssistantConfiguration

    config: AssistantConfiguration = load_configuration()
    system_prompt = config.prompt_template.system_prompt
    base_url = config.ollama.ollama_server_url

    logger.info(f"Loading Ollama - {config.ollama.model} from {base_url}")

    llm = Ollama(
            model=config.ollama.model,
            base_url=base_url,
    )
    embeddings = OllamaEmbeddings(
        base_url=base_url,
        model=config.ollama.model,
    )

    logger.debug(f"Ollama system prompt: {system_prompt}")
    logger.debug(f"Ollama base URL: {base_url}")
    logger.debug(f"Ollama model: {config.ollama.model}")

    return llm


def get_llm_text_gen_web_ui() -> BaseLLM:
    from langchain import PromptTemplate, LLMChain
    from langchain.llms import TextGen
    from langchain.embeddings import HuggingFaceEmbeddings
    from .configuration import load_configuration, AssistantConfiguration, TextGenWebUIConfiguration

    config: AssistantConfiguration = load_configuration()
    text_gen_web_ui_url = config.text_gen_web_ui.text_gen_web_ui_url
    llm = TextGen(model_url=text_gen_web_ui_url)

    return llm

def get_llm_local_llama_cpp() -> ServiceContext:
    from langchain.llms.llamacpp import LlamaCPP
    from .configuration import load_configuration, AssistantConfiguration

    config: AssistantConfiguration = load_configuration()


    model_url = config.local_llama_cpp.model_url
    model_path = config.local_llama_cpp.model_path
    n_gpu_layers = config.local_llama_cpp.number_gpu_layers

    if not Path(model_path).exists():
        model_path = None

    # TODO: Re-enable this feature
    #llm = LlamaCPP(
    #        model_url=model_url,
    #        model_path=model_path,
    #        temperature=0.1,
    #        max_new_tokens=256,
    #        # llama2 has a context window of 4096 tokens, but we set it lower to allow for some wiggle room
    #        context_window=3900,
    #        # kwargs to pass to __call__()
    #        generate_kwargs={},
    #        # kwargs to pass to __init__()
    #        # set to at least 1 to use GPU
    #        model_kwargs={
    #            'n_gpu_layers': n_gpu_layers,
    #            },
    #        # transform inputs into Llama2 format
    #        messages_to_prompt=messages_to_prompt,
    #        completion_to_prompt=completion_to_prompt,
    #        verbose=False,
    #        )
    raise NotImplementedError("Local Llama CPP is not yet implemented.")

def get_model(model_type: Optional[ModelType] = None) -> BaseLLM:
    """
    Returns a ServiceContext object for the specified model type.

    Args:
        model_type (Optional[ModelType], optional): The type of model to use. If None, the model type is loaded from the configuration file. Defaults to None.

    Raises:
        ValueError: If an unknown model type is specified.

    Returns:
        ServiceContext: A ServiceContext object for the specified model type.
    """
    if not model_type:
        from .configuration import load_configuration, AssistantConfiguration
        config: AssistantConfiguration = load_configuration()
        model_type = config.type

    match model_type:
        case ModelType.OpenAI:
            return get_llm_openai()
        case ModelType.Ollama:
            return get_llm_ollama()
        case ModelType.TextGenWebUI:
            return get_llm_text_gen_web_ui()
        case ModelType.LocalLlamaCpp:
            return get_llm_local_llama_cpp()
    raise ValueError(f"Unknown model type: {model_type}")

