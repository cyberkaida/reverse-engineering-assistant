#!/usr/bin/env python3
from __future__ import annotations

from typing import Optional
from pathlib import Path

from langchain.llms.base import BaseLLM
from langchain_openai import ChatOpenAI
from langchain.chat_models.base import BaseChatModel
import os

from enum import Enum

import logging
logger = logging.getLogger("reverse_engineering_assistant.model")

class ModelType(Enum):
    OpenAI = "openai"
    LocalLMStudio = "local_lmstudio"
    LocalLlamaCpp = "local_llama_cpp"
    TextGenWebUI = "text_gen_web_ui"
    Ollama = "ollama"



def get_llm_openai() -> BaseChatModel:
    from .configuration import load_configuration, AssistantConfiguration
    config: AssistantConfiguration = load_configuration()
    model = config.openai.model
    if not model:
        model = "gpt-4-1106-preview"

    api_key = config.openai.openai_api_token
    if not api_key or api_key == 'null':
        api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OpenAI API key not set. Please set the OPENAI_API_KEY environment variable or set your key in the ReVA config.")

    llm = ChatOpenAI(
        model=model,
        api_key=api_key
    )
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

def get_model(model_type: Optional[ModelType] = None) -> BaseChatModel | BaseLLM:
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
            raise NotImplementedError("llama-cpp is not yet implemented")
    raise ValueError(f"Unknown model type: {model_type}")

