#!/usr/bin/env python3
from __future__ import annotations

from typing import Optional, TypeAlias, Union
from pathlib import Path

from pydantic import SecretStr

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.language_models.base import BaseLanguageModel
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI

import os

from pydantic import SecretStr

from enum import Enum

import logging
logger = logging.getLogger("reverse_engineering_assistant.model")

class ModelType(Enum):
    OpenAI = "openai"
    Ollama = "ollama"

type RevaModel = Union[ChatOpenAI, ChatOllama]

def get_llm_openai(model: str = "gpt-4o", api_key: Optional[str] = None) -> ChatOpenAI:
    if not api_key or api_key == 'null' or api_key == "OPENAI_API_KEY":
        api_key = os.environ.get("OPENAI_API_KEY")

    if not api_key:
        raise ValueError("OpenAI API key not set. Please set the OPENAI_API_KEY environment variable or set your key in the ReVA config.")
    llm = ChatOpenAI(
        model=model,
        api_key=api_key # type: ignore
    )
    return llm

def get_llm_ollama(base_url: Optional[str] = None, model: str = "llama3") -> ChatOllama:
    logger.info(f"Loading Ollama - {model} from {base_url}")
    if not base_url:
        base_url = 'http://127.0.0.1:11434'
    llm = ChatOllama(
        model=model,
        base_url=base_url,
    )

    return llm

def get_model(model_type: ModelType = ModelType.OpenAI) -> RevaModel:
    """
    Returns a ServiceContext object for the specified model type.

    Args:
        model_type (Optional[ModelType], optional): The type of model to use. If None, the model type is loaded from the configuration file. Defaults to None.

    Raises:
        ValueError: If an unknown model type is specified.

    Returns:
        ServiceContext: A ServiceContext object for the specified model type.
    """

    match model_type:
        case ModelType.OpenAI:
            return get_llm_openai()
        case ModelType.Ollama:
            return get_llm_ollama()
    raise ValueError(f"Unknown model type: {model_type}")