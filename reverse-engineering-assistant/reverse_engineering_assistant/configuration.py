#!/usr/bin/env python3
from __future__ import annotations

import yaml
from typing import TypedDict, Optional, NotRequired

from .model import ModelType

from pathlib import Path

configuration_directory = Path.home() / ".config" / "reverse-engineering-assistant"
if not configuration_directory.exists():
    configuration_directory.mkdir(exist_ok=True, parents=True)
configuration_file = configuration_directory / "config.yaml"

class LlamaCPPConfiguration(TypedDict):
    # URL to download the model from.
    # Not required if the path is set
    model_url: Optional[str]
    # Path to the model file.
    # Not required if the URL is set
    model_path: Optional[str]
    # Number of layers to offload to the GPU
    # during inference
    number_gpu_layers: Optional[int]

class TextGenWebUIConfiguration(TypedDict):
    # Base URL of your text_gen_web_ui instance
    # e.g. http://localhost:5000
    text_gen_web_ui_url: str

class OpenAIConfiguration(TypedDict):
    # If None, we'll pull from the environment
    # variable OPENAI_API_TOKEN
    openai_api_token: Optional[str]

class AssistantConfiguration(TypedDict):
    type: ModelType
    openai: Optional[OpenAIConfiguration]
    local_llama_cpp: Optional[LlamaCPPConfiguration]
    text_gen_web_ui: Optional[TextGenWebUIConfiguration]

def save_configuration(configuration: AssistantConfiguration):
    with open(configuration_file, "w") as f:
        config = configuration.copy()
        config["type"] = config["type"].value
        yaml.safe_dump(config, f)

def load_configuration() -> AssistantConfiguration:
    if not configuration_file.exists():
        create_default_configuration()
    with open(configuration_file, "r") as f:
        config = yaml.safe_load(f)
        config["type"] = ModelType(config["type"])
        return config

def create_default_configuration():
    assistant_config: AssistantConfiguration = {
            "type": ModelType.OpenAI,
            "openai": {
                "openai_api_token": None,
            },
            "local_llama_cpp": {
                "model_url": "https://huggingface.co/TheBloke/Llama-2-13B-chat-GGML/resolve/main/llama-2-13b-chat.ggmlv3.q6_K.bin",
                "model_path": None,
                "number_gpu_layers": 1,
            },
            "text_gen_web_ui": {
                "text_gen_web_ui_url": "http://localhost:5000",
            },
    }
    save_configuration(assistant_config)
