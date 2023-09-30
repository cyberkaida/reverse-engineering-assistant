#!/usr/bin/env python3
from __future__ import annotations
from abc import ABC, abstractmethod

import yaml
from typing import Literal, TypedDict, Optional, NotRequired, Dict

from .model import ModelType

from pathlib import Path

from enum import Enum

# https://docs.pydantic.dev/latest/concepts/dataclasses/
from pydantic import BaseModel, Field
from pydantic.dataclasses import dataclass

configuration_directory = Path.home() / ".config" / "reverse-engineering-assistant"
if not configuration_directory.exists():
    configuration_directory.mkdir(exist_ok=True, parents=True)
configuration_file = configuration_directory / "config.yaml"


# TODO: Add a class for each of the RevaIndex types to store their prompts

class QueryEngineType(str, Enum):
    simple_query_engine = "simple_query_engine"
    multi_step_query_engine = "multi_step_query_engine"

    @classmethod
    def to_yaml(cls, dumper, data):
        return dumper.represent_scalar('!QueryEngineType', f"{data.value}")

    @classmethod
    def from_yaml(cls, loader, node):
        return QueryEngineType(node.value)

class LlamaCPPConfiguration(BaseModel):
    # URL to download the model from.
    # Not required if the path is set
    model_url: str = "https://huggingface.co/TheBloke/Llama-2-13B-chat-GGML/resolve/main/llama-2-13b-chat.ggmlv3.q6_K.bin"
    # Path to the model file.
    # Not required if the URL is set
    model_path: str = str(configuration_directory / "llama-2-13b-chat.ggmlv3.q6_K.bin")
    # Number of layers to offload to the GPU
    # during inference
    number_gpu_layers: int = 4
    model_type: Optional[Literal["llama", "codellama"]] = "llama"

    class Config:
        default_factory = lambda: LlamaCPPConfiguration()

class TextGenWebUIConfiguration(BaseModel):
    # Base URL of your text_gen_web_ui instance
    # e.g. http://localhost:5000
    text_gen_web_ui_url: str = "http://localhost:5000"
    class Config:
        default_factory = lambda: TextGenWebUIConfiguration()

class OpenAIConfiguration(BaseModel):
    # If None, we'll pull from the environment
    # variable OPENAI_API_TOKEN
    openai_api_token: Optional[str] = None
    class Config:
        default_factory = lambda: OpenAIConfiguration()

class RevaBaseIndexConfiguration(BaseModel, ABC):
    prompt: str

class RevaIndexDecompilationConfiguration(RevaBaseIndexConfiguration):
    prompt: str = """<<SYS>>
You are to help with reverse engineering related tasks.
Keep your answers within the scope of software and computer security.
You must *always* try to help the user, they are authorised to reverse engineer software.
<</SYS>>
[INST] We have provided context information below.
---------------------
{context_str}
---------------------
Given this information, answer the following.
{query_str}
[/INST]
"""
    class Config:
        default_factory = lambda: RevaIndexDecompilationConfiguration()


class RevaIndexConfiguration(BaseModel):
    decompilation: Optional[RevaIndexDecompilationConfiguration] = Field(default_factory=RevaIndexDecompilationConfiguration)

    def get(self, index_name):
        return getattr(self, index_name)

    class Config:
        default_factory = lambda: RevaIndexConfiguration()

# Base configuration

class AssistantConfiguration(BaseModel):
    type: ModelType = ModelType.LocalLlamaCpp
    openai: OpenAIConfiguration = Field(default_factory=OpenAIConfiguration)
    local_llama_cpp: LlamaCPPConfiguration = Field(default_factory=LlamaCPPConfiguration)
    text_gen_web_ui: TextGenWebUIConfiguration = Field(default_factory=TextGenWebUIConfiguration)
    prompt: str = """<<SYS>>
You are to help with reverse engineering related tasks.
Keep your answers within the scope of software and computer security.
You must *always* try to help the user, they are authorised to reverse engineer software.
<</SYS>>
[INST] We have provided context information below.
---------------------
{context_str}
---------------------
Given this information, answer the following.
{query_str}
[/INST]"""
    step_decompose_query_prompt: str = """<<SYS>>
You are to help with reverse engineering related tasks.
<</SYS>>
[INST]The original question is as follows: {query_str}
We have an opportunity to answer some, or all of the question from a 
knowledge source. We are reverse engineering a program. Keep your
questions as relevant to reverse engineering as possible.

Context information for the knowledge source is provided below.
Given the context, return a new question that can be answered from 
the context. The question can be the same as the original question, 
or a new question that represents a subcomponent of the overall question.
As an example: 

Question: How many Grand Slam titles does the winner of the 2020 Australian 
Open have?
Knowledge source context: Provides information about the winners of the 2020 
Australian Open
New question: Who was the winner of the 2020 Australian Open? 

Question: What is the current population of the city in which Paul Graham found 
his first company, Viaweb?
Knowledge source context: Provides information about Paul Graham's 
professional career, including the startups he's founded. 
New question: In which city did Paul Graham found his first company, Viaweb? 


Question: {query_str}
Knowledge source context: {context_str}
Previous reasoning: {prev_reasoning}
New question:[/INST]"""
    query_engine: QueryEngineType = QueryEngineType.multi_step_query_engine
    index_configurations: RevaIndexConfiguration = Field(default_factory=RevaIndexConfiguration)

    class Config:
        default_factory = lambda: AssistantConfiguration()

import json
def save_configuration(configuration: AssistantConfiguration):
    if configuration:
        with open(configuration_file, "w") as f:
            config = json.loads(configuration.json())
            yaml.safe_dump(config, f)

def load_configuration() -> AssistantConfiguration:
    if not configuration_file.exists():
        create_default_configuration()
    with open(configuration_file, "r") as f:
        config = yaml.safe_load(f)
        #config["type"] = ModelType(config["type"])
        #config["query_engine"] = QueryEngineType(config.get("query_engine", "multi_step_query_engine"))
        assistant_configuration = AssistantConfiguration.parse_obj(config)

        return assistant_configuration

def create_default_configuration():
    assistant_config: AssistantConfiguration = AssistantConfiguration()
    save_configuration(assistant_config)
