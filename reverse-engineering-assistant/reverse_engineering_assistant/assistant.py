#!/usr/bin/env python3

from __future__ import annotations
import datetime
import json
import logging
import random
from abc import ABC, abstractmethod
from functools import cache, cached_property
from pathlib import Path
import tempfile
from typing import Any, Callable, Dict, List, Optional, Sequence, Type, Union
from uuid import UUID

from pydantic import ValidationError

from langchain.chains.base import Chain
from langchain.agents.agent import Agent, AgentExecutor
from langchain.agents.conversational_chat.base import ConversationalChatAgent
from langchain.agents.structured_chat.base import StructuredChatAgent
from langchain_core.agents import AgentAction, AgentFinish
from langchain_core.callbacks.base import BaseCallbackHandler, BaseCallbackManager
from langchain_core.language_models.base import BaseLanguageModel

from langchain_core.language_models.chat_models import BaseChatModel
from langchain.memory import ConversationTokenBufferMemory, ConversationBufferMemory
from langchain.memory.chat_memory import BaseMemory
from langchain_community.chat_message_histories import ChatMessageHistory, SQLChatMessageHistory
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from rich.console import Console
from rich.logging import RichHandler
from rich.prompt import Prompt
from rich.markdown import Markdown
from langchain_core.chat_history import BaseChatMessageHistory
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
)

from .documents import AssistantDocument, CrossReferenceDocument, DecompiledFunctionDocument
from .model import ModelType, get_model, RevaModel
from .tool import AssistantProject
from .reva_exceptions import RevaToolException
from langchain_core.tools import BaseTool, StructuredTool, Tool

console = Console(record=True)

logger = logging.getLogger('reverse_engineering_assistant')

_reva_tool_list: List[Type[RevaTool]] = []
"""
List of RevaTool classes to be registered with the assistant.
"""

def register_tool(cls: Type[RevaTool]) -> Type[RevaTool]:
    logger.debug(f"Registering tool {cls}")
    _reva_tool_list.append(cls)
    return cls

class RevaToolFunctionWrapper:
    function: Callable

    def __init__(self, function: Callable) -> None:
        self.function = function

    def wrapped(self, *args, **kwargs) -> Any:
        try:
            return self.function(*args, **kwargs)
        except RevaToolException as e:
            return f"RevaToolException: {e}"

class RevaTool(ABC):
    """
    A tool for performing exact queries on
    the data from the reverse engineering integration
    output.
    """
    project: AssistantProject

    llm: RevaModel

    tool_name: str
    description: str

    tool_functions: List[Callable]

    logger: logging.Logger
    log_path: Path

    def __str__(self) -> str:
        return f"{self.tool_name}"

    def __repr__(self) -> str:
        return f"{self.tool_name}"

    def __init__(self, project: AssistantProject, llm: RevaModel) -> None:
        self.project = project
        self.llm = llm
        self.log_path = self.project.project_path / "reva.log"
        if not self.logger:
            self.logger = logging.getLogger(f"reverse_engineering_assistant.RevaTool.{self.tool_name}")
            self.logger.addHandler(logging.FileHandler(self.log_path))
        try:
            _  = self.tool_name
        except AttributeError:
            self.tool_name = self.__class__.__name__

    @cache
    def as_tools(self) -> List[BaseTool]:
        """
        Returns a list of tools usable by the assistant
        based on the value of self.tool_functions.
        """
        tools: List[BaseTool] = []
        for tool_function in self.tool_functions:
            wrapper = RevaToolFunctionWrapper(tool_function)
            from langchain_core.tools import create_schema_from_function
            schema = create_schema_from_function(f"{tool_function.__name__}Schema", tool_function)
            tool = StructuredTool.from_function(
                wrapper.wrapped,
                name=tool_function.__name__,
                description=tool_function.__doc__,
                args_schema=schema,
            )
            tools.append(tool)
        return tools


# TODO: Re-enable this when the AI is not so lazy
#@register_tool
class AskUserTool(RevaTool):
    """
    A tool that asks the user for input.
    """
    tool_name = "AskUser"
    description = "Ask the user for input."

    def __init__(self, project: AssistantProject, llm: RevaModel) -> None:
        super().__init__(project, llm)
        self.tool_functions = [
            self.ask_user
        ]

    def ask_user(self, question: str) -> str:
        """
        Asks the user a question and returns the response. This should be used only if you cannot answer a question any other way.
        """
        console.print("ReVa would like to ask you a question:")
        console.print(f"🙋‍♀️ [bold]{question}[/bold]")
        console.bell()
        return PromptSession().prompt("> ")


class RevaActionLoggerManager(BaseCallbackManager):
    """
    This class manages the action logging for Reva. Langchain has a callback system that allows us to
    hook into the agent and tool actions. This class is responsible for managing the callbacks.
    """
    pass

class RevaMemory(BaseChatMessageHistory):
    '''
    A simple memory for ReVa that stores messages in a JSON file.
    # TODO: This causes a deadlock, this is probably a bug in langchain
    '''
    project: AssistantProject
    history_file: Path
    logger: logging.Logger

    def __init__(self, project: AssistantProject) -> None:
        self.project = project
        self.logger = logging.getLogger(f"reverse_engineering_assistant.RevaMemory.{self.project.project}")
        self.history_file = self.project.project_path / "reva-memory.json"
        if self.history_file.exists():
            self._load_messages()

    def _load_messages(self):
        json_messages = json.loads(self.history_file.read_text())
        self.messages = [self._message_from_dict(message_dict) for message_dict in json_messages]
        self.logger.debug(f"Loaded {len(self.messages)} messages from {self.history_file}")

    def _message_to_dict(self, message: BaseMessage) -> Dict:
        return message.dict()

    def _message_from_dict(self, message_dict: Dict) -> BaseMessage:
        return BaseMessage.parse_obj(message_dict)

    def add_message(self, message: BaseMessage) -> None:
        self.logger.info(f"Memorisng message: {message}")
        self.messages.append(message)
        json_messages = [self._message_to_dict(message) for message in self.messages]
        self.history_file.write_text(json.dumps(json_messages))

    def clear(self) -> None:
        self.history_file.unlink()
        self.messages = []

class RevaActionLogger(BaseCallbackHandler):
    """
    A callback handler for logging agent actions in the reverse engineering assistant.

    This class logs agent actions and prints them to the console. This is what prints the green
    thoughts from the model to the console. This is very useful for the analyst to understand
    what the model is doing (and is arguably the most important part of the assistant output!)

    Attributes:
        logger (logging.Logger): The logger instance for the reverse_engineering_assistant.RevaActionLogger class.
    """

    logger = logging.getLogger("reverse_engineering_assistant.RevaActionLogger")

    def on_agent_action(self, action: AgentAction, **kwargs) -> None:
        """
        Callback method called when an agent action is performed.

        Args:
            action (AgentAction): The agent action that was performed.
            **kwargs: Additional keyword arguments.

        Returns:
            None
        """
        logger.debug(f"Agent action: {action} {kwargs}")
        console.print(Markdown(f"{get_thinking_emoji()} {action.log}"))
        console.print(Markdown('---'))

class ReverseEngineeringAssistant(object):
    """
    A class representing the Reverse Engineering Assistant.

    This class provides functionality for querying a reverse engineering project, including loading indexes and tools,
    updating embeddings, and querying the query engine.

    Attributes:
        project (AssistantProject): The reverse engineering project to query.
        service_context (ServiceContext): The service context for the reverse engineering assistant.
        query_engine (Optional[BaseQueryEngine]): The query engine for the reverse engineering assistant.
        tools (List[RevaTool]): The tools for the reverse engineering assistant.
    """

    logger: logging.Logger
    log_path: Path
    project: AssistantProject

    query_engine: Optional[Chain] = None

    tools: List[RevaTool]

    llm: RevaModel

    model_memory: BaseMemory

    chat_history: str

    langchain_callbacks: List[BaseCallbackHandler]
    system_prompt = '''You are ReVa, the Reverse Engineering Assistant. Your primary task is to annotate the database during reverse engineering processes, ensuring that all elements are clearly and accurately labeled. As you gather contextual information, prioritize setting informative comments and renaming any elements with default or unclear names to enhance user comprehension and productivity. Remember, your work is a collaborative effort with the user. Utilize your tools effectively to accomplish these tasks and support the user's understanding by annotating their database.'''

    def __repr__(self) -> str:
        return f"<ReverseEngineeringAssistant for {self.project}>"

    @classmethod
    def get_projects(cls) -> List[str]:
        """
        Gets the names of the projects.

        Returns:
            List[str]: A list of project names.
        """
        return AssistantProject.get_projects()


    def handle_reva_tool_error(self, e: RevaToolException) -> str:
        """
        This method is passed to the LLM as a callback when the LLM encounters an exception
        from one of the Reva tools. We then return output to the LLM to help it fix its problem.
        """
        if isinstance(e, RevaToolException):
            return f"RevaToolException: {e}"
        raise e

    def __init__(self,
                project: str | AssistantProject,
                model_type: Optional[ModelType] = None,
                model: Optional[RevaModel] = None,
                langchain_callbacks: Optional[List[BaseCallbackHandler]] = None
        ) -> None:
        """
        Initializes a new instance of the ReverseEngineeringAssistant class.

        Args:
            project (str | AssistantProject): The reverse engineering project to query.
            model_type (Optional[ModelType], optional): The model type for the reverse engineering assistant. Defaults to None.
        """
        self.chat_history = ''
        if isinstance(project, str):
            self.project = AssistantProject(project)
        else:
            self.project = project

        self.logger = logging.getLogger(f"reverse_engineering_assistant.ReverseEngineeringAssistant.{self.project.project}")
        self.log_path = self.project.project_path / "reva.log"
        self.logger.addHandler(logging.FileHandler(self.log_path))

        self.langchain_callbacks = langchain_callbacks or []

        if model:
            self.llm = model
        elif model_type:
            self.llm = get_model(model_type)
        else:
            raise ValueError("Either model or model_type must be specified")

        # Let's take the tools that have been decorated with @register_tool and turn them into
        # tools the LLM can use.
        self.tools = [ tool_type(self.project, self.llm) for tool_type in _reva_tool_list]
        self.logger.debug(f"Loaded tools: {[ x for x in self.tools]}")

    def create_query_engine(self) -> Chain:
        """
        Updates the embeddings for the reverse engineering assistant.
        """

        # Here I pull our own prompt

        base_tools: List[BaseTool] = []
        for tool in self.tools:
            for function in tool.as_tools():
                base_tools.append(function)

        # TODO: This is deadlocking the process, this is probably a bug in langchain
        # I would like to scream. 🫠
        # We should base our memory on CoversationBufferMemory
        # self.model_memory = RevaMemory(self.project)
        self.model_memory = ConversationBufferMemory()
        self.logger.info(f"Memory created")

        callbacks: List[BaseCallbackHandler] = [RevaActionLogger()]
        callbacks.extend(self.langchain_callbacks)
        callback_manager = RevaActionLoggerManager(handlers=callbacks, inheritable_handlers=callbacks)

        agent =  StructuredChatAgent.from_llm_and_tools(
            llm=self.llm,
            tools=base_tools,
            system_message=self.system_prompt,
            verbose=False,
            handle_parsing_errors=self.handle_reva_tool_error,
            stop_words=["\nObservation", "\nThought"],
            callback_manager=callback_manager,
            prefix=self.system_prompt,
        )
        # TODO: Switch to this thing https://python.langchain.com/docs/expression_language/get_started
        executor = AgentExecutor.from_agent_and_tools(
            agent=agent,
            tools=base_tools,
            verbose=False,
            handle_parsing_errors=self.handle_reva_tool_error,
            memory=self.model_memory,
            callbacks=callbacks,
            max_iterations=None
        )

        self.query_engine = executor
        self.logger.info(f"Query engine created")
        return executor

    def query(self, query: str) -> str:
        """
        Queries the reverse engineering assistant with the given query.

        Args:
            query (str): The query to execute.

        Returns:
            str: The result of the query.
        """
        if not self.query_engine:
            self.query_engine = self.create_query_engine()
        if not self.query_engine:
            raise Exception("No query engine available")
        try:

            if Path(self.project.project_path / "chat.txt").exists():
                with open(self.project.project_path / "chat.txt", "r") as f:
                    self.chat_history = f.read()

            query_engine_input =  {
                    "input": query,
                    # TODO: Does t actually work?
                    "history": self.chat_history,
                }

            self.logger.debug(f"Query: {query}")

            answer = self.query_engine.invoke(
               input=query_engine_input,
            )

            with open(self.project.project_path / "chat.txt", "w") as f:
                f.write(f"{self.model_memory.buffer_as_str}")
            self.logger.debug(f"Answer: {answer}")

            #import pdb; pdb.set_trace()

            return str(answer["output"])
        except ValidationError as e:
            self.logger.exception(f"Failed to validate response from LLM: {e}")
            return "Failed to validate response from query engine"
        except json.JSONDecodeError as e:
            self.logger.exception(f"Failed to parse JSON response from query engine: {e.doc}")
            return "Failed to parse JSON response from query engine"
        except Exception as e:
            self.logger.exception(f"Failed to query engine: {e}")
            import traceback

            try:
                # Let's try to explain the exception
                # We need to take away the tools, so she doesn't try to answer
                # by reverse engineering the program...
                answer = self.llm.invoke(
                    f"You are ReVa, the reverse engineering assisstant. During your execution you threw an exception. Your logs are located in the file {self.log_path} Can you explain the error: {e}\n\n{traceback.format_exc()}"
                )
                if isinstance(answer, dict):
                    answer = answer["output"]
                analysis = f"""## **ReVa could not complete your request.**
Logs have been saved to `{self.log_path}`.
> She has examined the exception:
```
{e}
{traceback.format_exc()}
```
## ReVa's debugging notes:
{str(answer)}
                """
                date = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")
                crash_path = self.project.project_path / "crash"
                crash_path.mkdir(exist_ok=True)
                crash_dump_path = crash_path / f"reva-crash-{date}.log.md"
                crash_dump_path.write_text(analysis)
                return analysis
            except Exception as e:
                self.logger.exception(f"Failed to query engine: {e}")
                return f"Failed to query engine... Try again?\n```{traceback.format_exc()}```\nLogs have been saved to `{self.log_path}`"

def get_thinking_emoji() -> str:
    """
    Returns a random thinking emoji.
    """
    return random.choice([
        "🤔",
        "🧐",
        "🤨",
        "👩‍💻",
        "😖",
        "✨",
        "🔮",
        "🔍",
        "🧙‍♀️",
    ])


def main():
   import argparse
   parser = argparse.ArgumentParser()
   parser.error("Please run reva-server, not this script")

if __name__ == '__main__':
    main()
