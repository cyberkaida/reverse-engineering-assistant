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
from typing import Any, Callable, Dict, List, Optional, Sequence, Type
from uuid import UUID

from langchain.chains.base import Chain
from langchain.agents.agent import Agent, AgentExecutor
from langchain.agents.conversational_chat.base import ConversationalChatAgent
from langchain.agents.structured_chat.base import StructuredChatAgent
from langchain_core.agents import AgentAction, AgentFinish
from langchain_core.callbacks.base import BaseCallbackHandler, BaseCallbackManager
from langchain.llms.base import BaseLLM
from langchain.chat_models.base import BaseChatModel
from langchain.memory import ConversationTokenBufferMemory, ChatMessageHistory, ConversationBufferMemory
from langchain.memory.chat_memory import BaseMemory
from langchain.tools.base import BaseTool, StructuredTool, Tool
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from rich.console import Console
from rich.logging import RichHandler
from rich.prompt import Prompt
from rich.markdown import Markdown

from .configuration import AssistantConfiguration, load_configuration
from .documents import AssistantDocument, CrossReferenceDocument, DecompiledFunctionDocument
from .model import ModelType, get_model
from .tool import AssistantProject
from .reva_exceptions import RevaToolException
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

    llm: BaseLLM | BaseChatModel

    tool_name: str
    description: str

    tool_functions: List[Callable]

    def __str__(self) -> str:
        return f"{self.tool_name}"

    def __init__(self, project: AssistantProject, llm: BaseLLM | BaseChatModel) -> None:
        self.project = project
        self.llm = llm

    @cache
    def as_tools(self) -> List[BaseTool]:
        """
        Returns a list of tools usable by the assistant
        based on the value of self.tool_functions.
        """
        tools: List[BaseTool] = []
        for tool_function in self.tool_functions:
            wrapper = RevaToolFunctionWrapper(tool_function)
            from langchain.tools.base import create_schema_from_function
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

    def __init__(self, project: AssistantProject, llm: BaseLLM | BaseChatModel) -> None:
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

    #project: AssistantProject

    query_engine: Optional[Chain] = None

    tools: List[RevaTool]

    llm: BaseLLM | BaseChatModel

    model_memory: BaseMemory

    chat_history: List[str]

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

    def __init__(self, project: str | AssistantProject, model_type: Optional[ModelType] = None) -> None:
        """
        Initializes a new instance of the ReverseEngineeringAssistant class.

        Args:
            project (str | AssistantProject): The reverse engineering project to query.
            model_type (Optional[ModelType], optional): The model type for the reverse engineering assistant. Defaults to None.
        """
        self.chat_history = []
        if isinstance(project, str):
            self.project = AssistantProject(project)
        else:
            self.project = project

        self.llm = get_model(model_type)

        # Let's take the tools that have been decorated with @register_tool and turn them into
        # tools the LLM can use.
        self.tools = [ tool_type(self.project, self.llm) for tool_type in _reva_tool_list]
        logger.debug(f"Loaded tools: {[ x for x in self.tools]}")

    def create_query_engine(self) -> Chain:
        """
        Updates the embeddings for the reverse engineering assistant.
        """

        # Here I pull our own prompt

        configuration: AssistantConfiguration = load_configuration()

        base_tools: List[BaseTool] = []
        for tool in self.tools:
            for function in tool.as_tools():
                base_tools.append(function)

        #self.model_memory = ConversationTokenBufferMemory(
        #    llm=self.llm
        #)
        self.model_memory = ConversationBufferMemory()
        callbacks: List[BaseCallbackHandler] = [RevaActionLogger()]
        callback_manager = RevaActionLoggerManager(handlers=callbacks, inheritable_handlers=callbacks)

        agent =  StructuredChatAgent.from_llm_and_tools(
            llm=self.llm,
            tools=base_tools,
            system_message=configuration.prompt_template.system_prompt,
            verbose=False,
            handle_parsing_errors=self.handle_reva_tool_error,
            stop_words=["\nObservation", "\nThought"],
            callback_manager=callback_manager,
        )
        # TODO: Switch to this thing https://python.langchain.com/docs/expression_language/get_started
        executor = AgentExecutor.from_agent_and_tools(
            agent=agent,
            tools=base_tools,
            verbose=False,
            handle_parsing_errors=self.handle_reva_tool_error,
            memory=self.model_memory,
            callbacks=callbacks,
        )

        self.query_engine = executor
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

            query_engine_input =  {
                    "input": query,
                }

            answer = self.query_engine.invoke(
               input=query_engine_input,
            )

            #import pdb; pdb.set_trace()

            return str(answer["output"])
        except json.JSONDecodeError as e:
            logger.exception(f"Failed to parse JSON response from query engine: {e.doc}")
            return "Failed to parse JSON response from query engine"
        except ValueError as e:
            logger.exception(f"Failed to query engine: {e}")
            return "Failed to query engine... Try again?"
        except Exception as e:
            logger.exception(f"Failed to query engine: {e}")
            return "Failed to query engine... Try again?"

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

    default_log_filename = f"ReVa-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.reva"
    default_log_path = Path(tempfile.gettempdir()) / Path(default_log_filename+".log")
    default_chat_path = Path(tempfile.gettempdir()) / Path(default_log_filename+".chat.txt")
    default_html_path = Path(tempfile.gettempdir()) / Path(default_log_filename+".html")

    parser = argparse.ArgumentParser(description="Reverse Engineering Assistant")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
    parser.add_argument('--debug', action='store_true', help="Debug output, useful during development")
    parser.add_argument("--project", required=False, type=str, help="Project name")
    parser.add_argument("-i", "--interactive", action="store_true", help="Enter interactive mode after processing queries")

    parser.add_argument('-f', '--file', default=default_log_path, type=Path, help=f"Save output to file. Defaults to {default_log_path}")

    parser.add_argument("-p", "--provider", required=False, choices=ModelType._member_names_, help="The model provider to use, defaults to the value of `model_type` in the config file.")

    parser.add_argument("QUERY", nargs="*", help="Queries to run, if not specified, enter interactive mode")

    args = parser.parse_args()

    model_type = ModelType._member_map_[args.provider] if args.provider else None

    console.print(f"Welcome to ReVa! The Reverse Engineering Assistant", style="bold green")
    console.print(f"Logging to {args.file}")

    logging_level = logging.DEBUG if args.debug else logging.INFO
    logger.level = logging.DEBUG

    rich_handler = RichHandler(
        console=console,
        level=logging_level,
    )
    logger.addHandler(rich_handler)

    # Create a logger for logging to a file. We'll log everything to the file.
    file_handler = logging.FileHandler(args.file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logging.root.setLevel(logging.DEBUG)
    logging.root.addHandler(file_handler)

    # If the debug flag is enabled we turn these on.
    if args.debug:
        logging.getLogger('httpx').addHandler(rich_handler)
        logging.getLogger('openai._base_client').addHandler(rich_handler)
        logging.getLogger('httpcore').addHandler(rich_handler)

    if not args.project:
        args.project = Prompt.ask("No project specified, please select from the following:", choices=ReverseEngineeringAssistant.get_projects())

    # Start up the API server
    from .assistant_api_server import run_server
    from threading import Thread
    server_thread = Thread(target=run_server, args=())
    server_thread.start()
    console.print("API server started", style="bold green")


    logger.info(f"Loading project {args.project}")
    assistant = ReverseEngineeringAssistant(args.project, model_type)
    assistant.create_query_engine()
    logger.info(f"Project loaded!")



    # Enter into a loop answering questions

    history_file = FileHistory(assistant.project.project_path / "chat-questions.txt")
    prompt_session = PromptSession(history=history_file)

    for query in args.QUERY:
        logger.debug(query)
        console.print(f"> {query}")
        # Add the query to the history file
        # so the user can autocomplete this later
        history_file.append_string(query)

        with console.status(f"Thinking..."):
            result = assistant.query(query)
            console.print(Markdown(result))
            console.print(Markdown('---'))


    if args.interactive or not args.QUERY:
        try:
            while True:
                query = prompt_session.prompt("> ", auto_suggest=AutoSuggestFromHistory())
                try:
                    logger.debug(query)
                    console.print(f"[green]{query}[/green]")
                    with console.status(f"{get_thinking_emoji()} Thinking..."):
                        result = assistant.query(query)
                        console.print(Markdown(result))
                        console.print(Markdown('---'))
                except KeyboardInterrupt:
                    console.print("[bold][yellow]Cancelled. Press Ctrl-C again to exit.[/yellow][/bold]")

        except KeyboardInterrupt:
            console.print("Finished!")
        except EOFError:
            console.print("Finished")

    if args.file:
        logger.info(f"Output saved to {args.file}")
        logger.info(f"Chat saved to {default_chat_path}")
        console.save_text(default_chat_path, clear=False)
        logger.info(f"HTML saved to {default_html_path}")
        console.save_html(default_html_path, clear=False)

if __name__ == '__main__':
    main()
