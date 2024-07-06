#!/usr/bin/env python3
from concurrent.futures import thread
import queue
from re import M
from typing import Generator, List, Tuple
from uuid import uuid4
from prompt_toolkit import PromptSession
import prompt_toolkit
from prompt_toolkit.history import FileHistory
import rich
import argparse
from pathlib import Path
import random

import threading

# Necessary for gRPC and Protobuf
import sys
sys.path.append(str(Path(__file__).parent.joinpath('protocol')))

import grpc
from .protocol.RevaChat_pb2_grpc import RevaChatServiceStub
from .protocol.RevaChat_pb2 import RevaChatMessage, RevaChatMessageResponse, OllamaConfig, OpenAIConfig


from .protocol.RevaHeartbeat_pb2_grpc import RevaHeartbeatStub
from .protocol.RevaHeartbeat_pb2 import RevaHeartbeatRequest, RevaHeartbeatResponse

from rich.console import Console
from rich.markdown import Markdown
from rich.pretty import Pretty

import os
import logging
# Get the appropriate temp directory depending on the OS
temp_dir = os.getenv('TEMP') if os.name == 'nt' else '/tmp'
log_file = os.path.join(temp_dir, 'reva-chat.log')
logging.basicConfig(
    filename=log_file, level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("reva-chat")

def read_loop(project: str, prompt_session: PromptSession):
    while True:
        try:
            message: str = prompt_session.prompt("> ")
            chat_message = RevaChatMessage(project=project, message=message)
            logger.info(f"Sending message: {chat_message}")
            yield chat_message
        except KeyboardInterrupt:
            pass
        except EOFError:
            break

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

def find_connectable_extensions() -> Generator[Tuple[Path, str, str], None, None]:
    reva_temp_directory = os.path.join(Path.home(), '.reva')
    reva_temp = Path(reva_temp_directory)
    if reva_temp.exists():
        for file in reva_temp.glob("reva-connection-*.connection"):
            connection_string = file.read_text()
            content = connection_string.split(":")
            if len(content) == 2:
                yield file, content[0], content[1]
            else:
                # If the connection string is the wrong format, we will remove it
                # this is to clean anything that dropped bad content in the directory
                logger.warning(f"Invalid connection string: {connection_string}. Cleaning.")
                file.unlink()

def main():
    parser = argparse.ArgumentParser(description="Reva Chat Client")
    parser.add_argument("--host", default="localhost", help="The host to connect to")
    parser.add_argument("--port", required=False, type=int, help="The port to connect to")
    parser.add_argument("--project", required=False, help="The project to connect to")
    parser.add_argument("--program", required=False, help="The program to connect to")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    import os
    openai_key = os.environ.get("OPENAI_API_KEY")

    provider_settings = parser.add_argument_group("Provider Settings")
    provider_settings.add_argument("--provider", default="openai" if openai_key else "ollama", choices=["openai", "ollama"], help="The inference provider to use")
    provider_settings.add_argument("--openai-api-key", default=openai_key, type=str, required=False, help="The OpenAI API key to use")
    provider_settings.add_argument("--ollama-url", default="http://127.0.0.1:11434", type=str, required=False, help="The Ollama URL to use")
    provider_settings.add_argument("--model", type=str, required=False, help="The model name to use")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.addHandler(logging.StreamHandler(sys.stdout))

    if not args.model:
        match args.provider:
            case "openai":
                args.model = "gpt-4o"
            case "ollama":
                args.model = "llama3"
            case _:
                parser.error(f"Invalid provider: {args.provider}")
        logger.info(f"--model was not specified. Selecting default model for {args.provider}: {args.model}")

    console = Console(record=True)
    if not args.port:
        connectable_extensions: List[RevaHeartbeatResponse] = []
        for file, host, port in find_connectable_extensions():
            # First try a heartbeat to see if the connection is still alive
            retries = 10
            for _ in range(2):
                try:
                    channel = grpc.insecure_channel(f"{host}:{port}")
                    stub = RevaHeartbeatStub(channel)
                    response = stub.heartbeat(RevaHeartbeatRequest())
                    connectable_extensions.append(response)
                    logger.info(f"Found connectable extension: {response}")
                    break
                except grpc.RpcError as e:
                    if retries > 0:
                        import time
                        retries -= 1
                        logger.warning(f"Failed to connect to {host}:{port}. Retrying in 1 second.")
                        time.sleep(1)
                    else:
                        # If we can't connect, clean it up
                        logger.debug(f"Removing old connection file: {file}")
                        file.unlink()
        if len(connectable_extensions) == 0:
            logger.error("No connectable extensions found. Is Ghidra running? Is the extension enabled?")
            parser.error("No connectable extensions found. Is Ghidra running? Is the extension enabled?")
        elif len(connectable_extensions) == 1:
            # If there's only one thing running, we won't ask the user
            response = connectable_extensions[0]
            logger.info(f"Using only connectable extension: {response}")
            args.host = response.inference_hostname
            args.port = response.inference_port
            args.project = response.project_name
        elif args.program:
            logger.info(f"Looking for program: {args.program} in connectable extensions")
            # If there's a program specified, we'll try to find the right connection
            for response in connectable_extensions:
                if response.project_name == args.project:
                    logger.info(f"Found connectable extension for program {args.program}: {response}")
                    args.host = response.inference_hostname
                    args.port = response.inference_port
                    args.project = response.project_name
                    break
        else:
            # Use prompt-toolkit to ask the user
            logger.debug(f"Multiple connectable extensions found: {connectable_extensions}")
            console.print("Multiple connectable extensions found. Please select one:")
            result = prompt_toolkit.shortcuts.radiolist_dialog(
                title="Multiple connectable extensions found. Please select one:",
                values=[(response, response.project_name) for response in connectable_extensions],
            ).run()
            logger.info(f"User selected: {result}")
            args.host = result.inference_hostname
            args.port = result.inference_port
            args.project = result.project_name

    if not args.project:
        logger.error("A project must be specified")
        parser.error("A project must be specified. Is Ghidra running? Is the extension enabled?")
    history_file_path: Path = Path.home() / ".cache" / "reverse-engineering-assistant" / args.project / "chat-questions.txt"
    history_file_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.port or not args.host:
        logger.error("A host and port must be specified")
        parser.error("A host and port must be specified. Is Ghidra running? Is the extension enabled?")
    channel = grpc.insecure_channel(f"{args.host}:{args.port}")
    stub = RevaChatServiceStub(channel)


    console.print("[bold]Welcome to Reva Chat![/bold]")
    console.print(f"[gray]Using {args.provider} with model {args.model}[/gray]")
    history_file = FileHistory(str(history_file_path))
    prompt_session = PromptSession(history=history_file)

    chat_id: str = str(uuid4())

    send_queue = queue.Queue()
    receive_queue = queue.Queue()

    def get_message_from_queue():
        while True:
            yield send_queue.get()
    def chat_thread_func():
        for response in stub.chatStream(get_message_from_queue()):
            receive_queue.put(response)
    chat_thread = threading.Thread(target=chat_thread_func, daemon=True)
    chat_thread.start()

    try:
        while True:
            query: str = prompt_session.prompt("> ")
            try:
                console.print(f"[green]{query}[/green]")

                chat_message = RevaChatMessage(
                    chatId=chat_id,
                    project=args.project,
                    message=query,
                )
                match args.provider:
                    case "openai":
                        chat_message.openai.model = args.model
                        chat_message.openai.token = args.openai_api_key
                    case "ollama":
                        chat_message.ollama.model = args.model
                        chat_message.ollama.url = args.ollama_url
                    case _:
                        raise ValueError(f"Invalid provider: {args.provider}")
                logger.info(f"Sending message: {chat_message}")
                send_queue.put(chat_message)
                while True:
                    with console.status(f"{get_thinking_emoji()} Thinking..."):
                        response = receive_queue.get()
                        logger.info(f"Received response: {response}")
                        console.print(Markdown("---"))
                        if response.thought:
                            console.print(Markdown(f"### {get_thinking_emoji()} - ReVa Thinking..."))
                            thought = response.thought
                            console.print(Markdown(thought))
                        elif response.message:
                            console.print(Markdown(f"# 👩‍💻 - ReVa\n\n>{query}\n\n{response.message}"))
                            break
                        else:
                            # ReVa had no thoughts? We all feel this way some times...
                            raise ValueError("Head empty, no thoughts, no message")
            except KeyboardInterrupt:
                console.print("[bold][yellow]Cancelled. Press Ctrl-C again to exit.[/yellow][/bold]")
    except KeyboardInterrupt:
        console.print("Goodbye! :wave:")

    chat_thread.join(2)

if __name__ == "__main__":
    main()
