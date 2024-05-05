#!/usr/bin/env python3
from typing import Generator
from prompt_toolkit import PromptSession
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
from .protocol.RevaChat_pb2 import RevaChatMessage, RevaChatMessageResponse

from rich.console import Console
from rich.markdown import Markdown
from rich.pretty import Pretty

import logging
logging.basicConfig(
    filename='/tmp/reva-server.log', level=logging.DEBUG,
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

def main():
    parser = argparse.ArgumentParser(description="Reva Chat Client")
    parser.add_argument("--host", default="localhost", help="The host to connect to")
    parser.add_argument("--port", required=True, type=int, help="The port to connect to")

    parser.add_argument("--project", help="The project to connect to")
    parser.add_argument("--program", required=False, help="The program to connect to")
    args = parser.parse_args()

    history_file_path: Path = Path.home() / ".cache" / "reverse-engineering-assistant" / args.project / "chat-questions.txt"
    history_file_path.parent.mkdir(parents=True, exist_ok=True)

    channel = grpc.insecure_channel(f"{args.host}:{args.port}")
    stub = RevaChatServiceStub(channel)
    console = Console(record=True)
    console.print("[bold]Welcome to Reva Chat![/bold]")
    history_file = FileHistory(str(history_file_path))
    prompt_session = PromptSession(history=history_file)

    try:
        while True:
            query: str = prompt_session.prompt("> ")
            try:
                console.print(f"[green]{query}[/green]")
                chat_message = RevaChatMessage(project=args.project, message=query)

                logger.info(f"Sending message: {chat_message}")
                for response in stub.chatResponseStream(chat_message):
                    logger.info(f"Received response: {response}")

                    console.print(Markdown("---"))
                    if response.thought:
                        console.print(Markdown(f"### {get_thinking_emoji()} - ReVa Thinking..."))
                        thought = response.thought
                        console.print(Markdown(thought))
                    elif response.message:
                        console.print(Markdown(response.message))
                    else:
                        # ReVa had no thoughts? We all feel this way some times...
                        raise ValueError("Head empty, no thoughts, no message")
            except KeyboardInterrupt:
                console.print("[bold][yellow]Cancelled. Press Ctrl-C again to exit.[/yellow][/bold]")
    except KeyboardInterrupt:
        console.print("Goodbye! :wave:")

if __name__ == "__main__":
    main()