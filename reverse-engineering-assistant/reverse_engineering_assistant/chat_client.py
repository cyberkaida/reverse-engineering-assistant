#!/usr/bin/env python3
from typing import Generator
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
import rich
import argparse
import grpc
from protocol.RevaChat_pb2_grpc import RevaChatServiceStub
from protocol.RevaChat_pb2 import RevaChatMessage, RevaChatMessageResponse

from rich.console import Console
from rich.markdown import Markdown

from pathlib import Path


def read_loop(project: str, prompt_session: PromptSession) -> Generator[RevaChatMessage]:
    while True:
        try:
            message: str = prompt_session.prompt("> ")
            yield RevaChatMessage(programName=project, message=message)
        except KeyboardInterrupt:
            pass
        except EOFError:
            break


def main():
    parser = argparse.ArgumentParser(description="Reva Chat Client")
    parser.add_argument("--host", default="localhost", help="The host to connect to")
    parser.add_argument("--port", required=True, type=int, help="The port to connect to")
    parser.add_argument("--program", default="default", help="The program to connect to")
    args = parser.parse_args()

    history_file_path: Path = Path.home() / ".cache" / "reverse-engineering-assistant" / args.project / "chat-questions.txt"
    history_file_path.parent.mkdir(parents=True, exist_ok=True)

    channel = grpc.insecure_channel(f"{args.host}:{args.port}")
    stub = RevaChatServiceStub(channel)

    with Console() as console:
        console.print("[bold]Welcome to Reva Chat![/bold]")
        history_file = FileHistory(str(history_file_path))
        prompt_session = PromptSession(history=history_file)
        read_generator = read_loop(args.program, prompt_session)

        for response in stub.sendMessageStream(read_generator):
            console.print(Markdown("---"))
            console.print(Markdown(response.message))

if __name__ == "__main__":
    main()