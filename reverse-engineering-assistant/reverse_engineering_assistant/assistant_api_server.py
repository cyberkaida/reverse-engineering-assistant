#!/usr/bin/env python3

"""
Here we start the gRPC server.
"""

from ast import parse
import threading
from pathlib import Path
import sys

import openai

sys.path.append(str(Path(__file__).parent.joinpath('protocol')))

import argparse
from concurrent import futures
from typing import Optional
import grpc
from grpc import Server

from .protocol import RevaHandshake_pb2_grpc, RevaHandshake_pb2
from .protocol import RevaChat_pb2_grpc
from .protocol import RevaHeartbeat_pb2_grpc, RevaHeartbeat_pb2

from .api_server_tools.llm_tools import RevaChat
from .api_server_tools.connection import get_channel, connect_to_extension

# Trigger the tools to load! If you don't do this
# poor ReVa won't know about her tools and she can't help you.
from .api_server_tools.re_tools import *

from .model import get_llm_ollama, get_llm_openai

import os
import logging
# Get the appropriate temp directory depending on the OS
temp_dir = os.getenv('TEMP') if os.name == 'nt' else '/tmp'
log_file = os.path.join(temp_dir, 'reva-chat.log')
logging.basicConfig(
    filename=log_file, level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("reva-server")



import socket
def get_unused_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 0))
    port = s.getsockname()[1]
    s.close()
    return port

thread_pool = futures.ThreadPoolExecutor(max_workers=10)
server: Server = grpc.server(thread_pool)
heartbeat_thread: threading.Thread

def heartbeat():
    try:
        stub = RevaHeartbeat_pb2_grpc.RevaHeartbeatStub(get_channel())
        request = RevaHeartbeat_pb2.RevaHeartbeatRequest()
        result = stub.heartbeat(request)
    except grpc.RpcError as e:
        logger.warning(f"Heartbeat failed: {e}")
        server.stop(5)

def start_serving(
        connect_host: str, connect_port: int,
        model: BaseChatModel | BaseLanguageModel = None,
        serve_host: str = 'localhost', serve_port: Optional[int] = None
        ):
    if not serve_port:
        serve_port = 0
    serve_port = server.add_insecure_port(f"{serve_host}:{serve_port}")

    # Register handlers
    RevaChat_pb2_grpc.add_RevaChatServiceServicer_to_server(RevaChat(model), server)

    # Start the service threads
    logger.info(f"Starting server - {serve_host}:{serve_port}")
    server.start()
    # Call the handshake, we are multithreaded now so the other side
    # can immediately call us back.

    logger.info(f"Connecting to extension @ {connect_host}:{connect_port}")
    _ = connect_to_extension(connect_host, connect_port)

    logger.info(f"Handshaking with extension @ {serve_host}:{serve_port}")
    stub = RevaHandshake_pb2_grpc.RevaHandshakeStub(get_channel())

    request = RevaHandshake_pb2.RevaHandshakeRequest()
    request.inferenceHostname = serve_host
    request.inferencePort = serve_port

    logger.info(f"Request: {request}")
    result = stub.Handshake(request)
    logger.info(f"Result: {result} - {type(result)}")

    # Start heartbeating on a timer. We end when the heartbeat fails.
    heartbeat_thread = threading.Timer(interval=30, function=heartbeat)
    heartbeat_thread.start()
    # Now that we have told the other side to connect to us, we can
    # perform requests
    logger.info(f"Server running")

    server.wait_for_termination()
    logger.warning("Server stopped")

def main():
    parser = argparse.ArgumentParser(description="Reva Chat Server")
    parser.add_argument('--connect-host', type=str, required=True, help="The callback host to connect to")
    parser.add_argument('--connect-port', type=int, required=True, help="The callback port to connect to")
    parser.add_argument('--listen-host', type=str, default='127.0.0.1', help='The host to listen on')
    parser.add_argument('--listen-port', type=int, help='The port to listen on')

    parser.add_argument('--provider', choices=[
        "ollama",
        "openai"
    ])

    openai_group = parser.add_argument_group("OpenAI")
    openai_group.add_argument('--openai-model', type=str, help="The OpenAI model to use, see https://platform.openai.com/docs/models for options")
    openai_group.add_argument('--openai-api-key', type=str, help="The OpenAI API key")

    ollama_group = parser.add_argument_group("Ollama")
    ollama_group.add_argument('--ollama-model', type=str, help="The Ollama model to use. Must be pulled into ollama.")
    ollama_group.add_argument('--ollama-server-url', type=str, help="The Ollama server URL")

    args = parser.parse_args()

    if args.openai_api_key == "OPENAI_API_KEY":
        args.openai_api_key = None

    # First get the right model
    if args.provider == "openai":
        model = get_llm_openai(
            model=args.openai_model,
            api_key=args.openai_api_key
        )
    elif args.provider == "ollama":
        model = get_llm_ollama(
            model=args.ollama_model,
            base_url=args.ollama_server_url
        )
    else:
        raise ValueError(f"Incorrect provider specified {args.provider}")

    start_serving(
        connect_host=args.connect_host,
        connect_port=args.connect_port,
        model=model,
        serve_host=args.listen_host,
        serve_port=args.listen_port
    )

if __name__ == "__main__":
    main()
