#!/usr/bin/env python3

"""
Here we start the gRPC server.
"""

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent.joinpath('protocol')))

import argparse
from concurrent import futures
from typing import Optional
import grpc
from grpc import Server

from .protocol import RevaHandshake_pb2_grpc, RevaHandshake_pb2
from .protocol import RevaChat_pb2_grpc

from .api_server_tools.llm_tools import RevaChat
from .api_server_tools.connection import get_channel, connect_to_extension

# Trigger the tools to load! If you don't do this
# poor ReVa won't know about her tools and she can't help you.
from .api_server_tools.re_tools import *

import logging
logging.basicConfig(
    filename='/tmp/reva-server.log', level=logging.DEBUG,
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

def start_serving(
        connect_host: str, connect_port: int,
        host: str = 'localhost', port: Optional[int] = None):
    if not port:
        port = 0
    port = server.add_insecure_port(f"{host}:{port}")

    # Register handlers
    RevaChat_pb2_grpc.add_RevaChatServiceServicer_to_server(RevaChat(), server)

    # Start the service threads
    logger.info(f"Starting server - {host}:{port}")
    server.start()
    # Call the handshake, we are multithreaded now so the other side
    # can immediately call us back.

    logger.info(f"Connecting to extension @ {connect_host}:{connect_port}")
    _ = connect_to_extension(connect_host, connect_port)

    logger.info(f"Handshaking with extension @ {host}:{port}")
    stub = RevaHandshake_pb2_grpc.RevaHandshakeStub(get_channel())

    request = RevaHandshake_pb2.RevaHandshakeRequest()
    request.inferenceHostname = host
    request.inferencePort = port

    logger.info(f"Request: {request}")
    result = stub.Handshake(request)
    logger.info(f"Result: {result} - {type(result)}")

    # Start heartbeating on a timer
    #heartbeat_thread = threading.Timer(interval=30, function=heartbeat)
    #heartbeat_thread.start()
    # Now that we have told the other side to connect to us, we can
    # perform requests
    logger.info(f"Server running")
    server.wait_for_termination()
    logger.warning("Server stopped")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--connect-host', type=str, required=True, help="The callback host to connect to")
    parser.add_argument('--connect-port', type=int, required=True, help="The callback port to connect to")
    parser.add_argument('--listen-host', type=str, default='127.0.0.1', help='The host to listen on')
    parser.add_argument('--listen-port', type=int, help='The port to listen on')

    args = parser.parse_args()

    start_serving(args.connect_host, args.connect_port, args.listen_host, args.listen_port)

if __name__ == "__main__":
    main()