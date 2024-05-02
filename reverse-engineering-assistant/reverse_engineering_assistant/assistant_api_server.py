#!/usr/bin/env python3

"""
Here we start the gRPC server.
"""

from fileinput import filename
import grp
from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent.joinpath('protocol')))

import argparse
import threading
from concurrent import futures
from typing import Optional
import grpc
from grpc import Channel, ChannelConnectivity, Server

from .protocol import RevaHandshake_pb2_grpc, RevaHandshake_pb2
from .protocol import RevaHeartbeat_pb2_grpc, RevaHeartbeat_pb2

from functools import cache

import logging
logging.basicConfig(filename='/tmp/reva-server.log', level=logging.DEBUG)
logger = logging.getLogger("reva-server")

import socket
def get_unused_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 0))
    port = s.getsockname()[1]
    s.close()
    return port

_channel: Optional[Channel] = None
@cache
def get_channel() -> Channel:
    global _channel
    if not _channel:
        raise ValueError("Channel not set")
    return _channel

thread_pool = futures.ThreadPoolExecutor(max_workers=10)
server: Server = grpc.server(thread_pool)

@cache
def connect_to_extension(host: str, port: int) -> Channel:
    channel: Channel = grpc.insecure_channel(f"{host}:{port}")
    global _channel
    _channel = channel
    return get_channel()

def heartbeat():
    try:
        stub = RevaHeartbeat_pb2_grpc.RevaHeartbeatStub(get_channel())
        request = RevaHeartbeat_pb2.RevaHeartbeatRequest()
        response = stub.Heartbeat(request)
        if response is None:
            print("Heartbeat failed, shutting down")
            server.stop(0)
    except grpc.RpcError:
        print("Heartbeat failed, shutting down")
        server.stop(0)


def start_serving(
        connect_host: str, connect_port: int,
        host: str = 'localhost', port: Optional[int] = None):
    if not port:
        port = 0
    port = server.add_insecure_port(f"{host}:{port}")

    # Start the service threads
    logger.info(f"Starting server - {host}:{port}")
    server.start()
    # Call the handshake, we are multithreaded now so the other side
    # can immediately call us back.

    logger.info(f"Connecting to extension @ {connect_host}:{connect_port}")
    channel = connect_to_extension(connect_host, connect_port)

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
    logger.info(f"Server started - {host}:{port}")
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