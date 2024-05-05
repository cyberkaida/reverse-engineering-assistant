from pathlib import Path
import sys
sys.path.append(str(Path(__file__).parent.joinpath('protocol')))
import grpc
from grpc import Channel, Server

from typing import Optional

from functools import cache

_channel: Optional[Channel] = None
@cache
def get_channel() -> Channel:
    global _channel
    if not _channel:
        raise ValueError("Channel not set")
    return _channel

@cache
def connect_to_extension(host: str, port: int) -> Channel:
    channel: Channel = grpc.insecure_channel(f"{host}:{port}")
    global _channel
    _channel = channel
    return get_channel()