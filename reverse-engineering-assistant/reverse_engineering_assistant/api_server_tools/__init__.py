

from typing import List


class RevaMessageHandler(object):
    handles_type = None


_global_message_handlers: List[RevaMessageHandler] = []

__all__ = ['register_message_handler']

def register_message_handler(cls: RevaMessageHandler):
    _global_message_handlers.append(cls)
    return cls