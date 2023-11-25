#!/usr/bin/env python3

"""
This module defines the document types for both the tool integration
and the assistant. This module must have minimal third party dependencies
so we can easily load it into reverse engineering tools like Ghidra and
BinaryNinja that may have a limited set of third party libraries or
environments where it is hard to compile things like llama-cpp or
langchain.

This module acts as a bridge between the tool integration and the
assistant. We serialise these documents to disk, then load them
from the assistant side.

At the moment, the only communication between the tool integration
and the assitant is via the file system, though in the future an
interactive component may be added (potentially file system based,
like a push/pull model).
"""

from __future__ import annotations
import json
from typing import Dict, Optional, List, Type, LiteralString
import logging
from pathlib import Path

logger = logging.getLogger('reverse_engineering_assistant')


document_type_map: Dict[str, Type[AssistantDocument]] = {}

def document_type(cls: Type[AssistantDocument]):
    document_type_map[cls.document_type] = cls
    return cls

class AssistantDocument(object):
    name: str
    content: str
    metadata: Dict[str, str]
    document_type: LiteralString

    def __init__(self,
                 name: str,
                 content: str,
                 document_type: str,
                 metadata: Optional[Dict[str, str]] = None
                 ) -> None:
        self.name = name
        self.document_type = document_type
        self.content = content
        self.metadata = metadata or {}
        self.metadata["document_type"] = document_type

    def to_json(self) -> str:
        logger.debug(f"Serialising document {self.name}")
        return json.dumps({
            'name': self.name,
            'content': self.content,
            'metadata': self.metadata,
        })

    @property
    def type(self) -> Type[AssistantDocument]:
        return document_type_map[self.document_type]

    @classmethod
    def from_json(cls, json_str: str) -> AssistantDocument:
        data = json.loads(json_str)

        t = document_type_map[data['metadata']['document_type']]
        if t != AssistantDocument:
            return t.from_json(json_str)

        return AssistantDocument(
            name=data['name'],
            content=data['content'],
            document_type=data['metadata']['document_type'],
            metadata=data['metadata'],
        )

@document_type
class DecompiledFunctionDocument(AssistantDocument):
    document_type = 'decompiled_function'

    @property
    def function_start_address(self) -> str:
        return self.metadata['function_start_address']
    
    @property
    def function_end_address(self) -> str:
        return self.metadata['function_end_address']
    
    @property
    def function_signature(self) -> str:
        return self.metadata['function_signature']
    
    @property
    def inbound_calls(self) -> List[str]:
        return self.metadata['inbound_calls']
    
    @property
    def outbound_calls(self) -> List[str]:
        return self.metadata['outbound_calls']
    
    @property
    def is_external(self) -> bool:
        return self.metadata['is_external']
    
    @property
    def is_thunk(self) -> bool:
        return self.metadata['is_thunk']
    
    @classmethod
    def from_json(cls, json_str: str) -> DecompiledFunctionDocument:
        data = json.loads(json_str)

        return DecompiledFunctionDocument(
            function_name=data['metadata']['function_name'],
            decompilation=data['content'],
            function_start_address=data['metadata']['function_start_address'],
            function_end_address=data['metadata']['function_end_address'],
            function_signature=data['metadata']['function_signature'],
            inbound_calls=data['metadata']['inbound_calls'],
            outbound_calls=data['metadata']['outbound_calls'],
            is_external=data['metadata']['is_external'],
            is_generated_name=data['metadata']['is_generated_name'],
        )

    def __init__(self,
                 function_name: str,
                 decompilation: str,
                 function_start_address: int | str,
                 function_end_address: int | str,
                 function_signature: str,
                 namespace: Optional[str] = None,
                 is_external: Optional[bool] = None,
                 inbound_calls: Optional[List[str]] = None,
                 outbound_calls: Optional[List[str]] = None,
                 is_generated_name: Optional[bool] = None,
                 ) -> None:
        assert isinstance(function_name, str)
        assert isinstance(decompilation, str)
        assert isinstance(function_start_address, int) or isinstance(function_start_address, str)
        assert isinstance(function_end_address, int) or isinstance(function_end_address, str)
        assert isinstance(function_signature, str)
        assert isinstance(is_external, bool) or is_external is None
        assert isinstance(inbound_calls, list) or inbound_calls is None
        assert isinstance(outbound_calls, list) or outbound_calls is None

        if isinstance(function_start_address, int):
            function_start_address = hex(function_start_address)
        if isinstance(function_end_address, int):
            function_end_address = hex(function_end_address)

        content = json.dumps(decompilation, indent=2, sort_keys=True)
        metadata = {
            'function_name': function_name,
            'function_start_address': function_start_address,
            'function_end_address': function_end_address,
            'function_signature': function_signature,
            'inbound_calls': inbound_calls or [],
            'outbound_calls': outbound_calls or [],
            'is_external': is_external or False,
            'is_generated_name': is_generated_name,
        }
        super().__init__(name=function_name, content=content, document_type=self.document_type, metadata=metadata)

    def __repr__(self) -> str:
        return f"DecompiledFunctionDocument(name={self.name}, metadata={self.metadata}, content_length={len(self.content)})"

@document_type
class CrossReferenceDocument(AssistantDocument):
    document_type = 'cross_reference'

    @property
    def subject_address(self) -> str:
        return self.metadata['subject_address']
    
    @property
    def references_to(self) -> List[str]:
        return self.metadata['references_to']
    
    @property
    def references_from(self) -> List[str]:
        return self.metadata['references_from']
    
    @property
    def symbol(self) -> str:
        return self.metadata['symbol']
    
    @classmethod
    def from_json(cls, json_str: str) -> CrossReferenceDocument:
        data = json.loads(json_str)

        return CrossReferenceDocument(
            address=data['metadata']['address'],
            symbol=data['metadata']['symbol'],
            references_to=data['metadata']['references_to'],
            references_from=data['metadata']['references_from'],
        )

    def __init__(self,
                 address: int | str,
                 symbol: str,
                 references_to: List[int | str],
                 references_from: List[int | str],
                 ):
        if isinstance(address, int):
            address = hex(address)
        name = f"Cross references for {address}"

        # First normalise the lists
        references_to = [hex(x) if isinstance(x, int) else x for x in references_to]
        references_from = [hex(x) if isinstance(x, int) else x for x in references_from]
        
        # The content is a json document of references to and from the given address
        # TODO: This is presentation layer to the model, it belongs in
        # assistant, not in document
        content = f""

        metadata = {
            'address': address,
            'subject_address': address,
            'references_to': references_to,
            'references_from': references_from,
            'symbol': symbol,
        }

        super().__init__(name=name, content=content, document_type=self.document_type, metadata=metadata)

@document_type
class StringDocument(AssistantDocument):
    document_type = 'string'
    def __init__(self,
                 string: str,
                 address: int | str,
                 ) -> None:
        if isinstance(address, int):
            address = hex(address)

        name = string
        content = string
        metadata = {
            'address': address,
        }
        super().__init__(name=name, content=content, document_type=self.document_type, metadata=metadata)

    def __repr__(self) -> str:
        return f"StringDocument(name={self.name}, metadata={self.metadata}, content_length={len(self.content)})"
