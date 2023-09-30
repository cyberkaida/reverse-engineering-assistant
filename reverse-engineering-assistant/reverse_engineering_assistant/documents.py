#!/usr/bin/env python3
from __future__ import annotations
import json
from typing import Dict, Optional, List, Type
import logging
logger = logging.getLogger('reverse_engineering_assistant')

document_type_map: Dict[str, Type[AssistantDocument]] = {}

def document_type(cls: Type[AssistantDocument]):
    document_type_map[cls.document_type] = cls
    return cls

class AssistantDocument(object):
    name: str
    content: str
    metadata: Dict[str, str]
    document_type: str

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
        logger.debug(f"Loading document from json: {json_str}")
        return AssistantDocument(
            name=data['name'],
            content=data['content'],
            document_type=data['metadata']['document_type'],
            metadata=data['metadata'],
        )

@document_type
class DecompiledFunctionDocument(AssistantDocument):
    document_type = 'decompiled_function'
    def __init__(self,
                 function_name: str,
                 decompilation: str,
                 function_start_address: int | str,
                 function_signature = str,
                 namespace: Optional[str] = None,
                 is_external: Optional[bool] = None,
                 inbound_calls: Optional[List[str]] = None,
                 outbound_calls: Optional[List[str]] = None,
                 ) -> None:
        if isinstance(function_start_address, int):
            function_start_address = hex(function_start_address)

        name = function_name
        references = json.dumps({
            'inbound_calls': inbound_calls or [],
            'outbound_calls': outbound_calls or [],
        })
        content = f"""{references}

        {decompilation}
        """
        metadata = {
            'address': function_start_address,
            'function': function_signature,
        }
        super().__init__(name=name, content=content, document_type=self.document_type, metadata=metadata)

    def __repr__(self) -> str:
        return f"DecompiledFunctionDocument(name={self.name}, metadata={self.metadata}, content_length={len(self.content)})"

@document_type
class CrossReferenceDocument(AssistantDocument):
    document_type = 'cross_reference'
    def __init__(self,
                 address: int | str,
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
        json_doc = json.dumps({
            'address': address,
            'to_this_address': references_to,
            'from_this_address': references_from,
        })
        content = f"""
        Cross references for {address} in json format:
        {json_doc}
        """

        metadata = {
            'address': address,
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
