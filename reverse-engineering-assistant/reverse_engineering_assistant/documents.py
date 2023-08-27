#!/usr/bin/env python3
from __future__ import annotations
import json
from typing import Dict, Optional
import logging
logger = logging.getLogger('reverse_engineering_assistant')

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

class DecompiledFunctionDocument(AssistantDocument):
    document_type = 'decompiled_function'
    def __init__(self,
                 function_name: str,
                 decompilation: str,
                 function_start_address: int | str,
                 function_signature = str,
                 namespace: Optional[str] = None,
                 is_external: Optional[bool] = None,
                 ) -> None:
        if isinstance(function_start_address, int):
            function_start_address = hex(function_start_address)

        name = function_name
        content = decompilation
        metadata = {
            'address': function_start_address,
            'function': function_signature,
        }
        super().__init__(name=name, content=content, document_type=self.document_type, metadata=metadata)

    def __repr__(self) -> str:
        return f"DecompiledFunctionDocument(name={self.name}, metadata={self.metadata}, content_length={len(self.content)})"
