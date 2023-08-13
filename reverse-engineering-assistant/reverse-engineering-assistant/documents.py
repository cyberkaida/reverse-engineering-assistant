#!/usr/bin/env python3
from __future__ import annotations
import json
from typing import Dict, Optional

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
        return json.dumps({
            'name': self.name,
            'content': self.content,
            'metadata': self.metadata,
        })

    @classmethod
    def from_json(cls, json_str: str) -> AssistantDocument:
        data = json.loads(json_str)
        return AssistantDocument(
            data['name'],
            data['content'],
            data['metadata']['document_type'],
            data['metadata'],
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
            'function_name': function_name,
            'function_signature': function_signature,
        }
        if namespace:
            metadata['namespace'] = namespace
        if is_external:
            metadata['is_external'] = is_external
        super().__init__(name, self.document_type, content, metadata)

