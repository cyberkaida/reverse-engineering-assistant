#!/usr/bin/env python3
from __future__ import annotations
import shutil
from typing import List

from documents import AssistantDocument

from pathlib import Path

base_path = Path.home() / ".config" / "reverse-engineering-assistant"
base_path.mkdir(parents=True, exist_ok=True)

projects_path = base_path / "projects"
projects_path.mkdir(parents=True, exist_ok=True)

class AssistantProject(object):
    project: str
    project_path: Path
    documents_path: Path

    def __init__(self, project: str) -> None:
        self.project = project
        self.project_path = projects_path / project
        self.project_path.mkdir(parents=True, exist_ok=True)
        self.documents_path = self.project_path / "documents"

    def reset_documents(self):
        shutil.rmtree(self.documents_path)
        self.documents_path.mkdir(parents=True, exist_ok=False)

    def add_document(self, name: str, document: AssistantDocument) -> Path:
        document_path = self.documents_path / f"{name}.json"
        document_path.write_text(document.to_json())
        return document_path

    def get_documents(self) -> List[AssistantDocument]:
        document_list: List[AssistantDocument] = []
        for json_file in self.documents_path.glob("*.json"):
            document_list.append(AssistantDocument.from_json(json_file.read_text()))
        return document_list



class ToolIntegration(object):
    project: AssistantProject
    def __init__(self, project: str | AssistantProject) -> None:
        if isinstance(project, str):
            self.project = AssistantProject(project)
        else:
            self.project = project

    def get_documents(self) -> List[AssistantDocument]:
        """
        This method is implemented by the tool, and returns a list
        of AssistantDocument objects to be indexed.
        """
        raise NotImplementedError()

    def save_documents(self):
        self.project.reset_documents()
        for index, document in enumerate(self.get_documents()):
            # Each document is named by its index as the "name" field
            # is not guaranteed to be path safe
            # TODO: Make the name field path safe
            self.project.add_document(f"{index}.json", document)
