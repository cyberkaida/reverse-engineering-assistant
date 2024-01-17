#!/usr/bin/env python3
from __future__ import annotations
import shutil
from typing import List

from .documents import AssistantDocument

from pathlib import Path

base_path = Path.home() / ".cache" / "reverse-engineering-assistant"
base_path.mkdir(parents=True, exist_ok=True)

projects_path = base_path / "projects"
projects_path.mkdir(parents=True, exist_ok=True)

class AssistantProject(object):
    """
    A class representing a project in the reverse engineering assistant tool.
    """

    project: str
    project_path: Path
    documents_path: Path

    def __repr__(self) -> str:
        return f"<AssistantProject: {self.project}>"

    @classmethod
    def get_projects(cls) -> List[str]:
        """
        Gets the names of the projects.

        Returns:
        - A list of project names.
        """
        return [project.name for project in projects_path.iterdir() if project.is_dir()]

    def __init__(self, project: str) -> None:
        """
        Initializes a new AssistantProject object.

        Args:
        - project (str): The name of the project.
        """
        self.project = project
        self.project_path = projects_path / project
        self.project_path.mkdir(parents=True, exist_ok=True)
        self.documents_path = self.project_path / "documents"
        self.documents_path.mkdir(parents=True, exist_ok=True)

    def reset_documents(self):
        """
        Resets the documents in the project.
        """
        if self.documents_path.exists():
            shutil.rmtree(self.documents_path)
        self.documents_path.mkdir(parents=True, exist_ok=False)

    def add_document(self, name: str, document: AssistantDocument) -> Path:
        """
        Adds a document to the project.

        Args:
        - name (str): The name of the document.
        - document (AssistantDocument): The document to add.

        Returns:
        - The path to the added document.
        """
        document_path = self.documents_path / f"{name}.json"
        document_path.write_text(document.to_json())
        return document_path

    def get_documents(self) -> List[AssistantDocument]:
        """
        Gets the documents in the project.

        Returns:
        - A list of AssistantDocument objects.
        """
        document_list: List[AssistantDocument] = []
        for json_file in self.documents_path.glob("*.json"):
            document_list.append(AssistantDocument.from_json(json_file.read_text()))
        return document_list

    def get_index_directory(self):
        """
        Gets the index directory for the project.

        Returns:
        - The path to the index directory.
        """
        return self.project_path / "index"



class ToolIntegration(object):
    project: AssistantProject
    def __init__(self, project: str | AssistantProject) -> None:
        """
        Initialises a new ToolIntegration object.

        Args:
        - project (str | AssistantProject): The name of the project or an existing AssistantProject object.
        """
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
        """
        Saves the documents returned by get_documents() to the project.
        """
        self.project.reset_documents()
        for index, document in enumerate(self.get_documents()):
            # Each document is named by its index as the "name" field
            # is not guaranteed to be path safe
            # TODO: Make the name field path safe
            self.project.add_document(f"{index}", document)
