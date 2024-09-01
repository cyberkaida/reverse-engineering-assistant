#!/usr/bin/env python3
from __future__ import annotations
import shutil
from typing import List

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
