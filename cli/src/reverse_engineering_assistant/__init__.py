"""Reverse Engineering Assistant CLI package."""

__version__ = "0.1.0"

# Import main API classes for programmatic use
from .cli import ReVaSession, find_free_port

__all__ = ["ReVaSession", "find_free_port", "__version__"]