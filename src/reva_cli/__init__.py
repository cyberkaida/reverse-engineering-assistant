"""
ReVa CLI - stdio MCP bridge for ReVa Ghidra extension.

This package provides a command-line interface that bridges stdio MCP transport
to ReVa's StreamableHTTP server, enabling seamless integration with Claude CLI.
"""

try:
    from ._version import version as __version__
except ImportError:
    # Fallback version if not installed or in development without git tags
    __version__ = "0.0.0.dev0"
