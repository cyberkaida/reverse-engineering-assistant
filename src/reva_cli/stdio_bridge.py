"""
Stdio to HTTP MCP bridge.

Bridges stdio MCP transport (used by Claude CLI) to ReVa's StreamableHTTP server.
Reads MCP messages from stdin, forwards to HTTP server, writes responses to stdout.
"""

import sys
import json
import asyncio
from typing import Optional


class StdioBridge:
    """Bridges stdio MCP transport to StreamableHTTP."""

    def __init__(self, port: int):
        """
        Initialize stdio bridge.

        Args:
            port: ReVa server port to connect to
        """
        self.port = port
        self.url = f"http://localhost:{port}/mcp/message"
        self.running = False
        self.session = None

    async def run(self):
        """
        Run the stdio<->HTTP bridge loop.

        Reads JSON-RPC messages from stdin, forwards to HTTP, writes responses to stdout.
        """
        from mcp.client.streamable_http import streamablehttp_client
        from mcp import ClientSession

        self.running = True
        print(f"Starting stdio<->HTTP bridge to {self.url}", file=sys.stderr)

        try:
            # Connect to ReVa server using MCP StreamableHTTP client
            async with streamablehttp_client(self.url, timeout=300.0) as (read_stream, write_stream, get_session_id):
                async with ClientSession(read_stream, write_stream) as session:
                    self.session = session

                    # Initialize session
                    print("Initializing MCP session...", file=sys.stderr)
                    init_result = await session.initialize()
                    print(f"MCP session initialized: {init_result.server_info.name} v{init_result.server_info.version}", file=sys.stderr)

                    # List available tools for debugging
                    tools_result = await session.list_tools()
                    print(f"Available tools: {len(tools_result.tools)}", file=sys.stderr)

                    # Main loop: read from stdin, process, write to stdout
                    print("Bridge ready - forwarding stdio<->HTTP", file=sys.stderr)

                    loop = asyncio.get_event_loop()

                    while self.running:
                        # Read line from stdin (non-blocking)
                        try:
                            line = await loop.run_in_executor(None, sys.stdin.readline)

                            if not line:
                                # EOF reached
                                print("EOF on stdin, shutting down", file=sys.stderr)
                                break

                            line = line.strip()
                            if not line:
                                continue

                            # Parse JSON-RPC message
                            try:
                                message = json.loads(line)
                            except json.JSONDecodeError as e:
                                print(f"Invalid JSON from stdin: {e}", file=sys.stderr)
                                continue

                            # Handle JSON-RPC message
                            response = await self.handle_message(message)

                            # Write response to stdout
                            if response:
                                json_response = json.dumps(response)
                                sys.stdout.write(json_response + "\n")
                                sys.stdout.flush()

                        except Exception as e:
                            print(f"Error processing message: {e}", file=sys.stderr)
                            import traceback
                            traceback.print_exc(file=sys.stderr)

        except Exception as e:
            print(f"Bridge error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
        finally:
            self.running = False
            self.session = None
            print("Bridge stopped", file=sys.stderr)

    async def handle_message(self, message: dict) -> Optional[dict]:
        """
        Handle a JSON-RPC message from stdin.

        Args:
            message: JSON-RPC message dictionary

        Returns:
            JSON-RPC response dictionary, or None
        """
        if not self.session:
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {
                    "code": -32603,
                    "message": "Session not initialized"
                }
            }

        method = message.get("method")
        params = message.get("params", {})
        msg_id = message.get("id")

        try:
            # Route to appropriate MCP method
            if method == "initialize":
                result = await self.session.initialize()
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": result.protocol_version,
                        "capabilities": result.capabilities.__dict__,
                        "serverInfo": {
                            "name": result.server_info.name,
                            "version": result.server_info.version
                        }
                    }
                }

            elif method == "tools/list":
                result = await self.session.list_tools()
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "tools": [
                            {
                                "name": tool.name,
                                "description": tool.description,
                                "inputSchema": tool.input_schema
                            }
                            for tool in result.tools
                        ]
                    }
                }

            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})

                result = await self.session.call_tool(tool_name, arguments)

                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": item.type,
                                "text": item.text if hasattr(item, 'text') else str(item)
                            }
                            for item in result.content
                        ],
                        "isError": result.isError if hasattr(result, 'isError') else False
                    }
                }

            elif method == "resources/list":
                result = await self.session.list_resources()
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "resources": [
                            {
                                "uri": resource.uri,
                                "name": resource.name,
                                "description": resource.description,
                                "mimeType": resource.mime_type if hasattr(resource, 'mime_type') else None
                            }
                            for resource in result.resources
                        ]
                    }
                }

            elif method == "resources/read":
                uri = params.get("uri")
                result = await self.session.read_resource(uri)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "contents": [
                            {
                                "uri": content.uri,
                                "mimeType": content.mime_type if hasattr(content, 'mime_type') else None,
                                "text": content.text if hasattr(content, 'text') else None
                            }
                            for content in result.contents
                        ]
                    }
                }

            elif method == "prompts/list":
                result = await self.session.list_prompts()
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "prompts": [
                            {
                                "name": prompt.name,
                                "description": prompt.description,
                                "arguments": prompt.arguments if hasattr(prompt, 'arguments') else []
                            }
                            for prompt in result.prompts
                        ]
                    }
                }

            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }

        except Exception as e:
            print(f"Error handling method {method}: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32603,
                    "message": str(e)
                }
            }

    def stop(self):
        """Stop the bridge."""
        self.running = False
