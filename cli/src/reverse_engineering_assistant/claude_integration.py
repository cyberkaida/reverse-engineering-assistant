#!/usr/bin/env python3
"""
Claude Code integration for ReVa - provides reva-claude command for AI-assisted analysis.
"""

import os
import sys
import socket
import subprocess
import tempfile
import json
import signal
import argparse
import datetime
from pathlib import Path
from typing import Optional, List
import anyio
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .cli import ReVaSession, find_free_port
from .ui_manager import ui, format_assistant_message, format_tool_use, format_final_answer

console = Console()


def parse_args() -> tuple[list[str], str | None, str | None, bool]:
    """Parse command line arguments for reva-claude."""
    parser = argparse.ArgumentParser(
        description="ReVa Claude Analysis - AI-powered binary analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reva-claude binary.exe -- "What does this program do?"
  reva-claude --json-output analysis.json malware.dll -- "Find suspicious functions"
  reva-claude --auto-analyze complex.exe -- "Comprehensive analysis"
  reva-claude lib1.so lib2.so -- "Compare these libraries"
  reva-claude -- "Analyze all EXE files in the current directory"
  reva-claude -- "Find and analyze suspicious binaries in /tmp"
        """
    )
    
    parser.add_argument('files', nargs='*', help='Binary files to pre-load (optional - AI can discover and load binaries dynamically)')
    parser.add_argument('--json-output', '-j', type=str, 
                       help='Save raw JSON responses to specified file')
    parser.add_argument('--auto-analyze', action='store_true',
                       help='Run analysis on all files upfront (default: lazy analysis)')
    parser.add_argument('prompt', nargs='*', 
                       help='Analysis prompt (use after -- separator for compatibility)')
    
    # Handle backward compatibility with -- separator
    if '--' in sys.argv:
        sep_index = sys.argv.index('--')
        args_before = sys.argv[1:sep_index]
        prompt_parts = sys.argv[sep_index + 1:]
        
        # Parse args before separator
        parsed_args = parser.parse_args(args_before)
        files = parsed_args.files
        json_output = parsed_args.json_output
        auto_analyze = parsed_args.auto_analyze
        prompt = ' '.join(prompt_parts) if prompt_parts else None
    else:
        # Normal argparse behavior
        args = parser.parse_args()
        files = args.files
        json_output = args.json_output
        auto_analyze = args.auto_analyze
        prompt = ' '.join(args.prompt) if args.prompt else None
    
    # Validate files exist (if any specified)
    for file_path in files:
        if not Path(file_path).exists():
            console.print(f"[red]Error: File not found: {file_path}")
            sys.exit(1)
    
    return files, prompt, json_output, auto_analyze


async def run_claude_analysis(files: Optional[List[str]] = None, prompt: Optional[str] = None, json_output: Optional[str] = None, auto_analyze: bool = False) -> None:
    """Run Claude analysis with ReVa MCP server."""
    # Use random port for ReVa to avoid conflicts
    port = find_free_port()
    
    console.print(f"[blue]Starting ReVa with Claude Code integration...")
    console.print(f"[dim]Port: {port}")
    if files:
        console.print(f"[dim]Pre-loading files: {', '.join(files)}")
    else:
        console.print(f"[dim]Starting with empty project - AI can load binaries dynamically")
    
    session = None
    mcp_config_path = None
    settings_path = None
    
    try:
        # Start ReVa session (binaries optional)
        session = ReVaSession(
            binaries=files if files else None,
            port=port,
            auto_analyze=auto_analyze,  # Use the CLI flag value
            quiet=True  # Suppress output for Claude integration
        )
        
        # Start the session (initializes PyGhidra, creates project, imports binaries, starts server)
        session.start()
        
        # Configure ReVa port AFTER PyGhidra is initialized - ReVa modules are now available
        try:
            from reva.plugin import ConfigManager
            from reva.util import RevaInternalServiceRegistry
            
            # Always create a fresh ConfigManager for headless mode and register it
            # This prevents McpServerManager from creating a new instance with defaults
            config_manager = ConfigManager(None)  # None = headless mode
            config_manager.setServerPort(port)
            RevaInternalServiceRegistry.registerService(ConfigManager, config_manager)
            console.print(f"[dim]Configured ReVa port: {port}")
            
        except Exception as e:
            console.print(f"[yellow]Warning: Could not configure ReVa port: {e}")
            console.print("[dim]Using default port configuration")
        
        console.print("[green]✓ ReVa MCP server is ready")
        
        # Create MCP configuration for Claude Code CLI with HTTP transport
        mcp_config = {
            "mcpServers": {
                "ReVa": {
                    "type": "http",
                    "url": f"http://localhost:{port}/mcp/message"
                }
            }
        }
        
        # Create settings to allow all ReVa tools without prompting
        settings = {
            "mcp": {
                "autoApprove": ["ReVa.*"]  # Auto-approve all ReVa tools
            }
        }
        
        # Write temporary config files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as mcp_file:
            json.dump(mcp_config, mcp_file, indent=2)
            mcp_config_path = mcp_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as settings_file:
            json.dump(settings, settings_file, indent=2)
            settings_path = settings_file.name
        
        if prompt:
            # One-shot mode: run prompt and exit using SDK
            try:
                from claude_code_sdk import query, ClaudeCodeOptions
                
                console.print(f"[blue]Running prompt: {prompt}")
                
                options = ClaudeCodeOptions(
                    mcp_servers={
                        "ReVa": {
                            "type": "http",
                            "url": f"http://localhost:{port}/mcp/message"
                        }
                    }
                    # No max_turns - let Claude Code decide
                    # No model specified - use Claude Code default
                )
                
                # Store all messages for JSON output
                all_messages = []
                final_answer_text = ""
                
                # Show analysis header and start ephemeral display
                ui.show_progress_header(files, prompt)
                ui.start_ephemeral_display()
                
                async for message in query(prompt=prompt, options=options):
                    # Store for JSON output
                    if json_output:
                        try:
                            # Try to convert message to dict for JSON serialization
                            if hasattr(message, '__dict__'):
                                all_messages.append(message.__dict__)
                            else:
                                all_messages.append(str(message))
                        except Exception:
                            all_messages.append(str(message))
                    
                    # Format output based on message type
                    message_type = type(message).__name__
                    
                    if message_type == 'AssistantMessage':
                        format_assistant_message(message)
                        
                        # Collect text for final answer detection
                        for block in message.content:
                            if hasattr(block, 'text'):
                                final_answer_text += block.text + "\n"
                    
                    elif message_type == 'ToolResultBlock':
                        # Don't interrupt thinking display with tool results
                        pass
                    
                    elif message_type == 'ResultMessage':
                        # This usually contains the final result
                        if hasattr(message, 'result'):
                            format_final_answer(message.result)
                        elif hasattr(message, 'content'):
                            format_final_answer(str(message.content))
                
                # Ensure ephemeral display is ended if we haven't shown a final result yet
                if final_answer_text.strip():
                    ui.end_ephemeral_display()
                
                # Save JSON output if requested
                if json_output:
                    try:
                        with open(json_output, 'w') as f:
                            json.dump({
                                'analysis_info': {
                                    'files': files,
                                    'prompt': prompt,
                                    'timestamp': datetime.datetime.now().isoformat()
                                },
                                'messages': all_messages
                            }, f, indent=2, default=str)
                        console.print(f"\n[dim]JSON output saved to: {json_output}")
                    except Exception as e:
                        console.print(f"\n[yellow]Warning: Could not save JSON output: {e}")
                
                console.print()
                
            except ImportError:
                console.print("[red]Error: claude-code-sdk not available. Install with: pip install claude-code-sdk")
                return
            except Exception as e:
                console.print(f"[red]Error running Claude analysis: {e}")
                return
        else:
            # Interactive mode: launch Claude Code CLI with MCP config
            console.print("[blue]Launching Claude Code interactive session...")
            console.print(f"[dim]ReVa tools will be available automatically")
            console.print(f"[dim]Try: 'What programs are loaded?' or 'Analyze the main function'")
            
            # Set up signal handlers for cleanup
            def cleanup_handler(signum: int, frame: object) -> None:
                console.print("\n[yellow]Claude Code session ended. Cleaning up...")
                # Cleanup temp files
                if mcp_config_path and Path(mcp_config_path).exists():
                    try:
                        os.unlink(mcp_config_path)
                    except Exception:
                        pass
                if settings_path and Path(settings_path).exists():
                    try:
                        os.unlink(settings_path)
                    except Exception:
                        pass
                # Cleanup ReVa
                if session:
                    session.shutdown()
                sys.exit(0)
            
            signal.signal(signal.SIGINT, cleanup_handler)
            signal.signal(signal.SIGTERM, cleanup_handler)
            
            try:
                # Launch interactive Claude Code CLI
                result = subprocess.run([
                    "claude", 
                    "--mcp-config", mcp_config_path,
                    "--settings", settings_path
                ], check=False)
                
                # Check the result
                if result.returncode == 127:
                    console.print("[red]Error: 'claude' command not found. Install Claude Code CLI first:")
                    console.print("  npm install -g @anthropic-ai/claude-code")
                elif result.returncode != 0:
                    console.print(f"[yellow]Claude Code exited with code {result.returncode}")
                
            except FileNotFoundError:
                console.print("[red]Error: 'claude' command not found. Install Claude Code CLI first:")
                console.print("  npm install -g @anthropic-ai/claude-code")
            except Exception as e:
                console.print(f"[red]Error launching Claude Code: {e}")
    
    finally:
        # Clean up all resources
        # Cleanup temp files
        if mcp_config_path and Path(mcp_config_path).exists():
            try:
                os.unlink(mcp_config_path)
            except Exception as e:
                console.print(f"[dim]Warning: Could not delete temp config: {e}")
        
        if settings_path and Path(settings_path).exists():
            try:
                os.unlink(settings_path)
            except Exception as e:
                console.print(f"[dim]Warning: Could not delete temp settings: {e}")
        
        # Cleanup ReVa
        if session:
            session.shutdown()


def main() -> None:
    """Main entry point for reva-claude command."""
    # Parse arguments
    files, prompt, json_output, auto_analyze = parse_args()
    
    if prompt:
        console.print(f"[bold green]ReVa Claude Analysis (One-shot)")
    else:
        console.print(f"[bold green]ReVa Claude Analysis (Interactive)")
    
    console.print(f"[dim]Files: {', '.join(files)}")
    
    # Show analysis mode
    if auto_analyze:
        console.print(f"[dim]Analysis: Upfront analysis enabled")
    else:
        console.print(f"[dim]Analysis: Lazy analysis (Claude will analyze as needed)")
    
    # Run the analysis
    try:
        anyio.run(run_claude_analysis, files, prompt, json_output, auto_analyze)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user")
    except Exception as e:
        console.print(f"[red]Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()