#!/usr/bin/env python3
"""
Clean UI manager for ReVa Claude integration.
Provides ephemeral thinking display and clean persistent results.
"""

from typing import Optional, List, Any
from rich.console import Console
from rich.live import Live
from rich.text import Text
from rich.panel import Panel

console = Console()


class CleanUI:
    """Clean UI manager for ReVa analysis output."""
    
    def __init__(self):
        self.live_display: Optional[Live] = None
        self.current_activity = ""
        
    def start_ephemeral_display(self):
        """Start the ephemeral thinking display."""
        if self.live_display is None:
            self.live_display = Live(
                Text("Starting analysis...", style="dim"),
                console=console,
                refresh_per_second=4,
                transient=False
            )
            self.live_display.start()
    
    def update_activity(self, activity: str):
        """Update the current activity in the ephemeral display."""
        self.current_activity = activity
        if self.live_display:
            self.live_display.update(Text(f"> {activity}", style="blue"))
    
    
    def show_thinking(self, thought: str):
        """Show Claude's thinking process in ephemeral display."""
        # Show the thinking text, but keep it reasonably concise for the live display
        # Split into lines and show the most meaningful one
        lines = thought.split('\n')
        
        # Find the most substantive line (skip empty lines and headers)
        substantive_line = ""
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and len(line) > 10:
                substantive_line = line
                break
        
        # If no substantive line found, use first non-empty line
        if not substantive_line:
            substantive_line = next((line.strip() for line in lines if line.strip()), thought[:100])
        
        # Truncate if too long for display
        if len(substantive_line) > 100:
            substantive_line = substantive_line[:97] + "..."
        
        self.update_activity(substantive_line)
    
    def end_ephemeral_display(self):
        """End the ephemeral display and clear it."""
        if self.live_display:
            self.live_display.stop()
            self.live_display = None
    
    def show_final_result(self, result_text: str):
        """Show the final result in persistent output."""
        # Clean up the result text
        clean_text = result_text.strip()
        
        console.print()
        console.print(Text("Final Analysis:", style="bold green"))
        console.print(clean_text)
        console.print()
    
    def show_error(self, error_text: str):
        """Show an error message."""
        console.print(f"Error: {error_text}", style="red")
    
    def show_warning(self, warning_text: str):
        """Show a warning message."""
        console.print(f"Warning: {warning_text}", style="yellow")
    
    def show_progress_header(self, files: List[str], prompt: str):
        """Show the analysis header."""
        # Don't repeat the prompt since it's already shown in main()
        console.print()


# Global UI instance
ui = CleanUI()


def format_assistant_message(message) -> None:
    """Format and display an AssistantMessage with clean UI."""
    for block in message.content:
        if hasattr(block, 'text'):
            # Show thinking in ephemeral display
            ui.show_thinking(block.text)
        elif hasattr(block, 'name'):  # ToolUseBlock
            format_tool_use(block)


def format_tool_use(tool_block) -> None:
    """Format and display tool usage cleanly."""
    # Don't interrupt the thinking display with tool execution details
    pass




def format_final_answer(text: str) -> None:
    """Format the final answer prominently."""
    ui.end_ephemeral_display()
    ui.show_final_result(text)