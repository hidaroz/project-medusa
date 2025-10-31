"""
Rich terminal UI components for MEDUSA
Progress bars, status tables, colored output, etc.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    TaskID,
)
from rich.tree import Tree
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

console = Console()


class MedusaDisplay:
    """Terminal display manager for MEDUSA operations"""

    def __init__(self):
        self.console = console

    def show_banner(self):
        """Display MEDUSA banner"""
        banner = """
[bold red]███╗   ███╗███████╗██████╗ ██╗   ██╗███████╗ █████╗ [/bold red]
[bold red]████╗ ████║██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗[/bold red]
[bold red]██╔████╔██║█████╗  ██║  ██║██║   ██║███████╗███████║[/bold red]
[bold red]██║╚██╔╝██║██╔══╝  ██║  ██║██║   ██║╚════██║██╔══██║[/bold red]
[bold red]██║ ╚═╝ ██║███████╗██████╔╝╚██████╔╝███████║██║  ██║[/bold red]
[bold red]╚═╝     ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝[/bold red]

[cyan]AI-Powered Autonomous Penetration Testing[/cyan]
[dim]For authorized security testing purposes only[/dim]
"""
        self.console.print(banner)

    def create_progress_bar(self, description: str = "Running...") -> Progress:
        """Create a progress bar for operations"""
        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
        )

    def show_phase_tree(self, phase: str, tasks: List[Dict[str, Any]]):
        """Display hierarchical task tree for current phase"""
        tree = Tree(f"[bold cyan]{phase}[/bold cyan]")

        for task in tasks:
            status = task.get("status", "pending")
            name = task.get("name", "Unknown")

            if status == "complete":
                icon = "[green]✓[/green]"
                style = "green"
            elif status == "in_progress":
                icon = "[yellow]⟳[/yellow]"
                style = "yellow"
            elif status == "failed":
                icon = "[red]✗[/red]"
                style = "red"
            else:
                icon = "[dim]○[/dim]"
                style = "dim"

            details = task.get("details", "")
            tree.add(f"{icon} {name}: [dim]{details}[/dim]", style=style)

        self.console.print(tree)

    def show_status_table(self, data: Dict[str, Any], title: str = "Status"):
        """Display a status table"""
        table = Table(title=title, show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="green")

        for key, value in data.items():
            # Format the key to be human-readable
            formatted_key = key.replace("_", " ").title()
            formatted_value = str(value)

            table.add_row(formatted_key, formatted_value)

        self.console.print(table)

    def show_technique_coverage(self, techniques: List[Dict[str, Any]]):
        """Display MITRE ATT&CK technique coverage"""
        table = Table(title="MITRE ATT&CK Coverage", show_header=True, header_style="bold magenta")
        table.add_column("Technique ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="white")
        table.add_column("Status", style="green")

        for technique in techniques:
            tid = technique.get("id", "T0000")
            name = technique.get("name", "Unknown")
            status = technique.get("status", "pending")

            if status == "executed":
                status_text = "[green]✓ Executed[/green]"
            elif status == "skipped":
                status_text = "[yellow]⊘ Skipped[/yellow]"
            else:
                status_text = "[dim]○ Pending[/dim]"

            table.add_row(tid, name, status_text)

        self.console.print(table)

    def show_findings(self, findings: List[Dict[str, Any]]):
        """Display security findings"""
        if not findings:
            self.console.print("[dim]No findings to display[/dim]")
            return

        for finding in findings:
            severity = finding.get("severity", "info").upper()
            title = finding.get("title", "Unknown Finding")
            description = finding.get("description", "")

            if severity == "CRITICAL":
                color = "red"
                icon = "🔴"
            elif severity == "HIGH":
                color = "red"
                icon = "🟠"
            elif severity == "MEDIUM":
                color = "yellow"
                icon = "🟡"
            elif severity == "LOW":
                color = "blue"
                icon = "🔵"
            else:
                color = "dim"
                icon = "⚪"

            panel = Panel(
                f"[{color}]{description}[/{color}]",
                title=f"{icon} [{color}]{severity}[/{color}] - {title}",
                border_style=color,
            )
            self.console.print(panel)

    def show_agent_thinking(self, thought: str):
        """Display agent's reasoning/thinking process"""
        self.console.print(Panel(f"[italic cyan]{thought}[/italic cyan]", title="🤖 Agent Thinking", border_style="cyan"))

    def show_error(self, message: str, title: str = "Error"):
        """Display error message"""
        self.console.print(Panel(f"[red]{message}[/red]", title=f"❌ {title}", border_style="red"))

    def show_success(self, message: str, title: str = "Success"):
        """Display success message"""
        self.console.print(Panel(f"[green]{message}[/green]", title=f"✓ {title}", border_style="green"))

    def show_warning(self, message: str, title: str = "Warning"):
        """Display warning message"""
        self.console.print(Panel(f"[yellow]{message}[/yellow]", title=f"⚠️  {title}", border_style="yellow"))

    def show_info(self, message: str):
        """Display info message"""
        self.console.print(f"[cyan]ℹ[/cyan] {message}")

    def create_live_dashboard(self) -> Layout:
        """Create a live updating dashboard layout"""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        return layout


# Global display instance
display = MedusaDisplay()

