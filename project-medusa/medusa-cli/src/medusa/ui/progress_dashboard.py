"""
Real-time progress dashboard
"""
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.layout import Layout
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
import threading
import time

console = Console()


@dataclass
class Step:
    """Represents a step in the operation"""
    name: str
    status: str = "pending"  # pending, running, completed, failed
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    details: str = ""


class ProgressDashboard:
    """Live progress dashboard for operations"""

    def __init__(self, operation_name: str):
        self.operation_name = operation_name
        self.steps: List[Step] = []
        self.current_step: Optional[Step] = None
        self.findings_count = 0
        self.started_at = datetime.now()
        self.layout = Layout()
        self.live = None
        self._lock = threading.Lock()

    def add_step(self, name: str) -> Step:
        """Add a new step"""
        step = Step(name=name)
        with self._lock:
            self.steps.append(step)
        return step

    def start_step(self, step: Step, details: str = ""):
        """Mark step as started"""
        with self._lock:
            step.status = "running"
            step.started_at = datetime.now()
            step.details = details
            self.current_step = step

    def complete_step(self, step: Step, details: str = ""):
        """Mark step as completed"""
        with self._lock:
            step.status = "completed"
            step.completed_at = datetime.now()
            if details:
                step.details = details

    def fail_step(self, step: Step, error: str):
        """Mark step as failed"""
        with self._lock:
            step.status = "failed"
            step.completed_at = datetime.now()
            step.details = f"Error: {error}"

    def add_finding(self):
        """Increment findings counter"""
        with self._lock:
            self.findings_count += 1

    def _generate_table(self) -> Table:
        """Generate the progress table"""
        table = Table(title=f"🔍 {self.operation_name}", show_header=True)
        table.add_column("Step", style="cyan", width=30)
        table.add_column("Status", width=15)
        table.add_column("Duration", width=12)
        table.add_column("Details", style="dim")

        for step in self.steps:
            # Status icon and color
            if step.status == "completed":
                status = "[green]✓ Completed[/]"
            elif step.status == "running":
                status = "[yellow]⚙ Running[/]"
            elif step.status == "failed":
                status = "[red]✗ Failed[/]"
            else:
                status = "[dim]○ Pending[/]"

            # Duration
            if step.started_at:
                end_time = step.completed_at or datetime.now()
                duration = (end_time - step.started_at).total_seconds()
                duration_str = f"{duration:.1f}s"
            else:
                duration_str = "-"

            table.add_row(
                step.name,
                status,
                duration_str,
                step.details[:50] if step.details else ""
            )

        return table

    def _generate_summary(self) -> Panel:
        """Generate summary panel"""
        elapsed = (datetime.now() - self.started_at).total_seconds()
        completed = sum(1 for s in self.steps if s.status == "completed")
        failed = sum(1 for s in self.steps if s.status == "failed")
        total = len(self.steps)

        summary = (
            f"⏱️  Elapsed: {elapsed:.1f}s\n"
            f"📊 Progress: {completed}/{total} steps completed\n"
            f"🔍 Findings: {self.findings_count}\n"
        )

        if failed > 0:
            summary += f"⚠️  Failures: {failed}\n"

        return Panel(summary, title="Summary", border_style="blue")

    def _generate_layout(self) -> Layout:
        """Generate the full layout"""
        layout = Layout()
        layout.split_column(
            Layout(self._generate_summary(), size=6),
            Layout(self._generate_table())
        )
        return layout

    def start(self):
        """Start the live dashboard"""
        self.live = Live(self._generate_layout(), refresh_per_second=4, console=console)
        self.live.start()

    def update(self):
        """Update the display"""
        if self.live:
            self.live.update(self._generate_layout())

    def stop(self):
        """Stop the dashboard"""
        if self.live:
            self.live.stop()


# Context manager for easy use
class dashboard:
    """Context manager for progress dashboard"""

    def __init__(self, operation_name: str):
        self.dash = ProgressDashboard(operation_name)

    def __enter__(self):
        self.dash.start()
        return self.dash

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.dash.stop()


# Usage example
"""
with dashboard("Reconnaissance") as dash:
    step1 = dash.add_step("Port scanning")
    dash.start_step(step1, "Scanning ports 1-1000")
    time.sleep(2)
    dash.complete_step(step1, "Found 3 open ports")

    step2 = dash.add_step("Service detection")
    dash.start_step(step2, "Identifying services")
    dash.add_finding()
    time.sleep(1)
    dash.complete_step(step2)
"""
