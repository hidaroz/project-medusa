"""
Smart progress indicators with time estimates and phase visualization.

Provides progress tracking for penetration testing phases with:
- Real-time progress bars
- Estimated time remaining
- Phase-by-phase breakdown
- Findings counter
- Elapsed time tracking
"""

from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from enum import Enum

from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
)
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()


class PhaseStatus(str, Enum):
    """Status of a penetration testing phase."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class PhaseMetrics:
    """Metrics for a penetration testing phase."""

    name: str
    estimated_duration: int  # seconds
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings_count: int = 0
    status: PhaseStatus = PhaseStatus.PENDING
    error_message: Optional[str] = None

    def get_duration(self) -> int:
        """Get actual or estimated duration in seconds."""
        if self.completed_at and self.started_at:
            return int((self.completed_at - self.started_at).total_seconds())
        elif self.started_at:
            return int((datetime.now() - self.started_at).total_seconds())
        return self.estimated_duration

    def get_status_icon(self) -> str:
        """Get status icon for display."""
        if self.status == PhaseStatus.COMPLETED:
            return "✓"
        elif self.status == PhaseStatus.RUNNING:
            return "⚡"
        elif self.status == PhaseStatus.SKIPPED:
            return "○"
        elif self.status == PhaseStatus.FAILED:
            return "✗"
        return "○"


class SmartProgress:
    """
    Smart progress tracking for penetration testing with time estimates.

    Features:
    - Real-time progress bars
    - Estimated time remaining
    - Phase-by-phase breakdown
    - Findings counter
    - Elapsed time tracking
    """

    def __init__(self):
        self.phases: Dict[str, PhaseMetrics] = {
            "reconnaissance": PhaseMetrics("Reconnaissance", 30),
            "enumeration": PhaseMetrics("Enumeration", 60),
            "vulnerability_scan": PhaseMetrics("Vulnerability Scan", 120),
            "exploitation": PhaseMetrics("Exploitation", 90),
            "post_exploitation": PhaseMetrics("Post-Exploitation", 60),
            "reporting": PhaseMetrics("Report Generation", 30),
        }
        self.current_phase: Optional[str] = None
        self.start_time = datetime.now()

    def start_phase(self, phase_name: str) -> None:
        """Start a new phase."""
        self.current_phase = phase_name
        if phase_name in self.phases:
            self.phases[phase_name].status = PhaseStatus.RUNNING
            self.phases[phase_name].started_at = datetime.now()

    def complete_phase(
        self, phase_name: str, findings_count: int = 0, error: Optional[str] = None
    ) -> None:
        """Mark phase as complete."""
        if phase_name in self.phases:
            if error:
                self.phases[phase_name].status = PhaseStatus.FAILED
                self.phases[phase_name].error_message = error
            else:
                self.phases[phase_name].status = PhaseStatus.COMPLETED
            self.phases[phase_name].completed_at = datetime.now()
            self.phases[phase_name].findings_count = findings_count

    def skip_phase(self, phase_name: str, reason: str = "") -> None:
        """Mark phase as skipped."""
        if phase_name in self.phases:
            self.phases[phase_name].status = PhaseStatus.SKIPPED
            self.phases[phase_name].error_message = reason

    def show_overall_progress(self) -> None:
        """Display overall progress visualization."""

        table = Table(
            title="[bold cyan]🎯 Penetration Test Progress[/bold cyan]",
            show_header=True,
            header_style="bold magenta",
        )

        table.add_column("Phase", style="cyan", width=25)
        table.add_column("Status", width=14)
        table.add_column("Duration", justify="right", width=12)
        table.add_column("Findings", justify="right", width=10)

        total_findings = 0

        for phase in self.phases.values():
            # Status with icon and color
            icon = phase.get_status_icon()
            if phase.status == PhaseStatus.COMPLETED:
                status = f"[green]{icon} Complete[/green]"
            elif phase.status == PhaseStatus.RUNNING:
                status = f"[yellow]{icon} Running[/yellow]"
            elif phase.status == PhaseStatus.SKIPPED:
                status = f"[dim]{icon} Skipped[/dim]"
            elif phase.status == PhaseStatus.FAILED:
                status = f"[red]{icon} Failed[/red]"
            else:
                status = f"[dim]{icon} Pending[/dim]"

            # Duration
            duration = phase.get_duration()
            if phase.status == PhaseStatus.COMPLETED or phase.status == PhaseStatus.FAILED:
                duration_str = f"{duration}s"
            elif phase.status == PhaseStatus.RUNNING:
                duration_str = f"[yellow]{duration}s...[/yellow]"
            else:
                duration_str = f"[dim]~{phase.estimated_duration}s[/dim]"

            # Findings
            findings_str = (
                f"[bold]{phase.findings_count}[/bold]"
                if phase.findings_count > 0
                else "[dim]0[/dim]"
            )
            total_findings += phase.findings_count

            table.add_row(
                phase.name,
                status,
                duration_str,
                findings_str,
            )

        # Calculate total elapsed time
        elapsed = (datetime.now() - self.start_time).total_seconds()

        # Add summary row
        table.add_section()
        table.add_row(
            "[bold]Total[/bold]",
            "",
            f"[bold]{int(elapsed)}s[/bold]",
            f"[bold cyan]{total_findings}[/bold cyan]",
        )

        console.print()
        console.print(table)
        console.print()

    def show_phase_start(self, phase_name: str) -> None:
        """Display message when a phase starts."""
        if phase_name in self.phases:
            phase = self.phases[phase_name]
            console.print()
            console.print(
                f"[bold cyan]▶ {phase.name}[/bold cyan] "
                f"[dim](est. {phase.estimated_duration}s)[/dim]"
            )

    def show_phase_complete(self, phase_name: str) -> None:
        """Display message when a phase completes."""
        if phase_name in self.phases:
            phase = self.phases[phase_name]
            duration = phase.get_duration()
            findings = f" - [bold cyan]{phase.findings_count} findings[/bold cyan]" if phase.findings_count > 0 else ""
            console.print(f"[green]✓ {phase.name} complete[/green] ({duration}s){findings}")

    def create_tool_progress(
        self, description: str, total: Optional[int] = None
    ) -> Progress:
        """
        Create progress bar for tool execution.

        Args:
            description: Tool description (e.g., "Scanning ports")
            total: Total units if known (e.g., number of ports)

        Returns:
            Progress object to use with context manager
        """

        return Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn() if total else TextColumn(""),
            TaskProgressColumn() if total else TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        )

    def show_findings_summary(self, findings: List[dict]) -> None:
        """Display findings summary by severity."""

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for finding in findings:
            severity = finding.get("severity", "INFO").upper()
            if severity in severity_counts:
                severity_counts[severity] += 1

        table = Table(title="[bold]📋 Findings Summary[/bold]")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        # Color code by severity
        severity_colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }

        for severity, count in sorted(
            severity_counts.items(),
            key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x[0]),
        ):
            if count > 0:
                color = severity_colors.get(severity, "white")
                table.add_row(
                    f"[{color}]{severity}[/{color}]",
                    f"[{color}]{count}[/{color}]",
                )

        console.print()
        console.print(table)
        console.print()

    def get_summary(self) -> dict:
        """Get summary statistics."""
        total_findings = sum(p.findings_count for p in self.phases.values())
        elapsed = (datetime.now() - self.start_time).total_seconds()
        completed = sum(
            1
            for p in self.phases.values()
            if p.status == PhaseStatus.COMPLETED
        )
        total = len(self.phases)

        return {
            "total_findings": total_findings,
            "elapsed_seconds": int(elapsed),
            "phases_completed": completed,
            "total_phases": total,
            "status": "completed" if completed == total else "in_progress",
        }

