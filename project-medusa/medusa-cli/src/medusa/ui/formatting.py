"""
Output Formatting
Rich formatting for CLI output
"""

from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.tree import Tree
from rich import box
import json


console = Console()


def format_output(data: Any, format_type: str = "rich") -> str:
    """
    Format output based on type

    Args:
        data: Data to format
        format_type: Output format (rich, json, plain, markdown)

    Returns:
        Formatted string
    """
    if format_type == "json":
        return json.dumps(data, indent=2)
    elif format_type == "plain":
        return str(data)
    elif format_type == "markdown":
        return _to_markdown(data)
    else:  # rich
        return _to_rich(data)


def format_table(
    data: List[Dict[str, Any]],
    title: Optional[str] = None,
    columns: Optional[List[str]] = None
) -> Table:
    """
    Create a rich table

    Args:
        data: List of dictionaries
        title: Table title
        columns: Column names (defaults to dict keys)

    Returns:
        Rich Table object
    """
    if not data:
        table = Table(title=title or "No Data")
        return table

    # Get columns from first item if not specified
    if not columns:
        columns = list(data[0].keys())

    # Create table
    table = Table(title=title, box=box.ROUNDED)

    # Add columns
    for col in columns:
        table.add_column(col.replace("_", " ").title(), style="cyan")

    # Add rows
    for row in data:
        table.add_row(*[str(row.get(col, "")) for col in columns])

    return table


def format_findings(findings: List[Dict[str, Any]]) -> Panel:
    """
    Format security findings

    Args:
        findings: List of findings

    Returns:
        Rich Panel with formatted findings
    """
    if not findings:
        return Panel("No findings", title="Findings", border_style="green")

    # Group by severity
    by_severity = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": [],
    }

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        by_severity.get(severity, by_severity["info"]).append(finding)

    # Build tree
    tree = Tree("🔍 Security Findings")

    severity_colors = {
        "critical": "bright_red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "cyan",
    }

    severity_icons = {
        "critical": "🔥",
        "high": "❗",
        "medium": "⚠️",
        "low": "ℹ️",
        "info": "📌",
    }

    for severity, findings_list in by_severity.items():
        if not findings_list:
            continue

        color = severity_colors.get(severity, "white")
        icon = severity_icons.get(severity, "•")

        severity_branch = tree.add(
            f"[{color}]{icon} {severity.upper()} ({len(findings_list)})[/{color}]"
        )

        for finding in findings_list[:10]:  # Limit to 10 per severity
            title = finding.get("title", finding.get("name", "Unknown"))
            severity_branch.add(f"[{color}]{title}[/{color}]")

    return Panel(tree, title="Findings Summary", border_style="cyan")


def format_progress(
    current: int,
    total: int,
    status: str = ""
) -> str:
    """
    Format progress indicator

    Args:
        current: Current progress
        total: Total items
        status: Status message

    Returns:
        Formatted progress string
    """
    percentage = (current / total * 100) if total > 0 else 0
    bar_length = 40
    filled = int(bar_length * current / total) if total > 0 else 0

    bar = "█" * filled + "░" * (bar_length - filled)

    return f"[{bar}] {current}/{total} ({percentage:.1f}%) {status}"


def format_host_info(host: Dict[str, Any]) -> Panel:
    """
    Format host information

    Args:
        host: Host dictionary

    Returns:
        Rich Panel with host info
    """
    content = []

    content.append(f"[bold]IP:[/bold] {host.get('ip', 'Unknown')}")
    content.append(f"[bold]Hostname:[/bold] {host.get('hostname', 'N/A')}")
    content.append(f"[bold]OS:[/bold] {host.get('os', 'Unknown')}")
    content.append(f"[bold]Status:[/bold] {host.get('status', 'Unknown')}")

    # Services
    services = host.get('services', [])
    if services:
        content.append(f"\n[bold]Services ({len(services)}):[/bold]")
        for svc in services[:5]:
            port = svc.get('port', '?')
            name = svc.get('name', 'unknown')
            content.append(f"  • {port}/{name}")

    # Vulnerabilities
    vulns = host.get('vulnerabilities', [])
    if vulns:
        content.append(f"\n[bold]Vulnerabilities ({len(vulns)}):[/bold]")
        for vuln in vulns[:3]:
            cve = vuln.get('cve_id', 'N/A')
            severity = vuln.get('severity', 'unknown')
            content.append(f"  • {cve} ({severity})")

    return Panel(
        "\n".join(content),
        title=f"Host: {host.get('ip', 'Unknown')}",
        border_style="cyan"
    )


def format_code(code: str, language: str = "python") -> Syntax:
    """
    Format code with syntax highlighting

    Args:
        code: Code string
        language: Programming language

    Returns:
        Rich Syntax object
    """
    return Syntax(code, language, theme="monokai", line_numbers=True)


def _to_rich(data: Any) -> str:
    """Convert data to rich format"""
    if isinstance(data, (list, dict)):
        return json.dumps(data, indent=2)
    return str(data)


def _to_markdown(data: Any) -> str:
    """Convert data to markdown"""
    if isinstance(data, list):
        if not data:
            return "No data"

        if isinstance(data[0], dict):
            # Table format
            keys = list(data[0].keys())
            lines = []

            # Header
            lines.append("| " + " | ".join(keys) + " |")
            lines.append("| " + " | ".join(["---"] * len(keys)) + " |")

            # Rows
            for row in data:
                lines.append("| " + " | ".join(str(row.get(k, "")) for k in keys) + " |")

            return "\n".join(lines)

    elif isinstance(data, dict):
        lines = []
        for key, value in data.items():
            lines.append(f"**{key}**: {value}")
        return "\n".join(lines)

    return str(data)
