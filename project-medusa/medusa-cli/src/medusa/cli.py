"""
MEDUSA CLI - Main entry point
Command-line interface using Typer framework
"""

import sys
import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from medusa import __version__
from medusa.config import get_config
from medusa.display import display
from medusa.modes import AutonomousMode, InteractiveMode, ObserveMode

app = typer.Typer(
    name="medusa",
    help="🔴 MEDUSA - AI-Powered Penetration Testing CLI",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def setup(
    force: bool = typer.Option(
        False, "--force", "-f", help="Force re-setup even if config exists"
    )
):
    """
    🔧 Run the setup wizard to configure MEDUSA.

    This will guide you through:
    - Setting up your Gemini API key
    - Configuring target environment
    - Setting risk tolerance levels
    - Initializing Docker environment (optional)
    """
    config = get_config()

    # Check if already configured
    if config.exists() and not force:
        console.print(
            "[yellow]MEDUSA is already configured.[/yellow]\n"
            f"Config location: [cyan]{config.config_path}[/cyan]\n\n"
            "Use [bold]--force[/bold] to reconfigure."
        )
        raise typer.Exit()

    # Run setup wizard
    try:
        config.run_setup_wizard()
    except KeyboardInterrupt:
        console.print("\n[yellow]Setup cancelled[/yellow]")
        raise typer.Exit(1)


@app.command()
def run(
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="Target URL (e.g., http://localhost:3001)"
    ),
    autonomous: bool = typer.Option(
        False, "--autonomous", "-a", help="Run in autonomous mode with approval gates"
    ),
    mode: Optional[str] = typer.Option(
        None, "--mode", "-m", help="Operating mode: autonomous, interactive, observe"
    ),
):
    """
    🚀 Run a penetration test.

    Examples:
        medusa run --target localhost --autonomous
        medusa run --target http://example.com --mode observe
    """
    # Ensure configuration exists
    config = get_config()
    if not config.exists():
        console.print(
            "[red]Error: MEDUSA is not configured.[/red]\n"
            "Run [bold]medusa setup[/bold] first."
        )
        raise typer.Exit(1)

    # Load config
    try:
        config_data = config.load()
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        raise typer.Exit(1)

    # Determine target
    if not target:
        target = config_data.get("target", {}).get("url")
        if not target:
            console.print("[red]Error: No target specified and no default configured.[/red]")
            raise typer.Exit(1)

    # Get API key
    api_key = config_data.get("api_key")
    if not api_key:
        console.print("[red]Error: No API key found in configuration.[/red]")
        raise typer.Exit(1)

    # Determine mode
    if autonomous or mode == "autonomous":
        _run_autonomous_mode(target, api_key)
    elif mode == "interactive":
        _run_interactive_mode(target, api_key)
    elif mode == "observe":
        _run_observe_mode(target, api_key)
    else:
        # Default to autonomous
        _run_autonomous_mode(target, api_key)


@app.command()
def shell(
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="Target URL (optional, can be set in shell)"
    )
):
    """
    💻 Start interactive shell mode.

    Provides a REPL where you can issue natural language commands:
        MEDUSA> scan network
        MEDUSA> enumerate services
        MEDUSA> show findings
    """
    # Ensure configuration
    config = get_config()
    if not config.exists():
        console.print(
            "[red]Error: MEDUSA is not configured.[/red]\n"
            "Run [bold]medusa setup[/bold] first."
        )
        raise typer.Exit(1)

    config_data = config.load()
    api_key = config_data.get("api_key")

    # Use configured target if not provided
    if not target:
        target = config_data.get("target", {}).get("url")

    _run_interactive_mode(target, api_key)


@app.command()
def observe(
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="Target URL to observe"
    )
):
    """
    👁️  Run in observe mode (reconnaissance only).

    Performs passive and active reconnaissance without exploitation.
    Generates an attack plan but does NOT execute it.

    Perfect for:
    - Initial assessment
    - Safe exploration
    - Attack planning
    """
    # Ensure configuration
    config = get_config()
    if not config.exists():
        console.print(
            "[red]Error: MEDUSA is not configured.[/red]\n"
            "Run [bold]medusa setup[/bold] first."
        )
        raise typer.Exit(1)

    config_data = config.load()
    api_key = config_data.get("api_key")

    if not target:
        target = config_data.get("target", {}).get("url")
        if not target:
            console.print("[red]Error: No target specified.[/red]")
            raise typer.Exit(1)

    _run_observe_mode(target, api_key)


@app.command()
def status():
    """
    📊 Show MEDUSA status and configuration.
    """
    config = get_config()

    if not config.exists():
        console.print(
            "[yellow]MEDUSA is not configured.[/yellow]\n"
            "Run [bold]medusa setup[/bold] to get started."
        )
        raise typer.Exit()

    # Load config
    config_data = config.load()

    # Display status
    display.console.print("\n[bold cyan]MEDUSA Status[/bold cyan]\n")

    status_data = {
        "Version": __version__,
        "Config Path": str(config.config_path),
        "Logs Directory": str(config.logs_dir),
        "Reports Directory": str(config.reports_dir),
        "Target": config_data.get("target", {}).get("url", "Not set"),
        "Target Type": config_data.get("target", {}).get("type", "Not set"),
        "API Key": "Configured" if config_data.get("api_key") else "Not set",
    }

    display.show_status_table(status_data, "Configuration")

    # Risk tolerance
    risk = config_data.get("risk_tolerance", {})
    risk_data = {
        "Auto-approve LOW risk": "Yes" if risk.get("auto_approve_low") else "No",
        "Auto-approve MEDIUM risk": "Yes" if risk.get("auto_approve_medium") else "No",
        "Auto-approve HIGH risk": "Yes" if risk.get("auto_approve_high") else "No",
    }

    display.console.print()
    display.show_status_table(risk_data, "Risk Tolerance")


@app.command()
def version():
    """
    📌 Show MEDUSA version.
    """
    console.print(f"[bold cyan]MEDUSA[/bold cyan] version [green]{__version__}[/green]")


@app.command()
def logs(
    latest: bool = typer.Option(False, "--latest", "-l", help="Show only latest log"),
    tail: int = typer.Option(
        20, "--tail", "-n", help="Number of lines to show from each log"
    ),
):
    """
    📝 View operation logs.
    """
    config = get_config()

    if not config.logs_dir.exists():
        console.print("[yellow]No logs directory found.[/yellow]")
        raise typer.Exit()

    # Get log files
    log_files = sorted(config.logs_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)

    if not log_files:
        console.print("[yellow]No log files found.[/yellow]")
        raise typer.Exit()

    if latest:
        log_files = [log_files[-1]]

    for log_file in log_files:
        console.print(f"\n[bold cyan]Log:[/bold cyan] {log_file.name}")
        console.print(f"[dim]Path: {log_file}[/dim]\n")

        # Read and display (simplified - would normally parse JSON nicely)
        try:
            import json

            with open(log_file) as f:
                data = json.load(f)

            # Show summary
            metadata = data.get("metadata", {})
            operation = data.get("operation", {})

            console.print(f"Operation ID: {metadata.get('operation_id', 'Unknown')}")
            console.print(f"Timestamp: {metadata.get('timestamp', 'Unknown')}")
            console.print(
                f"Duration: {operation.get('duration_seconds', 0):.1f}s"
            )
            console.print(
                f"Total Findings: {operation.get('summary', {}).get('total_findings', 0)}"
            )
        except Exception as e:
            console.print(f"[red]Error reading log: {e}[/red]")


@app.command()
def reports(
    open_latest: bool = typer.Option(
        False, "--open", "-o", help="Open latest report in browser"
    )
):
    """
    📄 View generated reports.
    """
    config = get_config()

    if not config.reports_dir.exists():
        console.print("[yellow]No reports directory found.[/yellow]")
        raise typer.Exit()

    # Get report files
    report_files = sorted(
        config.reports_dir.glob("*.html"), key=lambda p: p.stat().st_mtime
    )

    if not report_files:
        console.print("[yellow]No reports found.[/yellow]")
        raise typer.Exit()

    if open_latest:
        import webbrowser

        latest_report = report_files[-1]
        console.print(f"[green]Opening report:[/green] {latest_report.name}")
        webbrowser.open(f"file://{latest_report.absolute()}")
    else:
        console.print(f"\n[bold cyan]Available Reports:[/bold cyan]\n")
        for report in report_files[-10:]:  # Show last 10
            console.print(f"  • {report.name}")
        console.print(f"\n[dim]Location: {config.reports_dir}[/dim]")
        console.print("\n[cyan]Tip:[/cyan] Use [bold]--open[/bold] to view latest report")


def _run_autonomous_mode(target: str, api_key: str):
    """Run autonomous mode"""
    try:
        mode = AutonomousMode(target, api_key)
        asyncio.run(mode.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


def _run_interactive_mode(target: Optional[str], api_key: str):
    """Run interactive shell mode"""
    try:
        mode = InteractiveMode(target, api_key)
        asyncio.run(mode.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Session terminated[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


def _run_observe_mode(target: str, api_key: str):
    """Run observe mode"""
    try:
        mode = ObserveMode(target, api_key)
        asyncio.run(mode.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Observation interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


def main():
    """Main entry point"""
    try:
        app()
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()

