"""
MEDUSA CLI - Main entry point
Command-line interface using Typer framework
"""

import sys
import asyncio
from pathlib import Path
from typing import Optional
from datetime import datetime

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


@app.callback()
def main_callback(
    ctx: typer.Context,
    skip_checks: bool = typer.Option(False, "--skip-checks", help="Skip dependency checks")
):
    """MEDUSA - AI-Powered Penetration Testing"""

    # Skip checks for certain commands
    if ctx.invoked_subcommand in ["setup", "help", "version", "check_deps"]:
        return

    if not skip_checks:
        from medusa.core.dependencies import check_dependencies

        if not check_dependencies():
            console.print("\n[yellow]⚠[/] Some dependencies are missing")
            console.print("Run: [cyan]medusa setup[/] to fix")

            if not typer.confirm("Continue anyway?", default=False):
                raise typer.Exit(1)


@app.command()
def setup(
    force: bool = typer.Option(
        False, "--force", "-f", help="Force re-setup even if config exists"
    )
):
    """
    🔧 Run the interactive setup wizard to configure MEDUSA.

    This will guide you through:
    - Setting up your Gemini API key or local Ollama
    - Configuring target environment
    - Setting risk tolerance levels
    - Testing your configuration
    """
    from medusa.commands.setup_wizard import run_wizard

    config = get_config()

    # Check if already configured
    if config.exists() and not force:
        console.print(
            "[yellow]MEDUSA is already configured.[/yellow]\n"
            f"Config location: [cyan]{config.config_path}[/cyan]\n\n"
            "Use [bold]--force[/bold] to reconfigure."
        )
        raise typer.Exit()

    # Run new interactive setup wizard
    try:
        run_wizard()
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


@app.command(name="sh")
def shell_alias(
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="Target URL (optional)"
    )
):
    """
    💻 Alias for 'shell' command - interactive mode.
    """
    shell(target)


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


@app.command(name="obs")
def observe_alias(
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="Target URL to observe"
    )
):
    """
    👁️  Alias for 'observe' command - reconnaissance only mode.
    """
    observe(target)


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


@app.command(name="check-deps")
def check_deps():
    """
    🔍 Check system dependencies and requirements.

    Verifies that all required and optional dependencies are installed:
    - Python packages
    - System tools (nmap, docker, etc.)
    - Services (Ollama, etc.)
    """
    from medusa.core.dependencies import check_dependencies

    all_ok = check_dependencies()

    if all_ok:
        console.print("\n[bold green]✅ All required dependencies are installed![/bold green]")
    else:
        console.print("\n[bold yellow]⚠️  Some required dependencies are missing.[/bold yellow]")
        console.print("Run [cyan]medusa setup[/cyan] to configure MEDUSA and install dependencies.")


@app.command(name="validate-config")
def validate_config_cmd():
    """
    ✅ Validate MEDUSA configuration.

    Checks your configuration file for:
    - Potential issues
    - Risky settings
    - Best practice violations
    - Missing optional settings
    """
    from medusa.core.config_validator import validate_and_display

    config = get_config()

    if not config.exists():
        console.print(
            "[red]Error: MEDUSA is not configured.[/red]\n"
            "Run [bold]medusa setup[/bold] first."
        )
        raise typer.Exit(1)

    try:
        config_data = config.load()
        console.print("\n[bold cyan]Validating Configuration...[/bold cyan]\n")
        validate_and_display(config_data)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        raise typer.Exit(1)


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
def generate_report(
    log_file: Optional[str] = typer.Option(
        None, "--log", "-l", help="Path to log file (defaults to latest)"
    ),
    report_type: str = typer.Option(
        "all", "--type", "-t", help="Report type: technical, executive, markdown, pdf, all"
    ),
    output_dir: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output directory (defaults to config reports dir)"
    ),
):
    """
    📝 Generate reports from operation logs.

    Generate professional reports from previous penetration test runs.
    Useful for creating additional report formats or regenerating reports.

    Examples:
        medusa generate-report --type executive
        medusa generate-report --log /path/to/log.json --type pdf
        medusa generate-report --type all
    """
    from medusa.reporter import ReportGenerator
    import json

    config = get_config()

    # Determine log file
    if log_file:
        log_path = Path(log_file)
        if not log_path.exists():
            console.print(f"[red]Error: Log file not found: {log_file}[/red]")
            raise typer.Exit(1)
    else:
        # Use latest log
        if not config.logs_dir.exists():
            console.print("[yellow]No logs directory found.[/yellow]")
            raise typer.Exit()

        log_files = sorted(config.logs_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
        if not log_files:
            console.print("[yellow]No log files found.[/yellow]")
            raise typer.Exit()

        log_path = log_files[-1]
        console.print(f"[cyan]Using latest log:[/cyan] {log_path.name}\n")

    # Load log data
    try:
        with open(log_path) as f:
            log_data = json.load(f)

        operation_data = log_data.get("operation", {})
        operation_id = log_data.get("metadata", {}).get("operation_id", "unknown")
    except Exception as e:
        console.print(f"[red]Error reading log file: {e}[/red]")
        raise typer.Exit(1)

    # Initialize reporter
    reporter = ReportGenerator()

    # Override output directory if specified
    if output_dir:
        reporter.config.reports_dir = Path(output_dir)
        reporter.config.reports_dir.mkdir(parents=True, exist_ok=True)

    # Generate reports
    console.print("[bold cyan]Generating Reports...[/bold cyan]\n")
    generated = []

    try:
        if report_type in ["technical", "all"]:
            console.print("📊 Generating technical report...")
            html_path = reporter.generate_html_report(
                operation_data, operation_id, report_type="technical"
            )
            generated.append(("Technical Report (HTML)", html_path))
            console.print(f"   ✅ {html_path.name}\n")

        if report_type in ["executive", "all"]:
            console.print("📈 Generating executive summary...")
            exec_path = reporter.generate_executive_summary(operation_data, operation_id)
            generated.append(("Executive Summary (HTML)", exec_path))
            console.print(f"   ✅ {exec_path.name}\n")

        if report_type in ["markdown", "all"]:
            console.print("📝 Generating markdown report...")
            md_path = reporter.generate_markdown_report(operation_data, operation_id)
            generated.append(("Markdown Report", md_path))
            console.print(f"   ✅ {md_path.name}\n")

        if report_type in ["pdf", "all"]:
            console.print("📄 Generating PDF report...")
            pdf_path = reporter.generate_pdf_report(operation_data, operation_id)
            if pdf_path:
                generated.append(("PDF Report", pdf_path))
                console.print(f"   ✅ {pdf_path.name}\n")
            else:
                console.print("   ⚠️  PDF generation skipped (weasyprint not installed)\n")

        # Summary
        console.print(f"[bold green]✅ Generated {len(generated)} report(s):[/bold green]\n")
        for report_name, report_path in generated:
            console.print(f"  • {report_name}")
            console.print(f"    [dim]{report_path}[/dim]\n")

    except Exception as e:
        console.print(f"[red]Error generating reports: {e}[/red]")
        import traceback
        traceback.print_exc()
        raise typer.Exit(1)


@app.command()
def export(
    log_file: Optional[str] = typer.Argument(None, help="Path to log file (defaults to latest)"),
    format: str = typer.Option("all", "--format", "-f", help="Export format: json, csv, markdown, all"),
    output_dir: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory")
):
    """
    📤 Export findings in multiple formats.

    Export findings from operation logs to various formats:
    - JSON: Machine-readable data
    - CSV: Spreadsheet-friendly format
    - Markdown: Documentation-friendly format

    Examples:
        medusa export --format json
        medusa export /path/to/log.json --format csv
        medusa export --format all --output ./exports
    """
    from medusa.reporting.exporters import JSONExporter, CSVExporter, MarkdownExporter
    import json

    config = get_config()

    # Determine log file
    if log_file:
        log_path = Path(log_file)
        if not log_path.exists():
            console.print(f"[red]Error: Log file not found: {log_file}[/red]")
            raise typer.Exit(1)
    else:
        # Use latest log
        if not config.logs_dir.exists():
            console.print("[yellow]No logs directory found.[/yellow]")
            raise typer.Exit()

        log_files = sorted(config.logs_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
        if not log_files:
            console.print("[yellow]No log files found.[/yellow]")
            raise typer.Exit()

        log_path = log_files[-1]
        console.print(f"[cyan]Using latest log:[/cyan] {log_path.name}\n")

    # Load findings
    try:
        with open(log_path) as f:
            data = json.load(f)
    except Exception as e:
        console.print(f"[red]Error reading log file: {e}[/red]")
        raise typer.Exit(1)

    findings = data.get("findings", [])
    target = data.get("target", "unknown")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    output_path = Path(output_dir) if output_dir else config.reports_dir
    output_path.mkdir(parents=True, exist_ok=True)

    console.print("[bold cyan]Exporting findings...[/bold cyan]\n")

    if format in ["json", "all"]:
        json_path = output_path / f"findings_{timestamp}.json"
        JSONExporter.export(findings, json_path)
        console.print(f"[green]✓[/] Exported JSON: {json_path}")

    if format in ["csv", "all"]:
        csv_path = output_path / f"findings_{timestamp}.csv"
        CSVExporter.export(findings, csv_path)
        console.print(f"[green]✓[/] Exported CSV: {csv_path}")

    if format in ["markdown", "all"]:
        md_path = output_path / f"findings_{timestamp}.md"
        MarkdownExporter.export(findings, target, md_path)
        console.print(f"[green]✓[/] Exported Markdown: {md_path}")

    console.print(f"\n[bold green]✅ Export complete![/bold green]")
    console.print(f"[dim]Output directory: {output_path}[/dim]")


@app.command()
def reports(
    open_latest: bool = typer.Option(
        False, "--open", "-o", help="Open latest report in browser"
    ),
    report_type: Optional[str] = typer.Option(
        None, "--type", "-t", help="Filter by report type: html, md, pdf, exec"
    ),
):
    """
    📄 View generated reports.

    Report Types:
    - HTML technical reports (*.html)
    - Executive summaries (*executive*.html)
    - Markdown reports (*.md)
    - PDF reports (*.pdf)
    """
    config = get_config()

    if not config.reports_dir.exists():
        console.print("[yellow]No reports directory found.[/yellow]")
        raise typer.Exit()

    # Determine file pattern based on type
    if report_type == "md":
        pattern = "*.md"
    elif report_type == "pdf":
        pattern = "*.pdf"
    elif report_type == "exec":
        pattern = "*executive*.html"
    elif report_type == "html":
        pattern = "report-*.html"  # Exclude executive summaries
    else:
        pattern = "*.*"  # All reports

    # Get report files
    report_files = sorted(
        config.reports_dir.glob(pattern), key=lambda p: p.stat().st_mtime
    )

    if not report_files:
        console.print(f"[yellow]No {report_type or 'reports'} found.[/yellow]")
        raise typer.Exit()

    if open_latest:
        import webbrowser

        latest_report = report_files[-1]
        console.print(f"[green]Opening report:[/green] {latest_report.name}")

        # Open based on file type
        if latest_report.suffix == ".md":
            console.print(f"\n[cyan]Markdown report path:[/cyan]\n{latest_report.absolute()}")
            console.print("\n[dim]Tip: Open with your preferred markdown viewer[/dim]")
        else:
            webbrowser.open(f"file://{latest_report.absolute()}")
    else:
        console.print(f"\n[bold cyan]Available Reports:[/bold cyan]\n")

        # Group by type
        html_reports = [r for r in report_files if r.suffix == ".html" and "executive" not in r.name]
        exec_reports = [r for r in report_files if "executive" in r.name]
        md_reports = [r for r in report_files if r.suffix == ".md"]
        pdf_reports = [r for r in report_files if r.suffix == ".pdf"]

        if html_reports:
            console.print("[bold]Technical Reports (HTML):[/bold]")
            for report in html_reports[-5:]:
                console.print(f"  • {report.name}")

        if exec_reports:
            console.print("\n[bold]Executive Summaries:[/bold]")
            for report in exec_reports[-5:]:
                console.print(f"  • {report.name}")

        if md_reports:
            console.print("\n[bold]Markdown Reports:[/bold]")
            for report in md_reports[-5:]:
                console.print(f"  • {report.name}")

        if pdf_reports:
            console.print("\n[bold]PDF Reports:[/bold]")
            for report in pdf_reports[-5:]:
                console.print(f"  • {report.name}")

        console.print(f"\n[dim]Location: {config.reports_dir}[/dim]")
        console.print("\n[cyan]Tip:[/cyan] Use [bold]--open[/bold] to view latest report")
        console.print("[cyan]Tip:[/cyan] Use [bold]--type[/bold] to filter by type (html, md, pdf, exec)")


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

