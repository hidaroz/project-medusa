"""
Multi-Agent CLI Commands
Commands for interacting with the multi-agent system
"""

import asyncio
import json
from pathlib import Path
from typing import Optional
from datetime import datetime

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from medusa.config import get_config
from medusa.core.llm import LLMConfig, create_llm_client
from medusa.context.fusion_engine import ContextFusionEngine
from medusa.world_model.client import WorldModelClient
from medusa.agents import (
    OrchestratorAgent,
    ReconnaissanceAgent,
    VulnerabilityAnalysisAgent,
    PlanningAgent,
    ExploitationAgent,
    ReportingAgent,
    MessageBus,
    AgentTask,
    AgentStatus,
)
from medusa.agents.data_models import TaskPriority

# Import UX enhancements
try:
    from medusa.cli_ux_enhancements import (
        show_cost_estimate_prompt,
        show_post_operation_summary,
        show_error_with_solution,
        check_budget,
        record_operation_cost
    )
    UX_ENHANCEMENTS_AVAILABLE = True
except ImportError:
    UX_ENHANCEMENTS_AVAILABLE = False

# Create CLI app
agent_app = typer.Typer(
    name="agent",
    help="🤖 Multi-agent system commands",
    rich_markup_mode="rich",
)

console = Console()


@agent_app.command("run")
def multi_agent_run(
    target: str = typer.Argument(..., help="Target URL or IP address"),
    operation_type: str = typer.Option(
        "full_assessment",
        "--type",
        "-t",
        help="Operation type: full_assessment, recon_only, vuln_scan, penetration_test",
    ),
    objectives: Optional[str] = typer.Option(
        None,
        "--objectives",
        "-o",
        help="Comma-separated objectives (e.g., 'find_credentials,escalate_privileges')",
    ),
    auto_approve: bool = typer.Option(
        False, "--auto-approve", "-y", help="Auto-approve all actions (use with caution)"
    ),
    max_duration: int = typer.Option(
        3600, "--max-duration", "-d", help="Maximum operation duration in seconds"
    ),
    save_results: bool = typer.Option(
        True, "--save", "-s", help="Save operation results to file"
    ),
):
    """
    🚀 Run a multi-agent security operation.

    The orchestrator will coordinate specialist agents to perform:
    - Reconnaissance (network/service discovery)
    - Vulnerability Analysis (CVE correlation, risk assessment)
    - Strategic Planning (attack chain design)
    - Exploitation (simulated exploit execution)
    - Reporting (comprehensive documentation)

    Examples:
        medusa agent run http://localhost:3001
        medusa agent run 192.168.1.0/24 --type recon_only
        medusa agent run example.com --objectives "find_admin,extract_data"
        medusa agent run 10.0.0.1 --auto-approve
    """
    config = get_config()

    if not config.exists():
        if UX_ENHANCEMENTS_AVAILABLE:
            show_error_with_solution(
                Exception("MEDUSA is not configured"),
                "attempting to run multi-agent operation"
            )
        else:
            console.print(
                "[red]Error: MEDUSA is not configured.[/red]\n"
                "Run [bold]medusa setup[/bold] first."
            )
        raise typer.Exit(1)

    # Parse objectives
    objectives_list = []
    if objectives:
        objectives_list = [obj.strip() for obj in objectives.split(",")]

    # Show cost estimate and get confirmation (unless auto-approved)
    if UX_ENHANCEMENTS_AVAILABLE and not auto_approve:
        if not show_cost_estimate_prompt(operation_type, target):
            console.print("\n[yellow]Operation cancelled by user[/yellow]")
            raise typer.Exit(0)

    # Run the multi-agent operation
    console.print(f"\n[bold cyan]🤖 Multi-Agent Operation[/bold cyan]")
    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Type:[/bold] {operation_type}")
    if objectives_list:
        console.print(f"[bold]Objectives:[/bold] {', '.join(objectives_list)}")
    console.print()

    try:
        result = asyncio.run(
            _run_multi_agent_operation(
                target=target,
                operation_type=operation_type,
                objectives=objectives_list,
                auto_approve=auto_approve,
                max_duration=max_duration,
                config=config,
            )
        )

        # Display results with enhanced UX
        if UX_ENHANCEMENTS_AVAILABLE:
            show_post_operation_summary(result)
            # Record cost for budget tracking
            cost = result.get("cost_summary", {}).get("total_cost_usd", 0.0)
            record_operation_cost(cost)
        else:
            _display_operation_results(result)

        # Save results if requested
        if save_results:
            operation_id = result.get("operation_id", "unknown")
            output_path = config.logs_dir / f"multi-agent-{operation_id}.json"
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w") as f:
                json.dump(result, f, indent=2, default=str)

            if not UX_ENHANCEMENTS_AVAILABLE:  # Only show if not already shown in summary
                console.print(f"\n[green]✅ Results saved to:[/green] {output_path}")

    except KeyboardInterrupt:
        console.print("\n[yellow]⏸️  Operation interrupted by user[/yellow]")
        raise typer.Exit(0)
    except Exception as e:
        if UX_ENHANCEMENTS_AVAILABLE:
            show_error_with_solution(e, f"running {operation_type} on {target}")
        else:
            console.print(f"\n[red]❌ Operation failed:[/red] {str(e)}")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        raise typer.Exit(1)


@agent_app.command("interactive")
def interactive_mode():
    """
    💬 Interactive mode for beginners.

    Guides you through the assessment process step-by-step with prompts
    and recommendations. Perfect for first-time users!

    Example:
        medusa agent interactive
    """
    config = get_config()

    if not config.exists():
        console.print(
            "[red]Error: MEDUSA is not configured.[/red]\n"
            "Run [bold]medusa setup[/bold] first."
        )
        raise typer.Exit(1)

    # Use interactive prompts if available
    if UX_ENHANCEMENTS_AVAILABLE:
        from medusa.cli_ux_enhancements import show_interactive_mode_prompt
        target, operation_type, auto_approve = show_interactive_mode_prompt()
    else:
        # Fallback to basic prompts
        from rich.prompt import Prompt, Confirm
        console.print("\n[bold cyan]🤖 Multi-Agent Security Assessment[/bold cyan]\n")
        target = Prompt.ask("[bold]What target would you like to assess?[/bold]")
        operation_type = Prompt.ask(
            "[bold]Assessment type[/bold]",
            choices=["recon_only", "vuln_scan", "full_assessment"],
            default="vuln_scan"
        )
        auto_approve = Confirm.ask("\n[bold]Auto-approve low-risk actions?[/bold]", default=True)

    # Run the operation
    console.print(f"\n[cyan]Starting {operation_type} on {target}...[/cyan]\n")

    try:
        result = asyncio.run(
            _run_multi_agent_operation(
                target=target,
                operation_type=operation_type,
                objectives=[],
                auto_approve=auto_approve,
                max_duration=3600,
                config=config,
            )
        )

        # Display results
        if UX_ENHANCEMENTS_AVAILABLE:
            show_post_operation_summary(result)
        else:
            _display_operation_results(result)

        # Save results
        operation_id = result.get("operation_id", "unknown")
        output_path = config.logs_dir / f"multi-agent-{operation_id}.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(result, f, indent=2, default=str)

    except KeyboardInterrupt:
        console.print("\n[yellow]⏸️  Operation interrupted by user[/yellow]")
        raise typer.Exit(0)
    except Exception as e:
        console.print(f"\n[red]❌ Operation failed:[/red] {str(e)}")
        raise typer.Exit(1)


@agent_app.command("status")
def agent_status(
    agent_name: Optional[str] = typer.Option(
        None, "--agent", "-a", help="Show status for specific agent"
    ),
    operation_id: Optional[str] = typer.Option(
        None, "--operation", "-o", help="Show status for specific operation"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show detailed metrics"
    ),
):
    """
    📊 View agent status and metrics.

    Shows:
    - Agent health and availability
    - Task completion statistics
    - Cost tracking and token usage
    - Recent operations

    Examples:
        medusa agent status
        medusa agent status --agent ReconAgent
        medusa agent status --operation OP-20251113-001 --verbose
    """
    config = get_config()

    if not config.exists():
        console.print(
            "[red]Error: MEDUSA is not configured.[/red]\n"
            "Run [bold]medusa setup[/bold] first."
        )
        raise typer.Exit(1)

    # Load recent operations
    logs_dir = config.logs_dir
    if not logs_dir.exists():
        console.print("[yellow]No operations found.[/yellow]")
        raise typer.Exit()

    # Find multi-agent operation logs
    operation_logs = sorted(
        logs_dir.glob("multi-agent-*.json"), key=lambda p: p.stat().st_mtime
    )

    if not operation_logs:
        console.print("[yellow]No multi-agent operations found.[/yellow]")
        console.print(
            "\n[dim]Run [bold]medusa agent run <target>[/bold] to start an operation.[/dim]"
        )
        raise typer.Exit()

    # Filter by operation_id if provided
    if operation_id:
        operation_logs = [
            log for log in operation_logs if operation_id in log.name
        ]
        if not operation_logs:
            console.print(f"[yellow]Operation {operation_id} not found.[/yellow]")
            raise typer.Exit()

    # Load latest or specified operation
    latest_log = operation_logs[-1]

    try:
        with open(latest_log) as f:
            operation_data = json.load(f)
    except Exception as e:
        console.print(f"[red]Error reading operation log:[/red] {e}")
        raise typer.Exit(1)

    # Display status
    _display_agent_status(operation_data, agent_name, verbose)


@agent_app.command("report")
def agent_report(
    operation_id: Optional[str] = typer.Option(
        None, "--operation", "-o", help="Operation ID (defaults to latest)"
    ),
    report_type: str = typer.Option(
        "executive",
        "--type",
        "-t",
        help="Report type: executive, technical, remediation, compliance, all",
    ),
    format_type: str = typer.Option(
        "markdown", "--format", "-f", help="Output format: markdown, json, html"
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", help="Output file path"
    ),
):
    """
    📝 Generate reports from multi-agent operations.

    Uses the ReportingAgent to create professional reports:
    - Executive Summary: Business-focused overview
    - Technical Report: Detailed security documentation
    - Remediation Plan: Step-by-step fix guidance
    - Compliance Report: Framework mapping (PCI-DSS, HIPAA, etc.)

    Examples:
        medusa agent report
        medusa agent report --type technical --format html
        medusa agent report --operation OP-001 --type all
        medusa agent report --output my-report.md
    """
    config = get_config()

    if not config.exists():
        console.print(
            "[red]Error: MEDUSA is not configured.[/red]\n"
            "Run [bold]medusa setup[/bold] first."
        )
        raise typer.Exit(1)

    # Load operation data
    logs_dir = config.logs_dir
    operation_logs = sorted(
        logs_dir.glob("multi-agent-*.json"), key=lambda p: p.stat().st_mtime
    )

    if not operation_logs:
        console.print("[yellow]No multi-agent operations found.[/yellow]")
        raise typer.Exit()

    # Find requested operation
    if operation_id:
        operation_logs = [
            log for log in operation_logs if operation_id in log.name
        ]
        if not operation_logs:
            console.print(f"[yellow]Operation {operation_id} not found.[/yellow]")
            raise typer.Exit()

    latest_log = operation_logs[-1]

    try:
        with open(latest_log) as f:
            operation_data = json.load(f)
    except Exception as e:
        console.print(f"[red]Error reading operation log:[/red] {e}")
        raise typer.Exit(1)

    console.print(f"\n[bold cyan]📝 Generating Report[/bold cyan]")
    console.print(f"[bold]Operation:[/bold] {operation_data.get('operation_id')}")
    console.print(f"[bold]Type:[/bold] {report_type}")
    console.print(f"[bold]Format:[/bold] {format_type}\n")

    try:
        report = asyncio.run(
            _generate_agent_report(
                operation_data=operation_data,
                report_type=report_type,
                format_type=format_type,
                config=config,
            )
        )

        # Display or save report
        if output_file:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w") as f:
                if format_type == "json":
                    json.dump(report, f, indent=2, default=str)
                else:
                    f.write(report)

            console.print(f"[green]✅ Report saved to:[/green] {output_path}")
        else:
            # Display report
            console.print(Panel(report, title="Generated Report", border_style="cyan"))

    except Exception as e:
        console.print(f"[red]❌ Report generation failed:[/red] {str(e)}")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        raise typer.Exit(1)


async def _run_multi_agent_operation(
    target: str,
    operation_type: str,
    objectives: list,
    auto_approve: bool,
    max_duration: int,
    config,
) -> dict:
    """Run multi-agent operation"""

    operation_id = f"OP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Initialize components
        task = progress.add_task("Initializing multi-agent system...", total=None)

        # Load LLM config
        config_data = config.load()
        llm_cfg_dict = config_data.get("llm", {})
        llm_cfg = LLMConfig(**llm_cfg_dict)

        # Create LLM client
        llm_client = create_llm_client(llm_cfg)

        # Initialize world model
        world_model = WorldModelClient()
        await world_model.connect()

        # Initialize context fusion engine
        context_engine = ContextFusionEngine(world_model=world_model)

        # Initialize message bus
        message_bus = MessageBus()

        # Create specialist agents
        progress.update(task, description="Creating specialist agents...")

        recon_agent = ReconnaissanceAgent(
            llm_client=llm_client,
            context_engine=context_engine,
            message_bus=message_bus,
        )

        vuln_agent = VulnerabilityAnalysisAgent(
            llm_client=llm_client,
            context_engine=context_engine,
            message_bus=message_bus,
        )

        planning_agent = PlanningAgent(
            llm_client=llm_client,
            context_engine=context_engine,
            message_bus=message_bus,
        )

        exploit_agent = ExploitationAgent(
            require_approval=not auto_approve,
            llm_client=llm_client,
            context_engine=context_engine,
            message_bus=message_bus,
        )

        reporting_agent = ReportingAgent(
            llm_client=llm_client,
            context_engine=context_engine,
            message_bus=message_bus,
        )

        # Create orchestrator
        specialist_agents = {
            "ReconAgent": recon_agent,
            "VulnAnalysisAgent": vuln_agent,
            "PlanningAgent": planning_agent,
            "ExploitationAgent": exploit_agent,
            "ReportingAgent": reporting_agent,
        }

        orchestrator = OrchestratorAgent(
            specialist_agents=specialist_agents,
            llm_client=llm_client,
            context_engine=context_engine,
            message_bus=message_bus,
        )

        # Create operation task
        progress.update(task, description="Starting operation...")

        operation_task = AgentTask(
            task_id=operation_id,
            task_type="run_operation",
            description=f"{operation_type} on {target}",
            parameters={
                "target": target,
                "operation_type": operation_type,
                "objectives": objectives,
                "max_duration": max_duration,
            },
            priority=TaskPriority.HIGH,
        )

        # Execute operation
        progress.update(task, description=f"Running {operation_type}...")

        try:
            result = await orchestrator.execute_task(operation_task)

            # Collect metrics
            progress.update(task, description="Collecting metrics...")

            operation_result = {
                "operation_id": operation_id,
                "target": target,
                "operation_type": operation_type,
                "objectives": objectives,
                "status": result.status.value,
                "started_at": datetime.now().isoformat(),
                "findings": result.findings,
                "recommendations": result.recommendations,
                "metadata": result.metadata,
                "agent_metrics": {
                    "orchestrator": orchestrator.metrics.__dict__,
                    "recon": recon_agent.metrics.__dict__,
                    "vuln_analysis": vuln_agent.metrics.__dict__,
                    "planning": planning_agent.metrics.__dict__,
                    "exploitation": exploit_agent.metrics.__dict__,
                    "reporting": reporting_agent.metrics.__dict__,
                },
                "cost_summary": {
                    "total_tokens": result.tokens_used,
                    "total_cost_usd": result.cost_usd,
                },
            }

            progress.update(task, description="✅ Operation complete!", completed=True)

            return operation_result

        finally:
            # Cleanup
            await llm_client.close()
            await world_model.close()


def _display_operation_results(result: dict):
    """Display operation results in a formatted way"""

    console.print("\n[bold green]✅ Operation Complete[/bold green]\n")

    # Summary table
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    summary_table.add_column(style="cyan", width=20)
    summary_table.add_column(style="white")

    summary_table.add_row("Operation ID:", result.get("operation_id"))
    summary_table.add_row("Target:", result.get("target"))
    summary_table.add_row("Status:", result.get("status"))
    summary_table.add_row("Total Findings:", str(len(result.get("findings", []))))
    summary_table.add_row(
        "Recommendations:", str(len(result.get("recommendations", [])))
    )

    cost = result.get("cost_summary", {})
    summary_table.add_row("Total Tokens:", f"{cost.get('total_tokens', 0):,}")
    summary_table.add_row("Total Cost:", f"${cost.get('total_cost_usd', 0):.4f}")

    console.print(summary_table)

    # Agent metrics
    console.print("\n[bold cyan]Agent Performance:[/bold cyan]\n")

    metrics_table = Table(show_header=True, header_style="bold cyan")
    metrics_table.add_column("Agent", style="cyan")
    metrics_table.add_column("Tasks", justify="right")
    metrics_table.add_column("Completed", justify="right")
    metrics_table.add_column("Failed", justify="right")
    metrics_table.add_column("Avg Time (s)", justify="right")

    agent_metrics = result.get("agent_metrics", {})
    for agent_name, metrics in agent_metrics.items():
        tasks_completed = metrics.get("tasks_completed", 0)
        tasks_failed = metrics.get("tasks_failed", 0)
        total_tasks = tasks_completed + tasks_failed
        avg_time = metrics.get("average_task_time", 0)

        metrics_table.add_row(
            agent_name,
            str(total_tasks),
            str(tasks_completed),
            str(tasks_failed),
            f"{avg_time:.2f}",
        )

    console.print(metrics_table)


def _display_agent_status(operation_data: dict, agent_name: Optional[str], verbose: bool):
    """Display agent status information"""

    console.print(f"\n[bold cyan]🤖 Agent Status[/bold cyan]\n")

    # Operation summary
    console.print(f"[bold]Operation ID:[/bold] {operation_data.get('operation_id')}")
    console.print(f"[bold]Target:[/bold] {operation_data.get('target')}")
    console.print(f"[bold]Status:[/bold] {operation_data.get('status')}\n")

    agent_metrics = operation_data.get("agent_metrics", {})

    # Filter by agent if specified
    if agent_name:
        if agent_name in agent_metrics:
            agent_metrics = {agent_name: agent_metrics[agent_name]}
        else:
            console.print(f"[yellow]Agent '{agent_name}' not found.[/yellow]")
            return

    # Display metrics
    for agent, metrics in agent_metrics.items():
        table = Table(title=f"{agent}", show_header=False, box=None, padding=(0, 2))
        table.add_column(style="cyan", width=20)
        table.add_column(style="white")

        table.add_row("Tasks Completed:", str(metrics.get("tasks_completed", 0)))
        table.add_row("Tasks Failed:", str(metrics.get("tasks_failed", 0)))
        table.add_row("Average Time:", f"{metrics.get('average_task_time', 0):.2f}s")
        table.add_row("Total Cost:", f"${metrics.get('total_cost', 0):.4f}")

        if verbose:
            table.add_row("Total Tokens:", f"{metrics.get('total_tokens_used', 0):,}")
            table.add_row(
                "Total Execution Time:", f"{metrics.get('total_execution_time', 0):.2f}s"
            )

        console.print(table)
        console.print()


async def _generate_agent_report(
    operation_data: dict, report_type: str, format_type: str, config
) -> str:
    """Generate report using ReportingAgent"""

    # Load LLM config
    config_data = config.load()
    llm_cfg_dict = config_data.get("llm", {})
    llm_cfg = LLMConfig(**llm_cfg_dict)

    # Create LLM client
    llm_client = create_llm_client(llm_cfg)

    try:
        # Create reporting agent
        reporting_agent = ReportingAgent(llm_client=llm_client)

        # Create report task
        task = AgentTask(
            task_id=f"REPORT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            task_type=f"generate_{report_type}_report"
            if report_type != "all"
            else "generate_executive_summary",
            description=f"Generate {report_type} report",
            parameters={
                "operation_data": operation_data,
                "findings": operation_data.get("findings", []),
                "target": operation_data.get("target"),
                "operation_name": f"Security Assessment - {operation_data.get('operation_id')}",
            },
        )

        # Generate report
        result = await reporting_agent.execute_task(task)

        if result.status != AgentStatus.COMPLETED:
            raise Exception(f"Report generation failed: {result.error}")

        # Format report based on format_type
        report_content = result.findings[0] if result.findings else {}

        if format_type == "json":
            return report_content
        elif format_type == "markdown":
            return _format_report_as_markdown(report_content, report_type)
        elif format_type == "html":
            return _format_report_as_html(report_content, report_type)
        else:
            return json.dumps(report_content, indent=2, default=str)

    finally:
        await llm_client.close()


def _format_report_as_markdown(report_data: dict, report_type: str) -> str:
    """Format report as markdown"""

    if report_type == "executive":
        summary = report_data.get("executive_summary", {})
        md = f"# {summary.get('title', 'Executive Summary')}\n\n"
        md += f"**Date:** {summary.get('date', 'N/A')}\n"
        md += f"**Target:** {summary.get('target', 'N/A')}\n\n"
        md += f"## Overview\n\n{summary.get('executive_overview', 'N/A')}\n\n"

        risk = summary.get("risk_rating", {})
        md += f"## Risk Assessment\n\n"
        md += f"**Overall Risk:** {risk.get('overall_risk', 'N/A').upper()}\n"
        md += f"**Risk Score:** {risk.get('risk_score', 0)}/100\n\n"

        md += f"## Key Findings\n\n"
        for finding in summary.get("key_findings_summary", [])[:5]:
            md += f"- **{finding.get('finding', 'N/A')}**\n"
            md += f"  - Impact: {finding.get('business_impact', 'N/A')}\n"
            md += f"  - Urgency: {finding.get('urgency', 'N/A')}\n\n"

        return md

    # Default JSON formatting
    return f"# {report_type.title()} Report\n\n```json\n{json.dumps(report_data, indent=2, default=str)}\n```"


def _format_report_as_html(report_data: dict, report_type: str) -> str:
    """Format report as HTML"""
    # Simple HTML template
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{report_type.title()} Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #2c3e50; }}
            .section {{ margin: 20px 0; }}
            pre {{ background: #f4f4f4; padding: 15px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <h1>{report_type.title()} Report</h1>
        <div class="section">
            <pre>{json.dumps(report_data, indent=2, default=str)}</pre>
        </div>
    </body>
    </html>
    """
    return html
