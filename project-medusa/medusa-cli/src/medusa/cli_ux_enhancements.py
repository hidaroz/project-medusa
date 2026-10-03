"""
UX Enhancements for MEDUSA CLI
Provides better user experience with real-time progress, cost estimates, and helpful guidance
"""

from typing import Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich.prompt import Confirm
import time

console = Console()


def estimate_operation_cost(operation_type: str, target: str) -> Dict[str, Any]:
    """
    Estimate cost before running operation

    Args:
        operation_type: Type of operation
        target: Target URL/IP

    Returns:
        Dictionary with cost estimates
    """
    # Cost estimates based on operation type
    estimates = {
        "recon_only": {
            "min_cost": 0.01,
            "max_cost": 0.05,
            "duration": "1-3 minutes",
            "agents": ["ReconAgent"],
            "models": {"haiku": 0.05}
        },
        "vuln_scan": {
            "min_cost": 0.10,
            "max_cost": 0.20,
            "duration": "3-7 minutes",
            "agents": ["ReconAgent", "VulnAnalysisAgent"],
            "models": {"haiku": 0.20}
        },
        "full_assessment": {
            "min_cost": 0.30,
            "max_cost": 1.00,
            "duration": "10-20 minutes",
            "agents": ["ReconAgent", "VulnAnalysisAgent", "PlanningAgent", "ExploitationAgent", "ReportingAgent"],
            "models": {"haiku": 0.10, "sonnet": 0.40}
        },
        "penetration_test": {
            "min_cost": 0.50,
            "max_cost": 1.50,
            "duration": "15-30 minutes",
            "agents": ["All 6 agents"],
            "models": {"haiku": 0.15, "sonnet": 0.60}
        }
    }

    estimate = estimates.get(operation_type, estimates["full_assessment"])

    # Adjust for target complexity (simple heuristic)
    if "/" in target and not target.startswith("http"):  # Network range
        estimate["max_cost"] *= 2
        estimate["duration"] = "15-45 minutes"

    return estimate


def show_cost_estimate_prompt(operation_type: str, target: str) -> bool:
    """
    Show cost estimate and ask for confirmation

    Returns:
        True if user confirms, False otherwise
    """
    estimate = estimate_operation_cost(operation_type, target)

    # Create cost estimate panel
    cost_text = Text()
    cost_text.append("⚠️  Cost Estimate\n", style="bold yellow")
    cost_text.append("━" * 60 + "\n", style="dim")
    cost_text.append(f"\nTarget: ", style="cyan")
    cost_text.append(f"{target}\n")
    cost_text.append(f"Operation: ", style="cyan")
    cost_text.append(f"{operation_type}\n")
    cost_text.append(f"Estimated Duration: ", style="cyan")
    cost_text.append(f"{estimate['duration']}\n")
    cost_text.append(f"Estimated Cost: ", style="cyan bold")
    cost_text.append(f"${estimate['min_cost']:.2f} - ${estimate['max_cost']:.2f}\n\n", style="bold green")

    # Model breakdown
    cost_text.append("Models Used:\n", style="bold")
    for model, cost in estimate.get("models", {}).items():
        model_name = "Claude 3.5 Haiku" if model == "haiku" else "Claude 3.5 Sonnet"
        cost_text.append(f"  • {model_name}: ~${cost:.2f}\n", style="yellow")

    cost_text.append(f"\nAgents: {', '.join(estimate.get('agents', []))}\n", style="dim")

    console.print(Panel(cost_text, border_style="yellow"))

    # Ask for confirmation
    return Confirm.ask("\n[bold cyan]Continue with this operation?[/bold cyan]", default=True)


def create_agent_status_table(agent_statuses: Dict[str, Dict[str, Any]]) -> Table:
    """
    Create real-time agent status table

    Args:
        agent_statuses: Dictionary of agent name -> status info

    Returns:
        Rich Table with agent statuses
    """
    table = Table(title="Agent Status", show_header=True, header_style="bold cyan")
    table.add_column("Agent", style="cyan", width=18)
    table.add_column("Status", width=15)
    table.add_column("Progress", width=20)
    table.add_column("Cost", justify="right", width=10)

    status_symbols = {
        "idle": "○",
        "pending": "○",
        "in_progress": "⟳",
        "completed": "✓",
        "failed": "✗"
    }

    status_colors = {
        "idle": "dim",
        "pending": "yellow",
        "in_progress": "cyan bold",
        "completed": "green",
        "failed": "red"
    }

    for agent_name, status_info in agent_statuses.items():
        status = status_info.get("status", "idle")
        symbol = status_symbols.get(status, "○")
        color = status_colors.get(status, "white")

        # Progress text
        if status == "completed":
            duration = status_info.get("duration", 0)
            progress = f"Completed ({duration:.1f}s)"
        elif status == "in_progress":
            progress = status_info.get("current_task", "Working...")
        elif status == "pending":
            progress = "Waiting..."
        elif status == "failed":
            progress = "Failed"
        else:
            progress = "Idle"

        # Cost
        cost = status_info.get("cost", 0.0)
        cost_str = f"${cost:.3f}" if cost > 0 else "-"

        table.add_row(
            f"{symbol} {agent_name}",
            Text(status.replace("_", " ").title(), style=color),
            progress,
            cost_str
        )

    return table


def show_operation_progress_live(
    agent_statuses: Dict[str, Dict[str, Any]],
    total_tokens: int = 0,
    total_cost: float = 0.0
) -> Panel:
    """
    Create live-updating progress panel

    Args:
        agent_statuses: Current agent statuses
        total_tokens: Total tokens used so far
        total_cost: Total cost so far

    Returns:
        Rich Panel with current progress
    """
    table = create_agent_status_table(agent_statuses)

    # Footer with totals
    footer = Text()
    footer.append(f"\nTotal Tokens: ", style="dim")
    footer.append(f"{total_tokens:,}", style="cyan")
    footer.append(f"  |  Estimated Cost: ", style="dim")
    footer.append(f"${total_cost:.3f}", style="bold green")

    return Panel(table, title="[bold cyan]Multi-Agent Operation Progress[/bold cyan]",
                 subtitle=footer, border_style="cyan")


def show_post_operation_summary(result: Dict[str, Any]):
    """
    Show comprehensive post-operation summary with next steps

    Args:
        result: Operation result dictionary
    """
    operation_id = result.get("operation_id", "unknown")
    target = result.get("target", "unknown")
    findings = result.get("findings", [])
    cost = result.get("cost_summary", {}).get("total_cost_usd", 0.0)

    # Count findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = finding.get("severity", "low").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Success message
    console.print("\n")
    console.print("=" * 70, style="green")
    console.print(f"✅ Operation Complete - {operation_id}", style="bold green")
    console.print("=" * 70, style="green")
    console.print()

    # Results summary
    summary_table = Table(show_header=False, box=None, padding=(0, 2))
    summary_table.add_column(style="cyan bold", width=20)
    summary_table.add_column(style="white")

    summary_table.add_row("Target:", target)
    summary_table.add_row("Operation ID:", operation_id)
    summary_table.add_row("Total Findings:", str(len(findings)))

    # Severity breakdown
    if severity_counts["critical"] > 0:
        summary_table.add_row("  Critical:", f"[red bold]{severity_counts['critical']}[/red bold]")
    if severity_counts["high"] > 0:
        summary_table.add_row("  High:", f"[red]{severity_counts['high']}[/red]")
    if severity_counts["medium"] > 0:
        summary_table.add_row("  Medium:", f"[yellow]{severity_counts['medium']}[/yellow]")
    if severity_counts["low"] > 0:
        summary_table.add_row("  Low:", f"[blue]{severity_counts['low']}[/blue]")

    summary_table.add_row("Total Cost:", f"[bold green]${cost:.4f}[/bold green]")

    console.print(Panel(summary_table, title="[bold]📊 Results Summary[/bold]",
                       border_style="green"))

    # Next steps
    console.print()
    console.print("[bold cyan]🎯 Next Steps[/bold cyan]")
    console.print()

    steps = [
        ("View detailed findings", f"medusa agent status --operation {operation_id} --verbose"),
        ("Generate executive report", "medusa agent report --type executive"),
        ("Get remediation plan", "medusa agent report --type remediation"),
        ("View all results", f"cat ~/.medusa/logs/multi-agent-{operation_id}.json")
    ]

    for i, (description, command) in enumerate(steps, 1):
        console.print(f"[bold]{i}.[/bold] {description}:")
        console.print(f"   [cyan]{command}[/cyan]")
        console.print()

    # Quick actions
    console.print("[bold yellow]📝 Quick Actions:[/bold yellow]")
    console.print("  • Generate all reports: [cyan]medusa agent report --type all[/cyan]")
    console.print(f"  • Share findings: [cyan]medusa agent report --output report-{operation_id}.md[/cyan]")
    console.print()


def show_error_with_solution(error: Exception, context: str = ""):
    """
    Show error message with actionable solutions

    Args:
        error: The exception that occurred
        context: Context about what was being attempted
    """
    error_msg = str(error)

    # Common errors and solutions
    solutions = {
        "not configured": {
            "title": "Configuration Not Found",
            "description": "MEDUSA needs to be set up before you can run operations.",
            "quick_fix": "medusa setup",
            "steps": [
                "✓ Configure your LLM provider",
                "✓ Set up target environment",
                "✓ Initialize databases"
            ],
            "time": "Takes ~2 minutes"
        },
        "AccessDeniedException": {
            "title": "AWS Access Denied",
            "description": "Your AWS credentials don't have permission to use Bedrock.",
            "quick_fix": "Check IAM permissions",
            "steps": [
                "1. Verify IAM user has AmazonBedrockFullAccess policy",
                "2. Wait 5-10 minutes for IAM changes to propagate",
                "3. Check credentials: echo $AWS_ACCESS_KEY_ID"
            ],
            "docs": "See: docs/multi-agent/AWS_BEDROCK_SETUP.md"
        },
        "NoCredentialsError": {
            "title": "AWS Credentials Not Found",
            "description": "AWS credentials are not configured.",
            "quick_fix": "aws configure",
            "steps": [
                "1. Set environment variables:",
                "   export AWS_ACCESS_KEY_ID='your-key'",
                "   export AWS_SECRET_ACCESS_KEY='your-secret'",
                "2. Or run: aws configure"
            ],
            "docs": "See: docs/multi-agent/AWS_BEDROCK_SETUP.md"
        },
        "ValidationException": {
            "title": "Invalid Model or Request",
            "description": "The Bedrock model may not be available in your region.",
            "quick_fix": "Check model access",
            "steps": [
                "1. Go to AWS Bedrock console",
                "2. Click 'Model access'",
                "3. Enable Claude 3.5 Sonnet and Haiku",
                "4. Verify region is supported (us-west-2, us-east-1, eu-west-3)"
            ],
            "docs": "See: docs/multi-agent/AWS_BEDROCK_SETUP.md#step-1-enable-aws-bedrock-access"
        }
    }

    # Find matching solution
    solution = None
    for key, sol in solutions.items():
        if key.lower() in error_msg.lower():
            solution = sol
            break

    if solution:
        # Show formatted error with solution
        error_text = Text()
        error_text.append(f"❌ {solution['title']}\n\n", style="bold red")
        error_text.append(f"{solution['description']}\n\n", style="white")

        if context:
            error_text.append(f"While: {context}\n\n", style="dim")

        error_text.append("Quick Fix:\n", style="bold yellow")
        error_text.append(f"  {solution['quick_fix']}\n\n", style="cyan")

        if "steps" in solution:
            error_text.append("Steps:\n", style="bold")
            for step in solution["steps"]:
                error_text.append(f"  {step}\n", style="white")
            error_text.append("\n")

        if "time" in solution:
            error_text.append(f"{solution['time']}\n\n", style="dim")

        if "docs" in solution:
            error_text.append(f"📚 {solution['docs']}\n", style="blue")

        console.print(Panel(error_text, border_style="red", title="Error"))
    else:
        # Generic error display
        console.print(f"\n[bold red]❌ Error:[/bold red] {error_msg}")
        if context:
            console.print(f"[dim]While: {context}[/dim]")
        console.print("\n[yellow]💡 Tip:[/yellow] Check the logs for more details")
        console.print("[yellow]📚 Documentation:[/yellow] docs/multi-agent/USER_GUIDE.md")


def show_welcome_message():
    """Show welcome message for first-time users"""
    welcome = Text()
    welcome.append("🔴 MEDUSA Multi-Agent Security System\n\n", style="bold red")
    welcome.append("Welcome! MEDUSA uses AI-powered agents to perform comprehensive security assessments.\n\n", style="white")
    welcome.append("Quick Start:\n", style="bold cyan")
    welcome.append("  1. Run setup: ", style="white")
    welcome.append("medusa setup\n", style="cyan")
    welcome.append("  2. Verify LLM: ", style="white")
    welcome.append("medusa llm verify\n", style="cyan")
    welcome.append("  3. Start scan: ", style="white")
    welcome.append("medusa agent run <target>\n\n", style="cyan")
    welcome.append("Need help? ", style="dim")
    welcome.append("medusa agent run --help\n", style="cyan dim")

    console.print(Panel(welcome, border_style="cyan"))


def show_interactive_mode_prompt():
    """Interactive mode for beginners"""
    console.print("\n[bold cyan]🤖 Multi-Agent Security Assessment[/bold cyan]\n")

    # Get target
    from rich.prompt import Prompt
    target = Prompt.ask("[bold]What target would you like to assess?[/bold]")

    # Get assessment type
    console.print("\n[bold]What type of assessment?[/bold]")
    console.print("  [cyan]1.[/cyan] Quick scan (recon only) - Fast, ~$0.05")
    console.print("  [cyan]2.[/cyan] Vulnerability assessment - Medium, ~$0.15")
    console.print("  [cyan]3.[/cyan] Full security test - Comprehensive, ~$0.50")

    choice = Prompt.ask("Choose", choices=["1", "2", "3"], default="2")

    operation_types = {
        "1": "recon_only",
        "2": "vuln_scan",
        "3": "full_assessment"
    }
    operation_type = operation_types[choice]

    # Auto-approve
    auto_approve = Confirm.ask("\n[bold]Auto-approve low-risk actions?[/bold]", default=True)

    return target, operation_type, auto_approve


# Cost budget tracking
_daily_budget = None
_daily_spent = 0.0


def check_budget(estimated_cost: float) -> bool:
    """
    Check if operation fits within budget

    Args:
        estimated_cost: Estimated cost of operation

    Returns:
        True if within budget, False otherwise
    """
    global _daily_budget, _daily_spent

    if _daily_budget is None:
        return True  # No budget set

    if _daily_spent + estimated_cost > _daily_budget:
        console.print(Panel(
            f"[red]Budget exceeded![/red]\n\n"
            f"Daily budget: ${_daily_budget:.2f}\n"
            f"Already spent: ${_daily_spent:.2f}\n"
            f"This operation: ~${estimated_cost:.2f}\n"
            f"Would total: ${_daily_spent + estimated_cost:.2f}\n\n"
            f"To proceed anyway, set a higher budget with:\n"
            f"[cyan]medusa config set budget.daily <amount>[/cyan]",
            title="Budget Limit Reached",
            border_style="red"
        ))
        return False

    # Show budget remaining
    remaining = _daily_budget - _daily_spent - estimated_cost
    console.print(f"[dim]Budget: ${_daily_spent:.2f} / ${_daily_budget:.2f} "
                 f"(${remaining:.2f} remaining after this operation)[/dim]\n")

    return True


def record_operation_cost(actual_cost: float):
    """Record actual cost of completed operation"""
    global _daily_spent
    _daily_spent += actual_cost
