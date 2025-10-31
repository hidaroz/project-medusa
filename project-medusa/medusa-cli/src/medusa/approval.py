"""
Approval gate system for MEDUSA
Manages risk-based approval prompts for potentially dangerous operations
"""

from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from medusa.config import get_config

console = Console()


class RiskLevel(Enum):
    """Risk levels for operations"""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Action:
    """Represents an action requiring approval"""

    command: str
    technique_id: str
    technique_name: str
    risk_level: RiskLevel
    impact_description: str
    target: Optional[str] = None
    reversible: bool = True
    data_at_risk: Optional[str] = None


class ApprovalGate:
    """Manages approval gates for risky operations"""

    def __init__(self):
        self.config = get_config()
        self.approved_all = False  # User chose to approve all remaining
        self.aborted = False  # User chose to abort

    def should_auto_approve(self, risk_level: RiskLevel) -> bool:
        """Check if action should be auto-approved based on config"""
        if self.approved_all:
            return True

        risk_settings = self.config.get("risk_tolerance", {})

        if risk_level == RiskLevel.LOW:
            return risk_settings.get("auto_approve_low", True)
        elif risk_level == RiskLevel.MEDIUM:
            return risk_settings.get("auto_approve_medium", False)
        elif risk_level == RiskLevel.HIGH:
            return risk_settings.get("auto_approve_high", False)
        else:  # CRITICAL
            return False  # Never auto-approve critical actions

    def request_approval(self, action: Action) -> bool:
        """
        Request user approval for an action.
        Returns True if approved, False if denied/aborted.
        """
        if self.aborted:
            return False

        # Check auto-approval
        if self.should_auto_approve(action.risk_level):
            console.print(
                f"[dim]✓ Auto-approved ({action.risk_level.value} risk): {action.technique_name}[/dim]"
            )
            return True

        # Display approval prompt
        self._display_approval_prompt(action)

        # Get user choice
        choice = self._get_user_choice(action)

        if choice == "approve":
            console.print("[green]✓ Approved[/green]\n")
            return True
        elif choice == "approve_all":
            console.print("[green]✓ Approved (and all remaining)[/green]\n")
            self.approved_all = True
            return True
        elif choice == "deny":
            console.print("[yellow]⊘ Denied[/yellow]\n")
            return False
        elif choice == "skip":
            console.print("[yellow]⊘ Skipped[/yellow]\n")
            return False
        elif choice == "abort":
            console.print("[red]✗ Operation aborted by user[/red]\n")
            self.aborted = True
            return False
        else:
            # Default to deny
            return False

    def _display_approval_prompt(self, action: Action):
        """Display the approval prompt with action details"""
        # Determine border color based on risk
        if action.risk_level == RiskLevel.CRITICAL:
            border_color = "red"
            icon = "🔴"
            risk_color = "bold red"
        elif action.risk_level == RiskLevel.HIGH:
            border_color = "red"
            icon = "🟠"
            risk_color = "red"
        elif action.risk_level == RiskLevel.MEDIUM:
            border_color = "yellow"
            icon = "🟡"
            risk_color = "yellow"
        else:
            border_color = "blue"
            icon = "🔵"
            risk_color = "blue"

        # Build the prompt content
        content = f"""[{risk_color}]{action.risk_level.value} RISK ACTION[/{risk_color}]

[bold]Technique:[/bold] {action.technique_id} ({action.technique_name})
[bold]Command:[/bold] {action.command}
[bold]Impact:[/bold] {action.impact_description}
"""

        if action.target:
            content += f"[bold]Target:[/bold] {action.target}\n"

        if not action.reversible:
            content += "[bold red]⚠️  WARNING: This action is NOT reversible![/bold red]\n"

        if action.data_at_risk:
            content += f"[bold]Data at Risk:[/bold] {action.data_at_risk}\n"

        panel = Panel(content, title=f"{icon} Approval Required", border_style=border_color)
        console.print(panel)

    def _get_user_choice(self, action: Action) -> str:
        """Get user's approval choice"""
        choices = ["y", "n", "s", "a", "all"]
        prompt_text = (
            "\n[bold]Approve?[/bold] "
            "[green]y[/green]es / "
            "[red]n[/red]o / "
            "[yellow]s[/yellow]kip / "
            "[red]a[/red]bort / "
            "[green]all[/green] (approve all)"
        )

        choice = Prompt.ask(prompt_text, choices=choices, default="n")

        # Map choice to action
        if choice in ["y", "yes"]:
            return "approve"
        elif choice == "all":
            return "approve_all"
        elif choice in ["n", "no"]:
            return "deny"
        elif choice in ["s", "skip"]:
            return "skip"
        elif choice in ["a", "abort"]:
            return "abort"
        else:
            return "deny"

    def reset(self):
        """Reset approval state (for new operations)"""
        self.approved_all = False
        self.aborted = False

    def is_aborted(self) -> bool:
        """Check if operation has been aborted"""
        return self.aborted


# Example usage for testing
if __name__ == "__main__":
    gate = ApprovalGate()

    # Example: LOW risk action
    action_low = Action(
        command="nmap -sV localhost",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        risk_level=RiskLevel.LOW,
        impact_description="Scan network services (read-only, no system changes)",
        target="localhost",
        reversible=True,
    )

    # Example: MEDIUM risk action
    action_medium = Action(
        command="sqlmap -u http://target/api --dbs",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        risk_level=RiskLevel.MEDIUM,
        impact_description="Attempt SQL injection to enumerate databases",
        target="http://target/api",
        reversible=True,
    )

    # Example: HIGH risk action
    action_high = Action(
        command="DROP TABLE users; --",
        technique_id="T1485",
        technique_name="Data Destruction",
        risk_level=RiskLevel.HIGH,
        impact_description="May corrupt or destroy database tables",
        target="production_db",
        reversible=False,
        data_at_risk="User accounts database",
    )

    # Test approval flow
    console.print("[bold cyan]Testing Approval Gate System[/bold cyan]\n")

    if gate.request_approval(action_low):
        console.print("[dim]Executing low-risk action...[/dim]\n")

    if gate.request_approval(action_medium):
        console.print("[dim]Executing medium-risk action...[/dim]\n")

    if gate.request_approval(action_high):
        console.print("[dim]Executing high-risk action...[/dim]\n")

