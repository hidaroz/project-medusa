"""
First-run experience wizard.

Guides new users through initial setup with helpful tips and context.
"""

from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.text import Text

console = Console()

# Configuration directory
CONFIG_DIR = Path.home() / ".medusa"
FIRST_RUN_MARKER = CONFIG_DIR / ".first_run_complete"


def is_first_run() -> bool:
    """Check if this is the first time running MEDUSA."""
    return not FIRST_RUN_MARKER.exists()


def mark_first_run_complete() -> None:
    """Mark first run as complete."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    FIRST_RUN_MARKER.touch()


def show_welcome() -> bool:
    """
    Show welcome message for first-time users.

    Returns:
        True if user wants to continue with setup, False otherwise
    """

    console.print()
    console.print(
        Panel(
            "[bold cyan]Welcome to MEDUSA! 🔴[/bold cyan]\n\n"
            "AI-Powered Penetration Testing CLI\n\n"
            "This is your first time running MEDUSA.\n"
            "Let's get you set up with a quick wizard.\n\n"
            "[dim](This will only take a minute...)[/dim]",
            title="[bold]👋 Welcome[/bold]",
            border_style="cyan",
            expand=False,
        )
    )
    console.print()

    if not Confirm.ask("Ready to start setup?", default=True):
        console.print(
            "\n[yellow]You can run setup anytime with:[/yellow]\n"
            "  [cyan]medusa setup[/cyan]\n"
        )
        return False

    return True


def show_quick_tips() -> None:
    """Show quick start tips."""
    console.print()
    console.print(
        Panel(
            "[bold green]✅ Setup complete![/bold green]\n\n"
            "[bold cyan]Quick Start Tips:[/bold cyan]\n\n"
            "1️⃣  Try a safe reconnaissance scan:\n"
            "   [cyan]medusa observe example.com[/cyan]\n\n"
            "2️⃣  Start an interactive session:\n"
            "   [cyan]medusa shell[/cyan]\n\n"
            "3️⃣  View your configuration:\n"
            "   [cyan]medusa status[/cyan]\n\n"
            "4️⃣  Get help anytime:\n"
            "   [cyan]medusa --help[/cyan]\n\n"
            "[dim bold]📚 Full documentation:[/dim bold]\n"
            "   docs/QUICKSTART.md\n"
            "   https://github.com/your-org/medusa",
            title="[bold green]🎉 Ready to Go![/bold green]",
            border_style="green",
            expand=False,
        )
    )
    console.print()


def show_installation_tips() -> None:
    """Show tips about using MEDUSA if not properly installed."""
    console.print()
    console.print(
        Panel(
            "[bold yellow]📌 Installation Note[/bold yellow]\n\n"
            "If 'medusa' command is not found, use:\n"
            "[cyan]python3 -m medusa.cli --help[/cyan]\n\n"
            "To add 'medusa' to PATH permanently:\n"
            "[cyan]bash scripts/install.sh[/cyan]",
            title="[bold]💡 Tip[/bold]",
            border_style="yellow",
            expand=False,
        )
    )
    console.print()


def show_next_steps(config_exists: bool = False) -> None:
    """
    Show next steps based on configuration status.

    Args:
        config_exists: Whether configuration already exists
    """
    console.print()

    if config_exists:
        console.print(
            Panel(
                "[bold cyan]What's Next?[/bold cyan]\n\n"
                "Your configuration is ready. Try:\n\n"
                "[bold]1. Observe mode[/bold] (safe reconnaissance)\n"
                "   [cyan]medusa observe --target example.com[/cyan]\n\n"
                "[bold]2. Interactive shell[/bold] (manual testing)\n"
                "   [cyan]medusa shell[/cyan]\n\n"
                "[bold]3. Autonomous mode[/bold] (full automated test)\n"
                "   [cyan]medusa run --target example.com[/cyan]\n\n"
                "[bold]4. View reports[/bold]\n"
                "   [cyan]medusa reports --open[/cyan]",
                title="[bold cyan]🚀 Next Steps[/bold cyan]",
                border_style="cyan",
            )
        )
    else:
        console.print(
            Panel(
                "[bold cyan]What's Next?[/bold cyan]\n\n"
                "[bold]1. Run setup wizard:[/bold]\n"
                "   [cyan]medusa setup[/cyan]\n\n"
                "[bold]2. Start interactive shell:[/bold]\n"
                "   [cyan]medusa shell[/cyan]\n\n"
                "[bold]3. View help:[/bold]\n"
                "   [cyan]medusa --help[/cyan]",
                title="[bold cyan]🚀 Next Steps[/bold cyan]",
                border_style="cyan",
            )
        )

    console.print()


def run_first_time_wizard(config_exists: bool = False) -> None:
    """
    Run first-time setup wizard.

    Args:
        config_exists: Whether configuration already exists
    """

    if not show_welcome():
        mark_first_run_complete()
        return

    # If no config, suggest setup
    if not config_exists:
        if Confirm.ask("\nRun setup wizard now?", default=True):
            # Setup will be called by CLI
            console.print(
                "\n[cyan]Run: medusa setup[/cyan]\n"
            )
    
    show_quick_tips()
    show_next_steps(config_exists)
    mark_first_run_complete()

