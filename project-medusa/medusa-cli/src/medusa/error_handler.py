"""
Enhanced error handling with actionable messages and recovery suggestions.

Provides user-friendly error messages that guide users toward solutions.
"""

import sys
import traceback
from typing import Optional, Callable
from functools import wraps

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()


class MedusaError(Exception):
    """Base exception for MEDUSA errors with recovery suggestions."""

    def __init__(
        self,
        message: str,
        suggestion: Optional[str] = None,
        command: Optional[str] = None,
    ):
        self.message = message
        self.suggestion = suggestion
        self.command = command
        super().__init__(message)


class ConfigurationError(MedusaError):
    """Configuration-related errors."""

    pass


class DependencyError(MedusaError):
    """Missing dependency errors."""

    pass


class NetworkError(MedusaError):
    """Network-related errors."""

    pass


class AuthenticationError(MedusaError):
    """API key or authentication errors."""

    pass


class ValidationError(MedusaError):
    """Input validation errors."""

    pass


def handle_error(error: Exception) -> None:
    """
    Display user-friendly error message with recovery suggestions.

    Args:
        error: The exception that occurred
    """

    console.print()

    if isinstance(error, MedusaError):
        # Custom MEDUSA errors with suggestions
        panel_content = f"[bold red]Error:[/bold red] {error.message}"

        if error.suggestion:
            panel_content += f"\n\n[bold yellow]💡 Suggestion:[/bold yellow]\n{error.suggestion}"

        if error.command:
            panel_content += (
                f"\n\n[bold cyan]Try running:[/bold cyan]\n  {error.command}"
            )

        console.print(
            Panel(
                panel_content,
                title="[bold red]⚠️  Error[/bold red]",
                border_style="red",
            )
        )

    elif isinstance(error, ImportError):
        # Missing dependency
        module_name = (
            str(error).split("'")[1]
            if "'" in str(error)
            else str(error).split()[-1]
        )

        console.print(
            Panel(
                f"[bold red]Missing Dependency:[/bold red] {module_name}\n\n"
                f"[bold yellow]💡 Solution:[/bold yellow]\n"
                f"  Install the missing package:\n\n"
                f"[bold cyan]Run:[/bold cyan]\n"
                f"  pip install {module_name}\n\n"
                f"Or reinstall MEDUSA with all dependencies:\n"
                f"  pip install -e . --force-reinstall",
                title="[bold red]⚠️  Import Error[/bold red]",
                border_style="red",
            )
        )

    elif isinstance(error, FileNotFoundError):
        # Missing file or configuration
        console.print(
            Panel(
                f"[bold red]File Not Found:[/bold red]\n{error}\n\n"
                f"[bold yellow]💡 Solution:[/bold yellow]\n"
                f"  Run the setup wizard to create configuration:\n\n"
                f"[bold cyan]Run:[/bold cyan]\n"
                f"  medusa setup",
                title="[bold red]⚠️  Configuration Error[/bold red]",
                border_style="red",
            )
        )

    elif isinstance(error, PermissionError):
        # Permission issues
        console.print(
            Panel(
                f"[bold red]Permission Denied:[/bold red]\n{error}\n\n"
                f"[bold yellow]💡 Solution:[/bold yellow]\n"
                f"  Check file permissions:\n\n"
                f"[bold cyan]Try:[/bold cyan]\n"
                f"  sudo medusa [command]  # Run with elevated privileges\n"
                f"  # Or fix permissions:\n"
                f"  chmod +x [file]",
                title="[bold red]⚠️  Permission Error[/bold red]",
                border_style="red",
            )
        )

    elif "ConnectionError" in type(error).__name__ or "TimeoutError" in type(
        error
    ).__name__:
        # Network issues
        console.print(
            Panel(
                f"[bold red]Network Error:[/bold red] Cannot connect to target\n\n"
                f"[bold yellow]💡 Possible causes:[/bold yellow]\n"
                f"  • Target is unreachable or offline\n"
                f"  • Firewall blocking connection\n"
                f"  • Network connectivity issues\n"
                f"  • Invalid target URL\n\n"
                f"[bold cyan]Troubleshooting:[/bold cyan]\n"
                f"  1. Check target is reachable: ping [target]\n"
                f"  2. Check firewall settings\n"
                f"  3. Try different target or port\n"
                f"  4. Test connection: curl http://[target]",
                title="[bold red]⚠️  Connection Error[/bold red]",
                border_style="red",
            )
        )

    elif isinstance(error, ValueError):
        # Value errors
        console.print(
            Panel(
                f"[bold red]Invalid Value:[/bold red]\n{error}\n\n"
                f"[bold yellow]💡 Check:[/bold yellow]\n"
                f"  • Verify target URL format (e.g., http://example.com)\n"
                f"  • Check API key format\n"
                f"  • Ensure all required parameters are provided\n\n"
                f"[bold cyan]Get help:[/bold cyan]\n"
                f"  medusa --help",
                title="[bold red]⚠️  Value Error[/bold red]",
                border_style="red",
            )
        )

    else:
        # Unknown error - show traceback in debug mode
        console.print(
            Panel(
                f"[bold red]Unexpected Error:[/bold red] {type(error).__name__}\n\n"
                f"[dim]{error}[/dim]\n\n"
                f"[bold yellow]💡 What to do:[/bold yellow]\n"
                f"  1. Check logs: medusa logs --latest\n"
                f"  2. Report issue: https://github.com/your-org/medusa/issues\n"
                f"  3. Include:\n"
                f"     - Error message\n"
                f"     - Command that failed\n"
                f"     - Python version\n"
                f"     - MEDUSA version: medusa --version",
                title="[bold red]⚠️  Unexpected Error[/bold red]",
                border_style="red",
            )
        )

    console.print()


def error_handler_decorator(func: Callable) -> Callable:
    """
    Decorator to wrap CLI commands with error handling.

    Catches exceptions and displays user-friendly error messages.

    Usage:
        @app.command()
        @error_handler_decorator
        def my_command():
            ...
    """

    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except KeyboardInterrupt:
            console.print("\n\n[yellow]⏸️  Operation cancelled by user[/yellow]")
            sys.exit(0)
        except Exception as e:
            handle_error(e)
            sys.exit(1)

    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            console.print("\n\n[yellow]⏸️  Operation cancelled by user[/yellow]")
            sys.exit(0)
        except Exception as e:
            handle_error(e)
            sys.exit(1)

    # Return appropriate wrapper based on whether function is async
    import asyncio

    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper

