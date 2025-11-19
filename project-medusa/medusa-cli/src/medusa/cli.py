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
from medusa.error_handler import error_handler_decorator, handle_error
from medusa.first_run import is_first_run, run_first_time_wizard
from medusa.cli_multi_agent import agent_app

app = typer.Typer(
    name="medusa",
    help="🔴 MEDUSA - AI-Powered Penetration Testing CLI",
    add_completion=False,  # Disabled - using custom completion command instead
    rich_markup_mode="rich",
)
console = Console()

# LLM command group
llm_app = typer.Typer(help="LLM utilities and diagnostics")
app.add_typer(llm_app, name="llm")

# Multi-agent command group
app.add_typer(agent_app, name="agent")


@llm_app.command("verify")
def llm_verify():
    """
    ✓ Check that the configured LLM is reachable and active.
    
    Verifies connectivity with the LLM provider (local Ollama, cloud API, etc.)
    without running any prompts. Perfect for troubleshooting LLM setup issues.
    
    Exit codes:
        0 - LLM is connected and healthy
        1 - LLM is not available or unreachable
    
    Examples:
        medusa llm verify
    """
    from medusa.core.llm import LLMConfig, create_llm_client
    from rich.panel import Panel
    from rich.table import Table
    
    config = get_config()
    if not config.exists():
        console.print("[red]Error: MEDUSA is not configured.[/red]\n"
                      "Run [bold]medusa setup[/bold] first.")
        raise typer.Exit(1)
    
    llm_cfg_dict = config.get_llm_config()
    llm_cfg = LLMConfig(**llm_cfg_dict)
    
    async def _verify_llm():
        """Run LLM health check"""
        client = create_llm_client(llm_cfg)
        try:
            health = await client.health_check()
            return health
        finally:
            await client.close()
    
    def _hint_for_provider(provider: str, cfg: dict) -> str:
        """Generate provider-specific remediation hints"""
        if provider == "local":
            ollama_url = cfg.get('ollama_url', 'http://localhost:11434')
            local_model = cfg.get('local_model', 'mistral:7b-instruct')
            return (
                f"Ensure Ollama is running at {ollama_url}\n"
                f"and model '{local_model}' is available.\n\n"
                f"[yellow]Quick fix:[/yellow]\n"
                f"  1. Install Ollama: [cyan]curl -fsSL https://ollama.com/install.sh | sh[/cyan]\n"
                f"  2. Pull model: [cyan]ollama pull {local_model}[/cyan]\n"
                f"  3. Start Ollama: [cyan]ollama serve[/cyan]"
            )
        elif provider == "openai":
            return (
                "[yellow]Setup required:[/yellow]\n"
                "  1. Install SDK: [cyan]pip install openai[/cyan]\n"
                "  2. Export API key: [cyan]export CLOUD_API_KEY='sk-...'[/cyan]\n"
                "  3. Verify network access to api.openai.com"
            )
        elif provider == "anthropic":
            return (
                "[yellow]Setup required:[/yellow]\n"
                "  1. Install SDK: [cyan]pip install anthropic[/cyan]\n"
                "  2. Export API key: [cyan]export CLOUD_API_KEY='sk-ant-...'[/cyan]\n"
                "  3. Verify network access to api.anthropic.com"
            )
        elif provider == "mock":
            return "Mock provider is in testing mode. No real LLM available."
        return "Check provider configuration in ~/.medusa/config.yaml"
    
    try:
        health = asyncio.run(_verify_llm())
        
        if health.get("healthy"):
            # Success case
            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_row("[bold]Provider[/bold]", f"[green]{health.get('provider')}[/green]")
            table.add_row("[bold]Model[/bold]", f"[green]{health.get('model')}[/green]")
            
            # Add model info if available
            model_info = health.get("model_info", {})
            if model_info:
                if isinstance(model_info, dict):
                    if "parameters" in model_info:
                        params = model_info["parameters"]
                        if isinstance(params, (int, float)):
                            table.add_row("[bold]Parameters[/bold]", f"[cyan]{params:,}[/cyan]")
            
            console.print(Panel(
                table,
                title="[bold green]✓ LLM Connected[/bold green]",
                border_style="green"
            ))
            raise typer.Exit(0)
        else:
            # Failure case
            hint = _hint_for_provider(health.get("provider"), llm_cfg_dict)
            console.print(Panel(
                hint,
                title="[bold red]✗ LLM Not Connected[/bold red]",
                border_style="red"
            ))
            raise typer.Exit(1)
    
    except typer.Exit:
        # Re-raise typer.Exit to allow proper exit code handling
        raise
    except Exception as e:
        console.print(Panel(
            f"[red]Unexpected error during LLM verification:[/red]\n{str(e)}",
            title="[bold red]✗ Verification Failed[/bold red]",
            border_style="red"
        ))
        raise typer.Exit(1)


@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context):
    """
    Main callback - runs when no command is provided.
    Handles first-run experience and shows help.
    """
    # Check if this is first run (only when running `medusa` with no command)
    if is_first_run():
        config = get_config()
        run_first_time_wizard(config.exists())
    else:
        # Show banner and help if no command provided
        # Only show if no command was actually invoked
        if ctx.invoked_subcommand is None:
            display.show_banner()
            console.print("\nUse [bold cyan]medusa --help[/bold cyan] to see available commands.")


@app.command()
def setup(
    force: bool = typer.Option(
        False, "--force", "-f", help="Force re-setup even if config exists"
    )
):
    """
    🔧 Run the setup wizard to configure MEDUSA.

    This will guide you through:
    - Configuring LLM provider (Local Ollama, Cloud, or Mock)
    - Configuring target environment
    - Setting risk tolerance levels
    - Initializing Docker environment (optional)
    """
    # Show first-run wizard if this is first run
    if is_first_run():
        config = get_config()
        run_first_time_wizard(config.exists())
        # If wizard was shown, mark as complete and continue with setup
        if not config.exists():
            console.print("\n[cyan]Starting setup wizard...[/cyan]\n")
    
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
        False, "--autonomous", "-a", help="Run in autonomous mode with approval gates (equivalent to --mode autonomous)"
    ),
    mode: Optional[str] = typer.Option(
        None, "--mode", "-m", help="Operating mode: autonomous, interactive, observe"
    ),
    loop: bool = typer.Option(
        False, "--loop", "-l", help="Run continuously in a loop"
    ),
    interval: int = typer.Option(
        3600, "--interval", "-i", help="Interval between runs in seconds (default: 3600)"
    ),
):
    """
    🚀 Run a penetration test.

    Command Variants:
        medusa run                                    # Uses default target, autonomous mode
        medusa run --autonomous                       # Autonomous mode with default target
        medusa run --mode autonomous                  # Same as --autonomous
        medusa run --mode interactive                 # Interactive shell mode
        medusa run --mode observe                     # Observe/reconnaissance mode only
        medusa run --target <url>                    # Specify target, autonomous mode
        medusa run --target <url> --autonomous        # Explicit autonomous mode
        medusa run --target <url> --mode autonomous    # Same as above
        medusa run --target <url> --mode interactive  # Interactive mode with target
        medusa run --target <url> --mode observe      # Observe mode with target

    Examples:
        medusa run --target http://localhost:3001 --autonomous
        medusa run --target http://example.com --mode observe
        medusa run --mode interactive
    """
    # Valid mode values
    VALID_MODES = {"autonomous", "interactive", "observe"}

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

    # Validate mode if provided
    if mode is not None:
        mode_lower = mode.lower()
        if mode_lower not in VALID_MODES:
            console.print(
                f"[red]Error: Invalid mode '{mode}'.[/red]\n"
                f"Valid modes are: [bold]{', '.join(sorted(VALID_MODES))}[/bold]"
            )
            raise typer.Exit(1)
        mode = mode_lower  # Normalize to lowercase

    # Detect conflicting flags
    if autonomous and mode is not None:
        if mode != "autonomous":
            console.print(
                "[red]Error: Cannot use --autonomous and --mode together.[/red]\n"
                "Use either [bold]--autonomous[/bold] or [bold]--mode <mode>[/bold], not both.\n"
                "Note: [bold]--autonomous[/bold] is equivalent to [bold]--mode autonomous[/bold]"
            )
            raise typer.Exit(1)
        # Both specify autonomous, which is fine - just use autonomous mode

    # Determine target
    if not target:
        target = config_data.get("target", {}).get("url")
        if not target:
            console.print(
                "[red]Error: No target specified and no default configured.[/red]\n"
                "Use [bold]--target <url>[/bold] or run [bold]medusa setup[/bold] to configure a default target."
            )
            raise typer.Exit(1)

    # Get LLM config to determine if API key is needed
    llm_config = config.get_llm_config()
    provider = llm_config.get("provider", "auto")
    
    # Check if API key is required (only for cloud providers)
    api_key = config_data.get("api_key") or llm_config.get("cloud_api_key")
    
    # Only require API key for cloud providers
    if provider in ["openai", "anthropic"]:
        if not api_key:
            console.print("[red]Error: API key required for cloud LLM provider.[/red]")
            console.print(f"\n[yellow]Provider:[/yellow] {provider}")
            console.print("[yellow]Solution:[/yellow]")
            console.print("  1. Run [bold]medusa setup[/bold] to configure API key")
            console.print("  2. Or set [bold]CLOUD_API_KEY[/bold] environment variable")
            console.print("  3. Or use local provider: [bold]medusa setup[/bold] and choose 'Local (Ollama)'")
            raise typer.Exit(1)
    else:
        # For local/mock/auto providers, API key is optional
        # Use empty string if not provided (will be ignored)
        if not api_key:
            api_key = ""

    # Determine mode (priority: --autonomous flag > --mode flag > default)
    if autonomous:
        selected_mode = "autonomous"
    elif mode is not None:
        selected_mode = mode
    else:
        # Default to autonomous mode
        selected_mode = "autonomous"

    # Show banner before executing mode
    display.show_banner()
    console.print()

    # Execute selected mode
    if selected_mode == "autonomous":
        _run_autonomous_mode(target, api_key, loop, interval)
    elif selected_mode == "interactive":
        _run_interactive_mode(target, api_key)
    elif selected_mode == "observe":
        _run_observe_mode(target, api_key)
    else:
        # This should never happen due to validation above, but safety check
        console.print(f"[red]Error: Unknown mode '{selected_mode}'.[/red]")
        raise typer.Exit(1)


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
    
    # Get LLM config to determine if API key is needed
    llm_config = config.get_llm_config()
    provider = llm_config.get("provider", "auto")
    
    # Check if API key is required (only for cloud providers)
    api_key = config_data.get("api_key") or llm_config.get("cloud_api_key")
    
    # Only require API key for cloud providers
    if provider in ["openai", "anthropic"]:
        if not api_key:
            console.print("[red]Error: API key required for cloud LLM provider.[/red]")
            console.print(f"\n[yellow]Provider:[/yellow] {provider}")
            console.print("[yellow]Solution:[/yellow]")
            console.print("  1. Run [bold]medusa setup[/bold] to configure API key")
            console.print("  2. Or set [bold]CLOUD_API_KEY[/bold] environment variable")
            console.print("  3. Or use local provider: [bold]medusa setup[/bold] and choose 'Local (Ollama)'")
            raise typer.Exit(1)
    else:
        # For local/mock/auto providers, API key is optional
        if not api_key:
            api_key = ""

    # Use configured target if not provided
    if not target:
        target = config_data.get("target", {}).get("url")

    # Show banner before starting interactive mode
    display.show_banner()
    console.print()

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
    
    # Get LLM config to determine if API key is needed
    llm_config = config.get_llm_config()
    provider = llm_config.get("provider", "auto")
    
    # Check if API key is required (only for cloud providers)
    api_key = config_data.get("api_key") or llm_config.get("cloud_api_key")
    
    # Only require API key for cloud providers
    if provider in ["openai", "anthropic"]:
        if not api_key:
            console.print("[red]Error: API key required for cloud LLM provider.[/red]")
            console.print(f"\n[yellow]Provider:[/yellow] {provider}")
            console.print("[yellow]Solution:[/yellow]")
            console.print("  1. Run [bold]medusa setup[/bold] to configure API key")
            console.print("  2. Or set [bold]CLOUD_API_KEY[/bold] environment variable")
            console.print("  3. Or use local provider: [bold]medusa setup[/bold] and choose 'Local (Ollama)'")
            raise typer.Exit(1)
    else:
        # For local/mock/auto providers, API key is optional
        if not api_key:
            api_key = ""

    if not target:
        target = config_data.get("target", {}).get("url")
        if not target:
            console.print("[red]Error: No target specified.[/red]")
            raise typer.Exit(1)

    # Show banner before starting observe mode
    display.show_banner()
    console.print()

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
def completion(
    shell: str = typer.Argument(..., help="Shell type: bash, zsh, or fish"),
    install: bool = typer.Option(
        False, "--install", "-i", help="Install completion script to shell config"
    ),
):
    """
    🎯 Generate shell completion scripts.
    
    Typer provides built-in completion support. This command helps you install it.
    
    Examples:
        medusa completion bash --install
        medusa completion zsh
        medusa completion fish --install
    
    After installation, restart your shell or run:
        source ~/.bashrc    # for bash
        source ~/.zshrc     # for zsh
        # fish completion is automatic
    """
    shell_map = {
        "bash": "bash",
        "zsh": "zsh",
        "fish": "fish",
    }
    
    if shell not in shell_map:
        console.print(f"[red]Error: Unsupported shell '{shell}'[/red]")
        console.print("Supported shells: bash, zsh, fish")
        raise typer.Exit(1)
    
    # Use typer's built-in completion
    try:
        from typer.main import get_completion_install_instructions
        
        if install:
            # Determine config file location
            home = Path.home()
            if shell == "bash":
                config_file = home / ".bashrc"
                # Check for .bash_profile on macOS
                if not config_file.exists():
                    config_file = home / ".bash_profile"
            elif shell == "zsh":
                config_file = home / ".zshrc"
            elif shell == "fish":
                config_dir = home / ".config" / "fish"
                config_dir.mkdir(parents=True, exist_ok=True)
                config_file = config_dir / "completions" / "medusa.fish"
                config_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Check if already installed
            if config_file.exists():
                with open(config_file) as f:
                    content = f.read()
                    if "medusa" in content.lower() and ("complete" in content.lower() or "completion" in content.lower()):
                        console.print(f"[yellow]Completion may already be installed in {config_file}[/yellow]")
                        console.print("Check the file or use a different method to install.")
            
            # Get installation instructions
            instructions = get_completion_install_instructions(
                shell=shell,
                prog_name="medusa",
            )
            
            console.print(f"[green]Installation instructions for {shell}:[/green]\n")
            console.print(instructions)
            console.print(f"\n[cyan]Or manually add to {config_file}:[/cyan]")
            
            if shell == "bash":
                completion_line = 'eval "$(_MEDUSA_COMPLETE=bash_source medusa)"'
            elif shell == "zsh":
                completion_line = 'eval "$(_MEDUSA_COMPLETE=zsh_source medusa)"'
            else:  # fish
                completion_line = 'medusa --install-completion fish | source'
            
            console.print(f"  {completion_line}")
        else:
            # Show how to get completion
            console.print(f"[cyan]To enable {shell} completion, run:[/cyan]")
            console.print(f"  medusa completion {shell} --install\n")
            console.print(f"[dim]Or manually add to your shell config:[/dim]")
            if shell == "bash":
                console.print('  eval "$(_MEDUSA_COMPLETE=bash_source medusa)"')
            elif shell == "zsh":
                console.print('  eval "$(_MEDUSA_COMPLETE=zsh_source medusa)"')
            else:  # fish
                console.print('  medusa --install-completion fish | source')
    except ImportError:
        # Fallback: provide manual instructions
        console.print(f"[yellow]Using manual completion setup for {shell}[/yellow]\n")
        console.print(f"Add the following to your {shell} configuration file:\n")
        
        if shell == "bash":
            console.print('eval "$(_MEDUSA_COMPLETE=bash_source medusa)"')
            console.print("\nThen run: source ~/.bashrc")
        elif shell == "zsh":
            console.print('eval "$(_MEDUSA_COMPLETE=zsh_source medusa)"')
            console.print("\nThen run: source ~/.zshrc")
        else:  # fish
            console.print("medusa --install-completion fish | source")
            console.print("\nOr add to ~/.config/fish/completions/medusa.fish")


@app.command()
def version():
    """
    📌 Show MEDUSA version.
    """
    console.print(f"[bold cyan]MEDUSA[/bold cyan] version [green]{__version__}[/green]")


@app.command()
def logs(
    latest: bool = typer.Option(False, "--latest", "-l", help="Show only latest log"),
    log_type: Optional[str] = typer.Option(
        None, "--type", "-t", help="Filter by operation type (auto, observe, interactive)"
    ),
    date: Optional[str] = typer.Option(
        None, "--date", "-d", help="Filter by date (YYYY-MM-DD format)"
    ),
    min_findings: Optional[int] = typer.Option(
        None, "--findings", "-f", help="Show only logs with at least N findings"
    ),
    summary: bool = typer.Option(
        False, "--summary", "-s", help="Show summary statistics only"
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output in JSON format for scripting"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show verbose output with more details"
    ),
):
    """
    📝 View operation logs.
    
    Examples:
        medusa logs --latest
        medusa logs --type observe --summary
        medusa logs --date 2025-11-05 --json
        medusa logs --findings 5
    """
    import json
    from datetime import datetime
    from rich.table import Table
    
    config = get_config()

    if not config.logs_dir.exists():
        console.print("[yellow]No logs directory found.[/yellow]")
        raise typer.Exit()

    # Get log files
    log_files = sorted(config.logs_dir.glob("*.json"), key=lambda p: p.stat().st_mtime)

    if not log_files:
        console.print("[yellow]No log files found.[/yellow]")
        raise typer.Exit()

    # Filter logs
    filtered_logs = []
    for log_file in log_files:
        try:
            with open(log_file) as f:
                data = json.load(f)
            
            metadata = data.get("metadata", {})
            operation = data.get("operation", {})
            operation_id = metadata.get("operation_id", "")
            
            # Apply filters
            if log_type and log_type.lower() not in operation_id.lower():
                continue
            
            if date:
                timestamp = metadata.get("timestamp", "")
                if isinstance(timestamp, str):
                    try:
                        log_date = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).date()
                        filter_date = datetime.strptime(date, "%Y-%m-%d").date()
                        if log_date != filter_date:
                            continue
                    except (ValueError, AttributeError):
                        if date not in timestamp:
                            continue
            
            if min_findings is not None:
                findings_count = operation.get("summary", {}).get("total_findings", 0)
                if findings_count < min_findings:
                    continue
            
            filtered_logs.append((log_file, data))
        except Exception:
            continue  # Skip corrupted logs
    
    if not filtered_logs:
        console.print("[yellow]No logs match the specified filters.[/yellow]")
        raise typer.Exit()
    
    if latest:
        filtered_logs = [filtered_logs[-1]]
    
    # JSON output mode
    if json_output:
        import sys
        output = []
        for log_file, data in filtered_logs:
            metadata = data.get("metadata", {})
            operation = data.get("operation", {})
            output.append({
                "file": str(log_file.name),
                "path": str(log_file),
                "operation_id": metadata.get("operation_id", "Unknown"),
                "timestamp": metadata.get("timestamp", "Unknown"),
                "duration_seconds": operation.get("duration_seconds", 0),
                "total_findings": operation.get("summary", {}).get("total_findings", 0),
            })
        json.dump(output if len(output) > 1 else output[0], sys.stdout, indent=2)
        return
    
    # Summary statistics mode
    if summary:
        total_ops = len(filtered_logs)
        total_findings = 0
        total_duration = 0.0
        operation_types = {}
        
        for log_file, data in filtered_logs:
            operation = data.get("operation", {})
            metadata = data.get("metadata", {})
            operation_id = metadata.get("operation_id", "")
            
            findings = operation.get("summary", {}).get("total_findings", 0)
            duration = operation.get("duration_seconds", 0)
            
            total_findings += findings
            total_duration += duration
            
            # Determine operation type
            op_type = "unknown"
            if "observe" in operation_id.lower():
                op_type = "observe"
            elif "auto" in operation_id.lower():
                op_type = "autonomous"
            elif "interactive" in operation_id.lower():
                op_type = "interactive"
            
            operation_types[op_type] = operation_types.get(op_type, 0) + 1
        
        avg_duration = total_duration / total_ops if total_ops > 0 else 0
        
        table = Table(title="Log Summary Statistics", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Operations", str(total_ops))
        table.add_row("Total Findings", str(total_findings))
        table.add_row("Average Duration", f"{avg_duration:.1f}s")
        table.add_row("Total Duration", f"{total_duration:.1f}s")
        
        console.print()
        console.print(table)
        
        if operation_types:
            console.print("\n[bold cyan]Operations by Type:[/bold cyan]")
            for op_type, count in sorted(operation_types.items()):
                console.print(f"  • {op_type.capitalize()}: {count}")
        
        return
    
    # Normal display mode
    for log_file, data in filtered_logs:
        console.print(f"\n[bold cyan]Log:[/bold cyan] {log_file.name}")
        if verbose:
            console.print(f"[dim]Path: {log_file}[/dim]")
        console.print()
        
        try:
            metadata = data.get("metadata", {})
            operation = data.get("operation", {})
            summary_data = operation.get("summary", {})
            
            # Create a table for better formatting
            table = Table(show_header=False, box=None, padding=(0, 1))
            table.add_column(style="cyan", width=20)
            table.add_column(style="white")
            
            table.add_row("Operation ID:", metadata.get("operation_id", "Unknown"))
            table.add_row("Timestamp:", metadata.get("timestamp", "Unknown"))
            table.add_row("Duration:", f"{operation.get('duration_seconds', 0):.1f}s")
            table.add_row("Total Findings:", str(summary_data.get("total_findings", 0)))
            
            if verbose:
                findings_by_severity = summary_data.get("findings_by_severity", {})
                if findings_by_severity:
                    table.add_row("", "")  # Empty row
                    table.add_row("Findings by Severity:", "")
                    for severity, count in sorted(findings_by_severity.items()):
                        table.add_row(f"  {severity.capitalize()}:", str(count))
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error reading log: {e}[/red]")
            if verbose:
                import traceback
                console.print(traceback.format_exc())


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
def reports(
    open_latest: bool = typer.Option(
        False, "--open", "-o", help="Open latest report in browser"
    ),
    report_type: Optional[str] = typer.Option(
        None, "--type", "-t", help="Filter by report type: html, md, pdf, exec"
    ),
    latest: bool = typer.Option(
        False, "--latest", "-l", help="Show only latest report of each type"
    ),
    summary: bool = typer.Option(
        False, "--summary", "-s", help="Show summary statistics only"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show verbose output with full paths"
    ),
):
    """
    📄 View generated reports.

    Report Types:
    - HTML technical reports (*.html)
    - Executive summaries (*executive*.html)
    - Markdown reports (*.md)
    - PDF reports (*.pdf)
    
    Examples:
        medusa reports --latest
        medusa reports --type html --summary
        medusa reports --open
    """
    from datetime import datetime
    from rich.table import Table
    
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

    # Helper function to format file size
    def format_size(size_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

    # Helper function to format timestamp
    def format_timestamp(timestamp: float) -> str:
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S")

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
        return
    
    # Summary statistics mode
    if summary:
        html_reports = [r for r in report_files if r.suffix == ".html" and "executive" not in r.name]
        exec_reports = [r for r in report_files if "executive" in r.name]
        md_reports = [r for r in report_files if r.suffix == ".md"]
        pdf_reports = [r for r in report_files if r.suffix == ".pdf"]
        
        total_size = sum(f.stat().st_size for f in report_files)
        
        table = Table(title="Report Summary Statistics", show_header=True, header_style="bold cyan")
        table.add_column("Report Type", style="cyan")
        table.add_column("Count", style="green", justify="right")
        table.add_column("Total Size", style="yellow", justify="right")
        
        if html_reports:
            html_size = sum(f.stat().st_size for f in html_reports)
            table.add_row("Technical Reports (HTML)", str(len(html_reports)), format_size(html_size))
        if exec_reports:
            exec_size = sum(f.stat().st_size for f in exec_reports)
            table.add_row("Executive Summaries", str(len(exec_reports)), format_size(exec_size))
        if md_reports:
            md_size = sum(f.stat().st_size for f in md_reports)
            table.add_row("Markdown Reports", str(len(md_reports)), format_size(md_size))
        if pdf_reports:
            pdf_size = sum(f.stat().st_size for f in pdf_reports)
            table.add_row("PDF Reports", str(len(pdf_reports)), format_size(pdf_size))
        
        table.add_row("", "", "")  # Separator
        table.add_row("[bold]Total[/bold]", f"[bold]{len(report_files)}[/bold]", f"[bold]{format_size(total_size)}[/bold]")
        
        console.print()
        console.print(table)
        console.print(f"\n[dim]Location: {config.reports_dir}[/dim]")
        return

    # Normal display mode
    console.print(f"\n[bold cyan]Available Reports:[/bold cyan]\n")

    # Group by type
    html_reports = [r for r in report_files if r.suffix == ".html" and "executive" not in r.name]
    exec_reports = [r for r in report_files if "executive" in r.name]
    md_reports = [r for r in report_files if r.suffix == ".md"]
    pdf_reports = [r for r in report_files if r.suffix == ".pdf"]

    # Apply latest filter if requested
    if latest:
        html_reports = [html_reports[-1]] if html_reports else []
        exec_reports = [exec_reports[-1]] if exec_reports else []
        md_reports = [md_reports[-1]] if md_reports else []
        pdf_reports = [pdf_reports[-1]] if pdf_reports else []

    def display_report_group(reports: list, title: str):
        if not reports:
            return
        
        console.print(f"[bold]{title}:[/bold]")
        for report in reports:
            stat = report.stat()
            size = format_size(stat.st_size)
            timestamp = format_timestamp(stat.st_mtime)
            
            if verbose:
                console.print(f"  • {report.name}")
                console.print(f"    [dim]Size: {size} | Created: {timestamp}[/dim]")
                console.print(f"    [dim]Path: {report}[/dim]")
            else:
                console.print(f"  • {report.name} [dim]({size}, {timestamp})[/dim]")
        console.print()

    display_report_group(html_reports[-10:], "Technical Reports (HTML)")
    display_report_group(exec_reports[-10:], "Executive Summaries")
    display_report_group(md_reports[-10:], "Markdown Reports")
    display_report_group(pdf_reports[-10:], "PDF Reports")

    console.print(f"[dim]Location: {config.reports_dir}[/dim]")
    console.print("\n[cyan]Tip:[/cyan] Use [bold]--open[/bold] to view latest report")
    console.print("[cyan]Tip:[/cyan] Use [bold]--type[/bold] to filter by type (html, md, pdf, exec)")
    console.print("[cyan]Tip:[/cyan] Use [bold]--latest[/bold] to show only latest of each type")
    console.print("[cyan]Tip:[/cyan] Use [bold]--summary[/bold] for statistics")


def _run_autonomous_mode(target: str, api_key: str, loop: bool = False, interval: int = 3600):
    """Run autonomous mode"""
    import time
    
    while True:
        try:
            mode = AutonomousMode(target, api_key)
            asyncio.run(mode.run())
            
            if not loop:
                break
                
            console.print(f"\n[bold cyan]🔄 Loop enabled. Waiting {interval} seconds for next run...[/bold cyan]")
            time.sleep(interval)
            console.print("\n[bold cyan]🚀 Starting next run...[/bold cyan]\n")
            
        except KeyboardInterrupt:
            console.print("\n[yellow]⏸️  Operation interrupted by user[/yellow]")
            sys.exit(0)
        except Exception as e:
            handle_error(e)
            if not loop:
                sys.exit(1)
            
            console.print(f"[red]Error occurred: {e}. Retrying in {interval} seconds...[/red]")
            time.sleep(interval)


def _run_interactive_mode(target: Optional[str], api_key: str):
    """Run interactive shell mode"""
    try:
        mode = InteractiveMode(target, api_key)
        asyncio.run(mode.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]⏸️  Session terminated[/yellow]")
        sys.exit(0)
    except Exception as e:
        handle_error(e)
        sys.exit(1)


def _run_observe_mode(target: str, api_key: str):
    """Run observe mode"""
    try:
        mode = ObserveMode(target, api_key)
        asyncio.run(mode.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]⏸️  Observation interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        handle_error(e)
        sys.exit(1)


def main():
    """Main entry point with enhanced error handling"""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⏸️  Operation cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        handle_error(e)
        sys.exit(1)


if __name__ == "__main__":
    main()

