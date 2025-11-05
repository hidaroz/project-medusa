"""
Interactive setup wizard for MEDUSA
"""
import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
import os
from pathlib import Path
import yaml
import httpx

console = Console()

def run_wizard():
    """Run interactive setup wizard"""

    console.print(Panel.fit(
        "[bold cyan]MEDUSA Setup Wizard[/]\n"
        "Let's get you up and running in 60 seconds!",
        border_style="cyan"
    ))

    # Step 1: Check for existing config
    config_path = Path.home() / ".medusa" / "config.yaml"
    if config_path.exists():
        if not Confirm.ask(
            "\n[yellow]Existing config found. Overwrite?[/]",
            default=False
        ):
            console.print("[green]✓[/] Keeping existing configuration")
            return

    # Step 2: API Key Setup
    console.print("\n[bold]Step 1: AI Integration[/]")
    console.print("MEDUSA uses AI to make intelligent pentesting decisions.")

    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")

    if api_key:
        console.print(f"[green]✓[/] Found API key in environment")
        use_existing = Confirm.ask("Use this key?", default=True)
        if not use_existing:
            api_key = None

    if not api_key:
        console.print("\n[cyan]Options:[/]")
        console.print("  1. Use Google Gemini (get free API key)")
        console.print("  2. Use local Ollama (privacy-focused, no limits)")
        console.print("  3. Mock mode (for testing)")

        choice = Prompt.ask(
            "Choose option",
            choices=["1", "2", "3"],
            default="2"
        )

        if choice == "1":
            console.print("\n[cyan]→ Opening Google AI Studio...[/]")
            console.print("  Get your key at: https://aistudio.google.com/app/apikey")

            api_key = Prompt.ask("\nEnter your Gemini API key", password=True)

            # Validate API key
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
            ) as progress:
                progress.add_task("Testing API key...", total=None)

                if validate_gemini_key(api_key):
                    console.print("[green]✓[/] API key validated!")
                else:
                    console.print("[red]✗[/] Invalid API key")
                    return

        elif choice == "2":
            console.print("\n[cyan]Checking for Ollama installation...[/]")

            if check_ollama_installed():
                console.print("[green]✓[/] Ollama found!")
                api_key = "local_ollama"
            else:
                console.print("[yellow]⚠[/] Ollama not installed")
                console.print("\nInstall with:")
                console.print("  curl -fsSL https://ollama.com/install.sh | sh")
                console.print("  ollama pull mistral:7b-instruct")

                if Confirm.ask("\nContinue with mock mode instead?"):
                    api_key = "mock"
                else:
                    return

        else:  # Mock mode
            api_key = "mock"
            console.print("[cyan]ℹ[/] Using mock mode (simulated responses)")

    # Step 3: Target Configuration
    console.print("\n[bold]Step 2: Default Target[/]")
    target = Prompt.ask(
        "Default target for testing",
        default="localhost"
    )

    # Step 4: Mode Preference
    console.print("\n[bold]Step 3: Operating Mode[/]")
    console.print("  • observe - Read-only reconnaissance (safest)")
    console.print("  • autonomous - AI-driven with approval gates")
    console.print("  • shell - Interactive pentesting")

    mode = Prompt.ask(
        "Default mode",
        choices=["observe", "autonomous", "shell"],
        default="observe"
    )

    # Step 5: Advanced Settings
    configure_advanced = Confirm.ask(
        "\n[bold]Configure advanced settings?[/]",
        default=False
    )

    if configure_advanced:
        temperature = float(Prompt.ask("LLM temperature", default="0.7"))
        max_tokens = int(Prompt.ask("Max tokens per response", default="2048"))
        timeout = int(Prompt.ask("Request timeout (seconds)", default="30"))
    else:
        temperature = 0.7
        max_tokens = 2048
        timeout = 30

    # Build configuration
    config = {
        "api_key": api_key,
        "target": target,
        "mode": mode,
        "llm": {
            "model": "gemini-pro" if api_key != "mock" and api_key != "local_ollama" else "mistral:7b-instruct",
            "temperature": temperature,
            "max_tokens": max_tokens,
            "timeout": timeout,
            "max_retries": 3
        },
        "risk_tolerance": "medium",
        "auto_approve_low_risk": False,
        "logging": {
            "level": "INFO",
            "save_logs": True,
            "log_dir": "~/.medusa/logs"
        },
        "reporting": {
            "auto_generate": True,
            "format": "html",
            "report_dir": "~/.medusa/reports"
        }
    }

    # Step 6: Save Configuration
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    console.print(f"\n[green]✓[/] Configuration saved to {config_path}")

    # Step 7: Environment Setup
    if Confirm.ask("\nSet up environment variables?", default=True):
        setup_environment_variables(api_key)

    # Step 8: Quick Test
    if Confirm.ask("\nRun a quick test?", default=True):
        run_quick_test()

    # Success!
    console.print(Panel.fit(
        "[bold green]Setup Complete! 🎉[/]\n\n"
        "Try these commands:\n"
        "  • medusa observe scanme.nmap.org\n"
        "  • medusa status\n"
        "  • medusa shell --target localhost",
        border_style="green"
    ))


def validate_gemini_key(api_key: str) -> bool:
    """Validate Gemini API key"""
    try:
        response = httpx.get(
            "https://generativelanguage.googleapis.com/v1beta/models",
            headers={"x-goog-api-key": api_key},
            timeout=10
        )
        return response.status_code == 200
    except:
        return False


def check_ollama_installed() -> bool:
    """Check if Ollama is installed and running"""
    try:
        response = httpx.get("http://localhost:11434/api/tags", timeout=2)
        return response.status_code == 200
    except:
        return False


def setup_environment_variables(api_key: str):
    """Help user set up environment variables"""
    shell = os.getenv("SHELL", "bash")

    if "zsh" in shell:
        rc_file = Path.home() / ".zshrc"
    elif "bash" in shell:
        rc_file = Path.home() / ".bashrc"
    else:
        rc_file = None

    if rc_file and api_key not in ["mock", "local_ollama"]:
        console.print(f"\nAdd this to your {rc_file.name}:")
        console.print(f"  export GEMINI_API_KEY='{api_key}'")

        if Confirm.ask("Add automatically?"):
            with open(rc_file, 'a') as f:
                f.write(f"\n# MEDUSA Configuration\nexport GEMINI_API_KEY='{api_key}'\n")
            console.print("[green]✓[/] Added to shell configuration")


def run_quick_test():
    """Run a quick connectivity test"""
    from medusa.core.llm import LLMClient, LLMConfig
    import asyncio

    console.print("\n[cyan]Running quick test...[/]")

    # Load just-created config
    config_path = Path.home() / ".medusa" / "config.yaml"
    with open(config_path) as f:
        config = yaml.safe_load(f)

    try:
        llm_config = LLMConfig(
            api_key=config['api_key'],
            model=config['llm']['model'],
            temperature=config['llm']['temperature'],
            max_tokens=config['llm']['max_tokens'],
            timeout=config['llm']['timeout'],
            max_retries=config['llm']['max_retries']
        )

        client = LLMClient(llm_config)

        # Simple test
        response = asyncio.run(
            client._generate_with_retry("Say 'MEDUSA is ready!' in one sentence.")
        )

        console.print(f"[green]✓[/] Test successful!")
        console.print(f"[dim]Response: {response[:80]}...[/]")

    except Exception as e:
        console.print(f"[yellow]⚠[/] Test failed: {e}")
        console.print("You can still use MEDUSA, but check your configuration")
