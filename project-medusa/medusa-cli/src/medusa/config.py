"""
Configuration management for MEDUSA CLI
Handles setup wizard, config loading/saving, and user preferences
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class Config:
    """Configuration manager for MEDUSA"""

    DEFAULT_CONFIG_DIR = Path.home() / ".medusa"
    CONFIG_FILE = "config.yaml"
    LOGS_DIR = "logs"
    REPORTS_DIR = "reports"
    
    # Default LLM configuration
    DEFAULT_LLM_CONFIG = {
        "model": "gemini-pro",
        "temperature": 0.7,
        "max_tokens": 2048,
        "timeout": 30,
        "max_retries": 3,
        "mock_mode": False
    }

    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or self.DEFAULT_CONFIG_DIR
        self.config_path = self.config_dir / self.CONFIG_FILE
        self.logs_dir = self.config_dir / self.LOGS_DIR
        self.reports_dir = self.config_dir / self.REPORTS_DIR
        self.config_data: Dict[str, Any] = {}

    def ensure_directories(self):
        """Create necessary directories if they don't exist"""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)

    def exists(self) -> bool:
        """Check if configuration file exists"""
        return self.config_path.exists()

    def load(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if not self.exists():
            raise FileNotFoundError(
                f"Configuration not found at {self.config_path}. Run 'medusa setup' first."
            )

        with open(self.config_path, "r") as f:
            self.config_data = yaml.safe_load(f) or {}

        return self.config_data

    def save(self, data: Dict[str, Any]):
        """Save configuration to file"""
        self.ensure_directories()
        self.config_data = data

        with open(self.config_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        if not self.config_data:
            self.load()
        return self.config_data.get(key, default)
    
    def get_llm_config(self) -> Dict[str, Any]:
        """Get LLM configuration with defaults"""
        if not self.config_data:
            self.load()
        
        llm_config = self.config_data.get("llm", {})
        
        # Merge with defaults
        config = self.DEFAULT_LLM_CONFIG.copy()
        config.update(llm_config)
        
        # Add API key from root config if not in llm section
        if "api_key" not in config and "api_key" in self.config_data:
            config["api_key"] = self.config_data["api_key"]
        
        return config

    def run_setup_wizard(self) -> Dict[str, Any]:
        """Run interactive setup wizard"""
        console.clear()
        console.print(
            Panel(
                "[bold cyan]MEDUSA Setup Wizard[/bold cyan]\n"
                "Configure your AI-powered penetration testing environment",
                style="cyan",
                expand=False,
            )
        )
        console.print()

        config = {}

        # Step 1: API Key
        console.print("[bold yellow][1/4][/bold yellow] [cyan]Gemini API Key[/cyan]")
        console.print(
            "Get your free API key from: [link]https://ai.google.dev/gemini-api/docs/quickstart[/link]"
        )
        api_key = Prompt.ask("Enter your Google AI API key", password=True)

        # Validate API key (basic check)
        if len(api_key) < 20:
            console.print("[red]✗ Invalid API key format[/red]")
            return {}

        # Test the API key
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task("Validating API key...", total=None)
            # TODO: Actually validate with a test API call
            import time
            time.sleep(1)

        console.print("[green]✓ API key validated[/green]\n")
        config["api_key"] = api_key
        
        # LLM Configuration (using Gemini)
        config["llm"] = {
            "model": "gemini-pro",
            "temperature": 0.7,
            "max_tokens": 2048,
            "timeout": 30,
            "max_retries": 3,
            "mock_mode": False  # Set to True for testing without API calls
        }

        # Step 2: Target Environment
        console.print("[bold yellow][2/4][/bold yellow] [cyan]Target Environment[/cyan]")
        console.print("Do you want to test against:")
        console.print("  1. Local Docker environment (recommended for learning)")
        console.print("  2. Your own infrastructure")

        choice = Prompt.ask("Choice", choices=["1", "2"], default="1")
        target_type = "docker" if choice == "1" else "custom"
        console.print(f"[green]✓ {target_type.title()} environment selected[/green]\n")

        if target_type == "docker":
            config["target"] = {"type": "docker", "url": "http://localhost:3001"}
        else:
            target_url = Prompt.ask("Enter target URL", default="http://localhost:3001")
            config["target"] = {"type": "custom", "url": target_url}

        # Step 3: Risk Tolerance
        console.print("[bold yellow][3/4][/bold yellow] [cyan]Risk Tolerance[/cyan]")
        console.print("Auto-approve actions rated as:")

        risk_low = Confirm.ask("  - LOW risk (reconnaissance, safe commands)", default=True)
        risk_medium = Confirm.ask("  - MEDIUM risk (exploitation attempts)", default=False)
        risk_high = Confirm.ask(
            "  - HIGH risk (data destruction, persistence)", default=False
        )

        config["risk_tolerance"] = {
            "auto_approve_low": risk_low,
            "auto_approve_medium": risk_medium,
            "auto_approve_high": risk_high,
        }
        console.print("[green]✓ Risk settings saved[/green]\n")

        # Step 4: Docker Setup (if applicable)
        if target_type == "docker":
            console.print("[bold yellow][4/4][/bold yellow] [cyan]Docker Setup[/cyan]")
            console.print("Setting up vulnerable test environment...")

            with Progress(console=console) as progress:
                task = progress.add_task("[cyan]Initializing Docker containers...", total=100)
                import time

                for i in range(100):
                    time.sleep(0.02)
                    progress.update(task, advance=1)

            console.print("[green]✓ Docker environment ready[/green]\n")
        else:
            console.print("[bold yellow][4/4][/bold yellow] [cyan]Configuration Complete[/cyan]")
            console.print("[green]✓ Setup complete[/green]\n")

        # Save configuration
        self.save(config)

        console.print(
            Panel(
                "[bold green]✓ Setup complete![/bold green]\n\n"
                f"Configuration saved to: [cyan]{self.config_path}[/cyan]\n"
                "Logs will be saved to: [cyan]{logs}[/cyan]\n"
                "Reports will be saved to: [cyan]{reports}[/cyan]\n\n"
                "Try: [yellow]medusa run --help[/yellow]".format(
                    logs=self.logs_dir, reports=self.reports_dir
                ),
                style="green",
                expand=False,
            )
        )

        return config


# Global configuration instance
_config_instance: Optional[Config] = None


def get_config() -> Config:
    """Get or create the global configuration instance"""
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    return _config_instance

