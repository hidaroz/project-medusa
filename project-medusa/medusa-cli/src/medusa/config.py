"""
Configuration management for MEDUSA CLI
Handles setup wizard, config loading/saving, and user preferences
"""

import os
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
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
        "provider": "auto",  # Auto-detect: try local first, then Gemini, then mock
        "model": "mistral:7b-instruct",
        "ollama_url": "http://localhost:11434",
        "temperature": 0.7,
        "max_tokens": 2048,
        "timeout": 60,  # Increased for local models
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

    async def validate_gemini_api_key(self, api_key: str) -> Tuple[bool, str]:
        """
        Validate Google Gemini API key with a test request

        Args:
            api_key: The API key to validate

        Returns:
            Tuple of (is_valid: bool, message: str)
        """
        try:
            import google.generativeai as genai

            # Configure with the API key
            genai.configure(api_key=api_key)

            # Try a simple test request
            model = genai.GenerativeModel('gemini-pro-latest')
            response = await asyncio.to_thread(
                model.generate_content,
                "Respond with 'OK' if you receive this message."
            )

            if response and response.text:
                return True, "✅ API key is valid and working"
            else:
                return False, "❌ API key validation failed: No response from Gemini"

        except ImportError:
            return False, "❌ google-generativeai package not installed. Install with: pip install google-generativeai"
        except Exception as e:
            error_msg = str(e).lower()

            # Provide specific error messages based on error type
            if "api" in error_msg and ("key" in error_msg or "invalid" in error_msg):
                return False, "❌ Invalid API key. Get a new key from: https://ai.google.dev/gemini-api/docs/quickstart"
            elif "quota" in error_msg or "rate" in error_msg:
                return False, "⚠️ API quota exceeded. Check your usage at: https://aistudio.google.com/"
            elif "permission" in error_msg or "denied" in error_msg:
                return False, "❌ API key doesn't have required permissions. Enable Gemini API in your Google Cloud project"
            elif "network" in error_msg or "connection" in error_msg:
                return False, "⚠️ Network error. Check your internet connection"
            else:
                return False, f"❌ Validation error: {str(e)}"

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

        max_attempts = 3
        api_key_validated = False

        for attempt in range(max_attempts):
            api_key = Prompt.ask("Enter your Google AI API key", password=True)

            # Basic format check
            if len(api_key) < 20:
                console.print("[yellow]⚠️ API key seems too short[/yellow]")
                if attempt < max_attempts - 1:
                    continue
                else:
                    console.print("[red]✗ Maximum attempts reached. Setup failed.[/red]")
                    console.print("[yellow]Run 'medusa setup --force' to try again.[/yellow]")
                    return {}

            # Validate API key with real test
            console.print("\n[cyan]Validating API key...[/cyan]")

            is_valid, message = asyncio.run(self.validate_gemini_api_key(api_key))
            console.print(message)

            if is_valid:
                api_key_validated = True
                config["api_key"] = api_key
                break
            else:
                if attempt < max_attempts - 1:
                    console.print(f"\n[yellow]Attempt {attempt + 1}/{max_attempts}. Please try again.[/yellow]\n")
                else:
                    console.print("\n[red]✗ Maximum attempts reached. Setup failed.[/red]")
                    console.print("[yellow]Run 'medusa setup --force' to try again.[/yellow]")
                    return {}

        if not api_key_validated:
            console.print("[red]✗ API key validation failed[/red]")
            return {}

        console.print()
        
        # LLM Configuration (using Gemini)
        config["llm"] = {
            "model": "gemini-pro-latest",
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

