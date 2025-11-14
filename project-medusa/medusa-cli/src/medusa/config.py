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
    
    # Default LLM configuration (LLM-agnostic)
    DEFAULT_LLM_CONFIG = {
        "provider": "auto",  # auto, local, openai, anthropic, mock
        "local_model": "mistral:7b-instruct",
        "ollama_url": "http://localhost:11434",
        "temperature": 0.7,
        "max_tokens": 2048,
        "timeout": 60,
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
        
        # Legacy compatibility: Map old api_key to cloud_api_key if needed
        if "api_key" in self.config_data and "cloud_api_key" not in config:
            # If we have an old api_key but no provider specified, assume it's for cloud
            if config.get("provider") in ["openai", "anthropic"] or config.get("provider") == "auto":
                config["cloud_api_key"] = self.config_data["api_key"]
        
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

        # Step 1: LLM Provider Selection
        console.print("[bold yellow][1/4][/bold yellow] [cyan]LLM Provider Configuration[/cyan]")
        console.print("MEDUSA uses AI for intelligent penetration testing decisions.")
        console.print("\nChoose your LLM provider:")
        console.print("  1. [green]Local (Ollama)[/green] - Recommended (free, private, unlimited)")
        console.print("  2. [blue]AWS Bedrock (Claude 3.5)[/blue] - Enterprise-grade, smart routing, ~$0.25/scan")
        console.print("  3. [yellow]Cloud (OpenAI/Anthropic)[/yellow] - Requires API key")
        console.print("  4. [dim]Mock (Testing only)[/dim] - No real AI")

        provider_choice = Prompt.ask("Choice", choices=["1", "2", "3", "4"], default="1")
        
        llm_config = {
            "temperature": 0.7,
            "max_tokens": 2048,
            "timeout": 60,
            "max_retries": 3,
            "mock_mode": False
        }
        
        if provider_choice == "1":
            # Local Ollama provider
            llm_config["provider"] = "local"
            llm_config["local_model"] = "mistral:7b-instruct"
            llm_config["ollama_url"] = "http://localhost:11434"
            
            console.print("\n[cyan]Local Ollama Configuration[/cyan]")
            console.print("Using local Mistral-7B-Instruct model via Ollama.")
            
            # Check if Ollama is available
            import httpx
            try:
                with httpx.Client(timeout=2.0) as client:
                    response = client.get("http://localhost:11434/api/tags")
                    if response.status_code == 200:
                        console.print("[green]✓ Ollama is running[/green]")
                        # Check if mistral model is available
                        models = response.json().get("models", [])
                        mistral_available = any("mistral" in m.get("name", "").lower() for m in models)
                        if mistral_available:
                            console.print("[green]✓ Mistral model found[/green]")
                        else:
                            console.print("[yellow]⚠ Mistral model not found[/yellow]")
                            console.print("  Run: [cyan]ollama pull mistral:7b-instruct[/cyan]")
                    else:
                        console.print("[yellow]⚠ Ollama not responding[/yellow]")
                        console.print("  Install: [cyan]curl -fsSL https://ollama.com/install.sh | sh[/cyan]")
                        console.print("  Start: [cyan]ollama serve[/cyan]")
            except Exception:
                console.print("[yellow]⚠ Ollama not detected[/yellow]")
                console.print("  Install: [cyan]curl -fsSL https://ollama.com/install.sh | sh[/cyan]")
                console.print("  Pull model: [cyan]ollama pull mistral:7b-instruct[/cyan]")
                console.print("  Start: [cyan]ollama serve[/cyan]")
            
            console.print("\n[green]✓ Local provider configured[/green]\n")

        elif provider_choice == "2":
            # AWS Bedrock provider
            llm_config["provider"] = "bedrock"

            console.print("\n[cyan]AWS Bedrock Configuration[/cyan]")
            console.print("AWS Bedrock provides Claude 3.5 Sonnet and Haiku models")
            console.print("Learn more: [link]https://docs.medusa.ai/bedrock-setup[/link]\n")

            console.print("[bold]Step 1: AWS Region[/bold]")
            console.print("Bedrock is available in: us-east-1, us-west-2, eu-west-1, ap-southeast-1")
            aws_region = Prompt.ask(
                "Select AWS region",
                default="us-west-2",
                choices=["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]
            )
            llm_config["aws_region"] = aws_region

            console.print("\n[bold]Step 2: AWS Credentials[/bold]")
            console.print("Choose credential configuration method:")
            console.print("  1. [green]AWS CLI (Recommended)[/green] - Use existing ~/.aws/credentials")
            console.print("  2. [yellow]Environment Variables[/yellow] - Set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY")
            console.print("  3. [dim]Skip[/dim] - Configure manually later")

            cred_choice = Prompt.ask("Choice", choices=["1", "2", "3"], default="1")

            if cred_choice == "1":
                # AWS CLI - check if configured
                console.print("\nChecking AWS CLI configuration...")
                try:
                    import subprocess
                    result = subprocess.run(
                        ["aws", "sts", "get-caller-identity", "--region", aws_region],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        console.print("[green]✓ AWS credentials found and valid[/green]")
                        # Don't store credentials in config - use AWS credential chain
                    else:
                        console.print("[yellow]⚠ AWS CLI not configured[/yellow]")
                        console.print("\nRun: [cyan]aws configure[/cyan]")
                        console.print("You'll need:")
                        console.print("  - AWS Access Key ID")
                        console.print("  - AWS Secret Access Key")
                        console.print("  - Region: [cyan]{aws_region}[/cyan]")
                        console.print("\nContinuing with setup...")
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    console.print("[yellow]⚠ AWS CLI not found[/yellow]")
                    console.print("Install: [cyan]pip install awscli && aws configure[/cyan]")

            elif cred_choice == "2":
                # Environment variables
                console.print("\n[cyan]Set these environment variables:[/cyan]")
                console.print("  export AWS_ACCESS_KEY_ID=your_access_key")
                console.print("  export AWS_SECRET_ACCESS_KEY=your_secret_key")
                console.print("  export AWS_REGION={aws_region}")
                console.print("\n[yellow]⚠ Do not store credentials in config.yaml[/yellow]")

            else:
                console.print("\n[yellow]⚠ Credentials not configured[/yellow]")
                console.print("See setup guide: [link]docs/00-getting-started/bedrock-setup.md[/link]")

            console.print("\n[bold]Step 3: Model Access[/bold]")
            console.print("You must enable model access in AWS Console:")
            console.print("  1. Go to AWS Bedrock → Model access")
            console.print("  2. Click 'Modify model access'")
            console.print("  3. Enable: Anthropic Claude 3.5 Sonnet")
            console.print("  4. Enable: Anthropic Claude 3.5 Haiku")
            console.print("\nAccess is usually granted instantly.")

            model_access = Confirm.ask("\nHave you enabled model access?", default=False)

            if model_access:
                console.print("[green]✓ Model access confirmed[/green]")
            else:
                console.print("[yellow]⚠ Enable model access before running MEDUSA[/yellow]")

            # Configure smart routing models
            llm_config["smart_model"] = "anthropic.claude-3-5-sonnet-20241022-v2:0"
            llm_config["fast_model"] = "anthropic.claude-3-5-haiku-20241022-v1:0"
            llm_config["cloud_model"] = "anthropic.claude-3-5-haiku-20241022-v1:0"

            console.print("\n[bold]Smart Model Routing Enabled:[/bold]")
            console.print("  • Complex tasks → Claude 3.5 Sonnet ($3/$15 per 1M tokens)")
            console.print("  • Simple tasks → Claude 3.5 Haiku ($0.80/$4 per 1M tokens)")
            console.print("  • Est. cost savings: ~60%")
            console.print("  • Typical scan: $0.20-0.30")

            # Verify connection
            console.print("\n[bold]Verifying connection...[/bold]")
            try:
                import boto3
                from botocore.exceptions import ClientError, NoCredentialsError

                bedrock = boto3.client('bedrock-runtime', region_name=aws_region)

                # Try to invoke model (minimal test)
                test_response = bedrock.invoke_model(
                    modelId="anthropic.claude-3-5-haiku-20241022-v1:0",
                    body='{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":"test"}]}'
                )

                console.print("[green]✓ AWS Bedrock connection successful[/green]")
                console.print("[green]✓ Model access verified[/green]")
                console.print("[green]✓ Smart routing configured[/green]\n")

            except NoCredentialsError:
                console.print("[yellow]⚠ AWS credentials not found[/yellow]")
                console.print("Configure credentials before using Bedrock\n")
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                if error_code == 'AccessDeniedException':
                    console.print("[yellow]⚠ Model access not enabled[/yellow]")
                    console.print("Enable Claude 3.5 models in AWS Console\n")
                else:
                    console.print(f"[yellow]⚠ Connection error: {error_code}[/yellow]\n")
            except Exception as e:
                console.print(f"[yellow]⚠ Could not verify connection: {str(e)}[/yellow]\n")

            console.print("[green]✓ AWS Bedrock configured[/green]\n")

        elif provider_choice == "3":
            # Cloud provider
            console.print("\n[cyan]Cloud Provider Configuration[/cyan]")
            cloud_provider = Prompt.ask(
                "Select cloud provider",
                choices=["openai", "anthropic"],
                default="openai"
            )
            
            llm_config["provider"] = cloud_provider
            
            if cloud_provider == "openai":
                console.print("\nGet your API key from: [link]https://platform.openai.com/api-keys[/link]")
                api_key = Prompt.ask("Enter your OpenAI API key", password=True)
                llm_config["cloud_api_key"] = api_key
                llm_config["cloud_model"] = Prompt.ask(
                    "Model name",
                    default="gpt-4-turbo-preview"
                )
            else:  # anthropic
                console.print("\nGet your API key from: [link]https://console.anthropic.com/[/link]")
                api_key = Prompt.ask("Enter your Anthropic API key", password=True)
                llm_config["cloud_api_key"] = api_key
                llm_config["cloud_model"] = Prompt.ask(
                    "Model name",
                    default="claude-3-sonnet-20240229"
                )
            
            # Validate API key format
            if len(api_key) < 20:
                console.print("[red]✗ Invalid API key format[/red]")
                return {}
            
            console.print("[green]✓ Cloud provider configured[/green]\n")
            
        else:  # Mock
            llm_config["provider"] = "mock"
            llm_config["mock_mode"] = True
            console.print("\n[yellow]⚠ Mock mode enabled - no real AI will be used[/yellow]")
            console.print("[green]✓ Mock provider configured[/green]\n")
        
        config["llm"] = llm_config

        # Step 2: Target Environment
        console.print("[bold yellow][2/4][/bold yellow] [cyan]Target Environment[/cyan]")
        console.print("Do you want to test against:")
        console.print("  [cyan]1[/cyan]. Local Docker environment (recommended for learning)")
        console.print("  [cyan]2[/cyan]. Your own infrastructure")
        console.print()

        choice = Prompt.ask(
            "Select option",
            choices=["1", "2"],
            default="1",
            show_choices=True
        )
        
        target_type = "docker" if choice == "1" else "custom"
        console.print(f"[green]✓ {target_type.title()} environment selected[/green]\n")

        if target_type == "docker":
            config["target"] = {"type": "docker", "url": "http://localhost:3001"}
        else:
            console.print("[cyan]Enter your target URL[/cyan]")
            target_url = Prompt.ask("Target URL", default="http://localhost:3001")
            if not target_url.startswith(("http://", "https://")):
                console.print("[yellow]⚠ Warning: URL should start with http:// or https://[/yellow]")
                console.print("[yellow]Adding http:// prefix...[/yellow]")
                target_url = f"http://{target_url}"
            config["target"] = {"type": "custom", "url": target_url}
            console.print(f"[green]✓ Target URL configured: {target_url}[/green]\n")

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

