"""
Interactive Setup Wizard for MEDUSA
Guides users through initial configuration
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
import yaml
import questionary
from questionary import Choice
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from .validator import ConfigValidator
from .auto_detect import ToolDetector
from .profiles import ProfileManager


console = Console()


class SetupWizard:
    """Interactive setup wizard for first-time MEDUSA configuration"""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or Path.home() / ".medusa" / "config.yaml"
        self.validator = ConfigValidator()
        self.detector = ToolDetector()
        self.profile_manager = ProfileManager()
        self.config: Dict[str, Any] = {}

    def run(self, quick: bool = False, profile: Optional[str] = None) -> bool:
        """
        Run the setup wizard

        Args:
            quick: Skip optional questions
            profile: Use a specific profile

        Returns:
            True if setup completed successfully
        """
        try:
            console.print(Panel.fit(
                "[bold cyan]Welcome to MEDUSA Setup[/bold cyan]\n"
                "AI-Powered Autonomous Pentesting Platform\n\n"
                "This wizard will help you configure MEDUSA for first use.",
                border_style="cyan"
            ))

            if profile:
                return self._setup_with_profile(profile)

            if quick:
                return self._quick_setup()

            return self._interactive_setup()

        except KeyboardInterrupt:
            console.print("\n[yellow]Setup cancelled by user[/yellow]")
            return False
        except Exception as e:
            console.print(f"\n[red]Setup failed: {e}[/red]")
            return False

    def _interactive_setup(self) -> bool:
        """Full interactive setup"""

        # Step 1: Choose setup type
        setup_type = questionary.select(
            "How would you like to set up MEDUSA?",
            choices=[
                Choice("Quick setup (recommended defaults)", "quick"),
                Choice("Custom setup (choose all options)", "custom"),
                Choice("Load from profile", "profile"),
            ]
        ).ask()

        if setup_type == "quick":
            return self._quick_setup()
        elif setup_type == "profile":
            return self._setup_from_profile()

        # Step 2: LLM Provider Configuration
        console.print("\n[bold]Step 1: LLM Provider Configuration[/bold]")
        self._configure_llm()

        # Step 3: Database Configuration
        console.print("\n[bold]Step 2: Database Configuration[/bold]")
        self._configure_databases()

        # Step 4: Tool Detection
        console.print("\n[bold]Step 3: Security Tools Detection[/bold]")
        self._detect_tools()

        # Step 5: Safety Settings
        console.print("\n[bold]Step 4: Safety and Scope Settings[/bold]")
        self._configure_safety()

        # Step 6: Advanced Settings (optional)
        if questionary.confirm("Configure advanced settings?", default=False).ask():
            self._configure_advanced()

        # Step 7: Test Configuration
        console.print("\n[bold]Step 5: Testing Configuration[/bold]")
        if questionary.confirm("Test configuration now?", default=True).ask():
            if not self._test_configuration():
                if not questionary.confirm("Configuration test failed. Continue anyway?", default=False).ask():
                    return False

        # Step 8: Save Configuration
        console.print("\n[bold]Step 6: Saving Configuration[/bold]")
        return self._save_configuration()

    def _quick_setup(self) -> bool:
        """Quick setup with defaults"""
        console.print("\n[cyan]Running quick setup with recommended defaults...[/cyan]")

        # Set defaults
        self.config = {
            "llm": {
                "provider": "anthropic",
                "model": "claude-sonnet-4",
                "temperature": 0.3,
                "max_tokens": 4096,
            },
            "databases": {
                "neo4j": {
                    "uri": "bolt://localhost:7687",
                    "user": "neo4j",
                    "password": "",  # Will prompt
                },
                "chromadb": {
                    "path": str(Path.home() / ".medusa" / "chromadb"),
                    "collection": "medusa_knowledge",
                },
            },
            "safety": {
                "require_authorization": True,
                "auto_rollback": True,
                "audit_log": str(Path.home() / ".medusa" / "audit.log"),
            },
            "tools": {
                "auto_detect": True,
            },
            "output": {
                "format": "rich",
                "verbosity": "info",
            },
        }

        # Only ask for essential credentials
        api_key = questionary.password("Enter Anthropic API key (or press Enter to skip):").ask()
        if api_key:
            self.config["llm"]["api_key"] = api_key

        neo4j_password = questionary.password("Enter Neo4j password (or press Enter for default 'neo4j'):").ask()
        self.config["databases"]["neo4j"]["password"] = neo4j_password or "neo4j"

        # Auto-detect tools
        console.print("\n[cyan]Detecting installed security tools...[/cyan]")
        tools = self.detector.detect_all()
        self.config["tools"]["detected"] = {name: info["installed"] for name, info in tools.items()}

        # Save configuration
        return self._save_configuration()

    def _setup_from_profile(self) -> bool:
        """Setup from existing profile"""
        profiles = self.profile_manager.list_profiles()

        if not profiles:
            console.print("[yellow]No profiles found. Using custom setup instead.[/yellow]")
            return self._interactive_setup()

        profile_name = questionary.select(
            "Select a profile:",
            choices=[Choice(p["description"], p["name"]) for p in profiles]
        ).ask()

        return self._setup_with_profile(profile_name)

    def _setup_with_profile(self, profile_name: str) -> bool:
        """Setup using a specific profile"""
        try:
            profile_config = self.profile_manager.load_profile(profile_name)
            self.config = profile_config

            console.print(f"\n[green]Loaded profile: {profile_name}[/green]")

            # Still need to get API keys
            if "llm" in self.config:
                api_key = questionary.password("Enter LLM API key:").ask()
                self.config["llm"]["api_key"] = api_key

            if "databases" in self.config and "neo4j" in self.config["databases"]:
                neo4j_password = questionary.password("Enter Neo4j password:").ask()
                self.config["databases"]["neo4j"]["password"] = neo4j_password

            return self._save_configuration()

        except Exception as e:
            console.print(f"[red]Failed to load profile: {e}[/red]")
            return False

    def _configure_llm(self):
        """Configure LLM provider"""
        provider = questionary.select(
            "Select LLM provider:",
            choices=[
                Choice("AWS Bedrock (recommended for production)", "bedrock"),
                Choice("Anthropic (direct API)", "anthropic"),
                Choice("OpenAI", "openai"),
                Choice("Ollama (local)", "ollama"),
            ]
        ).ask()

        self.config["llm"] = {"provider": provider}

        if provider == "bedrock":
            self.config["llm"]["region"] = questionary.text(
                "AWS Region:",
                default="us-east-1"
            ).ask()
            self.config["llm"]["model"] = questionary.select(
                "Select model:",
                choices=[
                    "anthropic.claude-3-5-sonnet-20241022-v2:0",
                    "anthropic.claude-3-5-haiku-20241022-v1:0",
                    "anthropic.claude-3-opus-20240229-v1:0",
                ]
            ).ask()
            console.print("[dim]Note: Make sure AWS credentials are configured (aws configure)[/dim]")

        elif provider == "anthropic":
            api_key = questionary.password("Anthropic API key:").ask()
            self.config["llm"]["api_key"] = api_key
            self.config["llm"]["model"] = questionary.select(
                "Select model:",
                choices=[
                    "claude-sonnet-4",
                    "claude-3-5-sonnet-20241022",
                    "claude-3-5-haiku-20241022",
                ]
            ).ask()

        elif provider == "openai":
            api_key = questionary.password("OpenAI API key:").ask()
            self.config["llm"]["api_key"] = api_key
            self.config["llm"]["model"] = questionary.select(
                "Select model:",
                choices=["gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"]
            ).ask()

        elif provider == "ollama":
            self.config["llm"]["base_url"] = questionary.text(
                "Ollama base URL:",
                default="http://localhost:11434"
            ).ask()
            self.config["llm"]["model"] = questionary.text(
                "Model name:",
                default="llama2"
            ).ask()

        # Common settings
        self.config["llm"]["temperature"] = float(questionary.text(
            "Temperature (0.0-1.0):",
            default="0.3"
        ).ask())

        self.config["llm"]["max_tokens"] = int(questionary.text(
            "Max tokens:",
            default="4096"
        ).ask())

    def _configure_databases(self):
        """Configure databases"""
        self.config["databases"] = {}

        # Neo4j (Graph DB)
        use_neo4j = questionary.confirm(
            "Configure Neo4j graph database?",
            default=True
        ).ask()

        if use_neo4j:
            self.config["databases"]["neo4j"] = {
                "uri": questionary.text(
                    "Neo4j URI:",
                    default="bolt://localhost:7687"
                ).ask(),
                "user": questionary.text(
                    "Neo4j user:",
                    default="neo4j"
                ).ask(),
                "password": questionary.password("Neo4j password:").ask(),
            }

        # ChromaDB (Vector DB)
        use_chroma = questionary.confirm(
            "Configure ChromaDB vector database?",
            default=True
        ).ask()

        if use_chroma:
            self.config["databases"]["chromadb"] = {
                "path": questionary.text(
                    "ChromaDB path:",
                    default=str(Path.home() / ".medusa" / "chromadb")
                ).ask(),
                "collection": questionary.text(
                    "Collection name:",
                    default="medusa_knowledge"
                ).ask(),
            }

    def _detect_tools(self):
        """Detect installed security tools"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Detecting tools...", total=None)
            tools = self.detector.detect_all()
            progress.update(task, completed=True)

        # Show results
        console.print("\n[bold]Detected Tools:[/bold]")
        installed = []
        missing = []

        for name, info in tools.items():
            if info["installed"]:
                console.print(f"  [green]✓[/green] {name} - {info['version'] or 'installed'}")
                installed.append(name)
            else:
                console.print(f"  [red]✗[/red] {name} - not found")
                missing.append(name)

        if missing:
            console.print(f"\n[yellow]Missing tools: {', '.join(missing)}[/yellow]")
            install = questionary.confirm(
                "Would you like instructions for installing missing tools?",
                default=False
            ).ask()

            if install:
                self._show_install_instructions(missing)

        self.config["tools"] = {
            "auto_detect": True,
            "detected": {name: info["installed"] for name, info in tools.items()}
        }

    def _configure_safety(self):
        """Configure safety settings"""
        self.config["safety"] = {}

        self.config["safety"]["require_authorization"] = questionary.confirm(
            "Require authorization before high-risk actions?",
            default=True
        ).ask()

        if questionary.confirm("Configure authorized scope (IP ranges)?", default=True).ask():
            scope = []
            while True:
                cidr = questionary.text(
                    "Enter IP/CIDR (or press Enter to finish):",
                    validate=lambda x: x == "" or self._validate_cidr(x)
                ).ask()

                if not cidr:
                    break
                scope.append(cidr)

            self.config["safety"]["authorized_scope"] = scope

        self.config["safety"]["auto_rollback"] = questionary.confirm(
            "Enable automatic rollback on failures?",
            default=True
        ).ask()

        self.config["safety"]["audit_log"] = questionary.text(
            "Audit log path:",
            default=str(Path.home() / ".medusa" / "audit.log")
        ).ask()

    def _configure_advanced(self):
        """Configure advanced settings"""
        # Output settings
        self.config["output"] = {
            "format": questionary.select(
                "Default output format:",
                choices=["rich", "json", "plain", "markdown"]
            ).ask(),
            "verbosity": questionary.select(
                "Verbosity level:",
                choices=["debug", "info", "warning", "error"]
            ).ask(),
        }

        # Performance settings
        self.config["performance"] = {
            "max_threads": int(questionary.text(
                "Maximum concurrent threads:",
                default="10"
            ).ask()),
            "timeout": int(questionary.text(
                "Default timeout (seconds):",
                default="300"
            ).ask()),
        }

    def _test_configuration(self) -> bool:
        """Test the configuration"""
        console.print("\n[cyan]Testing configuration...[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:

            # Test LLM connection
            task = progress.add_task("Testing LLM connection...", total=None)
            llm_ok = self._test_llm()
            progress.update(task, completed=True)

            if llm_ok:
                console.print("[green]✓ LLM connection successful[/green]")
            else:
                console.print("[red]✗ LLM connection failed[/red]")

            # Test databases
            if "databases" in self.config:
                if "neo4j" in self.config["databases"]:
                    task = progress.add_task("Testing Neo4j connection...", total=None)
                    neo4j_ok = self._test_neo4j()
                    progress.update(task, completed=True)

                    if neo4j_ok:
                        console.print("[green]✓ Neo4j connection successful[/green]")
                    else:
                        console.print("[red]✗ Neo4j connection failed[/red]")

                if "chromadb" in self.config["databases"]:
                    task = progress.add_task("Testing ChromaDB...", total=None)
                    chroma_ok = self._test_chromadb()
                    progress.update(task, completed=True)

                    if chroma_ok:
                        console.print("[green]✓ ChromaDB initialized successfully[/green]")
                    else:
                        console.print("[red]✗ ChromaDB initialization failed[/red]")

        return llm_ok  # At minimum, LLM must work

    def _test_llm(self) -> bool:
        """Test LLM connection"""
        try:
            # Import here to avoid circular dependency
            from medusa.core.llm.factory import LLMFactory

            llm = LLMFactory.create_from_config(self.config["llm"])
            response = llm.generate("Say 'OK' if you can read this", max_tokens=10)
            return bool(response)
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
            return False

    def _test_neo4j(self) -> bool:
        """Test Neo4j connection"""
        try:
            from neo4j import GraphDatabase

            config = self.config["databases"]["neo4j"]
            driver = GraphDatabase.driver(
                config["uri"],
                auth=(config["user"], config["password"])
            )

            with driver.session() as session:
                result = session.run("RETURN 1")
                result.single()

            driver.close()
            return True
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
            return False

    def _test_chromadb(self) -> bool:
        """Test ChromaDB initialization"""
        try:
            import chromadb

            config = self.config["databases"]["chromadb"]
            client = chromadb.PersistentClient(path=config["path"])

            # Try to get or create collection
            client.get_or_create_collection(name=config["collection"])
            return True
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
            return False

    def _save_configuration(self) -> bool:
        """Save configuration to file"""
        try:
            # Validate configuration
            is_valid, errors = self.validator.validate(self.config)

            if not is_valid:
                console.print("[red]Configuration validation failed:[/red]")
                for error in errors:
                    console.print(f"  - {error}")
                return False

            # Create config directory
            self.config_path.parent.mkdir(parents=True, exist_ok=True)

            # Save configuration
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)

            console.print(f"\n[green]✓ Configuration saved to {self.config_path}[/green]")

            # Show next steps
            console.print(Panel.fit(
                "[bold green]Setup Complete![/bold green]\n\n"
                "Next steps:\n"
                "1. Run 'medusa setup --verify' to verify configuration\n"
                "2. Run 'medusa quickstart' for a guided first scan\n"
                "3. See 'medusa --help' for all commands\n\n"
                "Happy hacking! 🎯",
                border_style="green"
            ))

            return True

        except Exception as e:
            console.print(f"[red]Failed to save configuration: {e}[/red]")
            return False

    def _show_install_instructions(self, tools: List[str]):
        """Show installation instructions for missing tools"""
        console.print("\n[bold]Installation Instructions:[/bold]\n")

        instructions = {
            "nmap": "sudo apt install nmap (Linux) or brew install nmap (macOS)",
            "masscan": "sudo apt install masscan (Linux) or brew install masscan (macOS)",
            "nuclei": "GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            "httpx": "GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "amass": "GO111MODULE=on go install -v github.com/owasp-amass/amass/v4/...@master",
            "ffuf": "GO111MODULE=on go install github.com/ffuf/ffuf/v2@latest",
            "gobuster": "GO111MODULE=on go install github.com/OJ/gobuster/v3@latest",
            "sqlmap": "sudo apt install sqlmap (Linux) or brew install sqlmap (macOS)",
            "metasploit": "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall",
        }

        for tool in tools:
            if tool in instructions:
                console.print(f"[cyan]{tool}:[/cyan] {instructions[tool]}")

        console.print("\n[dim]Or run: medusa tools --install-all[/dim]")

    def _validate_cidr(self, cidr: str) -> bool:
        """Validate CIDR notation"""
        try:
            import ipaddress
            ipaddress.ip_network(cidr)
            return True
        except ValueError:
            return False

    def verify_setup(self) -> bool:
        """Verify existing setup"""
        if not self.config_path.exists():
            console.print(f"[red]No configuration found at {self.config_path}[/red]")
            console.print("Run 'medusa setup' to configure MEDUSA")
            return False

        try:
            with open(self.config_path) as f:
                self.config = yaml.safe_load(f)

            is_valid, errors = self.validator.validate(self.config)

            if is_valid:
                console.print("[green]✓ Configuration is valid[/green]")

                # Test connections
                return self._test_configuration()
            else:
                console.print("[red]Configuration has errors:[/red]")
                for error in errors:
                    console.print(f"  - {error}")
                return False

        except Exception as e:
            console.print(f"[red]Failed to verify configuration: {e}[/red]")
            return False

    def reset_setup(self) -> bool:
        """Reset configuration to defaults"""
        if self.config_path.exists():
            backup = self.config_path.with_suffix('.yaml.bak')
            self.config_path.rename(backup)
            console.print(f"[yellow]Backed up existing config to {backup}[/yellow]")

        console.print("[green]Configuration reset. Run 'medusa setup' to reconfigure.[/green]")
        return True
