"""
Interactive shell mode for MEDUSA
User gives natural language commands, agent interprets and executes
"""

import asyncio
from typing import Dict, Any, Optional
from datetime import datetime

from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel

from medusa.client import MedusaClient
from medusa.display import display
from medusa.approval import ApprovalGate, Action, RiskLevel
from medusa.config import get_config

console = Console()


class InteractiveMode:
    """Interactive shell mode for penetration testing"""

    def __init__(self, target: Optional[str] = None, api_key: str = ""):
        self.target = target
        self.api_key = api_key
        self.config = get_config()
        self.approval_gate = ApprovalGate()
        self.context: Dict[str, Any] = {
            "target": target,
            "session_started": datetime.now().isoformat(),
            "findings": [],
            "techniques_used": [],
        }
        self.running = True

    async def run(self):
        """Start interactive shell"""
        display.show_banner()
        console.print()
        console.print(
            Panel(
                "[bold cyan]MEDUSA Interactive Shell[/bold cyan]\n\n"
                "Enter natural language commands to control the agent.\n"
                "Type [yellow]'help'[/yellow] for available commands or [yellow]'exit'[/yellow] to quit.\n\n"
                f"Target: [green]{self.target or 'Not set'}[/green]",
                border_style="cyan",
            )
        )
        console.print()
        
        # Get LLM config from global config
        llm_config = self.config.get_llm_config()

        async with MedusaClient(self.target or "http://localhost:3001", self.api_key, llm_config=llm_config) as client:
            while self.running:
                try:
                    # Get user command
                    command = Prompt.ask("\n[bold cyan]MEDUSA>[/bold cyan]", default="")

                    if not command.strip():
                        continue

                    # Process command
                    await self._process_command(command.strip(), client)

                except KeyboardInterrupt:
                    console.print("\n[yellow]Use 'exit' to quit[/yellow]")
                    continue
                except EOFError:
                    break

        console.print("\n[dim]Session ended[/dim]")

    async def _process_command(self, command: str, client: MedusaClient):
        """Process user command"""
        cmd_lower = command.lower()

        # Built-in commands
        if cmd_lower in ["exit", "quit", "q"]:
            self.running = False
            return

        elif cmd_lower == "help":
            self._show_help()
            return

        elif cmd_lower.startswith("set target"):
            parts = command.split(maxsplit=2)
            if len(parts) >= 3:
                self.target = parts[2]
                self.context["target"] = self.target
                console.print(f"[green]✓ Target set to: {self.target}[/green]")
            else:
                console.print("[red]Usage: set target <url>[/red]")
            return

        elif cmd_lower == "show context":
            self._show_context()
            return

        elif cmd_lower == "show findings":
            self._show_findings()
            return

        elif cmd_lower == "clear":
            console.clear()
            return

        # Natural language commands - interpret with AI
        await self._execute_natural_command(command, client)

    def _show_help(self):
        """Show available commands"""
        help_text = """
[bold cyan]Available Commands:[/bold cyan]

[yellow]Built-in Commands:[/yellow]
  help                    - Show this help message
  set target <url>        - Set the target URL
  show context            - Display current session context
  show findings           - Display discovered findings
  clear                   - Clear the screen
  exit/quit               - Exit the shell

[yellow]Natural Language Commands (examples):[/yellow]
  scan network            - Perform network reconnaissance
  enumerate services      - Discover services and endpoints
  find vulnerabilities    - Scan for security vulnerabilities
  exploit sql injection   - Attempt SQL injection exploitation
  exfiltrate data         - Extract sensitive data
  show attack surface     - Display identified attack vectors

[dim]The agent will interpret your commands and execute appropriate actions.[/dim]
"""
        console.print(Panel(help_text, border_style="cyan"))

    def _show_context(self):
        """Show current session context"""
        context_display = {
            "Target": self.context.get("target", "Not set"),
            "Session Started": self.context.get("session_started", "Unknown"),
            "Findings": len(self.context.get("findings", [])),
            "Techniques Used": len(self.context.get("techniques_used", [])),
        }

        display.show_status_table(context_display, "Session Context")

    def _show_findings(self):
        """Show discovered findings"""
        findings = self.context.get("findings", [])

        if not findings:
            console.print("[dim]No findings yet[/dim]")
            return

        display.show_findings(findings)

    async def _execute_natural_command(self, command: str, client: MedusaClient):
        """Execute a natural language command"""
        console.print(f"[dim]Interpreting command: {command}[/dim]")

        # Simple keyword matching (in production, use LLM to interpret)
        cmd_lower = command.lower()

        if any(keyword in cmd_lower for keyword in ["scan", "recon", "reconnaissance", "network"]):
            await self._cmd_scan_network(client)

        elif any(keyword in cmd_lower for keyword in ["enumerate", "services", "endpoints"]):
            await self._cmd_enumerate_services(client)

        elif any(
            keyword in cmd_lower for keyword in ["vulnerabilities", "vulns", "weaknesses", "find"]
        ):
            await self._cmd_find_vulnerabilities(client)

        elif any(keyword in cmd_lower for keyword in ["exploit", "attack"]):
            await self._cmd_exploit(client, command)

        elif any(keyword in cmd_lower for keyword in ["exfiltrate", "extract", "steal", "data"]):
            await self._cmd_exfiltrate_data(client)

        else:
            console.print(
                "[yellow]⚠ Command not recognized. Type 'help' for available commands.[/yellow]"
            )

    async def _cmd_scan_network(self, client: MedusaClient):
        """Execute network scan"""
        display.show_agent_thinking(
            "I'll perform a network scan to identify open ports and running services."
        )

        # Request approval
        action = Action(
            command=f"nmap -sV {self.target}",
            technique_id="T1046",
            technique_name="Network Service Discovery",
            risk_level=RiskLevel.LOW,
            impact_description="Scan network services (read-only)",
            target=self.target,
        )

        if not self.approval_gate.request_approval(action):
            return

        # Execute scan
        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Scanning network...", total=100)
            for i in range(0, 100, 25):
                await asyncio.sleep(0.4)
                progress.update(task, advance=25)

            result = await client.perform_reconnaissance(self.target)
            progress.update(task, completed=100)

        # Store results
        self.context["findings"].extend(result["findings"])
        self.context["techniques_used"].extend(result["techniques"])

        # Display results
        console.print(f"\n[green]✓ Scan complete! Found {len(result['findings'])} items[/green]")
        display.show_findings(result["findings"][:5])

    async def _cmd_enumerate_services(self, client: MedusaClient):
        """Enumerate services and endpoints"""
        display.show_agent_thinking("I'll enumerate API endpoints and identify potential vulnerabilities.")

        action = Action(
            command="API enumeration",
            technique_id="T1590",
            technique_name="Gather Victim Network Information",
            risk_level=RiskLevel.LOW,
            impact_description="Enumerate services and endpoints",
            target=self.target,
        )

        if not self.approval_gate.request_approval(action):
            return

        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Enumerating services...", total=100)
            for i in range(0, 100, 33):
                await asyncio.sleep(0.5)
                progress.update(task, advance=33)

            result = await client.enumerate_services(self.target)
            progress.update(task, completed=100)

        self.context["findings"].extend(result["findings"])
        self.context["techniques_used"].extend(result["techniques"])

        console.print(f"\n[green]✓ Enumeration complete! Found {len(result['findings'])} items[/green]")
        display.show_findings(result["findings"][:5])

    async def _cmd_find_vulnerabilities(self, client: MedusaClient):
        """Find vulnerabilities"""
        console.print("[cyan]Analyzing for vulnerabilities...[/cyan]")

        # Simulate vulnerability scanning
        await asyncio.sleep(1)

        vulnerabilities = [
            f for f in self.context.get("findings", []) if f.get("type") == "vulnerability"
        ]

        if vulnerabilities:
            console.print(f"\n[green]Found {len(vulnerabilities)} vulnerabilities:[/green]")
            display.show_findings(vulnerabilities)
        else:
            console.print("[yellow]No vulnerabilities in current context. Run 'enumerate services' first.[/yellow]")

    async def _cmd_exploit(self, client: MedusaClient, command: str):
        """Attempt exploitation"""
        display.show_agent_thinking(
            f"Attempting to exploit vulnerability based on command: {command}"
        )

        action = Action(
            command=command,
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            risk_level=RiskLevel.MEDIUM,
            impact_description="Attempt to exploit identified vulnerability",
            target=self.target,
        )

        if not self.approval_gate.request_approval(action):
            return

        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Attempting exploitation...", total=100)
            for i in range(0, 100, 25):
                await asyncio.sleep(0.6)
                progress.update(task, advance=25)

            result = await client.attempt_exploitation(self.target, {})
            progress.update(task, completed=100)

        if result["status"] == "success":
            display.show_success("Exploitation successful!", title="Success")
            console.print(f"[green]Access gained: {result['result']['access_gained']}[/green]")
        else:
            display.show_warning(f"Exploitation failed: {result.get('error', 'Unknown')}")

    async def _cmd_exfiltrate_data(self, client: MedusaClient):
        """Exfiltrate data"""
        display.show_agent_thinking("Preparing to exfiltrate sensitive data from the target.")

        action = Action(
            command="Data exfiltration",
            technique_id="T1041",
            technique_name="Exfiltration Over C2 Channel",
            risk_level=RiskLevel.HIGH,
            impact_description="Extract sensitive data from target system",
            target=self.target,
            data_at_risk="Medical records, PII",
        )

        if not self.approval_gate.request_approval(action):
            return

        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Exfiltrating data...", total=100)
            for i in range(0, 100, 20):
                await asyncio.sleep(0.5)
                progress.update(task, advance=20)

            result = await client.exfiltrate_data(self.target, "medical_records")
            progress.update(task, completed=100)

        console.print(
            f"\n[green]✓ Exfiltrated {result['records_exfiltrated']} records[/green]"
        )
        console.print(f"[green]Estimated value: ${result['estimated_value']:,}[/green]")

