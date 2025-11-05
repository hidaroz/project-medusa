"""
Interactive shell mode for MEDUSA
User gives natural language commands, agent interprets and executes
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import InMemoryHistory
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False
    from rich.prompt import Prompt

from medusa.client import MedusaClient
from medusa.display import display
from medusa.approval import ApprovalGate, Action, RiskLevel
from medusa.config import get_config
from medusa.command_parser import CommandParser
from medusa.session import Session, CommandSuggester
from medusa.completers import MedusaCompleter, CommandAliasManager
from medusa.exporters import SessionExporter

console = Console()
logger = logging.getLogger(__name__)


class InteractiveMode:
    """Interactive shell mode for penetration testing"""

    def __init__(self, target: Optional[str] = None, api_key: str = ""):
        self.target = target
        self.api_key = api_key
        self.config = get_config()
        self.approval_gate = ApprovalGate()
        self.running = True

        # Initialize session management
        self.session = Session(target=target or "unknown")
        self.command_suggester = CommandSuggester()
        self.command_parser: Optional[CommandParser] = None  # Initialized when client is ready
        self.alias_manager = CommandAliasManager()

        # Setup prompt session with completion if available
        if PROMPT_TOOLKIT_AVAILABLE:
            self.prompt_session = PromptSession(
                history=InMemoryHistory(),
                completer=MedusaCompleter(),
                complete_while_typing=False,
            )
        else:
            self.prompt_session = None
            logger.warning("prompt_toolkit not available, tab completion disabled")

    async def run(self):
        """Start interactive shell"""
        display.show_banner()
        console.print()
        console.print(
            Panel(
                "[bold cyan]MEDUSA Interactive Shell[/bold cyan]\n\n"
                "Enter natural language commands to control the agent.\n"
                "Type [yellow]'help'[/yellow] for available commands or [yellow]'exit'[/yellow] to quit.\n"
                "Type [yellow]'suggestions'[/yellow] to see context-aware command suggestions.\n\n"
                f"Target: [green]{self.target or 'Not set'}[/green]\n"
                f"Session ID: [dim]{self.session.session_id}[/dim]",
                border_style="cyan",
            )
        )
        console.print()

        # Get LLM config from global config
        llm_config = self.config.get_llm_config()

        async with MedusaClient(self.target or "http://localhost:3001", self.api_key, llm_config=llm_config) as client:
            # Initialize command parser with LLM client
            self.command_parser = CommandParser(client.llm_client, target=self.target)

            # Show initial suggestions
            self._show_suggestions()

            while self.running:
                try:
                    # Get user command with tab completion
                    if self.prompt_session:
                        # Use prompt_toolkit for better input with completion
                        command = await asyncio.get_event_loop().run_in_executor(
                            None,
                            lambda: self.prompt_session.prompt("\nmedusa> ")
                        )
                    else:
                        # Fallback to rich prompt
                        from rich.prompt import Prompt
                        command = Prompt.ask("\n[bold cyan]medusa>[/bold cyan]", default="")

                    if not command.strip():
                        continue

                    # Resolve aliases
                    resolved_command = self.alias_manager.resolve(command.strip())
                    if resolved_command != command.strip():
                        console.print(f"[dim]→ {resolved_command}[/dim]")

                    # Process command
                    await self._process_command(resolved_command, client)

                except KeyboardInterrupt:
                    console.print("\n[yellow]Use 'exit' to quit[/yellow]")
                    continue
                except EOFError:
                    break

        # Save session on exit
        try:
            session_path = self.session.save()
            console.print(f"\n[dim]Session saved to: {session_path}[/dim]")
        except Exception as e:
            logger.error(f"Failed to save session: {e}")

        console.print("[dim]Session ended[/dim]")

    async def _process_command(self, command: str, client: MedusaClient):
        """Process user command using NL parsing"""
        cmd_lower = command.lower()

        # Built-in commands (handle before NL parsing for speed)
        if cmd_lower in ["exit", "quit", "q"]:
            self.running = False
            return

        elif cmd_lower == "help":
            self._show_help()
            return

        elif cmd_lower == "suggestions":
            self._show_suggestions()
            return

        elif cmd_lower.startswith("set target"):
            parts = command.split(maxsplit=2)
            if len(parts) >= 3:
                self.target = parts[2]
                self.session.update_context({"target": self.target})
                if self.command_parser:
                    self.command_parser.context["target"] = self.target
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

        elif cmd_lower == "show history":
            self._show_history()
            return

        elif cmd_lower == "show aliases":
            self._show_aliases()
            return

        elif cmd_lower.startswith("alias "):
            self._handle_alias_command(command[6:])  # Remove "alias "
            return

        elif cmd_lower.startswith("unalias "):
            alias_name = command[8:].strip()
            self.alias_manager.remove_alias(alias_name)
            console.print(f"[green]✓ Removed alias: {alias_name}[/green]")
            return

        elif cmd_lower.startswith("export "):
            self._handle_export_command(command[7:].strip())
            return

        elif cmd_lower == "clear":
            console.clear()
            return

        # Parse natural language command
        if not self.command_parser:
            console.print("[red]Error: Command parser not initialized[/red]")
            return

        # Show thinking indicator
        with console.status("[cyan]🤔 Understanding your command...", spinner="dots"):
            parsed = await self.command_parser.parse(command)

        # Check confidence level
        if parsed["confidence"] < 0.5:
            console.print(f"[yellow]⚠ {parsed.get('clarification', 'Command unclear')}[/yellow]")
            return

        # Show what we understood
        self._show_parsed_command(parsed)

        # Execute the action
        await self._execute_action(parsed, client)

    def _show_help(self):
        """Show available commands"""
        help_text = """
[bold cyan]Available Commands:[/bold cyan]

[yellow]Built-in Commands:[/yellow]
  help                       - Show this help message
  suggestions                - Show context-aware command suggestions
  set target <url>           - Set the target URL
  show context               - Display current session context
  show findings              - Display discovered findings
  show history               - Display command history
  show aliases               - Display command aliases
  alias <name> <command>     - Create a command alias
  unalias <name>             - Remove an alias
  export <format> [file]     - Export session (json, csv, html, markdown)
  clear                      - Clear the screen
  exit/quit                  - Exit the shell

[yellow]Command Aliases:[/yellow]
  s, scan                    - scan for open ports
  e, enum                    - enumerate services
  f, vulns                   - find vulnerabilities
  sqli, xss                  - test for SQL injection / XSS
  next                       - what should I do next?
  [dim]Use 'show aliases' to see all aliases[/dim]

[yellow]Natural Language Commands (examples):[/yellow]
  scan for open ports                    - Perform port scanning
  enumerate API endpoints                - Discover API endpoints
  find vulnerabilities                   - Scan for vulnerabilities
  test for SQL injection                 - Test SQL injection
  what should I do next?                 - Get AI recommendations
  show me all high severity findings     - Filter findings

[dim]💡 Tips:[/dim]
[dim]  • Use TAB for command completion[/dim]
[dim]  • Use natural language! The AI will understand your intent[/dim]
[dim]  • Create custom aliases for frequently used commands[/dim]
"""
        console.print(Panel(help_text, border_style="cyan"))

    def _show_suggestions(self):
        """Show context-aware command suggestions"""
        suggestions = self.command_suggester.get_suggestions(self.session.context)

        console.print("\n[bold cyan]💡 Suggested Commands:[/bold cyan]\n")
        for i, suggestion in enumerate(suggestions, 1):
            console.print(f"  [dim]{i}.[/dim] [yellow]{suggestion}[/yellow]")

        # Check if we should suggest moving to next phase
        phase_suggestion = self.command_suggester.get_next_phase_suggestion(
            self.session.context.get("phase", "reconnaissance"),
            len(self.session.findings)
        )
        if phase_suggestion:
            console.print(f"\n[cyan]💭 {phase_suggestion}[/cyan]")

    def _show_parsed_command(self, parsed: Dict[str, Any]):
        """Show what we understood from the command"""
        action = parsed.get("action", "unknown")
        confidence = parsed.get("confidence", 0.0)

        console.print(
            f"\n[dim]🤔 AI Understanding:[/dim] "
            f"[cyan]{action.replace('_', ' ').title()}[/cyan] "
            f"[dim](confidence: {confidence*100:.0f}%)[/dim]"
        )

        if parsed.get("clarification"):
            console.print(f"[yellow]   Note: {parsed['clarification']}[/yellow]")

    def _show_context(self):
        """Show current session context"""
        summary = self.session.get_summary()

        context_display = {
            "Target": summary["target"],
            "Session ID": summary["session_id"],
            "Duration": f"{summary['duration_seconds']:.1f}s",
            "Current Phase": summary["current_phase"],
            "Commands Executed": summary["commands_executed"],
            "Total Findings": summary["total_findings"],
            "Critical": summary["severity_counts"]["critical"],
            "High": summary["severity_counts"]["high"],
            "Medium": summary["severity_counts"]["medium"],
            "Techniques Used": summary["techniques_used"],
        }

        display.show_status_table(context_display, "Session Context")

    def _show_findings(self):
        """Show discovered findings"""
        if not self.session.findings:
            console.print("[dim]No findings yet[/dim]")
            return

        display.show_findings(self.session.findings)

    def _show_history(self):
        """Show command history"""
        history = self.session.command_history

        if not history:
            console.print("[dim]No commands in history[/dim]")
            return

        console.print("\n[bold cyan]Command History:[/bold cyan]\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=4)
        table.add_column("Time", style="cyan")
        table.add_column("Command", style="white")
        table.add_column("Phase", style="yellow")

        for i, entry in enumerate(history[-20:], 1):  # Show last 20
            timestamp = entry.get("timestamp", "")
            # Extract time from ISO format
            time_str = timestamp.split("T")[1][:8] if "T" in timestamp else timestamp
            command = entry.get("command", "")[:50]  # Truncate long commands
            phase = entry.get("phase", "unknown")

            table.add_row(str(i), time_str, command, phase)

        console.print(table)

    def _show_aliases(self):
        """Show all command aliases"""
        aliases = self.alias_manager.list_aliases()

        if not aliases:
            console.print("[dim]No aliases defined[/dim]")
            return

        console.print("\n[bold cyan]Command Aliases:[/bold cyan]\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Alias", style="yellow", no_wrap=True)
        table.add_column("Command", style="cyan")
        table.add_column("Category", style="dim")

        # Categorize aliases
        for alias, command in sorted(aliases.items()):
            # Determine category
            if len(alias) == 1:
                category = "shortcut"
            elif "scan" in command.lower():
                category = "scanning"
            elif "enum" in command.lower():
                category = "enumeration"
            elif "test" in command.lower() or "sql" in command.lower() or "xss" in command.lower():
                category = "testing"
            elif "show" in command.lower():
                category = "display"
            else:
                category = "other"

            table.add_row(alias, command[:60], category)

        console.print(table)
        console.print("\n[dim]💡 Tip: Use 'alias myalias command' to create custom aliases[/dim]")

    def _handle_alias_command(self, args: str):
        """Handle alias creation command"""
        parts = args.split(maxsplit=1)

        if len(parts) < 2:
            console.print("[red]Usage: alias <name> <command>[/red]")
            console.print("[yellow]Example: alias myscan scan for open ports[/yellow]")
            return

        alias_name = parts[0]
        command = parts[1]

        self.alias_manager.add_alias(alias_name, command)
        console.print(f"[green]✓ Created alias: {alias_name} → {command}[/green]")

    def _handle_export_command(self, args: str):
        """Handle session export command"""
        parts = args.split(maxsplit=1)

        if len(parts) < 1:
            console.print("[red]Usage: export <format> [filename][/red]")
            console.print("[yellow]Formats: json, csv, html, markdown[/yellow]")
            console.print("[yellow]Example: export html my_report.html[/yellow]")
            return

        export_format = parts[0].lower()
        filename = parts[1] if len(parts) > 1 else None

        # Generate default filename if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            extensions = {
                "json": "json",
                "csv": "csv",
                "html": "html",
                "markdown": "md",
                "md": "md"
            }
            ext = extensions.get(export_format, "txt")
            filename = f"medusa_report_{timestamp}.{ext}"

        try:
            # Prepare session data
            session_data = {
                "metadata": self.session.metadata,
                "target": self.session.target,
                "command_history": self.session.command_history,
                "findings": self.session.findings,
                "context": self.session.context,
                "summary": self.session.get_summary()
            }

            # Export based on format
            if export_format == "json":
                with open(filename, 'w') as f:
                    json.dump(session_data, f, indent=2)
                console.print(f"[green]✓ Exported to JSON: {filename}[/green]")

            elif export_format == "csv":
                filepath = SessionExporter.export_to_csv(session_data, filename)
                console.print(f"[green]✓ Exported findings to CSV: {filepath}[/green]")

            elif export_format == "html":
                filepath = SessionExporter.export_to_html(session_data, filename)
                console.print(f"[green]✓ Exported to HTML: {filepath}[/green]")
                console.print(f"[dim]Open {filepath} in your browser to view the report[/dim]")

            elif export_format in ["markdown", "md"]:
                filepath = SessionExporter.export_to_markdown(session_data, filename)
                console.print(f"[green]✓ Exported to Markdown: {filepath}[/green]")

            else:
                console.print(f"[red]Unknown export format: {export_format}[/red]")
                console.print("[yellow]Supported formats: json, csv, html, markdown[/yellow]")

        except Exception as e:
            console.print(f"[red]Export failed: {e}[/red]")
            logger.error(f"Export error: {e}", exc_info=True)

    async def _execute_action(self, parsed: Dict[str, Any], client: MedusaClient):
        """Execute parsed action"""
        action = parsed.get("action")

        # Map actions to execution methods
        action_map = {
            "port_scan": self._cmd_port_scan,
            "enumerate_services": self._cmd_enumerate_services,
            "scan_vulnerabilities": self._cmd_scan_vulnerabilities,
            "sqli_test": self._cmd_sqli_test,
            "xss_test": self._cmd_xss_test,
            "exploit": self._cmd_exploit,
            "exfiltrate_data": self._cmd_exfiltrate_data,
            "show_findings": self._cmd_show_findings_filtered,
            "what_next": self._cmd_what_next,
        }

        # Get the execution method
        executor = action_map.get(action)

        if not executor:
            console.print(f"[yellow]⚠ Unknown action: {action}[/yellow]")
            return

        # Execute the action
        try:
            result = await executor(client, parsed)

            # Record in session
            self.session.add_command(parsed.get("original_input", ""), result or {})

        except Exception as e:
            logger.error(f"Error executing action {action}: {e}", exc_info=True)
            console.print(f"[red]✗ Error: {e}[/red]")

    async def _cmd_port_scan(self, client: MedusaClient, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Execute port scan"""
        target = parsed.get("target", self.target)

        display.show_agent_thinking(
            f"I'll perform a port scan on {target} to identify open ports and running services."
        )

        # Request approval
        action = Action(
            command=f"nmap -sV {target}",
            technique_id="T1046",
            technique_name="Network Service Discovery",
            risk_level=RiskLevel.LOW,
            impact_description="Scan network services (read-only)",
            target=target,
        )

        if not self.approval_gate.request_approval(action):
            return {"status": "declined"}

        # Execute scan
        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Scanning network...", total=100)
            for i in range(0, 100, 25):
                await asyncio.sleep(0.4)
                progress.update(task, advance=25)

            result = await client.perform_reconnaissance(target)
            progress.update(task, completed=100)

        # Store results in session
        for finding in result.get("findings", []):
            self.session.add_finding(finding)

        for technique in result.get("techniques", []):
            self.session.add_technique(technique["id"], technique["name"])

        # Update phase
        self.session.update_phase("reconnaissance")

        # Display results
        console.print(f"\n[green]✓ Scan complete! Found {len(result['findings'])} items[/green]")
        if result.get("findings"):
            display.show_findings(result["findings"][:5])

        return result

    async def _cmd_enumerate_services(self, client: MedusaClient, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Enumerate services and endpoints"""
        target = parsed.get("target", self.target)

        display.show_agent_thinking(f"I'll enumerate services and API endpoints on {target}.")

        action = Action(
            command="API enumeration",
            technique_id="T1590",
            technique_name="Gather Victim Network Information",
            risk_level=RiskLevel.LOW,
            impact_description="Enumerate services and endpoints",
            target=target,
        )

        if not self.approval_gate.request_approval(action):
            return {"status": "declined"}

        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Enumerating services...", total=100)
            for i in range(0, 100, 33):
                await asyncio.sleep(0.5)
                progress.update(task, advance=33)

            result = await client.enumerate_services(target)
            progress.update(task, completed=100)

        # Store results
        for finding in result.get("findings", []):
            self.session.add_finding(finding)

        for technique in result.get("techniques", []):
            self.session.add_technique(technique["id"], technique["name"])

        self.session.update_phase("enumeration")

        console.print(f"\n[green]✓ Enumeration complete! Found {len(result['findings'])} items[/green]")
        if result.get("findings"):
            display.show_findings(result["findings"][:5])

        return result

    async def _cmd_scan_vulnerabilities(self, client: MedusaClient, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Scan for vulnerabilities"""
        console.print("[cyan]Scanning for vulnerabilities...[/cyan]")

        vulnerabilities = self.session.get_findings_by_type("vulnerability")

        if vulnerabilities:
            console.print(f"\n[green]Found {len(vulnerabilities)} vulnerabilities:[/green]")
            display.show_findings(vulnerabilities)
        else:
            console.print("[yellow]No vulnerabilities found yet. Try 'enumerate services' first.[/yellow]")

        return {"vulnerabilities": vulnerabilities}

    async def _cmd_sqli_test(self, client: MedusaClient, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Test for SQL injection"""
        target = parsed.get("target", self.target)

        display.show_agent_thinking(f"I'll test {target} for SQL injection vulnerabilities.")

        action = Action(
            command=f"sqlmap -u {target}",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            risk_level=RiskLevel.MEDIUM,
            impact_description="Test for SQL injection (may trigger alerts)",
            target=target,
        )

        if not self.approval_gate.request_approval(action):
            return {"status": "declined"}

        # Simulate SQL injection testing
        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Testing SQL injection...", total=100)
            for i in range(0, 100, 25):
                await asyncio.sleep(0.5)
                progress.update(task, advance=25)

        console.print("[green]✓ SQL injection test complete[/green]")
        console.print("[yellow]Found potential SQL injection vulnerability[/yellow]")

        # Add finding
        finding = {
            "type": "vulnerability",
            "severity": "high",
            "title": "SQL Injection",
            "description": "Potential SQL injection in search parameter"
        }
        self.session.add_finding(finding)

        return {"status": "complete", "finding": finding}

    async def _cmd_xss_test(self, client: MedusaClient, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Test for XSS vulnerabilities"""
        target = parsed.get("target", self.target)

        display.show_agent_thinking(f"I'll test {target} for XSS vulnerabilities.")

        console.print("[green]✓ XSS test complete[/green]")

        return {"status": "complete"}

    async def _cmd_exploit(self, client: MedusaClient, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt exploitation"""
        target = parsed.get("target", self.target)

        display.show_agent_thinking(f"Attempting to exploit vulnerability on {target}")

        action = Action(
            command="Exploitation attempt",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            risk_level=RiskLevel.MEDIUM,
            impact_description="Attempt to exploit identified vulnerability",
            target=target,
        )

        if not self.approval_gate.request_approval(action):
            return {"status": "declined"}

        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Attempting exploitation...", total=100)
            for i in range(0, 100, 25):
                await asyncio.sleep(0.6)
                progress.update(task, advance=25)

            result = await client.attempt_exploitation(target, {})
            progress.update(task, completed=100)

        if result["status"] == "success":
            display.show_success("Exploitation successful!", title="Success")
            console.print(f"[green]Access gained: {result['result']['access_gained']}[/green]")
        else:
            display.show_warning(f"Exploitation failed: {result.get('error', 'Unknown')}")

        return result

    async def _cmd_exfiltrate_data(self, client: MedusaClient, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Exfiltrate data"""
        target = parsed.get("target", self.target)

        display.show_agent_thinking("Preparing to exfiltrate sensitive data from the target.")

        action = Action(
            command="Data exfiltration",
            technique_id="T1041",
            technique_name="Exfiltration Over C2 Channel",
            risk_level=RiskLevel.HIGH,
            impact_description="Extract sensitive data from target system",
            target=target,
            data_at_risk="Medical records, PII",
        )

        if not self.approval_gate.request_approval(action):
            return {"status": "declined"}

        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Exfiltrating data...", total=100)
            for i in range(0, 100, 20):
                await asyncio.sleep(0.5)
                progress.update(task, advance=20)

            result = await client.exfiltrate_data(target, "medical_records")
            progress.update(task, completed=100)

        console.print(f"\n[green]✓ Exfiltrated {result['records_exfiltrated']} records[/green]")
        console.print(f"[green]Estimated value: ${result['estimated_value']:,}[/green]")

        return result

    async def _cmd_show_findings_filtered(self, client: MedusaClient, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Show filtered findings"""
        params = parsed.get("parameters", {})
        severity = params.get("severity")
        finding_type = params.get("type")

        findings = self.session.findings

        if severity:
            findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]

        if finding_type:
            findings = [f for f in findings if f.get("type", "").lower() == finding_type.lower()]

        if findings:
            display.show_findings(findings)
        else:
            console.print("[dim]No matching findings[/dim]")

        return {"findings": findings}

    async def _cmd_what_next(self, client: MedusaClient, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Get AI recommendation for next steps"""
        console.print("[cyan]💭 Analyzing current situation...[/cyan]\n")

        # Get AI recommendation
        context = {
            "phase": self.session.context.get("phase", "reconnaissance"),
            "findings": self.session.findings[-10:],  # Last 10 findings
            "target": self.target
        }

        with console.status("[cyan]Thinking...", spinner="dots"):
            recommendation = await client.get_ai_recommendation(context)

        # Display recommendations
        console.print("[bold yellow]AI Recommendations:[/bold yellow]\n")

        for i, rec in enumerate(recommendation.get("recommendations", []), 1):
            console.print(f"[cyan]{i}. {rec['action'].replace('_', ' ').title()}[/cyan]")
            console.print(f"   Confidence: {rec['confidence']*100:.0f}%")
            console.print(f"   Reasoning: [dim]{rec['reasoning']}[/dim]")
            console.print(f"   Risk: [{self._risk_color(rec['risk_level'])}]{rec['risk_level']}[/{self._risk_color(rec['risk_level'])}]")
            console.print()

        # Also show command suggestions
        self._show_suggestions()

        return recommendation

    def _risk_color(self, risk_level: str) -> str:
        """Get color for risk level"""
        colors = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}
        return colors.get(risk_level, "white")
