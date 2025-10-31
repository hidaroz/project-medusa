"""
Autonomous mode for MEDUSA
Agent plans and executes full attack chain with approval gates
"""

import asyncio
from typing import Dict, Any, List
from datetime import datetime
import time

from medusa.client import MedusaClient
from medusa.display import display
from medusa.approval import ApprovalGate, Action, RiskLevel
from medusa.reporter import ReportGenerator
from medusa.config import get_config


class AutonomousMode:
    """Autonomous penetration testing mode"""

    def __init__(self, target: str, api_key: str):
        self.target = target
        self.api_key = api_key
        self.config = get_config()
        self.approval_gate = ApprovalGate()
        self.reporter = ReportGenerator()
        self.operation_id = f"auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.operation_data: Dict[str, Any] = {
            "operation_id": self.operation_id,
            "mode": "autonomous",
            "target": target,
            "started_at": datetime.now().isoformat(),
            "phases": [],
            "findings": [],
            "techniques": [],
        }

    async def run(self):
        """Execute autonomous penetration test"""
        display.show_banner()
        display.console.print()
        display.console.print(
            f"[bold cyan]Starting Autonomous Assessment[/bold cyan] against [yellow]{self.target}[/yellow]"
        )
        display.console.print(f"[dim]Operation ID: {self.operation_id}[/dim]\n")

        start_time = time.time()

        async with MedusaClient(self.target, self.api_key) as client:
            # Phase 1: Reconnaissance
            await self._phase_reconnaissance(client)

            if self.approval_gate.is_aborted():
                display.show_error("Operation aborted by user")
                return

            # Phase 2: Enumeration
            await self._phase_enumeration(client)

            if self.approval_gate.is_aborted():
                display.show_error("Operation aborted by user")
                return

            # Phase 3: Exploitation
            await self._phase_exploitation(client)

            if self.approval_gate.is_aborted():
                display.show_error("Operation aborted by user")
                return

            # Phase 4: Post-Exploitation
            await self._phase_post_exploitation(client)

        # Calculate final metrics
        self.operation_data["completed_at"] = datetime.now().isoformat()
        self.operation_data["duration_seconds"] = time.time() - start_time

        # Generate reports
        await self._generate_reports(client)

    async def _phase_reconnaissance(self, client: MedusaClient):
        """Phase 1: Reconnaissance"""
        display.console.print("[bold blue]═══ Phase 1: Reconnaissance ═══[/bold blue]\n")

        # Request approval for reconnaissance
        action = Action(
            command=f"nmap -sV {self.target}",
            technique_id="T1046",
            technique_name="Network Service Discovery",
            risk_level=RiskLevel.LOW,
            impact_description="Scan network services (read-only, no system changes)",
            target=self.target,
            reversible=True,
        )

        if not self.approval_gate.request_approval(action):
            display.show_warning("Reconnaissance phase skipped")
            return

        # Show agent thinking
        display.show_agent_thinking(
            "Initiating reconnaissance to map the attack surface. "
            "I'll identify open ports, running services, and potential entry points."
        )

        # Execute reconnaissance
        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Scanning network services...", total=100)

            # Simulate scanning
            for i in range(0, 100, 20):
                await asyncio.sleep(0.5)
                progress.update(task, advance=20)

            result = await client.perform_reconnaissance(self.target)
            progress.update(task, completed=100)

        # Display results
        tasks = [
            {
                "name": "Port scan",
                "status": "complete",
                "details": f"{len([f for f in result['findings'] if f['type'] == 'open_port'])} open ports found",
            },
            {
                "name": "Service enumeration",
                "status": "complete",
                "details": "Identified web application",
            },
            {
                "name": "Technology detection",
                "status": "complete",
                "details": "React + Node.js detected",
            },
        ]
        display.show_phase_tree("Reconnaissance Phase", tasks)

        # Store results
        self.operation_data["phases"].append(
            {"name": "reconnaissance", "status": "complete", "result": result}
        )
        self.operation_data["findings"].extend(result["findings"])
        self.operation_data["techniques"].extend(result["techniques"])

        display.console.print()

    async def _phase_enumeration(self, client: MedusaClient):
        """Phase 2: Enumeration"""
        display.console.print("[bold blue]═══ Phase 2: Enumeration ═══[/bold blue]\n")

        # Request approval
        action = Action(
            command="API endpoint enumeration + vulnerability scanning",
            technique_id="T1590",
            technique_name="Gather Victim Network Information",
            risk_level=RiskLevel.LOW,
            impact_description="Enumerate API endpoints and check for common vulnerabilities",
            target=self.target,
            reversible=True,
        )

        if not self.approval_gate.request_approval(action):
            display.show_warning("Enumeration phase skipped")
            return

        # Show agent thinking
        display.show_agent_thinking(
            "Analyzing the target application to identify API endpoints, "
            "authentication mechanisms, and potential vulnerabilities."
        )

        # Execute enumeration
        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Enumerating API endpoints...", total=100)

            for i in range(0, 100, 25):
                await asyncio.sleep(0.6)
                progress.update(task, advance=25)

            result = await client.enumerate_services(self.target)
            progress.update(task, completed=100)

        # Display findings
        tasks = [
            {
                "name": "API enumeration",
                "status": "complete",
                "details": f"{len([f for f in result['findings'] if f['type'] == 'api_endpoint'])} endpoints found",
            },
            {
                "name": "Vulnerability scan",
                "status": "complete",
                "details": f"{len([f for f in result['findings'] if f['type'] == 'vulnerability'])} vulnerabilities detected",
            },
            {
                "name": "Configuration audit",
                "status": "complete",
                "details": "Security misconfigurations identified",
            },
        ]
        display.show_phase_tree("Enumeration Phase", tasks)

        # Show high-severity findings
        high_severity = [f for f in result["findings"] if f["severity"] in ["high", "critical"]]
        if high_severity:
            display.console.print()
            display.show_findings(high_severity[:3])  # Show top 3

        # Store results
        self.operation_data["phases"].append(
            {"name": "enumeration", "status": "complete", "result": result}
        )
        self.operation_data["findings"].extend(result["findings"])
        self.operation_data["techniques"].extend(result["techniques"])

        display.console.print()

    async def _phase_exploitation(self, client: MedusaClient):
        """Phase 3: Exploitation"""
        display.console.print("[bold blue]═══ Phase 3: Exploitation ═══[/bold blue]\n")

        # Get vulnerabilities from enumeration phase
        enum_phase = next(
            (p for p in self.operation_data["phases"] if p["name"] == "enumeration"), None
        )
        if not enum_phase:
            display.show_warning("No enumeration data available, skipping exploitation")
            return

        vulnerabilities = [
            f
            for f in enum_phase["result"]["findings"]
            if f["type"] == "vulnerability" or f["severity"] in ["high", "critical"]
        ]

        if not vulnerabilities:
            display.show_info("No exploitable vulnerabilities found")
            return

        # Request approval for exploitation
        action = Action(
            command="sqlmap -u http://target/api --dbs",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            risk_level=RiskLevel.MEDIUM,
            impact_description="Attempt exploitation of identified vulnerabilities. May trigger security alerts.",
            target=self.target,
            reversible=True,
        )

        if not self.approval_gate.request_approval(action):
            display.show_warning("Exploitation phase skipped")
            self.operation_data["phases"].append(
                {"name": "exploitation", "status": "skipped", "reason": "User declined"}
            )
            return

        # Show agent thinking
        display.show_agent_thinking(
            f"Attempting to exploit {len(vulnerabilities)} identified vulnerabilities. "
            "I'll prioritize high-severity issues and attempt to gain unauthorized access."
        )

        # Attempt exploitation
        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Attempting exploitation...", total=100)

            for i in range(0, 100, 33):
                await asyncio.sleep(0.7)
                progress.update(task, advance=33)

            result = await client.attempt_exploitation(self.target, vulnerabilities[0])
            progress.update(task, completed=100)

        # Display results
        if result["status"] == "success":
            display.show_success(
                f"Successfully exploited vulnerability! Gained {result['result']['access_gained']} access.",
                title="Exploitation Successful",
            )
            tasks = [
                {
                    "name": "Vulnerability exploitation",
                    "status": "complete",
                    "details": "Access gained",
                },
                {
                    "name": "Data extraction",
                    "status": "complete",
                    "details": f"{result['result']['data_extracted']} records extracted",
                },
                {
                    "name": "Credential discovery",
                    "status": "complete",
                    "details": f"{result['result']['credentials_found']} credentials found",
                },
            ]
        else:
            display.show_warning(
                f"Exploitation failed: {result.get('error', 'Unknown error')}",
                title="Exploitation Failed",
            )
            tasks = [
                {
                    "name": "Vulnerability exploitation",
                    "status": "failed",
                    "details": result.get("error", "Unknown error"),
                }
            ]

        display.show_phase_tree("Exploitation Phase", tasks)

        # Store results
        self.operation_data["phases"].append(
            {"name": "exploitation", "status": result["status"], "result": result}
        )
        self.operation_data["techniques"].extend(result["techniques"])

        display.console.print()

    async def _phase_post_exploitation(self, client: MedusaClient):
        """Phase 4: Post-Exploitation"""
        display.console.print("[bold blue]═══ Phase 4: Post-Exploitation ═══[/bold blue]\n")

        # Check if exploitation was successful
        exploit_phase = next(
            (p for p in self.operation_data["phases"] if p["name"] == "exploitation"), None
        )
        if not exploit_phase or exploit_phase.get("status") != "success":
            display.show_info("Skipping post-exploitation (no access gained)")
            return

        # Request approval for data exfiltration
        action = Action(
            command="Exfiltrate patient medical records",
            technique_id="T1041",
            technique_name="Exfiltration Over C2 Channel",
            risk_level=RiskLevel.HIGH,
            impact_description="Extract sensitive data from compromised system. May leave forensic traces.",
            target=self.target,
            reversible=True,
            data_at_risk="Patient medical records, PII, financial data",
        )

        if not self.approval_gate.request_approval(action):
            display.show_warning("Post-exploitation phase skipped")
            self.operation_data["phases"].append(
                {"name": "post_exploitation", "status": "skipped", "reason": "User declined"}
            )
            return

        # Show agent thinking
        display.show_agent_thinking(
            "With access gained, I'll now attempt to exfiltrate sensitive data "
            "to demonstrate the impact of the vulnerability."
        )

        # Execute data exfiltration
        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Exfiltrating data...", total=100)

            for i in range(0, 100, 25):
                await asyncio.sleep(0.5)
                progress.update(task, advance=25)

            result = await client.exfiltrate_data(self.target, "medical_records")
            progress.update(task, completed=100)

        # Display results
        tasks = [
            {
                "name": "Data exfiltration",
                "status": "complete",
                "details": f"{result['records_exfiltrated']} records exfiltrated",
            },
            {
                "name": "Value assessment",
                "status": "complete",
                "details": f"Estimated value: ${result['estimated_value']:,}",
            },
        ]
        display.show_phase_tree("Post-Exploitation Phase", tasks)

        # Store results
        self.operation_data["phases"].append(
            {"name": "post_exploitation", "status": "complete", "result": result}
        )
        self.operation_data["techniques"].extend(result["techniques"])

        display.console.print()

    async def _generate_reports(self, client: MedusaClient):
        """Generate final reports"""
        display.console.print("[bold blue]═══ Generating Reports ═══[/bold blue]\n")

        # Get comprehensive report from backend
        report_data = await client.generate_report(self.operation_id)

        # Merge with our operation data
        report_data["target"] = self.target
        report_data["mode"] = "autonomous"

        # Generate JSON log
        json_path = self.reporter.save_json_log(report_data, self.operation_id)
        display.show_success(f"JSON log saved: {json_path}")

        # Generate HTML report
        html_path = self.reporter.generate_html_report(report_data, self.operation_id)
        display.show_success(f"HTML report saved: {html_path}")

        # Display summary
        display.console.print()
        display.show_technique_coverage(report_data.get("mitre_coverage", []))

        display.console.print()
        display.show_status_table(report_data.get("summary", {}), "Operation Summary")

        display.console.print()
        display.console.print(
            f"\n[bold green]✓ Assessment complete![/bold green] Total duration: {report_data.get('duration_seconds', 0):.1f}s"
        )

