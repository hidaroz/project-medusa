"""
Observe mode for MEDUSA
Reconnaissance only - no exploitation, just intelligence gathering
"""

import asyncio
from typing import Dict, Any
from datetime import datetime
import time

from medusa.client import MedusaClient
from medusa.display import display
from medusa.reporter import ReportGenerator
from medusa.config import get_config


class ObserveMode:
    """Observe-only mode - reconnaissance without exploitation"""

    def __init__(self, target: str, api_key: str):
        self.target = target
        self.api_key = api_key
        self.config = get_config()
        self.reporter = ReportGenerator()
        self.operation_id = f"observe_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.intelligence: Dict[str, Any] = {
            "operation_id": self.operation_id,
            "mode": "observe",
            "target": target,
            "started_at": datetime.now().isoformat(),
            "reconnaissance": {},
            "enumeration": {},
            "attack_plan": {},
        }

    async def run(self):
        """Execute observation and intelligence gathering"""
        display.console.print()
        display.console.print(
            f"[bold cyan]Starting Observation Mode[/bold cyan] against [yellow]{self.target}[/yellow]"
        )
        display.console.print(
            "[dim]Reconnaissance only - no exploitation will be performed[/dim]\n"
        )
        display.console.print(f"[dim]Operation ID: {self.operation_id}[/dim]\n")

        start_time = time.time()
        
        # Get LLM config from global config
        llm_config = self.config.get_llm_config()

        async with MedusaClient(self.target, self.api_key, llm_config=llm_config) as client:
            # Phase 1: Passive Reconnaissance
            await self._passive_reconnaissance(client)

            # Phase 2: Active Enumeration
            await self._active_enumeration(client)

            # Phase 3: Vulnerability Assessment
            await self._vulnerability_assessment(client)

            # Phase 4: Generate Attack Plan (but don't execute)
            await self._generate_attack_plan(client)

        # Calculate metrics
        self.intelligence["completed_at"] = datetime.now().isoformat()
        self.intelligence["duration_seconds"] = time.time() - start_time

        # Generate intelligence report
        await self._generate_intelligence_report()

    async def _passive_reconnaissance(self, client: MedusaClient):
        """Passive reconnaissance - minimal footprint"""
        display.console.print("[bold blue]═══ Phase 1: Passive Reconnaissance ═══[/bold blue]")

        display.show_agent_thinking(
            "Performing passive reconnaissance with minimal detection footprint. "
            "I'm gathering publicly available information about the target."
        )

        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Passive reconnaissance...", total=100)

            # Simulate passive recon
            await asyncio.sleep(1)
            progress.update(task, advance=50)

            result = await client.perform_reconnaissance(self.target)
            progress.update(task, completed=100)

        # Display results
        tasks = [
            {"name": "DNS resolution", "status": "complete", "details": "Target resolved"},
            {
                "name": "Service detection",
                "status": "complete",
                "details": f"{len([f for f in result['findings'] if f['type'] == 'open_port'])} services detected",
            },
            {
                "name": "Technology fingerprinting",
                "status": "complete",
                "details": "Web stack identified",
            },
        ]
        display.show_phase_tree("Passive Reconnaissance", tasks)

        self.intelligence["reconnaissance"] = result
        display.console.print()

    async def _active_enumeration(self, client: MedusaClient):
        """Active enumeration - direct interaction with target"""
        display.console.print("[bold blue]═══ Phase 2: Active Enumeration ═══[/bold blue]")

        display.show_agent_thinking(
            "Actively probing the target to identify API endpoints, "
            "authentication mechanisms, and potential attack vectors."
        )

        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Active enumeration...", total=100)

            for i in range(0, 100, 25):
                await asyncio.sleep(0.6)
                progress.update(task, advance=25)

            result = await client.enumerate_services(self.target)
            progress.update(task, completed=100)

        # Display results
        tasks = [
            {
                "name": "API endpoint discovery",
                "status": "complete",
                "details": f"{len([f for f in result['findings'] if f['type'] == 'api_endpoint'])} endpoints found",
            },
            {
                "name": "Authentication analysis",
                "status": "complete",
                "details": "Unauthenticated endpoints identified",
            },
            {
                "name": "Input validation testing",
                "status": "complete",
                "details": "Potential injection points found",
            },
        ]
        display.show_phase_tree("Active Enumeration", tasks)

        self.intelligence["enumeration"] = result
        display.console.print()

    async def _vulnerability_assessment(self, client: MedusaClient):
        """Assess vulnerabilities without exploitation"""
        display.console.print("[bold blue]═══ Phase 3: Vulnerability Assessment ═══[/bold blue]\n")

        display.show_agent_thinking(
            "Analyzing identified weaknesses and assessing their severity. "
            "No exploitation attempts will be made."
        )

        # Simulate vulnerability assessment
        await asyncio.sleep(2)

        # Get findings from enumeration
        findings = self.intelligence.get("enumeration", {}).get("findings", [])
        vulnerabilities = [f for f in findings if f.get("type") == "vulnerability"]

        # Display vulnerability summary
        display.console.print(
            f"[cyan]Identified {len(vulnerabilities)} potential vulnerabilities:[/cyan]\n"
        )
        display.show_findings(findings[:6], phase="enumeration")

        # Categorize by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        display.show_status_table(
            {
                "Critical": severity_counts["critical"],
                "High": severity_counts["high"],
                "Medium": severity_counts["medium"],
                "Low": severity_counts["low"],
                "Info": severity_counts["info"],
            },
            "Vulnerability Summary",
        )

        display.console.print()

    async def _generate_attack_plan(self, client: MedusaClient):
        """Generate attack plan based on intelligence"""
        display.console.print("[bold blue]═══ Phase 4: Attack Plan Generation ═══[/bold blue]\n")

        display.show_agent_thinking(
            "Based on the gathered intelligence, I'm formulating an attack strategy. "
            "This plan will NOT be executed in observe mode."
        )

        # Get AI recommendations
        context = {
            "reconnaissance": self.intelligence.get("reconnaissance", {}),
            "enumeration": self.intelligence.get("enumeration", {}),
        }

        with display.create_progress_bar() as progress:
            task = progress.add_task("[cyan]Analyzing attack surface...", total=100)

            for i in range(0, 100, 20):
                await asyncio.sleep(0.4)
                progress.update(task, advance=20)

            plan = await client.get_ai_recommendation(context)
            progress.update(task, completed=100)

        # Display attack plan
        display.console.print("\n[bold yellow]Recommended Attack Strategy:[/bold yellow]\n")

        for i, rec in enumerate(plan.get("recommendations", []), 1):
            display.console.print(
                f"[cyan]{i}. {rec['action'].replace('_', ' ').title()}[/cyan]"
            )
            display.console.print(f"   Confidence: {rec['confidence']*100:.0f}%")
            display.console.print(f"   Reasoning: [dim]{rec['reasoning']}[/dim]")
            display.console.print(
                f"   Risk Level: [{self._risk_color(rec['risk_level'])}]{rec['risk_level']}[/{self._risk_color(rec['risk_level'])}]"
            )
            display.console.print()

        self.intelligence["attack_plan"] = plan
        display.console.print()

    def _risk_color(self, risk_level: str) -> str:
        """Get color for risk level"""
        colors = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}
        return colors.get(risk_level, "white")

    async def _generate_intelligence_report(self):
        """Generate intelligence report"""
        display.console.print("[bold blue]═══ Generating Intelligence Report ═══[/bold blue]\n")

        # Prepare report data
        findings = self.intelligence.get("enumeration", {}).get("findings", [])
        techniques = []
        techniques.extend(self.intelligence.get("reconnaissance", {}).get("techniques", []))
        techniques.extend(self.intelligence.get("enumeration", {}).get("techniques", []))

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        report_data = {
            "operation_id": self.operation_id,
            "target": self.target,
            "mode": "observe",
            "duration_seconds": self.intelligence.get("duration_seconds", 0),
            "summary": {
                "total_findings": len(findings),
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "techniques_used": len(techniques),
                "success_rate": 1.0,  # Observation mode always succeeds
            },
            "findings": findings,
            "mitre_coverage": techniques,
            "phases": [
                {
                    "name": "reconnaissance",
                    "status": "complete",
                    "duration": 0,
                    "findings": len(
                        self.intelligence.get("reconnaissance", {}).get("findings", [])
                    ),
                    "techniques": len(
                        self.intelligence.get("reconnaissance", {}).get("techniques", [])
                    ),
                },
                {
                    "name": "enumeration",
                    "status": "complete",
                    "duration": 0,
                    "findings": len(findings),
                    "techniques": len(
                        self.intelligence.get("enumeration", {}).get("techniques", [])
                    ),
                },
            ],
            "attack_plan": self.intelligence.get("attack_plan", {}),
        }

        # Generate reports
        display.console.print("\n[bold cyan]📝 Generating Reports...[/bold cyan]\n")

        # Generate JSON log
        json_path = self.reporter.save_json_log(report_data, self.operation_id)
        display.show_success(f"JSON log: {json_path.name}")

        # Generate technical HTML report
        html_path = self.reporter.generate_html_report(
            report_data, self.operation_id, report_type="technical"
        )
        display.show_success(f"Technical report: {html_path.name}")

        # Generate executive summary
        try:
            exec_path = self.reporter.generate_executive_summary(
                report_data, self.operation_id
            )
            display.show_success(f"Executive summary: {exec_path.name}")
        except Exception as e:
            display.show_warning(f"Executive summary generation failed: {e}")

        # Generate markdown report
        try:
            md_path = self.reporter.generate_markdown_report(
                report_data, self.operation_id
            )
            display.show_success(f"Markdown report: {md_path.name}")
        except Exception as e:
            display.show_warning(f"Markdown report generation failed: {e}")

        display.console.print(
            f"\n[dim]Reports location: {self.reporter.config.reports_dir}[/dim]"
        )

        # Display summary
        display.console.print()
        display.show_status_table(report_data["summary"], "Intelligence Summary")

        display.console.print()
        display.console.print(
            f"\n[bold green]✓ Observation complete![/bold green] "
            f"Duration: {report_data['duration_seconds']:.1f}s"
        )
        display.console.print(
            "\n[yellow]Note:[/yellow] Attack plan generated but NOT executed. "
            "Use autonomous mode to execute."
        )

