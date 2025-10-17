#!/usr/bin/env python3
"""
Project Medusa CLI - AI Adversary Simulation Operator
Main entry point for the command-line interface
"""

import sys
import argparse
import os
import json
from typing import Optional, Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from src.agents.ai_agent import MedusaAIAgent

VERSION = "0.1.0-alpha"

class MedusaCLI:
    """Main CLI controller for Project Medusa"""

    def __init__(self):
        self.parser = self._setup_parser()
        self.console = Console()
        self.ai_agent = None

    def _setup_parser(self) -> argparse.ArgumentParser:
        """Set up the command-line argument parser"""
        parser = argparse.ArgumentParser(
            description="Project Medusa - AI Adversary Simulation",
            epilog="For authorized security research purposes only."
        )

        parser.add_argument(
            '--version',
            action='version',
            version=f'Medusa CLI v{VERSION}'
        )

        subparsers = parser.add_subparsers(dest='command', help='Available commands')

        # Init command - Initialize the kill box environment
        init_parser = subparsers.add_parser(
            'init',
            help='Initialize the kill box environment'
        )
        init_parser.add_argument(
            '--force',
            action='store_true',
            help='Force reinitialization of existing environment'
        )

        # Deploy command - Deploy an AI agent
        deploy_parser = subparsers.add_parser(
            'deploy',
            help='Deploy an AI agent with a strategic objective'
        )
        deploy_parser.add_argument(
            '--objective',
            type=str,
            required=True,
            help='Strategic objective for the agent (e.g., "Locate patient database")'
        )
        deploy_parser.add_argument(
            '--model',
            type=str,
            default='gpt-4',
            help='LLM model to use for the agent'
        )

        # Monitor command - Monitor agent activity
        monitor_parser = subparsers.add_parser(
            'monitor',
            help='Monitor active agent operations'
        )
        monitor_parser.add_argument(
            '--live',
            action='store_true',
            help='Enable live monitoring mode'
        )

        # Report command - Generate operation reports
        report_parser = subparsers.add_parser(
            'report',
            help='Generate operation report'
        )
        report_parser.add_argument(
            '--output',
            type=str,
            help='Output file for report'
        )

        # Stop command - Emergency stop
        stop_parser = subparsers.add_parser(
            'stop',
            help='Emergency stop all agent operations'
        )

        # Status command - Show system status
        status_parser = subparsers.add_parser(
            'status',
            help='Display current system status'
        )

        # Natural language commands - Human-friendly interface
        object_parser = subparsers.add_parser(
            'find',
            help='Find specific data types using natural language'
        )
        object_parser.add_argument(
            'object',
            type=str,
            help='What to find (e.g., "medical records", "passwords", "financial data", "all data")'
        )
        object_parser.add_argument(
            '--extract',
            action='store_true',
            help='Extract found data to files'
        )
        object_parser.add_argument(
            '--output',
            type=str,
            default='discovery_results.json',
            help='Save discovery results to file'
        )

        # Assess command - Run AI security assessment
        assess_parser = subparsers.add_parser(
            'assess',
            help='Run autonomous AI security assessment'
        )
        assess_parser.add_argument(
            '--api-key',
            type=str,
            help='Gemini API key (or set GEMINI_API_KEY env var)'
        )
        assess_parser.add_argument(
            '--output',
            type=str,
            default='medusa_assessment_report.txt',
            help='Save report to file (default: medusa_assessment_report.txt)'
        )
        assess_parser.add_argument(
            '--extract-data',
            action='store_true',
            help='Extract and save sensitive data to files'
        )
        assess_parser.add_argument(
            '--interactive',
            action='store_true',
            help='Interactive mode - choose which data to extract'
        )

        return parser

    def run(self, args: Optional[list] = None) -> int:
        """Execute the CLI with given arguments"""
        parsed_args = self.parser.parse_args(args)

        if not parsed_args.command:
            self.parser.print_help()
            return 0

        # Route to appropriate command handler
        command_handlers = {
            'init': self._handle_init,
            'deploy': self._handle_deploy,
            'monitor': self._handle_monitor,
            'report': self._handle_report,
            'stop': self._handle_stop,
            'status': self._handle_status,
            'find': self._handle_find_operation,
            'assess': self._handle_assess,
        }

        handler = command_handlers.get(parsed_args.command)
        if handler:
            return handler(parsed_args)
        else:
            print(f"Unknown command: {parsed_args.command}")
            return 1

    def _handle_init(self, args) -> int:
        """Handle the init command"""
        print("🔧 Initializing Medusa kill box environment...")
        print("   [Placeholder] Docker environment setup")
        print("   [Placeholder] Network configuration")
        print("   [Placeholder] Target service deployment")
        print("✅ Environment initialized (mock)")
        return 0

    def _handle_deploy(self, args) -> int:
        """Handle the deploy command"""
        self.console.print(Panel("🚀 [bold blue]Deploying AI Agent[/bold blue]", style="blue"))
        self.console.print(f"   Objective: {args.objective}")
        self.console.print(f"   Model: {args.model}")

        try:
            # Initialize AI agent
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                self.console.print("❌ [red]Error: GEMINI_API_KEY environment variable not set[/red]")
                self.console.print("   Please set your Gemini API key: export GEMINI_API_KEY='your-key-here'")
                return 1

            self.ai_agent = MedusaAIAgent(api_key)
            self.console.print("✅ [green]AI Agent initialized with Gemini API[/green]")
            self.console.print("✅ [green]Agent deployed and ready for operations[/green]")
            return 0

        except Exception as e:
            self.console.print(f"❌ [red]Error deploying agent: {e}[/red]")
            return 1

    def _handle_monitor(self, args) -> int:
        """Handle the monitor command"""
        if args.live:
            print("📊 Live monitoring mode...")
            print("   [Placeholder] Real-time agent activity stream")
        else:
            print("📊 Agent activity summary:")
            print("   [Placeholder] Recent operations")
            print("   [Placeholder] Current status")
        return 0

    def _handle_report(self, args) -> int:
        """Handle the report command"""
        print("📄 Generating operation report...")
        if args.output:
            print(f"   Output: {args.output}")
        print("   [Placeholder] Report generation")
        print("✅ Report generated (mock)")
        return 0

    def _handle_stop(self, args) -> int:
        """Handle the emergency stop command"""
        print("🛑 EMERGENCY STOP initiated...")
        print("   [Placeholder] Stopping all agents")
        print("   [Placeholder] Cleanup operations")
        print("✅ All operations stopped (mock)")
        return 0

    def _handle_status(self, args) -> int:
        """Handle the status command"""
        self.console.print(Panel("📊 [bold green]Medusa System Status[/bold green]", style="green"))

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="green")

        table.add_row("Version", VERSION)
        table.add_row("Environment", "Initialized" if os.path.exists("medusa-backend") else "Not initialized")
        table.add_row("Backend API", "Running" if self._check_backend() else "Offline")
        table.add_row("AI Agent", "Ready" if self.ai_agent else "Not deployed")
        table.add_row("Gemini API", "Configured" if os.getenv('GEMINI_API_KEY') else "Not configured")

        self.console.print(table)
        return 0


    def _handle_find_operation(self, args) -> int:
        """Handle natural language find operations - Human-friendly interface"""
        self.console.print(Panel(f"🔍 [bold blue]C2 Agent: Finding '{args.object}'[/bold blue]", style="blue"))
        
        try:
            # Initialize AI agent
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                self.console.print("❌ [red]Error: No Gemini API key provided[/red]")
                self.console.print("   Set GEMINI_API_KEY environment variable")
                return 1
            
            self.ai_agent = MedusaAIAgent(api_key)
            
            # Map natural language to data types
            data_type = self._map_object_to_data_type(args.object)
            
            # Run discovery with mapped data type
            results = self.ai_agent.discover_data_sources(data_type)
            
            # Display results in a friendly way
            self.console.print(Panel(f"📊 [bold green]Found '{args.object}' - Discovery Results[/bold green]", style="green"))
            
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Access Level", results.get("access_level", "unknown").upper())
            table.add_row("Sources Found", str(results.get("total_found", 0)))
            table.add_row("High Confidence", str(results.get("high_confidence_count", 0)))
            table.add_row("Discovery Time", f"{results.get('discovery_time', 0):.2f}s")
            table.add_row("Efficiency", f"{results.get('efficiency', 0):.1f} rec/min")
            table.add_row("Total Value", f"${results.get('total_value', 0):,.2f}")
            
            # Calculate efficiency grade
            efficiency = results.get('efficiency', 0)
            if efficiency >= 400:
                grade = "A+ (Excellent)"
            elif efficiency >= 200:
                grade = "A (Very Good)"
            elif efficiency >= 100:
                grade = "B (Good)"
            elif efficiency >= 50:
                grade = "C (Satisfactory)"
            else:
                grade = "D (Needs Improvement)"
            
            table.add_row("Performance Grade", grade)
            
            self.console.print(table)
            
            # Extract high-value data if requested
            if args.extract:
                self._extract_high_value_data(results)
            
            # Save results
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            self.console.print(f"📄 [green]Results saved to: {args.output}[/green]")
            
            return 0
            
        except Exception as e:
            self.console.print(f"❌ [red]Find operation failed: {e}[/red]")
            return 1

    def _map_object_to_data_type(self, object_name: str) -> str:
        """Map natural language object names to data types"""
        object_lower = object_name.lower()
        
        # Medical records
        if any(keyword in object_lower for keyword in ['medical', 'patient', 'health', 'hospital', 'clinic', 'doctor']):
            return "medical_records"
        
        # Financial data
        elif any(keyword in object_lower for keyword in ['financial', 'money', 'bank', 'credit', 'salary', 'payroll', 'accounting']):
            return "financial_data"
        
        # Credentials
        elif any(keyword in object_lower for keyword in ['password', 'credential', 'login', 'auth', 'key', 'token', 'secret']):
            return "credentials"
        
        # Personal information
        elif any(keyword in object_lower for keyword in ['personal', 'contact', 'email', 'phone', 'address', 'user']):
            return "personal_info"
        
        # System data
        elif any(keyword in object_lower for keyword in ['system', 'config', 'log', 'backup', 'admin']):
            return "system_data"
        
        # All data
        elif any(keyword in object_lower for keyword in ['all', 'everything', 'data', 'files', 'records']):
            return "all"
        
        # Default to all if unclear
        else:
            return "all"

    def _extract_high_value_data(self, results: Dict[str, Any]):
        """Extract high-value data to files"""
        self.console.print(Panel("💾 [bold cyan]Extracting High-Value Data[/bold cyan]", style="cyan"))

        try:
            classified_data = results.get("classified_data", [])
            high_value_data = [
                item for item in classified_data
                if item.get("confidence_level") == "HIGH_CONFIDENCE" and item.get("estimated_value", 0) > 0
            ]

            if not high_value_data:
                self.console.print("⚠️ [yellow]No high-value data found for extraction[/yellow]")
                return

            # Group by classification
            data_by_type = {}
            for item in high_value_data:
                classification = item.get("classification", "unclassified")
                if classification not in data_by_type:
                    data_by_type[classification] = []
                data_by_type[classification].append(item)

            # Save each type to separate files
            for classification, items in data_by_type.items():
                filename = f"medusa_extracted_data/{classification}_data.json"
                os.makedirs("medusa_extracted_data", exist_ok=True)

                with open(filename, 'w') as f:
                    json.dump(items, f, indent=2)

                total_value = sum(item.get("estimated_value", 0) for item in items)
                self.console.print(f"  ✅ [green]Saved {len(items)} {classification} records (${total_value:,.2f}) to {filename}[/green]")

            self.console.print(f"💰 [green]Total extracted value: ${sum(item.get('estimated_value', 0) for item in high_value_data):,.2f}[/green]")

        except Exception as e:
            self.console.print(f"❌ [red]Data extraction failed: {e}[/red]")

    def _handle_assess(self, args) -> int:
        """Handle the assess command - Run autonomous C2 assessment"""
        self.console.print(Panel("🤖 [bold blue]C2 Agent: Autonomous Assessment[/bold blue]", style="blue"))

        try:
            # Initialize AI agent
            api_key = args.api_key or os.getenv('GEMINI_API_KEY')
            if not api_key:
                self.console.print("❌ [red]Error: No Gemini API key provided[/red]")
                self.console.print("   Use --api-key flag or set GEMINI_API_KEY environment variable")
                return 1

            self.ai_agent = MedusaAIAgent(api_key)

            # Run autonomous C2 assessment
            results = self.ai_agent.run_autonomous_assessment()

            # Display results summary
            self.console.print(Panel("📊 [bold green]C2 Assessment Complete[/bold green]", style="green"))

            # Show assessment summary table
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Access Level", results.get("access_level", "unknown").upper())
            table.add_row("Network Resources", str(len(results.get("network_discovery", {}).get("resources", []))))
            table.add_row("Data Sources", str(len(results.get("data_discovery", {}).get("sources", []))))
            table.add_row("Privilege Escalation", "✅ SUCCESS" if results.get("privilege_escalation", {}).get("success") else "❌ FAILED")
            table.add_row("Records Exfiltrated", str(results.get("data_exfiltration", {}).get("total_records", 0)))
            table.add_row("Total Value", f"${results.get('data_exfiltration', {}).get('total_value', 0):,.2f}")
            table.add_row("Performance Grade", results.get("performance_grade", "N/A"))

            self.console.print(table)

            # Interactive data extraction
            if args.interactive:
                self._interactive_data_extraction(results)
            elif args.extract_data:
                self._extract_all_data(results)

            # Save report
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            self.console.print(f"📄 [green]Report saved to: {args.output}[/green]")

            return 0

        except Exception as e:
            self.console.print(f"❌ [red]Assessment failed: {e}[/red]")
            return 1

    def _interactive_data_extraction(self, results):
        """Interactive mode - let user choose which data to extract"""
        self.console.print(Panel("🎯 [bold cyan]Interactive Data Extraction[/bold cyan]", style="cyan"))

        # Show available data types
        available_data = results["attack_results"].get("valuable_data_stolen", [])

        if not available_data:
            self.console.print("❌ [red]No valuable data found to extract[/red]")
            return

        # Display options
        self.console.print("\n📋 [bold]Available Data Types:[/bold]")
        for i, data in enumerate(available_data, 1):
            self.console.print(f"  {i}. {data['type'].replace('_', ' ').title()} - {data['market_value']} ({data['count']} records)")

        # Get user selection
        try:
            choice = input("\n🔍 Select data type to extract (number) or 'all' for everything: ").strip()

            if choice.lower() == 'all':
                self._extract_all_data(results)
            else:
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(available_data):
                    selected_data = available_data[choice_idx]
                    self._extract_specific_data(selected_data, results)
                else:
                    self.console.print("❌ [red]Invalid selection[/red]")
        except (ValueError, KeyboardInterrupt):
            self.console.print("\n❌ [red]Extraction cancelled[/red]")

    def _extract_all_data(self, results):
        """Extract all available sensitive data to files"""
        self.console.print(Panel("💾 [bold green]Extracting All Sensitive Data[/bold green]", style="green"))

        # Create output directory
        import os
        output_dir = "medusa_extracted_data"
        os.makedirs(output_dir, exist_ok=True)

        # Extract each data type
        for data in results["attack_results"].get("valuable_data_stolen", []):
            self._extract_specific_data(data, results, output_dir)

        self.console.print(f"📁 [green]All data saved to: {output_dir}/[/green]")

    def _extract_specific_data(self, data_type, results, output_dir="medusa_extracted_data"):
        """Extract specific data type to file"""
        import os
        import json
        from datetime import datetime

        os.makedirs(output_dir, exist_ok=True)

        # Get actual data from API
        try:
            import requests

            if data_type['type'] == 'medical_identity':
                response = requests.get("http://localhost:3001/api/patients", timeout=5)
                if response.status_code == 200:
                    patients_data = response.json().get('data', [])

                    # Extract only valuable fields
                    valuable_data = []
                    for patient in patients_data:
                        valuable_record = {
                            "id": patient.get("id"),
                            "name": f"{patient.get('firstName', '')} {patient.get('lastName', '')}",
                            "ssn": patient.get("ssn"),
                            "credit_card": patient.get("financialInfo", {}).get("creditCardNumber"),
                            "bank_account": patient.get("financialInfo", {}).get("bankAccountNumber"),
                            "insurance": patient.get("insuranceNumber"),
                            "phone": patient.get("phone"),
                            "email": patient.get("email"),
                            "address": patient.get("address"),
                            "extracted_at": datetime.now().isoformat(),
                            "estimated_value": 1500
                        }
                        valuable_data.append(valuable_record)

                    # Save to file
                    filename = f"{output_dir}/medical_identity_data.json"
                    with open(filename, 'w') as f:
                        json.dump(valuable_data, f, indent=2)

                    self.console.print(f"💰 [green]Medical Identity Data: {len(valuable_data)} records saved to {filename}[/green]")

            elif data_type['type'] == 'employee_credentials':
                response = requests.get("http://localhost:3001/api/employees", timeout=5)
                if response.status_code == 200:
                    employees_data = response.json().get('data', [])

                    # Extract only valuable fields
                    valuable_credentials = []
                    for employee in employees_data:
                        valuable_record = {
                            "id": employee.get("id"),
                            "name": f"{employee.get('firstName', '')} {employee.get('lastName', '')}",
                            "username": employee.get("credentials", {}).get("username"),
                            "password": employee.get("credentials", {}).get("password"),
                            "ssn": employee.get("ssn"),
                            "bank_account": employee.get("financialInfo", {}).get("bankAccountNumber"),
                            "salary": employee.get("salary"),
                            "department": employee.get("department"),
                            "position": employee.get("position"),
                            "extracted_at": datetime.now().isoformat(),
                            "estimated_value": 300
                        }
                        valuable_credentials.append(valuable_record)

                    # Save to file
                    filename = f"{output_dir}/employee_credentials.json"
                    with open(filename, 'w') as f:
                        json.dump(valuable_credentials, f, indent=2)

                    self.console.print(f"🔑 [green]Employee Credentials: {len(valuable_credentials)} records saved to {filename}[/green]")

        except Exception as e:
            self.console.print(f"❌ [red]Error extracting {data_type['type']}: {e}[/red]")

    def _check_backend(self) -> bool:
        """Check if backend API is running"""
        try:
            import requests
            response = requests.get("http://localhost:3001/health", timeout=2)
            return response.status_code == 200
        except:
            return False


def main():
    """Main entry point"""
    print("=" * 60)
    print(" PROJECT MEDUSA - AI Adversary Simulation")
    print(" For authorized security research purposes only")
    print("=" * 60)
    print()

    cli = MedusaCLI()
    sys.exit(cli.run())


if __name__ == '__main__':
    main()

