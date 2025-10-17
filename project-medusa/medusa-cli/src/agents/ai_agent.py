"""
AI Agent Module for Project Medusa CLI
C2 Framework for post-exploitation operations and autonomous data discovery
Integrates with Google Gemini API for intelligent decision making
"""

import os
import json
import requests
import time
import random
import subprocess
import platform
from typing import Dict, List, Optional, Any
from google import genai
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

class MedusaAIAgent:
    """
    C2 Framework AI Agent for post-exploitation operations.
    Operates after initial compromise with varying access levels.
    """

    def __init__(self, api_key: Optional[str] = None):
        """Initialize the C2 AI agent with Gemini API key"""
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY environment variable is required")

        self.client = genai.Client()

        # Detect current access level
        self.access_level = self._detect_access_level()
        self.performance_targets = self._set_performance_targets()

        console.print(f"🎯 [bold blue]C2 Agent Initialized - Access Level: {self.access_level.upper()}[/bold blue]")
        console.print(f"📊 [yellow]Performance Targets: {self.performance_targets}[/yellow]")

    def _detect_access_level(self) -> str:
        """Detect current access level based on system privileges"""
        try:
            # Check if running as administrator/root
            if platform.system() == "Windows":
                try:
                    import ctypes
                    return ctypes.windll.shell32.IsUserAnAdmin() and "admin" or "basic_user"
                except:
                    return "basic_user"
            else:
                return "root" if os.geteuid() == 0 else "basic_user"
        except:
            return "basic_user"

    def _set_performance_targets(self) -> Dict[str, Any]:
        """Set performance targets based on access level"""
        if self.access_level == "basic_user":
            return {
                "network_discovery_time": 60,  # seconds - simple file scanning
                "privilege_escalation_success": 0.3,  # 30%
                "data_discovery_efficiency": 40,  # records/minute - personal files only
                "stealth_priority": "low",  # personal files are expected to be accessed
                "max_threads": 2
            }
        elif self.access_level == "admin":
            return {
                "network_discovery_time": 120,  # seconds - system enumeration + network discovery
                "privilege_escalation_success": 0.7,  # 70%
                "data_discovery_efficiency": 120,  # records/minute - system-wide data
                "stealth_priority": "medium",  # system access should be logged
                "max_threads": 5
            }
        else:  # root/domain_admin
            return {
                "network_discovery_time": 300,  # seconds - enterprise database queries + cloud reconnaissance
                "privilege_escalation_success": 0.9,  # 90%
                "data_discovery_efficiency": 400,  # records/minute - enterprise data
                "stealth_priority": "high",  # enterprise access is heavily monitored
                "max_threads": 10
            }

    def discover_internal_network(self, scope: str = "local") -> Dict[str, Any]:
        """
        Discover internal network resources based on access level.
        C2-style reconnaissance after compromise.
        """
        console.print(Panel("🌐 [bold blue]C2 Agent: Internal Network Discovery[/bold blue]", style="blue"))

        start_time = time.time()
        discovered_resources = []

        try:
            if self.access_level == "basic_user":
                # Limited network discovery
                console.print("🔍 [cyan]Basic User: Limited network discovery[/cyan]")
                discovered_resources = self._discover_local_network()

            elif self.access_level == "admin":
                # Subnet-wide discovery
                console.print("🔍 [cyan]Admin: Subnet-wide discovery[/cyan]")
                discovered_resources = self._discover_subnet_network()

            else:  # root/domain_admin
                # Domain-wide discovery
                console.print("🔍 [cyan]Domain Admin: Enterprise-wide discovery[/cyan]")
                discovered_resources = self._discover_enterprise_network()

            discovery_time = time.time() - start_time

            return {
                "method": "internal_network_discovery",
                "access_level": self.access_level,
                "resources": discovered_resources,
                "discovery_time": discovery_time,
                "success_rate": self._calculate_network_discovery_success(discovered_resources),
                "total_found": len(discovered_resources)
            }

        except Exception as e:
            console.print(f"❌ [red]Network discovery failed: {e}[/red]")
            return {
                "method": "internal_network_discovery",
                "access_level": self.access_level,
                "resources": [],
                "discovery_time": time.time() - start_time,
                "success_rate": 0.0,
                "error": str(e)
            }

    def discover_data_sources(self, data_type: str = "all") -> Dict[str, Any]:
        """
        Discover sensitive data sources with intelligent classification and confidence scoring.
        C2-style data discovery for exfiltration planning.
        """
        console.print(Panel("💾 [bold blue]C2 Agent: Intelligent Data Discovery[/bold blue]", style="blue"))

        start_time = time.time()
        discovered_sources = []
        classified_data = []

        try:
            if self.access_level == "basic_user":
                # Personal data discovery
                console.print("🔍 [cyan]Basic User: Personal data discovery[/cyan]")
                discovered_sources = self._discover_personal_data()

            elif self.access_level == "admin":
                # System-wide data discovery
                console.print("🔍 [cyan]Admin: System-wide data discovery[/cyan]")
                discovered_sources = self._discover_system_data()

            else:  # root/domain_admin
                # Enterprise data discovery
                console.print("🔍 [cyan]Domain Admin: Enterprise data discovery[/cyan]")
                discovered_sources = self._discover_enterprise_data()

            # Intelligent classification and confidence scoring
            console.print("🧠 [cyan]AI Classification and Confidence Scoring[/cyan]")
            for source in discovered_sources:
                if source.get("accessible", False):
                    classified_source = self._classify_data_source(source)
                    classified_data.append(classified_source)

            discovery_time = time.time() - start_time
            efficiency = self._calculate_data_discovery_efficiency(classified_data, discovery_time)
            total_value = self._calculate_total_data_value(classified_data)

            # Display classification results
            self._display_classification_summary(classified_data)

            return {
                "method": "intelligent_data_discovery",
                "access_level": self.access_level,
                "sources": discovered_sources,
                "classified_data": classified_data,
                "discovery_time": discovery_time,
                "efficiency": efficiency,
                "total_found": len(discovered_sources),
                "total_value": total_value,
                "high_confidence_count": len([d for d in classified_data if d.get("confidence_level") == "HIGH_CONFIDENCE"])
            }

        except Exception as e:
            console.print(f"❌ [red]Data discovery failed: {e}[/red]")
            return {
                "method": "intelligent_data_discovery",
                "access_level": self.access_level,
                "sources": [],
                "classified_data": [],
                "discovery_time": time.time() - start_time,
                "efficiency": 0.0,
                "total_found": 0,
                "total_value": 0,
                "error": str(e)
            }

    def escalate_privileges(self, method: str = "auto") -> Dict[str, Any]:
        """
        Attempt privilege escalation based on access level.
        C2-style privilege escalation techniques.
        """
        console.print(Panel("⬆️ [bold blue]C2 Agent: Privilege Escalation[/bold blue]", style="blue"))

        start_time = time.time()

        try:
            if self.access_level == "basic_user":
                # Attempt local privilege escalation
                console.print("🔍 [cyan]Basic User: Attempting local privilege escalation[/cyan]")
                escalation_result = self._attempt_local_escalation()

            elif self.access_level == "admin":
                # Attempt domain privilege escalation
                console.print("🔍 [cyan]Admin: Attempting domain privilege escalation[/cyan]")
                escalation_result = self._attempt_domain_escalation()

            else:  # root/domain_admin
                # Already at highest level
                console.print("✅ [green]Already at highest privilege level[/green]")
                escalation_result = {"success": True, "new_level": "domain_admin"}

            escalation_time = time.time() - start_time

            return {
                "method": "privilege_escalation",
                "current_level": self.access_level,
                "result": escalation_result,
                "escalation_time": escalation_time,
                "success": escalation_result.get("success", False)
            }

        except Exception as e:
            console.print(f"❌ [red]Privilege escalation failed: {e}[/red]")
            return {
                "method": "privilege_escalation",
                "current_level": self.access_level,
                "result": {"success": False, "error": str(e)},
                "escalation_time": time.time() - start_time,
                "success": False
            }

    def exfiltrate_data(self, sources: List[Dict[str, Any]], method: str = "stealth") -> Dict[str, Any]:
        """
        Exfiltrate discovered data using C2 techniques.
        """
        console.print(Panel("📤 [bold blue]C2 Agent: Data Exfiltration[/bold blue]", style="blue"))

        start_time = time.time()
        exfiltrated_data = []

        try:
            console.print(f"🎯 [cyan]Exfiltrating data from {len(sources)} sources[/cyan]")

            for source in sources:
                if source.get("accessible", False):
                    data = self._extract_data_from_source(source)
                    if data:
                        exfiltrated_data.append({
                            "source": source["name"],
                            "data": data,
                            "records": len(data),
                            "value": self._calculate_data_value(data)
                        })
                        console.print(f"  ✅ [green]Extracted {len(data)} records from {source['name']}[/green]")

            exfiltration_time = time.time() - start_time
            total_records = sum(item["records"] for item in exfiltrated_data)
            total_value = sum(item["value"] for item in exfiltrated_data)

            return {
                "method": "data_exfiltration",
                "sources_processed": len(sources),
                "sources_successful": len(exfiltrated_data),
                "total_records": total_records,
                "total_value": total_value,
                "exfiltration_time": exfiltration_time,
                "data": exfiltrated_data
            }

        except Exception as e:
            console.print(f"❌ [red]Data exfiltration failed: {e}[/red]")
            return {
                "method": "data_exfiltration",
                "sources_processed": len(sources),
                "sources_successful": 0,
                "total_records": 0,
                "total_value": 0,
                "exfiltration_time": time.time() - start_time,
                "error": str(e)
            }

    # Helper methods for different access levels

    def _discover_local_network(self) -> List[Dict[str, Any]]:
        """Discover local network resources (basic user)"""
        resources = []

        # Simulate local network discovery
        console.print("  🔍 Scanning local subnet...")
        time.sleep(1)  # Simulate scanning time

        # Mock discovered resources
        resources = [
            {"type": "workstation", "ip": "192.168.1.100", "os": "Windows 10", "accessible": True},
            {"type": "printer", "ip": "192.168.1.101", "model": "HP LaserJet", "accessible": False},
            {"type": "router", "ip": "192.168.1.1", "model": "Linksys", "accessible": False}
        ]

        return resources

    def _discover_subnet_network(self) -> List[Dict[str, Any]]:
        """Discover subnet-wide resources (admin)"""
        resources = []

        console.print("  🔍 Scanning subnet 192.168.1.0/24...")
        time.sleep(2)  # Simulate longer scanning

        # Mock discovered resources
        resources = [
            {"type": "workstation", "ip": "192.168.1.100", "os": "Windows 10", "accessible": True},
            {"type": "server", "ip": "192.168.1.50", "os": "Windows Server 2019", "accessible": True},
            {"type": "database", "ip": "192.168.1.60", "type": "SQL Server", "accessible": True},
            {"type": "printer", "ip": "192.168.1.101", "model": "HP LaserJet", "accessible": False}
        ]

        return resources

    def _discover_enterprise_network(self) -> List[Dict[str, Any]]:
        """Discover enterprise-wide resources (domain admin)"""
        resources = []

        console.print("  🔍 Scanning enterprise domain...")
        time.sleep(3)  # Simulate comprehensive scanning

        # Mock discovered resources
        resources = [
            {"type": "domain_controller", "ip": "192.168.1.10", "os": "Windows Server 2019", "accessible": True},
            {"type": "database_server", "ip": "192.168.1.60", "type": "SQL Server", "accessible": True},
            {"type": "exchange_server", "ip": "192.168.1.70", "os": "Windows Server 2019", "accessible": True},
            {"type": "file_server", "ip": "192.168.1.80", "os": "Windows Server 2019", "accessible": True},
            {"type": "workstation", "ip": "192.168.1.100", "os": "Windows 10", "accessible": True}
        ]

        return resources

    def _discover_personal_data(self) -> List[Dict[str, Any]]:
        """Discover personal data sources (basic user) - limited to personal files and browser data"""
        sources = []

        console.print("  📁 Scanning personal files and browser data...")
        time.sleep(2)  # Simulate file system scanning

        # Mock personal data sources - what a basic user can actually access
        sources = [
            {"name": "Personal_Documents", "type": "personal_files", "path": "~/Documents", "accessible": True, "estimated_records": 15},
            {"name": "Downloads_Folder", "type": "personal_files", "path": "~/Downloads", "accessible": True, "estimated_records": 20},
            {"name": "Browser_History", "type": "browser_data", "path": "~/AppData/Local/Chrome/User Data", "accessible": True, "estimated_records": 50},
            {"name": "Saved_Passwords", "type": "credentials", "path": "~/AppData/Local/Chrome/User Data", "accessible": True, "estimated_records": 8},
            {"name": "Desktop_Files", "type": "personal_files", "path": "~/Desktop", "accessible": True, "estimated_records": 12},
            {"name": "Local_App_Data", "type": "system_data", "path": "~/AppData/Local", "accessible": True, "estimated_records": 25}
        ]

        return sources

    def _discover_system_data(self) -> List[Dict[str, Any]]:
        """Discover system-wide data sources (admin) - access to all user profiles and system configs"""
        sources = []

        console.print("  📁 Scanning system-wide data and user profiles...")
        time.sleep(3)  # Simulate system enumeration + network discovery

        # Mock system data sources - what an admin can actually access
        sources = [
            {"name": "All_User_Profiles", "type": "user_data", "path": "C:/Users", "accessible": True, "estimated_records": 80},
            {"name": "System_Registry", "type": "system_data", "path": "HKEY_LOCAL_MACHINE", "accessible": True, "estimated_records": 40},
            {"name": "Local_SQL_Database", "type": "database", "path": "C:/ProgramData/MSSQL", "accessible": True, "estimated_records": 120},
            {"name": "Employee_Database", "type": "financial_data", "path": "C:/ProgramData/HR", "accessible": True, "estimated_records": 60},
            {"name": "Network_Shares", "type": "shared_data", "path": "//fileserver/shared", "accessible": True, "estimated_records": 100},
            {"name": "Service_Accounts", "type": "credentials", "path": "C:/Windows/ServiceProfiles", "accessible": True, "estimated_records": 25},
            {"name": "Application_Configs", "type": "system_data", "path": "C:/ProgramData", "accessible": True, "estimated_records": 45}
        ]

        return sources

    def _discover_enterprise_data(self) -> List[Dict[str, Any]]:
        """Discover enterprise data sources (domain admin) - access to enterprise databases and cloud services"""
        sources = []

        console.print("  📁 Scanning enterprise databases and cloud services...")
        time.sleep(5)  # Simulate enterprise database queries + cloud reconnaissance

        # Mock enterprise data sources - what a domain admin can actually access
        sources = [
            {"name": "Patient_Medical_Database", "type": "medical_records", "path": "SQL Server - EHR System", "accessible": True, "estimated_records": 2000},
            {"name": "Financial_ERP_System", "type": "financial_data", "path": "Oracle DB - Financial System", "accessible": True, "estimated_records": 1500},
            {"name": "Employee_HR_Database", "type": "financial_data", "path": "SQL Server - HR System", "accessible": True, "estimated_records": 800},
            {"name": "Exchange_Email_System", "type": "personal_info", "path": "Exchange Server - Corporate Email", "accessible": True, "estimated_records": 5000},
            {"name": "Domain_Controller", "type": "credentials", "path": "Active Directory - Domain Controller", "accessible": True, "estimated_records": 300},
            {"name": "Cloud_Storage", "type": "personal_info", "path": "OneDrive/SharePoint - Cloud Storage", "accessible": True, "estimated_records": 2000},
            {"name": "Backup_Systems", "type": "system_data", "path": "Backup Server - Enterprise Backups", "accessible": True, "estimated_records": 1000},
            {"name": "API_Services", "type": "credentials", "path": "Cloud APIs - AWS/Azure Services", "accessible": True, "estimated_records": 150}
        ]

        return sources

    def _attempt_local_escalation(self) -> Dict[str, Any]:
        """Attempt local privilege escalation"""
        console.print("  🔧 Attempting local privilege escalation...")
        time.sleep(2)

        # Simulate escalation attempt
        success = random.random() < self.performance_targets["privilege_escalation_success"]

        if success:
            console.print("  ✅ [green]Local privilege escalation successful[/green]")
            return {"success": True, "new_level": "admin", "method": "local_exploit"}
        else:
            console.print("  ❌ [red]Local privilege escalation failed[/red]")
            return {"success": False, "method": "local_exploit"}

    def _attempt_domain_escalation(self) -> Dict[str, Any]:
        """Attempt domain privilege escalation"""
        console.print("  🔧 Attempting domain privilege escalation...")
        time.sleep(2)

        # Simulate escalation attempt
        success = random.random() < self.performance_targets["privilege_escalation_success"]

        if success:
            console.print("  ✅ [green]Domain privilege escalation successful[/green]")
            return {"success": True, "new_level": "domain_admin", "method": "domain_exploit"}
        else:
            console.print("  ❌ [red]Domain privilege escalation failed[/red]")
            return {"success": False, "method": "domain_exploit"}

    def _calculate_network_discovery_success(self, resources: List[Dict[str, Any]]) -> float:
        """Calculate network discovery success rate"""
        if not resources:
            return 0.0

        accessible_resources = len([r for r in resources if r.get("accessible", False)])
        return (accessible_resources / len(resources)) * 100

    def _calculate_data_discovery_efficiency(self, classified_data: List[Dict[str, Any]], discovery_time: float) -> float:
        """Calculate data discovery efficiency (records per minute)"""
        if discovery_time == 0:
            return 0.0

        # Only count high and medium confidence classifications
        high_confidence_records = sum(
            item.get("estimated_records", 0) for item in classified_data
            if item.get("confidence_level") in ["HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE"]
        )

        return (high_confidence_records / discovery_time) * 60  # records per minute

    def _extract_data_from_source(self, source: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract data from a discovered source"""
        # Simulate data extraction
        records = []
        record_count = source.get("estimated_records", 0)

        for i in range(min(record_count, 10)):  # Limit to 10 records for demo
            records.append({
                "id": f"{source['name']}_{i+1}",
                "type": source["type"],
                "data": f"Sample data from {source['name']}",
                "timestamp": time.time()
            })

        return records

    def _calculate_data_value(self, data: List[Dict[str, Any]]) -> float:
        """Calculate estimated value of extracted data"""
        base_value = 0
        for record in data:
            if record["type"] == "medical_data":
                base_value += 1500
            elif record["type"] == "financial_data":
                base_value += 1000
            elif record["type"] == "credentials":
                base_value += 500
            elif record["type"] == "personal_files":
                base_value += 100
            else:
                base_value += 50

        return base_value

    def run_autonomous_assessment(self) -> Dict[str, Any]:
        """
        Run autonomous C2 assessment combining all operations.
        """
        console.print(Panel("🤖 [bold blue]C2 Agent: Autonomous Assessment[/bold blue]", style="blue"))

        start_time = time.time()

        # Step 1: Network Discovery
        network_results = self.discover_internal_network()

        # Step 2: Data Discovery
        data_results = self.discover_data_sources()

        # Step 3: Privilege Escalation
        escalation_results = self.escalate_privileges()

        # Step 4: Data Exfiltration (if sources found)
        exfiltration_results = None
        if data_results.get("sources"):
            exfiltration_results = self.exfiltrate_data(data_results["sources"])

        # Calculate overall performance
        total_time = time.time() - start_time
        performance_grade = self._calculate_performance_grade(network_results, data_results, escalation_results, exfiltration_results)

        return {
            "access_level": self.access_level,
            "network_discovery": network_results,
            "data_discovery": data_results,
            "privilege_escalation": escalation_results,
            "data_exfiltration": exfiltration_results,
            "total_time": total_time,
            "performance_grade": performance_grade
        }

    def _calculate_performance_grade(self, network_results: Dict, data_results: Dict, escalation_results: Dict, exfiltration_results: Optional[Dict]) -> str:
        """Calculate overall performance grade"""
        scores = []

        # Network discovery score
        network_success = network_results.get("success_rate", 0)
        scores.append(min(network_success / 80, 1.0))  # Target: 80%

        # Data discovery efficiency score
        data_efficiency = data_results.get("efficiency", 0)
        target_efficiency = self.performance_targets["data_discovery_efficiency"]
        scores.append(min(data_efficiency / target_efficiency, 1.0))

        # Privilege escalation score
        escalation_success = 1.0 if escalation_results.get("success", False) else 0.0
        scores.append(escalation_success)

        # Data exfiltration score
        if exfiltration_results:
            exfil_success = exfiltration_results.get("sources_successful", 0) / max(exfiltration_results.get("sources_processed", 1), 1)
            scores.append(exfil_success)
        else:
            scores.append(0.0)

        average_score = sum(scores) / len(scores)

        if average_score >= 0.9:
            return "A+ (Excellent)"
        elif average_score >= 0.8:
            return "A (Very Good)"
        elif average_score >= 0.7:
            return "B (Good)"
        elif average_score >= 0.6:
            return "C (Satisfactory)"
        else:
            return "D (Needs Improvement)"

    def _classify_data_source(self, source: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify a data source using AI-powered analysis and confidence scoring.
        """
        try:
            # Generate sample data for analysis
            sample_data = self._generate_sample_data(source)

            # AI-powered classification using Gemini
            ai_result = self._analyze_with_gemini(sample_data, source.get("path", ""))

            # Pattern-based analysis
            pattern_result = self._analyze_with_patterns(sample_data)

            # Path-based analysis
            path_result = self._analyze_file_path(source.get("path", ""))

            # Calculate final confidence score
            final_confidence = self._calculate_final_confidence(ai_result, pattern_result, path_result)

            # Determine confidence level
            confidence_level = self._determine_confidence_level(final_confidence)

            # Calculate estimated value
            estimated_value = self._calculate_data_value(ai_result["classification"], source.get("estimated_records", 0))

            return {
                "source_name": source.get("name", "unknown"),
                "source_path": source.get("path", ""),
                "classification": ai_result["classification"],
                "confidence_score": final_confidence,
                "confidence_level": confidence_level,
                "estimated_records": source.get("estimated_records", 0),
                "estimated_value": estimated_value,
                "ai_reasoning": ai_result.get("reasoning", ""),
                "accessible": source.get("accessible", False)
            }

        except Exception as e:
            console.print(f"⚠️ [yellow]Classification failed for {source.get('name', 'unknown')}: {e}[/yellow]")
            return {
                "source_name": source.get("name", "unknown"),
                "classification": "unclassified",
                "confidence_score": 0.0,
                "confidence_level": "LOW_CONFIDENCE",
                "estimated_records": 0,
                "estimated_value": 0,
                "error": str(e)
            }

    def _analyze_with_gemini(self, data_sample: str, file_path: str) -> Dict[str, Any]:
        """
        Use Gemini AI to analyze data content and provide classification with confidence.
        """
        try:
            prompt = f"""
            Analyze this data sample and provide a classification with confidence score:

            Data Sample: {data_sample}
            File Path: {file_path}

            Classify as one of:
            - medical_records (SSN, insurance, medical history, patient data)
            - financial_data (credit cards, bank accounts, salary, financial info)
            - credentials (passwords, API keys, tokens, authentication data)
            - personal_info (addresses, phone numbers, email, personal details)
            - system_data (configs, logs, backups, system information)

            Provide your response in this exact format:
            Classification: [classification]
            Confidence: [0.0-1.0]
            Reasoning: [brief explanation]
            """

            response = self.client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            return self._parse_gemini_response(response.text)

        except Exception as e:
            console.print(f"⚠️ [yellow]Gemini analysis failed: {e}[/yellow]")
            return {
                "classification": "unclassified",
                "confidence": 0.0,
                "reasoning": f"AI analysis failed: {e}"
            }

    def _parse_gemini_response(self, response_text: str) -> Dict[str, Any]:
        """
        Parse Gemini's response to extract classification, confidence, and reasoning.
        """
        try:
            lines = response_text.strip().split('\n')
            classification = "unclassified"
            confidence = 0.0
            reasoning = "Unable to parse response"

            for line in lines:
                if line.startswith("Classification:"):
                    classification = line.split(":", 1)[1].strip().lower()
                elif line.startswith("Confidence:"):
                    try:
                        confidence = float(line.split(":", 1)[1].strip())
                    except ValueError:
                        confidence = 0.0
                elif line.startswith("Reasoning:"):
                    reasoning = line.split(":", 1)[1].strip()

            return {
                "classification": classification,
                "confidence": confidence,
                "reasoning": reasoning
            }

        except Exception as e:
            return {
                "classification": "unclassified",
                "confidence": 0.0,
                "reasoning": f"Parse error: {e}"
            }

    def _analyze_with_patterns(self, data_sample: str) -> Dict[str, Any]:
        """
        Analyze data using pattern matching for classification.
        """
        # Medical records patterns
        medical_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'patient_id|medical_record|diagnosis',
            r'insurance_id|policy_number',
            r'blood_type|allergies|medications',
            r'doctor|physician|nurse|hospital'
        ]

        # Financial data patterns
        financial_patterns = [
            r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # Credit card
            r'bank_account|routing_number',
            r'salary|wage|income|payroll',
            r'tax_id|ein',
            r'credit_score|debt|loan'
        ]

        # Credentials patterns
        credential_patterns = [
            r'password|passwd|pwd',
            r'api_key|secret_key|token',
            r'username|login|user_id',
            r'private_key|certificate',
            r'auth|authentication'
        ]

        # Personal info patterns
        personal_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone
            r'\d+\s+\w+\s+\w+',  # Address
            r'name|address|phone|email'
        ]

        # System data patterns
        system_patterns = [
            r'config|configuration',
            r'log|logging',
            r'backup|backup',
            r'system|sys',
            r'temp|tmp'
        ]

        import re

        # Check each pattern category
        medical_matches = sum(1 for pattern in medical_patterns if re.search(pattern, data_sample, re.IGNORECASE))
        financial_matches = sum(1 for pattern in financial_patterns if re.search(pattern, data_sample, re.IGNORECASE))
        credential_matches = sum(1 for pattern in credential_patterns if re.search(pattern, data_sample, re.IGNORECASE))
        personal_matches = sum(1 for pattern in personal_patterns if re.search(pattern, data_sample, re.IGNORECASE))
        system_matches = sum(1 for pattern in system_patterns if re.search(pattern, data_sample, re.IGNORECASE))

        # Determine classification based on highest match count
        matches = {
            "medical_records": medical_matches,
            "financial_data": financial_matches,
            "credentials": credential_matches,
            "personal_info": personal_matches,
            "system_data": system_matches
        }

        max_matches = max(matches.values())
        if max_matches > 0:
            classification = max(matches, key=matches.get)
            confidence = min(max_matches / 5.0, 1.0)  # Normalize to 0-1
        else:
            classification = "unclassified"
            confidence = 0.0

        return {
            "classification": classification,
            "confidence": confidence,
            "reasoning": f"Pattern matching found {max_matches} matches"
        }

    def _analyze_file_path(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze file path for classification hints.
        """
        if not file_path:
            return {"classification": "unclassified", "confidence": 0.0}

        path_lower = file_path.lower()

        # Path-based classification
        if any(keyword in path_lower for keyword in ['patient', 'medical', 'health', 'clinic']):
            return {"classification": "medical_records", "confidence": 0.7}
        elif any(keyword in path_lower for keyword in ['financial', 'payroll', 'accounting', 'bank']):
            return {"classification": "financial_data", "confidence": 0.7}
        elif any(keyword in path_lower for keyword in ['password', 'credential', 'auth', 'key']):
            return {"classification": "credentials", "confidence": 0.7}
        elif any(keyword in path_lower for keyword in ['config', 'system', 'log', 'backup']):
            return {"classification": "system_data", "confidence": 0.6}
        elif any(keyword in path_lower for keyword in ['user', 'personal', 'documents']):
            return {"classification": "personal_info", "confidence": 0.6}
        else:
            return {"classification": "unclassified", "confidence": 0.3}

    def _calculate_final_confidence(self, ai_result: Dict, pattern_result: Dict, path_result: Dict) -> float:
        """
        Calculate final confidence score using weighted combination.
        """
        # Weighted combination (AI gets highest weight)
        ai_confidence = ai_result.get("confidence", 0.0) * 0.5
        pattern_confidence = pattern_result.get("confidence", 0.0) * 0.3
        path_confidence = path_result.get("confidence", 0.0) * 0.2

        return min(ai_confidence + pattern_confidence + path_confidence, 1.0)

    def _determine_confidence_level(self, confidence_score: float) -> str:
        """
        Determine confidence level based on score.
        """
        if confidence_score >= 0.8:
            return "HIGH_CONFIDENCE"
        elif confidence_score >= 0.6:
            return "MEDIUM_CONFIDENCE"
        else:
            return "LOW_CONFIDENCE"

    def _calculate_data_value(self, classification: str, record_count: int) -> float:
        """
        Calculate estimated monetary value based on classification and record count.
        """
        value_per_record = {
            "medical_records": 1500,
            "financial_data": 1000,
            "credentials": 500,
            "personal_info": 100,
            "system_data": 50,
            "unclassified": 10
        }

        base_value = value_per_record.get(classification, 10)
        return base_value * record_count

    def _calculate_total_data_value(self, classified_data: List[Dict[str, Any]]) -> float:
        """
        Calculate total estimated value of all classified data.
        """
        return sum(item.get("estimated_value", 0) for item in classified_data)

    def _display_classification_summary(self, classified_data: List[Dict[str, Any]]):
        """
        Display a summary of data classification results.
        """
        if not classified_data:
            console.print("📊 [yellow]No data classified[/yellow]")
            return

        # Count by classification
        classification_counts = {}
        confidence_counts = {"HIGH_CONFIDENCE": 0, "MEDIUM_CONFIDENCE": 0, "LOW_CONFIDENCE": 0}
        total_value = 0

        for item in classified_data:
            classification = item.get("classification", "unclassified")
            confidence_level = item.get("confidence_level", "LOW_CONFIDENCE")
            value = item.get("estimated_value", 0)

            classification_counts[classification] = classification_counts.get(classification, 0) + 1
            confidence_counts[confidence_level] = confidence_counts[confidence_level] + 1
            total_value += value

        # Display summary table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Classification", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Confidence Level", style="yellow")

        for classification, count in classification_counts.items():
            # Find confidence level for this classification
            confidence_level = "LOW_CONFIDENCE"
            for item in classified_data:
                if item.get("classification") == classification:
                    confidence_level = item.get("confidence_level", "LOW_CONFIDENCE")
                    break

            table.add_row(
                classification.replace("_", " ").title(),
                str(count),
                confidence_level
            )

        console.print(table)
        console.print(f"💰 [green]Total Estimated Value: ${total_value:,.2f}[/green]")
        console.print(f"🎯 [blue]High Confidence: {confidence_counts['HIGH_CONFIDENCE']} sources[/blue]")

    def _generate_sample_data(self, source: Dict[str, Any]) -> str:
        """
        Generate sample data for analysis based on source type and access level.
        """
        source_type = source.get("type", "unknown")
        source_name = source.get("name", "unknown")

        # Generate realistic sample data based on source type and access level
        if "medical" in source_type.lower() or "patient" in source_name.lower():
            return f"Patient ID: P001, Name: John Doe, SSN: 123-45-6789, Insurance: BC123456789, Diagnosis: Hypertension, Blood Type: A+, Allergies: Penicillin"
        elif "financial" in source_type.lower() or "payroll" in source_name.lower() or "employee" in source_name.lower():
            return f"Employee: Jane Smith, SSN: 987-65-4321, Salary: $85,000, Bank Account: 1234567890, Credit Card: 4532-1234-5678-9012, Department: Engineering"
        elif "credential" in source_type.lower() or "password" in source_name.lower() or "domain" in source_name.lower():
            return f"Username: domain_admin, Password: DomainPass2024!, API Key: sk-prod-1234567890abcdef, Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs..., Service Account: svc_sql"
        elif "personal" in source_type.lower() or "user" in source_name.lower() or "browser" in source_name.lower():
            return f"Name: Alice Johnson, Email: alice@company.com, Phone: 555-123-4567, Address: 123 Main St, Browser: Chrome, Last Login: 2024-01-15"
        elif "system" in source_type.lower() or "config" in source_name.lower() or "registry" in source_name.lower():
            return f"Database Host: prod-db.company.com, Port: 5432, Username: db_admin, Password: AdminPass123!, Config: production, Version: PostgreSQL 13"
        elif "email" in source_name.lower() or "exchange" in source_name.lower():
            return f"From: ceo@company.com, To: board@company.com, Subject: Q4 Financial Results, Date: 2024-01-15, Attachments: financial_report.pdf"
        elif "cloud" in source_name.lower() or "storage" in source_name.lower():
            return f"File: confidential_contract.pdf, Owner: legal@company.com, Size: 2.5MB, Last Modified: 2024-01-14, Access Level: Restricted"
        else:
            return f"Sample data from {source_name}: Contains various information types based on access level"