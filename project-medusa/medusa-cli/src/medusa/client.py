"""
Backend API client for MEDUSA
Handles communication with the backend penetration testing API
Includes mock responses for development
"""

import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime
import random


class MedusaClient:
    """Client for communicating with MEDUSA backend API"""

    def __init__(self, base_url: str, api_key: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout)

    async def __aenter__(self):
        """Support async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Ensure HTTP client is closed on context exit."""
        await self.close()

    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()

    async def health_check(self) -> Dict[str, Any]:
        """Check if backend is reachable"""
        try:
            response = await self.client.get(f"{self.base_url}/health")
            return {"status": "online", "response_time": response.elapsed.total_seconds()}
        except Exception as e:
            # Return mock response for development
            return {"status": "mock", "message": "Using mock backend", "error": str(e)}

    async def start_operation(self, operation_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Start a new penetration testing operation"""
        # Mock response for development
        return {
            "operation_id": f"op_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "status": "started",
            "operation_type": operation_type,
            "started_at": datetime.now().isoformat(),
            "phases": ["reconnaissance", "enumeration", "exploitation", "post_exploitation"],
        }

    async def get_operation_status(self, operation_id: str) -> Dict[str, Any]:
        """Get status of an ongoing operation"""
        # Mock response
        phases = [
            {
                "name": "reconnaissance",
                "status": "complete",
                "progress": 100,
                "findings": 3,
                "duration": 45.2,
            },
            {
                "name": "enumeration",
                "status": "in_progress",
                "progress": 67,
                "findings": 5,
                "duration": 32.1,
            },
            {"name": "exploitation", "status": "pending", "progress": 0, "findings": 0, "duration": 0},
            {
                "name": "post_exploitation",
                "status": "pending",
                "progress": 0,
                "findings": 0,
                "duration": 0,
            },
        ]

        return {
            "operation_id": operation_id,
            "status": "running",
            "current_phase": "enumeration",
            "overall_progress": 42,
            "phases": phases,
            "total_findings": 8,
            "elapsed_time": 77.3,
        }

    async def perform_reconnaissance(self, target: str) -> Dict[str, Any]:
        """Perform reconnaissance on target"""
        # Mock response with realistic data
        return {
            "phase": "reconnaissance",
            "target": target,
            "duration": random.uniform(30, 60),
            "findings": [
                {
                    "type": "open_port",
                    "port": 80,
                    "service": "http",
                    "version": "nginx 1.21.0",
                    "severity": "info",
                },
                {
                    "type": "open_port",
                    "port": 443,
                    "service": "https",
                    "version": "nginx 1.21.0",
                    "severity": "info",
                },
                {
                    "type": "open_port",
                    "port": 3001,
                    "service": "http",
                    "version": "Node.js Express",
                    "severity": "info",
                },
                {
                    "type": "webapp",
                    "url": f"{target}",
                    "title": "MedCare EHR System",
                    "technologies": ["React", "Node.js", "Express"],
                    "severity": "info",
                },
            ],
            "techniques": [{"id": "T1046", "name": "Network Service Discovery", "status": "executed"}],
        }

    async def enumerate_services(self, target: str) -> Dict[str, Any]:
        """Enumerate services on target"""
        # Mock response
        return {
            "phase": "enumeration",
            "target": target,
            "duration": random.uniform(40, 80),
            "findings": [
                {
                    "type": "api_endpoint",
                    "path": "/api/patients",
                    "method": "GET",
                    "authentication": "none",
                    "severity": "medium",
                    "title": "Unauthenticated API Endpoint",
                    "description": "Patient data endpoint accessible without authentication",
                },
                {
                    "type": "api_endpoint",
                    "path": "/api/employees",
                    "method": "GET",
                    "authentication": "none",
                    "severity": "high",
                    "title": "Employee Data Exposure",
                    "description": "Employee credentials exposed via unauthenticated endpoint",
                },
                {
                    "type": "vulnerability",
                    "cve": "CVE-2021-XXXX",
                    "severity": "high",
                    "title": "SQL Injection Vulnerability",
                    "description": "Possible SQL injection in search parameter",
                    "confidence": "medium",
                },
                {
                    "type": "misconfiguration",
                    "severity": "medium",
                    "title": "CORS Misconfiguration",
                    "description": "Overly permissive CORS policy allows any origin",
                },
                {
                    "type": "information_disclosure",
                    "severity": "low",
                    "title": "Server Version Disclosure",
                    "description": "Server headers reveal version information",
                },
            ],
            "techniques": [
                {"id": "T1590", "name": "Gather Victim Network Information", "status": "executed"},
                {"id": "T1592", "name": "Gather Victim Host Information", "status": "executed"},
            ],
        }

    async def attempt_exploitation(
        self, target: str, vulnerability: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Attempt to exploit a vulnerability"""
        # Mock response
        success = random.choice([True, False, False])  # 33% success rate

        if success:
            return {
                "phase": "exploitation",
                "target": target,
                "vulnerability": vulnerability,
                "status": "success",
                "duration": random.uniform(20, 50),
                "result": {
                    "access_gained": "database_read",
                    "data_extracted": 150,
                    "credentials_found": 3,
                },
                "techniques": [
                    {"id": "T1190", "name": "Exploit Public-Facing Application", "status": "executed"}
                ],
            }
        else:
            return {
                "phase": "exploitation",
                "target": target,
                "vulnerability": vulnerability,
                "status": "failed",
                "duration": random.uniform(10, 30),
                "error": "Exploitation attempt failed - target may be patched",
                "techniques": [
                    {"id": "T1190", "name": "Exploit Public-Facing Application", "status": "failed"}
                ],
            }

    async def exfiltrate_data(self, target: str, data_type: str) -> Dict[str, Any]:
        """Exfiltrate data from target"""
        # Mock response
        record_counts = {"medical_records": 2000, "employee_data": 150, "credentials": 45}

        return {
            "phase": "post_exploitation",
            "target": target,
            "data_type": data_type,
            "duration": random.uniform(15, 40),
            "status": "success",
            "records_exfiltrated": record_counts.get(data_type, 100),
            "estimated_value": random.randint(50000, 500000),
            "techniques": [{"id": "T1041", "name": "Exfiltration Over C2 Channel", "status": "executed"}],
        }

    async def generate_report(self, operation_id: str) -> Dict[str, Any]:
        """Generate final operation report"""
        # Mock comprehensive report
        return {
            "operation_id": operation_id,
            "generated_at": datetime.now().isoformat(),
            "duration_seconds": 235.6,
            "summary": {
                "total_findings": 12,
                "critical": 0,
                "high": 3,
                "medium": 5,
                "low": 4,
                "techniques_used": 8,
                "success_rate": 0.75,
            },
            "phases": [
                {
                    "name": "reconnaissance",
                    "status": "complete",
                    "duration": 45.2,
                    "findings": 4,
                    "techniques": 1,
                },
                {
                    "name": "enumeration",
                    "status": "complete",
                    "duration": 72.1,
                    "findings": 5,
                    "techniques": 2,
                },
                {
                    "name": "exploitation",
                    "status": "complete",
                    "duration": 88.3,
                    "findings": 2,
                    "techniques": 3,
                },
                {
                    "name": "post_exploitation",
                    "status": "complete",
                    "duration": 30.0,
                    "findings": 1,
                    "techniques": 2,
                },
            ],
            "mitre_coverage": [
                {"id": "T1046", "name": "Network Service Discovery", "status": "executed"},
                {"id": "T1590", "name": "Gather Victim Network Information", "status": "executed"},
                {"id": "T1592", "name": "Gather Victim Host Information", "status": "executed"},
                {"id": "T1190", "name": "Exploit Public-Facing Application", "status": "executed"},
                {"id": "T1041", "name": "Exfiltration Over C2 Channel", "status": "executed"},
                {"id": "T1078", "name": "Valid Accounts", "status": "executed"},
                {"id": "T1059", "name": "Command and Scripting Interpreter", "status": "executed"},
                {"id": "T1485", "name": "Data Destruction", "status": "skipped"},
            ],
            "findings": [
                {
                    "id": "finding_001",
                    "severity": "high",
                    "title": "Unauthenticated API Access",
                    "description": "Critical API endpoints accessible without authentication",
                    "affected_endpoints": ["/api/patients", "/api/employees"],
                    "recommendation": "Implement OAuth 2.0 or JWT authentication",
                    "cvss_score": 7.5,
                },
                {
                    "id": "finding_002",
                    "severity": "high",
                    "title": "SQL Injection Vulnerability",
                    "description": "User input not properly sanitized in database queries",
                    "affected_endpoints": ["/api/search"],
                    "recommendation": "Use parameterized queries or ORM",
                    "cvss_score": 8.2,
                },
                {
                    "id": "finding_003",
                    "severity": "high",
                    "title": "Sensitive Data Exposure",
                    "description": "Patient SSN and financial data returned in API responses",
                    "affected_endpoints": ["/api/patients"],
                    "recommendation": "Implement field-level access control and data masking",
                    "cvss_score": 7.8,
                },
            ],
        }

    async def get_ai_recommendation(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get AI recommendation for next action"""
        # Mock AI-powered recommendation
        recommendations = [
            {
                "action": "exploit_sql_injection",
                "confidence": 0.85,
                "reasoning": "Detected SQL injection vulnerability with high success probability",
                "technique": "T1190",
                "risk_level": "MEDIUM",
            },
            {
                "action": "enumerate_databases",
                "confidence": 0.92,
                "reasoning": "Successful authentication allows database enumeration",
                "technique": "T1046",
                "risk_level": "LOW",
            },
            {
                "action": "exfiltrate_patient_data",
                "confidence": 0.78,
                "reasoning": "Unauthenticated access to patient records API",
                "technique": "T1041",
                "risk_level": "HIGH",
            },
        ]

        return {
            "recommendations": random.sample(recommendations, k=2),
            "context_analysis": "Target appears to be a healthcare application with multiple security weaknesses",
            "suggested_next_phase": "exploitation",
        }


# Synchronous wrapper for simpler usage
class SyncMedusaClient:
    """Synchronous wrapper around async client"""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key

    def _run_async(self, coro):
        """Helper to run async functions synchronously"""
        import asyncio

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(coro)

    def health_check(self) -> Dict[str, Any]:
        async def _check():
            async with MedusaClient(self.base_url, self.api_key) as client:
                return await client.health_check()

        return self._run_async(_check())

    # Add other sync wrappers as needed...

