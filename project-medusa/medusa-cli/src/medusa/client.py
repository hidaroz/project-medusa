"""
Backend API client for MEDUSA
Handles communication with the backend penetration testing API
Includes mock responses for development and real LLM integration
"""

import httpx
from typing import Dict, Any, List, Optional
from datetime import datetime
import random
import logging

from medusa.core.llm import LLMConfig, create_llm_client, LLMClient, MockLLMClient
from medusa.tools import NmapScanner, WebScanner, SQLMapScanner, NiktoScanner

logger = logging.getLogger(__name__)


class MedusaClient:
    """Client for communicating with MEDUSA backend API"""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: int = 30,
        llm_config: Optional[Dict[str, Any]] = None
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.client = httpx.AsyncClient(timeout=timeout)

        # Initialize LLM client
        if llm_config:
            llm_cfg = LLMConfig(
                api_key=llm_config.get("api_key", api_key),
                model=llm_config.get("model", "gemini-pro"),
                temperature=llm_config.get("temperature", 0.7),
                max_tokens=llm_config.get("max_tokens", 2048),
                timeout=llm_config.get("timeout", 30),
                max_retries=llm_config.get("max_retries", 3),
                mock_mode=llm_config.get("mock_mode", False)
            )
            self.llm_client = create_llm_client(llm_cfg)
            logger.info(f"LLM client initialized: {type(self.llm_client).__name__}")
        else:
            # Fallback to mock mode if no config provided
            self.llm_client = MockLLMClient()
            logger.info("No LLM config provided, using MockLLMClient")

        # Initialize real pentesting tools
        self.nmap = NmapScanner(timeout=600)
        self.web_scanner = WebScanner(timeout=120)
        self.sqlmap = SQLMapScanner(timeout=900)
        self.nikto = NiktoScanner(timeout=1800)
        logger.info("Real pentesting tools initialized: NmapScanner, WebScanner, SQLMapScanner, NiktoScanner")

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
        """
        Perform reconnaissance on target using REAL tools

        This method now uses actual nmap and web scanning instead of mock data.

        Process:
        1. Get AI recommendation for reconnaissance strategy
        2. Execute real nmap port scan
        3. Execute real web reconnaissance
        4. Return combined findings

        Args:
            target: Target URL or IP address

        Returns:
            Dict with real reconnaissance findings
        """
        logger.info(f"Starting REAL reconnaissance on target: {target}")
        import time
        start_time = time.time()

        all_findings = []
        executed_actions = []
        techniques = []

        # Parse target to extract hostname/IP
        target_host = target
        if target.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            target_host = parsed.netloc or target
            # Remove port if present for nmap
            if ':' in target_host:
                target_host = target_host.split(':')[0]

        # Step 1: Get AI recommendation for reconnaissance strategy
        try:
            strategy = await self.get_reconnaissance_strategy(target)
            logger.info(f"AI recommended {len(strategy.get('recommended_actions', []))} reconnaissance actions")
        except Exception as e:
            logger.warning(f"Failed to get AI strategy: {e}, proceeding with default strategy")
            strategy = {
                "recommended_actions": [
                    {"action": "port_scan", "ports": "1-1000"},
                    {"action": "web_fingerprint"}
                ],
                "focus_areas": ["web_services"],
                "risk_assessment": "LOW"
            }

        # Step 2: Execute REAL nmap scan
        logger.info(f"Executing REAL nmap scan on {target_host}")
        try:
            nmap_result = await self.nmap.execute(
                target=target_host,
                ports="1-1000",
                scan_type="-sV"
            )

            if nmap_result["success"]:
                logger.info(f"Nmap found {nmap_result['findings_count']} open ports/services")
                all_findings.extend(nmap_result["findings"])
                executed_actions.append({
                    "action": "port_scan",
                    "tool": "nmap",
                    "success": True,
                    "findings_count": nmap_result["findings_count"],
                    "duration": nmap_result["duration_seconds"]
                })
                techniques.append({
                    "id": "T1046",
                    "name": "Network Service Discovery",
                    "status": "executed"
                })
            else:
                logger.error(f"Nmap scan failed: {nmap_result.get('error', 'Unknown error')}")
                executed_actions.append({
                    "action": "port_scan",
                    "tool": "nmap",
                    "success": False,
                    "error": nmap_result.get("error", "Scan failed")
                })
        except Exception as e:
            logger.error(f"Nmap execution exception: {e}")
            executed_actions.append({
                "action": "port_scan",
                "tool": "nmap",
                "success": False,
                "error": str(e)
            })

        # Step 3: Execute REAL web reconnaissance
        logger.info(f"Executing REAL web reconnaissance on {target}")
        try:
            web_result = await self.web_scanner.execute(
                target=target,
                check_https=True,
                use_whatweb=True,
                check_endpoints=True
            )

            if web_result["success"]:
                logger.info(f"Web scanner found {web_result['findings_count']} findings")
                all_findings.extend(web_result["findings"])
                executed_actions.append({
                    "action": "web_reconnaissance",
                    "tool": "web_scanner",
                    "success": True,
                    "findings_count": web_result["findings_count"],
                    "duration": web_result["duration_seconds"]
                })
                techniques.append({
                    "id": "T1595",
                    "name": "Active Scanning - Web Technologies",
                    "status": "executed"
                })
            else:
                logger.warning(f"Web scan failed: {web_result.get('error', 'Unknown error')}")
                executed_actions.append({
                    "action": "web_reconnaissance",
                    "tool": "web_scanner",
                    "success": False,
                    "error": web_result.get("error", "Scan failed")
                })
        except Exception as e:
            logger.error(f"Web scanner exception: {e}")
            executed_actions.append({
                "action": "web_reconnaissance",
                "tool": "web_scanner",
                "success": False,
                "error": str(e)
            })

        duration = time.time() - start_time

        logger.info(
            f"Reconnaissance complete: {len(all_findings)} total findings, "
            f"{duration:.2f}s duration"
        )

        return {
            "phase": "reconnaissance",
            "target": target,
            "duration": duration,
            "findings": all_findings,
            "executed_actions": executed_actions,
            "techniques": techniques,
            "strategy": strategy,
            "findings_count": len(all_findings),
            "success": len(all_findings) > 0,
            "mode": "REAL_TOOLS"  # Flag to indicate real tools were used
        }

    async def enumerate_services(self, target: str, reconnaissance_findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Enumerate services on target using REAL tools

        This method performs deeper enumeration based on reconnaissance findings.

        Process:
        1. Get AI recommendation for enumeration strategy
        2. Perform deep web scanning on discovered services
        3. Test common API endpoints
        4. Return combined enumeration findings

        Args:
            target: Target URL or IP address
            reconnaissance_findings: Optional findings from reconnaissance phase

        Returns:
            Dict with real enumeration findings
        """
        logger.info(f"Starting REAL enumeration on target: {target}")
        import time
        start_time = time.time()

        all_findings = []
        executed_actions = []
        techniques = []

        # Step 1: Get AI recommendation for enumeration strategy
        try:
            if reconnaissance_findings:
                strategy = await self.get_enumeration_strategy(target, reconnaissance_findings)
                logger.info(f"AI recommended {len(strategy.get('recommended_actions', []))} enumeration actions")
            else:
                strategy = {
                    "recommended_actions": [{"action": "enumerate_web_paths"}],
                    "services_to_probe": ["http", "https"],
                    "risk_assessment": "LOW"
                }
        except Exception as e:
            logger.warning(f"Failed to get AI enumeration strategy: {e}, proceeding with default")
            strategy = {
                "recommended_actions": [{"action": "enumerate_web_paths"}],
                "services_to_probe": ["http", "https"],
                "risk_assessment": "LOW"
            }

        # Step 2: Deep web enumeration
        logger.info(f"Executing deep web enumeration on {target}")
        try:
            # Check for common API endpoints
            api_findings = await self._enumerate_api_endpoints(target)
            all_findings.extend(api_findings)

            if api_findings:
                executed_actions.append({
                    "action": "api_enumeration",
                    "tool": "custom_http_prober",
                    "success": True,
                    "findings_count": len(api_findings)
                })
                techniques.append({
                    "id": "T1590",
                    "name": "Gather Victim Network Information",
                    "status": "executed"
                })
        except Exception as e:
            logger.error(f"API enumeration exception: {e}")
            executed_actions.append({
                "action": "api_enumeration",
                "success": False,
                "error": str(e)
            })

        # Step 3: Analyze web services for misconfigurations
        if reconnaissance_findings:
            logger.info("Analyzing reconnaissance findings for security issues")
            analysis_findings = self._analyze_findings_for_vulnerabilities(reconnaissance_findings)
            all_findings.extend(analysis_findings)

            if analysis_findings:
                executed_actions.append({
                    "action": "vulnerability_analysis",
                    "tool": "custom_analyzer",
                    "success": True,
                    "findings_count": len(analysis_findings)
                })
                techniques.append({
                    "id": "T1592",
                    "name": "Gather Victim Host Information",
                    "status": "executed"
                })

        duration = time.time() - start_time

        logger.info(
            f"Enumeration complete: {len(all_findings)} findings, "
            f"{duration:.2f}s duration"
        )

        return {
            "phase": "enumeration",
            "target": target,
            "duration": duration,
            "findings": all_findings,
            "executed_actions": executed_actions,
            "techniques": techniques,
            "strategy": strategy,
            "findings_count": len(all_findings),
            "success": True,
            "mode": "REAL_TOOLS"
        }

    async def _enumerate_api_endpoints(self, target: str) -> List[Dict[str, Any]]:
        """
        Enumerate common API endpoints

        Args:
            target: Target URL

        Returns:
            List of API endpoint findings
        """
        findings = []

        # Common API endpoints to check
        api_endpoints = [
            "/api/v1/users",
            "/api/users",
            "/api/patients",
            "/api/employees",
            "/api/admin",
            "/api/config",
            "/api/health",
            "/api/status",
            "/api/docs",
            "/api/swagger",
            "/graphql",
            "/api/graphql",
        ]

        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"

        try:
            import aiohttp
            from urllib.parse import urljoin

            async with aiohttp.ClientSession() as session:
                for endpoint in api_endpoints:
                    url = urljoin(target, endpoint)

                    try:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=5),
                            ssl=False,
                            allow_redirects=False
                        ) as response:
                            if response.status in [200, 401, 403]:
                                # Endpoint exists
                                auth_required = response.status in [401, 403]

                                finding = {
                                    "type": "api_endpoint",
                                    "url": url,
                                    "path": endpoint,
                                    "method": "GET",
                                    "status_code": response.status,
                                    "authentication": "required" if auth_required else "none",
                                    "severity": "low" if auth_required else "medium",
                                    "title": f"API Endpoint Discovered: {endpoint}",
                                    "description": f"API endpoint accessible at {url}",
                                    "confidence": "high"
                                }

                                # Check if returns JSON
                                content_type = response.headers.get('content-type', '')
                                if 'json' in content_type.lower():
                                    finding["content_type"] = "application/json"
                                    finding["severity"] = "low" if auth_required else "medium"

                                findings.append(finding)
                                logger.debug(f"Found API endpoint: {url} (status: {response.status})")

                    except aiohttp.ClientError:
                        # Endpoint doesn't exist or isn't accessible
                        pass

        except Exception as e:
            logger.error(f"API enumeration failed: {e}")

        return findings

    def _analyze_findings_for_vulnerabilities(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze reconnaissance findings to identify potential vulnerabilities

        Args:
            findings: List of reconnaissance findings

        Returns:
            List of potential vulnerability findings
        """
        vulnerabilities = []

        for finding in findings:
            finding_type = finding.get("type", "")

            # Check for outdated software versions
            if finding_type == "open_port":
                service = finding.get("service", "")
                version = finding.get("version", "")

                # Check for known vulnerable services
                if service in ["ftp", "telnet", "rexec", "rlogin"]:
                    vulnerabilities.append({
                        "type": "vulnerability",
                        "severity": "high",
                        "title": f"Insecure Service Detected: {service.upper()}",
                        "description": f"{service.upper()} is an insecure protocol that transmits data in cleartext",
                        "port": finding.get("port"),
                        "service": service,
                        "confidence": "high",
                        "recommendation": f"Disable {service.upper()} and use secure alternatives (SSH, SFTP)"
                    })

                # Check for exposed databases
                if finding.get("port") in [3306, 5432, 27017, 6379, 9200]:
                    db_map = {
                        3306: "MySQL",
                        5432: "PostgreSQL",
                        27017: "MongoDB",
                        6379: "Redis",
                        9200: "Elasticsearch"
                    }
                    db_name = db_map.get(finding.get("port"), "Database")

                    vulnerabilities.append({
                        "type": "misconfiguration",
                        "severity": "high",
                        "title": f"Exposed {db_name} Database",
                        "description": f"{db_name} database port is accessible externally",
                        "port": finding.get("port"),
                        "confidence": "high",
                        "recommendation": f"Restrict {db_name} access to internal networks only"
                    })

            # Check for security header issues (already detected in reconnaissance)
            if finding_type == "misconfiguration":
                if "CORS" in finding.get("title", ""):
                    # Already detected, no need to duplicate
                    pass

        return vulnerabilities

    async def scan_for_vulnerabilities(
        self,
        target: str,
        enumeration_findings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Scan for vulnerabilities using REAL tools (SQLMap, Nikto)

        This method performs deep vulnerability scanning based on enumeration findings.

        Process:
        1. Run Nikto for web vulnerability scanning
        2. Run SQLMap for SQL injection detection on discovered endpoints
        3. Analyze and prioritize findings
        4. Return comprehensive vulnerability report

        Args:
            target: Target URL or hostname
            enumeration_findings: Optional findings from enumeration phase

        Returns:
            Dict with vulnerability findings
        """
        logger.info(f"Starting REAL vulnerability scanning on target: {target}")
        import time
        start_time = time.time()

        all_findings = []
        executed_actions = []
        techniques = []

        # Ensure target has proper URL format
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"

        # Step 1: Run Nikto web vulnerability scan
        logger.info(f"Executing REAL Nikto scan on {target}")
        try:
            nikto_result = await self.nikto.execute(
                target_url=target,
                tuning="123456789",  # All checks
                output_format="txt"
            )

            if nikto_result["success"]:
                logger.info(f"Nikto found {nikto_result['findings_count']} vulnerabilities")
                all_findings.extend(nikto_result["findings"])
                executed_actions.append({
                    "action": "web_vulnerability_scan",
                    "tool": "nikto",
                    "success": True,
                    "findings_count": nikto_result["findings_count"],
                    "duration": nikto_result["duration_seconds"]
                })
                techniques.append({
                    "id": "T1046",
                    "name": "Network Service Discovery - Web Vulnerabilities",
                    "status": "executed"
                })
            else:
                logger.warning(f"Nikto scan failed: {nikto_result.get('error', 'Unknown error')}")
                executed_actions.append({
                    "action": "web_vulnerability_scan",
                    "tool": "nikto",
                    "success": False,
                    "error": nikto_result.get("error", "Scan failed")
                })
        except Exception as e:
            logger.error(f"Nikto execution exception: {e}")
            executed_actions.append({
                "action": "web_vulnerability_scan",
                "tool": "nikto",
                "success": False,
                "error": str(e)
            })

        # Step 2: Run SQLMap for SQL injection testing
        # Test common injection points
        sql_injection_targets = self._identify_sql_injection_targets(target, enumeration_findings)

        for sql_target in sql_injection_targets[:5]:  # Limit to 5 targets for performance
            logger.info(f"Testing {sql_target} for SQL injection")
            try:
                sqlmap_result = await self.sqlmap.execute(
                    target_url=sql_target,
                    risk=2,
                    level=3,
                    batch=True
                )

                if sqlmap_result["success"] and sqlmap_result["findings_count"] > 0:
                    logger.info(f"SQLMap found {sqlmap_result['findings_count']} SQL injection vulnerabilities")
                    all_findings.extend(sqlmap_result["findings"])
                    executed_actions.append({
                        "action": "sql_injection_scan",
                        "tool": "sqlmap",
                        "target": sql_target,
                        "success": True,
                        "findings_count": sqlmap_result["findings_count"],
                        "duration": sqlmap_result["duration_seconds"]
                    })
                    techniques.append({
                        "id": "T1190",
                        "name": "Exploit Public-Facing Application - SQL Injection",
                        "status": "detected"
                    })
                else:
                    executed_actions.append({
                        "action": "sql_injection_scan",
                        "tool": "sqlmap",
                        "target": sql_target,
                        "success": True,
                        "findings_count": 0,
                        "message": "No SQL injection detected"
                    })

            except Exception as e:
                logger.error(f"SQLMap execution exception on {sql_target}: {e}")
                executed_actions.append({
                    "action": "sql_injection_scan",
                    "tool": "sqlmap",
                    "target": sql_target,
                    "success": False,
                    "error": str(e)
                })

        # Step 3: Prioritize findings by severity
        critical_findings = [f for f in all_findings if f.get("severity") == "critical"]
        high_findings = [f for f in all_findings if f.get("severity") == "high"]
        medium_findings = [f for f in all_findings if f.get("severity") == "medium"]
        low_findings = [f for f in all_findings if f.get("severity") == "low"]

        duration = time.time() - start_time

        logger.info(
            f"Vulnerability scanning complete: {len(all_findings)} total findings "
            f"(Critical: {len(critical_findings)}, High: {len(high_findings)}, "
            f"Medium: {len(medium_findings)}, Low: {len(low_findings)}), "
            f"{duration:.2f}s duration"
        )

        return {
            "phase": "vulnerability_scanning",
            "target": target,
            "duration": duration,
            "findings": all_findings,
            "executed_actions": executed_actions,
            "techniques": techniques,
            "findings_count": len(all_findings),
            "severity_breakdown": {
                "critical": len(critical_findings),
                "high": len(high_findings),
                "medium": len(medium_findings),
                "low": len(low_findings)
            },
            "success": True,
            "mode": "REAL_TOOLS"
        }

    def _identify_sql_injection_targets(
        self,
        base_url: str,
        enumeration_findings: Optional[List[Dict[str, Any]]]
    ) -> List[str]:
        """
        Identify potential SQL injection targets from enumeration findings

        Args:
            base_url: Base target URL
            enumeration_findings: Findings from enumeration phase

        Returns:
            List of URLs to test for SQL injection
        """
        targets = []

        # Always test base URL
        targets.append(base_url)

        # Add discovered API endpoints
        if enumeration_findings:
            for finding in enumeration_findings:
                if finding.get("type") == "api_endpoint":
                    endpoint_url = finding.get("url")
                    if endpoint_url and endpoint_url not in targets:
                        # Add parameter for testing
                        if "?" not in endpoint_url:
                            endpoint_url = f"{endpoint_url}?id=1"
                        targets.append(endpoint_url)

        # Add common vulnerable endpoints
        from urllib.parse import urljoin
        common_endpoints = [
            "/search?q=test",
            "/api/users?id=1",
            "/login?username=admin",
            "/products?id=1",
            "/view?page=1"
        ]

        for endpoint in common_endpoints:
            full_url = urljoin(base_url, endpoint)
            if full_url not in targets:
                targets.append(full_url)

        logger.info(f"Identified {len(targets)} potential SQL injection targets")
        return targets

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
        """
        Get AI recommendation for next action using LLM
        
        Args:
            context: Operation context including phase, findings, history
            
        Returns:
            Dict with recommendations, analysis, and suggested next phase
        """
        try:
            logger.debug(f"Requesting AI recommendation for context: {context.get('phase', 'unknown')}")
            result = await self.llm_client.get_next_action_recommendation(context)
            logger.info("AI recommendation generated successfully")
            return result
        except Exception as e:
            logger.error(f"Failed to get AI recommendation: {e}")
            # Fallback to safe mock response
            return {
                "recommendations": [
                    {
                        "action": "continue_enumeration",
                        "confidence": 0.7,
                        "reasoning": "Continue systematic enumeration",
                        "technique": "T1590",
                        "risk_level": "LOW",
                    }
                ],
                "context_analysis": "Continuing with safe reconnaissance activities",
                "suggested_next_phase": context.get("phase", "enumeration"),
            }
    
    async def get_reconnaissance_strategy(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Get AI-powered reconnaissance strategy
        
        Args:
            target: Target URL or IP
            context: Additional context
            
        Returns:
            Dict with reconnaissance recommendations
        """
        try:
            logger.debug(f"Requesting reconnaissance strategy for {target}")
            result = await self.llm_client.get_reconnaissance_recommendation(
                target, 
                context or {}
            )
            logger.info("Reconnaissance strategy generated")
            return result
        except Exception as e:
            logger.error(f"Failed to get reconnaissance strategy: {e}")
            return {
                "recommended_actions": [],
                "focus_areas": ["web_services"],
                "risk_assessment": "LOW"
            }
    
    async def get_enumeration_strategy(
        self,
        target: str,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Get AI-powered enumeration strategy based on reconnaissance findings
        
        Args:
            target: Target URL or IP
            findings: Reconnaissance findings
            
        Returns:
            Dict with enumeration recommendations
        """
        try:
            logger.debug(f"Requesting enumeration strategy for {target}")
            result = await self.llm_client.get_enumeration_recommendation(target, findings)
            logger.info("Enumeration strategy generated")
            return result
        except Exception as e:
            logger.error(f"Failed to get enumeration strategy: {e}")
            return {
                "recommended_actions": [],
                "services_to_probe": ["http"],
                "risk_assessment": "LOW"
            }
    
    async def assess_vulnerability_risk(
        self,
        vulnerability: Dict[str, Any],
        target_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Assess risk level of a vulnerability using AI
        
        Args:
            vulnerability: Vulnerability details
            target_context: Target environment context
            
        Returns:
            Risk level: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
        """
        try:
            logger.debug(f"Assessing risk for vulnerability: {vulnerability.get('type', 'unknown')}")
            risk = await self.llm_client.assess_vulnerability_risk(vulnerability, target_context)
            logger.info(f"Risk assessed as: {risk}")
            return risk
        except Exception as e:
            logger.error(f"Failed to assess vulnerability risk: {e}")
            # Safe default
            return vulnerability.get("severity", "MEDIUM").upper()
    
    async def plan_attack_strategy(
        self,
        target: str,
        findings: List[Dict[str, Any]],
        objectives: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive attack strategy using AI
        
        Args:
            target: Target URL or IP
            findings: All findings so far
            objectives: Attack objectives
            
        Returns:
            Dict with attack plan and strategy
        """
        try:
            logger.debug(f"Planning attack strategy for {target}")
            result = await self.llm_client.plan_attack_strategy(
                target,
                findings,
                objectives or ["security_assessment"]
            )
            logger.info("Attack strategy generated")
            return result
        except Exception as e:
            logger.error(f"Failed to plan attack strategy: {e}")
            return {
                "strategy_overview": "Conservative security assessment",
                "attack_chain": [],
                "success_probability": 0.5
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

