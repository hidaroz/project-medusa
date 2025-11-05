"""
SQLMap Integration
Provides automated SQL injection detection and exploitation using sqlmap
"""

import json
import re
from typing import Dict, List, Any, Optional
import time

from .base import BaseTool, ToolExecutionError


class SQLMapScanner(BaseTool):
    """
    SQLMap scanner integration for SQL injection detection

    Features:
    - Automated SQL injection detection
    - Database enumeration
    - Multiple injection techniques
    - Risk and level configuration
    - Output parsing from JSON format
    """

    def __init__(self, timeout: int = 900):
        """
        Initialize SQLMap scanner

        Args:
            timeout: Maximum scan time in seconds (default: 900 = 15 min)
        """
        super().__init__(timeout=timeout, tool_name="sqlmap")

    @property
    def tool_binary_name(self) -> str:
        return "sqlmap"

    async def execute(
        self,
        target_url: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        risk: int = 1,
        level: int = 1,
        technique: Optional[str] = None,
        dbms: Optional[str] = None,
        batch: bool = True,
        random_agent: bool = True
    ) -> Dict[str, Any]:
        """
        Execute SQLMap scan

        Args:
            target_url: Target URL to test
            data: POST data (e.g., "user=test&pass=test")
            cookie: Cookie header value
            headers: Additional HTTP headers
            risk: Risk level (1-3, default: 1)
            level: Detection level (1-5, default: 1)
            technique: Injection techniques to use (e.g., "BEUSTQ")
            dbms: Force back-end DBMS (e.g., "MySQL", "PostgreSQL")
            batch: Never ask for user input (default: True)
            random_agent: Use random User-Agent (default: True)

        Returns:
            Dict with SQL injection findings and scan results
        """
        # Check if sqlmap is available
        if not self.is_available():
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"{self.tool_binary_name} is not installed or not in PATH"
            )

        # Sanitize target URL
        try:
            safe_url = self._sanitize_target(target_url)
        except ValueError as e:
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"Invalid target URL: {str(e)}"
            )

        # Build sqlmap command
        cmd = [
            "sqlmap",
            "-u", safe_url,
            "--output-dir=/tmp/sqlmap_output",
            "--flush-session",  # Fresh scan
            "--fresh-queries",
        ]

        # Add batch mode (no user interaction)
        if batch:
            cmd.append("--batch")

        # Add random User-Agent
        if random_agent:
            cmd.append("--random-agent")

        # Add risk and level
        cmd.extend(["--risk", str(risk)])
        cmd.extend(["--level", str(level)])

        # Add POST data if provided
        if data:
            cmd.extend(["--data", data])

        # Add cookie if provided
        if cookie:
            cmd.extend(["--cookie", cookie])

        # Add custom headers
        if headers:
            for key, value in headers.items():
                cmd.extend(["--header", f"{key}: {value}"])

        # Add technique if specified
        if technique:
            cmd.extend(["--technique", technique])

        # Force DBMS if specified
        if dbms:
            cmd.extend(["--dbms", dbms])

        # Add text-only output for parsing
        cmd.append("--text-only")

        # Execute scan
        start_time = time.time()
        try:
            self.logger.info(f"Starting SQLMap scan on {safe_url}")
            stdout, stderr, returncode = await self._run_command(cmd)
            duration = time.time() - start_time

            # SQLMap returns 0 even if no vulnerabilities found
            # We parse output to determine findings
            findings = self.parse_output(stdout, stderr)

            success = returncode == 0 or len(findings) > 0

            self.logger.info(
                f"SQLMap scan completed: {len(findings)} findings, "
                f"{duration:.2f}s duration"
            )

            return self._create_result_dict(
                success=success,
                findings=findings,
                raw_output=stdout,
                duration=duration,
                metadata={
                    "target": safe_url,
                    "risk": risk,
                    "level": level,
                    "vulnerable": len(findings) > 0
                }
            )

        except ToolExecutionError as e:
            duration = time.time() - start_time
            self.logger.error(f"SQLMap execution error: {e}")
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=duration,
                error=str(e)
            )

    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse SQLMap output to extract SQL injection findings

        Args:
            stdout: SQLMap standard output
            stderr: SQLMap standard error

        Returns:
            List of SQL injection findings
        """
        findings = []

        if not stdout or not stdout.strip():
            self.logger.warning("Empty SQLMap output")
            return findings

        # Pattern 1: Parameter vulnerable marker
        # Example: "Parameter: id (GET) is vulnerable"
        param_pattern = r"Parameter:\s+(\w+)\s+\((\w+)\)\s+is\s+vulnerable"
        for match in re.finditer(param_pattern, stdout, re.MULTILINE):
            param_name = match.group(1)
            param_type = match.group(2)

            findings.append({
                "type": "sql_injection",
                "severity": "high",
                "title": f"SQL Injection in parameter '{param_name}'",
                "description": f"Parameter '{param_name}' ({param_type}) is vulnerable to SQL injection",
                "parameter": param_name,
                "parameter_type": param_type,
                "confidence": "high",
                "cvss_score": 8.5,
                "cwe": "CWE-89",
                "recommendation": "Use parameterized queries or prepared statements"
            })

        # Pattern 2: Injection type detection
        # Example: "Type: boolean-based blind"
        type_pattern = r"Type:\s+([\w\s-]+)"
        injection_types = re.findall(type_pattern, stdout)

        # Pattern 3: Payload information
        # Example: "Payload: id=1 AND 1=1"
        payload_pattern = r"Payload:\s+(.+?)(?:\n|$)"
        payloads = re.findall(payload_pattern, stdout)

        # Pattern 4: Database information
        # Example: "back-end DBMS: MySQL >= 5.0"
        dbms_pattern = r"back-end DBMS:\s+(.+?)(?:\n|$)"
        dbms_match = re.search(dbms_pattern, stdout)

        # Pattern 5: Detected technique
        # Example: "it looks like the back-end DBMS is 'MySQL'"
        detected_dbms = None
        if dbms_match:
            detected_dbms = dbms_match.group(1).strip()

        # Pattern 6: Check for "all tested parameters do not appear to be injectable"
        not_vulnerable_pattern = r"all tested parameters.*?not.*?injectable"
        is_not_vulnerable = re.search(not_vulnerable_pattern, stdout, re.IGNORECASE)

        # If specific vulnerabilities not found but no "not vulnerable" message
        # and we have injection types, create a general finding
        if injection_types and not is_not_vulnerable and not findings:
            findings.append({
                "type": "sql_injection",
                "severity": "high",
                "title": "SQL Injection Detected",
                "description": f"SQL injection vulnerability detected using: {', '.join(injection_types[:3])}",
                "injection_types": injection_types,
                "payloads": payloads[:3] if payloads else [],
                "dbms": detected_dbms,
                "confidence": "high",
                "cvss_score": 8.5,
                "cwe": "CWE-89",
                "recommendation": "Use parameterized queries or ORM framework"
            })

        # Pattern 7: Check for error messages indicating vulnerability
        if "sqlmap identified the following injection point" in stdout.lower():
            if not findings:  # Add generic finding if none detected yet
                findings.append({
                    "type": "sql_injection",
                    "severity": "high",
                    "title": "SQL Injection Point Identified",
                    "description": "SQLMap identified at least one injection point",
                    "confidence": "high",
                    "recommendation": "Review SQLMap output for detailed exploitation steps"
                })

        # Add database info if detected
        if detected_dbms and findings:
            for finding in findings:
                finding["detected_dbms"] = detected_dbms

        # Pattern 8: Check for specific database enumeration success
        if "Database:" in stdout or "Table:" in stdout:
            # Database was successfully enumerated
            for finding in findings:
                finding["exploitability"] = "confirmed"
                finding["severity"] = "critical"
                finding["cvss_score"] = 9.0

        self.logger.info(f"Parsed {len(findings)} SQL injection findings from SQLMap output")
        return findings

    async def test_parameter(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        data: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test a specific parameter for SQL injection

        Args:
            url: Target URL
            parameter: Parameter name to test
            method: HTTP method (GET or POST)
            data: POST data if method is POST

        Returns:
            Scan results for the specific parameter
        """
        self.logger.info(f"Testing parameter '{parameter}' for SQL injection")

        # Build appropriate command based on method
        if method.upper() == "GET":
            # Ensure parameter is in URL
            if "?" not in url:
                url = f"{url}?{parameter}=1"
            elif parameter not in url:
                url = f"{url}&{parameter}=1"

            return await self.execute(
                target_url=url,
                risk=2,
                level=3,
                batch=True
            )
        else:
            # POST method
            if not data:
                data = f"{parameter}=1"

            return await self.execute(
                target_url=url,
                data=data,
                risk=2,
                level=3,
                batch=True
            )

    async def quick_scan(
        self,
        url: str,
        data: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Perform a quick SQL injection scan (risk=1, level=1)

        Args:
            url: Target URL
            data: Optional POST data

        Returns:
            Quick scan results
        """
        return await self.execute(
            target_url=url,
            data=data,
            risk=1,
            level=1,
            batch=True,
            random_agent=True
        )

    async def thorough_scan(
        self,
        url: str,
        data: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Perform a thorough SQL injection scan (risk=3, level=5)

        Args:
            url: Target URL
            data: Optional POST data

        Returns:
            Thorough scan results
        """
        return await self.execute(
            target_url=url,
            data=data,
            risk=3,
            level=5,
            batch=True,
            random_agent=True
        )

    def _extract_vulnerable_params(self, output: str) -> List[str]:
        """
        Extract list of vulnerable parameters from output

        Args:
            output: SQLMap output text

        Returns:
            List of vulnerable parameter names
        """
        params = []
        pattern = r"Parameter:\s+(\w+)"

        for match in re.finditer(pattern, output):
            param = match.group(1)
            if param not in params:
                params.append(param)

        return params
