"""
SQLMap SQL Injection Detection and Exploitation Integration
Real SQL injection testing using SQLMap
"""

import time
import tempfile
import os
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs

from .base import BaseTool, ToolExecutionError


class SQLMapScanner(BaseTool):
    """
    SQLMap SQL injection scanner integration
    
    Detects and exploits SQL injection vulnerabilities using SQLMap
    Supports both automated testing and targeted exploitation
    """

    def __init__(self, timeout: int = 600):
        """
        Initialize SQLMap scanner

        Args:
            timeout: Maximum execution time in seconds (default: 600 = 10 min)
        """
        super().__init__(timeout=timeout, tool_name="sqlmap")

    @property
    def tool_binary_name(self) -> str:
        return "sqlmap"

    async def test_injection(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        cookies: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        level: int = 1,
        risk: int = 1,
        technique: str = "BEUSTQ",
        output_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test URL for SQL injection vulnerabilities

        Args:
            url: Target URL to test
            method: HTTP method (GET, POST, PUT, DELETE)
            data: POST data (e.g., "id=1&name=test")
            cookies: HTTP cookies
            headers: Additional headers
            level: Test level (1-5, higher = more thorough)
            risk: Risk level (1-3, higher = more aggressive)
            technique: SQLi techniques (B=Boolean, E=Error, U=Union, S=Stacked, T=Time-based, Q=Query)
            output_dir: Directory for output files

        Returns:
            Dict with injection test results
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

        # Sanitize URL
        try:
            safe_url = self._sanitize_target(url)
        except ValueError as e:
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"Invalid URL: {str(e)}"
            )

        # Validate level and risk parameters
        if not 1 <= level <= 5:
            level = min(max(level, 1), 5)
            self.logger.warning(f"Level out of range, using {level}")

        if not 1 <= risk <= 3:
            risk = min(max(risk, 1), 3)
            self.logger.warning(f"Risk out of range, using {risk}")

        # Create output directory if needed
        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="sqlmap_")
        else:
            os.makedirs(output_dir, exist_ok=True)

        try:
            # Build sqlmap command
            cmd = [
                "sqlmap",
                "-u", safe_url,
                "--batch",  # Non-interactive
                "--level", str(level),
                "--risk", str(risk),
                "--technique", technique,
                "-o",  # Optimize detection
                "--output-dir", output_dir,
                "--flush-session"  # Start fresh
            ]

            # Add HTTP method if not GET
            if method.upper() != "GET":
                cmd.extend(["-m", method.upper()])

            # Add POST data if provided
            if data:
                cmd.extend(["--data", data])

            # Add cookies if provided
            if cookies:
                cmd.extend(["--cookie", cookies])

            # Add headers if provided
            if headers:
                for header_name, header_value in headers.items():
                    cmd.extend(["-H", f"{header_name}: {header_value}"])

            # Execute command
            start_time = time.time()
            try:
                stdout, stderr, returncode = await self._run_command(cmd)
                duration = time.time() - start_time

                # Parse results
                findings = self.parse_output(stdout, stderr)

                # Determine if vulnerable based on output
                vulnerable = any(f.get("vulnerable") for f in findings)

                return self._create_result_dict(
                    success=True,
                    findings=findings,
                    raw_output=stdout + stderr,
                    duration=duration,
                    metadata={
                        "target_url": safe_url,
                        "method": method.upper(),
                        "level": level,
                        "risk": risk,
                        "techniques": technique,
                        "vulnerable": vulnerable,
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

        finally:
            # Clean up if temp directory was created
            if output_dir and output_dir.startswith(tempfile.gettempdir()):
                try:
                    import shutil
                    shutil.rmtree(output_dir, ignore_errors=True)
                except Exception as e:
                    self.logger.warning(f"Failed to clean up temp directory: {e}")

    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse SQLMap output to extract vulnerability information

        Args:
            stdout: Standard output from sqlmap
            stderr: Standard error from sqlmap

        Returns:
            List of findings with vulnerability details
        """
        findings = []

        if not stdout and not stderr:
            self.logger.warning("Empty sqlmap output")
            return findings

        try:
            output = stdout + stderr

            # Check for vulnerable indicators
            vulnerable_indicators = [
                "got a 200 HTTP code and 200 characters against",
                "it looks like the back-end DBMS is",
                "VULNERABLE PARAMETER",
                "[CRITICAL]",
                "[HIGH]",
                "Parameter appears to be vulnerable"
            ]

            is_vulnerable = any(indicator in output for indicator in vulnerable_indicators)

            # Extract vulnerable parameters
            # Pattern: *Parameter: id (GET)*
            param_pattern = r'\*Parameter:\s+(\w+)\s+\((\w+)\)\*'
            param_matches = re.findall(param_pattern, output)

            # Extract DBMS information
            # Pattern: it looks like the back-end DBMS is 'MySQL'
            dbms_pattern = r"it looks like the back-end DBMS is ['\"]?([^'\"]+)['\"]?"
            dbms_matches = re.findall(dbms_pattern, output, re.IGNORECASE)

            # Extract injection type
            # Pattern: [CRITICAL] time-based blind
            injection_pattern = r'\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s+(\w+(?:-\w+)*)'
            injection_matches = re.findall(injection_pattern, output)

            # Extract database names
            # Pattern: available databases: information_schema, mysql, test
            db_pattern = r'available databases:(.+?)(?:\n|$)'
            db_matches = re.findall(db_pattern, output, re.IGNORECASE)

            # Extract table information
            # Pattern: Database: wordpress\nTable: wp_users
            table_pattern = r'Table:\s+(\w+)'
            table_matches = re.findall(table_pattern, output)

            if is_vulnerable and (param_matches or dbms_matches or injection_matches):
                # Create vulnerability finding
                for param, location in param_matches:
                    finding = {
                        "type": "sql_injection",
                        "vulnerable": True,
                        "parameter": param,
                        "location": location,
                        "injection_types": [t[1] for t in injection_matches],
                        "dbms": dbms_matches[0] if dbms_matches else "Unknown",
                        "databases": [db.strip() for db in db_matches[0].split(',')] if db_matches else [],
                        "tables": table_matches if table_matches else [],
                        "severity": "CRITICAL" if "CRITICAL" in output else "HIGH",
                        "confidence": "high"
                    }
                    findings.append(finding)

            # If vulnerable but no specific details extracted, create generic finding
            if is_vulnerable and not findings:
                finding = {
                    "type": "sql_injection",
                    "vulnerable": True,
                    "parameter": "Unknown",
                    "injection_types": [t[1] for t in injection_matches] if injection_matches else ["Unknown"],
                    "dbms": dbms_matches[0] if dbms_matches else "Unknown",
                    "severity": "CRITICAL" if "CRITICAL" in output else "HIGH",
                    "confidence": "medium"
                }
                findings.append(finding)

            # Extract potential extraction targets
            column_pattern = r'Column:\s+(\w+)'
            column_matches = re.findall(column_pattern, output)
            if column_matches:
                for finding in findings:
                    finding["extractable_columns"] = column_matches

        except Exception as e:
            self.logger.error(f"Failed to parse sqlmap output: {e}")

        return findings

    async def quick_scan(self, url: str) -> Dict[str, Any]:
        """
        Quick SQL injection scan with minimal settings

        Args:
            url: Target URL

        Returns:
            Scan results
        """
        return await self.test_injection(
            url=url,
            level=1,
            risk=1,
            technique="BEUSTQ"
        )

    async def deep_scan(self, url: str, data: Optional[str] = None) -> Dict[str, Any]:
        """
        Deep SQL injection scan with thorough testing

        Args:
            url: Target URL
            data: POST data (if applicable)

        Returns:
            Scan results
        """
        return await self.test_injection(
            url=url,
            data=data,
            level=5,
            risk=2,
            technique="BEUSTQ"
        )

    async def test_parameter(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        data: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test specific parameter for SQL injection

        Args:
            url: Target URL
            parameter: Parameter name to test
            method: HTTP method
            data: POST data

        Returns:
            Test results
        """
        # Modify URL to target specific parameter
        if method.upper() == "GET":
            # Add test value to parameter in URL
            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}{parameter}=1"
        else:
            test_url = url
            if data is None:
                data = f"{parameter}=1"

        return await self.test_injection(
            url=test_url,
            method=method,
            data=data if method.upper() != "GET" else None,
            level=2,
            risk=1
        )

    async def extract_data(
        self,
        url: str,
        database: Optional[str] = None,
        table: Optional[str] = None,
        columns: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Extract data from database (requires prior vulnerability confirmation)

        Note: Requires HIGH risk approval due to potential impact

        Args:
            url: Target URL
            database: Database to extract from
            table: Table to extract from
            columns: Specific columns to extract

        Returns:
            Extraction results
        """
        # Build sqlmap command for data extraction
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",
            "-o",
            "--risk", "3",
            "--level", "5",
            "--dump"  # Enable dumping
        ]

        # Add database targeting if specified
        if database:
            cmd.extend(["-D", database])

        if table:
            cmd.extend(["-T", table])

        if columns:
            cmd.extend(["-C", ",".join(columns)])

        # Create output directory
        output_dir = tempfile.mkdtemp(prefix="sqlmap_dump_")

        try:
            cmd.extend(["--output-dir", output_dir])

            start_time = time.time()
            try:
                stdout, stderr, returncode = await self._run_command(cmd)
                duration = time.time() - start_time

                findings = self.parse_output(stdout, stderr)

                return self._create_result_dict(
                    success=True,
                    findings=findings,
                    raw_output=stdout + stderr,
                    duration=duration,
                    metadata={
                        "action": "data_extraction",
                        "database": database,
                        "table": table,
                    }
                )

            except ToolExecutionError as e:
                duration = time.time() - start_time
                self.logger.error(f"Data extraction failed: {e}")
                return self._create_result_dict(
                    success=False,
                    findings=[],
                    raw_output="",
                    duration=duration,
                    error=str(e)
                )

        finally:
            try:
                import shutil
                shutil.rmtree(output_dir, ignore_errors=True)
            except Exception as e:
                self.logger.warning(f"Failed to clean up temp directory: {e}")

