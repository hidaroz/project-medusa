"""
Metasploit Framework Integration
Provides exploit search, module execution, and vulnerability validation
"""

import json
import time
import re
from typing import Dict, List, Any, Optional
from pathlib import Path

from .base import BaseTool, ToolExecutionError
from .graph_integration import update_graph


class MetasploitClient(BaseTool):
    """
    Metasploit Framework integration

    Provides access to Metasploit's exploit database and execution capabilities
    with safety controls and structured output parsing
    """

    def __init__(self, timeout: int = 300, auto_approve: bool = False):
        """
        Initialize Metasploit client

        Args:
            timeout: Maximum execution time in seconds (default: 300)
            auto_approve: Auto-approve exploit execution (DANGEROUS - default: False)
        """
        super().__init__(timeout=timeout, tool_name="metasploit")
        self.auto_approve = auto_approve

    @property
    def tool_binary_name(self) -> str:
        return "msfconsole"

    async def search_exploits(
        self,
        query: str,
        platform: Optional[str] = None,
        type_filter: Optional[str] = None,
        rank_min: str = "normal"
    ) -> Dict[str, Any]:
        """
        Search Metasploit exploit database

        Args:
            query: Search query (CVE, keyword, etc.)
            platform: Filter by platform (linux, windows, etc.)
            type_filter: Filter by type (exploit, auxiliary, post)
            rank_min: Minimum exploit rank (low, normal, good, great, excellent)

        Returns:
            Dict with search results including:
            {
                "success": bool,
                "findings": List[Dict],  # List of matching exploits
                "findings_count": int,
                "query": str
            }
        """
        if not self.is_available():
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"{self.tool_binary_name} is not installed or not in PATH"
            )

        # Build search command
        search_cmd = f"search {query}"

        if platform:
            search_cmd += f" platform:{platform}"
        if type_filter:
            search_cmd += f" type:{type_filter}"
        if rank_min:
            search_cmd += f" rank:{rank_min}"

        # Execute search
        start_time = time.time()
        try:
            cmd = ["msfconsole", "-q", "-x", f"{search_cmd}; exit"]
            stdout, stderr, returncode = await self._run_command(cmd)
            duration = time.time() - start_time

            # Parse results
            findings = self._parse_search_output(stdout)

            return self._create_result_dict(
                success=True,
                findings=findings,
                raw_output=stdout,
                duration=duration,
                metadata={
                    "query": query,
                    "platform": platform,
                    "type_filter": type_filter,
                    "rank_min": rank_min
                }
            )

        except ToolExecutionError as e:
            duration = time.time() - start_time
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=duration,
                error=str(e)
            )

    async def get_module_info(self, module_path: str) -> Dict[str, Any]:
        """
        Get detailed information about a Metasploit module

        Args:
            module_path: Full module path (e.g., exploit/unix/webapp/example)

        Returns:
            Dict with module information
        """
        if not self.is_available():
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"{self.tool_binary_name} is not installed"
            )

        start_time = time.time()
        try:
            cmd = ["msfconsole", "-q", "-x", f"info {module_path}; exit"]
            stdout, stderr, returncode = await self._run_command(cmd)
            duration = time.time() - start_time

            # Parse module info
            module_info = self._parse_module_info(stdout)

            return self._create_result_dict(
                success=True,
                findings=[module_info] if module_info else [],
                raw_output=stdout,
                duration=duration,
                metadata={"module_path": module_path}
            )

        except ToolExecutionError as e:
            duration = time.time() - start_time
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=duration,
                error=str(e)
            )

    async def verify_vulnerability(
        self,
        target: str,
        module_path: str,
        options: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Verify if a target is vulnerable (check mode only - no exploitation)

        Args:
            target: Target IP or hostname
            module_path: Metasploit module to use
            options: Additional module options

        Returns:
            Dict with verification results
        """
        if not self.is_available():
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"{self.tool_binary_name} is not installed"
            )

        # Sanitize target
        try:
            safe_target = self._sanitize_target(target)
        except ValueError as e:
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"Invalid target: {str(e)}"
            )

        # Build verification command (check mode)
        commands = [
            f"use {module_path}",
            f"set RHOST {safe_target}",
            "set CHECK true",  # Enable check mode
        ]

        # Add custom options
        if options:
            for key, value in options.items():
                commands.append(f"set {key} {value}")

        commands.extend(["check", "exit"])
        command_str = "; ".join(commands)

        start_time = time.time()
        try:
            cmd = ["msfconsole", "-q", "-x", command_str]
            stdout, stderr, returncode = await self._run_command(cmd)
            duration = time.time() - start_time

            # Parse check results
            is_vulnerable = self._parse_check_output(stdout)

            finding = {
                "type": "vulnerability_check",
                "target": safe_target,
                "module": module_path,
                "vulnerable": is_vulnerable,
                "severity": self._determine_severity(module_path),
                "confidence": "high" if is_vulnerable else "low"
            }

            # Update graph if vulnerable
            if is_vulnerable:
                self._update_graph_for_vulnerability(finding)

            return self._create_result_dict(
                success=True,
                findings=[finding],
                raw_output=stdout,
                duration=duration,
                metadata={
                    "target": safe_target,
                    "module": module_path,
                    "check_only": True
                }
            )

        except ToolExecutionError as e:
            duration = time.time() - start_time
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=duration,
                error=str(e)
            )

    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse Metasploit output into structured format

        Args:
            stdout: Standard output from msfconsole
            stderr: Standard error from msfconsole

        Returns:
            List of findings
        """
        # This is primarily used by search operations
        return self._parse_search_output(stdout)

    def _parse_search_output(self, output: str) -> List[Dict[str, Any]]:
        """
        Parse Metasploit search output

        Args:
            output: Raw search output

        Returns:
            List of exploit findings
        """
        findings = []

        # Parse search results (typical format):
        # Name                           Disclosure Date  Rank    Description
        # ----                           ---------------  ----    -----------
        # exploit/unix/webapp/example    2023-01-01       great   Example

        lines = output.split('\n')
        in_results = False

        for line in lines:
            # Skip header and separator lines
            if 'Name' in line and 'Disclosure Date' in line:
                in_results = True
                continue
            if line.strip().startswith('---'):
                continue

            if in_results and line.strip():
                # Try to parse exploit line
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) >= 4:
                    finding = {
                        "type": "metasploit_module",
                        "module_path": parts[0],
                        "disclosure_date": parts[1] if parts[1] != '-' else None,
                        "rank": parts[2],
                        "description": parts[3] if len(parts) > 3 else "",
                        "severity": self._rank_to_severity(parts[2])
                    }
                    findings.append(finding)

        return findings

    def _parse_module_info(self, output: str) -> Optional[Dict[str, Any]]:
        """
        Parse module info output

        Args:
            output: Raw info output

        Returns:
            Module information dict or None
        """
        if not output:
            return None

        info = {
            "type": "metasploit_module_info",
            "name": None,
            "description": None,
            "authors": [],
            "references": [],
            "targets": []
        }

        # Simple parsing - extract key information
        lines = output.split('\n')
        for line in lines:
            if 'Name:' in line:
                info['name'] = line.split('Name:')[1].strip()
            elif 'Description:' in line:
                info['description'] = line.split('Description:')[1].strip()

        return info if info['name'] else None

    def _parse_check_output(self, output: str) -> bool:
        """
        Parse vulnerability check output

        Args:
            output: Raw check output

        Returns:
            True if vulnerable, False otherwise
        """
        output_lower = output.lower()

        # Look for vulnerability indicators
        vulnerable_indicators = [
            "target is vulnerable",
            "the target appears to be vulnerable",
            "vulnerable to",
            "[+] vulnerable"
        ]

        for indicator in vulnerable_indicators:
            if indicator in output_lower:
                return True

        # Look for not vulnerable indicators
        safe_indicators = [
            "target is not vulnerable",
            "does not appear to be vulnerable",
            "[-] not vulnerable"
        ]

        for indicator in safe_indicators:
            if indicator in output_lower:
                return False

        # Default to false if unclear
        return False

    def _rank_to_severity(self, rank: str) -> str:
        """
        Convert Metasploit rank to severity level

        Args:
            rank: Metasploit exploit rank

        Returns:
            Severity level (critical, high, medium, low)
        """
        rank_lower = rank.lower()

        if rank_lower in ['excellent', 'great']:
            return 'critical'
        elif rank_lower in ['good']:
            return 'high'
        elif rank_lower in ['normal', 'average']:
            return 'medium'
        else:
            return 'low'

    def _determine_severity(self, module_path: str) -> str:
        """
        Determine severity based on module path and type

        Args:
            module_path: Metasploit module path

        Returns:
            Severity level
        """
        path_lower = module_path.lower()

        # Remote code execution = critical
        if 'rce' in path_lower or 'remote_code' in path_lower:
            return 'critical'
        # Exploits = high
        elif 'exploit' in path_lower:
            return 'high'
        # Auxiliary = medium
        elif 'auxiliary' in path_lower:
            return 'medium'
        # Default
        else:
            return 'medium'

    def _update_graph_for_vulnerability(self, finding: Dict[str, Any]) -> None:
        """
        Update graph database with vulnerability information

        Args:
            finding: Vulnerability finding dictionary
        """
        try:
            parameters = {
                "host": finding.get("target", ""),
                "vulnerability_name": finding.get("module", ""),
                "severity": finding.get("severity", "medium"),
                "confidence": finding.get("confidence", "medium"),
                "vulnerable": finding.get("vulnerable", False)
            }

            if parameters["host"] and parameters["vulnerability_name"]:
                # Note: This would use a Cypher template for vulnerabilities
                # For now, just log
                self.logger.info(
                    f"Vulnerability found: {parameters['vulnerability_name']} "
                    f"on {parameters['host']}"
                )
        except Exception as e:
            self.logger.debug(f"Graph update failed for vulnerability: {e}")
