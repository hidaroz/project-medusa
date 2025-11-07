"""
Amass Subdomain Enumeration Integration
Provides real subdomain discovery using Amass with JSON output parsing
"""

import json
import time
import tempfile
import os
from typing import Dict, List, Any, Optional
from pathlib import Path

from .base import BaseTool, ToolExecutionError


class AmassScanner(BaseTool):
    """
    Amass subdomain enumeration integration
    
    Executes Amass for subdomain discovery and parses JSON output into structured findings
    Supports both passive and active enumeration modes
    """

    def __init__(self, timeout: int = 300, passive: bool = True):
        """
        Initialize Amass scanner

        Args:
            timeout: Maximum execution time in seconds (default: 300 = 5 min)
            passive: Use passive enumeration only (default: True for safety)
        """
        super().__init__(timeout=timeout, tool_name="amass")
        self.passive = passive

    @property
    def tool_binary_name(self) -> str:
        return "amass"

    async def enumerate_subdomains(
        self,
        domain: str,
        passive: Optional[bool] = None,
        sources: Optional[List[str]] = None,
        rate_limit: int = 100
    ) -> Dict[str, Any]:
        """
        Enumerate subdomains for a target domain

        Args:
            domain: Target domain to enumerate
            passive: Use passive enumeration only (overrides default)
            sources: Specific data sources to use
            rate_limit: Requests per second limit

        Returns:
            Dict with enumeration results:
            {
                "success": bool,
                "target_domain": str,
                "findings": List[Dict],
                "findings_count": int,
                "unique_ips": List[str],
                "sources": List[str],
                "duration_seconds": float
            }
        """
        # Check if amass is available
        if not self.is_available():
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"{self.tool_binary_name} is not installed or not in PATH"
            )

        # Sanitize domain
        try:
            safe_domain = self._sanitize_target(domain)
        except ValueError as e:
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"Invalid domain: {str(e)}"
            )

        # Determine enumeration mode
        use_passive = passive if passive is not None else self.passive

        # Create temporary output file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            output_file = f.name

        try:
            # Build amass command
            cmd = ["amass", "enum"]

            # Add enumeration mode
            if use_passive:
                cmd.append("-passive")

            # Add domain
            cmd.extend(["-d", safe_domain])

            # Note: Rate limiting is not directly supported in amass v4
            # Rate limiting is handled internally by amass based on data source limits
            # The rate_limit parameter is kept for API compatibility but not passed to amass

            # Add specific sources if provided
            if sources:
                sources_str = ",".join(sources)
                cmd.extend(["-src", sources_str])

            # Add output options
            # Use -oA to generate all output formats (including JSON)
            # The output_file path will be used as prefix, JSON will be at output_file.json
            output_prefix = output_file.replace('.json', '')
            cmd.extend(["-oA", output_prefix])
            # Update output_file to point to the JSON file that will be created
            output_file = f"{output_prefix}.json"

            # Execute command
            start_time = time.time()
            try:
                stdout, stderr, returncode = await self._run_command(cmd)
                duration = time.time() - start_time

                # Check for errors
                if returncode != 0 and "no subdomains found" not in stderr.lower():
                    self.logger.error(f"Amass failed with return code {returncode}")
                    self.logger.error(f"Stderr: {stderr}")
                    return self._create_result_dict(
                        success=False,
                        findings=[],
                        raw_output=stdout + stderr,
                        duration=duration,
                        error=f"Amass enumeration failed: {stderr}"
                    )

                # Parse results from JSON file
                findings = self._parse_json_output(output_file)

                # Extract unique IPs
                unique_ips = set()
                discovered_sources = set()
                for finding in findings:
                    if "ip_addresses" in finding:
                        unique_ips.update(finding["ip_addresses"])
                    if "sources" in finding:
                        discovered_sources.update(finding["sources"])

                return self._create_result_dict(
                    success=True,
                    findings=findings,
                    raw_output=stdout,
                    duration=duration,
                    metadata={
                        "target_domain": safe_domain,
                        "enumeration_mode": "passive" if use_passive else "active",
                        "unique_ips": list(unique_ips),
                        "data_sources": list(discovered_sources),
                    }
                )

            except ToolExecutionError as e:
                duration = time.time() - start_time
                self.logger.error(f"Amass execution error: {e}")
                return self._create_result_dict(
                    success=False,
                    findings=[],
                    raw_output="",
                    duration=duration,
                    error=str(e)
                )

        finally:
            # Clean up temporary file
            try:
                if os.path.exists(output_file):
                    os.unlink(output_file)
            except Exception as e:
                self.logger.warning(f"Failed to clean up temporary file: {e}")

    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse amass output (compatibility method)

        Args:
            stdout: Standard output from amass
            stderr: Standard error from amass

        Returns:
            List of findings
        """
        # For Amass, we parse JSON directly from file
        # This is a fallback implementation
        findings = []

        if not stdout:
            self.logger.warning("Empty amass output")
            return findings

        try:
            # Try to parse line-delimited JSON from stdout
            for line in stdout.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    finding = self._transform_amass_json(data)
                    if finding:
                        findings.append(finding)
                except json.JSONDecodeError:
                    # Skip lines that aren't valid JSON
                    continue

        except Exception as e:
            self.logger.error(f"Failed to parse amass output: {e}")

        return findings

    def _parse_json_output(self, json_file: str) -> List[Dict[str, Any]]:
        """
        Parse Amass JSON output file

        Args:
            json_file: Path to Amass JSON output file

        Returns:
            List of findings
        """
        findings = []

        if not os.path.exists(json_file):
            self.logger.warning(f"JSON output file not found: {json_file}")
            return findings

        try:
            with open(json_file, 'r') as f:
                # Amass outputs line-delimited JSON or a JSON array
                content = f.read().strip()

                if not content:
                    return findings

                # Try parsing as array first
                if content.startswith('['):
                    data = json.loads(content)
                    if isinstance(data, list):
                        for item in data:
                            finding = self._transform_amass_json(item)
                            if finding:
                                findings.append(finding)
                else:
                    # Parse line-delimited JSON
                    for line in content.split('\n'):
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            finding = self._transform_amass_json(data)
                            if finding:
                                findings.append(finding)
                        except json.JSONDecodeError:
                            continue

        except Exception as e:
            self.logger.error(f"Failed to parse JSON file: {e}")

        return findings

    def _transform_amass_json(self, amass_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Transform Amass JSON into standardized finding format

        Args:
            amass_data: Raw data from Amass JSON

        Returns:
            Transformed finding dict or None
        """
        if "name" not in amass_data:
            return None

        subdomain = amass_data.get("name", "")
        domain = amass_data.get("domain", "")
        addresses = amass_data.get("addresses", [])
        sources = amass_data.get("sources", [])
        tag = amass_data.get("tag", "dns")

        # Extract IP addresses
        ips = []
        if isinstance(addresses, list):
            for addr in addresses:
                if isinstance(addr, dict):
                    ips.append(addr.get("ip", ""))
                elif isinstance(addr, str):
                    ips.append(addr)

        ips = [ip for ip in ips if ip]  # Remove empty strings

        # Determine confidence based on source count and type
        confidence = "low"
        if len(sources) >= 3:
            confidence = "high"
        elif len(sources) >= 1:
            confidence = "medium"

        finding = {
            "type": "subdomain_enumeration",
            "subdomain": subdomain,
            "domain": domain,
            "ip_addresses": ips,
            "sources": sources,
            "tag": tag,
            "confidence": confidence,
            "severity": "low"  # Subdomains are informational findings
        }

        return finding

    async def quick_enum(self, domain: str) -> Dict[str, Any]:
        """
        Perform quick passive subdomain enumeration

        Args:
            domain: Target domain

        Returns:
            Enumeration results
        """
        return await self.enumerate_subdomains(
            domain=domain,
            passive=True,
            rate_limit=100
        )

    async def deep_enum(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive active subdomain enumeration

        Args:
            domain: Target domain

        Returns:
            Enumeration results
        """
        return await self.enumerate_subdomains(
            domain=domain,
            passive=False,
            rate_limit=50
        )

