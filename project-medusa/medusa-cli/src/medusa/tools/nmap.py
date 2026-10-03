"""
Nmap Scanner Integration
Provides real port scanning and service detection using nmap
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
import time

from .base import BaseTool, ToolExecutionError
from .graph_integration import CypherTemplates, update_graph


class NmapScanner(BaseTool):
    """
    Nmap port scanner integration

    Executes nmap scans and parses XML output into structured findings
    """

    def __init__(self, timeout: int = 600):
        """
        Initialize nmap scanner

        Args:
            timeout: Maximum scan time in seconds (default: 600 = 10 min)
        """
        super().__init__(timeout=timeout, tool_name="nmap")

    @property
    def tool_binary_name(self) -> str:
        return "nmap"

    async def execute(
        self,
        target: str,
        ports: str = "1-1000",
        scan_type: str = "-sV",
        additional_args: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Execute nmap scan

        Args:
            target: IP address or hostname to scan
            ports: Port range to scan (default: "1-1000")
            scan_type: Nmap scan type (default: "-sV" for version detection)
            additional_args: Additional nmap arguments

        Returns:
            Dict with scan results:
            {
                "success": bool,
                "target": str,
                "scan_type": str,
                "ports_scanned": str,
                "findings": List[Dict],
                "raw_output": str,
                "duration_seconds": float
            }
        """
        # Check if nmap is available
        if not self.is_available():
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"{self.tool_binary_name} is not installed or not in PATH"
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

        # Build nmap command
        cmd = [
            "nmap",
            scan_type,
        ]

        # Handle ports argument
        if ports:
            if ports.startswith("-"):
                # If ports starts with -, assume it's a flag (e.g. --top-ports)
                cmd.extend(ports.split())
            else:
                # Otherwise assume it's a list of ports
                cmd.extend(["-p", ports])

        cmd.extend([
            "-oX", "-",  # XML output to stdout
            "--host-timeout", "300s",
            "--max-retries", "2",
        ])

        # Add additional arguments if provided
        if additional_args:
            cmd.extend(additional_args)

        # Add target last
        cmd.append(safe_target)

        # Execute scan
        start_time = time.time()
        try:
            stdout, stderr, returncode = await self._run_command(cmd)
            duration = time.time() - start_time

            # Check for errors
            if returncode != 0:
                self.logger.error(f"Nmap failed with return code {returncode}")
                self.logger.error(f"Stderr: {stderr}")
                return self._create_result_dict(
                    success=False,
                    findings=[],
                    raw_output=stdout,
                    duration=duration,
                    error=f"Nmap scan failed: {stderr}"
                )

            # Parse results
            findings = self.parse_output(stdout, stderr)

            return self._create_result_dict(
                success=True,
                findings=findings,
                raw_output=stdout,
                duration=duration,
                metadata={
                    "target": safe_target,
                    "scan_type": scan_type,
                    "ports_scanned": ports,
                }
            )

        except ToolExecutionError as e:
            duration = time.time() - start_time
            self.logger.error(f"Nmap execution error: {e}")
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=duration,
                error=str(e)
            )

    def parse_output(self, xml_output: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse nmap XML output into structured findings

        Args:
            xml_output: Nmap XML output
            stderr: Standard error (for warnings)

        Returns:
            List of findings with open ports and service details
        """
        findings = []

        if not xml_output or not xml_output.strip():
            self.logger.warning("Empty nmap output")
            return findings

        try:
            # Parse XML
            root = ET.fromstring(xml_output)

            # Iterate through hosts
            for host in root.findall(".//host"):
                # Check if host is up
                status = host.find("status")
                if status is None or status.get("state") != "up":
                    continue

                # Get host address
                address_elem = host.find(".//address[@addrtype='ipv4']")
                if address_elem is None:
                    # Try IPv6
                    address_elem = host.find(".//address[@addrtype='ipv6']")

                if address_elem is None:
                    continue

                host_ip = address_elem.get("addr")

                # Get hostname if available
                hostname = None
                hostname_elem = host.find(".//hostname")
                if hostname_elem is not None:
                    hostname = hostname_elem.get("name")

                # Parse open ports
                for port in host.findall(".//port"):
                    port_finding = self._parse_port(port, host_ip, hostname)
                    if port_finding:
                        findings.append(port_finding)

                # Check for OS detection
                os_match = host.find(".//osmatch")
                if os_match is not None:
                    os_name = os_match.get("name")
                    os_accuracy = os_match.get("accuracy")

                    os_finding = {
                        "type": "os_detection",
                        "host": host_ip,
                        "hostname": hostname,
                        "os_name": os_name,
                        "accuracy": os_accuracy,
                        "severity": "info",
                        "confidence": "medium" if int(os_accuracy or 0) < 90 else "high"
                    }

                    # Update graph database with OS information
                    self._update_graph_for_os(os_finding)

                    findings.append(os_finding)

        except ET.ParseError as e:
            self.logger.error(f"Failed to parse nmap XML: {e}")
            self.logger.debug(f"XML output: {xml_output[:500]}")
            raise ToolExecutionError(f"Invalid nmap XML output: {str(e)}")

        self.logger.info(f"Parsed {len(findings)} findings from nmap output")
        return findings

    def _parse_port(
        self,
        port_elem: ET.Element,
        host_ip: str,
        hostname: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """
        Parse a single port element from nmap XML

        Args:
            port_elem: XML element for port
            host_ip: Host IP address
            hostname: Optional hostname

        Returns:
            Finding dict or None if port is not open
        """
        # Get port details
        port_id = port_elem.get("portid")
        protocol = port_elem.get("protocol")

        # Check port state
        state_elem = port_elem.find("state")
        if state_elem is None:
            return None

        state = state_elem.get("state")
        if state not in ["open", "filtered"]:
            return None

        # Get service information
        service_elem = port_elem.find("service")
        service_name = "unknown"
        service_product = None
        service_version = None
        service_extrainfo = None

        if service_elem is not None:
            service_name = service_elem.get("name") or "unknown"
            service_product = service_elem.get("product")
            service_version = service_elem.get("version")
            service_extrainfo = service_elem.get("extrainfo")

        # Build service string
        service_string = service_name
        if service_product:
            service_string = service_product
            if service_version:
                service_string += f" {service_version}"

        # Determine severity based on common vulnerable services
        severity = self._assess_port_severity(int(port_id), service_name, state)

        finding = {
            "type": "open_port",
            "host": host_ip,
            "hostname": hostname,
            "port": int(port_id),
            "protocol": protocol,
            "state": state,
            "service": service_name,
            "service_string": service_string,
            "product": service_product,
            "version": service_version,
            "extrainfo": service_extrainfo,
            "severity": severity,
            "confidence": "high" if state == "open" else "medium"
        }

        # Update graph database with port information
        self._update_graph_for_port(finding)

        return finding

    def _assess_port_severity(self, port: int, service: str, state: str) -> str:
        """
        Assess the severity of an open port

        Args:
            port: Port number
            service: Service name
            state: Port state (open/filtered)

        Returns:
            Severity level: "info", "low", "medium", "high"
        """
        # Common vulnerable services
        high_risk_services = {
            "telnet", "ftp", "smb", "netbios-ssn", "rexec", "rlogin", "rsh"
        }

        # Database ports (often should not be exposed)
        database_ports = {3306, 5432, 27017, 6379, 9200, 9042}

        # Admin/Management ports
        admin_ports = {22, 3389, 5900, 5901, 8080, 8443}

        if state == "filtered":
            return "info"

        if service in high_risk_services:
            return "high"

        if port in database_ports:
            return "medium"

        if port in admin_ports:
            return "low"

        return "info"

    async def quick_scan(self, target: str) -> Dict[str, Any]:
        """
        Perform a quick scan of top 100 ports

        Args:
            target: Target to scan

        Returns:
            Scan results
        """
        return await self.execute(
            target=target,
            ports="--top-ports 100",
            scan_type="-sV",
            additional_args=["--version-intensity", "5"]
        )

    async def full_scan(self, target: str) -> Dict[str, Any]:
        """
        Perform a comprehensive scan of all ports

        Args:
            target: Target to scan

        Returns:
            Scan results
        """
        return await self.execute(
            target=target,
            ports="1-65535",
            scan_type="-sV -sC",  # Version + default scripts
            additional_args=["--version-intensity", "7"]
        )

    def _update_graph_for_port(self, finding: Dict[str, Any]) -> None:
        """
        Update graph database with port information.

        Args:
            finding: Port finding dictionary
        """
        try:
            parameters = {
                "host_ip": finding.get("host", ""),
                "hostname": finding.get("hostname"),
                "port_number": finding.get("port", 0),
                "protocol": finding.get("protocol", "tcp"),
                "state": finding.get("state", "open"),
                "service": finding.get("service", "unknown"),
                "service_string": finding.get("service_string", ""),
                "product": finding.get("product"),
                "version": finding.get("version"),
                "extrainfo": finding.get("extrainfo")
            }

            if parameters["host_ip"] and parameters["port_number"]:
                update_graph(
                    CypherTemplates.NMAP_PORT,
                    parameters,
                    tool_name=self.tool_name
                )
        except Exception as e:
            self.logger.debug(f"Graph update failed for port: {e}")

    def _update_graph_for_os(self, finding: Dict[str, Any]) -> None:
        """
        Update graph database with OS detection information.

        Args:
            finding: OS detection finding dictionary
        """
        try:
            parameters = {
                "host_ip": finding.get("host", ""),
                "hostname": finding.get("hostname"),
                "os_name": finding.get("os_name", ""),
                "os_accuracy": finding.get("accuracy", "0")
            }

            if parameters["host_ip"] and parameters["os_name"]:
                update_graph(
                    CypherTemplates.NMAP_OS,
                    parameters,
                    tool_name=self.tool_name
                )
        except Exception as e:
            self.logger.debug(f"Graph update failed for OS detection: {e}")
