"""
Nikto Integration
Provides comprehensive web server vulnerability scanning using Nikto
"""

import re
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from .base import BaseTool, ToolExecutionError


class NiktoScanner(BaseTool):
    """
    Nikto web vulnerability scanner integration

    Features:
    - Comprehensive web server scanning
    - Vulnerability detection
    - Misconfigurations identification
    - Outdated software detection
    - SSL/TLS testing
    - Output parsing from CSV or text format
    """

    def __init__(self, timeout: int = 1800):
        """
        Initialize Nikto scanner

        Args:
            timeout: Maximum scan time in seconds (default: 1800 = 30 min)
        """
        super().__init__(timeout=timeout, tool_name="nikto")

    @property
    def tool_binary_name(self) -> str:
        return "nikto"

    async def execute(
        self,
        target_url: str,
        port: Optional[int] = None,
        ssl: Optional[bool] = None,
        tuning: Optional[str] = None,
        plugins: Optional[List[str]] = None,
        no_ssl: bool = False,
        use_proxy: Optional[str] = None,
        output_format: str = "txt"
    ) -> Dict[str, Any]:
        """
        Execute Nikto web vulnerability scan

        Args:
            target_url: Target URL or hostname
            port: Target port (default: auto-detect from URL)
            ssl: Force SSL/TLS (default: auto-detect)
            tuning: Scan tuning (0-9, x, a-b)
                    1=Interesting File
                    2=Misconfiguration
                    3=Information Disclosure
                    4=Injection (XSS/Script/HTML)
                    5=Remote File Retrieval
                    6=Denial of Service
                    7=Remote File Retrieval
                    8=Command Execution
                    9=SQL Injection
                    x=Reverse Tuning (exclude instead of include)
            plugins: List of plugin names to use
            no_ssl: Disable SSL checks
            use_proxy: Proxy server (e.g., "http://proxy:8080")
            output_format: Output format (txt, csv, html)

        Returns:
            Dict with vulnerability findings
        """
        # Check if nikto is available
        if not self.is_available():
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"{self.tool_binary_name} is not installed or not in PATH"
            )

        # Parse and sanitize target
        try:
            parsed_url = urlparse(target_url)
            host = parsed_url.hostname or target_url

            # Auto-detect port and SSL
            if port is None:
                port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)

            if ssl is None:
                ssl = parsed_url.scheme == 'https' or port == 443

            # Sanitize host
            safe_host = self._sanitize_target(host)
        except Exception as e:
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"Invalid target URL: {str(e)}"
            )

        # Build nikto command
        cmd = [
            "nikto",
            "-h", safe_host,
            "-p", str(port),
            "-Format", output_format,
            "-nointeractive",  # Don't prompt for user input
        ]

        # Add SSL if needed
        if ssl and not no_ssl:
            cmd.append("-ssl")

        # Add tuning options
        if tuning:
            cmd.extend(["-Tuning", tuning])

        # Add plugins
        if plugins:
            cmd.extend(["-Plugins", ",".join(plugins)])

        # Add proxy if specified
        if use_proxy:
            cmd.extend(["-useproxy", use_proxy])

        # Disable check for updates
        cmd.append("-noupdate")

        # Execute scan
        start_time = time.time()
        try:
            self.logger.info(f"Starting Nikto scan on {safe_host}:{port}")
            stdout, stderr, returncode = await self._run_command(cmd)
            duration = time.time() - start_time

            # Parse output
            findings = self.parse_output(stdout, stderr)

            # Nikto may return non-zero even on successful scans
            success = len(findings) > 0 or "0 host(s) tested" in stdout

            self.logger.info(
                f"Nikto scan completed: {len(findings)} findings, "
                f"{duration:.2f}s duration"
            )

            return self._create_result_dict(
                success=success,
                findings=findings,
                raw_output=stdout,
                duration=duration,
                metadata={
                    "target": safe_host,
                    "port": port,
                    "ssl": ssl,
                    "scan_type": "web_vulnerability"
                }
            )

        except ToolExecutionError as e:
            duration = time.time() - start_time
            self.logger.error(f"Nikto execution error: {e}")
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=duration,
                error=str(e)
            )

    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse Nikto output to extract vulnerability findings

        Args:
            stdout: Nikto standard output
            stderr: Nikto standard error

        Returns:
            List of vulnerability findings
        """
        findings = []

        if not stdout or not stdout.strip():
            self.logger.warning("Empty Nikto output")
            return findings

        # Pattern 1: Standard Nikto finding line
        # Example: "+ /admin/: Admin interface found"
        # Format: + <uri>: <description>
        finding_pattern = r'\+\s+([^\:]+):\s+(.+?)(?:\n|$)'

        for match in re.finditer(finding_pattern, stdout, re.MULTILINE):
            uri = match.group(1).strip()
            description = match.group(2).strip()

            # Skip non-vulnerability entries
            if any(skip in description.lower() for skip in [
                'retrieved x-powered-by',
                'the anti-clickjacking',
                'uncommon header',
            ]):
                continue

            # Determine severity based on keywords
            severity = self._assess_nikto_severity(description)

            finding = {
                "type": "web_vulnerability",
                "severity": severity,
                "title": self._extract_title(description),
                "description": description,
                "uri": uri,
                "source": "nikto",
                "confidence": "medium",
                "recommendation": self._get_recommendation(description)
            }

            # Add OSVDB if present in description
            osvdb_match = re.search(r'OSVDB[:-]?\s*(\d+)', description)
            if osvdb_match:
                finding["osvdb"] = osvdb_match.group(1)

            # Add CVE if present
            cve_match = re.search(r'CVE-\d{4}-\d+', description)
            if cve_match:
                finding["cve"] = cve_match.group(0)

            findings.append(finding)

        # Pattern 2: Server information
        server_pattern = r'Server:\s+(.+?)(?:\n|$)'
        server_match = re.search(server_pattern, stdout)
        if server_match:
            server_info = server_match.group(1).strip()
            findings.append({
                "type": "information_disclosure",
                "severity": "low",
                "title": "Server Version Disclosure",
                "description": f"Web server identifies as: {server_info}",
                "server": server_info,
                "confidence": "high",
                "recommendation": "Configure server to hide version information"
            })

        # Pattern 3: Allowed HTTP methods
        methods_pattern = r'Allowed HTTP Methods:\s+(.+?)(?:\n|$)'
        methods_match = re.search(methods_pattern, stdout)
        if methods_match:
            methods = methods_match.group(1).strip()
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'TRACK', 'CONNECT']

            found_dangerous = [m for m in dangerous_methods if m in methods.upper()]
            if found_dangerous:
                findings.append({
                    "type": "misconfiguration",
                    "severity": "medium",
                    "title": "Dangerous HTTP Methods Enabled",
                    "description": f"Potentially dangerous HTTP methods enabled: {', '.join(found_dangerous)}",
                    "methods": methods,
                    "dangerous_methods": found_dangerous,
                    "confidence": "high",
                    "recommendation": "Disable unnecessary HTTP methods (PUT, DELETE, TRACE)"
                })

        # Pattern 4: SSL/TLS issues
        ssl_issues = [
            (r'SSL.*?weak', "weak_ssl", "Weak SSL/TLS Configuration", "high"),
            (r'SSL.*?vulnerable', "ssl_vuln", "SSL/TLS Vulnerability", "high"),
            (r'certificate.*?expired', "cert_expired", "Expired SSL Certificate", "medium"),
            (r'certificate.*?self-signed', "cert_self_signed", "Self-Signed Certificate", "low"),
        ]

        for pattern, issue_type, title, severity in ssl_issues:
            if re.search(pattern, stdout, re.IGNORECASE):
                findings.append({
                    "type": "ssl_issue",
                    "severity": severity,
                    "title": title,
                    "description": f"SSL/TLS issue detected: {issue_type}",
                    "issue_type": issue_type,
                    "confidence": "high",
                    "recommendation": "Update SSL/TLS configuration and certificates"
                })

        # Pattern 5: Outdated software
        if "outdated" in stdout.lower() or "old version" in stdout.lower():
            outdated_pattern = r'([^\n]*(?:outdated|old version)[^\n]*)'
            for match in re.finditer(outdated_pattern, stdout, re.IGNORECASE):
                description = match.group(1).strip()
                findings.append({
                    "type": "outdated_software",
                    "severity": "medium",
                    "title": "Outdated Software Detected",
                    "description": description,
                    "confidence": "medium",
                    "recommendation": "Update to the latest stable version"
                })

        # Pattern 6: Default credentials or files
        default_patterns = [
            (r'default.*?password', "Default credentials may be in use"),
            (r'default.*?file', "Default installation file found"),
            (r'admin.*?default', "Default admin interface accessible"),
        ]

        for pattern, desc in default_patterns:
            if re.search(pattern, stdout, re.IGNORECASE):
                findings.append({
                    "type": "default_configuration",
                    "severity": "high",
                    "title": "Default Configuration Detected",
                    "description": desc,
                    "confidence": "medium",
                    "recommendation": "Remove default files and change default credentials"
                })

        self.logger.info(f"Parsed {len(findings)} findings from Nikto output")
        return findings

    def _assess_nikto_severity(self, description: str) -> str:
        """
        Assess severity of a Nikto finding based on description

        Args:
            description: Finding description

        Returns:
            Severity level: "low", "medium", "high", or "critical"
        """
        desc_lower = description.lower()

        # Critical indicators
        critical_keywords = [
            'remote code execution', 'arbitrary code', 'command injection',
            'sql injection', 'authentication bypass', 'arbitrary file'
        ]
        if any(keyword in desc_lower for keyword in critical_keywords):
            return "critical"

        # High severity indicators
        high_keywords = [
            'admin', 'password', 'credential', 'vulnerable', 'exploit',
            'shell', 'backdoor', 'injection', 'upload', 'directory traversal'
        ]
        if any(keyword in desc_lower for keyword in high_keywords):
            return "high"

        # Medium severity indicators
        medium_keywords = [
            'disclosure', 'misconfiguration', 'configuration', 'method',
            'cookie', 'session', 'redirect', 'xss'
        ]
        if any(keyword in desc_lower for keyword in medium_keywords):
            return "medium"

        # Default to low
        return "low"

    def _extract_title(self, description: str) -> str:
        """
        Extract a concise title from finding description

        Args:
            description: Full finding description

        Returns:
            Concise title
        """
        # Take first sentence or first 100 chars
        sentences = description.split('.')
        title = sentences[0].strip()

        if len(title) > 100:
            title = title[:97] + "..."

        return title

    def _get_recommendation(self, description: str) -> str:
        """
        Generate recommendation based on finding description

        Args:
            description: Finding description

        Returns:
            Remediation recommendation
        """
        desc_lower = description.lower()

        if 'admin' in desc_lower or 'default' in desc_lower:
            return "Restrict access to administrative interfaces and remove default files"
        elif 'password' in desc_lower or 'credential' in desc_lower:
            return "Change default credentials and enforce strong password policy"
        elif 'ssl' in desc_lower or 'tls' in desc_lower:
            return "Update SSL/TLS configuration to use strong ciphers and protocols"
        elif 'cookie' in desc_lower:
            return "Set secure and HttpOnly flags on cookies"
        elif 'injection' in desc_lower:
            return "Implement input validation and use parameterized queries"
        elif 'disclosure' in desc_lower:
            return "Configure server to minimize information disclosure"
        elif 'directory' in desc_lower and 'listing' in desc_lower:
            return "Disable directory listing on the web server"
        else:
            return "Review finding and apply appropriate security controls"

    async def quick_scan(self, url: str) -> Dict[str, Any]:
        """
        Perform a quick Nikto scan (basic checks only)

        Args:
            url: Target URL

        Returns:
            Quick scan results
        """
        return await self.execute(
            target_url=url,
            tuning="1,2,3",  # Interesting files, misconfig, info disclosure
            output_format="txt"
        )

    async def thorough_scan(self, url: str) -> Dict[str, Any]:
        """
        Perform a thorough Nikto scan (all checks)

        Args:
            url: Target URL

        Returns:
            Thorough scan results
        """
        return await self.execute(
            target_url=url,
            tuning="123456789",  # All checks
            output_format="txt"
        )

    async def ssl_scan(self, url: str) -> Dict[str, Any]:
        """
        Perform SSL/TLS focused scan

        Args:
            url: Target URL (should be HTTPS)

        Returns:
            SSL/TLS scan results
        """
        return await self.execute(
            target_url=url,
            ssl=True,
            tuning="1,2,3",
            output_format="txt"
        )
