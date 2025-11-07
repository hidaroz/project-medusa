"""
httpx Web Server Validation Integration
Provides fast HTTP server detection and validation using httpx
"""

import json
import time
import tempfile
import os
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from .base import BaseTool, ToolExecutionError
from .graph_integration import CypherTemplates, update_graph


class HttpxScanner(BaseTool):
    """
    httpx web server detection integration
    
    Fast HTTP toolkit for validating live web servers and gathering HTTP metadata
    Typically used after Amass for target validation
    """

    def __init__(self, timeout: int = 120, threads: int = 50):
        """
        Initialize httpx scanner

        Args:
            timeout: Maximum execution time in seconds (default: 120)
            threads: Number of concurrent threads (default: 50)
        """
        super().__init__(timeout=timeout, tool_name="httpx")
        self.threads = threads

    @property
    def tool_binary_name(self) -> str:
        return "httpx"

    async def validate_servers(
        self,
        targets: List[str],
        threads: Optional[int] = None,
        follow_redirects: bool = False,
        status_codes: Optional[List[int]] = None,
        timeout_per_request: int = 5,
        use_https: bool = True
    ) -> Dict[str, Any]:
        """
        Validate live web servers from list of targets

        Args:
            targets: List of URLs, domains, or IPs to check
            threads: Number of concurrent threads
            follow_redirects: Follow HTTP redirects
            status_codes: Status codes to consider "live" (default: 200-299)
            timeout_per_request: Timeout per request in seconds
            use_https: Probe HTTPS first (default: True)

        Returns:
            Dict with validation results:
            {
                "success": bool,
                "targets_checked": int,
                "live_servers": List[Dict],
                "findings_count": int,
                "duration_seconds": float
            }
        """
        # Check if httpx is available
        if not self.is_available():
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"{self.tool_binary_name} is not installed or not in PATH"
            )

        if not targets:
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error="No targets provided"
            )

        # Use provided thread count or default
        actual_threads = threads or self.threads

        # Default status codes
        if status_codes is None:
            status_codes = list(range(200, 300))  # 200-299

        # Create temporary file for targets
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for target in targets:
                # Ensure targets have scheme
                target_url = self._ensure_url_scheme(target, use_https)
                f.write(target_url + '\n')
            targets_file = f.name

        # Create temporary output file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            output_file = f.name

        try:
            # Build httpx command
            cmd = ["httpx"]

            # Input from file
            cmd.extend(["-l", targets_file])

            # Output options
            cmd.extend(["-json", "-o", output_file])

            # Connection options
            cmd.extend(["-threads", str(actual_threads)])
            cmd.extend(["-timeout", str(timeout_per_request)])

            # Follow redirects if requested
            if follow_redirects:
                cmd.append("-follow-redirects")

            # Silent mode
            cmd.append("-silent")

            # Execute command
            start_time = time.time()
            try:
                stdout, stderr, returncode = await self._run_command(cmd)
                duration = time.time() - start_time

                # Parse results from JSON file
                findings = self._parse_json_output(output_file, status_codes)

                # Count targets
                targets_checked = len(targets)
                live_servers_count = len([f for f in findings if f.get("status_code", 0) >= 200 and f.get("status_code", 0) < 300])

                return self._create_result_dict(
                    success=True,
                    findings=findings,
                    raw_output=stdout,
                    duration=duration,
                    metadata={
                        "targets_checked": targets_checked,
                        "live_servers": live_servers_count,
                        "threads_used": actual_threads,
                    }
                )

            except ToolExecutionError as e:
                duration = time.time() - start_time
                self.logger.error(f"httpx execution error: {e}")
                return self._create_result_dict(
                    success=False,
                    findings=[],
                    raw_output="",
                    duration=duration,
                    error=str(e)
                )

        finally:
            # Clean up temporary files
            for f in [targets_file, output_file]:
                try:
                    if os.path.exists(f):
                        os.unlink(f)
                except Exception as e:
                    self.logger.warning(f"Failed to clean up temporary file: {e}")

    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse httpx JSON output

        Args:
            stdout: Standard output from httpx
            stderr: Standard error from httpx

        Returns:
            List of findings
        """
        findings = []

        if not stdout:
            self.logger.warning("Empty httpx output")
            return findings

        try:
            # Parse line-delimited JSON from stdout
            for line in stdout.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    finding = self._transform_httpx_json(data)
                    if finding:
                        findings.append(finding)
                except json.JSONDecodeError:
                    continue

        except Exception as e:
            self.logger.error(f"Failed to parse httpx output: {e}")

        return findings

    def _parse_json_output(self, json_file: str, status_codes: List[int]) -> List[Dict[str, Any]]:
        """
        Parse httpx JSON output file

        Args:
            json_file: Path to httpx JSON output file
            status_codes: Status codes to consider "live"

        Returns:
            List of findings
        """
        findings = []

        if not os.path.exists(json_file):
            self.logger.warning(f"JSON output file not found: {json_file}")
            return findings

        try:
            with open(json_file, 'r') as f:
                # httpx outputs line-delimited JSON
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        finding = self._transform_httpx_json(data)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            self.logger.error(f"Failed to parse JSON file: {e}")

        return findings

    def _transform_httpx_json(self, httpx_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Transform httpx JSON into standardized finding format

        Args:
            httpx_data: Raw data from httpx JSON

        Returns:
            Transformed finding dict or None
        """
        if "url" not in httpx_data:
            return None

        url = httpx_data.get("url", "")
        status_code = httpx_data.get("status-code", 0)

        # Only return if server is live
        if status_code < 200 or status_code >= 300:
            return None

        # Extract metadata
        content_length = httpx_data.get("content-length", 0)
        content_type = httpx_data.get("content-type", "unknown")
        title = httpx_data.get("title", "")
        web_server = httpx_data.get("webserver", "unknown")
        tech_list = httpx_data.get("tech", [])

        # Parse URL to check for SSL
        parsed = urlparse(url)
        ssl = parsed.scheme == "https"

        # Determine severity based on HTTP status and content
        severity = self._assess_web_server_severity(status_code, web_server, content_type)

        finding = {
            "type": "web_server_detection",
            "url": url,
            "status_code": status_code,
            "status_text": self._get_status_text(status_code),
            "web_server": web_server,
            "content_type": content_type,
            "content_length": content_length,
            "title": title,
            "technologies": tech_list if tech_list else [],
            "ssl": ssl,
            "severity": severity,
            "confidence": "high"
        }

        # Update graph database with web server information
        self._update_graph_for_webserver(finding)

        return finding

    def _ensure_url_scheme(self, target: str, use_https: bool = True) -> str:
        """
        Ensure target has URL scheme (http/https)

        Args:
            target: Target URL or domain
            use_https: Use HTTPS by default

        Returns:
            Target with scheme
        """
        if "://" in target:
            return target

        scheme = "https" if use_https else "http"
        return f"{scheme}://{target}"

    def _get_status_text(self, status_code: int) -> str:
        """Get HTTP status text for code"""
        status_map = {
            200: "OK",
            201: "Created",
            204: "No Content",
            301: "Moved Permanently",
            302: "Found",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
        }
        return status_map.get(status_code, "Unknown")

    def _assess_web_server_severity(self, status_code: int, web_server: str, content_type: str) -> str:
        """
        Assess severity of web server finding

        Args:
            status_code: HTTP status code
            web_server: Web server string
            content_type: Content-Type header

        Returns:
            Severity level
        """
        # Admin panels and default pages are more interesting
        if status_code in [401, 403]:
            return "medium"  # Authentication required

        # API endpoints are valuable
        if "application/json" in content_type.lower():
            return "medium"

        # Older servers might be vulnerable
        vulnerable_servers = ["Apache/2.2", "Apache/2.0", "IIS/6", "IIS/7"]
        for vuln_server in vulnerable_servers:
            if vuln_server in web_server:
                return "high"

        return "low"

    async def quick_validate(self, targets: List[str], threads: Optional[int] = None) -> Dict[str, Any]:
        """
        Perform quick validation of targets

        Args:
            targets: List of targets to validate
            threads: Optional thread count (defaults to self.threads, or 10 if not set)

        Returns:
            Validation results
        """
        # Use provided threads, or self.threads, or a safe default (10)
        actual_threads = threads if threads is not None else (self.threads if self.threads <= 20 else 10)
        
        return await self.validate_servers(
            targets=targets,
            threads=actual_threads,
            timeout_per_request=5
        )

    async def deep_probe(self, targets: List[str]) -> Dict[str, Any]:
        """
        Perform deep probing of targets with redirects

        Args:
            targets: List of targets to probe

        Returns:
            Probing results
        """
        return await self.validate_servers(
            targets=targets,
            threads=25,
            follow_redirects=True,
            timeout_per_request=10
        )

    def _update_graph_for_webserver(self, finding: Dict[str, Any]) -> None:
        """
        Update graph database with web server information.

        Args:
            finding: Web server finding dictionary
        """
        try:
            # Prepare parameters for Cypher query
            parameters = {
                "url": finding.get("url", ""),
                "status_code": finding.get("status_code", 0),
                "status_text": finding.get("status_text", ""),
                "title": finding.get("title", ""),
                "web_server": finding.get("web_server", "unknown"),
                "content_type": finding.get("content_type", "unknown"),
                "content_length": finding.get("content_length", 0),
                "technologies": finding.get("technologies", []),
                "ssl": finding.get("ssl", False)
            }

            # Only update if we have a valid URL
            if parameters["url"]:
                update_graph(
                    CypherTemplates.HTTPX_WEBSERVER,
                    parameters,
                    tool_name=self.tool_name
                )
        except Exception as e:
            self.logger.debug(f"Graph update failed for web server: {e}")

