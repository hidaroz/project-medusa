"""
Web Scanner Integration
Provides HTTP reconnaissance, fingerprinting, and technology detection
"""

import re
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from .base import BaseTool, ToolExecutionError


class WebScanner(BaseTool):
    """
    Web reconnaissance and fingerprinting scanner

    Features:
    - HTTP/HTTPS accessibility testing
    - Header analysis
    - Technology fingerprinting (whatweb if available)
    - Common endpoint discovery
    - Response analysis
    """

    def __init__(self, timeout: int = 120):
        """
        Initialize web scanner

        Args:
            timeout: Maximum scan time in seconds (default: 120)
        """
        super().__init__(timeout=timeout, tool_name="web_scanner")

    @property
    def tool_binary_name(self) -> str:
        return "curl"  # Fallback tool if aiohttp not available

    async def execute(
        self,
        target: str,
        check_https: bool = True,
        use_whatweb: bool = True,
        check_endpoints: bool = True
    ) -> Dict[str, Any]:
        """
        Perform web reconnaissance

        Args:
            target: Target URL or hostname
            check_https: Also check HTTPS if HTTP works
            use_whatweb: Use whatweb for technology detection (if available)
            check_endpoints: Check for common endpoints

        Returns:
            Dict with web reconnaissance results
        """
        if not AIOHTTP_AVAILABLE:
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error="aiohttp library not available. Install with: pip install aiohttp"
            )

        start_time = time.time()
        findings = []

        # Normalize target
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"

        try:
            # Test HTTP accessibility
            http_result = await self._test_http_access(target)
            if http_result:
                findings.extend(http_result)

            # Test HTTPS if requested
            if check_https:
                https_target = target.replace('http://', 'https://')
                https_result = await self._test_http_access(https_target)
                if https_result:
                    findings.extend(https_result)

            # Run whatweb if available and requested
            if use_whatweb and self._is_whatweb_available():
                whatweb_result = await self._run_whatweb(target)
                if whatweb_result:
                    findings.extend(whatweb_result)

            # Check common endpoints if requested
            if check_endpoints and findings:
                # Only check endpoints if the target is accessible
                endpoint_result = await self._check_common_endpoints(target)
                if endpoint_result:
                    findings.extend(endpoint_result)

            duration = time.time() - start_time

            return self._create_result_dict(
                success=True,
                findings=findings,
                raw_output=self._format_findings_as_text(findings),
                duration=duration,
                metadata={"target": target}
            )

        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(f"Web scan error: {e}")
            return self._create_result_dict(
                success=False,
                findings=findings,  # Return partial findings
                raw_output="",
                duration=duration,
                error=str(e)
            )

    async def _test_http_access(self, url: str) -> List[Dict[str, Any]]:
        """
        Test HTTP/HTTPS accessibility and analyze response

        Args:
            url: Full URL to test

        Returns:
            List of findings
        """
        findings = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,  # Don't verify SSL for pentesting
                    allow_redirects=True
                ) as response:
                    # Basic accessibility finding
                    scheme = urlparse(url).scheme
                    findings.append({
                        "type": "web_service",
                        "url": url,
                        "scheme": scheme,
                        "status_code": response.status,
                        "accessible": True,
                        "severity": "info",
                        "confidence": "high"
                    })

                    # Analyze headers
                    header_findings = self._analyze_headers(url, dict(response.headers))
                    findings.extend(header_findings)

                    # Get response body for analysis
                    try:
                        body = await response.text()
                        body_findings = self._analyze_response_body(url, body)
                        findings.extend(body_findings)
                    except Exception as e:
                        self.logger.warning(f"Could not read response body: {e}")

        except aiohttp.ClientError as e:
            self.logger.debug(f"HTTP request to {url} failed: {e}")
            findings.append({
                "type": "web_service",
                "url": url,
                "accessible": False,
                "error": str(e),
                "severity": "info",
                "confidence": "high"
            })
        except Exception as e:
            self.logger.warning(f"Unexpected error testing {url}: {e}")

        return findings

    def _analyze_headers(self, url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Analyze HTTP headers for security issues and information disclosure

        Args:
            url: Target URL
            headers: Response headers

        Returns:
            List of findings
        """
        findings = []

        # Check for server version disclosure
        server = headers.get('Server') or headers.get('server')
        if server:
            findings.append({
                "type": "information_disclosure",
                "url": url,
                "title": "Server Version Disclosure",
                "description": f"Server header reveals version information: {server}",
                "server": server,
                "severity": "low",
                "confidence": "high"
            })

        # Check for X-Powered-By header
        powered_by = headers.get('X-Powered-By') or headers.get('x-powered-by')
        if powered_by:
            findings.append({
                "type": "information_disclosure",
                "url": url,
                "title": "X-Powered-By Header Disclosure",
                "description": f"X-Powered-By header reveals technology: {powered_by}",
                "technology": powered_by,
                "severity": "low",
                "confidence": "high"
            })

        # Check for missing security headers
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'Content-Security-Policy': 'XSS protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'X-XSS-Protection': 'XSS filter'
        }

        for header, description in security_headers.items():
            if header not in headers and header.lower() not in headers:
                findings.append({
                    "type": "misconfiguration",
                    "url": url,
                    "title": f"Missing Security Header: {header}",
                    "description": f"Missing {description} header",
                    "header": header,
                    "severity": "low",
                    "confidence": "high"
                })

        # Check for overly permissive CORS
        cors_header = headers.get('Access-Control-Allow-Origin') or headers.get('access-control-allow-origin')
        if cors_header == '*':
            findings.append({
                "type": "misconfiguration",
                "url": url,
                "title": "Overly Permissive CORS Policy",
                "description": "Access-Control-Allow-Origin set to '*' allows any origin",
                "severity": "medium",
                "confidence": "high"
            })

        return findings

    def _analyze_response_body(self, url: str, body: str) -> List[Dict[str, Any]]:
        """
        Analyze response body for interesting patterns

        Args:
            url: Target URL
            body: Response body

        Returns:
            List of findings
        """
        findings = []

        # Extract title
        title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
        if title_match:
            title = title_match.group(1).strip()
            findings.append({
                "type": "webapp_info",
                "url": url,
                "title": title,
                "severity": "info",
                "confidence": "high"
            })

        # Check for common frameworks in body
        frameworks = {
            'React': r'react',
            'Vue.js': r'vue',
            'Angular': r'ng-[a-z]+',
            'jQuery': r'jquery',
            'Bootstrap': r'bootstrap',
            'WordPress': r'wp-content',
            'Drupal': r'drupal',
        }

        detected_frameworks = []
        for framework, pattern in frameworks.items():
            if re.search(pattern, body, re.IGNORECASE):
                detected_frameworks.append(framework)

        if detected_frameworks:
            findings.append({
                "type": "technology_detection",
                "url": url,
                "title": "Frontend Frameworks Detected",
                "technologies": detected_frameworks,
                "severity": "info",
                "confidence": "medium"
            })

        # Check for comments with sensitive info
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        sensitive_patterns = [
            r'password', r'token', r'api[_-]?key', r'secret',
            r'todo', r'fix', r'bug', r'hack'
        ]

        for comment in comments:
            for pattern in sensitive_patterns:
                if re.search(pattern, comment, re.IGNORECASE):
                    findings.append({
                        "type": "information_disclosure",
                        "url": url,
                        "title": "Sensitive Information in HTML Comments",
                        "description": f"HTML comment may contain sensitive information: {comment[:100]}",
                        "severity": "low",
                        "confidence": "medium"
                    })
                    break  # Only report once per comment

        return findings

    def _is_whatweb_available(self) -> bool:
        """Check if whatweb is available"""
        import shutil
        return shutil.which('whatweb') is not None

    async def _run_whatweb(self, target: str) -> List[Dict[str, Any]]:
        """
        Run whatweb for technology fingerprinting

        Args:
            target: Target URL

        Returns:
            List of findings
        """
        findings = []

        try:
            cmd = ["whatweb", "--color=never", "-a", "3", target]
            stdout, stderr, returncode = await self._run_command(cmd)

            if returncode == 0:
                technologies = self._parse_whatweb_output(stdout)
                if technologies:
                    findings.append({
                        "type": "technology_detection",
                        "url": target,
                        "title": "Technologies Detected (WhatWeb)",
                        "technologies": technologies,
                        "raw_output": stdout,
                        "severity": "info",
                        "confidence": "high"
                    })
            else:
                self.logger.warning(f"whatweb failed: {stderr}")

        except ToolExecutionError as e:
            self.logger.debug(f"whatweb execution failed: {e}")
        except Exception as e:
            self.logger.warning(f"whatweb error: {e}")

        return findings

    def _parse_whatweb_output(self, output: str) -> List[str]:
        """
        Parse whatweb output to extract technologies

        Args:
            output: whatweb output

        Returns:
            List of detected technologies
        """
        technologies = []

        # WhatWeb format: http://target [200 OK] Technology[Version], Technology2
        if "[" in output and "]" in output:
            # Extract everything after the HTTP status
            parts = output.split("]", 1)
            if len(parts) > 1:
                tech_part = parts[1].strip()

                # Split by comma and extract tech names
                techs = tech_part.split(",")
                for tech in techs:
                    tech = tech.strip()
                    if tech:
                        # Remove version info in brackets
                        tech_name = re.sub(r'\[.*?\]', '', tech).strip()
                        if tech_name:
                            technologies.append(tech_name)

        return technologies

    async def _check_common_endpoints(self, base_url: str) -> List[Dict[str, Any]]:
        """
        Check for common interesting endpoints

        Args:
            base_url: Base URL to check

        Returns:
            List of findings
        """
        findings = []

        common_endpoints = [
            '/robots.txt',
            '/sitemap.xml',
            '/.git/HEAD',
            '/.env',
            '/api',
            '/api/v1',
            '/admin',
            '/login',
            '/swagger',
            '/graphql',
        ]

        try:
            async with aiohttp.ClientSession() as session:
                for endpoint in common_endpoints:
                    url = urljoin(base_url, endpoint)

                    try:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=5),
                            ssl=False,
                            allow_redirects=False
                        ) as response:
                            if response.status in [200, 301, 302]:
                                findings.append({
                                    "type": "endpoint_discovery",
                                    "url": url,
                                    "endpoint": endpoint,
                                    "status_code": response.status,
                                    "title": f"Endpoint Found: {endpoint}",
                                    "severity": self._assess_endpoint_severity(endpoint),
                                    "confidence": "high"
                                })
                    except aiohttp.ClientError:
                        # Endpoint not accessible, skip
                        pass

        except Exception as e:
            self.logger.warning(f"Error checking endpoints: {e}")

        return findings

    def _assess_endpoint_severity(self, endpoint: str) -> str:
        """
        Assess severity of discovered endpoint

        Args:
            endpoint: Endpoint path

        Returns:
            Severity level
        """
        high_risk = ['.git', '.env', '.aws', 'config', 'backup']
        medium_risk = ['admin', 'login', 'graphql', 'swagger']

        endpoint_lower = endpoint.lower()

        for pattern in high_risk:
            if pattern in endpoint_lower:
                return "high"

        for pattern in medium_risk:
            if pattern in endpoint_lower:
                return "medium"

        return "low"

    def _format_findings_as_text(self, findings: List[Dict[str, Any]]) -> str:
        """Format findings as readable text"""
        lines = []
        for finding in findings:
            lines.append(f"Type: {finding.get('type', 'unknown')}")
            lines.append(f"URL: {finding.get('url', 'N/A')}")
            if 'title' in finding:
                lines.append(f"Title: {finding['title']}")
            if 'description' in finding:
                lines.append(f"Description: {finding['description']}")
            lines.append(f"Severity: {finding.get('severity', 'info')}")
            lines.append("-" * 50)
        return "\n".join(lines)

    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """Not used for web scanner (uses direct HTTP calls)"""
        return []
