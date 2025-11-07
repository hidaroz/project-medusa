"""
Kerbrute Kerberos Enumeration Integration
Provides user enumeration, password spray, and bruteforce attacks via Kerberos
"""

import time
import tempfile
import os
import re
from typing import Dict, List, Any, Optional

from .base import BaseTool, ToolExecutionError


class KerbruteScanner(BaseTool):
    """
    Kerbrute Kerberos attack integration
    
    Supports user enumeration, password spray, and bruteforce attacks
    Essential for Active Directory penetration testing
    """

    def __init__(self, timeout: int = 600, threads: int = 10):
        """
        Initialize Kerbrute scanner

        Args:
            timeout: Maximum execution time in seconds (default: 600 = 10 min)
            threads: Number of concurrent threads (default: 10)
        """
        super().__init__(timeout=timeout, tool_name="kerbrute")
        self.threads = threads

    @property
    def tool_binary_name(self) -> str:
        return "kerbrute"

    async def enumerate_users(
        self,
        dc: str,
        domain: str,
        userlist: str,
        threads: Optional[int] = None,
        rate_limit: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Enumerate valid Kerberos users

        Args:
            dc: Domain Controller IP or hostname
            domain: Domain name (e.g., domain.local)
            userlist: Path to file with usernames to test
            threads: Number of concurrent threads
            rate_limit: Delay between attempts (ms)

        Returns:
            Dict with enumeration results:
            {
                "success": bool,
                "findings": List[Dict],
                "valid_users": int,
                "asrep_roastable": int,
                "duration_seconds": float
            }
        """
        return await self._execute_kerbrute(
            mode="userenum",
            dc=dc,
            domain=domain,
            userlist=userlist,
            threads=threads,
            rate_limit=rate_limit
        )

    async def password_spray(
        self,
        dc: str,
        domain: str,
        userlist: str,
        password: str,
        threads: Optional[int] = None,
        rate_limit: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Test password against multiple users (password spray)

        Args:
            dc: Domain Controller IP or hostname
            domain: Domain name
            userlist: Path to file with usernames
            password: Password to test
            threads: Number of concurrent threads
            rate_limit: Delay between attempts (ms)

        Returns:
            Dict with spray results
        """
        return await self._execute_kerbrute(
            mode="passwordspray",
            dc=dc,
            domain=domain,
            userlist=userlist,
            password=password,
            threads=threads,
            rate_limit=rate_limit
        )

    async def bruteforce_user(
        self,
        dc: str,
        domain: str,
        username: str,
        passwordlist: str,
        threads: Optional[int] = None,
        rate_limit: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Bruteforce password for single user

        Args:
            dc: Domain Controller IP or hostname
            domain: Domain name
            username: Username to bruteforce
            passwordlist: Path to file with passwords
            threads: Number of concurrent threads
            rate_limit: Delay between attempts (ms)

        Returns:
            Dict with bruteforce results
        """
        return await self._execute_kerbrute(
            mode="bruteuser",
            dc=dc,
            domain=domain,
            username=username,
            passwordlist=passwordlist,
            threads=threads,
            rate_limit=rate_limit
        )

    async def _execute_kerbrute(
        self,
        mode: str,
        dc: str,
        domain: str,
        userlist: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        passwordlist: Optional[str] = None,
        threads: Optional[int] = None,
        rate_limit: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute Kerbrute with specified mode and options

        Args:
            mode: Kerbrute mode (userenum, passwordspray, bruteuser)
            dc: Domain Controller
            domain: Domain name
            userlist: User list file path
            username: Single username
            password: Single password
            passwordlist: Password list file path
            threads: Thread count
            rate_limit: Rate limit in ms

        Returns:
            Standardized result dictionary
        """
        # Check if kerbrute is available
        if not self.is_available():
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"{self.tool_binary_name} is not installed or not in PATH"
            )

        # Sanitize inputs
        try:
            safe_dc = self._sanitize_target(dc)
            safe_domain = self._sanitize_target(domain)
        except ValueError as e:
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"Invalid input: {str(e)}"
            )

        # Verify files exist
        if userlist and not os.path.exists(userlist):
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"User list file not found: {userlist}"
            )

        if passwordlist and not os.path.exists(passwordlist):
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"Password list file not found: {passwordlist}"
            )

        # Use provided thread count or default
        actual_threads = threads or self.threads

        # Build kerbrute command
        cmd = ["kerbrute", mode]

        # Add domain controller
        cmd.extend(["-dc", safe_dc])

        # Add domain
        cmd.extend(["-d", safe_domain])

        # Add threads
        cmd.extend(["-t", str(actual_threads)])

        # Add rate limiting if specified
        if rate_limit:
            cmd.extend(["-w", str(rate_limit)])

        # Mode-specific arguments
        if mode == "userenum":
            if not userlist:
                return self._create_result_dict(
                    success=False,
                    findings=[],
                    raw_output="",
                    duration=0,
                    error="User list required for userenum mode"
                )
            cmd.append(userlist)

        elif mode == "passwordspray":
            if not userlist or not password:
                return self._create_result_dict(
                    success=False,
                    findings=[],
                    raw_output="",
                    duration=0,
                    error="User list and password required for passwordspray mode"
                )
            cmd.append(userlist)
            cmd.append(password)

        elif mode == "bruteuser":
            if not username or not passwordlist:
                return self._create_result_dict(
                    success=False,
                    findings=[],
                    raw_output="",
                    duration=0,
                    error="Username and password list required for bruteuser mode"
                )
            cmd.append(username)
            cmd.append(passwordlist)

        else:
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=0,
                error=f"Unknown kerbrute mode: {mode}"
            )

        # Execute command
        start_time = time.time()
        try:
            stdout, stderr, returncode = await self._run_command(cmd)
            duration = time.time() - start_time

            # Check for errors (kerbrute returns non-zero on auth failures)
            # This is normal behavior, so we parse output regardless
            findings = self.parse_output(stdout, stderr)

            # Build result based on mode
            metadata = {
                "mode": mode,
                "domain_controller": safe_dc,
                "domain": safe_domain,
                "threads": actual_threads,
            }

            if mode == "userenum":
                valid_users = len([f for f in findings if f.get("valid")])
                asrep_roastable = len([f for f in findings if f.get("requires_preauth") is False])

                metadata["valid_users"] = valid_users
                metadata["asrep_roastable"] = asrep_roastable

            elif mode == "passwordspray":
                successes = len([f for f in findings if f.get("successful")])
                metadata["successful_logins"] = successes

            elif mode == "bruteuser":
                successes = len([f for f in findings if f.get("successful")])
                metadata["successful_passwords"] = successes

            return self._create_result_dict(
                success=True,
                findings=findings,
                raw_output=stdout + stderr,
                duration=duration,
                metadata=metadata
            )

        except ToolExecutionError as e:
            duration = time.time() - start_time
            self.logger.error(f"Kerbrute execution error: {e}")
            return self._create_result_dict(
                success=False,
                findings=[],
                raw_output="",
                duration=duration,
                error=str(e)
            )

    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse Kerbrute text output

        Args:
            stdout: Standard output from kerbrute
            stderr: Standard error from kerbrute

        Returns:
            List of findings
        """
        findings = []

        if not stdout:
            self.logger.warning("Empty kerbrute output")
            return findings

        try:
            # Combine stdout and stderr for parsing
            output = stdout + stderr

            # Pattern for valid users (userenum mode)
            # Example: [+] VALID USER: jsmith @ domain.local
            valid_user_pattern = r'\[✓\]\s+VALID\s+USER:\s+(\S+)\s+@\s+(\S+)'
            user_matches = re.findall(valid_user_pattern, output, re.IGNORECASE)

            for username, domain in user_matches:
                finding = {
                    "type": "kerberos_user",
                    "username": username,
                    "domain": domain,
                    "valid": True,
                    "severity": "low",
                    "confidence": "high"
                }

                # Check if ASREProastable (no preauth required)
                # Example: [!] User jsmith@domain.local doesn't require preauthentication
                if f"{username}@{domain}" in output and "preauthentication" in output.lower():
                    finding["requires_preauth"] = False
                    finding["asrep_roastable"] = True
                    finding["severity"] = "medium"
                else:
                    finding["requires_preauth"] = True
                    finding["asrep_roastable"] = False

                findings.append(finding)

            # Pattern for successful authentications (passwordspray/bruteuser)
            # Example: [+] jsmith:Password123 @ domain.local
            auth_pattern = r'\[✓\]\s+(\S+):(\S+)\s+@\s+(\S+)'
            auth_matches = re.findall(auth_pattern, output, re.IGNORECASE)

            for username, password, domain in auth_matches:
                finding = {
                    "type": "kerberos_credentials",
                    "username": username,
                    "password": password,
                    "domain": domain,
                    "successful": True,
                    "severity": "high",
                    "confidence": "high"
                }
                findings.append(finding)

            # Pattern for ASREProastable users (no preauth)
            # Example: [!] No preauth required - jsmith
            asrep_pattern = r'No preauth required.*?(\S+)'
            asrep_matches = re.findall(asrep_pattern, output, re.IGNORECASE)

            for username in asrep_matches:
                # Update existing user finding if found
                updated = False
                for finding in findings:
                    if finding.get("username") == username:
                        finding["asrep_roastable"] = True
                        finding["requires_preauth"] = False
                        finding["severity"] = "medium"
                        updated = True
                        break

                if not updated:
                    finding = {
                        "type": "kerberos_user",
                        "username": username,
                        "valid": True,
                        "asrep_roastable": True,
                        "requires_preauth": False,
                        "severity": "medium",
                        "confidence": "high"
                    }
                    findings.append(finding)

        except Exception as e:
            self.logger.error(f"Failed to parse kerbrute output: {e}")

        return findings

    async def quick_enum(
        self,
        dc: str,
        domain: str,
        userlist: str
    ) -> Dict[str, Any]:
        """
        Quick user enumeration with default settings

        Args:
            dc: Domain Controller
            domain: Domain name
            userlist: User list file

        Returns:
            Enumeration results
        """
        return await self.enumerate_users(
            dc=dc,
            domain=domain,
            userlist=userlist,
            threads=10,
            rate_limit=100
        )

    async def safe_spray(
        self,
        dc: str,
        domain: str,
        userlist: str,
        password: str
    ) -> Dict[str, Any]:
        """
        Safe password spray with rate limiting to avoid lockouts

        Args:
            dc: Domain Controller
            domain: Domain name
            userlist: User list file
            password: Password to spray

        Returns:
            Spray results
        """
        return await self.password_spray(
            dc=dc,
            domain=domain,
            userlist=userlist,
            password=password,
            threads=5,  # Reduced threads
            rate_limit=500  # Delay between attempts
        )

