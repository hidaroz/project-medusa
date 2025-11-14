"""
Metasploit Integration
Provides access to Metasploit Framework via RPC API
"""

import json
import requests
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import logging
import time


class MetasploitRPC:
    """Metasploit RPC Client"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        username: str = "msf",
        password: str = "",
        ssl: bool = False
    ):
        """
        Initialize Metasploit RPC client

        Args:
            host: MSF RPC host
            port: MSF RPC port
            username: MSF RPC username
            password: MSF RPC password
            ssl: Use HTTPS
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssl = ssl

        protocol = "https" if ssl else "http"
        self.url = f"{protocol}://{host}:{port}/api/"

        self.token = None
        self.logger = logging.getLogger(__name__)

    def connect(self) -> bool:
        """
        Authenticate with MSF RPC

        Returns:
            True if authentication successful
        """
        try:
            response = self._call("auth.login", [self.username, self.password])

            if response.get("result") == "success":
                self.token = response.get("token")
                self.logger.info("Successfully authenticated with Metasploit RPC")
                return True
            else:
                self.logger.error(f"MSF RPC authentication failed: {response}")
                return False

        except Exception as e:
            self.logger.error(f"Failed to connect to MSF RPC: {e}")
            return False

    def disconnect(self):
        """Disconnect from MSF RPC"""
        if self.token:
            try:
                self._call("auth.logout", [self.token])
                self.logger.info("Disconnected from Metasploit RPC")
            except Exception as e:
                self.logger.warning(f"Error during disconnect: {e}")
            finally:
                self.token = None

    def search_exploits(
        self,
        query: str,
        type_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for exploits

        Args:
            query: Search query (CVE, keyword, etc.)
            type_filter: Filter by type (exploit, auxiliary, post, etc.)

        Returns:
            List of matching modules
        """
        if not self.token:
            raise RuntimeError("Not authenticated. Call connect() first.")

        try:
            # Search modules
            response = self._call("module.search", [self.token, query])

            modules = response.get("modules", [])

            # Filter by type if specified
            if type_filter:
                modules = [m for m in modules if m.startswith(type_filter)]

            # Get details for each module
            detailed_modules = []
            for module_name in modules[:20]:  # Limit to 20 for performance
                details = self.get_module_info(module_name)
                if details:
                    detailed_modules.append({
                        "name": module_name,
                        **details
                    })

            return detailed_modules

        except Exception as e:
            self.logger.error(f"Failed to search exploits: {e}")
            return []

    def get_module_info(self, module_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a module

        Args:
            module_name: Module name (e.g., "exploit/windows/smb/ms17_010_eternalblue")

        Returns:
            Module information dictionary
        """
        if not self.token:
            raise RuntimeError("Not authenticated. Call connect() first.")

        try:
            # Determine module type
            module_type = module_name.split("/")[0]

            response = self._call(
                f"module.info",
                [self.token, module_type, module_name]
            )

            return response

        except Exception as e:
            self.logger.error(f"Failed to get module info for {module_name}: {e}")
            return None

    def execute_exploit(
        self,
        module_name: str,
        options: Dict[str, Any],
        payload: Optional[str] = None,
        payload_options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute an exploit module

        Args:
            module_name: Exploit module name
            options: Module options (RHOST, RPORT, etc.)
            payload: Payload to use (optional)
            payload_options: Payload options (LHOST, LPORT, etc.)

        Returns:
            Execution result
        """
        if not self.token:
            raise RuntimeError("Not authenticated. Call connect() first.")

        try:
            # Create console
            console = self.create_console()
            console_id = console.get("id")

            if not console_id:
                return {"error": "Failed to create console"}

            # Build command
            cmd = f"use {module_name}\n"

            # Set options
            for key, value in options.items():
                cmd += f"set {key} {value}\n"

            # Set payload if specified
            if payload:
                cmd += f"set PAYLOAD {payload}\n"

                if payload_options:
                    for key, value in payload_options.items():
                        cmd += f"set {key} {value}\n"

            # Execute
            cmd += "exploit -j\n"  # -j for job mode

            # Write commands to console
            self.write_console(console_id, cmd)

            # Wait and read output
            time.sleep(2)
            output = self.read_console(console_id)

            # Clean up console
            self.destroy_console(console_id)

            return {
                "success": True,
                "output": output.get("data", ""),
                "module": module_name,
                "payload": payload,
            }

        except Exception as e:
            self.logger.error(f"Failed to execute exploit: {e}")
            return {
                "success": False,
                "error": str(e),
                "module": module_name,
            }

    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        List active sessions

        Returns:
            List of session dictionaries
        """
        if not self.token:
            raise RuntimeError("Not authenticated. Call connect() first.")

        try:
            response = self._call("session.list", [self.token])
            sessions = []

            for session_id, session_data in response.items():
                sessions.append({
                    "id": session_id,
                    **session_data
                })

            return sessions

        except Exception as e:
            self.logger.error(f"Failed to list sessions: {e}")
            return []

    def interact_session(self, session_id: str, command: str) -> str:
        """
        Execute command in a session

        Args:
            session_id: Session ID
            command: Command to execute

        Returns:
            Command output
        """
        if not self.token:
            raise RuntimeError("Not authenticated. Call connect() first.")

        try:
            # Write command
            self._call("session.shell_write", [self.token, session_id, command + "\n"])

            # Wait for output
            time.sleep(1)

            # Read output
            response = self._call("session.shell_read", [self.token, session_id])

            return response.get("data", "")

        except Exception as e:
            self.logger.error(f"Failed to interact with session {session_id}: {e}")
            return f"Error: {e}"

    def stop_session(self, session_id: str) -> bool:
        """
        Stop/kill a session

        Args:
            session_id: Session ID

        Returns:
            True if stopped successfully
        """
        if not self.token:
            raise RuntimeError("Not authenticated. Call connect() first.")

        try:
            response = self._call("session.stop", [self.token, session_id])
            return response.get("result") == "success"

        except Exception as e:
            self.logger.error(f"Failed to stop session {session_id}: {e}")
            return False

    def create_console(self) -> Dict[str, Any]:
        """Create a new console"""
        if not self.token:
            raise RuntimeError("Not authenticated. Call connect() first.")

        return self._call("console.create", [self.token])

    def destroy_console(self, console_id: str) -> bool:
        """Destroy a console"""
        if not self.token:
            raise RuntimeError("Not authenticated. Call connect() first.")

        try:
            self._call("console.destroy", [self.token, console_id])
            return True
        except Exception:
            return False

    def write_console(self, console_id: str, data: str):
        """Write to console"""
        if not self.token:
            raise RuntimeError("Not authenticated. Call connect() first.")

        return self._call("console.write", [self.token, console_id, data])

    def read_console(self, console_id: str) -> Dict[str, Any]:
        """Read from console"""
        if not self.token:
            raise RuntimeError("Not authenticated. Call connect() first.")

        return self._call("console.read", [self.token, console_id])

    def get_version(self) -> str:
        """Get Metasploit version"""
        try:
            response = self._call("core.version", [])
            return response.get("version", "unknown")
        except Exception as e:
            self.logger.error(f"Failed to get version: {e}")
            return "unknown"

    def _call(self, method: str, params: List[Any]) -> Dict[str, Any]:
        """
        Make RPC call

        Args:
            method: RPC method name
            params: Method parameters

        Returns:
            Response dictionary
        """
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }

        headers = {"Content-Type": "application/json"}

        response = requests.post(
            self.url,
            data=json.dumps(payload),
            headers=headers,
            verify=False,  # For self-signed certs
            timeout=30
        )

        response.raise_for_status()
        result = response.json()

        if "error" in result:
            raise RuntimeError(f"RPC error: {result['error']}")

        return result.get("result", {})

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
