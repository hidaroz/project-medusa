"""
Base class for all pentesting tool wrappers
Provides common functionality for subprocess execution, timeout handling, and error management
"""

import asyncio
import logging
import shutil
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime


logger = logging.getLogger(__name__)


class ToolExecutionError(Exception):
    """Raised when a tool execution fails"""
    pass


class BaseTool(ABC):
    """
    Base class for all pentesting tool wrappers

    Provides:
    - Subprocess execution with timeout
    - Error handling and logging
    - Tool availability checking
    - Structured output parsing
    """

    def __init__(self, timeout: int = 300, tool_name: str = None):
        """
        Initialize tool wrapper

        Args:
            timeout: Maximum execution time in seconds (default: 300)
            tool_name: Name of the tool binary (e.g., 'nmap', 'sqlmap')
        """
        self.timeout = timeout
        self.name = tool_name or self.__class__.__name__
        self.logger = logging.getLogger(f"{__name__}.{self.name}")

    def is_available(self) -> bool:
        """
        Check if the tool is available on the system

        Returns:
            True if tool is installed and accessible, False otherwise
        """
        tool_path = shutil.which(self.tool_binary_name)
        if tool_path:
            self.logger.debug(f"{self.tool_binary_name} found at: {tool_path}")
            return True
        else:
            self.logger.warning(f"{self.tool_binary_name} not found in PATH")
            return False

    @property
    @abstractmethod
    def tool_binary_name(self) -> str:
        """Return the name of the tool binary (e.g., 'nmap', 'sqlmap')"""
        pass

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Execute the tool against a target
        
        Default implementation - subclasses can override or use custom methods.
        Some tools use custom methods (e.g., enumerate_subdomains, validate_servers)
        instead of this generic execute() method.

        Args:
            target: Target IP, URL, or hostname
            **kwargs: Tool-specific arguments

        Returns:
            Dict with structured results including:
                - success: bool
                - findings: List[Dict]
                - raw_output: str
                - duration_seconds: float
                - error: Optional[str]
        
        Raises:
            NotImplementedError: If subclass doesn't implement execute() or custom methods
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} should implement execute() or use custom methods"
        )

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse tool output into structured format

        Args:
            stdout: Standard output from tool
            stderr: Standard error from tool

        Returns:
            List of findings as dictionaries
        """
        pass

    async def _run_command(
        self,
        cmd: List[str],
        input_data: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> Tuple[str, str, int]:
        """
        Run subprocess command with timeout and error handling

        Args:
            cmd: Command and arguments as list
            input_data: Optional stdin data
            env: Optional environment variables

        Returns:
            Tuple of (stdout, stderr, returncode)

        Raises:
            ToolExecutionError: If execution fails or times out
        """
        cmd_str = " ".join(cmd)
        self.logger.info(f"Executing: {cmd_str}")

        try:
            # Create subprocess
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                env=env
            )

            # Execute with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(
                        input=input_data.encode() if input_data else None
                    ),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                # Kill the process on timeout
                try:
                    process.kill()
                    await process.wait()
                except Exception as e:
                    self.logger.error(f"Failed to kill timed-out process: {e}")

                raise ToolExecutionError(
                    f"{self.name} execution timed out after {self.timeout}s"
                )

            # Decode output
            stdout_str = stdout.decode('utf-8', errors='ignore')
            stderr_str = stderr.decode('utf-8', errors='ignore')
            returncode = process.returncode

            self.logger.debug(
                f"Command completed: returncode={returncode}, "
                f"stdout_len={len(stdout_str)}, stderr_len={len(stderr_str)}"
            )

            return stdout_str, stderr_str, returncode

        except FileNotFoundError:
            raise ToolExecutionError(
                f"{self.name} binary not found. Please install {self.tool_binary_name}"
            )
        except PermissionError:
            raise ToolExecutionError(
                f"Permission denied executing {self.name}. Check permissions or run with sudo"
            )
        except Exception as e:
            raise ToolExecutionError(f"{self.name} execution failed: {str(e)}")

    def _sanitize_target(self, target: str) -> str:
        """
        Sanitize target input to prevent command injection

        Args:
            target: User-provided target

        Returns:
            Sanitized target string

        Raises:
            ValueError: If target contains suspicious characters
        """
        # Remove dangerous characters
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '\n', '\r']

        for char in dangerous_chars:
            if char in target:
                raise ValueError(
                    f"Invalid target: contains dangerous character '{char}'"
                )

        # Limit length
        if len(target) > 253:  # Max DNS length
            raise ValueError("Target string too long")

        return target.strip()

    def _create_result_dict(
        self,
        success: bool,
        findings: List[Dict[str, Any]],
        raw_output: str,
        duration: float,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create standardized result dictionary

        Args:
            success: Whether execution succeeded
            findings: List of findings
            raw_output: Raw tool output
            duration: Execution duration in seconds
            error: Optional error message
            metadata: Optional additional metadata

        Returns:
            Standardized result dictionary
        """
        result = {
            "success": success,
            "tool": self.name,
            "findings": findings,
            "findings_count": len(findings),
            "raw_output": raw_output,
            "duration_seconds": round(duration, 2),
            "timestamp": datetime.utcnow().isoformat(),
        }

        if error:
            result["error"] = error

        if metadata:
            result["metadata"] = metadata

        return result
