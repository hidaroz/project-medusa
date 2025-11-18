"""
MEDUSA Real Tool Integration Module
Provides wrappers for actual penetration testing tools
"""

from .base import BaseTool, ToolExecutionError
from .nmap import NmapScanner
from .web_scanner import WebScanner
from .amass import AmassScanner
from .httpx_scanner import HttpxScanner
from .kerbrute import KerbruteScanner
from .sql_injection import SQLMapScanner
from .metasploit import MetasploitClient

__all__ = [
    "BaseTool",
    "ToolExecutionError",
    "NmapScanner",
    "WebScanner",
    "AmassScanner",
    "HttpxScanner",
    "KerbruteScanner",
    "SQLMapScanner",
    "MetasploitClient",
]
