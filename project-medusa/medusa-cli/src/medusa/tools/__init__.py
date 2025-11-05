"""
MEDUSA Real Tool Integration Module
Provides wrappers for actual penetration testing tools
"""

from .base import BaseTool, ToolExecutionError
from .nmap import NmapScanner
from .web_scanner import WebScanner

__all__ = [
    "BaseTool",
    "ToolExecutionError",
    "NmapScanner",
    "WebScanner",
]
