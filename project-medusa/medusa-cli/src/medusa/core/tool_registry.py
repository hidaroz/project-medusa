"""
Tool Registry

Provides centralized tool management with lazy instantiation.
Decouples agents from direct tool dependencies, enabling easier testing and configuration.
"""

from typing import Dict, Optional, Type
import logging
from ..tools.base import BaseTool


logger = logging.getLogger(__name__)


class ToolRegistry:
    """
    Registry for managing tool instances with lazy instantiation.

    Benefits:
    - Decouples agents from tool implementations
    - Enables singleton pattern per tool (instantiated once, reused)
    - Simplifies mocking for testing
    - Allows future configuration-based tool swapping

    Example:
        registry = ToolRegistry()
        nmap = registry.get_tool("nmap")
        result = await nmap.quick_scan("192.168.1.1")
    """

    def __init__(self):
        """Initialize the tool registry with empty cache."""
        self._tools: Dict[str, BaseTool] = {}
        self._tool_classes: Dict[str, Type[BaseTool]] = {}
        self.logger = logging.getLogger(__name__)
        self._register_default_tools()

    def _register_default_tools(self):
        """Register all available tools with their classes."""
        # Import tools locally to avoid circular dependencies
        from ..tools.nmap import NmapScanner
        from ..tools.amass import AmassScanner
        from ..tools.httpx_scanner import HttpxScanner
        from ..tools.web_scanner import WebScanner
        from ..tools.metasploit import MetasploitClient
        from ..tools.sql_injection import SQLInjectionTester
        from ..tools.kerbrute import KerbruteScanner

        # Register tool mappings
        self._tool_classes = {
            "nmap": NmapScanner,
            "amass": AmassScanner,
            "httpx": HttpxScanner,
            "web_scanner": WebScanner,
            "metasploit": MetasploitClient,
            "sqlmap": SQLInjectionTester,
            "kerbrute": KerbruteScanner,
        }

        self.logger.debug(f"Registered {len(self._tool_classes)} tool types")

    def get_tool(self, tool_name: str) -> BaseTool:
        """
        Get a tool instance by name (lazy instantiation).

        Args:
            tool_name: Name of the tool (e.g., "nmap", "amass", "httpx")

        Returns:
            Tool instance (singleton per tool type)

        Raises:
            ValueError: If tool_name is not registered

        Example:
            nmap = registry.get_tool("nmap")
            amass = registry.get_tool("amass")
        """
        # Normalize tool name
        tool_name = tool_name.lower().strip()

        # Return cached instance if exists
        if tool_name in self._tools:
            self.logger.debug(f"Returning cached instance of '{tool_name}'")
            return self._tools[tool_name]

        # Check if tool class is registered
        if tool_name not in self._tool_classes:
            available = ", ".join(self._tool_classes.keys())
            raise ValueError(
                f"Unknown tool '{tool_name}'. Available tools: {available}"
            )

        # Instantiate and cache
        tool_class = self._tool_classes[tool_name]
        self.logger.info(f"Instantiating new '{tool_name}' tool")
        tool_instance = tool_class()
        self._tools[tool_name] = tool_instance

        return tool_instance

    def register_tool(self, tool_name: str, tool_class: Type[BaseTool]) -> None:
        """
        Register a custom tool class.

        Args:
            tool_name: Name to register the tool under
            tool_class: Tool class (must inherit from BaseTool)

        Raises:
            TypeError: If tool_class doesn't inherit from BaseTool

        Example:
            registry.register_tool("custom_scanner", MyCustomScanner)
        """
        if not issubclass(tool_class, BaseTool):
            raise TypeError(
                f"Tool class must inherit from BaseTool, got {tool_class}"
            )

        tool_name = tool_name.lower().strip()
        self._tool_classes[tool_name] = tool_class

        # Invalidate cache if tool was previously instantiated
        if tool_name in self._tools:
            self.logger.warning(
                f"Replacing existing instance of '{tool_name}' with new class"
            )
            del self._tools[tool_name]

        self.logger.info(f"Registered custom tool: '{tool_name}'")

    def is_tool_available(self, tool_name: str) -> bool:
        """
        Check if a tool is available on the system.

        Args:
            tool_name: Name of the tool

        Returns:
            True if tool is installed and accessible, False otherwise

        Example:
            if registry.is_tool_available("nmap"):
                nmap = registry.get_tool("nmap")
        """
        try:
            tool = self.get_tool(tool_name)
            return tool.is_available()
        except (ValueError, Exception) as e:
            self.logger.debug(f"Tool '{tool_name}' not available: {e}")
            return False

    def list_available_tools(self) -> Dict[str, bool]:
        """
        List all registered tools and their availability status.

        Returns:
            Dictionary mapping tool names to availability (True/False)

        Example:
            tools = registry.list_available_tools()
            # {"nmap": True, "amass": False, ...}
        """
        availability = {}
        for tool_name in self._tool_classes.keys():
            availability[tool_name] = self.is_tool_available(tool_name)

        return availability

    def clear_cache(self):
        """
        Clear all cached tool instances.

        Useful for testing or when tool configuration changes.
        """
        count = len(self._tools)
        self._tools.clear()
        self.logger.info(f"Cleared {count} cached tool instances")


# Global registry instance (optional convenience)
_global_registry: Optional[ToolRegistry] = None


def get_global_registry() -> ToolRegistry:
    """
    Get the global tool registry singleton.

    Returns:
        Global ToolRegistry instance

    Example:
        from medusa.core.tool_registry import get_global_registry

        registry = get_global_registry()
        nmap = registry.get_tool("nmap")
    """
    global _global_registry
    if _global_registry is None:
        _global_registry = ToolRegistry()
    return _global_registry