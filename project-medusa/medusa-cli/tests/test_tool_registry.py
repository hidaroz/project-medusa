"""
Tests for ToolRegistry

Verifies decoupling of agents from tools and lazy instantiation pattern.
"""

import pytest
from unittest.mock import Mock, MagicMock
from src.medusa.core.tool_registry import ToolRegistry, get_global_registry
from src.medusa.tools.base import BaseTool


class MockTool(BaseTool):
    """Mock tool for testing"""

    @property
    def tool_binary_name(self) -> str:
        return "mock_tool"

    def parse_output(self, stdout: str, stderr: str):
        return [{"mock": "data"}]

    async def execute(self, target: str, **kwargs):
        return {
            "success": True,
            "findings": [{"target": target}],
            "raw_output": "mock output",
            "duration_seconds": 0.1
        }


class TestToolRegistry:
    """Test ToolRegistry functionality"""

    def test_registry_initialization(self):
        """Test that registry initializes with default tools"""
        registry = ToolRegistry()

        assert registry is not None
        assert len(registry._tool_classes) > 0
        assert "nmap" in registry._tool_classes
        assert "amass" in registry._tool_classes
        assert "httpx" in registry._tool_classes

    def test_get_tool_lazy_instantiation(self):
        """Test that tools are instantiated lazily"""
        registry = ToolRegistry()

        # Tool should not exist in cache before first call
        assert "nmap" not in registry._tools

        # Get tool (should instantiate)
        nmap = registry.get_tool("nmap")

        # Tool should now exist in cache
        assert "nmap" in registry._tools
        assert nmap is not None

    def test_get_tool_singleton_pattern(self):
        """Test that same tool instance is returned on repeated calls"""
        registry = ToolRegistry()

        nmap1 = registry.get_tool("nmap")
        nmap2 = registry.get_tool("nmap")

        # Should be the exact same instance
        assert nmap1 is nmap2

    def test_get_tool_case_insensitive(self):
        """Test that tool names are case-insensitive"""
        registry = ToolRegistry()

        nmap1 = registry.get_tool("nmap")
        nmap2 = registry.get_tool("NMAP")
        nmap3 = registry.get_tool("Nmap")

        assert nmap1 is nmap2
        assert nmap2 is nmap3

    def test_get_tool_unknown_raises_error(self):
        """Test that unknown tool raises ValueError"""
        registry = ToolRegistry()

        with pytest.raises(ValueError) as exc_info:
            registry.get_tool("unknown_tool_xyz")

        assert "Unknown tool" in str(exc_info.value)
        assert "unknown_tool_xyz" in str(exc_info.value)

    def test_register_custom_tool(self):
        """Test registering a custom tool"""
        registry = ToolRegistry()

        # Register custom tool
        registry.register_tool("custom_tool", MockTool)

        # Should be able to get it
        tool = registry.get_tool("custom_tool")
        assert isinstance(tool, MockTool)

    def test_register_tool_replaces_existing(self):
        """Test that registering a tool replaces existing instance"""
        registry = ToolRegistry()

        # Get original nmap
        original_nmap = registry.get_tool("nmap")

        # Register a replacement
        registry.register_tool("nmap", MockTool)

        # Get new nmap (should be MockTool now)
        new_nmap = registry.get_tool("nmap")

        assert new_nmap is not original_nmap
        assert isinstance(new_nmap, MockTool)

    def test_register_tool_invalid_class_raises_error(self):
        """Test that registering invalid class raises TypeError"""
        registry = ToolRegistry()

        class NotATool:
            pass

        with pytest.raises(TypeError) as exc_info:
            registry.register_tool("invalid", NotATool)

        assert "must inherit from BaseTool" in str(exc_info.value)

    def test_is_tool_available(self):
        """Test checking tool availability"""
        registry = ToolRegistry()

        # Register mock tool
        registry.register_tool("mock_tool", MockTool)

        # Check availability (will depend on whether mock_tool binary exists)
        # This tests the method works, actual result depends on system
        result = registry.is_tool_available("mock_tool")
        assert isinstance(result, bool)

    def test_list_available_tools(self):
        """Test listing all tools and their availability"""
        registry = ToolRegistry()

        availability = registry.list_available_tools()

        assert isinstance(availability, dict)
        assert "nmap" in availability
        assert "amass" in availability
        assert isinstance(availability["nmap"], bool)

    def test_clear_cache(self):
        """Test clearing cached tool instances"""
        registry = ToolRegistry()

        # Get some tools (cache them)
        nmap1 = registry.get_tool("nmap")
        amass1 = registry.get_tool("amass")

        assert len(registry._tools) == 2

        # Clear cache
        registry.clear_cache()

        assert len(registry._tools) == 0

        # Get tools again (should create new instances)
        nmap2 = registry.get_tool("nmap")
        amass2 = registry.get_tool("amass")

        # Should be different instances
        assert nmap2 is not nmap1
        assert amass2 is not amass1

    def test_global_registry_singleton(self):
        """Test that global registry is a singleton"""
        registry1 = get_global_registry()
        registry2 = get_global_registry()

        assert registry1 is registry2


class TestAgentToolIntegration:
    """Test agents using ToolRegistry"""

    @pytest.mark.asyncio
    async def test_reconnaissance_agent_with_registry(self):
        """Test ReconnaissanceAgent uses ToolRegistry"""
        from src.medusa.agents.reconnaissance_agent import ReconnaissanceAgent

        # Create registry with mock tool
        registry = ToolRegistry()

        # Create agent with registry
        agent = ReconnaissanceAgent(
            tool_registry=registry,
            name="TestRecon",
            llm_client=Mock(),
            context_engine=None
        )

        # Agent should have tools attribute
        assert hasattr(agent, 'tools')
        assert agent.tools is registry

    @pytest.mark.asyncio
    async def test_vulnerability_agent_with_registry(self):
        """Test VulnerabilityAnalysisAgent uses ToolRegistry"""
        from src.medusa.agents.vulnerability_analysis_agent import VulnerabilityAnalysisAgent

        registry = ToolRegistry()

        agent = VulnerabilityAnalysisAgent(
            tool_registry=registry,
            name="TestVulnAnalysis",
            llm_client=Mock(),
            context_engine=None
        )

        assert hasattr(agent, 'tools')
        assert agent.tools is registry

    @pytest.mark.asyncio
    async def test_exploitation_agent_with_registry(self):
        """Test ExploitationAgent uses ToolRegistry"""
        from src.medusa.agents.exploitation_agent import ExploitationAgent

        registry = ToolRegistry()

        agent = ExploitationAgent(
            require_approval=False,
            tool_registry=registry,
            llm_client=Mock()
        )

        assert hasattr(agent, 'tools')
        assert agent.tools is registry

    @pytest.mark.asyncio
    async def test_agent_without_registry_creates_own(self):
        """Test that agents create their own registry if none provided"""
        from src.medusa.agents.reconnaissance_agent import ReconnaissanceAgent

        agent = ReconnaissanceAgent(
            name="TestRecon",
            llm_client=Mock(),
            context_engine=None
        )

        # Should have created its own registry
        assert hasattr(agent, 'tools')
        assert isinstance(agent.tools, ToolRegistry)
