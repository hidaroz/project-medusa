"""
Tool Registry Usage Examples

Demonstrates how to use ToolRegistry for testing and production.
"""

import asyncio
from typing import Dict, Any, List
from src.medusa.core.tool_registry import ToolRegistry, get_global_registry
from src.medusa.tools.base import BaseTool
from src.medusa.agents.reconnaissance_agent import ReconnaissanceAgent
from unittest.mock import Mock


# Example 1: Basic ToolRegistry Usage
async def example_basic_usage():
    """Basic tool registry usage"""
    print("=== Example 1: Basic Usage ===")

    # Create registry
    registry = ToolRegistry()

    # Get tools (lazy instantiation)
    nmap = registry.get_tool("nmap")
    print(f"Got nmap tool: {nmap.__class__.__name__}")

    # Check if tool is available on system
    is_available = registry.is_tool_available("nmap")
    print(f"Nmap available: {is_available}")

    # List all available tools
    all_tools = registry.list_available_tools()
    print(f"Available tools: {all_tools}")


# Example 2: Custom Mock Tool for Testing
class MockNmapScanner(BaseTool):
    """Mock Nmap scanner for testing"""

    @property
    def tool_binary_name(self) -> str:
        return "nmap"

    def parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        return [{"port": 80, "service": "http", "state": "open"}]

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Simulated nmap scan"""
        return {
            "success": True,
            "findings": [
                {"port": 80, "service": "http", "state": "open"},
                {"port": 443, "service": "https", "state": "open"},
            ],
            "raw_output": "Simulated nmap output",
            "duration_seconds": 0.1
        }

    async def quick_scan(self, target: str) -> Dict[str, Any]:
        """Simulated quick scan"""
        return await self.execute(target)


async def example_custom_tool():
    """Using custom/mock tools"""
    print("\n=== Example 2: Custom Mock Tool ===")

    # Create registry and register mock
    registry = ToolRegistry()
    registry.register_tool("nmap", MockNmapScanner)

    # Get and use mock tool
    nmap = registry.get_tool("nmap")
    result = await nmap.execute("192.168.1.1")

    print(f"Mock scan result: {result['success']}")
    print(f"Findings: {len(result['findings'])} ports found")
    print(f"Duration: {result['duration_seconds']}s")


# Example 3: Using Registry with Agents
async def example_agent_with_registry():
    """Agent using custom registry for testing"""
    print("\n=== Example 3: Agent with Custom Registry ===")

    # Create registry with mock tools
    registry = ToolRegistry()
    registry.register_tool("nmap", MockNmapScanner)

    # Create mock LLM client
    mock_llm = Mock()
    mock_llm.generate = Mock(return_value={
        'text': 'Reconnaissance strategy',
        'tokens_used': 100
    })

    # Create agent with custom registry
    agent = ReconnaissanceAgent(
        tool_registry=registry,
        name="TestReconAgent",
        llm_client=mock_llm,
        context_engine=None
    )

    print(f"Agent created with custom registry: {agent.name}")
    print(f"Agent tools: {agent.tools}")

    # Agent will use mock tools when executing tasks
    print("Agent will use MockNmapScanner instead of real nmap")


# Example 4: Shared Registry Across Agents
async def example_shared_registry():
    """Multiple agents sharing same registry"""
    print("\n=== Example 4: Shared Registry ===")

    # Create single registry
    registry = ToolRegistry()

    # Mock LLM
    mock_llm = Mock()

    # Create multiple agents sharing registry
    from src.medusa.agents.vulnerability_analysis_agent import VulnerabilityAnalysisAgent

    recon_agent = ReconnaissanceAgent(
        tool_registry=registry,
        name="ReconAgent",
        llm_client=mock_llm,
        context_engine=None
    )

    vuln_agent = VulnerabilityAnalysisAgent(
        tool_registry=registry,
        name="VulnAgent",
        llm_client=mock_llm,
        context_engine=None
    )

    # Both agents share same registry
    print(f"Recon registry: {id(recon_agent.tools)}")
    print(f"Vuln registry: {id(vuln_agent.tools)}")
    print(f"Same registry: {recon_agent.tools is vuln_agent.tools}")

    # Getting same tool from both agents returns same instance
    nmap1 = recon_agent.tools.get_tool("nmap")
    nmap2 = vuln_agent.tools.get_tool("nmap")
    print(f"Same nmap instance: {nmap1 is nmap2}")


# Example 5: Global Registry
async def example_global_registry():
    """Using global singleton registry"""
    print("\n=== Example 5: Global Registry ===")

    # Get global registry
    registry1 = get_global_registry()
    registry2 = get_global_registry()

    print(f"Registry 1 ID: {id(registry1)}")
    print(f"Registry 2 ID: {id(registry2)}")
    print(f"Same instance: {registry1 is registry2}")

    # All agents can use global registry
    mock_llm = Mock()
    agent = ReconnaissanceAgent(
        tool_registry=registry1,
        name="GlobalReconAgent",
        llm_client=mock_llm,
        context_engine=None
    )

    print(f"Agent using global registry: {agent.tools is registry1}")


# Example 6: Testing Pattern
async def example_testing_pattern():
    """Recommended pattern for testing agents"""
    print("\n=== Example 6: Testing Pattern ===")

    # 1. Create registry with mocks
    test_registry = ToolRegistry()
    test_registry.register_tool("nmap", MockNmapScanner)

    # 2. Create mock LLM
    mock_llm = Mock()

    # 3. Create agent with test dependencies
    agent = ReconnaissanceAgent(
        tool_registry=test_registry,
        name="TestAgent",
        llm_client=mock_llm,
        context_engine=None
    )

    # 4. Agent methods will use mock tools
    print("Agent configured for testing")
    print("All tools are mocked")
    print("No real scans will be executed")

    # 5. Clean up if needed
    test_registry.clear_cache()
    print("Registry cache cleared")


# Example 7: Dynamic Tool Switching
async def example_dynamic_switching():
    """Switching tools at runtime"""
    print("\n=== Example 7: Dynamic Tool Switching ===")

    registry = ToolRegistry()

    # Get real nmap
    nmap_real = registry.get_tool("nmap")
    print(f"Real tool: {nmap_real.__class__.__name__}")

    # Switch to mock
    registry.register_tool("nmap", MockNmapScanner)
    nmap_mock = registry.get_tool("nmap")
    print(f"Mock tool: {nmap_mock.__class__.__name__}")

    # Note: Different instances
    print(f"Different instances: {nmap_real is not nmap_mock}")


# Example 8: Tool Availability Checking
async def example_availability_checking():
    """Check which tools are available before using"""
    print("\n=== Example 8: Availability Checking ===")

    registry = ToolRegistry()

    # Check specific tool
    if registry.is_tool_available("nmap"):
        nmap = registry.get_tool("nmap")
        print("Nmap is available and ready to use")
    else:
        print("Nmap is not installed on this system")

    # Get all available tools
    available = registry.list_available_tools()
    print("\nAll tools:")
    for tool_name, is_available in available.items():
        status = "✓" if is_available else "✗"
        print(f"  {status} {tool_name}")


# Main execution
async def main():
    """Run all examples"""
    print("=" * 60)
    print("Tool Registry Examples")
    print("=" * 60)

    await example_basic_usage()
    await example_custom_tool()
    await example_agent_with_registry()
    await example_shared_registry()
    await example_global_registry()
    await example_testing_pattern()
    await example_dynamic_switching()
    await example_availability_checking()

    print("\n" + "=" * 60)
    print("All examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
