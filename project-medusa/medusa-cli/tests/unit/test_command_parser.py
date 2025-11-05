"""
Unit tests for CommandParser
"""

import pytest
from medusa.command_parser import CommandParser
from medusa.core.llm import MockLLMClient, LLMConfig


@pytest.fixture
def mock_llm():
    """Create mock LLM client"""
    config = LLMConfig(api_key="test", mock_mode=True)
    return MockLLMClient(config)


@pytest.fixture
def parser(mock_llm):
    """Create command parser with mock LLM"""
    return CommandParser(mock_llm, target="http://localhost:3001")


@pytest.mark.asyncio
async def test_parse_port_scan_command(parser):
    """Test parsing port scan command"""
    result = await parser.parse("scan for open ports")

    assert result["action"] == "port_scan"
    assert result["confidence"] > 0.5
    assert "target" in result


@pytest.mark.asyncio
async def test_parse_enumerate_command(parser):
    """Test parsing enumerate command"""
    result = await parser.parse("enumerate API endpoints")

    assert result["action"] == "enumerate_services"
    assert result["confidence"] > 0.5


@pytest.mark.asyncio
async def test_parse_sqli_command(parser):
    """Test parsing SQL injection test command"""
    result = await parser.parse("test for SQL injection")

    assert result["action"] == "sqli_test"
    assert result["needs_approval"] == True
    assert result["confidence"] > 0.5


@pytest.mark.asyncio
async def test_parse_show_findings_command(parser):
    """Test parsing show findings command"""
    result = await parser.parse("show findings")

    assert result["action"] in ["show_findings", "unknown"]


@pytest.mark.asyncio
async def test_parse_unclear_command(parser):
    """Test parsing unclear command"""
    result = await parser.parse("do something weird")

    # Should have low confidence or unknown action
    assert result["confidence"] < 0.8 or result["action"] == "unknown"


@pytest.mark.asyncio
async def test_command_history(parser):
    """Test command history tracking"""
    await parser.parse("scan for open ports")
    await parser.parse("enumerate services")

    history = parser.get_command_history()
    assert len(history) == 2
    assert history[0]["input"] == "scan for open ports"
    assert history[1]["input"] == "enumerate services"


@pytest.mark.asyncio
async def test_context_update(parser):
    """Test context updates"""
    await parser.parse("scan for open ports")

    context = parser.get_context()
    assert context["last_action"] == "port_scan"
    assert context["phase"] == "reconnaissance"


@pytest.mark.asyncio
async def test_add_finding(parser):
    """Test adding findings to context"""
    finding = {
        "type": "vulnerability",
        "severity": "high",
        "title": "Test Vulnerability"
    }

    parser.add_finding(finding)

    context = parser.get_context()
    assert len(context["findings"]) == 1
    assert context["findings"][0]["finding"] == finding
