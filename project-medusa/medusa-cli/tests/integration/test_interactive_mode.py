"""
Integration tests for Interactive Mode
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from medusa.modes.interactive import InteractiveMode
from medusa.command_parser import CommandParser
from medusa.session import Session, CommandSuggester
from medusa.completers import CommandAliasManager
from medusa.core.llm import MockLLMClient, LLMConfig


@pytest.fixture
def interactive_mode():
    """Create interactive mode instance"""
    return InteractiveMode(target="http://localhost:3001", api_key="test")


@pytest.fixture
def mock_llm():
    """Create mock LLM client"""
    config = LLMConfig(api_key="test", mock_mode=True)
    return MockLLMClient(config)


def test_interactive_mode_initialization(interactive_mode):
    """Test interactive mode initializes correctly"""
    assert interactive_mode.target == "http://localhost:3001"
    assert interactive_mode.api_key == "test"
    assert interactive_mode.session is not None
    assert interactive_mode.command_suggester is not None
    assert interactive_mode.alias_manager is not None


def test_session_creation(interactive_mode):
    """Test session is created with correct data"""
    session = interactive_mode.session
    assert session.target == "http://localhost:3001"
    assert session.context["phase"] == "reconnaissance"
    assert len(session.findings) == 0
    assert len(session.command_history) == 0


def test_alias_manager(interactive_mode):
    """Test alias manager works"""
    alias_mgr = interactive_mode.alias_manager

    # Test built-in aliases
    assert "s" in alias_mgr.aliases
    assert alias_mgr.resolve("s") == "scan for open ports"

    # Test custom alias
    alias_mgr.add_alias("test", "test command")
    assert alias_mgr.resolve("test") == "test command"

    # Test alias removal
    alias_mgr.remove_alias("test")
    assert "test" not in alias_mgr.aliases


def test_command_suggester():
    """Test command suggester provides relevant suggestions"""
    suggester = CommandSuggester()

    # Test reconnaissance phase suggestions
    context = {"phase": "reconnaissance", "findings": []}
    suggestions = suggester.get_suggestions(context)

    assert len(suggestions) > 0
    assert any("scan" in s.lower() for s in suggestions)


def test_session_export_integration(interactive_mode, tmp_path):
    """Test session can be exported"""
    session = interactive_mode.session

    # Add some test data
    session.add_command("test command", {"status": "success"})
    session.add_finding({
        "type": "vulnerability",
        "severity": "high",
        "title": "Test Vulnerability"
    })

    # Export session
    filepath = session.save(directory=str(tmp_path))
    assert filepath.exists()

    # Load session back
    loaded_session = Session.load(filepath)
    assert loaded_session.target == session.target
    assert len(loaded_session.command_history) == 1
    assert len(loaded_session.findings) == 1


@pytest.mark.asyncio
async def test_command_parser_integration(mock_llm):
    """Test command parser can parse commands"""
    parser = CommandParser(mock_llm, target="http://localhost:3001")

    # Test parsing a command
    result = await parser.parse("scan for open ports")

    assert "action" in result
    assert "confidence" in result
    assert result["action"] == "port_scan"
    assert result["confidence"] > 0.5


@pytest.mark.asyncio
async def test_command_parser_context(mock_llm):
    """Test command parser maintains context"""
    parser = CommandParser(mock_llm, target="http://localhost:3001")

    # Parse first command
    await parser.parse("scan for open ports")

    # Check context updated
    context = parser.get_context()
    assert context["last_action"] == "port_scan"
    assert context["phase"] == "reconnaissance"

    # Check history
    history = parser.get_command_history()
    assert len(history) == 1


def test_phase_transitions():
    """Test phase transition recommendations"""
    suggester = CommandSuggester()

    # Not enough findings for transition
    suggestion = suggester.get_next_phase_suggestion("reconnaissance", 1)
    assert suggestion is None

    # Enough findings for transition
    suggestion = suggester.get_next_phase_suggestion("reconnaissance", 5)
    assert suggestion is not None
    assert "enumeration" in suggestion.lower()


def test_alias_resolution_chain(interactive_mode):
    """Test alias resolution works correctly"""
    alias_mgr = interactive_mode.alias_manager

    # Test direct alias
    result = alias_mgr.resolve("s")
    assert result == "scan for open ports"

    # Test non-alias
    result = alias_mgr.resolve("some random command")
    assert result == "some random command"

    # Test alias with additional text
    result = alias_mgr.resolve("scan with version detection")
    assert "scan for open ports" in result


@pytest.mark.asyncio
async def test_end_to_end_command_flow(mock_llm):
    """Test end-to-end command parsing and execution flow"""
    # Create parser
    parser = CommandParser(mock_llm, target="http://localhost:3001")

    # Create session
    session = Session(target="http://localhost:3001")

    # Parse command
    parsed = await parser.parse("scan for open ports")
    assert parsed["action"] == "port_scan"

    # Add to session history
    session.add_command("scan for open ports", {"status": "success", "findings": []})

    # Check session state
    assert len(session.command_history) == 1
    assert session.command_history[0]["command"] == "scan for open ports"

    # Get suggestions based on session
    suggester = CommandSuggester()
    suggestions = suggester.get_suggestions(session.context)
    assert len(suggestions) > 0


@pytest.mark.asyncio
async def test_multiple_command_sequence(mock_llm):
    """Test sequence of commands maintains state"""
    parser = CommandParser(mock_llm, target="http://localhost:3001")
    session = Session(target="http://localhost:3001")

    # Command sequence
    commands = [
        "scan for open ports",
        "enumerate services",
        "find vulnerabilities"
    ]

    for cmd in commands:
        parsed = await parser.parse(cmd)
        session.add_command(cmd, {"status": "success"})

    # Verify all commands recorded
    assert len(session.command_history) == 3

    # Verify phase progression
    context = parser.get_context()
    assert context["last_action"] in ["port_scan", "enumerate_services", "scan_vulnerabilities"]


def test_alias_manager_advanced():
    """Test advanced alias manager features"""
    alias_mgr = CommandAliasManager()

    # Test getting aliases for command
    aliases = alias_mgr.get_alias_for_command("scan for open ports")
    assert "s" in aliases
    assert "scan" in aliases

    # Test list all aliases
    all_aliases = alias_mgr.list_aliases()
    assert len(all_aliases) > 10  # Should have many built-in aliases
