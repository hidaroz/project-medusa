"""
Unit tests for Session and CommandSuggester
"""

import pytest
import os
import json
from pathlib import Path
from medusa.session import Session, CommandSuggester


@pytest.fixture
def session():
    """Create test session"""
    return Session(target="http://localhost:3001")


@pytest.fixture
def suggester():
    """Create command suggester"""
    return CommandSuggester()


def test_session_initialization(session):
    """Test session initialization"""
    assert session.target == "http://localhost:3001"
    assert session.session_id.startswith("session_")
    assert session.context["target"] == "http://localhost:3001"
    assert session.context["phase"] == "reconnaissance"


def test_add_command(session):
    """Test adding command to history"""
    session.add_command("scan for ports", {"status": "complete"})

    assert len(session.command_history) == 1
    assert session.command_history[0]["command"] == "scan for ports"
    assert session.command_history[0]["result"]["status"] == "complete"


def test_add_finding(session):
    """Test adding finding"""
    finding = {
        "type": "vulnerability",
        "severity": "high",
        "title": "SQL Injection"
    }

    session.add_finding(finding)

    assert len(session.findings) == 1
    assert session.findings[0]["title"] == "SQL Injection"
    assert "timestamp" in session.findings[0]


def test_add_technique(session):
    """Test adding MITRE technique"""
    session.add_technique("T1046", "Network Service Discovery")

    techniques = session.context["techniques_used"]
    assert len(techniques) == 1
    assert techniques[0]["id"] == "T1046"
    assert techniques[0]["name"] == "Network Service Discovery"


def test_update_context(session):
    """Test context updates"""
    session.update_context({"custom_field": "value"})

    assert session.context["custom_field"] == "value"


def test_update_phase(session):
    """Test phase updates"""
    session.update_phase("enumeration")

    assert session.context["phase"] == "enumeration"


def test_get_findings_by_severity(session):
    """Test filtering findings by severity"""
    session.add_finding({"severity": "high", "type": "vuln1"})
    session.add_finding({"severity": "medium", "type": "vuln2"})
    session.add_finding({"severity": "high", "type": "vuln3"})

    high_findings = session.get_findings_by_severity("high")
    assert len(high_findings) == 2


def test_get_findings_by_type(session):
    """Test filtering findings by type"""
    session.add_finding({"type": "vulnerability", "severity": "high"})
    session.add_finding({"type": "open_port", "port": 80})
    session.add_finding({"type": "vulnerability", "severity": "medium"})

    vulns = session.get_findings_by_type("vulnerability")
    assert len(vulns) == 2


def test_session_summary(session):
    """Test session summary generation"""
    session.add_command("cmd1", {})
    session.add_command("cmd2", {})
    session.add_finding({"type": "vulnerability", "severity": "high"})
    session.add_finding({"type": "vulnerability", "severity": "medium"})
    session.add_technique("T1046", "Network Service Discovery")

    summary = session.get_summary()

    assert summary["commands_executed"] == 2
    assert summary["total_findings"] == 2
    assert summary["severity_counts"]["high"] == 1
    assert summary["severity_counts"]["medium"] == 1
    assert summary["techniques_used"] == 1


def test_session_save_and_load(session, tmp_path):
    """Test saving and loading session"""
    # Add some data
    session.add_command("test command", {"result": "ok"})
    session.add_finding({"type": "vulnerability", "severity": "high"})

    # Save session
    filepath = session.save(directory=str(tmp_path))

    assert os.path.exists(filepath)

    # Load session
    loaded_session = Session.load(filepath)

    assert loaded_session.target == session.target
    assert len(loaded_session.command_history) == 1
    assert len(loaded_session.findings) == 1


def test_list_sessions(tmp_path):
    """Test listing available sessions"""
    # Create multiple sessions
    session1 = Session(target="target1")
    session2 = Session(target="target2")

    session1.save(directory=str(tmp_path))
    session2.save(directory=str(tmp_path))

    # List sessions
    sessions = Session.list_sessions(directory=str(tmp_path))

    assert len(sessions) >= 2
    assert all("session_id" in s for s in sessions)
    assert all("target" in s for s in sessions)


def test_suggester_reconnaissance_phase(suggester):
    """Test suggestions for reconnaissance phase"""
    context = {
        "phase": "reconnaissance",
        "findings": []
    }

    suggestions = suggester.get_suggestions(context)

    assert len(suggestions) > 0
    assert any("scan" in s.lower() or "enumerate" in s.lower() for s in suggestions)


def test_suggester_enumeration_phase(suggester):
    """Test suggestions for enumeration phase"""
    context = {
        "phase": "enumeration",
        "findings": [
            {"service": "http", "type": "webapp"}
        ]
    }

    suggestions = suggester.get_suggestions(context)

    assert len(suggestions) > 0


def test_suggester_finding_based(suggester):
    """Test finding-based suggestions"""
    context = {
        "phase": "vulnerability_scan",
        "findings": [
            {"type": "vulnerability", "title": "SQL Injection"}
        ]
    }

    suggestions = suggester.get_suggestions(context)

    # Should suggest SQL-related actions
    assert any("sql" in s.lower() for s in suggestions)


def test_suggester_phase_transition(suggester):
    """Test phase transition suggestions"""
    # Not enough findings
    suggestion = suggester.get_next_phase_suggestion("reconnaissance", 1)
    assert suggestion is None

    # Enough findings to transition
    suggestion = suggester.get_next_phase_suggestion("reconnaissance", 5)
    assert suggestion is not None
    assert "enumeration" in suggestion
