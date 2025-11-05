"""
Shared pytest fixtures and test configuration for MEDUSA.

This file contains:
- Mock clients and configurations
- Reusable test data
- Test utilities
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, AsyncMock
from typing import Dict, Any, List


# ============================================================================
# PYTEST CONFIGURATION
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )


# ============================================================================
# TEMPORARY FILE FIXTURES
# ============================================================================

@pytest.fixture
def temp_dir():
    """Provide a temporary directory that's cleaned up after test."""
    temp = tempfile.mkdtemp()
    yield Path(temp)
    import shutil
    shutil.rmtree(temp)


@pytest.fixture
def temp_config_file(temp_dir):
    """Create a temporary config file."""
    config_path = temp_dir / "config.yaml"
    config_path.write_text("""
target: "192.168.1.100"
mode: "autonomous"
llm:
  provider: "local"
  model: "mistral:7b-instruct"
tools:
  nmap:
    enabled: true
  web_scanner:
    enabled: true
  sql_injection:
    enabled: true
""")
    return config_path


# ============================================================================
# MOCK CLIENT FIXTURES
# ============================================================================

@pytest.fixture
def mock_llm_client():
    """Mock LLM client for testing without API calls."""
    client = AsyncMock()
    
    # Mock reconnaissance recommendation
    client.get_reconnaissance_recommendation = AsyncMock(return_value={
        "recommended_actions": [
            {"action": "port_scan", "priority": "HIGH", "target": "10.0.0.1"}
        ],
        "risk_assessment": "LOW",
        "reasoning": "Initial reconnaissance to identify open ports"
    })
    
    # Mock enumeration strategy
    client.get_enumeration_strategy = AsyncMock(return_value={
        "enumeration_actions": [
            {"action": "service_detection", "priority": "HIGH"}
        ],
        "risk_assessment": "LOW"
    })
    
    # Mock vulnerability assessment
    client.assess_vulnerability_risk = AsyncMock(return_value="MEDIUM")
    
    # Mock exploitation decision
    client.should_attempt_exploitation = AsyncMock(return_value=False)
    
    # Mock report generation suggestions
    client.generate_report_summary = AsyncMock(return_value={
        "executive_summary": "Scan completed with 3 findings",
        "key_insights": ["Port 80 open", "Web server detected"],
        "recommendations": ["Apply security patches"]
    })
    
    return client


@pytest.fixture
def mock_nmap_client():
    """Mock Nmap tool client."""
    client = AsyncMock()
    client.execute = AsyncMock(return_value={
        "findings": [
            {"port": 22, "service": "ssh", "state": "open"},
            {"port": 80, "service": "http", "state": "open"},
            {"port": 443, "service": "https", "state": "open"}
        ],
        "findings_count": 3,
        "duration": 15.2
    })
    return client


@pytest.fixture
def mock_web_scanner():
    """Mock Web Scanner tool client."""
    client = AsyncMock()
    client.execute = AsyncMock(return_value={
        "findings": [
            {
                "type": "technology",
                "name": "nginx",
                "version": "1.20.1",
                "confidence": 0.95
            },
            {
                "type": "technology",
                "name": "PHP",
                "version": "8.0",
                "confidence": 0.90
            }
        ],
        "findings_count": 2,
        "duration": 8.5
    })
    return client


@pytest.fixture
def mock_medusa_client(mock_llm_client, mock_nmap_client, mock_web_scanner):
    """Mock MedusaClient with all components."""
    from unittest.mock import MagicMock
    
    client = MagicMock()
    client.llm = mock_llm_client
    client.nmap = mock_nmap_client
    client.web_scanner = mock_web_scanner
    client.sql_injection = AsyncMock()
    client.web_vuln = AsyncMock()
    client.logger = MagicMock()
    
    return client


# ============================================================================
# TEST DATA FIXTURES
# ============================================================================

@pytest.fixture
def mock_scan_results() -> Dict[str, Any]:
    """Typical reconnaissance scan results."""
    return {
        "target": "192.168.1.100",
        "scan_type": "nmap",
        "ports": [
            {"port": 22, "service": "ssh", "state": "open", "version": "OpenSSH 7.4"},
            {"port": 80, "service": "http", "state": "open", "version": "Apache/2.4.6"},
            {"port": 443, "service": "https", "state": "open", "version": "Apache/2.4.6"},
            {"port": 3306, "service": "mysql", "state": "open"},
        ],
        "os": "Linux",
        "os_accuracy": 95,
        "scan_time": 42.5
    }


@pytest.fixture
def mock_web_vulnerabilities() -> List[Dict[str, Any]]:
    """Mock web vulnerabilities from scanner."""
    return [
        {
            "type": "vulnerability",
            "name": "SQL Injection",
            "severity": "HIGH",
            "cvss": 9.8,
            "url": "http://192.168.1.100/search.php?q=",
            "parameter": "q",
            "description": "Unvalidated user input in search parameter"
        },
        {
            "type": "vulnerability",
            "name": "Cross-Site Scripting (XSS)",
            "severity": "MEDIUM",
            "cvss": 6.1,
            "url": "http://192.168.1.100/comment.php",
            "description": "HTML input not properly escaped"
        },
        {
            "type": "information_disclosure",
            "name": "Server Header Information",
            "severity": "LOW",
            "description": "Server version exposed in HTTP headers"
        }
    ]


@pytest.fixture
def mock_findings_complete() -> Dict[str, Any]:
    """Complete findings from full scan."""
    return {
        "target": "192.168.1.100",
        "scan_phases": ["reconnaissance", "enumeration", "vulnerability_scan"],
        "findings": [
            {
                "phase": "reconnaissance",
                "findings": [
                    {"port": 22, "service": "ssh"},
                    {"port": 80, "service": "http"},
                ]
            },
            {
                "phase": "enumeration",
                "findings": [
                    {"technology": "nginx", "version": "1.20.1"},
                    {"technology": "PHP", "version": "8.0"},
                ]
            },
            {
                "phase": "vulnerability_scan",
                "findings": [
                    {"vulnerability": "SQL Injection", "severity": "HIGH"},
                ]
            }
        ],
        "summary": {
            "total_findings": 5,
            "critical": 1,
            "high": 1,
            "medium": 2,
            "low": 1
        }
    }


# ============================================================================
# APPROVAL GATE FIXTURES
# ============================================================================

@pytest.fixture
def approval_gate_auto_approve():
    """Approval gate that auto-approves everything."""
    from unittest.mock import MagicMock
    
    gate = MagicMock()
    gate.auto_approve_low_risk = True
    gate.auto_approve_medium_risk = True
    gate.request_approval = AsyncMock(return_value=True)
    gate.aborted = False
    
    return gate


@pytest.fixture
def approval_gate_manual():
    """Approval gate that requires manual approval."""
    from unittest.mock import MagicMock
    
    gate = MagicMock()
    gate.auto_approve_low_risk = False
    gate.auto_approve_medium_risk = False
    gate.request_approval = AsyncMock(return_value=True)
    gate.aborted = False
    
    return gate


# ============================================================================
# CONFIGURATION FIXTURES
# ============================================================================

@pytest.fixture
def config_autonomous() -> Dict[str, Any]:
    """Configuration for autonomous mode."""
    return {
        "mode": "autonomous",
        "target": "192.168.1.100",
        "tools": {
            "nmap": {"enabled": True},
            "web_scanner": {"enabled": True},
            "sql_injection": {"enabled": True},
        },
        "llm": {
            "provider": "local",
            "model": "mistral:7b-instruct",
            "temperature": 0.7
        }
    }


@pytest.fixture
def config_interactive() -> Dict[str, Any]:
    """Configuration for interactive mode."""
    return {
        "mode": "interactive",
        "target": "192.168.1.100",
        "tools": {
            "nmap": {"enabled": True},
            "web_scanner": {"enabled": True},
        },
        "llm": {
            "provider": "local",
            "model": "mistral:7b-instruct",
            "temperature": 0.5
        }
    }


@pytest.fixture
def config_manual() -> Dict[str, Any]:
    """Configuration for manual mode."""
    return {
        "mode": "manual",
        "tools": {
            "nmap": {"enabled": True},
            "web_scanner": {"enabled": True},
            "sql_injection": {"enabled": True},
        }
    }


# ============================================================================
# TEST UTILITIES
# ============================================================================

class AsyncMockIterator:
    """Helper for async iteration in tests."""
    
    def __init__(self, items):
        self.items = items
        self.index = 0
    
    async def __aiter__(self):
        return self
    
    async def __anext__(self):
        if self.index >= len(self.items):
            raise StopAsyncIteration
        item = self.items[self.index]
        self.index += 1
        return item


@pytest.fixture
def async_mock_iterator():
    """Provide AsyncMockIterator for async tests."""
    return AsyncMockIterator