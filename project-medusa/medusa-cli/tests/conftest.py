"""
Pytest configuration and shared fixtures for MEDUSA test suite

This file is automatically loaded by pytest and provides:
- Shared fixtures available to all tests
- Pytest configuration
- Test setup and teardown logic
"""

import pytest
import sys
import os
import json
import yaml
import tempfile
import shutil
import platform
from pathlib import Path
from typing import Dict, Any
from unittest.mock import Mock, AsyncMock

# Add src to Python path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


# ============================================================================
# Directory and Path Fixtures
# ============================================================================

@pytest.fixture
def fixtures_dir():
    """Return path to fixtures directory"""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_config_path(fixtures_dir):
    """Return path to sample configuration file"""
    return fixtures_dir / "sample_config.yaml"


@pytest.fixture
def mock_responses_path(fixtures_dir):
    """Return path to mock responses JSON"""
    return fixtures_dir / "mock_responses.json"


@pytest.fixture
def temp_dir():
    """
    Provide a temporary directory that's cleaned up after test.
    Use this for any tests that need to write files.
    """
    temp = tempfile.mkdtemp()
    yield Path(temp)
    shutil.rmtree(temp, ignore_errors=True)


# ============================================================================
# Configuration Fixtures
# ============================================================================

@pytest.fixture
def mock_api_key():
    """Return a mock API key for testing"""
    return "test-mock-api-key-12345"


@pytest.fixture
def test_target():
    """Return a test target URL"""
    return "http://test-target.local"


@pytest.fixture
def mock_config(temp_dir, mock_api_key):
    """Return a complete mock configuration dictionary"""
    return {
        "api_key": mock_api_key,
        "target": {
            "type": "docker",
            "url": "http://localhost:3001"
        },
        "llm": {
            "model": "gemini-pro",
            "temperature": 0.7,
            "max_tokens": 2048,
            "timeout": 30,
            "max_retries": 3,
            "mock_mode": True
        },
        "risk_tolerance": {
            "auto_approve_low": True,
            "auto_approve_medium": False,
            "auto_approve_high": False
        },
        "output": {
            "log_level": "DEBUG",
            "report_format": "json",
            "save_logs": True,
            "logs_dir": str(temp_dir / "logs"),
            "reports_dir": str(temp_dir / "reports")
        }
    }


@pytest.fixture
def mock_config_file(temp_dir, mock_config):
    """Create a temporary config file with mock configuration"""
    config_path = temp_dir / "config.yaml"
    with open(config_path, "w") as f:
        yaml.dump(mock_config, f)
    return config_path


@pytest.fixture
def mock_llm_config(mock_api_key):
    """Return mock LLM configuration for testing"""
    from medusa.core.llm import LLMConfig
    return LLMConfig(
        api_key=mock_api_key,
        model="gemini-pro",
        temperature=0.7,
        max_tokens=2048,
        timeout=30,
        max_retries=3,
        mock_mode=True
    )


# ============================================================================
# LLM Fixtures
# ============================================================================

@pytest.fixture
def mock_llm_client():
    """Return a MockLLMClient for testing without API calls"""
    from medusa.core.llm import MockLLMClient, LLMConfig
    config = LLMConfig(api_key="mock", mock_mode=True)
    return MockLLMClient(config)


@pytest.fixture
def mock_llm_response():
    """Return a typical mock LLM response"""
    return {
        "recommended_actions": [
            {
                "action": "port_scan",
                "command": "nmap -sV target",
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "priority": "high",
                "reasoning": "Discover exposed services"
            }
        ],
        "focus_areas": ["web_services", "databases"],
        "risk_assessment": "LOW",
        "estimated_duration": 60
    }


# ============================================================================
# Scan and Pentest Data Fixtures
# ============================================================================

@pytest.fixture
def mock_scan_results():
    """Return typical reconnaissance scan results"""
    return {
        "target": "192.168.1.100",
        "scan_type": "comprehensive",
        "timestamp": "2025-10-31T12:00:00Z",
        "ports": [
            {
                "port": 22,
                "service": "ssh",
                "version": "OpenSSH 8.2p1",
                "state": "open"
            },
            {
                "port": 80,
                "service": "http",
                "version": "nginx 1.18.0",
                "state": "open"
            },
            {
                "port": 443,
                "service": "https",
                "version": "nginx 1.18.0",
                "state": "open"
            },
            {
                "port": 3306,
                "service": "mysql",
                "version": "MySQL 8.0",
                "state": "open"
            }
        ],
        "os": {
            "name": "Linux",
            "version": "Ubuntu 20.04",
            "confidence": 95
        },
        "vulnerabilities": []
    }


@pytest.fixture
def mock_vulnerability():
    """Return a sample vulnerability finding"""
    return {
        "type": "SQL Injection",
        "severity": "HIGH",
        "location": "/api/search?q=",
        "description": "User input not properly sanitized in search endpoint",
        "cvss_score": 7.5,
        "technique_id": "T1190",
        "remediation": "Use parameterized queries",
        "exploitable": True,
        "proof_of_concept": "' OR '1'='1"
    }


@pytest.fixture
def mock_enumeration_results():
    """Return typical enumeration results"""
    return {
        "target": "192.168.1.100",
        "timestamp": "2025-10-31T12:15:00Z",
        "web_endpoints": [
            {"path": "/api/users", "method": "GET", "auth_required": False},
            {"path": "/api/patients", "method": "GET", "auth_required": True},
            {"path": "/api/admin", "method": "GET", "auth_required": True}
        ],
        "database_info": {
            "type": "mysql",
            "version": "8.0",
            "databases": ["ehr_system", "test", "mysql"]
        },
        "technologies": [
            {"name": "PHP", "version": "7.4"},
            {"name": "nginx", "version": "1.18.0"},
            {"name": "MySQL", "version": "8.0"}
        ]
    }


# ============================================================================
# Approval and Action Fixtures
# ============================================================================

@pytest.fixture
def low_risk_action():
    """Return a LOW risk action for testing"""
    from medusa.approval import Action, RiskLevel
    return Action(
        command="nmap -sV localhost",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        risk_level=RiskLevel.LOW,
        impact_description="Scan network services (read-only, no system changes)",
        target="localhost",
        reversible=True
    )


@pytest.fixture
def high_risk_action():
    """Return a HIGH risk action for testing"""
    from medusa.approval import Action, RiskLevel
    return Action(
        command="sqlmap -u http://target/api --dump",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        risk_level=RiskLevel.HIGH,
        impact_description="Attempt to extract database contents",
        target="http://target/api",
        reversible=True,
        data_at_risk="Database contents"
    )


@pytest.fixture
def critical_risk_action():
    """Return a CRITICAL risk action for testing"""
    from medusa.approval import Action, RiskLevel
    return Action(
        command="rm -rf /var/lib/mysql/*",
        technique_id="T1485",
        technique_name="Data Destruction",
        risk_level=RiskLevel.CRITICAL,
        impact_description="Permanently delete database files",
        target="production_server",
        reversible=False,
        data_at_risk="All database data"
    )


# ============================================================================
# Mock Objects
# ============================================================================

@pytest.fixture
def mock_console():
    """Return a mock Rich console for testing output"""
    mock = Mock()
    mock.print = Mock()
    mock.clear = Mock()
    return mock


@pytest.fixture
def mock_user_input():
    """
    Return a mock for user input.
    Use with monkeypatch to control user responses in tests.
    """
    mock = Mock()
    mock.return_value = "y"  # Default to "yes"
    return mock


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_configure(config):
    """Register custom pytest markers"""
    config.addinivalue_line(
        "markers", "unit: Unit tests for individual components"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests for component interactions"
    )
    config.addinivalue_line(
        "markers", "slow: Tests that take longer than 1 second"
    )
    config.addinivalue_line(
        "markers", "requires_api: Tests that require real API access"
    )
    config.addinivalue_line(
        "markers", "requires_docker: Tests that require Docker environment"
    )
    config.addinivalue_line(
        "markers", "manual: Tests that require manual setup or specific environment"
    )
    config.addinivalue_line(
        "markers", "resource_intensive: Tests that use significant CPU/memory resources"
    )


# ============================================================================
# Platform-Aware Resource Configuration
# ============================================================================

def get_optimal_thread_count(default: int, max_threads: int = None) -> int:
    """
    Get optimal thread count based on platform to avoid system lag
    
    Args:
        default: Default thread count for production
        max_threads: Maximum threads to use (defaults to lower values on macOS)
        
    Returns:
        Optimal thread count for current platform
    """
    system = platform.system().lower()
    
    # macOS tends to lag with high thread counts, use lower values
    if system == "darwin":  # macOS
        if max_threads is None:
            max_threads = 10  # Conservative limit for macOS
        return min(default, max_threads)
    
    # Linux can handle more threads
    elif system == "linux":
        if max_threads is None:
            max_threads = 20  # Moderate limit for testing
        return min(default, max_threads)
    
    # Windows - conservative
    else:
        if max_threads is None:
            max_threads = 10
        return min(default, max_threads)


@pytest.fixture
def test_thread_count():
    """
    Provide optimal thread count for testing based on platform
    
    Returns:
        int: Thread count safe for testing (lower on macOS)
    """
    return get_optimal_thread_count(default=5, max_threads=5)


@pytest.fixture
def test_timeout():
    """
    Provide shorter timeout for testing to avoid long waits
    
    Returns:
        int: Timeout in seconds
    """
    return 60  # 1 minute for tests


# ============================================================================
# Tool Execution Logging Fixtures
# ============================================================================

@pytest.fixture
def capture_tool_logs(temp_dir):
    """
    Capture tool execution logs to a file
    
    Usage:
        def test_something(capture_tool_logs):
            # Tool logs will be captured to test_tool_execution.log
            ...
    """
    import logging
    
    # Create log file handler
    log_file = temp_dir / "test_tool_execution.log"
    handler = logging.FileHandler(str(log_file))
    handler.setLevel(logging.DEBUG)
    
    # Configure logger for medusa.tools
    logger = logging.getLogger("medusa.tools")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    
    # Also capture root logger for broader coverage
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(handler)
    
    yield log_file
    
    # Cleanup
    logger.removeHandler(handler)
    root_logger.removeHandler(handler)
    handler.close()


# ============================================================================
# Async Test Support
# ============================================================================

@pytest.fixture
def event_loop():
    """Create an event loop for async tests"""
    import asyncio
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()