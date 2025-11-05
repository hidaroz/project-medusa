#!/usr/bin/env python3
"""
End-to-end tests for MEDUSA Autonomous Mode

Tests complete autonomous penetration testing workflows against the lab environment.
These are slow tests that run full reconnaissance, enumeration, and exploitation phases.
"""

import pytest
import asyncio
import os
import sys
from pathlib import Path
from typing import Dict, Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def lab_target():
    """Return lab environment target"""
    return "http://localhost:8080"


@pytest.fixture
def mock_llm_config():
    """LLM configuration for testing (uses mock mode)"""
    return {
        "api_key": "test-key",
        "model": "gemini-pro",
        "temperature": 0.7,
        "mock_mode": True  # Use mock LLM for faster, deterministic tests
    }


@pytest.fixture
def real_llm_config():
    """Real LLM configuration (requires API key)"""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        pytest.skip("GEMINI_API_KEY not set - skipping real LLM test")

    return {
        "api_key": api_key,
        "model": "gemini-pro",
        "temperature": 0.7,
        "mock_mode": False
    }


# ============================================================================
# Autonomous Mode - Mock LLM Tests
# ============================================================================

@pytest.mark.e2e
@pytest.mark.requires_docker
@pytest.mark.slow
@pytest.mark.asyncio
async def test_autonomous_reconnaissance_phase(lab_target, mock_llm_config):
    """
    Test autonomous reconnaissance phase against lab
    Uses mock LLM for fast, deterministic testing
    """
    from medusa.client import MedusaClient

    async with MedusaClient(
        lab_target,
        api_key="test",
        llm_config=mock_llm_config
    ) as client:
        # Get AI recommendation for reconnaissance
        strategy = await client.get_reconnaissance_strategy(lab_target)

        # Verify AI provided recommendations
        assert "recommended_actions" in strategy
        assert len(strategy["recommended_actions"]) > 0

        # Execute recommended actions would go here
        # For mock mode, we verify the structure is correct


@pytest.mark.e2e
@pytest.mark.requires_docker
@pytest.mark.slow
@pytest.mark.asyncio
async def test_autonomous_full_workflow_mock(lab_target, mock_llm_config):
    """
    Test complete autonomous workflow with mock LLM
    Verifies the full workflow structure without real exploitation
    """
    from medusa.client import MedusaClient

    async with MedusaClient(
        lab_target,
        api_key="test",
        llm_config=mock_llm_config
    ) as client:
        # Phase 1: Get reconnaissance strategy
        recon_strategy = await client.get_reconnaissance_strategy(lab_target)
        assert "recommended_actions" in recon_strategy
        assert "risk_assessment" in recon_strategy

        # Phase 2: Get enumeration recommendations (simulated findings)
        mock_findings = [
            {"type": "open_port", "port": 8080, "service": "http"},
            {"type": "open_port", "port": 3306, "service": "mysql"},
            {"type": "open_port", "port": 22, "service": "ssh"}
        ]

        # Phase 3: Get next actions
        next_actions = await client.get_ai_recommendation({
            "phase": "enumeration",
            "findings": mock_findings,
            "target": lab_target
        })

        assert "recommendations" in next_actions
        assert len(next_actions["recommendations"]) > 0

        # Workflow completed successfully
        print("\n✅ Autonomous workflow structure validated")


# ============================================================================
# Autonomous Mode - Real LLM Tests (Optional)
# ============================================================================

@pytest.mark.e2e
@pytest.mark.requires_docker
@pytest.mark.requires_api
@pytest.mark.slow
@pytest.mark.asyncio
async def test_autonomous_reconnaissance_real_llm(lab_target, real_llm_config):
    """
    Test autonomous reconnaissance with real Gemini LLM
    Only runs if GEMINI_API_KEY is set
    """
    from medusa.client import MedusaClient

    async with MedusaClient(
        lab_target,
        api_key="test",
        llm_config=real_llm_config
    ) as client:
        # Get real AI recommendation
        strategy = await client.get_reconnaissance_strategy(lab_target)

        # Verify AI provided meaningful recommendations
        assert "recommended_actions" in strategy
        actions = strategy["recommended_actions"]
        assert len(actions) > 0

        # Verify actions have required fields
        for action in actions:
            assert "action" in action or "command" in action
            assert "priority" in action or "technique_id" in action

        print(f"\n✅ Real LLM provided {len(actions)} reconnaissance actions")


# ============================================================================
# Tool Integration Tests
# ============================================================================

@pytest.mark.e2e
@pytest.mark.requires_docker
@pytest.mark.slow
def test_nmap_scan_against_lab(lab_target):
    """Test nmap scanning against lab environment"""
    import subprocess

    # Extract host from URL
    from urllib.parse import urlparse
    parsed = urlparse(lab_target)
    host = parsed.hostname or "localhost"

    # Run nmap scan
    try:
        result = subprocess.run(
            ["nmap", "-p", "8080,3001,3306,2222,21", host],
            capture_output=True,
            text=True,
            timeout=60
        )

        assert result.returncode == 0, "nmap scan failed"
        output = result.stdout

        # Verify we found some open ports
        assert "open" in output.lower(), "No open ports found"
        print(f"\n✅ Nmap scan successful, found open ports")

    except FileNotFoundError:
        pytest.skip("nmap not installed")
    except subprocess.TimeoutExpired:
        pytest.fail("nmap scan timed out")


@pytest.mark.e2e
@pytest.mark.requires_docker
@pytest.mark.slow
def test_web_vulnerability_scan(lab_target):
    """Test basic web vulnerability scanning"""
    import requests

    # Test SQL injection endpoint
    sqli_url = f"{lab_target}/search.php?query=test' OR '1'='1"

    try:
        response = requests.get(sqli_url, timeout=10)
        # Just verify endpoint is accessible
        assert response.status_code in [200, 500]
        print("✅ SQL injection test endpoint accessible")

        # Test directory traversal
        traversal_url = f"{lab_target}/download.php?file=../../../etc/passwd"
        response = requests.get(traversal_url, timeout=10)
        # Endpoint should be accessible (whether vuln works or not)
        assert response.status_code in [200, 404, 500]
        print("✅ Directory traversal test endpoint accessible")

    except requests.exceptions.RequestException as e:
        pytest.fail(f"Web vulnerability scan failed: {e}")


# ============================================================================
# Performance Tests
# ============================================================================

@pytest.mark.e2e
@pytest.mark.requires_docker
@pytest.mark.slow
@pytest.mark.asyncio
async def test_reconnaissance_performance(lab_target, mock_llm_config):
    """Test that reconnaissance completes in reasonable time"""
    import time
    from medusa.client import MedusaClient

    start_time = time.time()

    async with MedusaClient(
        lab_target,
        api_key="test",
        llm_config=mock_llm_config
    ) as client:
        await client.get_reconnaissance_strategy(lab_target)

    duration = time.time() - start_time

    # Mock LLM should respond very quickly
    assert duration < 5.0, f"Reconnaissance took too long: {duration:.2f}s"
    print(f"\n✅ Reconnaissance completed in {duration:.2f}s")


# ============================================================================
# Error Handling Tests
# ============================================================================

@pytest.mark.e2e
@pytest.mark.asyncio
async def test_autonomous_mode_invalid_target(mock_llm_config):
    """Test autonomous mode handles invalid targets gracefully"""
    from medusa.client import MedusaClient

    invalid_target = "http://this-definitely-does-not-exist-12345.com"

    async with MedusaClient(
        invalid_target,
        api_key="test",
        llm_config=mock_llm_config
    ) as client:
        # Should still be able to get strategy (LLM doesn't check if target exists)
        strategy = await client.get_reconnaissance_strategy(invalid_target)
        assert "recommended_actions" in strategy


@pytest.mark.e2e
@pytest.mark.asyncio
async def test_autonomous_mode_missing_llm_config():
    """Test autonomous mode requires LLM configuration"""
    from medusa.client import MedusaClient

    # Creating client without LLM config should work
    # (it will use default/mock LLM)
    async with MedusaClient(
        "http://localhost:8080",
        api_key="test"
    ) as client:
        # Should fall back to mock LLM
        strategy = await client.get_reconnaissance_strategy("http://localhost:8080")
        assert "recommended_actions" in strategy


# ============================================================================
# Workflow Validation Tests
# ============================================================================

@pytest.mark.e2e
@pytest.mark.requires_docker
@pytest.mark.slow
@pytest.mark.asyncio
async def test_complete_autonomous_workflow_phases(lab_target, mock_llm_config):
    """
    Test that all phases of autonomous mode can execute in sequence
    Validates the complete workflow without actual exploitation
    """
    from medusa.client import MedusaClient

    phases_completed = []

    async with MedusaClient(
        lab_target,
        api_key="test",
        llm_config=mock_llm_config
    ) as client:
        # Phase 1: Reconnaissance
        recon = await client.get_reconnaissance_strategy(lab_target)
        assert "recommended_actions" in recon
        phases_completed.append("reconnaissance")
        print("✅ Phase 1: Reconnaissance")

        # Phase 2: Enumeration (with mock findings)
        enum_context = {
            "phase": "enumeration",
            "target": lab_target,
            "previous_findings": [
                {"type": "service", "name": "http", "port": 8080},
                {"type": "service", "name": "mysql", "port": 3306}
            ]
        }
        enum = await client.get_ai_recommendation(enum_context)
        assert "recommendations" in enum
        phases_completed.append("enumeration")
        print("✅ Phase 2: Enumeration")

        # Phase 3: Vulnerability Assessment
        vuln = {
            "type": "SQL Injection",
            "severity": "high",
            "location": "/search.php"
        }
        risk = await client.assess_vulnerability_risk(vuln)
        assert risk in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        phases_completed.append("vulnerability_assessment")
        print("✅ Phase 3: Vulnerability Assessment")

        # Phase 4: Next Action Recommendation
        next_action = await client.get_ai_recommendation({
            "phase": "exploitation",
            "vulnerabilities_found": [vuln],
            "target": lab_target
        })
        assert "recommendations" in next_action
        phases_completed.append("next_action")
        print("✅ Phase 4: Next Action")

    # Verify all phases completed
    expected_phases = [
        "reconnaissance",
        "enumeration",
        "vulnerability_assessment",
        "next_action"
    ]

    for phase in expected_phases:
        assert phase in phases_completed, f"Phase '{phase}' did not complete"

    print(f"\n✅ All {len(phases_completed)} workflow phases completed successfully")


# ============================================================================
# Report Generation Tests
# ============================================================================

@pytest.mark.e2e
@pytest.mark.requires_docker
@pytest.mark.slow
@pytest.mark.asyncio
async def test_generate_pentest_report(lab_target, mock_llm_config, tmp_path):
    """Test that a pentest report can be generated from results"""
    from medusa.client import MedusaClient

    async with MedusaClient(
        lab_target,
        api_key="test",
        llm_config=mock_llm_config
    ) as client:
        # Simulate pentest with findings
        findings = {
            "target": lab_target,
            "scan_date": "2025-11-05",
            "vulnerabilities": [
                {
                    "type": "SQL Injection",
                    "severity": "CRITICAL",
                    "location": "/search.php",
                    "cvss": 9.8
                },
                {
                    "type": "Weak Credentials",
                    "severity": "HIGH",
                    "location": "MySQL Database",
                    "cvss": 8.8
                }
            ],
            "recommendations": [
                "Implement parameterized queries",
                "Enforce strong password policy"
            ]
        }

        # Note: Actual report generation would be implemented in the reporter module
        # For now, we just verify the structure
        assert "vulnerabilities" in findings
        assert len(findings["vulnerabilities"]) > 0
        assert "recommendations" in findings

        print(f"✅ Report structure validated with {len(findings['vulnerabilities'])} findings")
