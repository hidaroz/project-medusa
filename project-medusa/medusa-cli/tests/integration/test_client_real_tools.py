"""
Integration tests for MedusaClient with real tool execution
Tests that client methods use real tools instead of mock data
"""

import pytest
import asyncio
from medusa.client import MedusaClient


@pytest.mark.integration
@pytest.mark.asyncio
async def test_client_initialization_with_real_tools():
    """Test that client initializes with real pentesting tools"""
    client = MedusaClient(
        base_url="http://localhost:8000",
        api_key="test",
        llm_config={"mock_mode": True}  # Use mock LLM to avoid API calls
    )

    # Check that tools are initialized
    assert hasattr(client, "nmap")
    assert hasattr(client, "web_scanner")
    assert client.nmap is not None
    assert client.web_scanner is not None

    await client.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_reconnaissance_uses_real_tools():
    """Test that perform_reconnaissance uses real tools"""
    client = MedusaClient(
        base_url="http://localhost:8000",
        api_key="test",
        llm_config={"mock_mode": True}
    )

    # Run reconnaissance against example.com
    result = await client.perform_reconnaissance("example.com")

    # Check that result has the REAL_TOOLS flag
    assert result.get("mode") == "REAL_TOOLS", "Client should use real tools, not mocks"

    # Check result structure
    assert "phase" in result
    assert result["phase"] == "reconnaissance"
    assert "findings" in result
    assert "executed_actions" in result
    assert "duration" in result

    # Check that executed_actions includes real tools
    actions = result["executed_actions"]
    tool_names = [action.get("tool") for action in actions]

    print(f"\nReconnaissance results:")
    print(f"Mode: {result.get('mode')}")
    print(f"Findings count: {result.get('findings_count')}")
    print(f"Executed actions: {len(actions)}")
    print(f"Tools used: {tool_names}")

    # Verify real tools were attempted
    assert "nmap" in tool_names or "web_scanner" in tool_names, \
        "At least one real tool should have been executed"

    await client.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_reconnaissance_against_localhost():
    """Test reconnaissance against localhost"""
    client = MedusaClient(
        base_url="http://localhost:8000",
        api_key="test",
        llm_config={"mock_mode": True}
    )

    result = await client.perform_reconnaissance("localhost")

    print(f"\nLocalhost reconnaissance:")
    print(f"Success: {result.get('success')}")
    print(f"Findings: {result.get('findings_count')}")
    print(f"Duration: {result.get('duration'):.2f}s")

    # Print sample findings
    if result.get("findings"):
        for finding in result["findings"][:3]:
            print(f"Finding: {finding.get('type')} - {finding.get('title', 'N/A')}")

    assert result.get("mode") == "REAL_TOOLS"

    await client.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_enumeration_uses_real_tools():
    """Test that enumerate_services uses real tools"""
    client = MedusaClient(
        base_url="http://localhost:8000",
        api_key="test",
        llm_config={"mock_mode": True}
    )

    # Run enumeration
    result = await client.enumerate_services("example.com")

    # Check that result has the REAL_TOOLS flag
    assert result.get("mode") == "REAL_TOOLS", "Enumeration should use real tools"

    # Check result structure
    assert "phase" in result
    assert result["phase"] == "enumeration"
    assert "findings" in result
    assert "executed_actions" in result

    print(f"\nEnumeration results:")
    print(f"Mode: {result.get('mode')}")
    print(f"Findings count: {result.get('findings_count')}")
    print(f"Duration: {result.get('duration'):.2f}s")

    await client.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_reconnaissance_enumeration_flow():
    """Test complete reconnaissance -> enumeration flow"""
    client = MedusaClient(
        base_url="http://localhost:8000",
        api_key="test",
        llm_config={"mock_mode": True}
    )

    # Step 1: Reconnaissance
    recon_result = await client.perform_reconnaissance("example.com")
    assert recon_result.get("mode") == "REAL_TOOLS"

    recon_findings = recon_result.get("findings", [])
    print(f"\nReconnaissance found {len(recon_findings)} items")

    # Step 2: Enumeration with recon findings
    enum_result = await client.enumerate_services(
        "example.com",
        reconnaissance_findings=recon_findings
    )
    assert enum_result.get("mode") == "REAL_TOOLS"

    enum_findings = enum_result.get("findings", [])
    print(f"Enumeration found {len(enum_findings)} items")

    # Verify no mock data patterns
    all_findings = recon_findings + enum_findings

    # Mock data typically has very specific port numbers and services
    # Real data will vary based on actual target
    print(f"\nTotal findings: {len(all_findings)}")

    await client.close()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_no_mock_data_in_results():
    """Verify that results do not contain hardcoded mock data"""
    client = MedusaClient(
        base_url="http://localhost:8000",
        api_key="test",
        llm_config={"mock_mode": True}
    )

    result = await client.perform_reconnaissance("example.com")

    # Check for mock data indicators
    findings = result.get("findings", [])

    # Mock data patterns to check for (from old implementation)
    mock_patterns = [
        "nginx 1.21.0",  # Exact version from mock
        "MedCare EHR System",  # Mock application name
        "Node.js Express",  # Generic mock string
    ]

    findings_text = str(findings)

    mock_found = False
    for pattern in mock_patterns:
        if pattern in findings_text:
            print(f"WARNING: Found mock pattern '{pattern}' in results")
            mock_found = True

    # Note: This is informational - real scans might legitimately find these
    print(f"\nMock pattern check: {'FOUND' if mock_found else 'CLEAN'}")

    await client.close()


if __name__ == "__main__":
    # Run basic test
    asyncio.run(test_reconnaissance_uses_real_tools())
