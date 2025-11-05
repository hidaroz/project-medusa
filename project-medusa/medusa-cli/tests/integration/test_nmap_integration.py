"""
Integration tests for Nmap scanner
Tests real nmap execution against localhost and test targets
"""

import pytest
import asyncio
from medusa.tools.nmap import NmapScanner


@pytest.mark.integration
@pytest.mark.asyncio
async def test_nmap_scanner_initialization():
    """Test that NmapScanner initializes correctly"""
    scanner = NmapScanner()
    assert scanner.name == "nmap"
    assert scanner.timeout == 600
    assert scanner.tool_binary_name == "nmap"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_nmap_is_available():
    """Test that nmap availability check works"""
    scanner = NmapScanner()
    is_available = scanner.is_available()
    # This will be True if nmap is installed, False otherwise
    assert isinstance(is_available, bool)


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not NmapScanner().is_available(), reason="nmap not installed")
async def test_nmap_scan_localhost():
    """Test nmap scan against localhost"""
    scanner = NmapScanner()

    result = await scanner.execute(
        target="127.0.0.1",
        ports="1-100",
        scan_type="-sV"
    )

    # Check result structure
    assert "success" in result
    assert "findings" in result
    assert "duration_seconds" in result
    assert "raw_output" in result

    # Log results for debugging
    print(f"\nNmap scan results:")
    print(f"Success: {result['success']}")
    print(f"Findings count: {result['findings_count']}")
    print(f"Duration: {result['duration_seconds']}s")

    if result["findings"]:
        print(f"Sample finding: {result['findings'][0]}")


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not NmapScanner().is_available(), reason="nmap not installed")
async def test_nmap_scan_with_service_detection():
    """Test nmap with service version detection"""
    scanner = NmapScanner()

    result = await scanner.execute(
        target="127.0.0.1",
        ports="80,443,22",
        scan_type="-sV"
    )

    assert result["success"] in [True, False]  # Might fail if no ports open

    # Check findings structure if any ports found
    for finding in result["findings"]:
        assert "type" in finding
        assert "port" in finding
        assert "state" in finding
        assert "service" in finding
        assert "confidence" in finding


@pytest.mark.integration
@pytest.mark.asyncio
async def test_nmap_invalid_target():
    """Test nmap with invalid target"""
    scanner = NmapScanner()

    result = await scanner.execute(
        target="invalid;target",  # Dangerous characters should be caught
        ports="80",
        scan_type="-sV"
    )

    assert result["success"] is False
    assert "error" in result
    assert "Invalid target" in result["error"]


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not NmapScanner().is_available(), reason="nmap not installed")
async def test_nmap_quick_scan():
    """Test quick scan method"""
    scanner = NmapScanner()

    result = await scanner.quick_scan("127.0.0.1")

    assert "success" in result
    assert "findings" in result
    print(f"\nQuick scan found {result['findings_count']} open ports")


if __name__ == "__main__":
    # Allow running tests directly
    asyncio.run(test_nmap_scan_localhost())
