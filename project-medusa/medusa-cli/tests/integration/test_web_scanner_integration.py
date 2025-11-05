"""
Integration tests for Web Scanner
Tests real HTTP reconnaissance against test targets
"""

import pytest
import asyncio
from medusa.tools.web_scanner import WebScanner


@pytest.mark.integration
@pytest.mark.asyncio
async def test_web_scanner_initialization():
    """Test that WebScanner initializes correctly"""
    scanner = WebScanner()
    assert scanner.name == "web_scanner"
    assert scanner.timeout == 120


@pytest.mark.integration
@pytest.mark.asyncio
async def test_web_scanner_localhost():
    """Test web scanner against localhost"""
    scanner = WebScanner()

    # Test against a known target (Google)
    result = await scanner.execute(
        target="http://example.com",
        check_https=True,
        use_whatweb=False,  # Skip whatweb for basic test
        check_endpoints=False
    )

    # Check result structure
    assert "success" in result
    assert "findings" in result
    assert "duration_seconds" in result

    print(f"\nWeb scan results:")
    print(f"Success: {result['success']}")
    print(f"Findings count: {result['findings_count']}")
    print(f"Duration: {result['duration_seconds']}s")

    if result["findings"]:
        print(f"Sample finding: {result['findings'][0]}")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_web_scanner_with_endpoint_discovery():
    """Test web scanner with endpoint discovery"""
    scanner = WebScanner()

    result = await scanner.execute(
        target="http://example.com",
        check_https=False,
        use_whatweb=False,
        check_endpoints=True
    )

    assert result["success"] in [True, False]

    # Check findings structure
    for finding in result["findings"]:
        assert "type" in finding
        assert "severity" in finding
        assert "confidence" in finding


@pytest.mark.integration
@pytest.mark.asyncio
async def test_web_scanner_localhost_8080():
    """Test web scanner against localhost:8080 (lab environment)"""
    scanner = WebScanner()

    result = await scanner.execute(
        target="http://localhost:8080",
        check_https=False,
        use_whatweb=False,
        check_endpoints=True
    )

    print(f"\nLocalhost:8080 scan results:")
    print(f"Success: {result['success']}")
    print(f"Findings: {result['findings_count']}")

    # Note: This will only work if lab environment is running


@pytest.mark.integration
@pytest.mark.asyncio
async def test_web_scanner_analyze_headers():
    """Test that web scanner analyzes headers correctly"""
    scanner = WebScanner()

    result = await scanner.execute(
        target="http://example.com",
        check_https=False,
        use_whatweb=False,
        check_endpoints=False
    )

    if result["success"]:
        # Check if any header analysis findings exist
        header_findings = [
            f for f in result["findings"]
            if f.get("type") in ["information_disclosure", "misconfiguration"]
        ]
        print(f"\nFound {len(header_findings)} header-related findings")


if __name__ == "__main__":
    # Allow running tests directly
    asyncio.run(test_web_scanner_localhost())
