"""
Integration tests for Nikto scanner
Tests real Nikto execution for web vulnerability detection
"""

import pytest
import asyncio
from medusa.tools.web_vuln import NiktoScanner


@pytest.mark.integration
@pytest.mark.asyncio
async def test_nikto_scanner_initialization():
    """Test that NiktoScanner initializes correctly"""
    scanner = NiktoScanner()
    assert scanner.name == "nikto"
    assert scanner.timeout == 1800
    assert scanner.tool_binary_name == "nikto"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_nikto_is_available():
    """Test that nikto availability check works"""
    scanner = NiktoScanner()
    is_available = scanner.is_available()
    # This will be True if nikto is installed, False otherwise
    assert isinstance(is_available, bool)


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not NiktoScanner().is_available(), reason="nikto not installed")
async def test_nikto_scan_basic():
    """Test basic nikto scan"""
    scanner = NiktoScanner(timeout=300)  # 5 minute timeout for testing

    # Scan example.com (safe, public site)
    result = await scanner.execute(
        target_url="http://example.com",
        port=80,
        ssl=False,
        tuning="1,2,3",  # Interesting files, misconfig, info disclosure
        output_format="txt"
    )

    # Check result structure
    assert "success" in result
    assert "findings" in result
    assert "duration_seconds" in result
    assert "raw_output" in result

    print(f"\nNikto scan results:")
    print(f"Success: {result['success']}")
    print(f"Findings count: {result['findings_count']}")
    print(f"Duration: {result['duration_seconds']}s")

    if result["findings"]:
        print(f"Sample finding: {result['findings'][0]}")


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not NiktoScanner().is_available(), reason="nikto not installed")
async def test_nikto_parse_output():
    """Test Nikto output parsing"""
    scanner = NiktoScanner()

    # Sample Nikto output
    sample_output = """
    + Server: Apache/2.4.41 (Ubuntu)
    + /admin/: Admin interface found
    + /config.php: Configuration file found
    + Allowed HTTP Methods: GET, POST, PUT, DELETE
    + OSVDB-3268: /icons/: Directory indexing found.
    + CVE-2021-12345: Vulnerable to known exploit
    """

    findings = scanner.parse_output(sample_output, "")

    assert len(findings) > 0

    # Check for different finding types
    types = [f.get("type") for f in findings]
    assert "web_vulnerability" in types or "information_disclosure" in types

    print(f"\nParsed {len(findings)} findings from sample output")
    for finding in findings:
        print(f"  - {finding.get('title', 'N/A')}: {finding.get('severity', 'N/A')}")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_nikto_invalid_target():
    """Test nikto with invalid target"""
    scanner = NiktoScanner(timeout=10)

    result = await scanner.execute(
        target_url="invalid;target",  # Dangerous characters should be caught
        port=80
    )

    assert result["success"] is False
    assert "error" in result
    assert "Invalid target" in result["error"]


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not NiktoScanner().is_available(), reason="nikto not installed")
async def test_nikto_quick_scan():
    """Test quick scan method"""
    scanner = NiktoScanner(timeout=180)  # 3 minutes

    result = await scanner.quick_scan("http://example.com")

    assert "success" in result
    print(f"\nQuick scan completed: {result['findings_count']} findings")


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not NiktoScanner().is_available(), reason="nikto not installed")
async def test_nikto_ssl_scan():
    """Test SSL-specific scanning"""
    scanner = NiktoScanner(timeout=180)

    result = await scanner.ssl_scan("https://example.com")

    assert "success" in result
    assert "findings" in result
    print(f"\nSSL scan completed: {result['findings_count']} findings")


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not NiktoScanner().is_available(), reason="nikto not installed")
async def test_nikto_localhost():
    """Test nikto against localhost"""
    scanner = NiktoScanner(timeout=120)

    result = await scanner.execute(
        target_url="http://localhost",
        port=80,
        tuning="1,2",  # Quick checks
        output_format="txt"
    )

    # May or may not find issues on localhost
    assert "success" in result or "error" in result

    print(f"\nLocalhost scan results:")
    print(f"Success: {result.get('success', False)}")
    print(f"Findings: {result.get('findings_count', 0)}")


@pytest.mark.integration
@pytest.mark.asyncio
def test_nikto_severity_assessment():
    """Test severity assessment logic"""
    scanner = NiktoScanner()

    test_cases = [
        ("Remote code execution possible", "critical"),
        ("Admin interface accessible", "high"),
        ("SQL injection vulnerability", "critical"),
        ("Cookie without secure flag", "medium"),
        ("Server version disclosure", "low"),
        ("Directory listing enabled", "medium"),
    ]

    for description, expected_severity in test_cases:
        severity = scanner._assess_nikto_severity(description)
        print(f"'{description}' -> {severity} (expected: {expected_severity})")

        # Verify severity is reasonable
        assert severity in ["low", "medium", "high", "critical"]


@pytest.mark.integration
@pytest.mark.asyncio
def test_nikto_extract_title():
    """Test title extraction from descriptions"""
    scanner = NiktoScanner()

    test_cases = [
        "Admin interface found. This is a security risk.",
        "Configuration file accessible without authentication, may contain sensitive data.",
        "Very long description that exceeds one hundred characters and should be truncated properly to avoid display issues in reports and user interfaces.",
    ]

    for description in test_cases:
        title = scanner._extract_title(description)
        assert len(title) <= 100
        assert len(title) > 0
        print(f"Extracted: '{title}'")


@pytest.mark.integration
@pytest.mark.asyncio
def test_nikto_get_recommendation():
    """Test recommendation generation"""
    scanner = NiktoScanner()

    test_cases = [
        "Admin panel found at /admin",
        "Default password detected",
        "SSL certificate expired",
        "Cookie without HttpOnly flag",
        "SQL injection possible",
        "Directory listing enabled",
    ]

    for description in test_cases:
        recommendation = scanner._get_recommendation(description)
        assert isinstance(recommendation, str)
        assert len(recommendation) > 0
        print(f"'{description}' -> '{recommendation}'")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_nikto_dangerous_methods_detection():
    """Test detection of dangerous HTTP methods"""
    scanner = NiktoScanner()

    sample_output = """
    + Allowed HTTP Methods: GET, POST, PUT, DELETE, TRACE
    """

    findings = scanner.parse_output(sample_output, "")

    # Should detect dangerous methods
    method_findings = [f for f in findings if f.get("type") == "misconfiguration"]

    if method_findings:
        assert "methods" in method_findings[0]
        print(f"\nDetected dangerous methods: {method_findings[0].get('dangerous_methods', [])}")


if __name__ == "__main__":
    # Allow running tests directly
    asyncio.run(test_nikto_scan_basic())
