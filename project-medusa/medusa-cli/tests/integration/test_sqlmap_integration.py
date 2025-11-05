"""
Integration tests for SQLMap scanner
Tests real SQLMap execution for SQL injection detection
"""

import pytest
import asyncio
from medusa.tools.sql_injection import SQLMapScanner


@pytest.mark.integration
@pytest.mark.asyncio
async def test_sqlmap_scanner_initialization():
    """Test that SQLMapScanner initializes correctly"""
    scanner = SQLMapScanner()
    assert scanner.name == "sqlmap"
    assert scanner.timeout == 900
    assert scanner.tool_binary_name == "sqlmap"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_sqlmap_is_available():
    """Test that sqlmap availability check works"""
    scanner = SQLMapScanner()
    is_available = scanner.is_available()
    # This will be True if sqlmap is installed, False otherwise
    assert isinstance(is_available, bool)


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not SQLMapScanner().is_available(), reason="sqlmap not installed")
async def test_sqlmap_scan_basic():
    """Test basic sqlmap scan"""
    scanner = SQLMapScanner(timeout=60)  # Short timeout for testing

    # Use a safe test URL (intentionally vulnerable test site)
    # Note: In production, replace with actual test target
    result = await scanner.execute(
        target_url="http://testphp.vulnweb.com/artists.php?artist=1",
        risk=1,
        level=1,
        batch=True
    )

    # Check result structure
    assert "success" in result
    assert "findings" in result
    assert "duration_seconds" in result
    assert "raw_output" in result

    print(f"\nSQLMap scan results:")
    print(f"Success: {result['success']}")
    print(f"Findings count: {result['findings_count']}")
    print(f"Duration: {result['duration_seconds']}s")

    if result["findings"]:
        print(f"Sample finding: {result['findings'][0]}")


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not SQLMapScanner().is_available(), reason="sqlmap not installed")
async def test_sqlmap_parse_output():
    """Test SQLMap output parsing"""
    scanner = SQLMapScanner()

    # Sample SQLMap output
    sample_output = """
    Parameter: id (GET) is vulnerable
    Type: boolean-based blind
    Payload: id=1 AND 1=1
    back-end DBMS: MySQL >= 5.0
    sqlmap identified the following injection point
    """

    findings = scanner.parse_output(sample_output, "")

    assert len(findings) > 0
    assert any(f.get("type") == "sql_injection" for f in findings)

    print(f"\nParsed {len(findings)} findings from sample output")
    for finding in findings:
        print(f"  - {finding.get('title', 'N/A')}: {finding.get('severity', 'N/A')}")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_sqlmap_invalid_target():
    """Test sqlmap with invalid target"""
    scanner = SQLMapScanner(timeout=10)

    result = await scanner.execute(
        target_url="invalid;target",  # Dangerous characters should be caught
        batch=True
    )

    assert result["success"] is False
    assert "error" in result
    assert "Invalid target" in result["error"]


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not SQLMapScanner().is_available(), reason="sqlmap not installed")
async def test_sqlmap_quick_scan():
    """Test quick scan method"""
    scanner = SQLMapScanner(timeout=60)

    # Use testphp.vulnweb.com (intentionally vulnerable for testing)
    result = await scanner.quick_scan("http://testphp.vulnweb.com/artists.php?artist=1")

    assert "success" in result
    print(f"\nQuick scan completed: {result['findings_count']} findings")


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not SQLMapScanner().is_available(), reason="sqlmap not installed")
async def test_sqlmap_test_parameter():
    """Test parameter-specific scanning"""
    scanner = SQLMapScanner(timeout=60)

    result = await scanner.test_parameter(
        url="http://testphp.vulnweb.com/artists.php",
        parameter="artist",
        method="GET"
    )

    assert "success" in result
    assert "findings" in result
    print(f"\nParameter test completed: {result['findings_count']} findings")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_sqlmap_not_vulnerable_detection():
    """Test that sqlmap correctly reports when no vulnerability found"""
    scanner = SQLMapScanner(timeout=30)

    # Create sample output with "not vulnerable" message
    sample_output = "all tested parameters do not appear to be injectable"

    findings = scanner.parse_output(sample_output, "")

    # Should return empty findings list
    assert len(findings) == 0
    print("\nCorrectly detected no vulnerabilities in safe output")


@pytest.mark.integration
@pytest.mark.asyncio
def test_sqlmap_extract_vulnerable_params():
    """Test extraction of vulnerable parameters from output"""
    scanner = SQLMapScanner()

    sample_output = """
    Parameter: id (GET) is vulnerable
    Parameter: name (POST) is vulnerable
    Parameter: user (COOKIE) is vulnerable
    """

    params = scanner._extract_vulnerable_params(sample_output)

    assert len(params) == 3
    assert "id" in params
    assert "name" in params
    assert "user" in params
    print(f"\nExtracted vulnerable parameters: {params}")


if __name__ == "__main__":
    # Allow running tests directly
    asyncio.run(test_sqlmap_scan_basic())
