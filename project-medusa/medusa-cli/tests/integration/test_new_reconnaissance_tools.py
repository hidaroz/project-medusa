"""
Integration tests for new reconnaissance and initial access tools
Tests Amass, httpx, Kerbrute, and SQLMap integrations
"""

import pytest
import asyncio
import shutil
from medusa.tools.amass import AmassScanner
from medusa.tools.httpx_scanner import HttpxScanner
from medusa.tools.kerbrute import KerbruteScanner
from medusa.tools.sql_injection import SQLMapScanner
from medusa.core.llm import MockLLMClient


# ============================================================================
# Helper functions for tool availability checks (avoid module-level instantiation)
# ============================================================================

def amass_available() -> bool:
    """Check if amass is available without instantiating scanner"""
    try:
        return shutil.which("amass") is not None
    except Exception:
        return False


def httpx_available() -> bool:
    """Check if httpx is available without instantiating scanner"""
    try:
        return shutil.which("httpx") is not None
    except Exception:
        return False


def kerbrute_available() -> bool:
    """Check if kerbrute is available without instantiating scanner"""
    try:
        return shutil.which("kerbrute") is not None
    except Exception:
        return False


def sqlmap_available() -> bool:
    """Check if sqlmap is available without instantiating scanner"""
    try:
        return shutil.which("sqlmap") is not None
    except Exception:
        return False


# ============================================================================
# Amass Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
async def test_amass_scanner_initialization():
    """Test that AmassScanner initializes correctly"""
    scanner = AmassScanner()
    assert scanner.name == "amass"
    assert scanner.timeout == 300
    assert scanner.tool_binary_name == "amass"
    assert scanner.passive is True


@pytest.mark.integration
@pytest.mark.asyncio
async def test_amass_is_available():
    """Test that amass availability check works"""
    scanner = AmassScanner()
    is_available = scanner.is_available()
    assert isinstance(is_available, bool)


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not amass_available(), reason="amass not installed")
async def test_amass_quick_enum():
    """Test quick passive enumeration"""
    scanner = AmassScanner()
    
    result = await scanner.quick_enum("example.com")
    
    # Check result structure
    assert "success" in result
    assert "findings" in result
    assert "duration_seconds" in result
    assert "findings_count" in result
    assert isinstance(result["findings"], list)
    
    # Amass should find something for example.com
    if result["success"]:
        print(f"\nAmass found {result['findings_count']} subdomains for example.com")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_amass_invalid_domain():
    """Test amass with invalid domain"""
    scanner = AmassScanner()
    
    result = await scanner.enumerate_subdomains(
        domain="invalid;domain",  # Dangerous characters
        passive=True
    )
    
    assert result["success"] is False
    assert "error" in result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_amass_finding_structure():
    """Test that amass findings have correct structure"""
    scanner = AmassScanner()
    
    # Create mock findings for testing
    mock_data = {
        "name": "api.example.com",
        "domain": "example.com",
        "addresses": ["1.2.3.4"],
        "sources": ["DNS", "Certificate"],
        "tag": "dns"
    }
    
    finding = scanner._transform_amass_json(mock_data)
    
    assert finding is not None
    assert finding["type"] == "subdomain_enumeration"
    assert finding["subdomain"] == "api.example.com"
    assert finding["domain"] == "example.com"
    assert "1.2.3.4" in finding["ip_addresses"]
    assert "confidence" in finding


# ============================================================================
# httpx Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
async def test_httpx_scanner_initialization():
    """Test that HttpxScanner initializes correctly"""
    scanner = HttpxScanner()
    assert scanner.name == "httpx"
    assert scanner.timeout == 120
    assert scanner.threads == 50
    assert scanner.tool_binary_name == "httpx"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_httpx_is_available():
    """Test that httpx availability check works"""
    scanner = HttpxScanner()
    is_available = scanner.is_available()
    assert isinstance(is_available, bool)


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not httpx_available(), reason="httpx not installed")
async def test_httpx_validation_with_known_hosts():
    """Test httpx validation with known live hosts"""
    scanner = HttpxScanner(timeout=30)
    
    targets = [
        "https://example.com",
        "https://google.com",
        "https://github.com"
    ]
    
    result = await scanner.quick_validate(targets)
    
    # Check result structure
    assert "success" in result
    assert "findings" in result
    assert "duration_seconds" in result
    assert isinstance(result["findings"], list)
    
    # These hosts should be live
    if result["success"] and result["findings"]:
        print(f"\nhttpx validated {len(result['findings'])} live servers")
        for finding in result["findings"]:
            print(f"  - {finding['url']}: {finding['status_code']}")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_httpx_finding_structure():
    """Test that httpx findings have correct structure"""
    scanner = HttpxScanner()
    
    # Create mock httpx response for testing
    mock_data = {
        "url": "https://api.example.com",
        "status-code": 200,
        "content-length": 1234,
        "content-type": "application/json",
        "title": "API Documentation",
        "webserver": "nginx/1.21.0",
        "tech": ["PHP", "MySQL"]
    }
    
    finding = scanner._transform_httpx_json(mock_data)
    
    assert finding is not None
    assert finding["type"] == "web_server_detection"
    assert finding["url"] == "https://api.example.com"
    assert finding["status_code"] == 200
    assert finding["ssl"] is True
    assert "nginx" in finding["web_server"]


# ============================================================================
# Kerbrute Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
async def test_kerbrute_scanner_initialization():
    """Test that KerbruteScanner initializes correctly"""
    scanner = KerbruteScanner()
    assert scanner.name == "kerbrute"
    assert scanner.timeout == 600
    assert scanner.threads == 10
    assert scanner.tool_binary_name == "kerbrute"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_kerbrute_is_available():
    """Test that kerbrute availability check works"""
    scanner = KerbruteScanner()
    is_available = scanner.is_available()
    assert isinstance(is_available, bool)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_kerbrute_enumerate_users_missing_userlist():
    """Test kerbrute user enumeration without userlist"""
    scanner = KerbruteScanner()
    
    result = await scanner.enumerate_users(
        dc="10.0.0.1",
        domain="domain.local",
        userlist="/nonexistent/users.txt"
    )
    
    assert result["success"] is False
    assert "error" in result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_kerbrute_output_parsing():
    """Test parsing of kerbrute output"""
    scanner = KerbruteScanner()
    
    # Mock kerbrute output
    mock_output = """
    [*] Starting Kerberos Enumeration
    [✓] VALID USER: jsmith @ domain.local
    [✓] VALID USER: admin @ domain.local
    [!] User jsmith@domain.local doesn't require preauthentication
    [✓] jsmith:Password123 @ domain.local
    """
    
    findings = scanner.parse_output(mock_output, "")
    
    # Check we found valid users
    users = [f for f in findings if f.get("type") == "kerberos_user"]
    assert len(users) > 0
    
    # Check we found credentials
    creds = [f for f in findings if f.get("type") == "kerberos_credentials"]
    assert len(creds) > 0


# ============================================================================
# SQLMap Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
async def test_sqlmap_scanner_initialization():
    """Test that SQLMapScanner initializes correctly"""
    scanner = SQLMapScanner()
    assert scanner.name == "sqlmap"
    assert scanner.timeout == 600
    assert scanner.tool_binary_name == "sqlmap"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_sqlmap_is_available():
    """Test that sqlmap availability check works"""
    scanner = SQLMapScanner()
    is_available = scanner.is_available()
    assert isinstance(is_available, bool)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_sqlmap_invalid_url():
    """Test sqlmap with invalid URL"""
    scanner = SQLMapScanner()
    
    result = await scanner.test_injection(
        url="invalid;url",  # Dangerous characters
        level=1,
        risk=1
    )
    
    assert result["success"] is False
    assert "error" in result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_sqlmap_finding_structure():
    """Test that sqlmap findings have correct structure"""
    scanner = SQLMapScanner()
    
    # Create mock sqlmap response for testing
    mock_output = """
    [CRITICAL] time-based blind
    *Parameter: id (GET)*
    it looks like the back-end DBMS is 'MySQL'
    available databases: information_schema, mysql, wordpress
    """
    
    findings = scanner.parse_output(mock_output, "")
    
    # Check finding structure
    if findings:
        finding = findings[0]
        assert finding["type"] == "sql_injection"
        assert "parameter" in finding
        assert "injection_types" in finding
        assert "dbms" in finding


# ============================================================================
# LLM Target Prioritization Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
async def test_llm_target_prioritization():
    """Test LLM-based target prioritization"""
    llm = MockLLMClient()
    
    # Mock Amass findings
    amass_findings = [
        {
            "subdomain": "admin.example.com",
            "ip_addresses": ["1.2.3.4"],
            "sources": ["DNS"]
        },
        {
            "subdomain": "api.example.com",
            "ip_addresses": ["1.2.3.5"],
            "sources": ["Certificate"]
        },
        {
            "subdomain": "obscure-service.example.com",
            "ip_addresses": ["1.2.3.6"],
            "sources": ["DNS"]
        }
    ]
    
    # Mock httpx findings
    httpx_findings = [
        {
            "url": "https://admin.example.com",
            "status_code": 200
        },
        {
            "url": "https://api.example.com",
            "status_code": 200
        }
    ]
    
    result = await llm.prioritize_reconnaissance_targets(
        amass_findings,
        httpx_findings
    )
    
    # Check result structure
    assert "prioritized_targets" in result
    assert "scan_strategy" in result
    assert isinstance(result["prioritized_targets"], list)


# ============================================================================
# Integration Workflow Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_reconnaissance_workflow_mock():
    """Test full reconnaissance workflow with mock tools"""
    # Create mock findings from each stage
    
    # Stage 1: Amass enumeration
    amass_results = {
        "success": True,
        "findings": [
            {
                "subdomain": "admin.example.com",
                "domain": "example.com",
                "ip_addresses": ["1.2.3.4"],
                "sources": ["DNS"]
            }
        ],
        "findings_count": 1
    }
    
    # Stage 2: LLM prioritization
    llm = MockLLMClient()
    prioritized = await llm.prioritize_reconnaissance_targets(
        amass_results["findings"]
    )
    
    assert "prioritized_targets" in prioritized
    
    # Stage 3: httpx validation (would happen with real targets)
    assert amass_results["findings_count"] > 0
    
    print("\n✓ Full reconnaissance workflow test passed")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_amass_to_httpx_workflow():
    """Test workflow from Amass output to httpx validation"""
    # This tests the integration between tools
    
    # Create mock Amass finding
    amass_scanner = AmassScanner()
    mock_amass_finding = {
        "name": "www.example.com",
        "domain": "example.com",
        "addresses": ["1.2.3.4"],
        "sources": ["DNS"],
        "tag": "dns"
    }
    
    # Transform to standard format
    finding = amass_scanner._transform_amass_json(mock_amass_finding)
    assert finding is not None
    
    # The finding would then be sent to httpx
    subdomain = finding["subdomain"]
    assert subdomain == "www.example.com"
    
    # httpx would create URL from subdomain
    httpx_scanner = HttpxScanner()
    url = httpx_scanner._ensure_url_scheme(subdomain)
    assert "://" in url
    
    print(f"\n✓ Amass→httpx workflow: {subdomain} → {url}")


# ============================================================================
# Unit-like tests for error handling
# ============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
async def test_amass_sanitizes_input():
    """Test that Amass sanitizes domain input"""
    scanner = AmassScanner()
    
    # Test dangerous characters
    dangerous_domains = [
        "example.com;rm -rf /",
        "example.com&&cat /etc/passwd",
        "example.com|whoami"
    ]
    
    for domain in dangerous_domains:
        result = await scanner.enumerate_subdomains(domain)
        assert result["success"] is False


@pytest.mark.integration
@pytest.mark.asyncio
async def test_httpx_empty_targets():
    """Test httpx with empty target list"""
    scanner = HttpxScanner()
    
    result = await scanner.validate_servers([])
    
    assert result["success"] is False
    assert "error" in result


@pytest.mark.integration
@pytest.mark.asyncio
async def test_kerbrute_invalid_parameters():
    """Test Kerbrute with invalid parameters"""
    scanner = KerbruteScanner()
    
    result = await scanner.enumerate_users(
        dc="invalid;dc",  # Dangerous characters
        domain="domain.local",
        userlist="/tmp/users.txt"
    )
    
    assert result["success"] is False


# ============================================================================
# Real Tool Execution Tests (Phase 4)
# ============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not amass_available(), reason="amass not installed")
async def test_amass_real_execution_example_com():
    """Test Amass against example.com (safe, public domain)"""
    scanner = AmassScanner(timeout=180)  # 3 min timeout
    
    result = await scanner.quick_enum("example.com")
    
    # Check result structure
    assert "success" in result
    assert "findings" in result
    assert "duration_seconds" in result
    assert isinstance(result["findings"], list)
    
    # If successful, validate findings structure
    if result["success"]:
        assert result["findings_count"] >= 0
        print(f"\nAmass found {result['findings_count']} subdomains for example.com")
        if result["findings"]:
            finding = result["findings"][0]
            assert "subdomain" in finding
            assert "domain" in finding


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not httpx_available(), reason="httpx not installed")
async def test_httpx_real_execution_known_hosts():
    """Test httpx against known live hosts"""
    scanner = HttpxScanner(timeout=30)
    
    targets = [
        "https://example.com",
        "https://google.com",
        "https://github.com"
    ]
    
    result = await scanner.quick_validate(targets)
    
    # Check result structure
    assert "success" in result
    assert "findings" in result
    assert isinstance(result["findings"], list)
    
    # Should find at least some live servers
    if result["success"]:
        print(f"\nhttpx validated {len(result['findings'])} live servers")
        for finding in result["findings"][:5]:  # Print first 5
            assert "url" in finding
            assert "status_code" in finding
            print(f"  - {finding['url']}: {finding['status_code']}")


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not kerbrute_available(), reason="kerbrute not installed")
@pytest.mark.manual  # Only run in lab environment
async def test_kerbrute_in_lab():
    """Test Kerbrute against lab AD environment (requires LAB_AD_DC env var)"""
    import os
    
    if not os.getenv("LAB_AD_DC"):
        pytest.skip("Lab environment not configured (set LAB_AD_DC and LAB_DOMAIN)")
    
    scanner = KerbruteScanner(timeout=300)
    
    # Create a minimal test userlist
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("administrator\n")
        f.write("guest\n")
        userlist = f.name
    
    try:
        result = await scanner.enumerate_users(
            dc=os.getenv("LAB_AD_DC"),
            domain=os.getenv("LAB_DOMAIN", "lab.local"),
            userlist=userlist
        )
        
        assert "success" in result
        assert "findings" in result
    finally:
        import os as os_module
        try:
            os_module.unlink(userlist)
        except:
            pass


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not sqlmap_available(), reason="sqlmap not installed")
@pytest.mark.manual  # Only run with test target
async def test_sqlmap_against_test_target():
    """Test SQLMap against intentionally vulnerable test app (requires VULN_TEST_URL env var)"""
    import os
    
    test_url = os.getenv("VULN_TEST_URL")
    if not test_url:
        pytest.skip("No test target configured (set VULN_TEST_URL)")
    
    scanner = SQLMapScanner(timeout=120)
    
    result = await scanner.quick_scan(test_url)
    
    assert "success" in result
    assert "findings" in result
    assert isinstance(result["findings"], list)


# ============================================================================
# Real Workflow Integration Tests (Phase 5)
# ============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not amass_available() or not httpx_available(), reason="amass or httpx not installed")
async def test_amass_to_httpx_real_workflow():
    """Test real Amass → httpx workflow"""
    
    # Step 1: Run Amass
    amass = AmassScanner(timeout=180)  # 3 min timeout
    amass_result = await amass.quick_enum("example.com")
    
    assert amass_result["success"]
    assert len(amass_result["findings"]) >= 0
    
    # Step 2: Extract subdomains
    subdomains = [f["subdomain"] for f in amass_result["findings"]]
    print(f"\nFound {len(subdomains)} subdomains")
    
    # Step 3: Validate with httpx (test first 10 to avoid timeout)
    if subdomains:
        httpx = HttpxScanner(timeout=60)
        httpx_result = await httpx.quick_validate(subdomains[:10])
        
        assert httpx_result["success"]
        print(f"Live servers: {httpx_result.get('metadata', {}).get('live_servers', len(httpx_result['findings']))}")
        
        # Step 4: Verify data compatibility
        for finding in httpx_result["findings"]:
            assert "url" in finding
            assert "status_code" in finding


@pytest.mark.integration
@pytest.mark.asyncio
async def test_llm_prioritization_with_real_amass_data():
    """Test LLM prioritization using real Amass findings (if available)"""
    import os
    
    # Only run if amass is available
    if not amass_available():
        pytest.skip("amass not installed")
    
    # Get real Amass data
    amass = AmassScanner(timeout=180)
    amass_result = await amass.quick_enum("example.com")
    
    if not amass_result["success"] or not amass_result["findings"]:
        pytest.skip("No Amass findings available for testing")
    
    # Test LLM prioritization
    llm = MockLLMClient()
    prioritized = await llm.prioritize_reconnaissance_targets(
        amass_result["findings"]
    )
    
    assert "prioritized_targets" in prioritized
    assert isinstance(prioritized["prioritized_targets"], list)
    
    # Verify prioritized targets have required fields
    if prioritized["prioritized_targets"]:
        for target in prioritized["prioritized_targets"]:
            assert "priority" in target
            assert "target" in target


# ============================================================================
# Performance and Reliability Tests (Phase 7)
# ============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not amass_available(), reason="amass not installed")
async def test_tool_timeout_handling():
    """Test that tools respect timeout settings"""
    import time
    
    # Set very short timeout
    scanner = AmassScanner(timeout=5)  # 5 seconds
    
    start = time.time()
    result = await scanner.quick_enum("example.com")
    duration = time.time() - start
    
    # Should complete (may timeout or succeed, but shouldn't hang)
    assert duration < 15  # Max 15 seconds including cleanup
    assert "success" in result


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not httpx_available(), reason="httpx not installed")
async def test_error_handling_unreachable_targets():
    """Test tools handle unreachable targets gracefully"""
    httpx = HttpxScanner(timeout=10)
    
    # Test with invalid/unreachable targets
    result = await httpx.validate_servers([
        "http://192.0.2.1",  # Reserved IP - should timeout
        "http://invalid-domain-xyz-123.com"
    ])
    
    # Should complete without crashing
    assert "findings" in result
    # May have 0 findings, but shouldn't error


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v"])

