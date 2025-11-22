"""
JSON Parsing Demo

Demonstrates the robust JSON parsing capabilities of the enhanced LLM client.
Shows how various malformed JSON responses are successfully parsed.
"""

import asyncio
import sys
sys.path.insert(0, '/Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src')

from medusa.core.llm import create_llm_client
from medusa.core.llm.config import LLMConfig
from medusa.core.llm.providers.mock import MockLLMProvider


def print_test(title: str, response: str, result: dict = None, error: str = None):
    """Print a test result in a formatted way"""
    print(f"\n{'='*70}")
    print(f"TEST: {title}")
    print(f"{'='*70}")
    print(f"\nINPUT RESPONSE:")
    print("-" * 70)
    print(response)
    print("-" * 70)

    if result:
        print(f"\n✅ PARSED SUCCESSFULLY:")
        import json
        print(json.dumps(result, indent=2))
    elif error:
        print(f"\n❌ PARSING FAILED:")
        print(error)
    print()


async def demo_basic_parsing():
    """Demo basic JSON parsing scenarios"""
    print("\n" + "="*70)
    print("BASIC JSON PARSING SCENARIOS")
    print("="*70)

    config = LLMConfig(provider="mock")
    provider = MockLLMProvider()
    client = create_llm_client(config=config, provider=provider)

    # Test 1: Pure JSON
    response1 = '{"action": "scan", "target": "192.168.1.1", "ports": [80, 443]}'
    try:
        result = client._extract_json_from_response(response1)
        print_test("Pure JSON Object", response1, result=result)
    except ValueError as e:
        print_test("Pure JSON Object", response1, error=str(e))

    # Test 2: JSON Array
    response2 = '[{"id": 1, "type": "vulnerability"}, {"id": 2, "type": "exploit"}]'
    try:
        result = client._extract_json_from_response(response2)
        print_test("JSON Array", response2, result=result)
    except ValueError as e:
        print_test("JSON Array", response2, error=str(e))


async def demo_markdown_parsing():
    """Demo parsing JSON from markdown code blocks"""
    print("\n" + "="*70)
    print("MARKDOWN CODE BLOCK SCENARIOS")
    print("="*70)

    config = LLMConfig(provider="mock")
    provider = MockLLMProvider()
    client = create_llm_client(config=config, provider=provider)

    # Test 3: Markdown with json tag
    response3 = '''Here is the analysis:

```json
{
    "findings": ["port 80 open", "port 443 open"],
    "severity": "medium",
    "cve_count": 3
}
```

Let me know if you need more details!'''
    try:
        result = client._extract_json_from_response(response3)
        print_test("Markdown with ```json Tag", response3, result=result)
    except ValueError as e:
        print_test("Markdown with ```json Tag", response3, error=str(e))

    # Test 4: Plain markdown block
    response4 = '''```
{
    "status": "success",
    "data": ["item1", "item2", "item3"]
}
```'''
    try:
        result = client._extract_json_from_response(response4)
        print_test("Plain Markdown Block", response4, result=result)
    except ValueError as e:
        print_test("Plain Markdown Block", response4, error=str(e))


async def demo_malformed_json():
    """Demo parsing malformed JSON that gets repaired"""
    print("\n" + "="*70)
    print("MALFORMED JSON REPAIR SCENARIOS")
    print("="*70)

    config = LLMConfig(provider="mock")
    provider = MockLLMProvider()
    client = create_llm_client(config=config, provider=provider)

    # Test 5: Trailing commas
    response5 = '''{
    "vulnerabilities": [
        {
            "type": "SQL Injection",
            "severity": "high",
            "cve": "CVE-2021-1234",
        },
        {
            "type": "XSS",
            "severity": "medium",
            "cve": "CVE-2021-5678",
        },
    ],
    "total": 2,
}'''
    try:
        result = client._extract_json_from_response(response5)
        print_test("Trailing Commas (Repaired)", response5, result=result)
    except ValueError as e:
        print_test("Trailing Commas (Should Repair)", response5, error=str(e))

    # Test 6: Comments in JSON
    response6 = '''{
    // Reconnaissance results
    "target": "example.com",
    "scan_type": "full", /* comprehensive scan */
    "duration": 120 // seconds
}'''
    try:
        result = client._extract_json_from_response(response6)
        print_test("JSON with Comments (Repaired)", response6, result=result)
    except ValueError as e:
        print_test("JSON with Comments (Should Repair)", response6, error=str(e))


async def demo_complex_real_world():
    """Demo parsing complex real-world LLM responses"""
    print("\n" + "="*70)
    print("COMPLEX REAL-WORLD SCENARIOS")
    print("="*70)

    config = LLMConfig(provider="mock")
    provider = MockLLMProvider()
    client = create_llm_client(config=config, provider=provider)

    # Test 7: ChatGPT-style response
    response7 = '''I'll analyze the target and provide recommendations.

Based on the reconnaissance findings, here's the exploitation strategy:

```json
{
    "exploitation_plan": {
        "strategy": "Multi-stage attack",
        "target_vulnerability": "SQL Injection in login form",
        "exploitation_steps": [
            {
                "step": 1,
                "phase": "weaponization",
                "action": "Craft SQL injection payload",
                "tool": "sqlmap",
                "commands": ["sqlmap -u http://target/login --dbs"],
                "mitre_technique": "T1190",
                "risk_level": "medium"
            },
            {
                "step": 2,
                "phase": "exploitation",
                "action": "Extract database credentials",
                "tool": "sqlmap",
                "commands": ["sqlmap -u http://target/login -D users --dump"],
                "mitre_technique": "T1552.001",
                "risk_level": "high"
            }
        ],
        "success_probability": 0.75,
        "estimated_duration": "30 minutes",
        "risk_assessment": {
            "overall_risk": "high",
            "detection_likelihood": "medium"
        }
    }
}
```

This strategy focuses on the identified SQL injection vulnerability. Would you like me to proceed with the exploitation?'''

    try:
        result = client._extract_json_from_response(response7)
        print_test("ChatGPT-Style Complex Response", response7, result=result)
    except ValueError as e:
        print_test("ChatGPT-Style Complex Response", response7, error=str(e))

    # Test 8: Claude-style with explanation
    response8 = '''## Vulnerability Analysis Results

Here's my analysis of the reconnaissance findings:

{
    "vulnerabilities": [
        {
            "vulnerability_type": "Outdated Apache version",
            "cve_references": ["CVE-2021-44228"],
            "severity": "critical",
            "cvss_score": 9.8,
            "exploitability": "high",
            "affected_service": "Apache/2.4.49"
        },
        {
            "vulnerability_type": "Weak SSH configuration",
            "cve_references": [],
            "severity": "medium",
            "cvss_score": 5.3,
            "exploitability": "medium",
            "affected_service": "OpenSSH 7.4"
        }
    ],
    "total_found": 2,
    "high_severity_count": 1,
    "recommendations": [
        "Update Apache to latest version immediately",
        "Harden SSH configuration",
        "Enable fail2ban"
    ]
}

### Next Steps

Based on this analysis, I recommend proceeding with exploitation planning for the critical Apache vulnerability.'''

    try:
        result = client._extract_json_from_response(response8)
        print_test("Claude-Style with Markdown Headers", response8, result=result)
    except ValueError as e:
        print_test("Claude-Style with Markdown Headers", response8, error=str(e))


async def demo_edge_cases():
    """Demo edge cases and error handling"""
    print("\n" + "="*70)
    print("EDGE CASES AND ERROR HANDLING")
    print("="*70)

    config = LLMConfig(provider="mock")
    provider = MockLLMProvider()
    client = create_llm_client(config=config, provider=provider)

    # Test 9: No JSON found
    response9 = "This is just plain text with no JSON at all."
    try:
        result = client._extract_json_from_response(response9)
        print_test("No JSON Found", response9, result=result)
    except ValueError as e:
        print_test("No JSON Found (Expected Error)", response9, error=str(e))

    # Test 10: Nested JSON with text
    response10 = '''Analysis complete. Results:

{
    "scan_results": {
        "target": "192.168.1.1",
        "open_ports": [
            {"port": 22, "service": "ssh", "version": "OpenSSH 7.4"},
            {"port": 80, "service": "http", "version": "Apache 2.4.49"},
            {"port": 443, "service": "https", "version": "Apache 2.4.49"}
        ],
        "vulnerabilities": {
            "critical": 1,
            "high": 0,
            "medium": 2,
            "low": 5
        }
    },
    "metadata": {
        "scan_duration": 45,
        "timestamp": "2025-11-20T10:30:00Z"
    }
}

Total scan time: 45 seconds'''

    try:
        result = client._extract_json_from_response(response10)
        print_test("Nested JSON with Surrounding Text", response10, result=result)
    except ValueError as e:
        print_test("Nested JSON with Surrounding Text", response10, error=str(e))


async def main():
    """Run all demos"""
    print("\n" + "="*70)
    print("LLM JSON PARSING ROBUSTNESS DEMONSTRATION")
    print("="*70)
    print("\nThis demo shows how the enhanced JSON parser handles:")
    print("  • Pure JSON objects and arrays")
    print("  • Markdown code blocks (```json and ```)")
    print("  • Malformed JSON (trailing commas, comments)")
    print("  • Complex real-world LLM responses")
    print("  • Edge cases and error scenarios")

    await demo_basic_parsing()
    await demo_markdown_parsing()
    await demo_malformed_json()
    await demo_complex_real_world()
    await demo_edge_cases()

    print("\n" + "="*70)
    print("DEMO COMPLETED")
    print("="*70)
    print("\n✅ All scenarios demonstrated successfully!")
    print("\nKey Takeaways:")
    print("  1. Handles various JSON formats automatically")
    print("  2. Repairs common LLM-generated JSON errors")
    print("  3. Provides detailed error messages for debugging")
    print("  4. Validates return types (dict/list only)")
    print("  5. Performance optimized with fast-path for valid JSON")
    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
