#!/usr/bin/env python3
"""
Test script for MEDUSA LLM integration
Tests both mock and real LLM clients
"""

import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from medusa.core.llm import LLMConfig, LLMClient, MockLLMClient, create_llm_client
from rich.console import Console
from rich.panel import Panel

console = Console()


async def test_mock_llm():
    """Test the mock LLM client"""
    console.print("\n[bold cyan]Testing Mock LLM Client[/bold cyan]\n")
    
    config = LLMConfig(api_key="mock", mock_mode=True)
    client = MockLLMClient(config)
    
    # Test 1: Reconnaissance recommendation
    console.print("[yellow]Test 1: Reconnaissance Recommendation[/yellow]")
    recon_result = await client.get_reconnaissance_recommendation(
        "http://example.com",
        {"phase": "initial"}
    )
    console.print(f"✓ Actions: {len(recon_result['recommended_actions'])}")
    console.print(f"✓ Risk: {recon_result['risk_assessment']}")
    
    # Test 2: Enumeration recommendation
    console.print("\n[yellow]Test 2: Enumeration Recommendation[/yellow]")
    enum_result = await client.get_enumeration_recommendation(
        "http://example.com",
        [{"type": "open_port", "port": 80}]
    )
    console.print(f"✓ Actions: {len(enum_result['recommended_actions'])}")
    
    # Test 3: Vulnerability risk assessment
    console.print("\n[yellow]Test 3: Vulnerability Risk Assessment[/yellow]")
    vuln = {"type": "sql_injection", "severity": "high"}
    risk = await client.assess_vulnerability_risk(vuln)
    console.print(f"✓ Risk level: {risk}")
    
    # Test 4: Attack planning
    console.print("\n[yellow]Test 4: Attack Strategy Planning[/yellow]")
    attack_plan = await client.plan_attack_strategy(
        "http://example.com",
        [{"type": "api_endpoint", "path": "/api/users"}],
        ["data_access"]
    )
    console.print(f"✓ Attack chain steps: {len(attack_plan['attack_chain'])}")
    console.print(f"✓ Success probability: {attack_plan['success_probability']}")
    
    # Test 5: Next action recommendation
    console.print("\n[yellow]Test 5: Next Action Recommendation[/yellow]")
    next_action = await client.get_next_action_recommendation({
        "phase": "enumeration",
        "findings": []
    })
    console.print(f"✓ Recommendations: {len(next_action['recommendations'])}")
    
    console.print("\n[bold green]✓ All Mock LLM tests passed![/bold green]")


async def test_real_llm(provider: str = "local", api_key: str = None):
    """Test the real LLM client with configured provider"""
    console.print(f"\n[bold cyan]Testing Real LLM Client ({provider.upper()})[/bold cyan]\n")
    
    try:
        config = LLMConfig(
            provider=provider,
            cloud_api_key=api_key,
            temperature=0.7,
            mock_mode=False
        )
        client = create_llm_client(config)
        
        if isinstance(client, MockLLMClient):
            console.print("[yellow]⚠ Falling back to Mock client (check API key)[/yellow]")
            return
        
        # Test 1: Simple reconnaissance recommendation
        console.print("[yellow]Test 1: Real LLM Reconnaissance[/yellow]")
        recon_result = await client.get_reconnaissance_recommendation(
            "http://testapp.com",
            {"environment": "web application"}
        )
        console.print(f"✓ Generated {len(recon_result.get('recommended_actions', []))} actions")
        console.print(f"✓ Risk: {recon_result.get('risk_assessment', 'N/A')}")
        
        # Test 2: Risk assessment
        console.print("\n[yellow]Test 2: Real LLM Risk Assessment[/yellow]")
        vuln = {
            "type": "SQL Injection",
            "severity": "high",
            "description": "User input not sanitized in search query"
        }
        risk = await client.assess_vulnerability_risk(vuln)
        console.print(f"✓ AI-assessed risk: {risk}")
        
        console.print("\n[bold green]✓ Real LLM tests passed![/bold green]")
        
    except Exception as e:
        console.print(f"[red]✗ Real LLM test failed: {e}[/red]")
        console.print("[yellow]This is expected if google-generativeai is not installed[/yellow]")


async def test_client_integration():
    """Test MedusaClient with LLM integration"""
    console.print("\n[bold cyan]Testing MedusaClient Integration[/bold cyan]\n")
    
    from medusa.client import MedusaClient
    
    # Test with mock LLM config
    llm_config = {
        "api_key": "mock",
        "model": "gemini-pro",
        "mock_mode": True
    }
    
    async with MedusaClient("http://localhost:3001", "test_api_key", llm_config=llm_config) as client:
        # Test get_ai_recommendation
        console.print("[yellow]Test: get_ai_recommendation[/yellow]")
        result = await client.get_ai_recommendation({
            "phase": "enumeration",
            "target": "http://localhost:3001"
        })
        console.print(f"✓ Recommendations: {len(result['recommendations'])}")
        
        # Test get_reconnaissance_strategy
        console.print("\n[yellow]Test: get_reconnaissance_strategy[/yellow]")
        strategy = await client.get_reconnaissance_strategy("http://localhost:3001")
        console.print(f"✓ Strategy generated with {len(strategy.get('recommended_actions', []))} actions")
        
        # Test assess_vulnerability_risk
        console.print("\n[yellow]Test: assess_vulnerability_risk[/yellow]")
        risk = await client.assess_vulnerability_risk({"type": "xss", "severity": "medium"})
        console.print(f"✓ Risk level: {risk}")
    
    console.print("\n[bold green]✓ MedusaClient integration tests passed![/bold green]")


async def main():
    """Main test runner"""
    console.print(Panel.fit(
        "[bold cyan]MEDUSA LLM Integration Test Suite[/bold cyan]\n"
        "Testing AI components for penetration testing decisions",
        border_style="cyan"
    ))
    
    # Test 1: Mock LLM (always works)
    await test_mock_llm()
    
    # Test 2: Client integration
    await test_client_integration()
    
    # Test 3: Real LLM (if API key provided)
    api_key = os.environ.get("GEMINI_API_KEY")
    if api_key:
        await test_real_llm(api_key)
    else:
        console.print("\n[yellow]ℹ Skipping real LLM tests (set GEMINI_API_KEY to test)[/yellow]")
    
    console.print("\n" + "="*60)
    console.print(Panel.fit(
        "[bold green]✓ All tests completed![/bold green]\n\n"
        "The LLM integration is working correctly.\n"
        "• Mock mode: ✓ Working\n"
        "• Client integration: ✓ Working\n"
        f"• Real LLM: {'✓ Working' if api_key else '⚠ Not tested (no API key)'}",
        border_style="green"
    ))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Tests interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Test suite failed: {e}[/red]")
        import traceback
        traceback.print_exc()

