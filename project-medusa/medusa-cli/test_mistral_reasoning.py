#!/usr/bin/env python3
"""
Test script to verify Mistral-7B-Instruct is working for penetration testing reasoning.

This script tests:
1. LLM provider initialization
2. Reconnaissance recommendation generation
3. Next action recommendation
4. Attack strategy planning

Run: python test_mistral_reasoning.py
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from medusa.core.llm import create_llm_client, LLMConfig
from medusa.core.llm import LocalLLMClient  # Legacy adapter for testing
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import json

console = Console()


async def test_llm_provider():
    """Test 1: Verify LLM provider initialization"""
    console.print("\n[bold cyan]Test 1: LLM Provider Initialization[/bold cyan]")
    
    config = LLMConfig(
        provider="local",
        local_model="mistral:7b-instruct",
        ollama_url="http://localhost:11434"
    )
    
    try:
        client = create_llm_client(config)
        health = await client.health_check()
        
        if health["healthy"]:
            console.print(f"[green]✓[/green] Provider: {health['provider']}")
            console.print(f"[green]✓[/green] Model: {health.get('model', 'unknown')}")
            console.print(f"[green]✓[/green] Health check passed\n")
            return client
        else:
            console.print(f"[red]✗[/red] Health check failed: {health.get('error', 'Unknown error')}\n")
            return None
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to initialize LLM: {e}\n")
        return None


async def test_reconnaissance_recommendation(client):
    """Test 2: Reconnaissance recommendation"""
    console.print("[bold cyan]Test 2: Reconnaissance Recommendation[/bold cyan]")
    console.print("[dim]Testing if LLM can reason about reconnaissance strategy...[/dim]\n")
    
    target = "http://localhost:3001"
    context = {
        "phase": "reconnaissance",
        "target": target,
        "previous_findings": [],
        "objectives": ["Identify attack surface", "Find vulnerabilities"]
    }
    
    try:
        # Use legacy adapter for compatibility
        legacy_client = LocalLLMClient(LLMConfig(provider="local", local_model="mistral:7b-instruct"))
        
        console.print(f"[yellow]Asking LLM:[/yellow] What reconnaissance actions should I take for {target}?")
        console.print("[dim]Waiting for LLM response...[/dim]\n")
        
        result = await legacy_client.get_reconnaissance_recommendation(target, context)
        
        console.print("[green]✓[/green] LLM provided recommendation!\n")
        
        # Display results
        table = Table(title="Reconnaissance Recommendations", show_header=True, header_style="bold magenta")
        table.add_column("Action", style="cyan")
        table.add_column("Reasoning", style="white")
        table.add_column("Risk", style="yellow")
        
        if isinstance(result, dict) and "actions" in result:
            for action in result.get("actions", [])[:5]:  # Show first 5
                table.add_row(
                    action.get("action", "N/A"),
                    action.get("reasoning", "N/A")[:60] + "..." if len(action.get("reasoning", "")) > 60 else action.get("reasoning", "N/A"),
                    action.get("risk_level", "N/A")
                )
        else:
            # Fallback display
            console.print(f"[yellow]Response format:[/yellow] {type(result)}")
            console.print(f"[dim]{json.dumps(result, indent=2)[:500]}...[/dim]\n")
        
        console.print(table)
        console.print()
        
        # Legacy client doesn't have close method
        if hasattr(legacy_client, 'close'):
            await legacy_client.close()
        return True
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to get recommendation: {e}\n")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]\n")
        return False


async def test_next_action_recommendation(client):
    """Test 3: Next action recommendation"""
    console.print("[bold cyan]Test 3: Next Action Recommendation[/bold cyan]")
    console.print("[dim]Testing if LLM can reason about what to do next...[/dim]\n")
    
    context = {
        "phase": "enumeration",
        "target": "http://localhost:3001",
        "findings": [
            {
                "type": "open_port",
                "port": 80,
                "service": "http",
                "details": "Web server detected"
            },
            {
                "type": "open_port",
                "port": 3306,
                "service": "mysql",
                "details": "Database server detected"
            }
        ],
        "completed_actions": ["port_scan", "service_detection"],
        "objectives": ["Find SQL injection vulnerabilities"]
    }
    
    try:
        legacy_client = LocalLLMClient(LLMConfig(provider="local", local_model="mistral:7b-instruct"))
        
        console.print("[yellow]Asking LLM:[/yellow] Given these findings, what should I do next?")
        console.print("[dim]Waiting for LLM response...[/dim]\n")
        
        result = await legacy_client.get_next_action_recommendation(context)
        
        console.print("[green]✓[/green] LLM provided next action recommendation!\n")
        
        # Display results
        if isinstance(result, dict):
            if "recommendations" in result:
                table = Table(title="Next Action Recommendations", show_header=True, header_style="bold magenta")
                table.add_column("Action", style="cyan")
                table.add_column("Confidence", style="green")
                table.add_column("Reasoning", style="white")
                table.add_column("Risk", style="yellow")
                
                for rec in result.get("recommendations", [])[:3]:
                    table.add_row(
                        rec.get("action", "N/A"),
                        f"{rec.get('confidence', 0):.2f}",
                        rec.get("reasoning", "N/A")[:50] + "..." if len(rec.get("reasoning", "")) > 50 else rec.get("reasoning", "N/A"),
                        rec.get("risk_level", "N/A")
                    )
                console.print(table)
                
                if "context_analysis" in result:
                    console.print(f"\n[yellow]Context Analysis:[/yellow] {result['context_analysis']}")
                if "suggested_next_phase" in result:
                    console.print(f"[yellow]Suggested Phase:[/yellow] {result['suggested_next_phase']}")
            else:
                console.print(f"[yellow]Response:[/yellow] {json.dumps(result, indent=2)[:500]}...")
        else:
            console.print(f"[yellow]Response type:[/yellow] {type(result)}")
            console.print(f"[dim]{str(result)[:500]}...[/dim]")
        
        console.print()
        # Legacy client doesn't have close method
        if hasattr(legacy_client, 'close'):
            await legacy_client.close()
        return True
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to get next action: {e}\n")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]\n")
        return False


async def test_attack_strategy_planning(client):
    """Test 4: Attack strategy planning"""
    console.print("[bold cyan]Test 4: Attack Strategy Planning[/bold cyan]")
    console.print("[dim]Testing if LLM can plan an attack strategy...[/dim]\n")
    
    target = "http://localhost:3001"
    findings = [
        {
            "type": "vulnerability",
            "severity": "high",
            "name": "SQL Injection",
            "location": "/api/search",
            "description": "SQL injection vulnerability detected in search parameter"
        },
        {
            "type": "open_port",
            "port": 3306,
            "service": "mysql",
            "details": "MySQL database accessible"
        }
    ]
    objectives = ["Extract sensitive data", "Gain database access"]
    
    try:
        legacy_client = LocalLLMClient(LLMConfig(provider="local", local_model="mistral:7b-instruct"))
        
        console.print("[yellow]Asking LLM:[/yellow] Plan an attack strategy based on these findings")
        console.print("[dim]Waiting for LLM response...[/dim]\n")
        
        result = await legacy_client.plan_attack_strategy(target, findings, objectives)
        
        console.print("[green]✓[/green] LLM provided attack strategy!\n")
        
        # Display results
        if isinstance(result, dict):
            if "attack_chain" in result or "steps" in result:
                steps = result.get("attack_chain", result.get("steps", []))
                table = Table(title="Attack Strategy", show_header=True, header_style="bold magenta")
                table.add_column("Step", style="cyan")
                table.add_column("Action", style="white")
                table.add_column("Technique", style="yellow")
                table.add_column("Risk", style="red")
                
                for i, step in enumerate(steps[:5], 1):
                    table.add_row(
                        str(i),
                        step.get("action", step.get("description", "N/A")),
                        step.get("technique", "N/A"),
                        step.get("risk_level", "N/A")
                    )
                console.print(table)
            else:
                console.print(f"[yellow]Response:[/yellow] {json.dumps(result, indent=2)[:500]}...")
        else:
            console.print(f"[yellow]Response type:[/yellow] {type(result)}")
        
        console.print()
        # Legacy client doesn't have close method
        if hasattr(legacy_client, 'close'):
            await legacy_client.close()
        return True
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to plan strategy: {e}\n")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]\n")
        return False


async def main():
    """Run all tests"""
    console.print(Panel(
        "[bold cyan]Mistral-7B-Instruct Reasoning Test[/bold cyan]\n"
        "Testing LLM reasoning capabilities for penetration testing",
        style="cyan"
    ))
    
    # Test 1: Provider initialization
    client = await test_llm_provider()
    if not client:
        console.print("[red]Cannot proceed - LLM provider not available[/red]")
        return 1
    
    # Test 2: Reconnaissance recommendation
    recon_ok = await test_reconnaissance_recommendation(client)
    
    # Test 3: Next action recommendation
    next_action_ok = await test_next_action_recommendation(client)
    
    # Test 4: Attack strategy planning
    strategy_ok = await test_attack_strategy_planning(client)
    
    # Summary
    console.print(Panel(
        f"[bold]Test Results:[/bold]\n\n"
        f"Provider Initialization: [green]✓[/green]\n"
        f"Reconnaissance Recommendation: {'[green]✓[/green]' if recon_ok else '[red]✗[/red]'}\n"
        f"Next Action Recommendation: {'[green]✓[/green]' if next_action_ok else '[red]✗[/red]'}\n"
        f"Attack Strategy Planning: {'[green]✓[/green]' if strategy_ok else '[red]✗[/red]'}\n\n"
        f"Overall: {'[green]SUCCESS[/green]' if all([recon_ok, next_action_ok, strategy_ok]) else '[yellow]PARTIAL[/yellow]'}",
        style="cyan" if all([recon_ok, next_action_ok, strategy_ok]) else "yellow"
    ))
    
    await client.close()
    
    return 0 if all([recon_ok, next_action_ok, strategy_ok]) else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

