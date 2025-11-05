#!/usr/bin/env python3
"""
Compare output quality between Gemini and Local LLM.

Usage:
    python scripts/compare_llm_quality.py --gemini-key YOUR_KEY
    
Or set environment variable:
    export GEMINI_API_KEY=your_key
    python scripts/compare_llm_quality.py
"""

import asyncio
import json
import argparse
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'medusa-cli', 'src'))

try:
    from medusa.core.llm import LLMClient, LocalLLMClient, LLMConfig
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.markdown import Markdown
except ImportError:
    print("❌ Required dependencies not installed")
    print("Run: pip install -e medusa-cli")
    sys.exit(1)

console = Console()


async def compare_reconnaissance(target: str, context: dict, gemini_key: str = None):
    """Compare reconnaissance recommendations"""
    
    console.print(f"\n{'='*80}")
    console.print(Panel(
        f"[bold cyan]Test: Reconnaissance Recommendation[/bold cyan]\n"
        f"Target: {target}\n"
        f"Context: {json.dumps(context)}",
        expand=False
    ))
    console.print(f"{'='*80}\n")
    
    results = {}
    
    # Gemini
    if gemini_key:
        try:
            console.print("[yellow]🤖 Querying Gemini API...[/yellow]")
            gemini_config = LLMConfig(provider="gemini", api_key=gemini_key)
            gemini_client = LLMClient(gemini_config)
            gemini_result = await gemini_client.get_reconnaissance_recommendation(target, context)
            
            console.print("\n[bold green]--- GEMINI OUTPUT ---[/bold green]")
            console.print(json.dumps(gemini_result, indent=2))
            results['gemini'] = gemini_result
        except Exception as e:
            console.print(f"[red]Gemini failed: {e}[/red]")
            results['gemini'] = None
    else:
        console.print("[yellow]⚠️  Gemini API key not provided, skipping Gemini comparison[/yellow]")
        results['gemini'] = None
    
    # Local Mistral
    try:
        console.print("\n[yellow]🤖 Querying Local Mistral-7B...[/yellow]")
        local_config = LLMConfig(provider="local", model="mistral:7b-instruct")
        local_client = LocalLLMClient(local_config)
        
        # Check if Ollama is available
        if not await local_client._check_ollama_health():
            console.print("[red]❌ Ollama not available or model not found[/red]")
            results['local'] = None
        else:
            local_result = await local_client.get_reconnaissance_recommendation(target, context)
            
            console.print("\n[bold cyan]--- MISTRAL-7B OUTPUT ---[/bold cyan]")
            console.print(json.dumps(local_result, indent=2))
            results['local'] = local_result
    except Exception as e:
        console.print(f"[red]Local LLM failed: {e}[/red]")
        results['local'] = None
    
    # Compare
    if results['gemini'] and results['local']:
        console.print("\n[bold magenta]--- COMPARISON ---[/bold magenta]")
        
        table = Table(title="Side-by-Side Comparison")
        table.add_column("Metric", style="cyan")
        table.add_column("Gemini", style="green")
        table.add_column("Mistral-7B", style="blue")
        
        table.add_row(
            "Actions Count",
            str(len(results['gemini'].get('recommended_actions', []))),
            str(len(results['local'].get('recommended_actions', [])))
        )
        table.add_row(
            "Risk Assessment",
            results['gemini'].get('risk_assessment', 'N/A'),
            results['local'].get('risk_assessment', 'N/A')
        )
        table.add_row(
            "Focus Areas",
            str(len(results['gemini'].get('focus_areas', []))),
            str(len(results['local'].get('focus_areas', [])))
        )
        
        console.print(table)
    
    return results


async def compare_risk_assessment(vuln: dict, context: dict, gemini_key: str = None):
    """Compare risk assessments"""
    
    console.print(f"\n{'='*80}")
    console.print(Panel(
        f"[bold cyan]Test: Vulnerability Risk Assessment[/bold cyan]\n"
        f"Vulnerability: {json.dumps(vuln, indent=2)}",
        expand=False
    ))
    console.print(f"{'='*80}\n")
    
    results = {}
    
    # Gemini
    if gemini_key:
        try:
            console.print("[yellow]🤖 Querying Gemini API...[/yellow]")
            gemini_config = LLMConfig(provider="gemini", api_key=gemini_key)
            gemini_client = LLMClient(gemini_config)
            gemini_risk = await gemini_client.assess_vulnerability_risk(vuln, context)
            console.print(f"[green]Gemini assessment: [bold]{gemini_risk}[/bold][/green]")
            results['gemini'] = gemini_risk
        except Exception as e:
            console.print(f"[red]Gemini failed: {e}[/red]")
            results['gemini'] = None
    else:
        results['gemini'] = None
    
    # Local
    try:
        console.print("\n[yellow]🤖 Querying Local Mistral-7B...[/yellow]")
        local_config = LLMConfig(provider="local")
        local_client = LocalLLMClient(local_config)
        
        if await local_client._check_ollama_health():
            local_risk = await local_client.assess_vulnerability_risk(vuln, context)
            console.print(f"[cyan]Mistral assessment: [bold]{local_risk}[/bold][/cyan]")
            results['local'] = local_risk
        else:
            console.print("[red]❌ Ollama not available[/red]")
            results['local'] = None
    except Exception as e:
        console.print(f"[red]Local LLM failed: {e}[/red]")
        results['local'] = None
    
    # Compare
    if results['gemini'] and results['local']:
        match = results['gemini'] == results['local']
        if match:
            console.print("\n[bold green]✅ Both models agree![/bold green]")
        else:
            console.print(f"\n[bold yellow]⚠️  Models disagree: {results['gemini']} vs {results['local']}[/bold yellow]")
    
    return results


async def main():
    parser = argparse.ArgumentParser(description="Compare LLM output quality")
    parser.add_argument(
        "--gemini-key",
        help="Gemini API key (or set GEMINI_API_KEY)",
        default=os.getenv("GEMINI_API_KEY")
    )
    args = parser.parse_args()
    
    console.print(
        Panel(
            "[bold cyan]MEDUSA LLM Quality Comparison[/bold cyan]\n"
            "Comparing Google Gemini vs Local Mistral-7B-Instruct",
            expand=False
        )
    )
    
    if not args.gemini_key:
        console.print(
            "[yellow]⚠️  No Gemini API key provided. "
            "Only testing local LLM.[/yellow]\n"
        )
    
    test_cases = [
        {
            "type": "recon",
            "target": "192.168.1.100",
            "context": {"environment": "internal_network", "known_os": "Linux"}
        },
        {
            "type": "recon",
            "target": "https://example.com",
            "context": {"environment": "web_application"}
        },
        {
            "type": "risk",
            "vuln": {
                "type": "SQL Injection",
                "severity": "high",
                "url": "http://example.com/search"
            },
            "context": {"environment": "production", "industry": "healthcare"}
        },
        {
            "type": "risk",
            "vuln": {
                "type": "Missing Security Header",
                "header": "X-Frame-Options"
            },
            "context": {"environment": "staging"}
        }
    ]
    
    for i, test in enumerate(test_cases, 1):
        console.print(f"\n\n{'#'*80}")
        console.print(f"[bold]# Test Case {i}/{len(test_cases)}[/bold]")
        console.print(f"{'#'*80}")
        
        if test["type"] == "recon":
            await compare_reconnaissance(
                test["target"],
                test["context"],
                args.gemini_key
            )
        elif test["type"] == "risk":
            await compare_risk_assessment(
                test["vuln"],
                test["context"],
                args.gemini_key
            )
        
        await asyncio.sleep(2)  # Rate limiting
    
    # Summary
    console.print("\n\n" + "="*80)
    console.print(
        Panel(
            "[bold green]✅ Comparison Complete![/bold green]\n\n"
            "[yellow]Key Takeaways:[/yellow]\n"
            "• Local Mistral-7B is slower but has no rate limits\n"
            "• Gemini has better reasoning but costs money\n"
            "• For pentesting, both provide usable recommendations\n"
            "• Local LLM recommended for development/testing",
            title="Summary",
            style="green",
            expand=False
        )
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Comparison cancelled[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)

