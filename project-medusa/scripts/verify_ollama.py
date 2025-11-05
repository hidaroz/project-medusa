#!/usr/bin/env python3
"""
Ollama verification script for MEDUSA.

Checks if Ollama is properly installed and configured.
"""

import sys
import os
import asyncio

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'medusa-cli', 'src'))

try:
    import httpx
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    print("❌ Required dependencies not installed")
    print("Run: pip install httpx rich")
    sys.exit(1)

console = Console()


async def check_ollama_server(url: str = "http://localhost:11434") -> bool:
    """Check if Ollama server is running."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{url}/api/tags")
            if response.status_code == 200:
                return True
            return False
    except httpx.ConnectError:
        return False
    except Exception as e:
        console.print(f"[yellow]Warning: {e}[/yellow]")
        return False


async def get_available_models(url: str = "http://localhost:11434"):
    """Get list of available models."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{url}/api/tags")
            if response.status_code == 200:
                data = response.json()
                return data.get('models', [])
            return []
    except Exception:
        return []


async def test_generation(url: str = "http://localhost:11434", model: str = "mistral:7b-instruct"):
    """Test model generation."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{url}/api/generate",
                json={
                    "model": model,
                    "prompt": "Respond with exactly: SUCCESS",
                    "stream": False
                }
            )
            if response.status_code == 200:
                result = response.json()
                text = result.get("response", "")
                return "SUCCESS" in text.upper()
            return False
    except Exception as e:
        console.print(f"[yellow]Generation test failed: {e}[/yellow]")
        return False


async def main():
    """Main verification routine."""
    console.print(
        Panel(
            "[bold cyan]MEDUSA Ollama Verification[/bold cyan]\n"
            "Checking Ollama installation and configuration",
            expand=False
        )
    )
    console.print()
    
    # Check 1: Ollama server
    console.print("[yellow]Checking Ollama server...[/yellow]")
    ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
    is_running = await check_ollama_server(ollama_url)
    
    if is_running:
        console.print(f"[green]✅ Ollama is running at {ollama_url}[/green]\n")
    else:
        console.print(f"[red]❌ Ollama server not reachable at {ollama_url}[/red]")
        console.print("\n[yellow]To start Ollama:[/yellow]")
        console.print("  Linux/Mac: [cyan]ollama serve[/cyan]")
        console.print("  Windows: Ollama should start automatically")
        console.print("  Docker: [cyan]docker run -d -p 11434:11434 ollama/ollama[/cyan]\n")
        sys.exit(1)
    
    # Check 2: Available models
    console.print("[yellow]Checking available models...[/yellow]")
    models = await get_available_models(ollama_url)
    
    if not models:
        console.print("[red]❌ No models installed[/red]")
        console.print("\n[yellow]To install recommended model:[/yellow]")
        console.print("  [cyan]ollama pull mistral:7b-instruct[/cyan]\n")
        sys.exit(1)
    
    # Display models in table
    table = Table(title="Installed Models")
    table.add_column("Model", style="cyan")
    table.add_column("Size", style="green")
    
    recommended_model = os.getenv("OLLAMA_MODEL", "mistral:7b-instruct")
    has_recommended = False
    
    for model in models:
        model_name = model.get('name', 'unknown')
        model_size = model.get('size', 0)
        
        # Convert bytes to GB
        size_gb = model_size / (1024 ** 3)
        size_str = f"{size_gb:.2f} GB"
        
        if model_name == recommended_model:
            has_recommended = True
            table.add_row(f"✅ {model_name}", size_str)
        else:
            table.add_row(model_name, size_str)
    
    console.print(table)
    console.print()
    
    if not has_recommended:
        console.print(f"[yellow]⚠️  Recommended model '{recommended_model}' not found[/yellow]")
        console.print(f"[yellow]To install: [cyan]ollama pull {recommended_model}[/cyan][/yellow]\n")
    else:
        console.print(f"[green]✅ Recommended model '{recommended_model}' is available[/green]\n")
    
    # Check 3: Test generation
    if has_recommended:
        console.print("[yellow]Testing model generation...[/yellow]")
        success = await test_generation(ollama_url, recommended_model)
        
        if success:
            console.print("[green]✅ Model generation test successful[/green]\n")
        else:
            console.print("[red]❌ Model generation test failed[/red]\n")
            sys.exit(1)
    
    # Summary
    console.print(
        Panel(
            "[bold green]✅ All checks passed![/bold green]\n\n"
            f"Ollama URL: [cyan]{ollama_url}[/cyan]\n"
            f"Model: [cyan]{recommended_model}[/cyan]\n"
            f"Models installed: [cyan]{len(models)}[/cyan]\n\n"
            "MEDUSA is ready to use local LLM!",
            title="Verification Complete",
            style="green",
            expand=False
        )
    )
    
    console.print("\n[yellow]Next steps:[/yellow]")
    console.print("  1. Run MEDUSA: [cyan]medusa observe scanme.nmap.org[/cyan]")
    console.print("  2. Or set provider explicitly: [cyan]export MEDUSA_LLM_PROVIDER=local[/cyan]")
    console.print("  3. View documentation: [cyan]docs/OLLAMA_SETUP.md[/cyan]\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Verification cancelled[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)

