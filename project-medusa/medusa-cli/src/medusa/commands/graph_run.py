import asyncio
import typer
from rich.console import Console
from rich.panel import Panel
from rich.status import Status
from typing import Optional
from langchain_core.messages import HumanMessage

from medusa.core.medusa_graph import create_medusa_graph
from medusa.config import get_config

console = Console()

def run_graph_command(
    target: str = typer.Argument(..., help="Target to scan (e.g. scanme.nmap.org)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed graph events"),
):
    """
    Run the autonomous agent graph against a target.
    """
    asyncio.run(execute_graph(target, verbose))

async def execute_graph(target: str, verbose: bool):
    """Execute the LangGraph workflow."""
    
    console.print(Panel(f"[bold cyan]Starting Medusa Autonomous Graph[/bold cyan]\nTarget: {target}", border_style="cyan"))
    
    # Initialize graph
    try:
        graph = create_medusa_graph()
    except Exception as e:
        console.print(f"[red]Error initializing graph: {e}[/red]")
        return

    # Initial state
    initial_state = {
        "messages": [HumanMessage(content=f"Scan {target} and report findings.")],
        "findings": [],
        "plan": {},
        "current_phase": "start",
        "next_worker": "Supervisor",
        "context": {"target": target},
        # Initialize new fields to avoid key errors before we update the state definition fully
        "cost_tracking": {}, 
        "approval_status": {},
        "operation_id": f"op-{target.replace('.', '-')}",
        "risk_level": "LOW"
    }
    
    console.print(f"[yellow]Initializing agents and LLM clients...[/yellow]")
    
    with console.status("[bold green]Running autonomous agents...[/bold green]") as status:
        try:
            async for event in graph.astream(initial_state):
                for key, value in event.items():
                    if key == "Supervisor":
                        next_node = value.get("next_worker", "Unknown")
                        status.update(f"[bold blue]Supervisor[/bold blue] deciding next step: [cyan]{next_node}[/cyan]")
                        console.print(f" > [bold blue]Supervisor[/bold blue] routed to: [cyan]{next_node}[/cyan]")
                    else:
                        status.update(f"[bold green]Agent Working:[/bold green] {key}")
                        console.print(f" > [bold green]{key}[/bold green] completed task.")
                        
                        # Show messages if any
                        if "messages" in value and value["messages"]:
                            last_msg = value["messages"][-1]
                            console.print(Panel(last_msg.content, title=f"Output from {key}", border_style="green"))
                        
                        # Show findings count
                        if "findings" in value:
                            count = len(value["findings"])
                            if count > 0:
                                console.print(f"   Found {count} items")

            console.print(Panel("[bold green]Graph Execution Completed Successfully[/bold green]", border_style="green"))
            
        except Exception as e:
            console.print(f"[red]Error during graph execution: {e}[/red]")
            import traceback
            console.print(traceback.format_exc())

