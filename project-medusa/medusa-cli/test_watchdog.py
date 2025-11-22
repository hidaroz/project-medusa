#!/usr/bin/env python3
"""
Test script to simulate stuck agent scenarios for watchdog testing

This script helps test the watchdog service by creating various
failure scenarios including:
- Stuck operations (zombie states)
- API health failures
- Timeout scenarios
"""

import asyncio
import sys
import time
from datetime import datetime, timedelta
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


async def simulate_stuck_operation(
    api_url: str = "http://localhost:8000",
    operation_id: str = None
):
    """
    Simulate a stuck operation by creating an operation and then
    manually preventing state updates

    This tests the watchdog's ability to detect zombie states
    """
    console.print(Panel(
        "[yellow]This test simulates a stuck operation to verify watchdog detection[/yellow]",
        title="[bold]Stuck Operation Test[/bold]",
        border_style="yellow"
    ))

    try:
        async with httpx.AsyncClient() as client:
            # 1. Create or get operation
            if operation_id:
                console.print(f"\n[cyan]Using existing operation: {operation_id}[/cyan]")
            else:
                console.print("\n[cyan]Creating test operation...[/cyan]")
                response = await client.post(
                    f"{api_url}/api/operations",
                    json={
                        "target": "test-target.local",
                        "mode": "autonomous",
                        "config": {"test": True}
                    }
                )
                response.raise_for_status()
                operation_id = response.json()["id"]
                console.print(f"[green]✓ Created operation: {operation_id}[/green]")

            # 2. Get initial state
            response = await client.get(f"{api_url}/api/operations/{operation_id}/status")
            response.raise_for_status()
            initial_state = response.json()

            console.print("\n[cyan]Initial operation state:[/cyan]")
            state_table = Table(show_header=False, box=None, padding=(0, 2))
            state_table.add_row("[bold]Status[/bold]", f"[yellow]{initial_state.get('status')}[/yellow]")
            state_table.add_row("[bold]Last Update[/bold]", f"[yellow]{initial_state.get('last_state_update_timestamp')}[/yellow]")
            console.print(state_table)

            # 3. Instructions for manual testing
            console.print("\n" + "="*60)
            console.print(Panel(
                f"""[bold cyan]Manual Test Instructions:[/bold cyan]

1. In a separate terminal, start the watchdog:
   [yellow]medusa watchdog --operation-id {operation_id} --stuck-threshold 60[/yellow]

2. The watchdog will monitor this operation
3. After 60 seconds of no state updates, it should detect the stuck state
4. This simulates an infinite loop or deadlock scenario

[bold]Current operation ID:[/bold] [cyan]{operation_id}[/cyan]

[dim]Press Ctrl+C when done testing[/dim]
""",
                title="[bold green]Ready for Testing[/bold green]",
                border_style="green"
            ))

            # 4. Keep script alive
            try:
                while True:
                    await asyncio.sleep(10)
                    console.print(f"[dim]{datetime.now().strftime('%H:%M:%S')} - Operation still in stuck state (simulated)[/dim]")
            except KeyboardInterrupt:
                console.print("\n[yellow]Test stopped by user[/yellow]")

    except Exception as e:
        console.print(f"\n[red]Error during test: {e}[/red]")
        raise


async def simulate_api_failure(api_url: str = "http://localhost:8000"):
    """
    Test watchdog behavior when API is completely down

    This simulates a complete API failure scenario
    """
    console.print(Panel(
        "[yellow]This test simulates API failure to verify watchdog detection[/yellow]",
        title="[bold]API Failure Test[/bold]",
        border_style="yellow"
    ))

    console.print("\n" + "="*60)
    console.print(Panel(
        f"""[bold cyan]Manual Test Instructions:[/bold cyan]

1. In a separate terminal, start the watchdog:
   [yellow]medusa watchdog --api-url {api_url} --auto-restart[/yellow]

2. While the watchdog is running, stop the MEDUSA API:
   [yellow]docker-compose stop medusa-api[/yellow]
   or
   [yellow]pkill -f api_server.py[/yellow]

3. The watchdog should detect health check failures after 3 consecutive attempts
4. With --auto-restart flag, it will exit with code 1 (for Docker restart)

[bold]Test API URL:[/bold] [cyan]{api_url}[/cyan]

[dim]Press Ctrl+C when done testing[/dim]
""",
        title="[bold green]Ready for Testing[/bold green]",
        border_style="green"
    ))

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Test stopped by user[/yellow]")


async def check_watchdog_status(api_url: str = "http://localhost:8000"):
    """
    Check current API status and running operations

    Useful for verifying the state before running watchdog tests
    """
    console.print(Panel(
        "[cyan]Checking MEDUSA API status and running operations[/cyan]",
        title="[bold]Watchdog Pre-Check[/bold]",
        border_style="cyan"
    ))

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Check health
            console.print("\n[cyan]Checking API health...[/cyan]")
            try:
                response = await client.get(f"{api_url}/health")
                response.raise_for_status()
                health_data = response.json()
                console.print(f"[green]✓ API is healthy: {health_data}[/green]")
            except Exception as e:
                console.print(f"[red]✗ API health check failed: {e}[/red]")
                return

            # Get running operations
            console.print("\n[cyan]Checking for running operations...[/cyan]")
            try:
                response = await client.get(
                    f"{api_url}/api/operations",
                    params={"status": "RUNNING"}
                )
                response.raise_for_status()
                operations = response.json()

                if operations:
                    console.print(f"[yellow]Found {len(operations)} running operation(s):[/yellow]")

                    ops_table = Table(show_header=True)
                    ops_table.add_column("ID", style="cyan")
                    ops_table.add_column("Status", style="yellow")
                    ops_table.add_column("Last Update", style="green")

                    for op in operations:
                        ops_table.add_row(
                            op.get("id", "unknown"),
                            op.get("status", "unknown"),
                            op.get("last_state_update_timestamp", "unknown")
                        )

                    console.print(ops_table)
                else:
                    console.print("[green]No running operations found[/green]")

            except Exception as e:
                console.print(f"[red]✗ Failed to get operations: {e}[/red]")

    except Exception as e:
        console.print(f"[red]Error during status check: {e}[/red]")


async def main():
    """Main test menu"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Test script for MEDUSA watchdog service",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check current API status
  python test_watchdog.py check

  # Simulate a stuck operation
  python test_watchdog.py stuck

  # Test API failure handling
  python test_watchdog.py api-failure

  # Use custom API URL
  python test_watchdog.py check --api-url http://localhost:8080
        """
    )

    parser.add_argument(
        "test_type",
        choices=["check", "stuck", "api-failure"],
        help="Type of test to run"
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="MEDUSA API base URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--operation-id",
        help="Existing operation ID to use for stuck test (optional)"
    )

    args = parser.parse_args()

    console.print("\n[bold cyan]MEDUSA Watchdog Test Suite[/bold cyan]\n")

    if args.test_type == "check":
        await check_watchdog_status(args.api_url)
    elif args.test_type == "stuck":
        await simulate_stuck_operation(args.api_url, args.operation_id)
    elif args.test_type == "api-failure":
        await simulate_api_failure(args.api_url)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
        sys.exit(0)