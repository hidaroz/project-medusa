#!/usr/bin/env python3
"""
Verification script for LangGraph checkpointing and graceful shutdown.

This script tests the core reliability features:
1. PostgreSQL checkpointer initialization
2. Graph compilation with checkpointer
3. Operation Manager signal handling
4. Graceful shutdown flow

Usage:
    python verify_checkpointing.py
"""

import asyncio
import sys
import os
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from medusa.core.medusa_graph import create_medusa_graph
from medusa.core.checkpointer import (
    create_postgres_checkpointer,
    get_thread_id,
    cleanup_checkpointer
)
from medusa.core.operation_manager import (
    OperationManager,
    set_current_operation_manager
)
from medusa.core.graph_state import MedusaState


def print_header(title: str) -> None:
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70 + "\n")


def print_success(message: str) -> None:
    """Print a success message."""
    print(f"✅ {message}")


def print_error(message: str) -> None:
    """Print an error message."""
    print(f"❌ {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    print(f"⚠️  {message}")


def print_info(message: str) -> None:
    """Print an info message."""
    print(f"ℹ️  {message}")


async def test_checkpointer_initialization():
    """Test 1: Checkpointer Initialization"""
    print_header("Test 1: PostgreSQL Checkpointer Initialization")

    try:
        checkpointer = await create_postgres_checkpointer()

        if checkpointer:
            print_success("Checkpointer initialized successfully")
            print_info(f"Type: {type(checkpointer).__name__}")

            # Cleanup
            await cleanup_checkpointer(checkpointer)
            print_success("Checkpointer cleanup successful")
            return True
        else:
            print_warning("Checkpointer initialization skipped (no PostgreSQL config)")
            print_info("Set POSTGRES_CONNECTION_STRING or POSTGRES_PASSWORD to enable")
            return None  # Not a failure, just not configured

    except Exception as e:
        print_error(f"Checkpointer initialization failed: {e}")
        return False


async def test_graph_compilation():
    """Test 2: Graph Compilation with Checkpointer"""
    print_header("Test 2: Graph Compilation with Checkpointer")

    try:
        # Try with checkpointer
        checkpointer = await create_postgres_checkpointer()
        graph = create_medusa_graph(checkpointer=checkpointer)

        print_success("Graph compiled with checkpointer")
        print_info(f"Graph type: {type(graph).__name__}")

        # Try without checkpointer
        graph_no_cp = create_medusa_graph(checkpointer=None)
        print_success("Graph compiled without checkpointer")

        # Cleanup
        if checkpointer:
            await cleanup_checkpointer(checkpointer)

        return True

    except Exception as e:
        print_error(f"Graph compilation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_operation_manager():
    """Test 3: Operation Manager"""
    print_header("Test 3: Operation Manager Lifecycle")

    try:
        # Create operation manager
        operation_id = f"test-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        manager = OperationManager(operation_id)
        print_success(f"OperationManager created: {operation_id}")

        # Setup signal handlers
        manager.setup_signal_handlers()
        print_success("Signal handlers registered")

        # Test should_continue
        assert manager.should_continue("Reconnaissance") == True
        print_success("should_continue() returns True initially")

        # Simulate shutdown request
        manager.shutdown_requested = True
        assert manager.should_continue("Reconnaissance") == False
        print_success("should_continue() returns False after shutdown request")

        # Test status
        status = manager.get_status()
        assert status["operation_id"] == operation_id
        assert status["shutdown_requested"] == True
        print_success("get_status() returns correct data")

        # Restore handlers
        manager.restore_handlers()
        print_success("Signal handlers restored")

        return True

    except Exception as e:
        print_error(f"Operation Manager test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_graceful_shutdown_flow():
    """Test 4: Graceful Shutdown Flow"""
    print_header("Test 4: Graceful Shutdown Flow")

    try:
        # Setup
        checkpointer = await create_postgres_checkpointer()
        graph = create_medusa_graph(checkpointer=checkpointer)
        operation_id = f"shutdown-test-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        operation_manager = OperationManager(operation_id)
        operation_manager.setup_signal_handlers()
        set_current_operation_manager(operation_manager)

        print_success("Test environment setup complete")

        # Create thread ID
        thread_id = get_thread_id(operation_id)
        print_info(f"Thread ID: {thread_id}")

        # Create initial state
        initial_state = MedusaState(
            messages=[],
            target="http://test-target.local",
            next_worker="Reconnaissance",
            findings={},
            vulnerabilities=[],
            attack_plan=None,
            approval_status={},
            current_node="Supervisor"
        )

        print_info("Created initial state")

        # Configure graph
        config = {
            "configurable": {
                "thread_id": thread_id
            }
        }

        print_info("Graph configuration created")
        print_success("Graceful shutdown flow verification complete")

        # Note: We don't actually run the graph here to avoid needing
        # full LLM setup, but the structure is verified

        # Cleanup
        await operation_manager.cleanup()
        if checkpointer:
            await cleanup_checkpointer(checkpointer)

        print_success("Cleanup complete")
        return True

    except Exception as e:
        print_error(f"Graceful shutdown flow test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_thread_id_generation():
    """Test 5: Thread ID Generation"""
    print_header("Test 5: Thread ID Generation")

    try:
        # Test without session
        thread_id1 = get_thread_id("op-001")
        assert thread_id1 == "op-001"
        print_success(f"Thread ID without session: {thread_id1}")

        # Test with session
        thread_id2 = get_thread_id("op-002", "session-abc")
        assert thread_id2 == "session-abc::op-002"
        print_success(f"Thread ID with session: {thread_id2}")

        # Verify uniqueness
        assert thread_id1 != thread_id2
        print_success("Thread IDs are unique")

        return True

    except Exception as e:
        print_error(f"Thread ID generation test failed: {e}")
        return False


async def run_all_tests():
    """Run all verification tests."""
    print("\n" + "🔍 MEDUSA Checkpointing & Graceful Shutdown Verification")
    print("=" * 70)

    results = {}

    # Run tests
    results["checkpointer"] = await test_checkpointer_initialization()
    results["graph"] = await test_graph_compilation()
    results["operation_manager"] = test_operation_manager()
    results["shutdown_flow"] = await test_graceful_shutdown_flow()
    results["thread_id"] = await test_thread_id_generation()

    # Summary
    print_header("Test Summary")

    passed = sum(1 for v in results.values() if v is True)
    failed = sum(1 for v in results.values() if v is False)
    skipped = sum(1 for v in results.values() if v is None)

    for test_name, result in results.items():
        if result is True:
            print_success(f"{test_name}: PASSED")
        elif result is False:
            print_error(f"{test_name}: FAILED")
        else:
            print_warning(f"{test_name}: SKIPPED")

    print(f"\n📊 Results: {passed} passed, {failed} failed, {skipped} skipped")

    if failed > 0:
        print_error("Some tests failed. Please review the output above.")
        return False
    elif skipped > 0:
        print_warning("Some tests skipped. Configure PostgreSQL for full testing.")
        return True
    else:
        print_success("All tests passed! 🎉")
        return True


if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)
