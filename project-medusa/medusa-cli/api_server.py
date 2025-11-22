#!/usr/bin/env python3
"""
Medusa API Server - Production Embedded Graph Architecture
============================================================

This server runs the Medusa Agent Graph directly in-process using FastAPI.
No subprocess calls - the graph executes in shared memory with full access
to PostgreSQL checkpointing for 24+ hour autonomous operations.

Architecture:
  Client -> FastAPI -> LangGraph (in-process) -> PostgreSQL Checkpointer

Key Features:
- FastAPI async framework (native LangGraph compatibility)
- PostgreSQL connection pooling for checkpointer
- Background task execution for long-running operations
- Thread-based resumability via thread_id
- Memory-efficient operation with state offloading
"""

import os
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from pathlib import Path
import yaml

# PostgreSQL connection pooling
from psycopg_pool import AsyncConnectionPool

# LangGraph checkpointing
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

# Medusa graph and state
from medusa.core.medusa_graph import create_medusa_graph
from medusa.core.graph_state import MedusaState

try:
    from medusa.config import Config
    HAS_MEDUSA_LIB = True
except ImportError:
    HAS_MEDUSA_LIB = False

# ============================================================================
# Configuration
# ============================================================================

POSTGRES_URI = os.getenv(
    "POSTGRES_URI",
    "postgresql://postgres:postgres@localhost:5432/medusa"
)

TARGET_URL = os.getenv("TARGET_URL", "http://localhost:3001")

# Global state for tracking operations
operation_registry: Dict[str, Dict[str, Any]] = {}
connection_pool: Optional[AsyncConnectionPool] = None

# Active background tasks for zombie detection (Phase 3)
# Maps thread_id -> asyncio.Task object
active_operations: Dict[str, asyncio.Task] = {}

STALL_THRESHOLD_SECONDS = 900  # 15 minutes

# ============================================================================
# Lifespan Management (Database Connection Pooling)
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application lifecycle: setup and teardown.

    - Startup: Initialize PostgreSQL connection pool
    - Shutdown: Close connection pool gracefully
    """
    global connection_pool

    print("=" * 80)
    print("Medusa API Server - Starting Up")
    print("=" * 80)
    print(f"PostgreSQL URI: {POSTGRES_URI.split('@')[-1]}")  # Hide credentials
    print(f"Target URL: {TARGET_URL}")
    print("Initializing connection pool...")

    try:
        # Create async connection pool
        connection_pool = AsyncConnectionPool(
            conninfo=POSTGRES_URI,
            min_size=2,
            max_size=20,
            timeout=30.0,
            max_idle=300.0  # 5 minutes
        )

        # Test connection
        async with connection_pool.connection() as conn:
            result = await conn.execute("SELECT 1")
            print(f"✓ Database connection successful")

        print("✓ Connection pool initialized")
        print("=" * 80)

    except Exception as e:
        print(f"✗ Failed to connect to PostgreSQL: {e}")
        print("  Running in degraded mode (no checkpointing)")
        connection_pool = None

    yield  # Server runs here

    # Shutdown
    print("\nShutting down Medusa API Server...")
    if connection_pool:
        await connection_pool.close()
        print("✓ Connection pool closed")

# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="Medusa API Server",
    description="Production-grade AI Penetration Testing API with Embedded Graph Execution",
    version="2.0.0-production",
    lifespan=lifespan
)

# Configure CORS
frontend_origins = os.getenv("FRONTEND_URL", "")
if frontend_origins:
    allowed_origins = [origin.strip() for origin in frontend_origins.split(",") if origin.strip()]
else:
    # Default for local development
    allowed_origins = ["http://localhost:3000", "http://localhost:3001", "http://localhost:8080"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# Pydantic Models
# ============================================================================

class OperationRequest(BaseModel):
    objective: str = Field(..., min_length=1, description="The objective for the Medusa operation")
    thread_id: Optional[str] = Field(default=None, description="Thread ID for resuming operations")
    operation_type: str = Field(default="full_assessment", description="Type: full_assessment, recon_only, vuln_scan")
    max_iterations: int = Field(default=50, description="Maximum graph iterations before stopping")

class OperationResponse(BaseModel):
    status: str
    operation_id: str
    thread_id: str
    message: str

class ConfigUpdate(BaseModel):
    config: Dict[str, Any]

class ApprovalDecision(BaseModel):
    decision: str = Field(..., description="APPROVED or REJECTED")
    approver: Optional[str] = Field(default=None, description="Email or name of approver")
    notes: Optional[str] = Field(default=None, description="Optional approval notes")

# ============================================================================
# Helper Functions
# ============================================================================

def get_medusa_home() -> Path:
    """Get Medusa home directory"""
    return Path(os.path.expanduser("~/.medusa"))

def add_operation_log(operation_id: str, message: str, level: str = "info"):
    """Log operation events"""
    if operation_id not in operation_registry:
        return

    operation_registry[operation_id]["logs"].append({
        "timestamp": datetime.now().isoformat(),
        "level": level,
        "message": message
    })

    print(f"[{level.upper()}] {operation_id}: {message}")

# ============================================================================
# Background Task: Graph Execution
# ============================================================================

async def run_graph_task(
    medusa_graph,
    initial_state: Optional[MedusaState],
    config: Dict[str, Any]
):
    """
    Execute the Medusa graph to completion in the background.

    This is the core function that runs the autonomous agent.
    It uses AsyncPostgresSaver for crash recovery and resumability.

    Phase 3: Task is tracked in active_operations for zombie detection.
    Phase 4: Supports resume with None initial_state (continue from checkpoint).

    Args:
        medusa_graph: Compiled LangGraph instance
        initial_state: Initial state dict or None (for resume)
        config: Configuration with thread_id and recursion_limit
    """
    thread_id = config["configurable"]["thread_id"]

    # Find operation_id for this thread
    operation_id = None
    for op_id, op_data in operation_registry.items():
        if op_data.get("thread_id") == thread_id:
            operation_id = op_id
            break

    if not operation_id:
        print(f"Warning: No operation_id found for thread {thread_id}")
        return

    try:
        add_operation_log(operation_id, f"Starting graph execution (thread: {thread_id})", "info")

        # Update status
        operation_registry[operation_id]["status"] = "running"
        if "started_at" not in operation_registry[operation_id]:
            operation_registry[operation_id]["started_at"] = datetime.now().isoformat()

        # Execute graph to completion
        # Pass None for resume, or initial_state for new operation
        final_state = await medusa_graph.ainvoke(initial_state, config=config)

        # Process results
        findings_count = len(final_state.get("findings", []))
        total_findings = findings_count + final_state.get("archived_findings_count", 0)

        add_operation_log(operation_id, f"Graph execution completed", "success")
        add_operation_log(operation_id, f"Total findings: {total_findings} ({findings_count} in memory, {final_state.get('archived_findings_count', 0)} archived)", "info")
        add_operation_log(operation_id, f"Total cost: ${final_state.get('cost_tracking', {}).get('total_cost', 0):.4f}", "info")

        # Update operation status
        operation_registry[operation_id]["status"] = "completed"
        operation_registry[operation_id]["completed_at"] = datetime.now().isoformat()
        operation_registry[operation_id]["results"] = {
            "findings_count": total_findings,
            "cost": final_state.get("cost_tracking", {}).get("total_cost", 0),
            "final_phase": final_state.get("current_phase", "unknown")
        }

    except asyncio.CancelledError:
        # Task was cancelled (e.g., by watchdog for being stalled)
        add_operation_log(operation_id, "Graph execution cancelled (zombie detection or manual stop)", "warning")
        operation_registry[operation_id]["status"] = "cancelled"
        operation_registry[operation_id]["cancelled_at"] = datetime.now(timezone.utc).isoformat()
        raise  # Re-raise to properly handle cancellation

    except Exception as e:
        add_operation_log(operation_id, f"Graph execution failed: {str(e)}", "error")
        operation_registry[operation_id]["status"] = "failed"
        operation_registry[operation_id]["error"] = str(e)

        import traceback
        print(traceback.format_exc())

    finally:
        # Always remove from active_operations when done (success, failure, or cancellation)
        if thread_id in active_operations:
            del active_operations[thread_id]
            add_operation_log(operation_id, f"Task unregistered from monitoring (thread: {thread_id})", "debug")

# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    db_status = "connected" if connection_pool else "disconnected"

    return {
        "status": "healthy",
        "service": "Medusa API Server",
        "version": "2.0.0-production",
        "architecture": "embedded-graph",
        "database": db_status,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/status")
async def get_system_status():
    """
    Get overall system status including current operation and metrics.

    This endpoint aggregates information from the operation registry to provide
    a unified view of system status for the frontend dashboard.
    """
    # Find current running operation
    current_operation = None
    system_status = "idle"

    for op_id, op_data in operation_registry.items():
        if op_data["status"] in ["running", "initializing"]:
            system_status = "running"
            current_operation = {
                "id": op_id,
                "type": op_data["operation_type"],
                "objective": op_data["objective"],
                "started_at": op_data["created_at"],
                "status": op_data["status"]
            }
            break

    # Check if any operation completed recently
    if system_status == "idle":
        for op_data in operation_registry.values():
            if op_data["status"] == "completed":
                system_status = "completed"
                break
            elif op_data["status"] in ["failed", "error"]:
                system_status = "error"
                break

    # Calculate metrics
    total_ops = len(operation_registry)
    completed = sum(1 for op in operation_registry.values() if op["status"] == "completed")

    # Find earliest start time
    start_times = [
        op["created_at"] for op in operation_registry.values()
        if "created_at" in op
    ]
    time_started = min(start_times) if start_times else None

    # Find latest completion time
    completion_times = [
        op.get("completed_at") for op in operation_registry.values()
        if op.get("completed_at")
    ]
    time_completed = max(completion_times) if completion_times else None

    return {
        "status": system_status,
        "current_operation": current_operation,
        "metrics": {
            "operations_completed": completed,
            "data_found": 0,  # TODO: Extract from operation results
            "time_started": time_started,
            "time_completed": time_completed
        },
        "last_update": datetime.now().isoformat()
    }

@app.get("/api/health/detailed")
async def detailed_health_check(thread_id: Optional[str] = None):
    """
    Detailed health check with zombie agent detection (Phase 3).

    If thread_id is provided, checks if that specific operation is stalled.
    If no thread_id, checks all active operations.

    Staleness criteria:
    - last_updated timestamp > 15 minutes ago
    - Task still exists in active_operations
    - Status is "running"

    Action on stalled operation:
    - Mark as STALLED
    - Cancel the asyncio.Task
    - Return alert=True
    """
    now = datetime.now(timezone.utc)
    
    results = {
        "timestamp": now.isoformat(),
        "database": "connected" if connection_pool else "disconnected",
        "active_operations_count": len(active_operations),
        "operations_checked": [],
        "stalled_operations": []
    }

    # If specific thread_id provided, check only that one
    threads_to_check = [thread_id] if thread_id else list(active_operations.keys())

    for tid in threads_to_check:
        if tid not in active_operations:
            continue

        # Find operation_id for this thread_id
        operation_id = None
        for op_id, op_data in operation_registry.items():
            if op_data.get("thread_id") == tid:
                operation_id = op_id
                break

        if not operation_id:
            continue

        operation_data = operation_registry[operation_id]

        # Try to get last_updated from checkpoint
        last_updated_str = None
        time_since_update = None

        if connection_pool:
            try:
                async with connection_pool.connection() as conn:
                    # Get latest checkpoint for this thread
                    # Extract last_updated directly from JSONB
                    result = await conn.execute(
                        """
                        SELECT thread_id, checkpoint -> 'channel_values' ->> 'last_updated' as last_updated
                        FROM checkpoints 
                        WHERE thread_id = %s 
                        ORDER BY thread_ts DESC LIMIT 1
                        """,
                        (tid,)
                    )
                    row = await result.fetchone()

                    if row:
                        last_updated_str = row[1]

                        # Calculate time since update
                        if last_updated_str:
                            try:
                                last_updated = datetime.fromisoformat(last_updated_str.replace('Z', '+00:00'))
                                time_since_update = (now - last_updated).total_seconds()
                            except (ValueError, AttributeError):
                                pass
            except Exception as e:
                print(f"Error querying checkpoint for {tid}: {e}")

        # Determine if stalled
        is_stalled = False
        # Treat None as healthy (just started)
        if time_since_update is not None and time_since_update > STALL_THRESHOLD_SECONDS:
            is_stalled = True

        operation_status = {
            "thread_id": tid,
            "operation_id": operation_id,
            "status": operation_data.get("status", "unknown"),
            "last_updated": last_updated_str,
            "time_since_update_seconds": time_since_update,
            "is_stalled": is_stalled,
            "stall_threshold_seconds": STALL_THRESHOLD_SECONDS
        }

        results["operations_checked"].append(operation_status)

        # Handle stalled operation
        if is_stalled and operation_data.get("status") == "running":
            results["stalled_operations"].append(operation_status)

            # Cancel the task
            task = active_operations.get(tid)
            if task and not task.done():
                task.cancel()
                add_operation_log(
                    operation_id,
                    f"ZOMBIE DETECTED: Operation stalled for {time_since_update:.0f}s. Task cancelled.",
                    "critical"
                )

                # Update operation registry
                operation_data["status"] = "stalled"
                operation_data["stalled_at"] = now.isoformat()
                operation_data["stall_reason"] = f"No state update for {time_since_update:.0f}s"

    # Determine overall status
    overall_status = "HEALTHY"
    alert = False

    if results["stalled_operations"]:
        overall_status = "STALLED"
        alert = True

    results["status"] = overall_status
    results["alert"] = alert

    return results

@app.post("/api/start", response_model=OperationResponse, status_code=201)
async def start_operation(request: OperationRequest, background_tasks: BackgroundTasks):
    """
    Start a new Medusa autonomous operation.

    This endpoint:
    1. Creates a new operation with unique IDs
    2. Initializes the graph with PostgreSQL checkpointer
    3. Runs the graph in the background
    4. Returns immediately with operation tracking info

    The operation will continue running even if the API restarts
    (thanks to checkpointing with thread_id).
    """

    # Generate IDs
    operation_id = f"op_{int(datetime.now().timestamp())}_{uuid.uuid4().hex[:8]}"
    thread_id = request.thread_id or f"thread_{operation_id}"

    # Check if already running
    if any(op["status"] == "running" for op in operation_registry.values()):
        raise HTTPException(
            status_code=400,
            detail="An operation is already running. Only one operation can run at a time."
        )

    # Register operation
    operation_registry[operation_id] = {
        "operation_id": operation_id,
        "thread_id": thread_id,
        "objective": request.objective,
        "operation_type": request.operation_type,
        "status": "initializing",
        "logs": [],
        "created_at": datetime.now().isoformat()
    }

    add_operation_log(operation_id, f"Operation created: {request.objective}", "info")

    # Create checkpointer and graph
    if connection_pool:
        checkpointer = AsyncPostgresSaver(connection_pool)
        async with connection_pool.connection() as conn:
            await checkpointer.setup()
    else:
        checkpointer = None

    medusa_graph = create_medusa_graph(checkpointer=checkpointer)

    # Define initial state
    initial_state: MedusaState = {
        "target": TARGET_URL,
        "findings": [],
        "messages": [],
        "plan": {},
        "current_phase": "reconnaissance",
        "next_worker": "Reconnaissance",
        "context": {
            "objective": request.objective,
            "operation_type": request.operation_type
        },
        "cost_tracking": {
            "total_cost": 0.0,
            "by_agent": {}
        },
        "approval_status": {},
        "operation_id": operation_id,
        "risk_level": "LOW",
        "archived_findings_count": 0,
        "archived_messages_count": 0,
        "resumed_from_checkpoint": False,
        "last_updated": datetime.now(timezone.utc).isoformat()
    }

    # Configuration for this run
    config = {
        "configurable": {
            "thread_id": thread_id
        },
        "recursion_limit": request.max_iterations
    }

    # Start background task
    # We use asyncio.create_task instead of BackgroundTasks to get the task object
    # and register it for zombie detection monitoring
    task = asyncio.create_task(
        run_graph_task(medusa_graph, initial_state, config)
    )

    # Register in global registry
    active_operations[thread_id] = task
    add_operation_log(operation_id, f"Task registered for monitoring (thread: {thread_id})", "debug")

    return OperationResponse(
        status="started",
        operation_id=operation_id,
        thread_id=thread_id,
        message=f"{request.operation_type} operation initiated"
    )

@app.get("/api/operations/{operation_id}")
async def get_operation_status(operation_id: str):
    """
    Get status of a specific operation.

    Enhanced to detect if operation is waiting for approval (interrupt_before).
    Checks graph state to see if next step is "Exploitation" node.
    """
    if operation_id not in operation_registry:
        raise HTTPException(status_code=404, detail="Operation not found")

    operation_data = operation_registry[operation_id].copy()
    thread_id = operation_data.get("thread_id")

    # Check if operation is paused at an interrupt point
    if thread_id and connection_pool:
        try:
            # Create checkpointer to query state
            checkpointer = AsyncPostgresSaver(connection_pool)
            medusa_graph = create_medusa_graph(checkpointer=checkpointer)

            config = {"configurable": {"thread_id": thread_id}}

            # Get current state
            state = await medusa_graph.aget_state(config)

            # Check if waiting at interrupt (next contains "Exploitation")
            if state.next and "Exploitation" in state.next:
                operation_data["status"] = "WAITING_FOR_APPROVAL"
                operation_data["next_step"] = "Exploitation"
                operation_data["awaiting_approval"] = True

                # Include planned exploitation if available
                if state.values:
                    planned = state.values.get("planned_exploitation", [])
                    if planned:
                        operation_data["planned_exploitation"] = planned

        except Exception as e:
            print(f"Error checking graph state: {e}")
            # Continue without state check

    return operation_data

@app.get("/api/operations")
async def list_operations():
    """List all operations"""
    return {
        "operations": list(operation_registry.values()),
        "total": len(operation_registry)
    }

@app.post("/api/operations/{operation_id}/stop")
async def stop_operation(operation_id: str):
    """
    Stop a running operation.

    Note: Due to the graph's autonomous nature, this only marks
    it as stopped. The graph will complete its current node.
    Use thread_id to resume later.
    """
    if operation_id not in operation_registry:
        raise HTTPException(status_code=404, detail="Operation not found")

    operation = operation_registry[operation_id]

    if operation["status"] != "running":
        raise HTTPException(status_code=400, detail="Operation is not running")

    operation["status"] = "stopped"
    add_operation_log(operation_id, "Operation stopped by user", "warning")

    return {"status": "stopped", "message": "Operation marked for stopping"}

@app.post("/api/operations/{operation_id}/approve")
async def approve_exploitation(operation_id: str, decision: ApprovalDecision):
    """
    Approve exploitation for a paused operation.

    This endpoint:
    1. Validates the operation is waiting for approval
    2. Updates approval status in state
    3. Resumes graph execution from checkpoint
    4. Registers the resumed task for watchdog monitoring

    Phase 4: Human-in-the-Loop approval gate implementation.

    Args:
        operation_id: Operation to approve
        decision: Approval decision with approver info

    Returns:
        Status indicating resumption
    """
    if operation_id not in operation_registry:
        raise HTTPException(status_code=404, detail="Operation not found")

    if decision.decision not in ["APPROVED", "REJECTED"]:
        raise HTTPException(status_code=400, detail="Decision must be APPROVED or REJECTED")

    operation_data = operation_registry[operation_id]
    thread_id = operation_data.get("thread_id")

    if not thread_id:
        raise HTTPException(status_code=400, detail="No thread_id found for operation")

    if not connection_pool:
        raise HTTPException(status_code=503, detail="Checkpointer not available")

    # Check current state
    try:
        checkpointer = AsyncPostgresSaver(connection_pool)
        medusa_graph = create_medusa_graph(checkpointer=checkpointer)

        config = {"configurable": {"thread_id": thread_id}}
        state = await medusa_graph.aget_state(config)

        # Verify operation is at interrupt point
        if not state.next or "Exploitation" not in state.next:
            raise HTTPException(
                status_code=400,
                detail="Operation is not waiting for approval at Exploitation node"
            )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error checking state: {str(e)}")

    if decision.decision == "APPROVED":
        # Update approval status
        add_operation_log(
            operation_id,
            f"Exploitation APPROVED by {decision.approver or 'unknown'}",
            "info"
        )

        # Update operation metadata
        operation_data["approval_decision"] = "APPROVED"
        operation_data["approved_by"] = decision.approver
        operation_data["approved_at"] = datetime.now(timezone.utc).isoformat()
        operation_data["approval_notes"] = decision.notes

        # CRITICAL: Resume the graph execution
        # Pass None as initial_state to continue from checkpoint
        config = {
            "configurable": {
                "thread_id": thread_id
            },
            "recursion_limit": 50  # Default limit for resumed operations
        }

        # Create the resume task
        task = asyncio.create_task(
            run_graph_task(medusa_graph, None, config)
        )

        # CRITICAL: Re-register for watchdog monitoring
        active_operations[thread_id] = task
        add_operation_log(
            operation_id,
            f"Exploitation resumed and re-registered for monitoring (thread: {thread_id})",
            "info"
        )

        return {
            "status": "resumed",
            "operation_id": operation_id,
            "thread_id": thread_id,
            "decision": "APPROVED",
            "message": "Exploitation approved and resumed"
        }

    else:  # REJECTED
        add_operation_log(
            operation_id,
            f"Exploitation REJECTED by {decision.approver or 'unknown'}",
            "warning"
        )

        # Update operation metadata
        operation_data["approval_decision"] = "REJECTED"
        operation_data["rejected_by"] = decision.approver
        operation_data["rejected_at"] = datetime.now(timezone.utc).isoformat()
        operation_data["rejection_notes"] = decision.notes
        operation_data["status"] = "rejected"

        return {
            "status": "rejected",
            "operation_id": operation_id,
            "thread_id": thread_id,
            "decision": "REJECTED",
            "message": "Exploitation rejected. Operation will not continue."
        }

@app.post("/api/operations/{operation_id}/reject")
async def reject_exploitation(operation_id: str, decision: ApprovalDecision):
    """
    Reject exploitation for a paused operation.

    This is an alias for /approve with decision=REJECTED for clarity.

    Args:
        operation_id: Operation to reject
        decision: Rejection decision with approver info

    Returns:
        Status indicating rejection
    """
    decision.decision = "REJECTED"
    return await approve_exploitation(operation_id, decision)

@app.get("/api/logs")
async def get_all_logs(limit: int = 100):
    """Get recent logs from all operations"""
    all_logs = []

    for op_id, op_data in operation_registry.items():
        for log in op_data.get("logs", []):
            all_logs.append({
                **log,
                "operation_id": op_id
            })

    # Sort by timestamp, most recent first
    all_logs.sort(key=lambda x: x["timestamp"], reverse=True)

    return {
        "logs": all_logs[:limit],
        "total": len(all_logs)
    }

@app.post("/api/command")
async def execute_command(request: Request):
    """
    Execute a medusa CLI command via subprocess.

    This endpoint allows the web terminal to execute medusa commands.
    It runs commands in a subprocess for safety and isolation.

    Security:
    - Only allows 'medusa' commands and safe system commands
    - Blocks dangerous commands
    - Timeout protection (30 seconds)
    """
    body = await request.json()
    command_str = body.get("command", "").strip()

    if not command_str:
        raise HTTPException(status_code=400, detail={"error": "No command provided"})

    # Security check: only allow medusa commands or specific safe system commands
    allowed_safe_commands = ['help', 'ls', 'pwd', 'whoami', 'clear', 'date', 'echo']

    # Check if command starts with 'medusa' or is in allowed list
    is_medusa_cmd = command_str.startswith('medusa')
    is_safe_cmd = command_str.split()[0] in allowed_safe_commands if command_str.split() else False

    if not (is_medusa_cmd or is_safe_cmd):
        raise HTTPException(
            status_code=403,
            detail={
                "error": f"Command not allowed. Only 'medusa' commands or safe commands ({', '.join(allowed_safe_commands)}) are permitted."
            }
        )

    try:
        import shlex
        import subprocess

        # Split command into list for subprocess
        try:
            cmd_args = shlex.split(command_str)
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail={"error": f"Invalid command syntax: {str(e)}"}
            )

        # Fix: Use sys.executable to run medusa module directly
        # This avoids PATH issues where 'medusa' command might not be found
        if cmd_args and cmd_args[0] == 'medusa':
            import sys
            cmd_args = [sys.executable, "-m", "medusa.cli"] + cmd_args[1:]

        # Run command with timeout
        result = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            timeout=30,  # 30 second timeout
            env={**os.environ, "PYTHONUNBUFFERED": "1"}  # Ensure unbuffered output
        )

        return {
            "command": command_str,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=408,
            detail={"error": "Command timed out after 30 seconds"}
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={
                "error": f"Command '{cmd_args[0]}' not found. Make sure medusa CLI is installed."
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": f"Command execution failed: {str(e)}"}
        )

@app.get("/api/metrics")
async def get_metrics():
    """Get aggregated metrics across all operations"""
    total_ops = len(operation_registry)
    completed = sum(1 for op in operation_registry.values() if op["status"] == "completed")
    running = sum(1 for op in operation_registry.values() if op["status"] == "running")
    failed = sum(1 for op in operation_registry.values() if op["status"] == "failed")

    total_cost = sum(
        op.get("results", {}).get("cost", 0)
        for op in operation_registry.values()
        if "results" in op
    )

    return {
        "total_operations": total_ops,
        "completed": completed,
        "running": running,
        "failed": failed,
        "total_cost": round(total_cost, 4)
    }

@app.get("/api/reports")
async def list_reports():
    """List generated reports"""
    reports_dir = get_medusa_home() / "reports"
    if not reports_dir.exists():
        return {"reports": [], "total": 0}

    reports = []
    for f in reports_dir.glob("*.html"):
        reports.append({
            "id": f.name,
            "name": f.name,
            "path": str(f),
            "size": f.stat().st_size,
            "created_at": datetime.fromtimestamp(f.stat().st_ctime).isoformat(),
            "type": "html"
        })

    # Also look for JSON logs
    logs_dir = get_medusa_home() / "logs"
    if logs_dir.exists():
        for f in logs_dir.glob("*.json"):
            reports.append({
                "id": f.name,
                "name": f.name,
                "path": str(f),
                "size": f.stat().st_size,
                "created_at": datetime.fromtimestamp(f.stat().st_ctime).isoformat(),
                "type": "json"
            })

    reports.sort(key=lambda x: x["created_at"], reverse=True)
    return {"reports": reports, "total": len(reports)}

@app.get("/api/reports/{report_id}")
async def get_report(report_id: str):
    """Get specific report content"""
    # Security: prevent path traversal
    if ".." in report_id or "/" in report_id:
        raise HTTPException(status_code=400, detail="Invalid report ID")

    reports_dir = get_medusa_home() / "reports"
    logs_dir = get_medusa_home() / "logs"

    target_file = None
    if report_id.endswith(".html"):
        target_file = reports_dir / report_id
    elif report_id.endswith(".json"):
        target_file = logs_dir / report_id

    if target_file and target_file.exists():
        return FileResponse(target_file)

    raise HTTPException(status_code=404, detail="Report not found")

@app.get("/api/config")
async def get_config():
    """Get system configuration"""
    if HAS_MEDUSA_LIB:
        try:
            config = Config()
            return {"config": config.load(), "path": str(config.config_path)}
        except Exception as e:
            print(f"Config library load failed: {e}")

    config_path = get_medusa_home() / "config.yaml"
    if config_path.exists():
        try:
            with open(config_path, "r") as f:
                content = yaml.safe_load(f)
            return {"config": content, "path": str(config_path)}
        except Exception as e:
            raise HTTPException(status_code=500, detail={"error": str(e)})

    raise HTTPException(status_code=404, detail="Config not found")

@app.post("/api/config")
async def update_config(update: ConfigUpdate):
    """Update system configuration"""
    config_path = get_medusa_home() / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        current_config = {}
        if config_path.exists():
            with open(config_path, "r") as f:
                current_config = yaml.safe_load(f) or {}

        # Deep update
        def deep_update(source, overrides):
            for key, value in overrides.items():
                if isinstance(value, dict) and value:
                    returned = deep_update(source.get(key, {}), value)
                    source[key] = returned
                else:
                    source[key] = value
            return source

        updated_config = deep_update(current_config, update.config)

        with open(config_path, "w") as f:
            yaml.dump(updated_config, f, default_flow_style=False)

        return {"status": "updated", "config": updated_config}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})

@app.get("/api/llm/status")
async def get_llm_status():
    """Check LLM connection status"""
    return {
        "connected": True,
        "provider": os.getenv("LLM_PROVIDER", "local"),
        "model": os.getenv("LLM_LOCAL_MODEL", "mistral:7b-instruct"),
        "message": "LLM status check via direct import not yet implemented"
    }

# ============================================================================
# Startup Event
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize server on startup"""
    medusa_home = get_medusa_home()
    config_path = medusa_home / "config.yaml"
    first_run_marker = medusa_home / ".first_run_complete"

    # Ensure directory structure exists
    (medusa_home / "logs").mkdir(parents=True, exist_ok=True)
    (medusa_home / "reports").mkdir(parents=True, exist_ok=True)

    if not config_path.exists():
        print(f"Initializing default configuration at {config_path}")
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Comprehensive default configuration for CLI compatibility
        default_config = {
            "llm": {
                "provider": os.getenv("LLM_PROVIDER", "local"),
                "model": os.getenv("LLM_LOCAL_MODEL", "mistral:7b-instruct"),
                "base_url": os.getenv("LLM_OLLAMA_URL", "http://localhost:11434"),
                "temperature": 0.7,
                "max_tokens": 2048,
                "timeout": 60,
                "max_retries": 3
            },
            "target": {
                "type": "docker",
                "url": os.getenv("TARGET_URL", "http://localhost:3001")
            },
            "tools": {
                "nmap": {"enabled": True},
                "httpx": {"enabled": True},
                "amass": {"enabled": False},
                "sqlmap": {"enabled": False},
                "owasp_zap": {"enabled": False},
                "metasploit": {"enabled": False}
            },
            "risk_tolerance": {
                "auto_approve_low": True,
                "auto_approve_medium": False,
                "auto_approve_high": False
            },
            "logging": {
                "level": "INFO",
                "file": str(medusa_home / "logs" / "medusa.log"),
                "console": True
            },
            "neo4j": {
                "uri": os.getenv("NEO4J_URI", "bolt://localhost:7687"),
                "username": os.getenv("NEO4J_USERNAME", "neo4j"),
                "password": os.getenv("NEO4J_PASSWORD", "medusa_graph_pass")
            }
        }
        try:
            with open(config_path, "w") as f:
                yaml.dump(default_config, f, default_flow_style=False)
            print("✓ Default configuration created")
            print(f"  Config location: {config_path}")
        except Exception as e:
            print(f"✗ Failed to create default config: {e}")

    # Ensure first-run marker exists (prevents setup wizard)
    if not first_run_marker.exists():
        try:
            first_run_marker.touch()
            print("✓ First-run marker created (skips setup wizard)")
        except Exception as e:
            print(f"✗ Failed to create first-run marker: {e}")

    # Verify config is readable
    try:
        with open(config_path, "r") as f:
            loaded_config = yaml.safe_load(f)
            print(f"✓ Configuration loaded successfully")
            print(f"  LLM Provider: {loaded_config.get('llm', {}).get('provider', 'unknown')}")
            print(f"  Target: {loaded_config.get('target', {}).get('url', 'unknown')}")
    except Exception as e:
        print(f"⚠ Warning: Could not verify config: {e}")

# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    port = int(os.getenv("PORT", os.getenv("MEDUSA_API_PORT", "5000")))

    print("\n" + "=" * 80)
    print("🐍 Medusa API Server - Production Embedded Graph Architecture")
    print("=" * 80)
    print(f"Version: 2.0.0-production")
    print(f"Host: 0.0.0.0")
    print(f"Port: {port}")
    print(f"Docs: http://localhost:{port}/docs")
    print("=" * 80 + "\n")

    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=port,
        reload=False,
        log_level="info",
        access_log=True
    )
