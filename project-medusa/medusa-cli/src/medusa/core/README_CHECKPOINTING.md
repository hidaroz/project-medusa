# LangGraph Checkpointing & Graceful Shutdown Guide

## Overview

MEDUSA now uses LangGraph's native PostgreSQL checkpointing for crash recovery and graceful shutdown capabilities. This ensures that operations can be interrupted and resumed exactly where they left off.

## Key Features

1. **Automatic State Persistence**: Graph state is automatically saved to PostgreSQL
2. **Crash Recovery**: Resume operations after crashes or interruptions
3. **Graceful Shutdown**: CTRL+C allows current node to finish before pausing
4. **Thread-based Sessions**: Use `thread_id` to identify and resume operations

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MEDUSA Operation                     │
└─────────────────────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  LangGraph   │  │ PostgreSQL   │  │ Operation    │
│  Graph       │  │ Checkpointer │  │ Manager      │
│              │  │              │  │              │
│ - Nodes      │  │ - State      │  │ - Signals    │
│ - Edges      │  │ - History    │  │ - Shutdown   │
│ - Routing    │  │ - Resume     │  │ - Lifecycle  │
└──────────────┘  └──────────────┘  └──────────────┘
```

## Setup

### 1. Install Dependencies

```bash
cd medusa-cli
pip install -r requirements.txt
```

This installs:
- `langgraph-checkpoint-postgres>=1.0.0`
- `psycopg>=3.1.0`
- `psycopg-pool>=3.1.0`

### 2. Setup PostgreSQL

You can use Docker for easy PostgreSQL setup:

```bash
docker run -d \
  --name medusa-postgres \
  -e POSTGRES_USER=medusa \
  -e POSTGRES_PASSWORD=medusa_checkpoint_pass \
  -e POSTGRES_DB=medusa \
  -p 5432:5432 \
  postgres:15
```

### 3. Configure Environment

Set environment variables in `.env` or your shell:

```bash
# Option 1: Full connection string
export POSTGRES_CONNECTION_STRING="postgresql://medusa:medusa_checkpoint_pass@localhost:5432/medusa"

# Option 2: Individual components (will be combined automatically)
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_DB=medusa
export POSTGRES_USER=medusa
export POSTGRES_PASSWORD=medusa_checkpoint_pass
```

## Usage

### Basic Usage with Checkpointing

```python
import asyncio
from medusa.core.medusa_graph import create_medusa_graph
from medusa.core.checkpointer import create_postgres_checkpointer, get_thread_id
from medusa.core.operation_manager import OperationManager, set_current_operation_manager
from medusa.core.graph_state import MedusaState

async def run_pentest_with_checkpointing(target: str, operation_id: str):
    """
    Run a penetration test with checkpointing enabled.

    Args:
        target: Target URL or IP address
        operation_id: Unique identifier for this operation
    """
    # 1. Create the checkpointer
    checkpointer = await create_postgres_checkpointer()

    if not checkpointer:
        print("⚠️  Warning: Running without checkpointing (no PostgreSQL)")

    # 2. Create the graph with checkpointer
    graph = create_medusa_graph(checkpointer=checkpointer)

    # 3. Setup operation manager for graceful shutdown
    operation_manager = OperationManager(operation_id)
    operation_manager.setup_signal_handlers()
    set_current_operation_manager(operation_manager)

    # 4. Generate thread ID for this operation
    thread_id = get_thread_id(operation_id)

    # 5. Configure graph execution
    config = {
        "configurable": {
            "thread_id": thread_id
        }
    }

    # 6. Create initial state
    initial_state = MedusaState(
        messages=[],
        target=target,
        next_worker="Reconnaissance",
        findings={},
        vulnerabilities=[],
        attack_plan=None,
        approval_status={},
        current_node="Supervisor"
    )

    try:
        print(f"🚀 Starting operation: {operation_id}")
        print(f"🎯 Target: {target}")
        print(f"💾 Thread ID: {thread_id}")

        # 7. Run the graph
        # If this thread_id has a checkpoint, it will resume from there
        result = await graph.ainvoke(initial_state, config)

        print("\n✅ Operation completed successfully!")
        return result

    except KeyboardInterrupt:
        print("\n⚠️  Operation interrupted by user")

    except Exception as e:
        print(f"\n❌ Operation failed: {e}")

    finally:
        # Cleanup
        await operation_manager.cleanup()

        if checkpointer:
            from medusa.core.checkpointer import cleanup_checkpointer
            await cleanup_checkpointer(checkpointer)

# Run it
asyncio.run(run_pentest_with_checkpointing("http://example.com", "pentest-001"))
```

### Resuming from Checkpoint

If an operation is interrupted (CTRL+C, crash, etc.), you can resume it:

```python
async def resume_operation(operation_id: str):
    """Resume a paused or crashed operation."""

    # Same setup
    checkpointer = await create_postgres_checkpointer()
    graph = create_medusa_graph(checkpointer=checkpointer)
    operation_manager = OperationManager(f"{operation_id}-resumed")
    operation_manager.setup_signal_handlers()
    set_current_operation_manager(operation_manager)

    # IMPORTANT: Use the SAME thread_id
    thread_id = get_thread_id(operation_id)
    config = {"configurable": {"thread_id": thread_id}}

    # Check if checkpoint exists
    from medusa.core.checkpointer import get_latest_checkpoint
    checkpoint = await get_latest_checkpoint(checkpointer, thread_id)

    if not checkpoint:
        print(f"❌ No checkpoint found for operation: {operation_id}")
        return

    print(f"📌 Found checkpoint - resuming operation: {operation_id}")

    # Resume by invoking with same thread_id
    # LangGraph will automatically load the checkpoint and continue
    result = await graph.ainvoke(None, config)  # State loaded from checkpoint

    print("✅ Operation resumed and completed!")
    return result

# Resume a previous operation
asyncio.run(resume_operation("pentest-001"))
```

### Graceful Shutdown Example

When you press CTRL+C during execution:

```
🚀 Starting operation: pentest-001
🎯 Target: http://example.com
💾 Thread ID: pentest-001

[Supervisor] Routing to Reconnaissance...
[Reconnaissance] Scanning ports...
^C
🛑 Graceful shutdown requested. Current node will finish and state will be saved...
   Press Ctrl+C again to force quit (not recommended)

[Reconnaissance] Scan complete. Found 5 open ports.
[Supervisor] Checking shutdown status...

✅ Current node completed. Saving state and pausing...

💾 State saved to checkpoint: pentest-001
🔄 Resume with: medusa resume pentest-001
```

## How It Works

### 1. Checkpointer Integration

The graph is compiled with a checkpointer:

```python
# medusa/core/medusa_graph.py
def create_medusa_graph(checkpointer: Optional[BaseCheckpointSaver] = None):
    workflow = StateGraph(MedusaState)
    # ... add nodes and edges ...
    return workflow.compile(checkpointer=checkpointer)
```

### 2. Thread-Based Sessions

Each operation has a unique `thread_id`:

```python
thread_id = get_thread_id("pentest-001")
config = {"configurable": {"thread_id": thread_id}}
```

LangGraph uses this to:
- Save state after each node execution
- Load state when resuming
- Maintain execution history

### 3. Graceful Shutdown Flow

```
1. User presses CTRL+C
   ↓
2. OperationManager catches SIGINT
   ↓
3. Sets shutdown_requested = True
   ↓
4. Current node continues execution
   ↓
5. Supervisor checks should_continue()
   ↓
6. Returns "PAUSE" instead of next worker
   ↓
7. Graph routes to END
   ↓
8. State automatically saved to PostgreSQL
```

### 4. Supervisor Integration

The supervisor checks for shutdown before routing:

```python
# medusa/core/supervisor.py
async def supervisor_node(state: MedusaState) -> Dict[str, Any]:
    # Check for shutdown request
    operation_manager = get_current_operation_manager()
    if operation_manager:
        if not operation_manager.should_continue(state.get("current_node")):
            return {"next_worker": "PAUSE"}

    # Normal LLM-based routing...
```

## PostgreSQL Schema

The checkpointer creates these tables automatically:

```sql
-- Checkpoint storage
CREATE TABLE checkpoints (
    thread_id TEXT,
    thread_ts TIMESTAMP,
    parent_ts TIMESTAMP,
    checkpoint JSONB,
    metadata JSONB,
    PRIMARY KEY (thread_id, thread_ts)
);

-- Checkpoint writes (for tracking)
CREATE TABLE checkpoint_writes (
    thread_id TEXT,
    thread_ts TIMESTAMP,
    task_id TEXT,
    idx INTEGER,
    channel TEXT,
    value JSONB,
    PRIMARY KEY (thread_id, thread_ts, task_id, idx)
);
```

## Querying Checkpoints

You can inspect checkpoints directly:

```sql
-- List all operations
SELECT DISTINCT thread_id, MAX(thread_ts) as latest_checkpoint
FROM checkpoints
GROUP BY thread_id
ORDER BY latest_checkpoint DESC;

-- View specific operation state
SELECT checkpoint, metadata
FROM checkpoints
WHERE thread_id = 'pentest-001'
ORDER BY thread_ts DESC
LIMIT 1;

-- Check operation history
SELECT thread_ts, metadata->>'step' as step
FROM checkpoints
WHERE thread_id = 'pentest-001'
ORDER BY thread_ts ASC;
```

## CLI Integration Example

Here's how to integrate with the CLI:

```python
# medusa/cli.py

@app.command("run")
async def run_pentest(
    target: str,
    operation_id: Optional[str] = None,
    resume: bool = False
):
    """Run or resume a penetration test."""

    # Generate operation ID if not provided
    if not operation_id:
        operation_id = f"pentest-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    # Initialize checkpointer
    checkpointer = await create_postgres_checkpointer()

    if resume:
        # Check if checkpoint exists
        checkpoint = await get_latest_checkpoint(checkpointer, operation_id)
        if not checkpoint:
            console.print(f"[red]No checkpoint found for: {operation_id}[/red]")
            return
        console.print(f"[green]Resuming operation: {operation_id}[/green]")
    else:
        console.print(f"[green]Starting new operation: {operation_id}[/green]")

    # Run with checkpointing
    await run_pentest_with_checkpointing(target, operation_id)


@app.command("resume")
async def resume_command(operation_id: str):
    """Resume a paused operation."""
    await run_pentest(target=None, operation_id=operation_id, resume=True)


@app.command("list-operations")
async def list_operations():
    """List all saved operations."""
    checkpointer = await create_postgres_checkpointer()
    checkpoints = await list_checkpoints(checkpointer)

    table = Table(title="Saved Operations")
    table.add_column("Operation ID")
    table.add_column("Last Checkpoint")
    table.add_column("Status")

    for cp in checkpoints:
        table.add_row(cp['thread_id'], cp['ts'], cp['status'])

    console.print(table)
```

## Testing

### Unit Tests

```python
import pytest
from medusa.core.operation_manager import OperationManager

@pytest.mark.asyncio
async def test_graceful_shutdown():
    manager = OperationManager("test-001")

    # Should continue initially
    assert manager.should_continue("Reconnaissance") == True

    # Request shutdown
    manager.shutdown_requested = True

    # Should not continue
    assert manager.should_continue("Reconnaissance") == False
```

### Integration Tests

```python
@pytest.mark.asyncio
async def test_checkpoint_resume():
    checkpointer = await create_postgres_checkpointer()
    graph = create_medusa_graph(checkpointer=checkpointer)

    thread_id = get_thread_id("test-resume-001")
    config = {"configurable": {"thread_id": thread_id}}

    # Run partially
    state = MedusaState(target="http://test.com", next_worker="Reconnaissance")

    # Simulate interruption after one step
    # (Implementation depends on test setup)

    # Resume
    result = await graph.ainvoke(None, config)

    # Verify state was preserved
    assert result["target"] == "http://test.com"
```

## Troubleshooting

### Checkpointing Not Working

1. **Check PostgreSQL connection**:
   ```bash
   psql -h localhost -U medusa -d medusa -c "SELECT 1"
   ```

2. **Verify environment variables**:
   ```bash
   echo $POSTGRES_CONNECTION_STRING
   ```

3. **Check logs**:
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

### State Not Resuming

1. **Verify thread_id is the same**:
   - The same `thread_id` must be used for resume

2. **Check checkpoint exists**:
   ```python
   checkpoint = await get_latest_checkpoint(checkpointer, thread_id)
   print(checkpoint)
   ```

### Graceful Shutdown Not Working

1. **Verify OperationManager is set**:
   ```python
   from medusa.core.operation_manager import get_current_operation_manager
   mgr = get_current_operation_manager()
   assert mgr is not None
   ```

2. **Check signal handlers**:
   ```python
   operation_manager.setup_signal_handlers()
   ```

## Best Practices

1. **Always use unique operation IDs**: Prevents checkpoint conflicts
2. **Set descriptive thread IDs**: Include timestamps or user context
3. **Handle cleanup**: Always call `cleanup()` in `finally` blocks
4. **Log checkpoints**: Track when state is saved
5. **Test resume**: Regularly test resume functionality
6. **Monitor PostgreSQL**: Keep an eye on database size and performance

## Performance Considerations

- **Checkpoint overhead**: ~10-50ms per node (depends on state size)
- **Database size**: Grows with number of operations and state complexity
- **Connection pooling**: Use `psycopg-pool` for better performance
- **Cleanup**: Implement checkpoint cleanup for old operations

## Future Enhancements

- [ ] Automatic checkpoint cleanup (TTL-based)
- [ ] Checkpoint compression for large states
- [ ] Multiple checkpoint strategies (Redis, SQLite, etc.)
- [ ] Checkpoint visualization in web dashboard
- [ ] Checkpoint export/import for migration
- [ ] Distributed checkpointing for multi-agent scenarios

---

**Last Updated**: 2025-11-20
**Module Version**: 2.0.0
