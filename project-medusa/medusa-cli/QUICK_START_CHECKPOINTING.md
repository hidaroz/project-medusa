# Quick Start: Checkpointing & Graceful Shutdown

## 🚀 5-Minute Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Setup PostgreSQL

```bash
docker run -d \
  --name medusa-postgres \
  -e POSTGRES_USER=medusa \
  -e POSTGRES_PASSWORD=medusa_pass \
  -e POSTGRES_DB=medusa \
  -p 5432:5432 \
  postgres:15
```

### 3. Configure Environment

```bash
export POSTGRES_CONNECTION_STRING="postgresql://medusa:medusa_pass@localhost:5432/medusa"
```

---

## 💻 Basic Usage

### Run with Checkpointing

```python
import asyncio
from medusa.core.medusa_graph import create_medusa_graph
from medusa.core.checkpointer import create_postgres_checkpointer, get_thread_id
from medusa.core.operation_manager import OperationManager, set_current_operation_manager
from medusa.core.graph_state import MedusaState

async def main():
    # Setup
    checkpointer = await create_postgres_checkpointer()
    graph = create_medusa_graph(checkpointer=checkpointer)

    # Operation manager for graceful shutdown
    op_mgr = OperationManager("op-001")
    op_mgr.setup_signal_handlers()
    set_current_operation_manager(op_mgr)

    # Configure thread
    config = {"configurable": {"thread_id": get_thread_id("op-001")}}

    # Initial state
    state = MedusaState(
        target="http://target.com",
        next_worker="Reconnaissance",
        messages=[], findings={}, vulnerabilities=[],
        attack_plan=None, approval_status={}, current_node="Supervisor"
    )

    # Run (auto-saves checkpoints)
    result = await graph.ainvoke(state, config)

    # Cleanup
    await op_mgr.cleanup()

asyncio.run(main())
```

### Resume After Interruption

```python
async def resume():
    checkpointer = await create_postgres_checkpointer()
    graph = create_medusa_graph(checkpointer=checkpointer)

    # SAME thread_id as before
    config = {"configurable": {"thread_id": get_thread_id("op-001")}}

    # Resume (state loaded automatically)
    result = await graph.ainvoke(None, config)

asyncio.run(resume())
```

---

## 🎮 User Experience

### Starting Operation
```bash
$ medusa run http://target.com --operation-id pentest-001
🚀 Starting operation: pentest-001
🎯 Target: http://target.com
💾 Thread ID: pentest-001

[Supervisor] Routing to Reconnaissance...
[Reconnaissance] Scanning ports...
```

### Graceful Shutdown (Ctrl+C)
```bash
[Reconnaissance] Scanning 192.168.1.1...
^C
🛑 Graceful shutdown requested. Current node will finish and state will be saved...
   Press Ctrl+C again to force quit (not recommended)

[Reconnaissance] Scan complete. Found 5 open ports.
✅ Current node completed. Saving state and pausing...
💾 State saved to checkpoint: pentest-001
```

### Resuming
```bash
$ medusa resume pentest-001
📌 Found checkpoint - resuming operation: pentest-001
[Supervisor] Routing to VulnerabilityAnalysis...
[VulnerabilityAnalysis] Analyzing findings...
```

---

## 🔑 Key Concepts

| Concept | Description | Example |
|---------|-------------|---------|
| **Thread ID** | Unique operation identifier | `"pentest-001"` |
| **Checkpointer** | PostgreSQL state saver | `AsyncPostgresSaver` |
| **Operation Manager** | Handles signals & shutdown | `OperationManager("op-001")` |
| **Config** | Graph runtime config | `{"configurable": {"thread_id": "op-001"}}` |

---

## 🔧 Architecture

```
User Code
    ↓
┌───────────────────┐
│ OperationManager  │ ← Handles Ctrl+C
└───────────────────┘
    ↓
┌───────────────────┐
│  MedusaGraph      │ ← Nodes & routing
└───────────────────┘
    ↓
┌───────────────────┐
│  Checkpointer     │ ← Saves to PostgreSQL
└───────────────────┘
```

---

## 📋 Checklist

Before running:
- [ ] PostgreSQL running (`docker ps | grep postgres`)
- [ ] Environment variable set (`echo $POSTGRES_CONNECTION_STRING`)
- [ ] Dependencies installed (`pip list | grep langgraph`)

For resuming:
- [ ] Use same `thread_id`
- [ ] Checkpointer initialized
- [ ] Same graph configuration

---

## 🆘 Troubleshooting

**Can't connect to PostgreSQL?**
```bash
psql -h localhost -U medusa -d medusa
# Password: medusa_pass
```

**Checkpoint not found?**
```sql
SELECT thread_id FROM checkpoints;
```

**State not resuming?**
- Verify identical `thread_id`
- Check checkpoint exists in DB
- Ensure same graph definition

---

## 📚 Full Documentation

- **Comprehensive Guide**: [README_CHECKPOINTING.md](src/medusa/core/README_CHECKPOINTING.md)
- **Implementation Summary**: [IMPLEMENTATION_SUMMARY.md](../IMPLEMENTATION_SUMMARY.md)
- **Verification Script**: [verify_checkpointing.py](verify_checkpointing.py)

---

## 🎯 Quick Reference

```python
# Create checkpointer
checkpointer = await create_postgres_checkpointer()

# Create graph
graph = create_medusa_graph(checkpointer=checkpointer)

# Setup graceful shutdown
op_mgr = OperationManager(operation_id)
op_mgr.setup_signal_handlers()
set_current_operation_manager(op_mgr)

# Configure thread
thread_id = get_thread_id(operation_id)
config = {"configurable": {"thread_id": thread_id}}

# Run (auto-saves)
result = await graph.ainvoke(state, config)

# Resume (same thread_id)
result = await graph.ainvoke(None, config)

# Cleanup
await op_mgr.cleanup()
```

---

**That's it!** 🎉 You're ready to use checkpointing and graceful shutdown.
