from typing import TypedDict, List, Dict, Any, Annotated, Optional
from langchain_core.messages import BaseMessage
import operator

class MedusaState(TypedDict):
    """
    Global state for the Medusa Agent Graph.

    MEMORY MANAGEMENT NOTES:
    - `findings` uses operator.add, which means each node appends to the list
    - For long-running operations (24+ hours), this can cause memory bloat
    - Future improvement: Offload findings to PostgreSQL and keep only summaries in-memory
    - Track archived findings count to monitor when offloading is needed
    """
    # Conversation history
    messages: Annotated[List[BaseMessage], operator.add]

    # Structured findings from all agents
    # WARNING: This list grows indefinitely with operator.add
    # Each node returns ONLY new findings, but they accumulate in state
    findings: Annotated[List[Dict[str, Any]], operator.add]

    # Current operation plan
    plan: Dict[str, Any]

    # Current phase of the operation (recon, vuln, plan, exploit, report)
    current_phase: str

    # The next worker node to execute
    next_worker: str

    # Shared context/knowledge base
    context: Dict[str, Any]

    # Target URL or IP address
    target: str

    # Cost tracking for the operation
    cost_tracking: Dict[str, Any]

    # Approval status for high-risk actions
    approval_status: Dict[str, Any]

    # Unique operation identifier
    operation_id: str

    # Current risk level (LOW, MEDIUM, HIGH, CRITICAL)
    risk_level: str

    # === MEMORY MANAGEMENT FIELDS ===

    # Count of findings that have been archived to database
    # When findings list grows too large (e.g., > 1000), we can:
    # 1. Write findings to PostgreSQL checkpointer storage
    # 2. Clear the findings list
    # 3. Increment archived_findings_count
    # 4. Keep only a summary or recent N findings in memory
    archived_findings_count: int

    # Count of messages that have been archived (for conversation history pruning)
    archived_messages_count: int

    # Flag to indicate if this operation is resuming from checkpoint
    # (helps determine if we need to reload archived data)
    resumed_from_checkpoint: bool

    # === MONITORING FIELDS (Phase 3: Zombie Agent Prevention) ===

    # ISO timestamp of the last state update
    # Updated by each graph node to detect stalled operations
    # Used by /health/detailed endpoint to identify zombie agents
    last_updated: Optional[str]
