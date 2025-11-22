from typing import Optional
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.base import BaseCheckpointSaver
from medusa.core.graph_state import MedusaState
from medusa.core.supervisor import supervisor_node
from medusa.core.approval_node import approval_node
from medusa.agents.graph_nodes import (
    recon_node,
    vuln_node,
    planning_node,
    exploit_node,
    reporting_node
)

def create_medusa_graph(checkpointer: Optional[BaseCheckpointSaver] = None):
    """
    Constructs the Medusa Agent Graph with optional checkpointing.

    Args:
        checkpointer: Optional LangGraph checkpointer for state persistence.
                     If provided, enables crash recovery and pause/resume.
                     Use AsyncPostgresSaver for production.

    Returns:
        Compiled LangGraph workflow
    """
    workflow = StateGraph(MedusaState)

    # Add nodes
    workflow.add_node("Supervisor", supervisor_node)
    workflow.add_node("Reconnaissance", recon_node)
    workflow.add_node("VulnerabilityAnalysis", vuln_node)
    workflow.add_node("Planning", planning_node)
    workflow.add_node("Exploitation", exploit_node)
    workflow.add_node("Reporting", reporting_node)
    workflow.add_node("ApprovalGate", approval_node)

    # Define edges
    # Workers always report back to Supervisor
    workflow.add_edge("Reconnaissance", "Supervisor")
    workflow.add_edge("VulnerabilityAnalysis", "Supervisor")
    workflow.add_edge("Planning", "Supervisor")
    workflow.add_edge("Exploitation", "Supervisor")
    workflow.add_edge("Reporting", "Supervisor")

    # Supervisor decides next step
    conditional_map = {
        "Reconnaissance": "Reconnaissance",
        "VulnerabilityAnalysis": "VulnerabilityAnalysis",
        "Planning": "Planning",
        "Exploitation": "ApprovalGate", # Intercept high-risk actions
        "Reporting": "Reporting",
        "FINISH": END,
        "PAUSE": END  # Allow graceful pause
    }

    workflow.add_conditional_edges(
        "Supervisor",
        lambda x: x["next_worker"],
        conditional_map
    )

    # Approval Gate Logic
    def check_approval(state):
        status = state.get("approval_status", {})
        if status.get("approved"):
            return "Exploitation"
        return "Supervisor" # Return to supervisor if rejected/pending

    workflow.add_conditional_edges(
        "ApprovalGate",
        check_approval,
        {"Exploitation": "Exploitation", "Supervisor": "Supervisor"}
    )

    # Entry point
    workflow.set_entry_point("Supervisor")

    # Compile with checkpointer if provided
    # interrupt_before: Pause execution before high-risk nodes for human approval
    return workflow.compile(
        checkpointer=checkpointer,
        interrupt_before=["Exploitation"]
    )
