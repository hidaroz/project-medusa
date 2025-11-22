from typing import Dict, Any
from langchain_core.messages import AIMessage
from medusa.core.graph_state import MedusaState
from medusa.config import get_config

async def approval_node(state: MedusaState) -> Dict[str, Any]:
    """
    Checks if approval is needed and handles it.
    """
    risk_level = state.get("risk_level", "LOW")
    config = get_config()
    
    # Ensure config is loaded
    if not config.config_data:
        try:
            config.load()
        except:
            pass # Fallback to defaults
            
    risk_config = config.get("risk_tolerance", {})
    
    auto_approve_low = risk_config.get("auto_approve_low", True)
    auto_approve_medium = risk_config.get("auto_approve_medium", False)
    auto_approve_high = risk_config.get("auto_approve_high", False)
    
    approved = False
    message = ""
    
    if risk_level == "LOW":
        approved = auto_approve_low
        message = "Low risk action auto-approved." if approved else "Low risk action requires approval."
    elif risk_level == "MEDIUM":
        approved = auto_approve_medium
        message = "Medium risk action auto-approved." if approved else "Medium risk action requires approval."
    elif risk_level in ["HIGH", "CRITICAL"]:
        approved = auto_approve_high
        message = "High risk action auto-approved." if approved else "High risk action requires approval."
        
    # If not approved, we basically effectively stop or skip high risk actions in this autonomous flow
    # unless there is a human-in-the-loop mechanism. 
    # For now, we mark status.
    
    return {
        "approval_status": {"approved": approved, "risk_level": risk_level, "timestamp": "now"},
        "messages": [AIMessage(content=f"Approval Gate: {message}")]
    }

