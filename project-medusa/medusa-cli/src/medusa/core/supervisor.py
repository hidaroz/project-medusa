import json
import re
from typing import Literal, Dict, Any, List
from langchain_core.messages import AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from medusa.core.graph_state import MedusaState
from medusa.config import get_config
from medusa.core.llm import create_llm_client, LLMConfig
from medusa.core.operation_manager import get_current_operation_manager

# Define the supervisor's decision options
options = ["Reconnaissance", "VulnerabilityAnalysis", "Planning", "Exploitation", "Reporting", "FINISH", "PAUSE"]

# System prompt for the supervisor
system_prompt = (
    "You are the supervisor of a penetration testing team.\n"
    "Your goal is to coordinate the following workers: {members}.\n"
    "Given the following conversation and findings, decide who should act next.\n"
    "Each worker will perform a task and respond with their results.\n"
    "1. Reconnaissance: Scans the target.\n"
    "2. VulnerabilityAnalysis: Analyzes findings for vulnerabilities.\n"
    "3. Planning: Creates an attack plan based on vulnerabilities.\n"
    "4. Exploitation: Plans and executes safe exploitation attempts.\n"
    "5. Reporting: Generates a final report.\n"
    "6. FINISH: When the report is generated or the user request is satisfied.\n\n"
    "Respond with a JSON object containing a single key 'next_worker' with the name of the next worker."
)

# Create the prompt template
prompt = ChatPromptTemplate.from_messages(
    [
        ("system", system_prompt),
        MessagesPlaceholder(variable_name="messages"),
        (
            "system",
            "Given the conversation above, who should act next? "
            "Or should we FINISH? Select one of: {options}",
        ),
    ]
).partial(options=str(options), members=", ".join(options[:-1]))

def get_llm_client():
    """Initialize LLM client from config."""
    try:
        config = get_config()
        llm_config_dict = config.get_llm_config()
        llm_config = LLMConfig(**llm_config_dict)
        return create_llm_client(llm_config)
    except Exception as e:
        print(f"Error initializing LLM client: {e}")
        return None

def fallback_supervisor_logic(state: MedusaState) -> str:
    """Deterministic fallback logic if LLM fails."""
    messages = state.get("messages", [])
    last_message = messages[-1] if messages else None
    
    if not messages:
        return "Reconnaissance"
    
    content = last_message.content if last_message else ""
    
    if "Reconnaissance completed" in content:
        return "VulnerabilityAnalysis"
    elif "Vulnerability analysis completed" in content:
        return "Planning"
    elif "Strategic plan created" in content:
        return "Reporting"
    elif "Report generated" in content:
        return "FINISH"
        
    return "FINISH"

async def supervisor_node(state: MedusaState) -> Dict[str, Any]:
    """
    Determines the next worker node using LLM.

    Checks for shutdown requests before routing to ensure graceful
    operation termination with state preservation.
    """
    # Check for shutdown request from OperationManager
    operation_manager = get_current_operation_manager()
    if operation_manager:
        current_node = state.get("current_node", "Supervisor")
        if not operation_manager.should_continue(current_node):
            print("\n✅ Current node completed. Saving state and pausing...")
            return {"next_worker": "PAUSE"}

    llm_client = get_llm_client()

    # If client init failed or we are in strict mock mode without provider, use fallback
    if not llm_client:
        return {"next_worker": fallback_supervisor_logic(state)}

    try:
        # Format messages for the prompt
        # Note: We need to convert messages to a format the prompt template accepts or stringify them
        # For now, let's just stringify the last few messages to keep context manageable
        messages = state.get("messages", [])
        formatted_messages = []
        for m in messages[-5:]: # Keep last 5 messages context
             role = "assistant" if isinstance(m, AIMessage) else "user"
             formatted_messages.append(f"{role}: {m.content}")
             
        conversation_history = "\n".join(formatted_messages)
        
        # We manually format because ChatPromptTemplate might be tied to LangChain's LCEL which we aren't fully using here with our custom client
        # Simulating the prompt construction
        final_prompt = (
            f"{system_prompt.format(members=', '.join(options[:-1]))}\n\n"
            f"Conversation History:\n{conversation_history}\n\n"
            f"Given the conversation above, who should act next? "
            f"Or should we FINISH? Select one of: {str(options)}"
        )

        response = await llm_client.generate_with_routing(
            prompt=final_prompt,
            task_type="supervisor_routing",
            force_json=True
        )
        
        # Parse response
        try:
            content = response.content
            # Extract JSON if needed
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
                
            data = json.loads(content)
            next_worker = data.get("next_worker")
            
            if next_worker not in options:
                print(f"Warning: LLM suggested invalid worker '{next_worker}'. Using fallback.")
                next_worker = fallback_supervisor_logic(state)
                
        except json.JSONDecodeError:
            print(f"Warning: Could not parse supervisor JSON response: {content}")
            next_worker = fallback_supervisor_logic(state)
            
        return {"next_worker": next_worker}
        
    except Exception as e:
        print(f"Error in supervisor LLM node: {e}")
        return {"next_worker": fallback_supervisor_logic(state)}

