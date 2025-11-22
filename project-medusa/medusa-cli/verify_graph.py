import asyncio
import logging
from medusa.core.medusa_graph import create_medusa_graph
from langchain_core.messages import HumanMessage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    print("Initializing Medusa Graph...")
    try:
        graph = create_medusa_graph()
        
        print("Graph initialized successfully.")
        
        initial_state = {
            "messages": [HumanMessage(content="Scan scanme.nmap.org and report findings.")],
            "findings": [],
            "plan": {},
            "current_phase": "start",
            "next_worker": "Supervisor", # Initial entry
            "context": {"target": "scanme.nmap.org"},
            "target": "scanme.nmap.org",
            "cost_tracking": {},
            "approval_status": {},
            "operation_id": "verify-op",
            "risk_level": "LOW"
        }
        
        print("Invoking graph...")
        async for event in graph.astream(initial_state):
            for key, value in event.items():
                print(f"\n--- Node: {key} ---")
                if "messages" in value:
                    print(f"Message: {value['messages'][-1].content}")
                if "next_worker" in value:
                    print(f"Next Worker: {value['next_worker']}")
                if "findings" in value:
                    print(f"Findings Count: {len(value['findings'])}")
                    
        print("\nGraph execution completed.")
        
    except ImportError as e:
        print(f"\nError: Missing dependencies. Please install requirements.txt.\nDetails: {e}")
    except Exception as e:
        print(f"\nError during execution: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
