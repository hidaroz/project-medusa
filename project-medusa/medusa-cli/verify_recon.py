import asyncio
import logging
from medusa.agents.reconnaissance_agent import ReconnaissanceAgent
from medusa.agents.data_models import AgentTask

# Configure logging
logging.basicConfig(level=logging.INFO)

async def main():
    print("Initializing ReconnaissanceAgent...")
    # Mock LLM client not needed for run_scan as we implemented it to run nmap directly
    # But BaseAgent init requires it. We can pass a dummy.
    class DummyLLM:
        pass
        
    agent = ReconnaissanceAgent(llm_client=DummyLLM())
    
    print("Creating scan task...")
    task = AgentTask(
        task_id="test-scan",
        task_type="run_scan",
        description="Test scan",
        parameters={
            "target": "scanme.nmap.org", # Safe target
            "scan_type": "fast"
        }
    )
    
    print("Executing task...")
    try:
        result = await agent.run_task(task)
        print(f"Task Status: {result.status}")
        print(f"Findings: {len(result.data.get('findings', []))}")
        if result.data.get('findings'):
            print("First finding:", result.data['findings'][0])
    except Exception as e:
        print(f"Task failed: {e}")

if __name__ == "__main__":
    asyncio.run(main())
