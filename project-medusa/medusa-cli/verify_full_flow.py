import asyncio
import logging
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "src"))

from medusa.agents.orchestrator_agent import OrchestratorAgent
from medusa.agents.data_models import AgentTask
from medusa.core.llm.client import LLMClient
from medusa.core.llm.config import LLMConfig
from medusa.core.llm.providers.mock import MockProvider

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verify_flow")

async def main():
    logger.info("Initializing components...")
    
    # Setup Mock LLM
    config = LLMConfig(provider="mock")
    provider = MockProvider()
    llm_client = LLMClient(config, provider)
    
    # Initialize Orchestrator (it will init sub-agents with the same LLM client)
    # Note: In a real app, we might pass the client factory or init them explicitly.
    # The Orchestrator's __init__ creates its own sub-agents. 
    # We need to make sure they use OUR llm_client or we need to patch them.
    # Looking at Orchestrator code, it initializes agents in __init__.
    # Let's check if we can pass the client.
    
    from medusa.agents.reconnaissance_agent import ReconnaissanceAgent
    from medusa.agents.vulnerability_analysis_agent import VulnerabilityAnalysisAgent
    from medusa.agents.planning_agent import PlanningAgent

    # Initialize specialist agents
    recon_agent = ReconnaissanceAgent(llm_client=llm_client)
    vuln_agent = VulnerabilityAnalysisAgent(llm_client=llm_client)
    planning_agent = PlanningAgent(llm_client=llm_client)

    specialist_agents = {
        "ReconAgent": recon_agent,
        "VulnAnalysisAgent": vuln_agent,
        "PlanningAgent": planning_agent
    }
    
    orchestrator = OrchestratorAgent(
        llm_client=llm_client,
        specialist_agents=specialist_agents
    )
    
    # We need to inject our LLM client into the sub-agents because Orchestrator might create new ones
    # or we need to rely on how Orchestrator creates them.
    # Let's check Orchestrator implementation.
    # It seems Orchestrator creates agents using the same llm_client passed to it.
    
    logger.info("Creating operation task...")
    task = AgentTask(
        task_id="test-op",
        task_type="run_operation",
        description="Test Operation",
        parameters={
            "target": "scanme.nmap.org",
            "objectives": ["Identify open ports", "Find vulnerabilities"]
        }
    )
    
    logger.info("Executing operation...")
    try:
        result = await orchestrator.run_task(task)
        logger.info(f"Operation Status: {result.status}")
        if result.status == "failed":
            logger.error(f"Operation Error: {result.error}")
        
        # Check Recon Findings
        logger.info(f"Result Metadata Keys: {result.metadata.keys()}")
        recon_data = result.metadata.get("phase_results", {}).get("reconnaissance", {})
        # recon_data is a dict (from to_dict())
        findings = recon_data.get("findings", [])
        logger.info(f"Recon Findings: {len(findings)}")
        if findings:
            logger.info(f"Sample Finding: {findings[0]}")
            
        # Check Vuln Analysis
        vuln_data = result.metadata.get("phase_results", {}).get("vulnerability_analysis", {})
        vulnerabilities = vuln_data.get("findings", [])
        logger.info(f"Vulnerabilities Found: {len(vulnerabilities)}")
        if vulnerabilities:
            logger.info(f"Sample Vulnerability: {vulnerabilities[0]}")
            
    except Exception as e:
        logger.error(f"Operation failed: {e}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main())
