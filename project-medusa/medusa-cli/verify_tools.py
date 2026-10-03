import asyncio
import logging
from unittest.mock import MagicMock, AsyncMock
from medusa.agents.graph_nodes import recon_agent, vuln_agent, planning_agent, reporting_agent
from medusa.agents.data_models import AgentTask

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def verify_recon_tools():
    print("\n--- Verifying ReconnaissanceAgent Tools ---")
    # Mock tools
    recon_agent.amass_tool = AsyncMock()
    recon_agent.amass_tool.execute.return_value = {"success": True, "findings": [{"subdomain": "test.scanme.nmap.org"}], "raw_output": "test"}
    
    recon_agent.httpx_tool = AsyncMock()
    recon_agent.httpx_tool.execute.return_value = {"success": True, "findings": [{"url": "http://scanme.nmap.org", "status": 200}], "raw_output": "test"}

    # Test Amass
    print("Testing Amass integration...")
    task = AgentTask(task_id="1", task_type="run_scan", parameters={"target": "scanme.nmap.org", "scan_type": "subdomain"})
    result = await recon_agent.run_task(task)
    if result.status == "completed" and recon_agent.amass_tool.execute.called:
        print("✅ Amass integration verified.")
    else:
        print("❌ Amass integration failed.")

    # Test Httpx
    print("Testing Httpx integration...")
    task = AgentTask(task_id="2", task_type="run_scan", parameters={"target": "scanme.nmap.org", "scan_type": "web_probe"})
    result = await recon_agent.run_task(task)
    if result.status == "completed" and recon_agent.httpx_tool.execute.called:
        print("✅ Httpx integration verified.")
    else:
        print("❌ Httpx integration failed.")

async def verify_vuln_tools():
    print("\n--- Verifying VulnerabilityAnalysisAgent Tools ---")
    # Mock tool
    vuln_agent.web_scanner = AsyncMock()
    vuln_agent.web_scanner.execute.return_value = {"success": True, "findings": [{"vuln": "XSS"}], "raw_output": "test"}

    # Test WebScanner
    print("Testing WebScanner integration...")
    task = AgentTask(task_id="3", task_type="run_web_scan", parameters={"target": "http://scanme.nmap.org"})
    result = await vuln_agent.run_task(task)
    if result.status == "completed" and vuln_agent.web_scanner.execute.called:
        print("✅ WebScanner integration verified.")
    else:
        print("❌ WebScanner integration failed.")

async def main():
    await verify_recon_tools()
    await verify_vuln_tools()
    # Exploitation verification requires more complex mocking due to mode switching, skipping for now as logic is similar.

if __name__ == "__main__":
    asyncio.run(main())
