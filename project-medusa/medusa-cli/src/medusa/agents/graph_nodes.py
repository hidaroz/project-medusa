import json
from typing import Dict, Any
from datetime import datetime, timezone
from langchain_core.messages import HumanMessage, AIMessage

from medusa.core.graph_state import MedusaState
from medusa.agents.reconnaissance_agent import ReconnaissanceAgent
from medusa.agents.vulnerability_analysis_agent import VulnerabilityAnalysisAgent
from medusa.agents.planning_agent import PlanningAgent
from medusa.agents.exploitation_agent import ExploitationAgent
from medusa.agents.reporting_agent import ReportingAgent
from medusa.agents.data_models import AgentTask
from medusa.config import get_config
from medusa.core.llm import create_llm_client, LLMConfig

def get_initialized_agents():
    """
    Initialize agents with real LLM client from configuration.
    """
    try:
        config = get_config()
        llm_config_dict = config.get_llm_config()
        llm_config = LLMConfig(**llm_config_dict)
        llm_client = create_llm_client(llm_config)
    except Exception as e:
        # Fallback for tests or if config is missing
        print(f"Warning: Could not initialize LLM client: {e}. Using dummy client.")
        class DummyLLM:
            async def generate(self, *args, **kwargs):
                return type('obj', (object,), {'content': '{}', 'metadata': {}, 'tokens_used': 0})()
            async def generate_with_routing(self, *args, **kwargs):
                return type('obj', (object,), {'content': '{}', 'metadata': {}, 'tokens_used': 0})()
        llm_client = DummyLLM()

    return {
        "recon": ReconnaissanceAgent(llm_client=llm_client),
        "vuln": VulnerabilityAnalysisAgent(llm_client=llm_client),
        "planning": PlanningAgent(llm_client=llm_client),
        "exploitation": ExploitationAgent(llm_client=llm_client, require_approval=True),
        "reporting": ReportingAgent(llm_client=llm_client)
    }

# Initialize agents
agents = get_initialized_agents()
recon_agent = agents["recon"]
vuln_agent = agents["vuln"]
planning_agent = agents["planning"]
exploit_agent = agents["exploitation"]
reporting_agent = agents["reporting"]

async def recon_node(state: MedusaState) -> Dict[str, Any]:
    """
    Executes the Reconnaissance Agent.
    """
    target = state.get("target", "scanme.nmap.org")
    
    task = AgentTask(
        task_id="recon-task",
        task_type="run_scan",
        description=f"Scan {target}",
        parameters={"target": target, "scan_type": "fast"}
    )
    
    # Track cost
    start_cost = recon_agent.total_cost
    result = await recon_agent.run_task(task)
    task_cost = recon_agent.total_cost - start_cost
    
    # Update cost tracking
    cost_tracking = state.get("cost_tracking", {"total_cost": 0.0, "by_agent": {}})
    cost_tracking["total_cost"] = cost_tracking.get("total_cost", 0.0) + task_cost
    agent_costs = cost_tracking.get("by_agent", {})
    agent_costs["recon"] = agent_costs.get("recon", 0.0) + task_cost
    cost_tracking["by_agent"] = agent_costs
    
    # Update state (Phase 3: Include last_updated timestamp)
    return {
        "findings": result.findings,
        "messages": [AIMessage(content=f"Reconnaissance completed. Found {len(result.findings)} open ports.")],
        "cost_tracking": cost_tracking,
        "last_updated": datetime.now(timezone.utc).isoformat()
    }

async def vuln_node(state: MedusaState) -> Dict[str, Any]:
    """
    Executes the Vulnerability Analysis Agent.
    """
    findings = state.get("findings", [])
    target = state.get("target", "unknown")
    
    if not findings:
        return {"messages": [AIMessage(content="No findings to analyze.")]}
        
    task = AgentTask(
        task_id="vuln-task",
        task_type="analyze_findings",
        description="Analyze findings",
        parameters={"findings": findings, "target": target}
    )
    
    # Track cost
    start_cost = vuln_agent.total_cost
    result = await vuln_agent.run_task(task)
    task_cost = vuln_agent.total_cost - start_cost
    
    # Update cost tracking
    cost_tracking = state.get("cost_tracking", {"total_cost": 0.0, "by_agent": {}})
    cost_tracking["total_cost"] = cost_tracking.get("total_cost", 0.0) + task_cost
    agent_costs = cost_tracking.get("by_agent", {})
    agent_costs["vuln"] = agent_costs.get("vuln", 0.0) + task_cost
    cost_tracking["by_agent"] = agent_costs
    
    return {
        "findings": result.findings, # Append/Merge new findings (vulnerabilities)
        "messages": [AIMessage(content=f"Vulnerability analysis completed. Identified {len(result.findings)} potential issues.")],
        "cost_tracking": cost_tracking,
        "last_updated": datetime.now(timezone.utc).isoformat()
    }

async def planning_node(state: MedusaState) -> Dict[str, Any]:
    """
    Executes the Planning Agent.
    """
    findings = state.get("findings", [])
    
    task = AgentTask(
        task_id="plan-task",
        task_type="create_operation_plan",
        description="Create plan",
        parameters={"findings": findings, "objectives": ["Identify attack vectors"]}
    )
    
    # Track cost
    start_cost = planning_agent.total_cost
    result = await planning_agent.run_task(task)
    task_cost = planning_agent.total_cost - start_cost
    
    # Update cost tracking
    cost_tracking = state.get("cost_tracking", {"total_cost": 0.0, "by_agent": {}})
    cost_tracking["total_cost"] = cost_tracking.get("total_cost", 0.0) + task_cost
    agent_costs = cost_tracking.get("by_agent", {})
    agent_costs["planning"] = agent_costs.get("planning", 0.0) + task_cost
    cost_tracking["by_agent"] = agent_costs
    
    # The plan is usually in findings[0] for this agent
    plan = result.findings[0] if result.findings else {}
    
    return {
        "plan": plan,
        "messages": [AIMessage(content="Strategic plan created.")],
        "cost_tracking": cost_tracking,
        "last_updated": datetime.now(timezone.utc).isoformat()
    }

async def exploit_node(state: MedusaState) -> Dict[str, Any]:
    """
    Executes the Exploitation Agent.
    """
    findings = state.get("findings", [])
    plan = state.get("plan", {})
    target = state.get("target", "unknown")
    
    task = AgentTask(
        task_id="exploit-task",
        task_type="plan_exploitation", # Start with planning exploitation
        description="Plan and prepare exploitation",
        parameters={
            "target": target, 
            "vulnerabilities": findings, 
            "constraints": {"safe_mode": True}
        }
    )
    
    # Track cost
    start_cost = exploit_agent.total_cost
    result = await exploit_agent.run_task(task)
    task_cost = exploit_agent.total_cost - start_cost
    
    # Update cost tracking
    cost_tracking = state.get("cost_tracking", {"total_cost": 0.0, "by_agent": {}})
    cost_tracking["total_cost"] = cost_tracking.get("total_cost", 0.0) + task_cost
    agent_costs = cost_tracking.get("by_agent", {})
    agent_costs["exploitation"] = agent_costs.get("exploitation", 0.0) + task_cost
    cost_tracking["by_agent"] = agent_costs
    
    return {
        "findings": result.findings,
        "messages": [AIMessage(content="Exploitation analysis completed.")],
        "cost_tracking": cost_tracking,
        "last_updated": datetime.now(timezone.utc).isoformat()
    }

async def reporting_node(state: MedusaState) -> Dict[str, Any]:
    """
    Executes the Reporting Agent.
    """
    findings = state.get("findings", [])
    plan = state.get("plan", {})
    target = state.get("target", "unknown")
    
    task = AgentTask(
        task_id="report-task",
        task_type="generate_executive_summary",
        description="Generate report",
        parameters={
            "findings": findings, 
            "target": target,
            "operation_data": {"plan": plan}
        }
    )
    
    # Track cost
    start_cost = reporting_agent.total_cost
    result = await reporting_agent.run_task(task)
    task_cost = reporting_agent.total_cost - start_cost
    
    # Update cost tracking
    cost_tracking = state.get("cost_tracking", {"total_cost": 0.0, "by_agent": {}})
    cost_tracking["total_cost"] = cost_tracking.get("total_cost", 0.0) + task_cost
    agent_costs = cost_tracking.get("by_agent", {})
    agent_costs["reporting"] = agent_costs.get("reporting", 0.0) + task_cost
    cost_tracking["by_agent"] = agent_costs
    
    return {
        "messages": [AIMessage(content=f"Report generated: {result.findings[0].get('executive_summary', {}).get('title', 'Report')}")],
        "cost_tracking": cost_tracking,
        "last_updated": datetime.now(timezone.utc).isoformat()
    }
