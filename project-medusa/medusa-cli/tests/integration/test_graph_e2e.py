import pytest
import asyncio
from unittest.mock import MagicMock, patch
from langchain_core.messages import HumanMessage
from medusa.core.medusa_graph import create_medusa_graph

@pytest.mark.asyncio
async def test_graph_execution_flow():
    """
    Test the full graph execution flow with mock LLM.
    This ensures the graph is constructed correctly and nodes can execute.
    """
    # Mock config to ensure we use mock provider and avoid API calls
    with patch('medusa.agents.graph_nodes.get_config') as mock_get_config, \
         patch('medusa.core.supervisor.get_config') as mock_sup_config:
        
        mock_config_data = {
            "provider": "mock", 
            "mock_mode": True,
            "temperature": 0.0
        }
        
        mock_config_inst = MagicMock()
        mock_config_inst.get_llm_config.return_value = mock_config_data
        mock_config_inst.get.return_value = {} # for risk_tolerance
        
        mock_get_config.return_value = mock_config_inst
        mock_sup_config.return_value = mock_config_inst
        
        # Re-import or re-initialize graph to pick up mocks if needed
        # (In this case, graph_nodes imports get_config at module level, but calls it in get_initialized_agents)
        # We might need to patch where it's called.
        
        # Since agents are initialized at module level in graph_nodes.py, patching get_config AFTER import 
        # might not affect the agents if they are already initialized.
        # However, our updated graph_nodes.py calls get_config inside get_initialized_agents() 
        # but calls get_initialized_agents() at module level.
        # So we need to reload the module or patch the agents directly.
        
        # Easier approach: Patch the agents in graph_nodes
        with patch('medusa.agents.graph_nodes.recon_agent') as mock_recon, \
             patch('medusa.agents.graph_nodes.vuln_agent') as mock_vuln, \
             patch('medusa.agents.graph_nodes.planning_agent') as mock_plan, \
             patch('medusa.agents.graph_nodes.exploit_agent') as mock_exploit, \
             patch('medusa.agents.graph_nodes.reporting_agent') as mock_report, \
             patch('medusa.core.supervisor.get_llm_client') as mock_sup_client:
             
            # Setup mock agents
            async def mock_run_task(task):
                return type('obj', (object,), {
                    'findings': [{"type": "test_finding"}],
                    'status': 'COMPLETED',
                    'data': {},
                    'recommendations': []
                })()
            
            mock_recon.run_task.side_effect = mock_run_task
            mock_recon.total_cost = 0.0
            
            mock_vuln.run_task.side_effect = mock_run_task
            mock_vuln.total_cost = 0.0
            
            mock_plan.run_task.side_effect = mock_run_task
            mock_plan.total_cost = 0.0
            
            mock_exploit.run_task.side_effect = mock_run_task
            mock_exploit.total_cost = 0.0
            
            mock_report.run_task.side_effect = mock_run_task
            mock_report.total_cost = 0.0
            
            # Setup mock supervisor LLM
            mock_llm = MagicMock()
            async def mock_generate(*args, **kwargs):
                # Return a sequence of decisions
                return type('obj', (object,), {
                    'content': '{"next_worker": "Reconnaissance"}',
                    'tokens_used': 10,
                    'metadata': {}
                })()
            
            mock_llm.generate_with_routing.side_effect = [
                type('obj', (object,), {'content': '{"next_worker": "Reconnaissance"}', 'tokens_used': 10})(),
                type('obj', (object,), {'content': '{"next_worker": "VulnerabilityAnalysis"}', 'tokens_used': 10})(),
                type('obj', (object,), {'content': '{"next_worker": "FINISH"}', 'tokens_used': 10})(),
            ]
            mock_sup_client.return_value = mock_llm
            
            # Create graph
            graph = create_medusa_graph()
            
            initial_state = {
                "messages": [HumanMessage(content="Scan test")],
                "findings": [],
                "plan": {},
                "current_phase": "start",
                "next_worker": "Supervisor",
                "context": {"target": "test"},
                "target": "test",
                "cost_tracking": {},
                "approval_status": {"approved": True}, # Auto approve for test
                "operation_id": "test-op",
                "risk_level": "LOW"
            }
            
            events = []
            async for event in graph.astream(initial_state):
                events.append(event)
                if len(events) > 5: break
            
            # Assertions
            assert len(events) > 0
            # Check if we visited nodes
            node_names = [list(e.keys())[0] for e in events]
            assert "Supervisor" in node_names
            assert "Reconnaissance" in node_names

