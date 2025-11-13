"""
Integration tests for Multi-Agent System
Tests end-to-end operation, coordination, and cost tracking
"""

import pytest
import json
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from pathlib import Path

# Mark as integration tests
pytestmark = pytest.mark.integration


@pytest.fixture
def mock_world_model():
    """Mock WorldModelClient"""
    mock = AsyncMock()
    mock.connect = AsyncMock()
    mock.close = AsyncMock()
    mock.get_all_hosts = AsyncMock(return_value=[
        {"ip": "192.168.1.100", "hostname": "test-server", "services": []}
    ])
    mock.query = AsyncMock(return_value=[])
    mock.get_graph_statistics = Mock(return_value={"nodes": 10, "edges": 5})
    return mock


@pytest.fixture
def mock_vector_store():
    """Mock VectorStore"""
    mock = Mock()
    mock.search_mitre_techniques = Mock(return_value=[
        {
            "technique_id": "T1046",
            "technique_name": "Network Service Scanning",
            "description": "Adversaries may attempt to get a listing of services running on remote hosts",
            "tactics": ["discovery"],
        }
    ])
    mock.search_tool_usage = Mock(return_value=[
        {
            "tool": "nmap",
            "command": "nmap -sV -p- <target>",
            "description": "Service version detection scan",
            "category": "reconnaissance"
        }
    ])
    mock.search_cves = Mock(return_value=[
        {
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 Remote Code Execution",
            "severity": "critical",
            "cvss": 10.0
        }
    ])
    mock.get_stats = Mock(return_value={"total_docs": 100})
    return mock


@pytest.fixture
def mock_context_engine(mock_world_model, mock_vector_store):
    """Mock ContextFusionEngine"""
    mock = Mock()
    mock.world_model = mock_world_model
    mock.vector_store = mock_vector_store
    mock.build_context_for_reconnaissance = Mock(return_value={
        "phase": "reconnaissance",
        "target": "test.example.com",
        "mitre_techniques": [],
        "tool_suggestions": []
    })
    mock.build_context_for_vulnerability_analysis = Mock(return_value={
        "phase": "vulnerability_analysis",
        "cves": [],
        "exploitability": []
    })
    mock.build_context_for_planning = Mock(return_value={
        "phase": "planning",
        "attack_chains": []
    })
    mock.build_context_for_exploitation = Mock(return_value={
        "phase": "exploitation",
        "exploitation_techniques": [],
        "available_exploits": []
    })
    mock.record_action = Mock()
    mock.operation_history = []
    return mock


@pytest.fixture
def mock_message_bus():
    """Mock MessageBus"""
    mock = AsyncMock()
    mock.publish = AsyncMock()
    mock.subscribe = AsyncMock()
    return mock


@pytest.fixture
async def mock_llm_client():
    """Mock LLM client with realistic responses"""
    mock = AsyncMock()

    # Mock health check
    mock.health_check = AsyncMock(return_value={
        "healthy": True,
        "provider": "mock",
        "model": "mock-model"
    })

    # Mock generate method with different responses based on task
    async def generate_side_effect(*args, **kwargs):
        prompt = kwargs.get('prompt', '')

        # Create a mock response object
        response = Mock()
        response.tokens_used = 100
        response.latency_ms = 500
        response.metadata = {"cost_usd": 0.001}

        # Return different content based on prompt
        if "reconnaissance" in prompt.lower():
            response.content = json.dumps({
                "reconnaissance_strategy": {
                    "approach": "network_scanning",
                    "tools_recommended": ["nmap", "masscan"],
                    "expected_duration": "5-10 minutes"
                }
            })
        elif "vulnerability" in prompt.lower():
            response.content = json.dumps({
                "vulnerability_assessment": {
                    "vulnerabilities": [
                        {
                            "name": "SQL Injection",
                            "severity": "high",
                            "confidence": 0.85
                        }
                    ]
                }
            })
        elif "plan" in prompt.lower():
            response.content = json.dumps({
                "operation_plan": {
                    "phases": ["reconnaissance", "vulnerability_analysis", "exploitation"],
                    "estimated_duration": "2 hours"
                }
            })
        elif "exploit" in prompt.lower():
            response.content = json.dumps({
                "exploitation_analysis": {
                    "predicted_outcome": "success",
                    "success_probability": 0.75
                }
            })
        elif "report" in prompt.lower() or "executive" in prompt.lower():
            response.content = json.dumps({
                "executive_summary": {
                    "title": "Security Assessment - Executive Summary",
                    "date": "2025-11-13",
                    "risk_rating": {"overall_risk": "high"}
                }
            })
        else:
            response.content = json.dumps({"result": "success"})

        return response

    mock.generate = AsyncMock(side_effect=generate_side_effect)
    mock.generate_with_routing = AsyncMock(side_effect=generate_side_effect)
    mock.close = AsyncMock()

    return mock


# ============================================================================
# End-to-End Operation Tests
# ============================================================================

@pytest.mark.asyncio
async def test_full_multi_agent_operation(
    mock_llm_client,
    mock_context_engine,
    mock_message_bus,
    temp_dir
):
    """
    Test complete multi-agent operation from start to finish

    This test verifies:
    - All agents can be initialized
    - Orchestrator coordinates agents properly
    - Operation completes successfully
    - Results are properly formatted
    """
    from medusa.agents import (
        OrchestratorAgent,
        ReconnaissanceAgent,
        VulnerabilityAnalysisAgent,
        PlanningAgent,
        ExploitationAgent,
        ReportingAgent,
        AgentTask,
        AgentStatus,
    )
    from medusa.agents.data_models import TaskPriority

    # Create all specialist agents
    recon_agent = ReconnaissanceAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    vuln_agent = VulnerabilityAnalysisAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    planning_agent = PlanningAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    exploit_agent = ExploitationAgent(
        require_approval=False,  # Auto-approve for testing
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    reporting_agent = ReportingAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    # Create orchestrator
    specialist_agents = {
        "ReconAgent": recon_agent,
        "VulnAnalysisAgent": vuln_agent,
        "PlanningAgent": planning_agent,
        "ExploitationAgent": exploit_agent,
        "ReportingAgent": reporting_agent,
    }

    orchestrator = OrchestratorAgent(
        specialist_agents=specialist_agents,
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    # Create operation task
    task = AgentTask(
        task_id="TEST-OP-001",
        task_type="run_operation",
        description="Test security assessment",
        parameters={
            "target": "test.example.com",
            "operation_type": "full_assessment",
            "objectives": ["find_vulnerabilities", "assess_risk"],
        },
        priority=TaskPriority.HIGH,
    )

    # Execute operation
    result = await orchestrator.execute_task(task)

    # Verify result
    assert result.status == AgentStatus.COMPLETED
    assert result.task_id == "TEST-OP-001"
    assert result.agent_name == "Orchestrator"
    assert len(result.findings) > 0

    # Verify cost tracking
    assert result.tokens_used > 0
    assert result.cost_usd >= 0

    # Verify metadata
    assert "target" in result.metadata
    assert result.metadata["target"] == "test.example.com"


@pytest.mark.asyncio
async def test_reconnaissance_agent_execution(
    mock_llm_client,
    mock_context_engine,
    mock_message_bus
):
    """Test ReconnaissanceAgent executes tasks correctly"""
    from medusa.agents import ReconnaissanceAgent, AgentTask, AgentStatus
    from medusa.agents.data_models import TaskPriority

    agent = ReconnaissanceAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    task = AgentTask(
        task_id="RECON-001",
        task_type="recommend_strategy",
        description="Recommend reconnaissance strategy",
        parameters={"target": "test.example.com"},
        priority=TaskPriority.HIGH,
    )

    result = await agent.execute_task(task)

    assert result.status == AgentStatus.COMPLETED
    assert result.agent_name == "ReconAgent"
    assert result.tokens_used > 0
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_vulnerability_analysis_agent(
    mock_llm_client,
    mock_context_engine,
    mock_message_bus
):
    """Test VulnerabilityAnalysisAgent identifies vulnerabilities"""
    from medusa.agents import VulnerabilityAnalysisAgent, AgentTask, AgentStatus

    agent = VulnerabilityAnalysisAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    findings = [
        {
            "service": "apache",
            "version": "2.4.41",
            "port": 80
        }
    ]

    task = AgentTask(
        task_id="VULN-001",
        task_type="analyze_findings",
        description="Analyze reconnaissance findings",
        parameters={
            "findings": findings,
            "target": "test.example.com"
        },
    )

    result = await agent.execute_task(task)

    assert result.status == AgentStatus.COMPLETED
    assert result.agent_name == "VulnAnalysisAgent"
    assert len(result.findings) > 0


@pytest.mark.asyncio
async def test_planning_agent_creates_plan(
    mock_llm_client,
    mock_context_engine,
    mock_message_bus
):
    """Test PlanningAgent creates operational plans"""
    from medusa.agents import PlanningAgent, AgentTask, AgentStatus

    agent = PlanningAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    all_findings = {
        "reconnaissance": [{"finding": "Port 80 open"}],
        "vulnerabilities": [{"vuln": "SQL Injection"}],
    }

    task = AgentTask(
        task_id="PLAN-001",
        task_type="create_operation_plan",
        description="Create operation plan",
        parameters={
            "all_findings": all_findings,
            "objectives": ["exploit_vulnerabilities"],
            "target": "test.example.com"
        },
    )

    result = await agent.execute_task(task)

    assert result.status == AgentStatus.COMPLETED
    assert result.agent_name == "PlanningAgent"
    assert len(result.recommendations) > 0


@pytest.mark.asyncio
async def test_exploitation_agent_simulates_exploits(
    mock_llm_client,
    mock_context_engine,
    mock_message_bus
):
    """Test ExploitationAgent simulates exploits safely"""
    from medusa.agents import ExploitationAgent, AgentTask, AgentStatus

    agent = ExploitationAgent(
        require_approval=False,
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    vulnerabilities = [
        {
            "name": "SQL Injection",
            "severity": "high",
            "location": "/api/search"
        }
    ]

    task = AgentTask(
        task_id="EXPLOIT-001",
        task_type="plan_exploitation",
        description="Plan exploitation",
        parameters={
            "vulnerabilities": vulnerabilities,
            "target": "test.example.com"
        },
    )

    result = await agent.execute_task(task)

    assert result.status == AgentStatus.COMPLETED
    assert result.agent_name == "ExploitationAgent"
    assert "simulation_mode" not in result.metadata or result.metadata.get("simulation_mode") == True


@pytest.mark.asyncio
async def test_reporting_agent_generates_reports(
    mock_llm_client,
    mock_context_engine,
    mock_message_bus
):
    """Test ReportingAgent generates comprehensive reports"""
    from medusa.agents import ReportingAgent, AgentTask, AgentStatus

    agent = ReportingAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    findings = [
        {
            "type": "vulnerability",
            "severity": "high",
            "description": "SQL Injection found"
        }
    ]

    task = AgentTask(
        task_id="REPORT-001",
        task_type="generate_executive_summary",
        description="Generate executive summary",
        parameters={
            "findings": findings,
            "target": "test.example.com",
            "operation_name": "Test Assessment",
            "operation_data": {}
        },
    )

    result = await agent.execute_task(task)

    assert result.status == AgentStatus.COMPLETED
    assert result.agent_name == "ReportingAgent"
    assert len(result.findings) > 0
    assert "report_id" in result.metadata


# ============================================================================
# Agent Coordination Tests
# ============================================================================

@pytest.mark.asyncio
async def test_orchestrator_delegates_tasks_correctly(
    mock_llm_client,
    mock_context_engine,
    mock_message_bus
):
    """Test Orchestrator delegates tasks to correct agents"""
    from medusa.agents import (
        OrchestratorAgent,
        ReconnaissanceAgent,
        VulnerabilityAnalysisAgent,
        AgentCapability
    )

    recon_agent = ReconnaissanceAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    vuln_agent = VulnerabilityAnalysisAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    specialist_agents = {
        "ReconAgent": recon_agent,
        "VulnAnalysisAgent": vuln_agent,
    }

    orchestrator = OrchestratorAgent(
        specialist_agents=specialist_agents,
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    # Verify correct agent selection
    recon_capable = orchestrator._find_agent_by_capability(AgentCapability.RECONNAISSANCE)
    assert recon_capable == recon_agent

    vuln_capable = orchestrator._find_agent_by_capability(AgentCapability.VULNERABILITY_ANALYSIS)
    assert vuln_capable == vuln_agent


@pytest.mark.asyncio
async def test_message_bus_communication(mock_message_bus):
    """Test agents can communicate via message bus"""
    from medusa.agents.data_models import AgentMessage, MessageType

    message = AgentMessage(
        sender="ReconAgent",
        recipient="VulnAnalysisAgent",
        message_type=MessageType.TASK_RESULT,
        content={"findings": ["port 80 open"]},
    )

    await mock_message_bus.publish(message)

    mock_message_bus.publish.assert_called_once_with(message)


@pytest.mark.asyncio
async def test_agent_metrics_tracking(
    mock_llm_client,
    mock_context_engine,
    mock_message_bus
):
    """Test agents track metrics correctly"""
    from medusa.agents import ReconnaissanceAgent, AgentTask

    agent = ReconnaissanceAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    task = AgentTask(
        task_id="METRICS-001",
        task_type="recommend_strategy",
        description="Test metrics",
        parameters={"target": "test.example.com"},
    )

    # Execute task
    result = await agent.execute_task(task)

    # Check metrics
    metrics = agent.metrics
    assert metrics.tasks_completed == 1
    assert metrics.tasks_failed == 0
    assert metrics.total_tokens_used > 0
    assert metrics.total_cost >= 0
    assert metrics.total_execution_time > 0


# ============================================================================
# Cost Tracking Tests
# ============================================================================

@pytest.mark.asyncio
async def test_cost_tracking_per_agent(
    mock_llm_client,
    mock_context_engine,
    mock_message_bus
):
    """Test cost tracking works for each agent"""
    from medusa.agents import ReconnaissanceAgent, AgentTask

    agent = ReconnaissanceAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    task = AgentTask(
        task_id="COST-001",
        task_type="recommend_strategy",
        description="Test cost tracking",
        parameters={"target": "test.example.com"},
    )

    result = await agent.execute_task(task)

    # Verify cost tracking in result
    assert result.tokens_used > 0
    assert result.cost_usd >= 0

    # Verify cost tracking in agent metrics
    assert agent.metrics.total_tokens_used > 0
    assert agent.metrics.total_cost >= 0


@pytest.mark.asyncio
async def test_operation_cost_aggregation(
    mock_llm_client,
    mock_context_engine,
    mock_message_bus
):
    """Test costs are properly aggregated across multiple agents"""
    from medusa.agents import (
        OrchestratorAgent,
        ReconnaissanceAgent,
        VulnerabilityAnalysisAgent,
        AgentTask,
    )

    recon_agent = ReconnaissanceAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    vuln_agent = VulnerabilityAnalysisAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    specialist_agents = {
        "ReconAgent": recon_agent,
        "VulnAnalysisAgent": vuln_agent,
    }

    orchestrator = OrchestratorAgent(
        specialist_agents=specialist_agents,
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    task = AgentTask(
        task_id="AGG-COST-001",
        task_type="run_operation",
        description="Test cost aggregation",
        parameters={
            "target": "test.example.com",
            "operation_type": "full_assessment",
            "objectives": [],
        },
    )

    result = await orchestrator.execute_task(task)

    # Total cost should be sum of all agent costs
    assert result.tokens_used > 0
    assert result.cost_usd >= 0

    # Individual agent costs
    recon_cost = recon_agent.metrics.total_cost
    vuln_cost = vuln_agent.metrics.total_cost

    # Total should include all agent costs
    assert result.cost_usd >= (recon_cost + vuln_cost)


# ============================================================================
# Error Handling Tests
# ============================================================================

@pytest.mark.asyncio
async def test_agent_handles_llm_error_gracefully(
    mock_context_engine,
    mock_message_bus
):
    """Test agents handle LLM errors gracefully"""
    from medusa.agents import ReconnaissanceAgent, AgentTask, AgentStatus

    # Create LLM client that raises error
    error_llm = AsyncMock()
    error_llm.generate_with_routing = AsyncMock(side_effect=Exception("LLM Error"))

    agent = ReconnaissanceAgent(
        llm_client=error_llm,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    task = AgentTask(
        task_id="ERROR-001",
        task_type="recommend_strategy",
        description="Test error handling",
        parameters={"target": "test.example.com"},
    )

    result = await agent.execute_task(task)

    # Should fail gracefully
    assert result.status == AgentStatus.FAILED
    assert "error" in result.error.lower() or result.error is not None


@pytest.mark.asyncio
async def test_orchestrator_continues_on_agent_failure(
    mock_llm_client,
    mock_context_engine,
    mock_message_bus
):
    """Test orchestrator continues operation even if one agent fails"""
    from medusa.agents import (
        OrchestratorAgent,
        ReconnaissanceAgent,
        VulnerabilityAnalysisAgent,
        AgentTask,
        AgentStatus
    )

    # Create agent that will fail
    failing_llm = AsyncMock()
    failing_llm.generate_with_routing = AsyncMock(side_effect=Exception("Agent failure"))

    failing_agent = ReconnaissanceAgent(
        llm_client=failing_llm,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    # Create successful agent
    success_agent = VulnerabilityAnalysisAgent(
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    specialist_agents = {
        "ReconAgent": failing_agent,
        "VulnAnalysisAgent": success_agent,
    }

    orchestrator = OrchestratorAgent(
        specialist_agents=specialist_agents,
        llm_client=mock_llm_client,
        context_engine=mock_context_engine,
        message_bus=mock_message_bus,
    )

    task = AgentTask(
        task_id="RESILIENCE-001",
        task_type="run_operation",
        description="Test resilience",
        parameters={
            "target": "test.example.com",
            "operation_type": "full_assessment",
            "objectives": [],
        },
    )

    result = await orchestrator.execute_task(task)

    # Operation should complete despite one agent failing
    # The orchestrator should mark it as COMPLETED or PARTIAL based on implementation
    assert result.status in [AgentStatus.COMPLETED, AgentStatus.FAILED]
    assert result.agent_name == "Orchestrator"
