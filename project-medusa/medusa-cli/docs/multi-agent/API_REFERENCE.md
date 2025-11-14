# Multi-Agent System API Reference

## Overview

This document provides comprehensive API documentation for MEDUSA's Multi-Agent System. It covers all agents, data models, and key interfaces for developers who want to use or extend the system programmatically.

## Table of Contents

1. [Core Interfaces](#core-interfaces)
2. [Data Models](#data-models)
3. [Agent APIs](#agent-apis)
4. [Context Fusion Engine API](#context-fusion-engine-api)
5. [Message Bus API](#message-bus-api)
6. [CLI Integration](#cli-integration)
7. [Examples](#examples)

---

## Core Interfaces

### BaseAgent

Abstract base class for all agents.

```python
from medusa.agents import BaseAgent, AgentCapability
from typing import List, Optional

class BaseAgent(ABC):
    def __init__(
        self,
        name: str,
        capabilities: List[AgentCapability],
        llm_client: LLMClient,
        context_engine: Optional[ContextFusionEngine] = None,
        message_bus: Optional[MessageBus] = None
    ):
        """
        Initialize base agent.

        Args:
            name: Agent name
            capabilities: List of agent capabilities
            llm_client: LLM client for AI operations
            context_engine: Optional context fusion engine
            message_bus: Optional message bus for communication
        """
        pass

    @abstractmethod
    async def execute_task(self, task: AgentTask) -> AgentResult:
        """
        Execute agent-specific task.

        Args:
            task: Task to execute

        Returns:
            AgentResult with findings and metrics
        """
        pass

    def can_handle(self, capability: AgentCapability) -> bool:
        """
        Check if agent has specific capability.

        Args:
            capability: Capability to check

        Returns:
            True if agent has capability
        """
        pass
```

**Properties**:
- `name`: str - Agent identifier
- `capabilities`: List[AgentCapability] - Agent capabilities
- `metrics`: AgentMetrics - Performance metrics
- `logger`: logging.Logger - Agent logger

---

## Data Models

### AgentTask

Represents a task for an agent to execute.

```python
from medusa.agents.data_models import AgentTask, TaskPriority, AgentStatus

@dataclass
class AgentTask:
    task_id: str
    task_type: str
    description: str
    parameters: Dict[str, Any]
    priority: TaskPriority = TaskPriority.MEDIUM
    status: AgentStatus = AgentStatus.IDLE
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
```

**Example**:
```python
task = AgentTask(
    task_id="RECON-001",
    task_type="recommend_strategy",
    description="Recommend reconnaissance strategy",
    parameters={"target": "example.com"},
    priority=TaskPriority.HIGH
)
```

---

### AgentResult

Represents the result of an agent's task execution.

```python
@dataclass
class AgentResult:
    task_id: str
    agent_name: str
    status: AgentStatus
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    tokens_used: int = 0
    cost_usd: float = 0.0
    completed_at: datetime = field(default_factory=datetime.now)
```

**Example**:
```python
result = AgentResult(
    task_id="RECON-001",
    agent_name="ReconAgent",
    status=AgentStatus.COMPLETED,
    findings=[{
        "service": "http",
        "port": 80,
        "version": "nginx 1.18.0"
    }],
    recommendations=[{
        "action": "scan_for_vulnerabilities",
        "priority": "high"
    }],
    tokens_used=150,
    cost_usd=0.001
)
```

---

### AgentStatus

Enum representing agent task status.

```python
class AgentStatus(Enum):
    IDLE = "idle"
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
```

---

### TaskPriority

Enum representing task priority levels.

```python
class TaskPriority(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```

---

### AgentCapability

Enum representing agent capabilities.

```python
class AgentCapability(Enum):
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    PLANNING = "planning"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    ORCHESTRATION = "orchestration"
```

---

### AgentMetrics

Tracks performance metrics for an agent.

```python
@dataclass
class AgentMetrics:
    agent_name: str
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_tokens_used: int = 0
    total_cost: float = 0.0
    total_execution_time: float = 0.0
    average_task_time: float = 0.0
```

---

## Agent APIs

### OrchestratorAgent

Coordinates multiple specialist agents to perform complex operations.

```python
from medusa.agents import OrchestratorAgent

class OrchestratorAgent(BaseAgent):
    def __init__(
        self,
        specialist_agents: Dict[str, BaseAgent],
        llm_client: LLMClient,
        context_engine: Optional[ContextFusionEngine] = None,
        message_bus: Optional[MessageBus] = None
    ):
        """
        Initialize orchestrator agent.

        Args:
            specialist_agents: Dictionary of specialist agents
            llm_client: LLM client
            context_engine: Context fusion engine
            message_bus: Message bus for communication
        """
        pass
```

**Task Types**:
- `run_operation`: Execute complete multi-agent operation

**Example**:
```python
# Create specialist agents
recon_agent = ReconnaissanceAgent(llm_client=llm_client)
vuln_agent = VulnerabilityAnalysisAgent(llm_client=llm_client)

# Create orchestrator
orchestrator = OrchestratorAgent(
    specialist_agents={
        "ReconAgent": recon_agent,
        "VulnAnalysisAgent": vuln_agent
    },
    llm_client=llm_client
)

# Execute operation
task = AgentTask(
    task_id="OP-001",
    task_type="run_operation",
    description="Full security assessment",
    parameters={
        "target": "example.com",
        "operation_type": "full_assessment",
        "objectives": ["find_vulnerabilities"]
    }
)

result = await orchestrator.execute_task(task)
```

---

### ReconnaissanceAgent

Specializes in reconnaissance and information gathering.

```python
from medusa.agents import ReconnaissanceAgent

class ReconnaissanceAgent(BaseAgent):
    def __init__(
        self,
        llm_client: LLMClient,
        context_engine: Optional[ContextFusionEngine] = None,
        message_bus: Optional[MessageBus] = None
    ):
        """Initialize reconnaissance agent."""
        pass
```

**Task Types**:
- `recommend_strategy`: Recommend reconnaissance approach
- `analyze_network`: Analyze network infrastructure
- `suggest_tools`: Suggest appropriate tools

**Example**:
```python
agent = ReconnaissanceAgent(llm_client=llm_client)

task = AgentTask(
    task_id="RECON-001",
    task_type="recommend_strategy",
    description="Recommend reconnaissance strategy",
    parameters={"target": "example.com"}
)

result = await agent.execute_task(task)
print(result.recommendations)
```

---

### VulnerabilityAnalysisAgent

Specializes in vulnerability identification and risk assessment.

```python
from medusa.agents import VulnerabilityAnalysisAgent

class VulnerabilityAnalysisAgent(BaseAgent):
    def __init__(
        self,
        llm_client: LLMClient,
        context_engine: Optional[ContextFusionEngine] = None,
        message_bus: Optional[MessageBus] = None
    ):
        """Initialize vulnerability analysis agent."""
        pass
```

**Task Types**:
- `analyze_findings`: Analyze reconnaissance findings
- `correlate_cves`: Correlate with CVE database
- `assess_exploitability`: Assess exploitation difficulty

**Example**:
```python
agent = VulnerabilityAnalysisAgent(llm_client=llm_client)

task = AgentTask(
    task_id="VULN-001",
    task_type="analyze_findings",
    description="Analyze findings for vulnerabilities",
    parameters={
        "findings": [
            {"service": "apache", "version": "2.4.41"}
        ],
        "target": "example.com"
    }
)

result = await agent.execute_task(task)
print(result.findings)
```

---

### PlanningAgent

Specializes in strategic planning and attack chain design.

```python
from medusa.agents import PlanningAgent

class PlanningAgent(BaseAgent):
    def __init__(
        self,
        llm_client: LLMClient,
        context_engine: Optional[ContextFusionEngine] = None,
        message_bus: Optional[MessageBus] = None
    ):
        """Initialize planning agent."""
        pass
```

**Task Types**:
- `create_operation_plan`: Create comprehensive operation plan
- `design_attack_chain`: Design multi-step attack sequence
- `optimize_approach`: Optimize attack approach

**Example**:
```python
agent = PlanningAgent(llm_client=llm_client)

task = AgentTask(
    task_id="PLAN-001",
    task_type="create_operation_plan",
    description="Create operation plan",
    parameters={
        "all_findings": {
            "reconnaissance": [...],
            "vulnerabilities": [...]
        },
        "objectives": ["exploit_sqli"],
        "target": "example.com"
    }
)

result = await agent.execute_task(task)
print(result.recommendations)
```

---

### ExploitationAgent

Specializes in exploitation simulation (safe, analysis-based).

```python
from medusa.agents import ExploitationAgent

class ExploitationAgent(BaseAgent):
    def __init__(
        self,
        require_approval: bool = True,
        llm_client: LLMClient,
        context_engine: Optional[ContextFusionEngine] = None,
        message_bus: Optional[MessageBus] = None
    ):
        """
        Initialize exploitation agent.

        Args:
            require_approval: Whether to require approval for exploits
            llm_client: LLM client
            context_engine: Context fusion engine
            message_bus: Message bus
        """
        pass
```

**Task Types**:
- `plan_exploitation`: Plan exploitation approach
- `execute_exploit`: Simulate exploit execution
- `verify_access`: Verify successful exploitation
- `recommend_post_exploitation`: Suggest post-exploit actions

**Example**:
```python
agent = ExploitationAgent(
    require_approval=False,  # Auto-approve for testing
    llm_client=llm_client
)

task = AgentTask(
    task_id="EXPLOIT-001",
    task_type="plan_exploitation",
    description="Plan exploitation",
    parameters={
        "vulnerabilities": [{
            "type": "SQL Injection",
            "location": "/api/search"
        }],
        "target": "example.com"
    }
)

result = await agent.execute_task(task)
print(result.findings)
```

**⚠️ Safety**: All exploitation is SIMULATED. No real attacks are executed.

---

### ReportingAgent

Specializes in generating comprehensive security reports.

```python
from medusa.agents import ReportingAgent

class ReportingAgent(BaseAgent):
    def __init__(
        self,
        llm_client: LLMClient,
        context_engine: Optional[ContextFusionEngine] = None,
        message_bus: Optional[MessageBus] = None
    ):
        """Initialize reporting agent."""
        pass
```

**Task Types**:
- `generate_executive_summary`: Business-focused report
- `generate_technical_report`: Comprehensive technical docs
- `generate_remediation_plan`: Step-by-step fix guidance
- `aggregate_findings`: Aggregate multi-agent findings
- `generate_compliance_report`: Framework-specific assessment

**Example**:
```python
agent = ReportingAgent(llm_client=llm_client)

task = AgentTask(
    task_id="REPORT-001",
    task_type="generate_executive_summary",
    description="Generate executive summary",
    parameters={
        "findings": [...],
        "target": "example.com",
        "operation_name": "Security Assessment",
        "operation_data": {}
    }
)

result = await agent.execute_task(task)
report_id = result.metadata["report_id"]
report = agent.get_report(report_id)
```

---

## Context Fusion Engine API

### ContextFusionEngine

Combines multiple knowledge sources for rich agent context.

```python
from medusa.context.fusion_engine import ContextFusionEngine

class ContextFusionEngine:
    def __init__(
        self,
        world_model: Optional[WorldModelClient] = None,
        vector_store: Optional[VectorStore] = None
    ):
        """
        Initialize context fusion engine.

        Args:
            world_model: Neo4j graph database client
            vector_store: ChromaDB vector store
        """
        pass
```

**Methods**:

#### build_context_for_reconnaissance
```python
def build_context_for_reconnaissance(
    self,
    target: str,
    existing_findings: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Build context for reconnaissance phase.

    Args:
        target: Target system
        existing_findings: Optional existing findings

    Returns:
        Rich context dictionary
    """
    pass
```

#### build_context_for_vulnerability_analysis
```python
def build_context_for_vulnerability_analysis(
    self,
    findings: List[Dict[str, Any]],
    target: str
) -> Dict[str, Any]:
    """
    Build context for vulnerability analysis.

    Args:
        findings: Reconnaissance findings
        target: Target system

    Returns:
        Rich context dictionary
    """
    pass
```

#### build_context_for_planning
```python
def build_context_for_planning(
    self,
    all_findings: Dict[str, List[Dict[str, Any]]],
    objectives: List[str],
    target: str
) -> Dict[str, Any]:
    """
    Build context for strategic planning.

    Args:
        all_findings: All findings from previous phases
        objectives: Operation objectives
        target: Target system

    Returns:
        Rich context dictionary
    """
    pass
```

#### build_context_for_exploitation
```python
def build_context_for_exploitation(
    self,
    vulnerabilities: List[Dict[str, Any]],
    target: str
) -> Dict[str, Any]:
    """
    Build context for exploitation phase.

    Args:
        vulnerabilities: Identified vulnerabilities
        target: Target system

    Returns:
        Rich context dictionary
    """
    pass
```

#### record_action
```python
def record_action(self, action: Dict[str, Any]):
    """
    Record action to short-term memory.

    Args:
        action: Action details (agent, action_type, target, etc.)
    """
    pass
```

**Example**:
```python
# Initialize
context_engine = ContextFusionEngine(
    world_model=world_model_client,
    vector_store=vector_store
)

# Build recon context
context = context_engine.build_context_for_reconnaissance(
    target="example.com"
)

# Contains:
# - MITRE ATT&CK techniques
# - Tool suggestions
# - Known hosts
# - Recent actions
```

---

## Message Bus API

### MessageBus

Enables asynchronous communication between agents.

```python
from medusa.agents.message_bus import MessageBus

class MessageBus:
    def __init__(self):
        """Initialize message bus."""
        pass

    async def publish(self, message: AgentMessage):
        """
        Publish message to bus.

        Args:
            message: Message to publish
        """
        pass

    async def subscribe(self, topic: str, handler: Callable):
        """
        Subscribe to topic.

        Args:
            topic: Topic to subscribe to
            handler: Callback function for messages
        """
        pass
```

**AgentMessage**:
```python
@dataclass
class AgentMessage:
    sender: str
    recipient: str  # or "broadcast"
    message_type: MessageType
    content: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
```

**Example**:
```python
# Create message bus
bus = MessageBus()

# Subscribe to messages
async def handle_task_result(message: AgentMessage):
    print(f"Received result from {message.sender}")
    print(message.content)

await bus.subscribe("task_result", handle_task_result)

# Publish message
message = AgentMessage(
    sender="ReconAgent",
    recipient="Orchestrator",
    message_type=MessageType.TASK_RESULT,
    content={"findings": [...]}
)

await bus.publish(message)
```

---

## CLI Integration

### Running Operations Programmatically

```python
import asyncio
from medusa.cli_multi_agent import _run_multi_agent_operation
from medusa.config import get_config

async def run_assessment():
    config = get_config()

    result = await _run_multi_agent_operation(
        target="example.com",
        operation_type="full_assessment",
        objectives=["find_vulnerabilities"],
        auto_approve=False,
        max_duration=3600,
        config=config
    )

    return result

# Run
result = asyncio.run(run_assessment())
print(f"Operation complete: {result['operation_id']}")
print(f"Total cost: ${result['cost_summary']['total_cost_usd']:.4f}")
```

### Generating Reports Programmatically

```python
import asyncio
from medusa.cli_multi_agent import _generate_agent_report
from medusa.config import get_config

async def generate_report(operation_data):
    config = get_config()

    report = await _generate_agent_report(
        operation_data=operation_data,
        report_type="executive",
        format_type="markdown",
        config=config
    )

    return report

# Generate
report = asyncio.run(generate_report(operation_data))
print(report)
```

---

## Examples

### Example 1: Custom Agent

Create a custom agent that extends BaseAgent:

```python
from medusa.agents import BaseAgent, AgentCapability, AgentTask, AgentResult, AgentStatus
from typing import List, Optional

class CustomAgent(BaseAgent):
    def __init__(self, llm_client, *args, **kwargs):
        super().__init__(
            name="CustomAgent",
            capabilities=[AgentCapability.RECONNAISSANCE],
            llm_client=llm_client,
            *args,
            **kwargs
        )

    async def execute_task(self, task: AgentTask) -> AgentResult:
        # Your custom logic here
        result = AgentResult(
            task_id=task.task_id,
            agent_name=self.name,
            status=AgentStatus.COMPLETED,
            findings=[{"custom": "finding"}]
        )
        return result

# Use custom agent
custom_agent = CustomAgent(llm_client=llm_client)
task = AgentTask(
    task_id="CUSTOM-001",
    task_type="custom_task",
    description="Custom task",
    parameters={}
)
result = await custom_agent.execute_task(task)
```

### Example 2: Multi-Target Assessment

Assess multiple targets in parallel:

```python
import asyncio

async def assess_target(target: str, orchestrator: OrchestratorAgent):
    task = AgentTask(
        task_id=f"OP-{target}",
        task_type="run_operation",
        description=f"Assess {target}",
        parameters={
            "target": target,
            "operation_type": "full_assessment"
        }
    )
    return await orchestrator.execute_task(task)

# Assess multiple targets
targets = ["host1.com", "host2.com", "host3.com"]
tasks = [assess_target(t, orchestrator) for t in targets]
results = await asyncio.gather(*tasks)

for result in results:
    print(f"Target: {result.metadata['target']}")
    print(f"Findings: {len(result.findings)}")
    print(f"Cost: ${result.cost_usd:.4f}")
```

### Example 3: Custom Reporting

Generate custom reports with specific formatting:

```python
from medusa.agents import ReportingAgent, AgentTask

async def generate_custom_report(findings: list, target: str):
    reporting_agent = ReportingAgent(llm_client=llm_client)

    # Generate executive summary
    exec_task = AgentTask(
        task_id="REPORT-EXEC-001",
        task_type="generate_executive_summary",
        description="Generate executive summary",
        parameters={
            "findings": findings,
            "target": target,
            "operation_name": "Custom Assessment"
        }
    )

    exec_result = await reporting_agent.execute_task(exec_task)

    # Generate technical report
    tech_task = AgentTask(
        task_id="REPORT-TECH-001",
        task_type="generate_technical_report",
        description="Generate technical report",
        parameters={
            "findings": findings,
            "target": target,
            "operation_name": "Custom Assessment"
        }
    )

    tech_result = await reporting_agent.execute_task(tech_task)

    return {
        "executive": exec_result.findings[0],
        "technical": tech_result.findings[0]
    }

reports = await generate_custom_report(findings, "example.com")
```

### Example 4: Cost Monitoring

Monitor and limit costs during operations:

```python
async def run_with_cost_limit(orchestrator: OrchestratorAgent, max_cost: float):
    task = AgentTask(
        task_id="COST-LIMITED-OP",
        task_type="run_operation",
        description="Cost-limited operation",
        parameters={
            "target": "example.com",
            "operation_type": "full_assessment"
        }
    )

    result = await orchestrator.execute_task(task)

    # Check cost
    if result.cost_usd > max_cost:
        print(f"⚠️  Cost exceeded limit: ${result.cost_usd:.4f} > ${max_cost:.2f}")
    else:
        print(f"✅ Within budget: ${result.cost_usd:.4f}")

    return result

result = await run_with_cost_limit(orchestrator, max_cost=0.10)
```

---

## Error Handling

### Handling Agent Failures

```python
try:
    result = await agent.execute_task(task)

    if result.status == AgentStatus.FAILED:
        print(f"Agent failed: {result.error}")
        # Handle failure
    else:
        print("Agent succeeded")
        # Process results

except Exception as e:
    print(f"Unexpected error: {e}")
    # Handle exception
```

### Timeout Handling

```python
import asyncio

async def execute_with_timeout(agent, task, timeout_seconds=300):
    try:
        result = await asyncio.wait_for(
            agent.execute_task(task),
            timeout=timeout_seconds
        )
        return result
    except asyncio.TimeoutError:
        print(f"Task timed out after {timeout_seconds}s")
        return None

result = await execute_with_timeout(agent, task, timeout_seconds=60)
```

---

## Best Practices

### 1. Always Close Connections

```python
llm_client = create_llm_client(config)
world_model = WorldModelClient()

try:
    await world_model.connect()
    # Your code here
finally:
    await llm_client.close()
    await world_model.close()
```

### 2. Use Context Managers (When Available)

```python
async with WorldModelClient() as world_model:
    # Your code here
    pass
```

### 3. Handle Partial Results

```python
result = await orchestrator.execute_task(task)

if result.status == AgentStatus.COMPLETED:
    # Full success
    process_all_findings(result.findings)
elif result.status == AgentStatus.FAILED:
    # Check if partial results available
    if result.findings:
        print("Partial results available")
        process_partial_findings(result.findings)
```

### 4. Monitor Metrics

```python
# After operation
for agent_name, agent in specialist_agents.items():
    metrics = agent.metrics
    print(f"{agent_name}:")
    print(f"  Tasks: {metrics.tasks_completed}")
    print(f"  Cost: ${metrics.total_cost:.4f}")
    print(f"  Avg Time: {metrics.average_task_time:.2f}s")
```

---

## Support

For additional help:
- [User Guide](USER_GUIDE.md)
- [Architecture Guide](ARCHITECTURE.md)
- [GitHub Issues](https://github.com/your-org/project-medusa/issues)
- [Documentation](https://docs.medusa-security.io)
