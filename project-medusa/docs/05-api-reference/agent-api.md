# Agent API Reference

Complete reference for MEDUSA multi-agent system.

## Overview

MEDUSA's multi-agent architecture consists of specialized AI agents that collaborate to perform autonomous penetration testing. Each agent has specific capabilities and communicates through a message bus coordinated by the Orchestrator.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   OrchestratorAgent                     │
│              (Coordinates all agents)                   │
└─────────────────────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Reconnais-   │  │ Vulnerability│  │  Planning    │
│ sance Agent  │  │ Analysis     │  │  Agent       │
│              │  │ Agent        │  │              │
└──────────────┘  └──────────────┘  └──────────────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │        Exploitation Agent      │
        └────────────────────────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │        Reporting Agent         │
        └────────────────────────────────┘
```

## Core Components

### Base Agent

All agents inherit from `BaseAgent` which provides:
- LLM client integration
- Context fusion engine integration
- Cost tracking
- Error handling
- Message bus integration

**Class:** `medusa.agents.BaseAgent`

**Methods:**

```python
async def run_task(task: AgentTask) -> AgentResult:
    """
    Execute a task.

    Args:
        task: Task to execute

    Returns:
        Task execution result
    """
```

```python
@abstractmethod
async def _execute_task(task: AgentTask) -> Dict[str, Any]:
    """
    Execute task logic (implemented by subclasses).

    Args:
        task: Task to execute

    Returns:
        Task result data
    """
```

---

## Agent Types

### 1. OrchestratorAgent

**Purpose:** Coordinates all other agents and manages the overall penetration testing workflow.

**Capabilities:**
- Task delegation
- Agent coordination
- Workflow management
- Decision-making on next steps

**Class:** `medusa.agents.OrchestratorAgent`

**Task Types:**
- `coordinate_operation` - Coordinate full security operation
- `delegate_task` - Delegate task to specialist agent
- `decide_next_action` - Decide next action based on current state

**Example Usage:**
```python
from medusa.agents import OrchestratorAgent
from medusa.agents.data_models import AgentTask, TaskPriority

# Create orchestrator
orchestrator = OrchestratorAgent(
    llm_client=llm_client,
    context_engine=context_engine,
    message_bus=message_bus
)

# Create coordination task
task = AgentTask(
    task_id="op_001",
    task_type="coordinate_operation",
    description="Coordinate full security assessment",
    parameters={
        "target": "http://localhost:3001",
        "operation_type": "full_assessment",
        "objectives": ["find_credentials", "escalate_privileges"]
    },
    priority=TaskPriority.HIGH
)

# Execute
result = await orchestrator.run_task(task)
```

---

### 2. ReconnaissanceAgent

**Purpose:** Performs network and service discovery.

**Capabilities:**
- Network scanning (Nmap)
- Subdomain enumeration (Amass)
- HTTP probing (httpx)
- Port and service detection
- Domain discovery

**Class:** `medusa.agents.ReconnaissanceAgent`

**Task Types:**
- `recommend_recon_strategy` - Recommend reconnaissance approach
- `execute_network_scan` - Execute network scan
- `enumerate_subdomains` - Discover subdomains
- `probe_web_services` - Probe HTTP services
- `analyze_scan_results` - Analyze reconnaissance findings

**Example Usage:**
```python
from medusa.agents import ReconnaissanceAgent

# Create reconnaissance agent
recon_agent = ReconnaissanceAgent(
    llm_client=llm_client,
    context_engine=context_engine,
    tool_executor=tool_executor
)

# Network scan task
task = AgentTask(
    task_id="recon_001",
    task_type="execute_network_scan",
    description="Scan target network for open ports",
    parameters={
        "target": "192.168.1.0/24",
        "scan_type": "comprehensive"
    }
)

result = await recon_agent.run_task(task)
```

**Result Data:**
```python
{
    "hosts_discovered": 15,
    "ports_found": 47,
    "services_identified": 32,
    "findings": [
        {
            "host": "192.168.1.10",
            "port": 80,
            "service": "http",
            "version": "Apache 2.4.41"
        },
        # ...
    ]
}
```

---

### 3. VulnerabilityAnalysisAgent

**Purpose:** Analyzes discovered services for vulnerabilities.

**Capabilities:**
- CVE correlation
- Vulnerability risk assessment
- Exploit availability analysis
- MITRE ATT&CK technique mapping
- Vulnerability prioritization

**Class:** `medusa.agents.VulnerabilityAnalysisAgent`

**Task Types:**
- `analyze_vulnerabilities` - Analyze findings for vulnerabilities
- `assess_risk` - Assess vulnerability risk levels
- `correlate_cves` - Correlate with CVE database
- `recommend_exploits` - Recommend applicable exploits
- `prioritize_targets` - Prioritize vulnerable targets

**Example Usage:**
```python
from medusa.agents import VulnerabilityAnalysisAgent

vuln_agent = VulnerabilityAnalysisAgent(
    llm_client=llm_client,
    context_engine=context_engine
)

task = AgentTask(
    task_id="vuln_001",
    task_type="analyze_vulnerabilities",
    description="Analyze discovered services for vulnerabilities",
    parameters={
        "findings": recon_results,
        "target_info": target_metadata
    }
)

result = await vuln_agent.run_task(task)
```

**Result Data:**
```python
{
    "vulnerabilities_found": 8,
    "critical_count": 2,
    "high_count": 3,
    "medium_count": 3,
    "findings": [
        {
            "cve": "CVE-2021-44228",
            "severity": "CRITICAL",
            "service": "Apache Log4j",
            "affected_hosts": ["192.168.1.10"],
            "exploit_available": True,
            "mitre_techniques": ["T1190"],
            "recommendation": "Test for Log4Shell vulnerability"
        },
        # ...
    ]
}
```

---

### 4. PlanningAgent

**Purpose:** Creates attack strategies and execution plans.

**Capabilities:**
- Attack chain design
- Technique selection
- Risk assessment
- Resource planning
- Success probability estimation

**Class:** `medusa.agents.PlanningAgent`

**Task Types:**
- `create_attack_plan` - Create comprehensive attack plan
- `design_attack_chain` - Design multi-step attack chain
- `assess_plan_risk` - Assess plan risk and feasibility
- `optimize_plan` - Optimize plan for efficiency

**Example Usage:**
```python
from medusa.agents import PlanningAgent

planning_agent = PlanningAgent(
    llm_client=llm_client,
    context_engine=context_engine
)

task = AgentTask(
    task_id="plan_001",
    task_type="create_attack_plan",
    description="Create attack plan based on vulnerabilities",
    parameters={
        "vulnerabilities": vuln_results,
        "objectives": ["find_credentials", "escalate_privileges"],
        "constraints": {"max_risk": "HIGH"}
    }
)

result = await planning_agent.run_task(task)
```

**Result Data:**
```python
{
    "plan_id": "plan_001",
    "attack_chain": [
        {
            "step": 1,
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "target": "192.168.1.10:8080",
            "tool": "sqlmap",
            "risk_level": "MEDIUM",
            "success_probability": 0.75
        },
        {
            "step": 2,
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "action": "Use extracted credentials",
            "risk_level": "LOW",
            "success_probability": 0.85
        },
        # ...
    ],
    "overall_risk": "MEDIUM",
    "estimated_duration": 1800,
    "success_probability": 0.65
}
```

---

### 5. ExploitationAgent

**Purpose:** Executes exploitation attempts (simulated).

**Capabilities:**
- SQL injection testing
- Authentication bypass
- Privilege escalation
- Credential extraction
- Web vulnerability exploitation

**Class:** `medusa.agents.ExploitationAgent`

**Task Types:**
- `execute_exploit` - Execute specific exploit
- `test_sql_injection` - Test for SQL injection
- `attempt_auth_bypass` - Attempt authentication bypass
- `extract_credentials` - Extract credentials
- `verify_exploit_success` - Verify exploitation success

**Example Usage:**
```python
from medusa.agents import ExploitationAgent

exploit_agent = ExploitationAgent(
    llm_client=llm_client,
    tool_executor=tool_executor,
    approval_gate=approval_gate
)

task = AgentTask(
    task_id="exploit_001",
    task_type="test_sql_injection",
    description="Test SQL injection on login endpoint",
    parameters={
        "target_url": "http://192.168.1.10/login",
        "parameter": "username",
        "technique_id": "T1190"
    }
)

result = await exploit_agent.run_task(task)
```

**Result Data:**
```python
{
    "success": True,
    "technique_id": "T1190",
    "exploitation_method": "SQL Injection",
    "findings": {
        "vulnerability_confirmed": True,
        "database_type": "MySQL",
        "databases_found": ["medical_db", "users_db"],
        "credentials_extracted": [
            {"username": "admin", "password_hash": "5f4dcc3b..."}
        ]
    },
    "risk_level": "HIGH",
    "mitigation": "Use parameterized queries"
}
```

---

### 6. ReportingAgent

**Purpose:** Generates comprehensive security reports.

**Capabilities:**
- Report generation (HTML, JSON, Markdown)
- MITRE ATT&CK mapping
- Vulnerability documentation
- Executive summaries
- Technical documentation

**Class:** `medusa.agents.ReportingAgent`

**Task Types:**
- `generate_report` - Generate full operation report
- `create_executive_summary` - Create executive summary
- `document_findings` - Document specific findings
- `map_mitre_techniques` - Map to MITRE ATT&CK framework

**Example Usage:**
```python
from medusa.agents import ReportingAgent

reporting_agent = ReportingAgent(
    llm_client=llm_client
)

task = AgentTask(
    task_id="report_001",
    task_type="generate_report",
    description="Generate comprehensive security report",
    parameters={
        "operation_results": all_results,
        "format": "html",
        "include_mitre": True
    }
)

result = await reporting_agent.run_task(task)
```

**Result Data:**
```python
{
    "report_generated": True,
    "format": "html",
    "file_path": "~/.medusa/reports/operation_20240115_143022_technical.html",
    "summary": {
        "total_hosts": 15,
        "vulnerabilities_found": 8,
        "critical_findings": 2,
        "mitre_techniques_used": 12
    }
}
```

---

## Data Models

### AgentTask

Represents a task for an AI agent.

```python
@dataclass
class AgentTask:
    task_id: str                        # Unique task identifier
    task_type: str                      # Type of task
    description: str                    # Human-readable description
    parameters: Dict[str, Any]          # Task-specific parameters
    priority: TaskPriority              # Task priority level
    status: TaskStatus                  # Current task status
    created_at: datetime                # Task creation timestamp
    context: Optional[Dict[str, Any]]   # Additional context
    parent_task_id: Optional[str]       # Parent task ID (for subtasks)
```

**TaskPriority Enum:**
```python
class TaskPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```

**TaskStatus Enum:**
```python
class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
```

---

### AgentResult

Represents the result of an agent task execution.

```python
@dataclass
class AgentResult:
    task_id: str                        # Associated task ID
    status: TaskStatus                  # Execution status
    agent_name: Optional[str]           # Agent that executed task
    data: Dict[str, Any]                # Result data
    metadata: Dict[str, Any]            # Additional metadata
    error: Optional[str]                # Error message if failed
    cost_usd: float                     # Cost in USD for LLM calls
    tokens_used: int                    # Total tokens used
    duration_seconds: float             # Execution duration
    context_used: Optional[Dict]        # Context provided to LLM
    llm_response: Optional[str]         # Raw LLM response
    findings: List[Dict[str, Any]]      # Findings discovered
```

---

### AgentMessage

Represents inter-agent communication messages.

```python
@dataclass
class AgentMessage:
    message_id: str                     # Unique message identifier
    sender: str                         # Sender agent name
    recipient: str                      # Recipient agent name (or "all")
    message_type: str                   # Message type
    content: Dict[str, Any]             # Message content
    timestamp: datetime                 # Message timestamp
    priority: TaskPriority              # Message priority
```

---

### AgentCapability

Defines agent capabilities.

```python
class AgentCapability(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    PLANNING = "planning"
    REPORTING = "reporting"
    ORCHESTRATION = "orchestration"
```

---

### AgentStatus

Defines agent execution status.

```python
class AgentStatus(str, Enum):
    IDLE = "idle"
    THINKING = "thinking"
    EXECUTING = "executing"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
```

---

## Message Bus

The `MessageBus` enables asynchronous communication between agents.

**Class:** `medusa.agents.MessageBus`

**Methods:**

```python
async def publish(message: AgentMessage) -> None:
    """Publish a message to the bus."""

async def subscribe(agent_name: str, message_types: List[str]) -> None:
    """Subscribe agent to specific message types."""

async def get_messages(agent_name: str) -> List[AgentMessage]:
    """Get pending messages for agent."""

async def clear_messages(agent_name: str) -> None:
    """Clear all messages for agent."""
```

**Example Usage:**
```python
from medusa.agents import MessageBus, AgentMessage
from medusa.agents.data_models import TaskPriority

message_bus = MessageBus()

# Subscribe to messages
await message_bus.subscribe("VulnerabilityAnalysisAgent", ["findings", "vulnerabilities"])

# Publish message
message = AgentMessage(
    message_id="msg_001",
    sender="ReconnaissanceAgent",
    recipient="VulnerabilityAnalysisAgent",
    message_type="findings",
    content={
        "findings": scan_results,
        "host_count": 15
    },
    timestamp=datetime.now(),
    priority=TaskPriority.HIGH
)

await message_bus.publish(message)

# Retrieve messages
messages = await message_bus.get_messages("VulnerabilityAnalysisAgent")
```

---

## Context Fusion Engine

The `ContextFusionEngine` provides context-aware recommendations using RAG (Retrieval-Augmented Generation).

**Class:** `medusa.context.ContextFusionEngine`

**Methods:**

```python
async def get_contextual_recommendations(
    query: str,
    operation_phase: str,
    operation_state: Optional[Dict[str, Any]] = None,
    top_k: int = 5
) -> List[Dict[str, Any]]:
    """
    Get context-aware recommendations.

    Args:
        query: Context query
        operation_phase: Current operation phase
        operation_state: Current operation state
        top_k: Number of recommendations to return

    Returns:
        List of contextual recommendations
    """
```

**Example Usage:**
```python
from medusa.context.fusion_engine import ContextFusionEngine

context_engine = ContextFusionEngine(llm_client=llm_client)

recommendations = await context_engine.get_contextual_recommendations(
    query="SQL injection testing strategies",
    operation_phase="exploitation",
    operation_state={
        "target": "http://localhost:3001",
        "vulnerabilities_found": ["SQL Injection"],
        "databases_discovered": ["medical_db"]
    },
    top_k=5
)
```

**Recommendation Format:**
```python
[
    {
        "technique": "Time-based SQL Injection",
        "description": "Use time delays to infer database structure",
        "relevance_score": 0.92,
        "source": "OWASP Testing Guide"
    },
    # ...
]
```

---

## Cost Tracking

All agents track LLM usage costs.

**Access Cost Data:**
```python
# Individual agent cost
agent.total_cost  # Total cost in USD

# Result-level cost
result.cost_usd  # Cost for specific task execution
result.tokens_used  # Tokens used for task
```

**Aggregate Cost Tracking:**
```python
from medusa.cli_ux_enhancements import record_operation_cost

# Record operation cost
await record_operation_cost(
    operation_id="op_001",
    cost_usd=0.25,
    tokens_used=5000,
    agent_name="ReconnaissanceAgent"
)
```

---

## Approval Gates

Exploitation actions require approval based on risk level.

**Integration:**
```python
from medusa.approval import ApprovalGate, Action, RiskLevel

approval_gate = ApprovalGate()

# Create action requiring approval
action = Action(
    command="sqlmap -u http://target/api --dbs",
    technique_id="T1190",
    technique_name="Exploit Public-Facing Application",
    risk_level=RiskLevel.MEDIUM,
    impact_description="Attempt SQL injection to enumerate databases",
    target="http://target/api"
)

# Request approval
approved = approval_gate.request_approval(action)

if approved:
    # Execute exploitation
    pass
```

**Risk Levels:**
- `LOW` - Auto-approved (e.g., port scanning)
- `MEDIUM` - Prompt user (e.g., vulnerability scanning)
- `HIGH` - Requires approval (e.g., exploitation attempts)
- `CRITICAL` - Always requires approval (e.g., data modification)

---

## Error Handling

All agents handle errors gracefully and return structured error results.

**Error Result Example:**
```python
AgentResult(
    task_id="task_001",
    status=TaskStatus.FAILED,
    error="Connection timeout to target host",
    duration_seconds=30.5,
    cost_usd=0.0,
    tokens_used=0
)
```

**Best Practices:**
- Always check `result.status` before using `result.data`
- Log errors for debugging: `result.error`
- Retry failed tasks with exponential backoff
- Monitor agent status: `agent.status`

---

## Complete Example

Full multi-agent operation workflow:

```python
import asyncio
from medusa.config import get_config
from medusa.core.llm import LLMConfig, create_llm_client
from medusa.context.fusion_engine import ContextFusionEngine
from medusa.agents import (
    OrchestratorAgent,
    ReconnaissanceAgent,
    VulnerabilityAnalysisAgent,
    PlanningAgent,
    ExploitationAgent,
    ReportingAgent,
    MessageBus,
    AgentTask,
    TaskPriority
)

async def run_multi_agent_operation(target: str):
    # Setup
    config = get_config()
    llm_config = LLMConfig(**config.get_llm_config())
    llm_client = create_llm_client(llm_config)
    context_engine = ContextFusionEngine(llm_client=llm_client)
    message_bus = MessageBus()

    # Create agents
    orchestrator = OrchestratorAgent(
        llm_client=llm_client,
        context_engine=context_engine,
        message_bus=message_bus
    )

    recon_agent = ReconnaissanceAgent(
        llm_client=llm_client,
        context_engine=context_engine,
        message_bus=message_bus
    )

    vuln_agent = VulnerabilityAnalysisAgent(
        llm_client=llm_client,
        context_engine=context_engine,
        message_bus=message_bus
    )

    planning_agent = PlanningAgent(
        llm_client=llm_client,
        context_engine=context_engine,
        message_bus=message_bus
    )

    exploit_agent = ExploitationAgent(
        llm_client=llm_client,
        message_bus=message_bus
    )

    reporting_agent = ReportingAgent(
        llm_client=llm_client,
        message_bus=message_bus
    )

    # Create orchestration task
    task = AgentTask(
        task_id="op_001",
        task_type="coordinate_operation",
        description="Full security assessment",
        parameters={
            "target": target,
            "operation_type": "full_assessment",
            "objectives": ["find_credentials", "escalate_privileges"]
        },
        priority=TaskPriority.HIGH
    )

    # Execute
    result = await orchestrator.run_task(task)

    # Cleanup
    await llm_client.close()

    return result

# Run
result = asyncio.run(run_multi_agent_operation("http://localhost:3001"))
print(f"Operation completed: {result.status}")
print(f"Total cost: ${result.cost_usd:.4f}")
```

---

## See Also

- [CLI API Reference](cli-api.md) - Command-line interface documentation
- [AI Agents Guide](../02-development/ai-agents-guide.md) - Agent development guide
- [Security Policy](../06-security/security-policy.md) - Security and ethical guidelines
- [Technical Reference](../02-development/technical-reference.md) - Technical architecture details
