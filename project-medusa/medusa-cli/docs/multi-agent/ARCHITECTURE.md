# Multi-Agent System Architecture

## Overview

MEDUSA's Multi-Agent System is a sophisticated framework built on the principles of distributed AI systems, where specialized agents collaborate to perform complex security assessment tasks. This document provides a comprehensive technical overview of the architecture, design patterns, and implementation details.

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Core Components](#core-components)
3. [Agent Design Patterns](#agent-design-patterns)
4. [Communication Infrastructure](#communication-infrastructure)
5. [Context Fusion Engine](#context-fusion-engine)
6. [Smart Model Routing](#smart-model-routing)
7. [Cost Tracking](#cost-tracking)
8. [Data Flow](#data-flow)
9. [Scaling and Performance](#scaling-and-performance)
10. [Security Considerations](#security-considerations)

---

## System Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI Interface                            │
│         medusa agent run | status | report                   │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                  Orchestrator Agent                          │
│              (Supervisor Pattern)                            │
└───┬───────┬───────┬───────┬──────────┬──────────────────────┘
    │       │       │       │          │
┌───▼───┐ ┌▼──────┐ ┌▼────┐ ┌▼───────┐ ┌▼──────────┐
│ Recon │ │ Vuln  │ │Plan │ │Exploit │ │ Reporting │
│ Agent │ │Agent  │ │Agent│ │ Agent  │ │  Agent    │
└───┬───┘ └┬──────┘ └┬────┘ └┬───────┘ └┬──────────┘
    │      │         │        │          │
    └──────┴─────────┴────────┴──────────┘
                     │
         ┌───────────▼────────────┐
         │    Message Bus         │
         │  (Pub/Sub Pattern)     │
         └───────────┬────────────┘
                     │
    ┌────────────────┼────────────────┐
    │                │                │
┌───▼────┐  ┌────────▼────┐  ┌───────▼──────┐
│ Neo4j  │  │  ChromaDB   │  │ AWS Bedrock  │
│ Graph  │  │ Vector Store│  │   Claude     │
└────────┘  └─────────────┘  └──────────────┘
```

### Layer Architecture

#### 1. **Presentation Layer** (CLI)
- User interface via Typer CLI framework
- Rich terminal output with tables and progress bars
- Command parsing and validation

#### 2. **Orchestration Layer** (Orchestrator Agent)
- Task delegation and coordination
- Multi-phase operation management
- Result aggregation
- Error handling and recovery

#### 3. **Agent Layer** (Specialist Agents)
- 6 specialized agents with distinct capabilities
- Independent task execution
- Inter-agent communication via message bus

#### 4. **Intelligence Layer** (LLM Integration)
- AWS Bedrock Claude 3.5 (Sonnet & Haiku)
- Smart model routing for cost optimization
- Prompt engineering and response parsing

#### 5. **Data Layer** (Knowledge Bases)
- **Neo4j Graph DB**: Infrastructure state and relationships
- **ChromaDB Vector Store**: Semantic knowledge (MITRE, CVEs, tools)
- **Operation History**: Short-term memory

---

## Core Components

### 1. Orchestrator Agent

**Role**: Supervisor that coordinates all specialist agents.

**Key Responsibilities**:
- Task delegation based on agent capabilities
- Multi-phase operation coordination
- Result aggregation and synthesis
- Cost tracking and metrics collection

**Design Pattern**: **Supervisor Pattern**

**Code Structure**:
```python
class OrchestratorAgent(BaseAgent):
    def __init__(self, specialist_agents: Dict[str, BaseAgent]):
        self.specialist_agents = specialist_agents
        self.capabilities = [AgentCapability.ORCHESTRATION]

    async def execute_task(self, task: AgentTask) -> AgentResult:
        # Delegate to appropriate specialist agents
        # Coordinate multi-phase operations
        # Aggregate results
        pass

    def _find_agent_by_capability(self, capability: AgentCapability):
        # Find agent with matching capability
        pass

    async def _delegate_task(self, task: AgentTask, agent_name: str):
        # Delegate task to specific agent
        pass
```

**Operation Flow**:
1. Receive operation task
2. Break down into phases (recon → vuln → planning → exploitation → reporting)
3. Delegate each phase to appropriate agent
4. Collect and aggregate results
5. Track costs and metrics
6. Return comprehensive operation result

---

### 2. Specialist Agents

#### ReconnaissanceAgent

**Capability**: `RECONNAISSANCE`

**Responsibilities**:
- Recommend reconnaissance strategies
- Suggest appropriate tools
- Analyze network infrastructure
- Identify services and technologies

**Context Requirements**:
- MITRE ATT&CK discovery techniques
- Tool documentation (Nmap, Masscan, etc.)
- Known hosts from graph database

**Model Routing**: Uses **Haiku** (moderate complexity)

---

#### VulnerabilityAnalysisAgent

**Capability**: `VULNERABILITY_ANALYSIS`

**Responsibilities**:
- Correlate findings with CVE database
- Assess exploitability
- Prioritize vulnerabilities by risk
- Provide detailed impact analysis

**Context Requirements**:
- CVE database (20+ high-impact CVEs)
- MITRE ATT&CK exploitation techniques
- Known vulnerabilities from graph database

**Model Routing**: Uses **Haiku** (moderate complexity)

---

#### PlanningAgent

**Capability**: `PLANNING`

**Responsibilities**:
- Design attack chains
- Create operational plans
- Optimize attack sequences
- Consider MITRE ATT&CK tactics

**Context Requirements**:
- All findings from previous phases
- MITRE ATT&CK tactics and techniques
- Attack chain templates
- Full operation history

**Model Routing**: Uses **Sonnet** (complex reasoning required)

---

#### ExploitationAgent

**Capability**: `EXPLOITATION`

**Responsibilities**:
- Plan exploitation approaches
- Simulate exploit execution (NO REAL ATTACKS)
- Manage approval gates
- Recommend post-exploitation actions

**Context Requirements**:
- Known exploits for vulnerabilities
- MITRE ATT&CK exploitation techniques
- Credentials database
- Exploitation tool documentation

**Model Routing**: Uses **Haiku** (moderate complexity)

**Safety Features**:
- All exploitation is SIMULATED
- Approval gates for sensitive actions
- No real attacks executed
- Analysis and recommendation only

---

#### ReportingAgent

**Capability**: `REPORTING`

**Responsibilities**:
- Generate executive summaries
- Create technical reports
- Produce remediation plans
- Map to compliance frameworks

**Context Requirements**:
- All findings from operation
- Agent metrics and statistics
- Cost tracking data

**Model Routing**: Uses **Sonnet** (high-quality reports required)

**Report Types**:
- Executive Summary (business-focused)
- Technical Report (comprehensive technical docs)
- Remediation Plan (step-by-step guidance)
- Compliance Report (framework mapping)

---

### 3. Base Agent Architecture

All agents inherit from `BaseAgent`:

```python
class BaseAgent(ABC):
    def __init__(
        self,
        name: str,
        capabilities: List[AgentCapability],
        llm_client: LLMClient,
        context_engine: Optional[ContextFusionEngine] = None,
        message_bus: Optional[MessageBus] = None
    ):
        self.name = name
        self.capabilities = capabilities
        self.llm_client = llm_client
        self.context_engine = context_engine
        self.message_bus = message_bus
        self.metrics = AgentMetrics(agent_name=name)
        self.logger = logging.getLogger(f"medusa.agents.{name}")

    @abstractmethod
    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute agent-specific task"""
        pass

    def can_handle(self, capability: AgentCapability) -> bool:
        """Check if agent has capability"""
        return capability in self.capabilities
```

**Key Features**:
- Abstract base class enforcing common interface
- Built-in metrics tracking
- Context engine integration
- Message bus communication
- Logging infrastructure

---

## Agent Design Patterns

### 1. Supervisor Pattern (Orchestrator)

The Orchestrator uses the **Supervisor Pattern** to manage specialist agents:

**Benefits**:
- Centralized coordination
- Clear separation of concerns
- Easy to add new agents
- Fault tolerance (continue if one agent fails)

**Implementation**:
```python
async def _run_operation(self, task: AgentTask) -> AgentResult:
    # Phase 1: Reconnaissance
    recon_result = await self._delegate_task(recon_task, "ReconAgent")

    # Phase 2: Vulnerability Analysis
    vuln_result = await self._delegate_task(vuln_task, "VulnAnalysisAgent")

    # Phase 3: Planning
    planning_result = await self._delegate_task(planning_task, "PlanningAgent")

    # Aggregate results
    return self._aggregate_results([recon_result, vuln_result, planning_result])
```

---

### 2. Capability-Based Routing

Agents declare capabilities, orchestrator routes based on them:

```python
class AgentCapability(Enum):
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    PLANNING = "planning"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    ORCHESTRATION = "orchestration"
```

**Benefits**:
- Flexible task delegation
- Easy to extend with new capabilities
- Clear agent responsibilities

---

### 3. Message-Oriented Architecture

Agents communicate via asynchronous messages:

```python
class MessageBus:
    async def publish(self, message: AgentMessage):
        # Publish to subscribers
        pass

    async def subscribe(self, topic: str, handler: Callable):
        # Subscribe to topic
        pass
```

**Benefits**:
- Loose coupling between agents
- Asynchronous communication
- Scalable architecture

---

## Communication Infrastructure

### Message Bus

**Implementation**: Publish-Subscribe Pattern

**Message Types**:
```python
class MessageType(Enum):
    TASK_ASSIGNMENT = "task_assignment"
    TASK_RESULT = "task_result"
    STATUS_UPDATE = "status_update"
    ERROR = "error"
```

**Message Structure**:
```python
@dataclass
class AgentMessage:
    sender: str
    recipient: str  # or "broadcast"
    message_type: MessageType
    content: Dict[str, Any]
    timestamp: datetime
    message_id: str
```

### Inter-Agent Communication Flow

```
1. Orchestrator publishes task assignment
   ↓
2. Target agent receives message
   ↓
3. Agent executes task
   ↓
4. Agent publishes result message
   ↓
5. Orchestrator receives and processes result
```

---

## Context Fusion Engine

### Architecture

The Context Fusion Engine combines multiple knowledge sources:

```python
class ContextFusionEngine:
    def __init__(
        self,
        world_model: WorldModelClient,  # Neo4j
        vector_store: VectorStore        # ChromaDB
    ):
        self.world_model = world_model
        self.vector_store = vector_store
        self.operation_history = []
```

### Knowledge Sources

#### 1. **Neo4j Graph Database** (Current State)
- **Nodes**: Hosts, Services, Vulnerabilities, Credentials
- **Edges**: Relationships (runs_on, connects_to, exploits)
- **Queries**: Cypher queries for path finding

**Example**:
```cypher
MATCH (h:Host)-[:RUNS]->(s:Service)
WHERE s.port = 80
RETURN h, s
```

#### 2. **ChromaDB Vector Store** (Semantic Knowledge)
- **Collections**:
  - `mitre_attack`: 200+ MITRE techniques
  - `cve_database`: 20+ high-impact CVEs
  - `tool_documentation`: 30+ tool commands
  - `operation_history`: Past operations

**Example**:
```python
vector_store.search_mitre_techniques(
    query="network service discovery",
    n_results=5
)
```

#### 3. **Operation History** (Short-Term Memory)
- Recent actions (last 50)
- Task results
- Agent interactions

### Context Building

Different agents need different context:

```python
# For Reconnaissance
context = context_engine.build_context_for_reconnaissance(
    target="example.com"
)
# Returns: MITRE techniques, tool suggestions, known hosts

# For Vulnerability Analysis
context = context_engine.build_context_for_vulnerability_analysis(
    findings=[...]
)
# Returns: CVE correlations, exploitability data

# For Planning
context = context_engine.build_context_for_planning(
    all_findings={...}
)
# Returns: Attack chains, MITRE tactics, full history

# For Exploitation
context = context_engine.build_context_for_exploitation(
    vulnerabilities=[...]
)
# Returns: Known exploits, credentials, exploitation techniques
```

---

## Smart Model Routing

### Cost Optimization Strategy

**Problem**: Claude 3.5 Sonnet is expensive ($3/$15 per 1M tokens)

**Solution**: Route simple/moderate tasks to Haiku ($0.80/$4 per 1M tokens)

**Savings**: 70-80% cost reduction

### Task Complexity Classification

```python
class TaskComplexity(Enum):
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
```

### Routing Rules

| Task Type | Complexity | Model | Cost |
|-----------|------------|-------|------|
| Recommend recon strategy | MODERATE | Haiku | Low |
| Analyze vulnerabilities | MODERATE | Haiku | Low |
| Create attack plan | COMPLEX | Sonnet | High |
| Plan exploitation | MODERATE | Haiku | Low |
| Generate reports | COMPLEX | Sonnet | High |

### Implementation

```python
class ModelRouter:
    def select_model(self, task_type: str) -> str:
        complexity = self._assess_complexity(task_type)

        if complexity == TaskComplexity.COMPLEX:
            return self.smart_model  # Sonnet
        else:
            return self.fast_model  # Haiku
```

### Usage in Agents

```python
# Agent automatically uses routing
llm_response = await self.llm_client.generate_with_routing(
    prompt=prompt,
    task_type="recommend_recon_strategy",  # Determines model
    force_json=True
)
```

---

## Cost Tracking

### Multi-Level Tracking

#### 1. **Per-Request Tracking**
```python
class LLMResponse:
    tokens_used: int
    cost_usd: float
    model: str
    latency_ms: int
```

#### 2. **Per-Agent Tracking**
```python
class AgentMetrics:
    agent_name: str
    tasks_completed: int
    tasks_failed: int
    total_tokens_used: int
    total_cost: float
    average_task_time: float
```

#### 3. **Per-Operation Tracking**
```python
{
    "cost_summary": {
        "total_tokens": 2400,
        "total_cost_usd": 0.08
    },
    "agent_metrics": {
        "recon": {"total_cost": 0.01},
        "vuln_analysis": {"total_cost": 0.02},
        "planning": {"total_cost": 0.03},
        ...
    }
}
```

### Cost Aggregation

```python
# Orchestrator aggregates costs from all agents
total_cost = sum(
    agent.metrics.total_cost
    for agent in self.specialist_agents.values()
)
```

---

## Data Flow

### Complete Operation Flow

```
1. CLI Command
   └─ medusa agent run http://example.com

2. CLI Parser
   └─ Parse arguments and options
   └─ Validate inputs

3. Initialization
   └─ Create LLM client (AWS Bedrock)
   └─ Connect to Neo4j graph database
   └─ Connect to ChromaDB vector store
   └─ Initialize context fusion engine
   └─ Create message bus
   └─ Instantiate all 6 agents

4. Task Creation
   └─ Create AgentTask for orchestrator
   └─ Include target, operation type, objectives

5. Phase 1: Reconnaissance
   ├─ Orchestrator delegates to ReconAgent
   ├─ ReconAgent builds context from:
   │  ├─ MITRE ATT&CK techniques
   │  ├─ Tool documentation
   │  └─ Known hosts from graph
   ├─ ReconAgent calls LLM (Haiku) with context
   ├─ LLM generates reconnaissance strategy
   ├─ ReconAgent returns AgentResult
   └─ Cost tracked: ~$0.01

6. Phase 2: Vulnerability Analysis
   ├─ Orchestrator delegates to VulnAnalysisAgent
   ├─ VulnAnalysisAgent builds context from:
   │  ├─ CVE database
   │  ├─ Recon findings
   │  └─ MITRE exploitation techniques
   ├─ VulnAnalysisAgent calls LLM (Haiku)
   ├─ LLM correlates with CVEs, assesses risk
   ├─ VulnAnalysisAgent returns AgentResult
   └─ Cost tracked: ~$0.02

7. Phase 3: Strategic Planning
   ├─ Orchestrator delegates to PlanningAgent
   ├─ PlanningAgent builds context from:
   │  ├─ All findings
   │  ├─ MITRE ATT&CK tactics
   │  ├─ Attack chain templates
   │  └─ Full operation history
   ├─ PlanningAgent calls LLM (Sonnet) for complex reasoning
   ├─ LLM designs attack chains
   ├─ PlanningAgent returns AgentResult
   └─ Cost tracked: ~$0.03 (higher - uses Sonnet)

8. Phase 4: Exploitation (Optional)
   ├─ Orchestrator delegates to ExploitationAgent
   ├─ ExploitationAgent builds context from:
   │  ├─ Known exploits
   │  ├─ MITRE exploitation techniques
   │  ├─ Credentials database
   │  └─ Exploitation tools
   ├─ ExploitationAgent calls LLM (Haiku)
   ├─ LLM simulates exploitation (SAFE)
   ├─ ExploitationAgent returns AgentResult
   └─ Cost tracked: ~$0.01

9. Phase 5: Reporting
   ├─ Orchestrator delegates to ReportingAgent
   ├─ ReportingAgent aggregates all findings
   ├─ ReportingAgent calls LLM (Sonnet) for high-quality reports
   ├─ LLM generates executive summary
   ├─ ReportingAgent returns AgentResult
   └─ Cost tracked: ~$0.02 (higher - uses Sonnet)

10. Result Aggregation
    ├─ Orchestrator combines all agent results
    ├─ Aggregates costs: Total ~$0.09
    ├─ Aggregates metrics from all agents
    └─ Creates comprehensive operation result

11. Persistence
    ├─ Save to ~/.medusa/logs/multi-agent-OP-XXX.json
    └─ Include all findings, metrics, costs

12. Display
    ├─ Show operation summary
    ├─ Display agent performance table
    └─ Show cost breakdown

13. Cleanup
    ├─ Close LLM client
    ├─ Close database connections
    └─ Clear message bus
```

---

## Scaling and Performance

### Horizontal Scaling

**Agent Instances**:
- Each specialist agent can be instantiated multiple times
- Enables parallel processing of multiple targets

**Message Bus**:
- Can be replaced with distributed message queue (RabbitMQ, Kafka)
- Enables agents to run on different machines

### Vertical Scaling

**Batch Processing**:
```python
# Process multiple targets in parallel
targets = ["host1.com", "host2.com", "host3.com"]
tasks = [create_task(target) for target in targets]
results = await asyncio.gather(*tasks)
```

**Concurrent Agent Execution**:
```python
# Run multiple agents concurrently
recon_task = asyncio.create_task(recon_agent.execute_task(task1))
vuln_task = asyncio.create_task(vuln_agent.execute_task(task2))
results = await asyncio.gather(recon_task, vuln_task)
```

### Performance Optimizations

1. **Async/Await**: All I/O operations are async
2. **Connection Pooling**: Reuse database connections
3. **Caching**: Vector store uses persistent storage
4. **Smart Routing**: Use cheaper models when possible

---

## Security Considerations

### 1. Exploitation Safety

- ✅ All exploitation is SIMULATED
- ✅ No real attacks executed
- ✅ Analysis and recommendation only
- ✅ Approval gates for sensitive actions

### 2. Data Protection

- Operation results stored locally
- Sensitive data not sent to external services (except LLM providers)
- Use encryption for data at rest
- Secure database connections (TLS)

### 3. Authentication & Authorization

- AWS credentials managed via environment variables
- Database credentials in secure configuration
- API keys not logged or displayed

### 4. Input Validation

- All user inputs validated
- SQL injection prevention in graph queries
- Command injection prevention in tool execution

### 5. Audit Trail

- All operations logged
- Full history maintained in operation_history
- Cost tracking for accountability

---

## Future Enhancements

### 1. Distributed Architecture
- Deploy agents on separate machines
- Use distributed message queue (RabbitMQ)
- Scale horizontally for large networks

### 2. Additional Agents
- **EnumerationAgent**: Specialized in service enumeration
- **PrivEscAgent**: Focused on privilege escalation
- **DataExfilAgent**: Specialized in data discovery

### 3. Machine Learning Integration
- Train models on past operations
- Predict vulnerability exploitability
- Optimize attack sequences

### 4. Real-Time Collaboration
- Multiple users coordinate assessments
- Shared operation state
- Live status updates

---

## Conclusion

The MEDUSA Multi-Agent System represents a sophisticated approach to automated security assessment, combining:

- **Specialized AI Agents** with distinct capabilities
- **Context Fusion** from multiple knowledge sources
- **Smart Model Routing** for cost optimization
- **Comprehensive Tracking** of costs and metrics
- **Safe Simulation** of exploitation techniques

This architecture enables efficient, cost-effective, and comprehensive security assessments while maintaining safety and control.

---

## References

- [User Guide](USER_GUIDE.md)
- [API Reference](API_REFERENCE.md)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)
- [Neo4j Graph Database](https://neo4j.com/docs/)
- [ChromaDB Vector Store](https://docs.trychroma.com/)
