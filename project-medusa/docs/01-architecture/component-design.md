# MEDUSA Component Design

**Navigation**: [Home](../../README.md) → [Docs](../INDEX.md) → [Architecture](README.md) → Component Design

---

## Overview

This document provides a detailed technical design of each major component in the MEDUSA architecture. For high-level architecture, see [System Overview](system-overview.md).

---

## Table of Contents

1. [CLI Component](#1-cli-component)
2. [LangGraph Multi-Agent System](#2-langgraph-multi-agent-system)
3. [Specialized Agents](#3-specialized-agents)
4. [LLM Integration Layer](#4-llm-integration-layer)
5. [Context Fusion Engine](#5-context-fusion-engine)
6. [Security Tools Integration](#6-security-tools-integration)
7. [Database Schema](#7-database-schema)

---

## 1. CLI Component

### Purpose
Command-line interface for user interaction with MEDUSA agents.

### Technology Stack
- **Framework**: Typer (Python CLI framework)
- **UI**: Rich (terminal formatting and progress indicators)
- **Config**: YAML-based configuration management

### Architecture

```python
medusa-cli/
├── src/medusa/
│   ├── cli.py              # Main CLI entry point
│   ├── config.py           # Configuration management
│   └── commands/
│       ├── agent.py        # Agent commands (run, status, report)
│       ├── setup.py        # Setup wizard
│       └── shell.py        # Interactive shell mode
```

### Key Commands

#### `medusa agent run <target>`
**Purpose**: Execute multi-agent security assessment

**Parameters**:
- `target`: URL or IP address
- `--type`: Operation type (full_assessment, recon_only, vuln_scan, penetration_test)
- `--objectives`: Comma-separated goals
- `--auto-approve`: Skip approval prompts
- `--max-duration`: Time limit in seconds
- `--save`: Save results to file

**Flow**:
1. Parse command arguments
2. Initialize LangGraph with `MedusaState`
3. Start graph execution
4. Monitor progress with Rich progress bars
5. Handle approval gates if needed
6. Save results to `~/.medusa/operations/`

#### `medusa agent status [operation-id]`
**Purpose**: Monitor operation status and costs

**Parameters**:
- `operation-id`: Optional, defaults to latest
- `--live`: Live monitoring mode
- `--agent`: Filter by specific agent
- `--format`: Output format (table/json)

#### `medusa agent report <operation-id>`
**Purpose**: Generate comprehensive report

**Parameters**:
- `operation-id`: Operation to report on
- `--type`: Report type (executive, technical, remediation, compliance)
- `--format`: Output format (html, json, markdown)
- `--export`: Export path

### Configuration Management

**Location**: `~/.medusa/config.yaml`

**Structure**:
```yaml
llm:
  provider: bedrock  # bedrock, local, openai, anthropic, auto
  aws_region: us-west-2
  smart_model: anthropic.claude-3-5-sonnet-20241022-v2:0
  fast_model: anthropic.claude-3-5-haiku-20241022-v1:0
  temperature: 0.7
  timeout: 60

database:
  neo4j_uri: bolt://localhost:7687
  neo4j_user: neo4j
  neo4j_password: password
  vector_store_path: ~/.medusa/chroma_db

security:
  approval_required: true
  auto_approve_low_risk: false
  max_operation_duration: 3600

cost:
  budget_limit: 10.0  # USD
  alert_threshold: 0.8  # 80% of budget
```

---

## 2. LangGraph Multi-Agent System

### Purpose
Orchestrate specialized security agents through stateful, cyclic workflows.

### Core Components

#### StateGraph ([`medusa_graph.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/core/medusa_graph.py))

**Implementation**:
```python
from langgraph.graph import StateGraph, END

def create_medusa_graph():
    workflow = StateGraph(MedusaState)
    
    # Add nodes
    workflow.add_node("Supervisor", supervisor_node)
    workflow.add_node("Reconnaissance", recon_node)
    workflow.add_node("VulnerabilityAnalysis", vuln_node)
    workflow.add_node("Planning", planning_node)
    workflow.add_node("Exploitation", exploit_node)
    workflow.add_node("Reporting", reporting_node)
    workflow.add_node("ApprovalGate", approval_node)
    
    # Workers return to Supervisor
    workflow.add_edge("Reconnaissance", "Supervisor")
    workflow.add_edge("VulnerabilityAnalysis", "Supervisor")
    workflow.add_edge("Planning", "Supervisor")
    workflow.add_edge("Exploitation", "Supervisor")
    workflow.add_edge("Reporting", "Supervisor")
    
    # Supervisor conditional routing
    workflow.add_conditional_edges(
        "Supervisor",
        lambda x: x["next_worker"],
        {
            "Reconnaissance": "Reconnaissance",
            "VulnerabilityAnalysis": "VulnerabilityAnalysis",
            "Planning": "Planning",
            "Exploitation": "ApprovalGate",  # High-risk intercept
            "Reporting": "Reporting",
            "FINISH": END
        }
    )
    
    # Approval gate logic
    workflow.add_conditional_edges(
        "ApprovalGate",
        lambda state: "Exploitation" if state.get("approval_status", {}).get("approved") else "Supervisor",
        {"Exploitation": "Exploitation", "Supervisor": "Supervisor"}
    )
    
    workflow.set_entry_point("Supervisor")
    return workflow.compile()
```

**Key Features**:
- **Stateful**: `MedusaState` persists across all nodes
- **Cyclic**: Agents can be revisited based on findings
- **Conditional**: Routing based on state analysis
- **Safe**: Approval gates for high-risk actions

#### MedusaState ([`graph_state.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/core/graph_state.py))

**TypedDict Definition**:
```python
from typing import TypedDict, List, Dict, Any, Annotated
from langchain_core.messages import BaseMessage
import operator

class MedusaState(TypedDict):
    # Conversation history (appended)
    messages: Annotated[List[BaseMessage], operator.add]
    
    # Structured findings (appended)
    findings: Annotated[List[Dict[str, Any]], operator.add]
    
    # Current operation plan (replaced)
    plan: Dict[str, Any]
    
    # Current phase (replaced)
    current_phase: str
    
    # Next worker to execute (replaced)
    next_worker: str
    
    # Shared context/knowledge (replaced)
    context: Dict[str, Any]
    
    # Target URL or IP (replaced)
    target: str
    
    # Cost tracking (replaced)
    cost_tracking: Dict[str, Any]
    
    # Approval status (replaced)
    approval_status: Dict[str, Any]
    
    # Operation ID (replaced)
    operation_id: str
    
    # Risk level (replaced)
    risk_level: str
```

**State Management**:
- **Annotated with `operator.add`**: Lists are appended (messages, findings)
- **No annotation**: Dicts are replaced (plan, context, cost_tracking)
- **Immutable**: Each node returns new state dict, LangGraph merges

#### Supervisor Node ([`supervisor.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/core/supervisor.py))

**Purpose**: LLM-powered router that decides next agent

**Implementation**:
```python
async def supervisor_node(state: MedusaState) -> Dict[str, Any]:
    llm_client = get_llm_client()
    
    if not llm_client:
        return {"next_worker": fallback_supervisor_logic(state)}
    
    # Format conversation history
    messages = state.get("messages", [])
    conversation_history = format_messages(messages[-5:])
    
    # Construct prompt
    prompt = f"""
    You are the supervisor of a penetration testing team.
    Workers: Reconnaissance, VulnerabilityAnalysis, Planning, Exploitation, Reporting
    
    Conversation History:
    {conversation_history}
    
    Given the conversation above, who should act next?
    Or should we FINISH?
    
    Respond with JSON: {{"next_worker": "WorkerName"}}
    """
    
    # Get LLM decision
    response = await llm_client.generate_with_routing(
        prompt=prompt,
        task_type="supervisor_routing",
        force_json=True
    )
    
    # Parse response
    data = json.loads(response.content)
    next_worker = data.get("next_worker")
    
    # Validate
    if next_worker not in options:
        next_worker = fallback_supervisor_logic(state)
    
    return {"next_worker": next_worker}
```

**Fallback Logic** (if LLM fails):
```python
def fallback_supervisor_logic(state: MedusaState) -> str:
    messages = state.get("messages", [])
    if not messages:
        return "Reconnaissance"
    
    last_content = messages[-1].content
    
    if "Reconnaissance completed" in last_content:
        return "VulnerabilityAnalysis"
    elif "Vulnerability analysis completed" in last_content:
        return "Planning"
    elif "Strategic plan created" in last_content:
        return "Reporting"
    elif "Report generated" in last_content:
        return "FINISH"
    
    return "FINISH"
```

#### Agent Nodes ([`graph_nodes.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/agents/graph_nodes.py))

**Purpose**: Wrap specialized agents as LangGraph nodes

**Pattern** (all agents follow this):
```python
async def recon_node(state: MedusaState) -> Dict[str, Any]:
    # 1. Extract parameters from state
    target = state.get("target", "unknown")
    
    # 2. Create agent task
    task = AgentTask(
        task_id="recon-task",
        task_type="run_scan",
        parameters={"target": target, "scan_type": "fast"}
    )
    
    # 3. Execute agent
    start_cost = recon_agent.total_cost
    result = await recon_agent.run_task(task)
    task_cost = recon_agent.total_cost - start_cost
    
    # 4. Update cost tracking
    cost_tracking = state.get("cost_tracking", {"total_cost": 0.0, "by_agent": {}})
    cost_tracking["total_cost"] += task_cost
    cost_tracking["by_agent"]["recon"] = cost_tracking.get("by_agent", {}).get("recon", 0.0) + task_cost
    
    # 5. Return state updates
    return {
        "findings": result.findings,  # Appended to existing
        "messages": [AIMessage(content=f"Reconnaissance completed. Found {len(result.findings)} open ports.")],
        "cost_tracking": cost_tracking  # Replaced
    }
```

**Cost Tracking**: Every node tracks LLM usage and updates `cost_tracking` in state.

---

## 3. Specialized Agents

### Base Agent Architecture

**Abstract Base Class** ([`base_agent.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/agents/base_agent.py)):

```python
class BaseAgent(ABC):
    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        context_engine: Optional[ContextFusionEngine] = None,
        message_bus: Optional[MessageBus] = None
    ):
        self.llm_client = llm_client
        self.context_engine = context_engine
        self.message_bus = message_bus
        self.total_cost = 0.0
        self.metrics = AgentMetrics()
    
    @abstractmethod
    async def execute_task(self, task: AgentTask) -> AgentResult:
        """Execute the task. Must be implemented by subclasses."""
        pass
    
    async def run_task(self, task: AgentTask) -> AgentResult:
        """Wrapper that adds metrics tracking."""
        start_time = time.time()
        result = await self.execute_task(task)
        duration = time.time() - start_time
        
        self.metrics.tasks_completed += 1
        self.metrics.total_duration += duration
        
        return result
```

### Reconnaissance Agent

**File**: [`reconnaissance_agent.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/agents/reconnaissance_agent.py)

**Capabilities**:
- Port scanning (Nmap)
- Subdomain enumeration (Amass)
- Web server probing (HTTPX)
- Service fingerprinting
- Neo4j integration for infrastructure mapping

**Task Types**:
1. `run_scan`: Execute Nmap scan
2. `enumerate_subdomains`: Run Amass
3. `probe_web_servers`: Use HTTPX
4. `fingerprint_services`: Identify service versions

**Example Execution**:
```python
async def execute_task(self, task: AgentTask) -> AgentResult:
    if task.task_type == "run_scan":
        target = task.parameters["target"]
        scan_type = task.parameters.get("scan_type", "fast")
        
        # Execute Nmap
        nmap_results = await self.nmap_scanner.scan(target, scan_type)
        
        # Store in Neo4j
        await self.world_model.add_host(target, nmap_results)
        
        # Format findings
        findings = [
            {
                "type": "open_port",
                "port": port,
                "service": service,
                "version": version
            }
            for port, service, version in nmap_results
        ]
        
        return AgentResult(
            task_id=task.task_id,
            status="completed",
            findings=findings
        )
```

### Vulnerability Analysis Agent

**File**: [`vulnerability_analysis_agent.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/agents/vulnerability_analysis_agent.py)

**Capabilities**:
- SQL injection testing (SQLMap)
- CVE matching via vector search
- Vulnerability prioritization
- Risk assessment
- CVSS scoring

**Task Types**:
1. `analyze_findings`: Analyze reconnaissance results
2. `test_sql_injection`: Run SQLMap
3. `match_cves`: Search CVE database
4. `prioritize_vulnerabilities`: Risk-based ranking

**CVE Matching Flow**:
```python
async def match_cves(self, service: str, version: str) -> List[Dict]:
    # 1. Build search query
    query = f"{service} {version} vulnerability"
    
    # 2. Semantic search in vector store
    cve_results = await self.context_engine.vector_store.search_cves(
        query=query,
        n_results=10
    )
    
    # 3. Filter and rank by CVSS score
    relevant_cves = [
        cve for cve in cve_results
        if cve["cvss_score"] >= 7.0  # High severity
    ]
    
    # 4. Return prioritized list
    return sorted(relevant_cves, key=lambda x: x["cvss_score"], reverse=True)
```

### Planning Agent

**File**: [`planning_agent.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/agents/planning_agent.py)

**Capabilities**:
- Strategic attack planning
- MITRE ATT&CK technique mapping
- Multi-step attack chain generation
- Risk-reward analysis
- Resource estimation

**Uses Sonnet** (smart model) for complex reasoning

**Task Types**:
1. `create_operation_plan`: Generate strategic plan
2. `map_mitre_techniques`: Map to ATT&CK framework
3. `generate_attack_chain`: Create multi-step sequence
4. `assess_risk`: Evaluate plan risk level

**Planning Flow**:
```python
async def create_operation_plan(self, findings: List[Dict], objectives: List[str]) -> Dict:
    # 1. Get MITRE context
    mitre_context = await self.context_engine.build_context_for_planning(findings)
    
    # 2. Construct prompt
    prompt = f"""
    Create a strategic penetration testing plan.
    
    Findings: {json.dumps(findings, indent=2)}
    Objectives: {objectives}
    MITRE Context: {mitre_context}
    
    Generate a multi-step plan with:
    - Attack vectors
    - MITRE ATT&CK techniques
    - Risk assessment
    - Success criteria
    
    Return JSON format.
    """
    
    # 3. Get LLM response (uses Sonnet for quality)
    response = await self.llm_client.generate_with_routing(
        prompt=prompt,
        task_type="strategic_planning",  # Routes to Sonnet
        force_json=True
    )
    
    # 4. Parse and validate plan
    plan = json.loads(response.content)
    return plan
```

### Exploitation Agent

**File**: [`exploitation_agent.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/agents/exploitation_agent.py)

**Capabilities**:
- Exploit planning
- Safe exploitation execution
- Post-exploitation recommendations
- Access verification
- **Approval gates** for high-risk actions

**Task Types**:
1. `plan_exploitation`: Create exploit strategy
2. `execute_exploit`: Run exploit (requires approval)
3. `verify_access`: Confirm successful exploitation
4. `recommend_post_exploitation`: Next steps after access

**Approval Gate Integration**:
```python
async def execute_task(self, task: AgentTask) -> AgentResult:
    if task.task_type == "execute_exploit":
        # Check if approval required
        if self.require_approval:
            # Set approval status in state (handled by approval_node)
            return AgentResult(
                task_id=task.task_id,
                status="pending_approval",
                findings=[],
                metadata={"requires_approval": True, "risk_level": "HIGH"}
            )
        
        # Execute exploit if approved
        exploit_result = await self._execute_exploit(task.parameters)
        return AgentResult(
            task_id=task.task_id,
            status="completed",
            findings=[exploit_result]
        )
```

### Reporting Agent

**File**: [`reporting_agent.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/agents/reporting_agent.py)

**Capabilities**:
- Executive summary generation
- Technical detailed reports
- Remediation plans
- Compliance reports (HIPAA, PCI-DSS, etc.)
- JSON/Markdown/HTML export

**Uses Sonnet** (smart model) for quality writing

**Report Formats**:
1. **Executive Summary**: High-level overview for management
2. **Technical Report**: Detailed findings for security teams
3. **Remediation Plan**: Step-by-step fixes
4. **Compliance Report**: Regulatory compliance mapping
5. **JSON Export**: Machine-readable data

**Report Generation**:
```python
async def generate_executive_summary(self, findings: List[Dict], target: str, operation_data: Dict) -> Dict:
    # 1. Aggregate findings
    total_findings = len(findings)
    high_severity = len([f for f in findings if f.get("severity") == "HIGH"])
    
    # 2. Construct prompt
    prompt = f"""
    Generate an executive summary for a penetration test.
    
    Target: {target}
    Total Findings: {total_findings}
    High Severity: {high_severity}
    
    Findings: {json.dumps(findings[:10], indent=2)}  # Top 10
    
    Create a concise executive summary with:
    - Overall risk assessment
    - Key findings
    - Business impact
    - Recommended actions
    
    Return JSON format.
    """
    
    # 3. Get LLM response (uses Sonnet for quality)
    response = await self.llm_client.generate_with_routing(
        prompt=prompt,
        task_type="report_generation",  # Routes to Sonnet
        force_json=True
    )
    
    # 4. Parse and format
    summary = json.loads(response.content)
    return summary
```

---

## 4. LLM Integration Layer

### Multi-Provider Architecture

**Factory Pattern** ([`factory.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/core/llm/factory.py)):

```python
def create_llm_client(config: LLMConfig) -> LLMClient:
    provider = config.provider
    
    if provider == "bedrock":
        from medusa.core.llm.providers.bedrock import BedrockProvider
        return LLMClient(BedrockProvider(config))
    elif provider == "local":
        from medusa.core.llm.providers.ollama import OllamaProvider
        return LLMClient(OllamaProvider(config))
    elif provider == "openai":
        from medusa.core.llm.providers.openai import OpenAIProvider
        return LLMClient(OpenAIProvider(config))
    elif provider == "anthropic":
        from medusa.core.llm.providers.anthropic import AnthropicProvider
        return LLMClient(AnthropicProvider(config))
    elif provider == "auto":
        # Auto-detect available provider
        return auto_detect_provider(config)
    else:
        raise ValueError(f"Unknown provider: {provider}")
```

### AWS Bedrock Provider

**File**: [`bedrock.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/core/llm/providers/bedrock.py)

**Models Supported**:
- **Claude 3.5 Sonnet**: `anthropic.claude-3-5-sonnet-20241022-v2:0`
- **Claude 3.5 Haiku**: `anthropic.claude-3-5-haiku-20241022-v1:0`
- **Titan Embeddings**: `amazon.titan-embed-text-v1`

**Pricing Table**:
```python
PRICING = {
    "claude-3-5-sonnet": {
        "input": 3.00,   # per 1M tokens
        "output": 15.00
    },
    "claude-3-5-haiku": {
        "input": 0.80,
        "output": 4.00
    },
    "titan-embeddings": {
        "input": 0.50,
        "output": 1.50
    }
}
```

**Cost Calculation**:
```python
def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
    pricing = self.PRICING.get(self.model, {"input": 0, "output": 0})
    input_cost = (input_tokens / 1_000_000) * pricing["input"]
    output_cost = (output_tokens / 1_000_000) * pricing["output"]
    return input_cost + output_cost
```

**Health Check**:
```python
async def health_check(self) -> bool:
    try:
        response = self.bedrock_runtime.invoke_model(
            modelId=self.model,
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "messages": [{"role": "user", "content": "test"}],
                "max_tokens": 10
            })
        )
        return True
    except ClientError as e:
        logger.error(f"Bedrock health check failed: {e}")
        return False
```

### Model Router

**File**: [`router.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/core/llm/router.py)

**Task Complexity Assessment**:
```python
class TaskComplexity(Enum):
    SIMPLE = "simple"      # Use Haiku (cheap, fast)
    MODERATE = "moderate"  # Use Haiku
    COMPLEX = "complex"    # Use Sonnet (smart, expensive)

COMPLEX_TASKS = [
    "strategic_planning",
    "report_generation",
    "attack_chain_planning",
    "risk_assessment",
    "compliance_mapping",
    "executive_summary",
    "remediation_planning",
    "supervisor_routing"
]

SIMPLE_TASKS = [
    "tool_execution",
    "data_parsing",
    "finding_aggregation",
    "port_scan_analysis",
    "service_identification",
    "vulnerability_classification",
    "cve_matching",
    "log_analysis"
]
```

**Model Selection**:
```python
def select_model(self, task_type: str, context: Optional[Dict] = None) -> str:
    # Check if task is explicitly complex
    if task_type in COMPLEX_TASKS:
        return self.smart_model  # Sonnet
    
    # Check if task is explicitly simple
    if task_type in SIMPLE_TASKS:
        return self.fast_model  # Haiku
    
    # Default to fast model for unknown tasks
    return self.fast_model
```

**Cost Savings**:
- **Haiku**: $0.80 input / $4.00 output per 1M tokens
- **Sonnet**: $3.00 input / $15.00 output per 1M tokens
- **Savings**: 60-75% by using Haiku for simple tasks

### Cost Tracker

**File**: [`cost_tracker.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/core/cost_tracker.py)

**Data Model**:
```python
@dataclass
class CostEntry:
    timestamp: datetime
    agent: str
    task_type: str
    model: str
    input_tokens: int
    output_tokens: int
    cost: float

class OperationCostTracker:
    def __init__(self, operation_id: str):
        self.operation_id = operation_id
        self.entries: List[CostEntry] = []
        self.total_cost = 0.0
    
    def record(self, entry: CostEntry):
        self.entries.append(entry)
        self.total_cost += entry.cost
    
    def get_summary(self) -> Dict:
        return {
            "operation_id": self.operation_id,
            "total_cost": self.total_cost,
            "by_agent": self._get_cost_by_agent(),
            "by_model": self._get_cost_by_model(),
            "by_task_type": self._get_cost_by_task_type()
        }
    
    def export_json(self, path: str):
        with open(path, 'w') as f:
            json.dump(self.get_summary(), f, indent=2)
```

---

## 5. Context Fusion Engine

### Vector Store

**File**: [`vector_store.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/context/vector_store.py)

**Collections**:
1. **mitre_attack**: MITRE ATT&CK techniques (600+)
2. **cve_database**: CVE vulnerabilities (100+)
3. **tool_documentation**: Security tool usage guides (6 tools)
4. **operation_history**: Past operations for learning

**Embedding Functions**:
- **Primary**: Bedrock Titan Embeddings (cloud)
- **Fallback**: sentence-transformers (local)

**Implementation**:
```python
class VectorStore:
    def __init__(self, persist_directory: str, use_bedrock: bool = True):
        self.client = chromadb.PersistentClient(path=persist_directory)
        
        if use_bedrock:
            self.embedding_function = BedrockEmbeddingFunction()
        else:
            self.embedding_function = SentenceTransformerEmbeddingFunction()
        
        # Initialize collections
        self.mitre_collection = self.client.get_or_create_collection(
            name="mitre_attack",
            embedding_function=self.embedding_function
        )
        # ... other collections
    
    async def search_mitre_techniques(self, query: str, n_results: int = 5) -> List[Dict]:
        results = self.mitre_collection.query(
            query_texts=[query],
            n_results=n_results
        )
        return self._format_results(results)
```

### Context Fusion Engine

**File**: [`fusion_engine.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/context/fusion_engine.py)

**Purpose**: Combine vector search + graph queries for comprehensive context

**Context Builders**:
```python
class ContextFusionEngine:
    def __init__(self, vector_store: VectorStore, world_model: WorldModel):
        self.vector_store = vector_store
        self.world_model = world_model
    
    async def build_context_for_reconnaissance(self, target: str) -> str:
        # 1. Get tool documentation
        tool_docs = await self.vector_store.search_tool_usage(
            query="nmap amass httpx reconnaissance",
            n_results=3
        )
        
        # 2. Get MITRE techniques for reconnaissance
        mitre_techniques = await self.vector_store.search_mitre_techniques(
            query="reconnaissance discovery network scanning",
            n_results=5
        )
        
        # 3. Combine into context
        context = f"""
        Tool Documentation:
        {self._format_tool_docs(tool_docs)}
        
        Relevant MITRE ATT&CK Techniques:
        {self._format_mitre_techniques(mitre_techniques)}
        """
        return context
    
    async def build_context_for_vulnerability_analysis(self, findings: List[Dict]) -> str:
        # 1. Extract services from findings
        services = [f["service"] for f in findings if "service" in f]
        
        # 2. Search CVEs for each service
        cve_results = []
        for service in services:
            cves = await self.vector_store.search_cves(
                query=f"{service} vulnerability",
                n_results=3
            )
            cve_results.extend(cves)
        
        # 3. Get graph data for infrastructure
        graph_data = await self.world_model.get_infrastructure_state()
        
        # 4. Combine
        context = f"""
        Relevant CVEs:
        {self._format_cves(cve_results)}
        
        Infrastructure State:
        {self._format_graph_data(graph_data)}
        """
        return context
```

---

## 6. Security Tools Integration

### Tool Adapter Pattern

**Purpose**: Standardize interface for all security tools

**Base Interface**:
```python
class SecurityTool(ABC):
    @abstractmethod
    async def execute(self, parameters: Dict) -> Dict:
        """Execute the tool with given parameters."""
        pass
    
    @abstractmethod
    def parse_output(self, raw_output: str) -> List[Dict]:
        """Parse tool output into structured findings."""
        pass
```

### Nmap Scanner

**Implementation**:
```python
class NmapScanner(SecurityTool):
    async def execute(self, parameters: Dict) -> Dict:
        target = parameters["target"]
        scan_type = parameters.get("scan_type", "fast")
        
        # Build nmap command
        if scan_type == "fast":
            cmd = f"nmap -F -sV {target}"
        elif scan_type == "full":
            cmd = f"nmap -p- -sV -sC {target}"
        
        # Execute
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        # Parse output
        findings = self.parse_output(stdout.decode())
        
        return {
            "tool": "nmap",
            "target": target,
            "findings": findings
        }
    
    def parse_output(self, raw_output: str) -> List[Dict]:
        # Parse nmap XML or text output
        findings = []
        for line in raw_output.split('\n'):
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                port = parts[0].split('/')[0]
                service = parts[2] if len(parts) > 2 else "unknown"
                findings.append({
                    "type": "open_port",
                    "port": int(port),
                    "service": service,
                    "protocol": "tcp"
                })
        return findings
```

### SQLMap Integration

**Implementation**:
```python
class SQLMapScanner(SecurityTool):
    async def execute(self, parameters: Dict) -> Dict:
        url = parameters["url"]
        data = parameters.get("data")
        
        # Build sqlmap command
        cmd = f"sqlmap -u {url}"
        if data:
            cmd += f" --data='{data}'"
        cmd += " --batch --level=1 --risk=1"
        
        # Execute
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        # Parse output
        findings = self.parse_output(stdout.decode())
        
        return {
            "tool": "sqlmap",
            "url": url,
            "findings": findings
        }
```

---

## 7. Database Schema

### Neo4j Graph Database

**Purpose**: Store infrastructure state and relationships

**Node Types**:
```cypher
// Host node
(:Host {
    ip: string,
    hostname: string,
    os: string,
    discovered_at: datetime
})

// Port node
(:Port {
    number: int,
    protocol: string,
    state: string
})

// Service node
(:Service {
    name: string,
    version: string,
    banner: string
})

// Vulnerability node
(:Vulnerability {
    cve_id: string,
    severity: string,
    cvss_score: float,
    description: string
})
```

**Relationships**:
```cypher
(:Host)-[:HAS_PORT]->(:Port)
(:Port)-[:RUNS_SERVICE]->(:Service)
(:Service)-[:HAS_VULNERABILITY]->(:Vulnerability)
(:Host)-[:CONNECTS_TO]->(:Host)
```

**Example Queries**:
```cypher
// Find all high-severity vulnerabilities
MATCH (h:Host)-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.cvss_score >= 7.0
RETURN h.ip, p.number, s.name, v.cve_id, v.cvss_score
ORDER BY v.cvss_score DESC

// Find attack paths
MATCH path = (start:Host)-[:CONNECTS_TO*]->(target:Host)
WHERE start.ip = "10.0.0.1" AND target.ip = "10.0.0.100"
RETURN path
```

### ChromaDB Vector Database

**Collections Schema**:

**mitre_attack**:
```json
{
    "id": "T1595.001",
    "metadata": {
        "technique_name": "Active Scanning: Scanning IP Blocks",
        "tactic": "Reconnaissance",
        "description": "...",
        "detection": "...",
        "mitigation": "..."
    },
    "document": "Full text of technique description",
    "embedding": [0.123, 0.456, ...]  // 1536-dim vector
}
```

**cve_database**:
```json
{
    "id": "CVE-2021-44228",
    "metadata": {
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "affected_products": ["Apache Log4j 2.0-2.14.1"],
        "published_date": "2021-12-10"
    },
    "document": "Full CVE description",
    "embedding": [0.789, 0.012, ...]
}
```

---

## Related Documentation

- [System Overview](system-overview.md) - High-level architecture
- [Network Architecture](network-architecture.md) - Lab environment topology
- [LangGraph Migration](langgraph-migration.md) - LangGraph implementation details
- [Implementation Status](IMPLEMENTATION-STATUS.md) - Current development status

---

**Last Updated**: 2025-11-20  
**Version**: 2.1 (LangGraph Multi-Agent)

**Navigation**: [Home](../../README.md) → [Docs](../INDEX.md) → [Architecture](README.md) → Component Design
