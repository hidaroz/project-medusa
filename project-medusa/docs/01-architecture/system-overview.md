# MEDUSA System Overview

**Navigation**: [Home](../../README.md) → [Docs](../INDEX.md) → [Architecture](README.md) → System Overview

---

## Introduction

MEDUSA (Multi-Environment Detection and Understanding System for Autonomous testing) is an AI-powered autonomous penetration testing framework that combines enterprise-grade language models with traditional security testing tools through an intelligent multi-agent architecture.

**Core Innovation**: LangGraph-based supervisor-worker pattern that enables stateful, cyclic agent workflows with intelligent decision-making and cost optimization.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MEDUSA ARCHITECTURE                          │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    CLI Interface Layer                        │  │
│  │  • Command parsing (Typer)                                    │  │
│  │  • Rich terminal UI                                           │  │
│  │  • Configuration management                                   │  │
│  └────────────────────────────┬─────────────────────────────────┘  │
│                               │                                     │
│  ┌────────────────────────────▼─────────────────────────────────┐  │
│  │              LangGraph Multi-Agent Orchestration              │  │
│  │                                                               │  │
│  │   ┌──────────────────────────────────────────────────────┐   │  │
│  │   │          Supervisor Node (LLM-based Router)          │   │  │
│  │   │         • Analyzes current state                     │   │  │
│  │   │         • Decides next agent                         │   │  │
│  │   │         • Manages operation lifecycle                │   │  │
│  │   └─────────────────┬────────────────────────────────────┘   │  │
│  │                     │                                         │  │
│  │       ┌─────────────┼─────────────┬──────────────┐            │  │
│  │       │             │             │              │            │  │
│  │       ▼             ▼             ▼              ▼            │  │
│  │  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │  │
│  │  │  Recon  │  │   Vuln   │  │ Planning │  │ Exploit  │       │  │
│  │  │  Agent  │  │ Analysis │  │  Agent   │  │  Agent   │       │  │
│  │  │ (Haiku) │  │ (Haiku)  │  │ (Sonnet) │  │ (Haiku)  │       │  │
│  │  └────┬────┘  └─────┬────┘  └─────┬────┘  └─────┬────┘       │  │
│  │       │             │             │              │            │  │
│  │       │             │             │              ▼            │  │
│  │       │             │             │      ┌──────────────┐     │  │
│  │       │             │             │      │  Approval    │     │  │
│  │       │             │             │      │  Gate Node   │     │  │
│  │       │             │             │      └──────┬───────┘     │  │
│  │       │             │             │             │             │  │
│  │       └─────────────┴─────────────┴─────────────┘             │  │
│  │                     │                                         │  │
│  │                     ▼                                         │  │
│  │       ┌────────────────────────────────────┐                  │  │
│  │       │    Reporting Agent (Sonnet)        │                  │  │
│  │       │  • Executive summaries             │                  │  │
│  │       │  • Technical reports               │                  │  │
│  │       │  • Remediation plans               │                  │  │
│  │       └────────────────────────────────────┘                  │  │
│  │                                                               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                               │                                     │
│  ┌────────────────────────────▼─────────────────────────────────┐  │
│  │                  Shared State (MedusaState)                   │  │
│  │  • Messages: Conversation history                            │  │
│  │  • Findings: Structured security findings                    │  │
│  │  • Plan: Operation plan and objectives                       │  │
│  │  • Context: Shared knowledge base                            │  │
│  │  • Cost Tracking: Real-time LLM usage                        │  │
│  │  • Approval Status: High-risk action approvals               │  │
│  └────────────────────────────┬─────────────────────────────────┘  │
│                               │                                     │
│  ┌────────────────────────────▼─────────────────────────────────┐  │
│  │                    Integration Layer                          │  │
│  │                                                               │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │  │
│  │  │  LLM Layer   │  │   Context    │  │  Security    │        │  │
│  │  │              │  │   Fusion     │  │   Tools      │        │  │
│  │  │ • Bedrock    │  │              │  │              │        │  │
│  │  │ • Ollama     │  │ • Vector DB  │  │ • Nmap       │        │  │
│  │  │ • OpenAI     │  │ • Graph DB   │  │ • SQLMap     │        │  │
│  │  │ • Anthropic  │  │ • MITRE      │  │ • Amass      │        │  │
│  │  │              │  │ • CVE DB     │  │ • HTTPX      │        │  │
│  │  │ • Router     │  │ • Tool Docs  │  │ • Metasploit │        │  │
│  │  │ • Cost Track │  │              │  │              │        │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘        │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

                               │
                               ▼
                  ┌────────────────────────┐
                  │   Target Environment   │
                  │                        │
                  │  • Lab Environment     │
                  │    (8 Docker services) │
                  │  • External targets    │
                  │    (authorized only)   │
                  └────────────────────────┘
```

---

## Core Components

### 1. LangGraph Multi-Agent System

**Purpose**: Orchestrate specialized security agents through stateful workflows

**Key Features**:
- **StateGraph**: LangGraph's state machine for agent coordination
- **Supervisor Node**: LLM-powered router that decides next agent based on current state
- **5 Specialized Agents**: Each focused on specific security testing phase
- **Cyclic Execution**: Agents can be revisited based on findings
- **Approval Gates**: Human-in-the-loop for high-risk actions

**Implementation**: [`medusa_graph.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/core/medusa_graph.py)

### 2. Specialized Security Agents

#### Reconnaissance Agent (Haiku)
- **Purpose**: Discover attack surface
- **Tools**: Nmap, Amass, HTTPX
- **Output**: Open ports, services, subdomains
- **Cost**: Low (uses fast Haiku model)

#### Vulnerability Analysis Agent (Haiku)
- **Purpose**: Identify security weaknesses
- **Tools**: SQLMap, CVE database, vulnerability scanners
- **Output**: Prioritized vulnerability list
- **Cost**: Low-Medium

#### Planning Agent (Sonnet)
- **Purpose**: Create strategic attack plan
- **Tools**: MITRE ATT&CK mapping, risk assessment
- **Output**: Multi-step operation plan
- **Cost**: Medium (uses smart Sonnet model for complex reasoning)

#### Exploitation Agent (Haiku + Approval Gate)
- **Purpose**: Safely test vulnerabilities
- **Tools**: Metasploit, custom exploits
- **Output**: Exploitation results, access verification
- **Safety**: Requires approval for high-risk actions

#### Reporting Agent (Sonnet)
- **Purpose**: Generate comprehensive reports
- **Formats**: Executive summary, technical report, remediation plan, compliance report, JSON/Markdown
- **Cost**: Medium (uses Sonnet for quality writing)

### 3. LLM Integration Layer

**Multi-Provider Support**:
- **AWS Bedrock** (Primary): Claude 3.5 Sonnet & Haiku with enterprise reliability
- **Ollama** (Fallback): Local LLM for offline/air-gapped environments
- **OpenAI/Anthropic** (Alternative): Direct API access

**Smart Model Routing**:
- Automatically selects optimal model based on task complexity
- **Haiku** for tool execution, simple analysis (cheap, fast)
- **Sonnet** for strategic planning, reporting (smart, expensive)
- **Cost Savings**: 60-70% compared to using Sonnet for all tasks

**Cost Tracking**:
- Real-time monitoring of LLM usage
- Per-agent cost breakdown
- Per-operation total cost
- Budget alerts and limits

**Implementation**: [`bedrock.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/core/llm/providers/bedrock.py), [`router.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/core/llm/router.py)

### 4. Context Fusion Engine

**Purpose**: Provide agents with relevant knowledge for intelligent decision-making

**Components**:

#### Vector Database (ChromaDB)
- **MITRE ATT&CK**: 600+ techniques with semantic search
- **CVE Database**: 100+ vulnerabilities with descriptions
- **Tool Documentation**: Usage guides for Nmap, SQLMap, etc.
- **Operation History**: Past operations for learning

#### Graph Database (Neo4j)
- **Infrastructure State**: Hosts, ports, services, relationships
- **Attack Paths**: Discovered routes through network
- **Vulnerability Chains**: Connected weaknesses

**Fusion Process**:
1. Agent requests context for current task
2. Vector search retrieves relevant MITRE techniques, CVEs, tool docs
3. Graph query retrieves infrastructure state
4. Combined context enhances LLM prompts
5. Agent makes more informed decisions

**Implementation**: [`vector_store.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/context/vector_store.py), [`fusion_engine.py`](file:///Users/hidaroz/INFO492/devprojects/project-medusa/medusa-cli/src/medusa/context/fusion_engine.py)

### 5. Security Tools Integration

**Reconnaissance**:
- **Nmap**: Port scanning, service detection
- **Amass**: Subdomain enumeration
- **HTTPX**: Web server probing

**Vulnerability Analysis**:
- **SQLMap**: SQL injection testing
- **Custom scanners**: XSS, IDOR, authentication bypass

**Exploitation**:
- **Metasploit**: Exploit framework integration
- **Custom exploits**: Safe, controlled testing

**All tools** wrapped in standardized interface for agent access.

### 6. Lab Environment

**Purpose**: Safe, isolated testing environment with realistic vulnerabilities

**Architecture**:
- **DMZ Network** (172.20.0.0/24): Public-facing services
- **Internal Network** (172.21.0.0/24): Backend systems

**8 Vulnerable Services**:
1. EHR Web Portal (Apache/PHP)
2. EHR API (Node.js/Express)
3. MySQL Database
4. SSH Server (Ubuntu)
5. FTP Server (vsftpd)
6. LDAP Server (OpenLDAP)
7. Log Collector (Syslog + Web UI)
8. Workstation (Ubuntu + Samba)

**Vulnerabilities**: 25+ realistic security flaws across all services

See [network-architecture.md](network-architecture.md) for detailed topology.

---

## Data Flow

### Typical Operation Flow

```
1. User initiates operation
   ↓
2. CLI creates initial MedusaState
   ↓
3. LangGraph starts → Supervisor Node
   ↓
4. Supervisor analyzes state → Routes to Reconnaissance Agent
   ↓
5. Recon Agent:
   - Requests context from Context Fusion Engine
   - Executes Nmap, Amass, HTTPX
   - Updates MedusaState with findings
   - Returns to Supervisor
   ↓
6. Supervisor analyzes findings → Routes to Vulnerability Analysis Agent
   ↓
7. Vuln Agent:
   - Requests CVE context for discovered services
   - Runs SQLMap, vulnerability scanners
   - Updates findings with vulnerabilities
   - Returns to Supervisor
   ↓
8. Supervisor → Routes to Planning Agent
   ↓
9. Planning Agent:
   - Requests MITRE ATT&CK techniques
   - Creates multi-step attack plan
   - Updates state with plan
   - Returns to Supervisor
   ↓
10. Supervisor → Routes to Exploitation Agent
    ↓
11. Approval Gate intercepts (high-risk action)
    ↓
12. User approves/rejects
    ↓
13. Exploitation Agent (if approved):
    - Safely tests vulnerabilities
    - Verifies access
    - Updates findings
    - Returns to Supervisor
    ↓
14. Supervisor → Routes to Reporting Agent
    ↓
15. Reporting Agent:
    - Aggregates all findings
    - Generates executive summary
    - Creates technical report
    - Produces remediation plan
    - Returns to Supervisor
    ↓
16. Supervisor → FINISH
    ↓
17. Final report delivered to user
```

---

## Key Design Principles

### 1. Stateful Workflows
- **MedusaState** persists across all agent invocations
- Agents build upon previous findings
- No information loss between phases

### 2. Intelligent Routing
- Supervisor uses LLM to analyze state and decide next step
- Not a fixed pipeline - agents can be revisited
- Adapts to findings dynamically

### 3. Cost Optimization
- Smart model routing reduces LLM costs by 60-70%
- Real-time cost tracking prevents budget overruns
- Efficient context retrieval minimizes token usage

### 4. Safety First
- Approval gates for high-risk actions
- Risk-based decision making
- Audit trail of all actions
- Safe mode for educational use

### 5. Extensibility
- Easy to add new agents (just add node + routing logic)
- Pluggable LLM providers
- Modular tool integration
- Customizable workflows

---

## Integration Points

### External Systems

**AWS Bedrock**:
- Claude 3.5 Sonnet & Haiku models
- Titan Embeddings for vector search
- Enterprise reliability and scale

**ChromaDB**:
- Vector database for semantic search
- MITRE, CVE, tool documentation storage
- Bedrock Titan or local embeddings

**Neo4j**:
- Graph database for infrastructure state
- Attack path visualization
- Relationship mapping

**Docker**:
- Lab environment containerization
- Service isolation
- Easy reset and deployment

### Internal Interfaces

**Agent ↔ LLM Client**:
- Standardized `generate()` and `generate_with_routing()` methods
- Automatic cost tracking
- Error handling and retries

**Agent ↔ Context Engine**:
- `build_context_for_*()` methods for each phase
- Semantic search across knowledge bases
- Graph queries for infrastructure state

**Agent ↔ Tools**:
- Unified tool adapter interface
- Async execution
- Result parsing and normalization

---

## Deployment Modes

### 1. Local Development
- Ollama for local LLM
- Docker lab environment
- No cloud dependencies

### 2. Cloud Production
- AWS Bedrock for LLM
- Remote targets (authorized)
- Enterprise scale

### 3. Hybrid
- Bedrock for LLM (cost-optimized)
- Local lab for testing
- Best of both worlds

---

## Performance Characteristics

**Operation Duration**:
- Reconnaissance: 2-5 minutes
- Full assessment: 10-20 minutes
- Depends on target complexity and LLM provider

**Cost Per Operation** (with Bedrock + smart routing):
- Reconnaissance only: $0.05-0.10
- Vulnerability scan: $0.15-0.25
- Full assessment: $0.20-0.30

**Resource Usage**:
- RAM: 4-8 GB (agents + LLM client)
- CPU: 2-4 cores
- Storage: 10-20 GB (logs, reports, vector DB)

---

## Security Considerations

**Approval Gates**:
- All high-risk actions require explicit approval
- Risk levels: LOW, MEDIUM, HIGH, CRITICAL
- Configurable auto-approval policies

**Audit Trail**:
- All actions logged with timestamps
- LLM decisions recorded
- Cost tracking for accountability

**Isolation**:
- Lab environment fully isolated in Docker
- No external network access by default
- Safe for educational use

**Authorization**:
- Only test authorized targets
- Compliance with CFAA, HIPAA, GDPR
- Ethical hacking guidelines

---

## Future Enhancements

**Planned Features**:
- Parallel agent execution for independent tasks
- Advanced LLM-based supervisor (replace deterministic fallback)
- Real-time web dashboard
- Plugin system for custom agents and tools
- Multi-user collaborative operations
- Cloud deployment templates (AWS, Azure, GCP)

---

## Related Documentation

- [Component Design](component-design.md) - Deep dive on each component
- [Network Architecture](network-architecture.md) - Lab environment topology
- [LangGraph Migration](langgraph-migration.md) - LangGraph implementation details
- [Implementation Status](IMPLEMENTATION-STATUS.md) - Current development status
- [CLI Architecture](cli-architecture.md) - Command-line interface design

---

**Last Updated**: 2025-11-20  
**Version**: 2.1 (LangGraph Multi-Agent)

**Navigation**: [Home](../../README.md) → [Docs](../INDEX.md) → [Architecture](README.md) → System Overview
