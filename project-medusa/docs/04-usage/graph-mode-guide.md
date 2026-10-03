# MEDUSA Graph Mode Guide

MEDUSA uses a **LangGraph-based** autonomous architecture to coordinate specialized AI agents. This graph mode allows for dynamic, non-linear workflows where agents can loop, retry, and adapt based on findings.

## Architecture

The system consists of:
- **Supervisor**: An LLM-based router that decides the next step based on current state.
- **Specialized Agents**:
  - `ReconnaissanceAgent`: Scans targets (Nmap, Amass).
  - `VulnerabilityAnalysisAgent`: Analyzes findings for vulnerabilities.
  - `PlanningAgent`: Creates strategic attack plans.
  - `ExploitationAgent`: Executes or simulates safe exploitation.
  - `ReportingAgent`: Generates comprehensive reports.
- **ApprovalGate**: A safety mechanism that intercepts high-risk actions (like exploitation) and requires approval.

## Running in Graph Mode

Use the CLI command `medusa graph run`:

```bash
# Basic usage
medusa graph run scanme.nmap.org

# Verbose output (see every agent decision)
medusa graph run 192.168.1.5 --verbose
```

## Configuration

Graph mode uses the standard `config.yaml`. 

### Approval Gates
You can configure risk tolerance in `~/.medusa/config.yaml`:

```yaml
risk_tolerance:
  auto_approve_low: true
  auto_approve_medium: false
  auto_approve_high: false
```

- If `auto_approve_high` is `false`, the `Exploitation` phase will require manual approval (or pause in the graph).

### Cost Tracking
The graph tracks LLM costs per agent. Costs are displayed in the CLI output and stored in the final report.

## State Management

The graph maintains a shared state:
```python
class MedusaState(TypedDict):
    messages: List[BaseMessage]      # Conversation history
    findings: List[Dict]             # Accumulated findings
    plan: Dict                       # Current operation plan
    target: str                      # Target URL/IP
    cost_tracking: Dict              # Real-time costs
    approval_status: Dict            # Gate status
    risk_level: str                  # Current risk
```

## extending the Graph

To add a new node, edit `medusa-cli/src/medusa/core/medusa_graph.py` and register the node and edge in `create_medusa_graph`.

