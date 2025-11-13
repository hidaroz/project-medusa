# Multi-Agent System User Guide

## Overview

MEDUSA's Multi-Agent System is a coordinated framework of specialized AI agents that work together to perform comprehensive security assessments. This guide will help you understand and effectively use the multi-agent capabilities.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Understanding the Agents](#understanding-the-agents)
3. [Running Operations](#running-operations)
4. [Monitoring Status](#monitoring-status)
5. [Generating Reports](#generating-reports)
6. [Advanced Usage](#advanced-usage)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Prerequisites

1. MEDUSA must be configured:
   ```bash
   medusa setup
   ```

2. AWS Bedrock credentials configured (if using AWS provider):
   ```bash
   export AWS_REGION="us-east-1"
   export AWS_ACCESS_KEY_ID="your-key"
   export AWS_SECRET_ACCESS_KEY="your-secret"
   ```

3. Vector database populated (run indexers):
   ```bash
   python scripts/index_mitre_attack.py
   python scripts/index_tool_docs.py
   python scripts/index_cves.py
   ```

### Your First Multi-Agent Operation

Run a basic security assessment:

```bash
medusa agent run http://localhost:3001
```

This will:
- Initialize all 6 specialist agents
- Perform reconnaissance
- Analyze vulnerabilities
- Create strategic plans
- Simulate exploitation (safe)
- Generate comprehensive reports

---

## Understanding the Agents

### The Agent Team

MEDUSA uses 6 specialized agents coordinated by an Orchestrator:

#### 1. **Orchestrator Agent**
- **Role**: Supervisor and coordinator
- **Responsibilities**:
  - Delegates tasks to specialist agents
  - Coordinates multi-phase operations
  - Aggregates results
  - Tracks overall progress

#### 2. **Reconnaissance Agent**
- **Role**: Information gathering specialist
- **Responsibilities**:
  - Recommends reconnaissance strategies
  - Suggests appropriate tools (Nmap, Masscan, etc.)
  - Analyzes network infrastructure
  - Identifies services and technologies

#### 3. **Vulnerability Analysis Agent**
- **Role**: Security assessment specialist
- **Responsibilities**:
  - Correlates findings with CVE database
  - Assesses exploitability
  - Prioritizes vulnerabilities by risk
  - Provides detailed impact analysis

#### 4. **Planning Agent**
- **Role**: Strategic planning specialist
- **Responsibilities**:
  - Designs attack chains
  - Creates operational plans
  - Optimizes attack sequences
  - Considers MITRE ATT&CK tactics

#### 5. **Exploitation Agent**
- **Role**: Exploitation simulation specialist
- **Responsibilities**:
  - Plans exploitation approaches
  - Simulates exploit execution (NO REAL ATTACKS)
  - Manages approval gates
  - Recommends post-exploitation actions

#### 6. **Reporting Agent**
- **Role**: Documentation specialist
- **Responsibilities**:
  - Generates executive summaries
  - Creates technical reports
  - Produces remediation plans
  - Maps to compliance frameworks

### Agent Communication

Agents communicate through a **Message Bus** using publish-subscribe patterns:
- Asynchronous messaging
- Task delegation
- Result sharing
- Status updates

### Context Fusion Engine

All agents have access to:
- **Neo4j Graph Database**: Current infrastructure state
- **ChromaDB Vector Store**: Semantic knowledge (MITRE, CVEs, tools)
- **Operation History**: Short-term memory of current session

---

## Running Operations

### Command Structure

```bash
medusa agent run <target> [OPTIONS]
```

### Basic Operations

#### 1. Full Security Assessment
```bash
medusa agent run http://example.com
```

Performs complete assessment:
- Reconnaissance
- Vulnerability analysis
- Strategic planning
- Exploitation simulation
- Report generation

#### 2. Reconnaissance Only
```bash
medusa agent run 192.168.1.0/24 --type recon_only
```

Focuses on information gathering without exploitation.

#### 3. Vulnerability Scan
```bash
medusa agent run http://example.com --type vuln_scan
```

Performs reconnaissance and vulnerability analysis only.

#### 4. Penetration Test (Full)
```bash
medusa agent run http://example.com --type penetration_test
```

Complete penetration test including exploitation simulation.

### Advanced Options

#### Specify Objectives
```bash
medusa agent run http://example.com \
  --objectives "find_credentials,escalate_privileges,extract_data"
```

Common objectives:
- `find_credentials`: Look for credential exposure
- `escalate_privileges`: Find privilege escalation paths
- `extract_data`: Identify data exfiltration opportunities
- `establish_persistence`: Find persistence mechanisms
- `lateral_movement`: Discover lateral movement paths

#### Auto-Approve Actions
```bash
medusa agent run http://example.com --auto-approve
```

⚠️ **Warning**: Bypasses approval gates. Use only in controlled environments.

#### Set Maximum Duration
```bash
medusa agent run http://example.com --max-duration 1800
```

Limits operation to 30 minutes (1800 seconds).

#### Disable Result Saving
```bash
medusa agent run http://example.com --no-save
```

Don't save operation results to file.

### Operation Flow

```
1. Initialization
   └─ Create all specialist agents
   └─ Connect to databases (Neo4j, ChromaDB)
   └─ Initialize message bus

2. Phase 1: Reconnaissance
   └─ ReconAgent recommends strategy
   └─ Analyzes network infrastructure
   └─ Identifies services and technologies

3. Phase 2: Vulnerability Analysis
   └─ VulnAnalysisAgent correlates with CVE database
   └─ Assesses exploitability
   └─ Prioritizes by risk

4. Phase 3: Strategic Planning
   └─ PlanningAgent designs attack chains
   └─ Creates operational plan
   └─ Optimizes attack sequence

5. Phase 4: Exploitation (Simulated)
   └─ ExploitationAgent plans exploits
   └─ Simulates execution (safe)
   └─ Recommends post-exploitation

6. Phase 5: Reporting
   └─ ReportingAgent aggregates findings
   └─ Generates comprehensive reports
   └─ Provides remediation guidance

7. Cleanup
   └─ Save operation results
   └─ Close database connections
   └─ Display summary
```

---

## Monitoring Status

### View Latest Operation Status

```bash
medusa agent status
```

Shows:
- Operation ID and target
- Agent performance metrics
- Task completion statistics
- Cost and token usage

### View Specific Agent

```bash
medusa agent status --agent ReconAgent
```

Shows detailed metrics for a single agent.

### View Specific Operation

```bash
medusa agent status --operation OP-20251113-001
```

Query historical operation by ID.

### Verbose Mode

```bash
medusa agent status --verbose
```

Shows additional details:
- Total tokens used per agent
- Total execution time
- Individual task breakdowns

### Example Output

```
🤖 Agent Status

Operation ID: OP-20251113-145230
Target: http://example.com
Status: completed

┌─────────────────┬───────┬───────────┬────────┬──────────────┐
│ Agent           │ Tasks │ Completed │ Failed │ Avg Time (s) │
├─────────────────┼───────┼───────────┼────────┼──────────────┤
│ orchestrator    │     1 │         1 │      0 │         45.23│
│ recon           │     3 │         3 │      0 │          8.12│
│ vuln_analysis   │     5 │         5 │      0 │         12.45│
│ planning        │     2 │         2 │      0 │         18.90│
│ exploitation    │     1 │         1 │      0 │          6.34│
│ reporting       │     1 │         1 │      0 │         22.11│
└─────────────────┴───────┴───────────┴────────┴──────────────┘
```

---

## Generating Reports

### Command Structure

```bash
medusa agent report [OPTIONS]
```

### Report Types

#### 1. Executive Summary (Default)
```bash
medusa agent report
```

Non-technical, business-focused report with:
- High-level risk assessment
- Key findings summary
- Business impact analysis
- Recommended actions

**Best for**: Executive stakeholders, management

#### 2. Technical Report
```bash
medusa agent report --type technical
```

Comprehensive technical documentation with:
- Detailed vulnerability analysis
- Proof-of-concept details
- CVSS scores
- Technical remediation steps

**Best for**: Security teams, technical staff

#### 3. Remediation Plan
```bash
medusa agent report --type remediation
```

Step-by-step fix guidance with:
- Prioritized action items
- Implementation steps
- Estimated effort
- Validation procedures

**Best for**: DevOps, system administrators

#### 4. Compliance Report
```bash
medusa agent report --type compliance
```

Framework-specific assessment with:
- Control mappings (PCI-DSS, HIPAA, GDPR)
- Compliance status
- Gap analysis
- Audit trail

**Best for**: Compliance officers, auditors

#### 5. All Report Types
```bash
medusa agent report --type all
```

Generates all report types at once.

### Output Formats

#### Markdown (Default)
```bash
medusa agent report --format markdown
```

Human-readable, can be viewed in any text editor or rendered as HTML.

#### JSON
```bash
medusa agent report --format json
```

Machine-readable, ideal for integration with other tools.

#### HTML
```bash
medusa agent report --format html
```

Web-ready, can be opened in a browser.

### Save to File

```bash
medusa agent report --output my-assessment.md
```

Saves report to specified file instead of displaying.

### Specify Operation

```bash
medusa agent report --operation OP-20251113-001
```

Generate report from historical operation.

### Complete Example

```bash
medusa agent report \
  --operation OP-20251113-001 \
  --type technical \
  --format html \
  --output security-assessment.html
```

---

## Advanced Usage

### Cost Optimization

The multi-agent system uses **smart model routing** for cost efficiency:

- **Simple/Moderate Tasks**: Claude 3.5 Haiku ($0.80/$4 per 1M tokens)
- **Complex Tasks**: Claude 3.5 Sonnet ($3/$15 per 1M tokens)

This provides **70-80% cost savings** compared to using Sonnet for everything.

#### Monitor Costs

```bash
medusa agent status --verbose
```

Shows cost breakdown per agent.

### Custom Objectives

Define specific objectives for targeted assessments:

```bash
medusa agent run http://api.example.com \
  --objectives "find_api_keys,test_authentication,check_rate_limiting"
```

### Integration with CI/CD

Run as part of security pipeline:

```bash
#!/bin/bash

# Run assessment
medusa agent run http://staging.example.com \
  --type vuln_scan \
  --max-duration 600 \
  --save

# Check for critical findings
CRITICAL=$(medusa agent status --verbose | grep -c "critical")

if [ "$CRITICAL" -gt 0 ]; then
    echo "❌ Critical vulnerabilities found!"
    exit 1
fi

echo "✅ No critical vulnerabilities"
```

### Programmatic Access

Operation results are saved as JSON:

```bash
# Run operation
medusa agent run http://example.com

# Parse results
jq '.findings[] | select(.severity=="critical")' \
  ~/.medusa/logs/multi-agent-OP-*.json
```

---

## Troubleshooting

### Common Issues

#### 1. "MEDUSA is not configured"

**Solution**:
```bash
medusa setup
```

Follow the setup wizard.

#### 2. "No multi-agent operations found"

**Cause**: No operations have been run yet.

**Solution**:
```bash
medusa agent run http://example.com
```

#### 3. LLM Connection Errors

**Check LLM connectivity**:
```bash
medusa llm verify
```

**Solutions**:
- Verify AWS credentials (if using Bedrock)
- Check API keys (if using other providers)
- Ensure network connectivity

#### 4. Vector Database Empty

**Symptoms**: Agents have limited context, no MITRE/CVE suggestions.

**Solution**: Run indexer scripts:
```bash
python scripts/index_mitre_attack.py
python scripts/index_tool_docs.py
python scripts/index_cves.py
```

#### 5. High Costs

**Check current routing**:
```bash
medusa agent status --verbose
```

**Optimization**:
- Most operations should use Haiku (cheap)
- Only planning/reporting use Sonnet (expensive)
- If all tasks use Sonnet, check model configuration

#### 6. Slow Performance

**Possible causes**:
- Large target network
- Many services discovered
- Complex vulnerability analysis

**Solutions**:
- Use `--type recon_only` for faster scans
- Set `--max-duration` to limit runtime
- Target specific hosts instead of networks

### Debug Mode

Enable verbose logging:

```bash
export MEDUSA_LOG_LEVEL=DEBUG
medusa agent run http://example.com
```

Check logs:
```bash
tail -f ~/.medusa/logs/medusa.log
```

### Getting Help

1. **Check documentation**:
   ```bash
   medusa agent run --help
   medusa agent status --help
   medusa agent report --help
   ```

2. **View examples**:
   ```bash
   medusa agent run --help | grep -A 20 "Examples:"
   ```

3. **Check operation logs**:
   ```bash
   ls -lah ~/.medusa/logs/multi-agent-*.json
   ```

---

## Best Practices

### 1. Start Small

Begin with reconnaissance-only operations:
```bash
medusa agent run http://example.com --type recon_only
```

### 2. Review Before Full Assessment

Check reconnaissance results before running full assessment:
```bash
medusa agent status --verbose
```

### 3. Use Objectives

Be specific about what you're looking for:
```bash
medusa agent run http://example.com \
  --objectives "find_sqli,find_xss,check_auth"
```

### 4. Monitor Costs

Always check costs after operations:
```bash
medusa agent status --verbose
```

### 5. Save Important Operations

Always use `--save` for production assessments (default):
```bash
medusa agent run http://production.example.com --save
```

### 6. Generate Multiple Reports

Different audiences need different reports:
```bash
# For executives
medusa agent report --type executive --output exec-summary.md

# For security team
medusa agent report --type technical --output tech-report.html

# For DevOps
medusa agent report --type remediation --output fixes.md
```

---

## Security Considerations

### Exploitation Safety

- ✅ **All exploitation is SIMULATED**
- ✅ **No real attacks are executed**
- ✅ **Analysis and recommendation only**
- ✅ **Approval gates for sensitive actions**

### Data Privacy

- Operation results stored locally in `~/.medusa/logs/`
- No data sent to external services (except LLM providers)
- Results include sensitive information - protect accordingly

### Target Authorization

⚠️ **IMPORTANT**: Only assess systems you own or have explicit authorization to test.

Unauthorized security testing is illegal.

---

## Next Steps

1. **Run your first assessment**:
   ```bash
   medusa agent run http://localhost:3001
   ```

2. **Check the results**:
   ```bash
   medusa agent status --verbose
   ```

3. **Generate reports**:
   ```bash
   medusa agent report --type all
   ```

4. **Learn more**:
   - [Architecture Guide](ARCHITECTURE.md)
   - [API Reference](API_REFERENCE.md)
   - [Development Guide](../DEVELOPMENT.md)

---

## Support

- **Issues**: https://github.com/your-org/project-medusa/issues
- **Documentation**: https://docs.medusa-security.io
- **Community**: https://discord.gg/medusa-security
