# CLI API Reference

Complete reference for MEDUSA command-line interface.

## Overview

MEDUSA provides a comprehensive CLI built with Typer and Rich for terminal UI. All commands support `--help` for detailed usage information.

## Command Structure

```
medusa [COMMAND] [SUBCOMMAND] [OPTIONS] [ARGUMENTS]
```

### Command Groups

- **Main Commands** - Core penetration testing operations
- **llm** - LLM utilities and diagnostics
- **agent** - Multi-agent system commands
- **graph** - LangGraph autonomous agent commands

## Main Commands

### `medusa setup`

Run the setup wizard to configure MEDUSA.

**Usage:**
```bash
medusa setup [OPTIONS]
```

**Options:**
- `--force, -f` - Force re-setup even if config exists

**Description:**
Guides you through:
- Configuring LLM provider (Local Ollama, Cloud, or Mock)
- Configuring target environment
- Setting risk tolerance levels
- Initializing Docker environment (optional)

**Examples:**
```bash
# Initial setup
medusa setup

# Reconfigure existing installation
medusa setup --force
```

---

### `medusa run`

Run a penetration test.

**Usage:**
```bash
medusa run [OPTIONS]
```

**Options:**
- `--target, -t TEXT` - Target URL (e.g., http://localhost:3001)
- `--autonomous, -a` - Run in autonomous mode with approval gates
- `--mode, -m TEXT` - Operating mode: `autonomous`, `interactive`, `observe`
- `--loop, -l` - Run continuously in a loop
- `--interval, -i INTEGER` - Interval between runs in seconds (default: 3600)

**Modes:**

1. **Autonomous Mode** - Full AI-driven attack chain with approval gates
   - Reconnaissance → Enumeration → Vulnerability Assessment → Exploitation → Post-Exploitation
   - Requires user approval for HIGH and CRITICAL risk actions

2. **Interactive Mode** - Natural language shell for manual control
   - Issue commands like "scan network" or "enumerate services"
   - Step-by-step control with AI assistance

3. **Observe Mode** - Read-only reconnaissance
   - Passive and active reconnaissance only
   - Generates attack plan without execution
   - Safe for initial assessment

**Examples:**
```bash
# Autonomous mode with default target
medusa run

# Autonomous mode with specific target
medusa run --target http://localhost:3001 --autonomous

# Observe mode (reconnaissance only)
medusa run --target http://example.com --mode observe

# Interactive shell mode
medusa run --mode interactive

# Continuous scanning (every hour)
medusa run --target http://localhost:3001 --loop --interval 3600
```

---

### `medusa shell`

Start interactive shell mode.

**Usage:**
```bash
medusa shell [OPTIONS]
```

**Options:**
- `--target, -t TEXT` - Target URL (optional, can be set in shell)

**Description:**
Provides a REPL (Read-Eval-Print Loop) where you can issue natural language commands.

**Shell Commands:**
```
MEDUSA> scan network
MEDUSA> enumerate services
MEDUSA> show findings
MEDUSA> analyze vulnerabilities
MEDUSA> exit
```

**Examples:**
```bash
# Start shell with target
medusa shell --target http://localhost:3001

# Start shell without target (set later)
medusa shell
```

---

### `medusa observe`

Run in observe mode (reconnaissance only).

**Usage:**
```bash
medusa observe [OPTIONS]
```

**Options:**
- `--target, -t TEXT` - Target URL to observe

**Description:**
Performs passive and active reconnaissance without exploitation. Generates an attack plan but does NOT execute it.

**Perfect for:**
- Initial assessment
- Safe exploration
- Attack planning

**Examples:**
```bash
medusa observe --target http://localhost:3001
medusa observe --target 192.168.1.0/24
```

---

### `medusa status`

Show current configuration and system status.

**Usage:**
```bash
medusa status
```

**Displays:**
- Configuration file location
- LLM provider and model
- Target environment
- Risk tolerance settings
- Directory locations

**Example:**
```bash
medusa status
```

**Sample Output:**
```
╭─────────── MEDUSA Status ───────────╮
│ LLM Provider:  local (Ollama)       │
│ Model:         mistral:7b-instruct  │
│ Target:        http://localhost:3001│
│ Config:        ~/.medusa/config.yaml│
╰─────────────────────────────────────╯
```

---

### `medusa logs`

View operation logs.

**Usage:**
```bash
medusa logs [OPTIONS]
```

**Options:**
- `--latest` - Show the most recent log file
- `--operation TEXT` - Show logs for specific operation ID
- `--tail INTEGER` - Show last N lines (default: 100)
- `--follow, -f` - Follow log output in real-time

**Examples:**
```bash
# View latest logs
medusa logs --latest

# View specific operation
medusa logs --operation operation_20240115_143022

# Follow logs in real-time
medusa logs --latest --follow

# Show last 50 lines
medusa logs --latest --tail 50
```

---

### `medusa reports`

Manage and view reports.

**Usage:**
```bash
medusa reports [SUBCOMMAND] [OPTIONS]
```

**Subcommands:**
- `list` - List all available reports
- `view REPORT_ID` - View a specific report
- `export REPORT_ID` - Export report to different format
- `clean` - Remove old reports

**Options:**
- `--format TEXT` - Output format: `html`, `json`, `markdown` (for export)
- `--output TEXT` - Output file path (for export)
- `--days INTEGER` - Remove reports older than N days (for clean)

**Examples:**
```bash
# List all reports
medusa reports list

# View specific report
medusa reports view operation_20240115_143022

# Export report as HTML
medusa reports export operation_20240115_143022 --format html --output report.html

# Clean old reports (older than 30 days)
medusa reports clean --days 30
```

---

### `medusa version`

Show MEDUSA version information.

**Usage:**
```bash
medusa --version
medusa version
```

---

### `medusa completions`

Generate shell completion scripts.

**Usage:**
```bash
medusa completions [SHELL]
```

**Shells:**
- `bash`
- `zsh`
- `fish`

**Examples:**
```bash
# Generate bash completions
medusa completions bash > ~/.medusa_completions.sh
source ~/.medusa_completions.sh

# Generate zsh completions
medusa completions zsh > ~/.medusa_completions.zsh
```

---

## LLM Commands

### `medusa llm verify`

Check that the configured LLM is reachable and active.

**Usage:**
```bash
medusa llm verify
```

**Description:**
Verifies connectivity with the LLM provider (local Ollama, cloud API, etc.) without running any prompts. Perfect for troubleshooting LLM setup issues.

**Exit Codes:**
- `0` - LLM is connected and healthy
- `1` - LLM is not available or unreachable

**Examples:**
```bash
medusa llm verify
```

**Sample Output (Success):**
```
╭───────── ✓ LLM Connected ─────────╮
│ Provider:    local (Ollama)       │
│ Model:       mistral:7b-instruct  │
│ Parameters:  7,241,748,480        │
╰───────────────────────────────────╯
```

**Sample Output (Failure):**
```
╭───────── ✗ LLM Not Connected ─────────╮
│ Ensure Ollama is running at           │
│ http://localhost:11434                │
│                                        │
│ Quick fix:                             │
│   1. Install Ollama: curl -fsSL...    │
│   2. Pull model: ollama pull mistral  │
│   3. Start Ollama: ollama serve       │
╰────────────────────────────────────────╯
```

---

## Multi-Agent Commands

### `medusa agent run`

Run a multi-agent security operation.

**Usage:**
```bash
medusa agent run TARGET [OPTIONS]
```

**Arguments:**
- `TARGET` - Target URL or IP address (required)

**Options:**
- `--type, -t TEXT` - Operation type (default: `full_assessment`)
  - `full_assessment` - Complete penetration test
  - `recon_only` - Reconnaissance only
  - `vuln_scan` - Vulnerability scanning
  - `penetration_test` - Full exploitation attempt
- `--objectives, -o TEXT` - Comma-separated objectives
- `--auto-approve, -y` - Auto-approve all actions (use with caution)
- `--max-duration, -d INTEGER` - Maximum operation duration in seconds (default: 3600)
- `--save, -s` - Save operation results to file (default: True)

**Description:**
The orchestrator will coordinate specialist agents to perform:
- Reconnaissance (network/service discovery)
- Vulnerability Analysis (CVE correlation, risk assessment)
- Strategic Planning (attack chain design)
- Exploitation (simulated exploit execution)
- Reporting (comprehensive documentation)

**Examples:**
```bash
# Full assessment of target
medusa agent run http://localhost:3001

# Reconnaissance only
medusa agent run 192.168.1.0/24 --type recon_only

# With specific objectives
medusa agent run example.com --objectives "find_admin,extract_data"

# Auto-approve all actions (dangerous!)
medusa agent run 10.0.0.1 --auto-approve

# Time-limited operation (30 minutes)
medusa agent run http://target.com --max-duration 1800
```

**Objectives:**
Common objectives you can specify:
- `find_credentials` - Locate credentials or authentication bypass
- `escalate_privileges` - Attempt privilege escalation
- `lateral_movement` - Explore network for lateral movement
- `exfiltrate_data` - Identify data exfiltration opportunities
- `persistence` - Establish persistent access (simulated)
- `find_admin` - Locate administrative interfaces
- `extract_data` - Extract sensitive data

---

### `medusa agent status`

Show status of running multi-agent operations.

**Usage:**
```bash
medusa agent status [OPTIONS]
```

**Options:**
- `--operation TEXT` - Show status for specific operation ID
- `--all` - Show all operations (including completed)

**Examples:**
```bash
# Show current operation status
medusa agent status

# Show specific operation
medusa agent status --operation op_20240115_143022

# Show all operations
medusa agent status --all
```

---

### `medusa agent stop`

Stop a running multi-agent operation.

**Usage:**
```bash
medusa agent stop [OPERATION_ID]
```

**Arguments:**
- `OPERATION_ID` - Operation to stop (optional if only one is running)

**Examples:**
```bash
# Stop current operation
medusa agent stop

# Stop specific operation
medusa agent stop op_20240115_143022
```

---

## Graph Commands

### `medusa graph run`

Run LangGraph autonomous agent.

**Usage:**
```bash
medusa graph run TARGET [OPTIONS]
```

**Arguments:**
- `TARGET` - Target URL or IP address (required)

**Options:**
- `--objectives, -o TEXT` - Comma-separated objectives
- `--max-iterations INTEGER` - Maximum graph iterations (default: 20)
- `--approval-mode TEXT` - Approval mode: `manual`, `auto_low`, `auto_medium` (default: `manual`)

**Description:**
Runs the LangGraph-based autonomous agent system with:
- Structured state management
- Approval gates for risk mitigation
- Adaptive decision-making based on findings
- Graph-based workflow coordination

**Examples:**
```bash
# Run graph mode with manual approval
medusa graph run http://localhost:3001

# Auto-approve low-risk actions
medusa graph run http://target.com --approval-mode auto_low

# With specific objectives and iteration limit
medusa graph run 192.168.1.1 --objectives "recon,vuln_scan" --max-iterations 10
```

**Approval Modes:**
- `manual` - Prompt for all actions (default, safest)
- `auto_low` - Auto-approve LOW risk actions, prompt for others
- `auto_medium` - Auto-approve LOW and MEDIUM risk actions, prompt for HIGH/CRITICAL
- `auto_all` - Auto-approve all (dangerous, for testing only)

---

## Configuration

### Configuration File

**Location:** `~/.medusa/config.yaml`

**Structure:**
```yaml
# LLM Configuration
llm:
  provider: local  # or 'bedrock', 'openai', 'anthropic', 'mock'
  local_model: mistral:7b-instruct
  ollama_url: http://localhost:11434
  temperature: 0.7
  max_tokens: 2048
  timeout: 60
  max_retries: 3

# Target Configuration
target:
  type: docker  # or 'custom'
  url: http://localhost:3001

# Risk Tolerance
risk_tolerance:
  auto_approve_low: true
  auto_approve_medium: false
  auto_approve_high: false
  auto_approve_critical: false

# Logging
logging:
  level: INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  log_dir: ~/.medusa/logs

# Reporting
reporting:
  default_format: html  # html, json, markdown
  include_mitre_mapping: true
```

### Environment Variables

MEDUSA supports the following environment variables:

- `CLOUD_API_KEY` - API key for cloud LLM providers (OpenAI, Anthropic)
- `MEDUSA_LOG_LEVEL` - Override log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `MEDUSA_CONFIG_DIR` - Override config directory (default: ~/.medusa)
- `NEO4J_PASSWORD` - Password for Neo4j graph database
- `OLLAMA_URL` - Override Ollama server URL

**Examples:**
```bash
# Use OpenAI with API key
export CLOUD_API_KEY="sk-..."
medusa setup  # Choose OpenAI provider

# Enable debug logging
export MEDUSA_LOG_LEVEL=DEBUG
medusa run --target http://localhost:3001

# Use custom Ollama server
export OLLAMA_URL="http://192.168.1.100:11434"
medusa llm verify
```

---

## Risk Levels

MEDUSA categorizes all actions by risk level to enable informed approval decisions.

### Risk Level Definitions

| Level | Description | Examples | Default Approval |
|-------|-------------|----------|------------------|
| **LOW** | Read-only, no system changes | Port scanning, service enumeration, DNS lookups | Auto-approved |
| **MEDIUM** | Active testing, minimal impact | Vulnerability scanning, brute-force attempts, SQL injection tests | Prompt user |
| **HIGH** | Data modification, potential impact | Database manipulation, file uploads, credential extraction | Requires approval |
| **CRITICAL** | Destructive or permanent changes | Data destruction, system shutdown, persistence mechanisms | Always prompt |

### Approval Configuration

Edit `~/.medusa/config.yaml`:

```yaml
risk_tolerance:
  auto_approve_low: true      # Auto-approve port scans, service enumeration
  auto_approve_medium: false  # Prompt for vulnerability scans, exploitation attempts
  auto_approve_high: false    # Always prompt for data modification
  # CRITICAL actions always require approval (hardcoded safety)
```

**Interactive Approval Prompt:**
```
┌──────────── 🟠 Approval Required ────────────┐
│ MEDIUM RISK ACTION                           │
│                                              │
│ Technique: T1190 (Exploit Public-Facing App)│
│ Command: sqlmap -u http://target/api --dbs  │
│ Impact: Attempt SQL injection to enumerate  │
│         databases                            │
│ Target: http://target/api                   │
└──────────────────────────────────────────────┘

Approve? yes / no / skip / abort / all (approve all)
```

---

## Exit Codes

MEDUSA uses standard exit codes:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error |
| `2` | Configuration error |
| `3` | LLM connection error |
| `4` | Target unreachable |
| `130` | User interrupted (Ctrl+C) |

---

## Output Formats

### Terminal Output

MEDUSA uses Rich for beautiful terminal output:
- **Progress bars** - For long-running operations
- **Panels** - For important messages and summaries
- **Tables** - For structured data (findings, vulnerabilities)
- **Syntax highlighting** - For code and logs

### Report Formats

Generated reports support multiple formats:

**HTML (Technical Report)**
- Dark-themed professional layout
- MITRE ATT&CK technique mapping
- Vulnerability details with CVE links
- Attack chain visualization
- Location: `~/.medusa/reports/operation_[ID]_technical.html`

**HTML (Executive Summary)**
- Business-focused summary
- Risk metrics and severity distribution
- High-level findings
- Recommendations
- Location: `~/.medusa/reports/operation_[ID]_executive.html`

**JSON**
- Machine-readable format
- Complete operation data
- Ideal for integration with other tools
- Location: `~/.medusa/logs/operation_[ID].json`

**Markdown**
- Documentation-friendly format
- Can be integrated into wikis, repos
- Location: `~/.medusa/reports/operation_[ID].md`

---

## Common Patterns

### Basic Workflow

```bash
# 1. Initial setup
medusa setup

# 2. Verify LLM connectivity
medusa llm verify

# 3. Run reconnaissance
medusa observe --target http://target.com

# 4. Review findings, then run full assessment
medusa run --target http://target.com --autonomous

# 5. View reports
medusa reports list
medusa reports view operation_20240115_143022
```

### Multi-Agent Workflow

```bash
# 1. Run coordinated multi-agent operation
medusa agent run http://target.com --type full_assessment

# 2. Monitor status
medusa agent status

# 3. If needed, stop operation
medusa agent stop
```

### Graph Mode Workflow

```bash
# 1. Run LangGraph autonomous agent
medusa graph run http://target.com --objectives "recon,vuln_scan"

# 2. Auto-approve low-risk actions for faster execution
medusa graph run http://target.com --approval-mode auto_low --max-iterations 15
```

### Continuous Monitoring

```bash
# Monitor target every hour
medusa run --target http://target.com --loop --interval 3600 --mode observe
```

---

## Troubleshooting

### Common Issues

**LLM Not Connected:**
```bash
medusa llm verify
# Follow provider-specific remediation hints
```

**Target Unreachable:**
```bash
# Test connectivity manually
curl http://target.com

# Check Docker containers (if using MedCare EHR)
docker ps | grep medcare
```

**Configuration Errors:**
```bash
# Validate config
medusa status

# Reconfigure
medusa setup --force
```

**Permission Errors:**
```bash
# Fix permissions
chmod -R u+w ~/.medusa/

# Or remove and reconfigure
rm -rf ~/.medusa/
medusa setup
```

### Debug Mode

Enable debug logging:
```bash
export MEDUSA_LOG_LEVEL=DEBUG
medusa run --target http://target.com
```

View debug logs:
```bash
medusa logs --latest --follow
```

---

## See Also

- [Development Setup Guide](../02-development/setup-guide.md) - Set up development environment
- [CLI Quickstart](../00-getting-started/cli-quickstart.md) - Quick start guide
- [Security Policy](../06-security/security-policy.md) - Security and ethical guidelines
- [Agent API Reference](agent-api.md) - Multi-agent system API details
