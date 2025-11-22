# MEDUSA CLI - Multi-Agent AI-Powered Penetration Testing

**Enterprise-grade autonomous security assessment with LangGraph SDK and AWS Bedrock integration**

MEDUSA CLI is a professional command-line tool featuring a **LangGraph-based multi-agent system** with 5 specialized agents orchestrated by a Supervisor node. Built for security professionals with smart cost optimization and real-time tracking.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![AWS Bedrock](https://img.shields.io/badge/AWS-Bedrock-orange.svg)](https://aws.amazon.com/bedrock/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

## ⚠️ Legal Disclaimer

**This tool is for authorized security testing only.** You must have explicit permission to test any system. Unauthorized access to computer systems is illegal.

---

## Features

### 🤖 LangGraph Multi-Agent System (Recommended)

**LangGraph StateGraph with Supervisor-Worker pattern** for comprehensive security assessments:

- **Supervisor Node** - Routes tasks to specialized agents based on state
- **Reconnaissance Agent** - Network discovery and enumeration (Nmap, Amass, Httpx)
- **Vulnerability Analysis Agent** - CVE correlation and web scanning (WebScanner)
- **Planning Agent** - Strategic attack chain development
- **Exploitation Agent** - Controlled exploitation simulation (Metasploit)
- **Reporting Agent** - Multi-format report generation

**Benefits:**
- ✅ **LangGraph SDK** - Stateful, cyclic agent workflows with conditional routing
- ✅ **60% cost savings** through smart model routing (Haiku vs Sonnet)
- ✅ **Real-time cost tracking** - See exactly what you're spending
- ✅ **Context fusion** - Combines graph + vector databases for intelligence
- ✅ **Tool integration** - Real security tools (Nmap, Amass, Httpx, WebScanner, Metasploit)
- ✅ **Comprehensive reports** - Executive, technical, and remediation formats

### 💻 Classic Single-Agent Modes (Legacy)

1. **Autonomous Mode** - AI-driven with approval gates
2. **Interactive Shell** - Natural language commands
3. **Observe Mode** - Read-only reconnaissance

### 🛡️ Safety Features

- **Risk-based approval gates** - LOW/MEDIUM/HIGH/CRITICAL classifications
- **Configurable auto-approval** - Set your comfort level
- **Emergency abort** - Cancel operations instantly
- **Detailed logging** - Full audit trail of all actions

### 📊 Professional Reporting & Cost Tracking

**Automatic report generation** in multiple formats:

- **📄 Technical HTML Reports** - Dark-themed professional reports for security teams
- **📈 Executive Summaries** - Business-focused reports for management
- **📝 Markdown Reports** - Integration with documentation systems and Git
- **📁 JSON Logs** - Machine-readable structured data for automation
- **🎯 MITRE ATT&CK Mapping** - Complete technique coverage tracking
- **💰 Cost Reports** - Per-agent cost breakdown and optimization insights
- **💎 Beautiful Terminal UI** - Real-time progress with Rich library

All reports include:
- Risk ratings and severity classifications
- Detailed findings with CVSS scores
- Remediation recommendations
- Attack timeline and phases
- MITRE ATT&CK technique visualization
- **LLM cost breakdown** (when using AWS Bedrock)

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/hidaroz/project-medusa
cd medusa-cli

# Install CLI
pip install -e .

# Verify installation
medusa --version
```

### First-Time Setup

```bash
# Run setup wizard
medusa setup
```

This will guide you through:
1. **LLM Provider** - AWS Bedrock (recommended) or Local Ollama
2. **AWS Configuration** (if Bedrock) - Credentials and region setup
3. **Vector Database** - Index MITRE ATT&CK, CVEs, and tool docs
4. **Risk Tolerance** - Configure auto-approval levels
5. **Target Environment** - Local lab or external systems

### LLM Provider Setup

#### Option 1: AWS Bedrock (Recommended) ☁️

```bash
# Configure AWS credentials
aws configure
# Enter: Access Key ID, Secret Key, Region (us-west-2)

# Set provider
export LLM_PROVIDER=bedrock

# Verify connection
medusa llm verify
```

**Cost**: ~$0.20-0.30 per full assessment with smart routing

📚 [Complete Bedrock Setup Guide](docs/multi-agent/AWS_BEDROCK_SETUP.md)

#### Option 2: Local Ollama 🔒

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull model
ollama pull mistral:7b-instruct

# Set provider
export LLM_PROVIDER=local

# Verify
medusa llm verify
```

**Cost**: Free (zero cost)

### Basic Usage

#### Multi-Agent Assessment (Recommended)

```bash
# Full security assessment
medusa agent run http://target.com

# Reconnaissance only
medusa agent run target.com --type recon_only

# Vulnerability scan
medusa agent run target.com --type vuln_scan

# Check status and costs
medusa agent status --verbose

# Generate reports
medusa agent report --type technical --format html
```

The LangGraph multi-agent system will:
- ✅ Coordinate 5 specialized agents via Supervisor node
- ✅ Perform intelligent reconnaissance with real tools
- ✅ Correlate with CVE database
- ✅ Generate strategic plans
- ✅ Simulate exploitation (safely)
- ✅ Produce comprehensive reports
- 💰 Track costs in real-time

#### Single-Agent Modes (Legacy)

```bash
# Observe mode (read-only)
medusa observe --target http://target.com

# Autonomous mode (AI-driven)
medusa autonomous --target http://target.com

# Interactive shell
medusa shell
```

---

## 📖 Detailed Usage

### Multi-Agent Commands

| Command | Description |
|---------|-------------|
| `medusa graph run <target>` | **NEW!** Run autonomous graph assessment |
| `medusa agent run <target>` | Run legacy multi-agent assessment |
| `medusa agent run <target> --type recon_only` | Reconnaissance only |
| `medusa agent run <target> --type vuln_scan` | Vulnerability scanning |
| `medusa agent status` | Show latest operation status |
| `medusa agent status --verbose` | Detailed metrics with costs |
| `medusa agent report --type <type>` | Generate report (executive/technical/remediation) |
| `medusa llm verify` | Verify LLM connection |

### Single-Agent Commands (Legacy)

| Command | Description |
|---------|-------------|
| `medusa setup` | Run setup wizard |
| `medusa observe --target <url>` | Reconnaissance only (read-only) |
| `medusa autonomous --target <url>` | AI-driven assessment |
| `medusa shell` | Start interactive shell |
| `medusa status` | Show configuration |
| `medusa logs` | View operation logs |
| `medusa version` | Show version |

### LLM Connectivity Check

Verify your LLM provider is configured and accessible:

```bash
medusa llm verify
```

**Output on success (AWS Bedrock):**
```
╭─────────────────── LLM Connected ──────────────────-─╮
│  Provider   AWS Bedrock                              │
│  Region     us-west-2                                │
│  Smart Model   claude-3-5-sonnet-v2:0                │
│  Fast Model    claude-3-5-haiku-v1:0                 │
│  Smart Routing Enabled ✓                             │
│                                                      │
│  Cost Optimization:                                  │
│  • Smart routing saves ~60% on costs                 │
│  • Typical assessment: $0.20-0.30                    │
╰────────────────────────────────────────────────────--╯
```

**Output on success (Local Ollama):**
```
╭─────────────────── LLM Connected ─────────────────-──╮
│  Provider   local                                    │
│  Model      mistral:7b-instruct                      │
│  Cost       Free (unlimited)                         │
╰───────────────────────────────────────────────--─────╯
```

**Supported Providers:**
- **bedrock** - AWS Bedrock with Claude 3.5 (recommended for production)
- **local** - Ollama with Mistral or other models (recommended for offline)
- **openai** - OpenAI GPT-4 (requires API key)
- **anthropic** - Anthropic Claude API (requires API key)
- **mock** - Testing mode (no actual LLM calls)

### Multi-Agent Assessment Flow

```bash
medusa agent run http://target.com
```

**What happens:**

1. **Initialization** ⚙️
   - LangGraph StateGraph initializes
   - Supervisor Node starts
   - Connects to Neo4j graph database
   - Loads vector database (MITRE/CVE knowledge)
   - Initializes all 5 specialist agent nodes

2. **Reconnaissance Phase** 🔍
   - Recon Agent performs discovery
   - Network scanning, service enumeration
   - **Risk: LOW** (auto-approved)
   - **Cost: ~$0.03-0.05**

3. **Vulnerability Analysis Phase** 🔎
   - Vulnerability Analysis Agent evaluates findings
   - Correlates with CVE database
   - Prioritizes by risk
   - **Risk: LOW** (auto-approved)
   - **Cost: ~$0.04-0.06**

4. **Strategic Planning Phase** 🧠
   - Planning Agent designs attack chains
   - Generates comprehensive strategy
   - Maps to MITRE ATT&CK
   - **Risk: LOW** (planning only)
   - **Cost: ~$0.08-0.10** (uses Sonnet for deep reasoning)

5. **Exploitation Phase** 💥
   - Exploitation Agent simulates attacks
   - **Risk: MEDIUM/HIGH** (requires approval)
   - Controlled, safe simulation
   - **Cost: ~$0.02-0.04**

6. **Reporting Phase** 📊
   - Reporting Agent generates all formats
   - Executive, technical, remediation reports
   - **Cost: ~$0.03-0.05**

**Total typical cost: $0.20-0.30** (with smart routing)

### Interactive Mode Commands

Natural language examples:

```bash
MEDUSA> scan network
MEDUSA> find vulnerabilities
MEDUSA> exploit sql injection
MEDUSA> show findings
MEDUSA> exfiltrate data
MEDUSA> show context
```

Built-in commands:

```bash
MEDUSA> help              # Show available commands
MEDUSA> set target <url>  # Change target
MEDUSA> show context      # Display session info
MEDUSA> show findings     # List discovered issues
MEDUSA> clear             # Clear screen
MEDUSA> exit              # Quit shell
```

### Observe Mode

Perfect for initial assessment:

```bash
medusa observe --target http://target.com
```

**Output includes:**
- Network reconnaissance results
- Service enumeration
- Vulnerability assessment
- **AI-generated attack plan** (not executed)
- Intelligence report

---

## 🎯 Approval Gate System

MEDUSA uses risk-based approval gates to prevent accidental damage:

### Risk Levels

| Level | Description | Default Action |
|-------|-------------|----------------|
| **LOW** | Read-only operations (scans, enumeration) | Auto-approve |
| **MEDIUM** | Exploitation attempts, reversible actions | Prompt user |
| **HIGH** | Data modification, exfiltration | Prompt + explain |
| **CRITICAL** | Destructive actions, persistence | Always prompt |

### Example Prompt

```
⚠️  MEDIUM RISK ACTION

Technique: T1190 (Exploit Public-Facing Application)
Command: sqlmap -u http://target/api --dbs
Impact: Attempt SQL injection to enumerate databases

Approve? [y/n/s/a/all]:
  y   - Approve this action
  n   - Deny this action
  s   - Skip this step
  a   - Abort entire operation
  all - Approve all remaining actions
```

### Configure in Setup

```bash
medusa setup

[3/4] Risk Tolerance
Auto-approve actions rated as:
  - LOW risk (reconnaissance, safe commands) [y/n]: y
  - MEDIUM risk (exploitation attempts) [y/n]: n
  - HIGH risk (data destruction, persistence) [y/n]: n
```

---

## 📁 File Structure

After setup, MEDUSA creates:

```
~/.medusa/
├── config.yaml           # Configuration
├── logs/                 # JSON operation logs
│   └── run-20240129_143022-op_001.json
└── reports/              # HTML reports
    └── report-20240129_143022-op_001.html
```

### Configuration File

`~/.medusa/config.yaml`:

```yaml
api_key: "your-gemini-api-key"
target:
  type: docker
  url: http://localhost:3001
risk_tolerance:
  auto_approve_low: true
  auto_approve_medium: false
  auto_approve_high: false
```

---

## 💰 Cost Management (AWS Bedrock)

### Real-Time Cost Tracking

Track LLM costs in real-time for all multi-agent operations:

```bash
# View detailed cost breakdown
medusa agent status --verbose
```

**Example Output:**
```
┌─────────────────────────────────────────┐
│  Multi-Agent Operation Cost Summary     │
├─────────────────────────────────────────┤
│  Total Cost: $0.23                      │
│  Orchestrator:        $0.05 (Sonnet)    │
│  Recon Agent:         $0.03 (Haiku)     │
│  Vuln Analysis:       $0.04 (Haiku)     │
│  Planning Agent:      $0.08 (Sonnet)    │
│  Exploitation:        $0.02 (Haiku)     │
│  Reporting:           $0.01 (Haiku)     │
│                                          │
│  Total Tokens: 45,230                   │
│  Smart Routing Savings: 62%             │
└─────────────────────────────────────────┘
```

### Operation Cost Estimates

| Operation Type | Duration | Typical Cost |
|---------------|----------|--------------|
| `recon_only` | 2-5 min | $0.05-0.10 |
| `vuln_scan` | 5-8 min | $0.10-0.15 |
| `full_assessment` | 10-20 min | $0.20-0.30 |

### Monthly Cost Estimates

| Usage Level | Assessments/Month | Monthly Cost |
|------------|------------------|--------------|
| Light (Learning) | 10 | $2-3 |
| Medium (Testing) | 50 | $10-15 |
| Heavy (Production) | 200 | $40-60 |
| Enterprise | 1000+ | $200-300 |

### Cost Optimization

**Smart Routing** (automatic):
- Uses Haiku ($0.80/$4 per 1M tokens) for 70% of tasks
- Uses Sonnet ($3/$15 per 1M tokens) for complex reasoning
- **Saves 60-70%** vs Sonnet-only

**Cost Control:**
```bash
# Set max cost per operation
medusa agent run target.com --max-cost 0.50

# Use free local LLM
export LLM_PROVIDER=local

# Mock mode (testing, no LLM calls)
export LLM_PROVIDER=mock
```

---

## 📊 Reports

### JSON Logs

Structured logs for automation:

```json
{
  "metadata": {
    "operation_id": "auto_20240129_143022",
    "timestamp": "2024-01-29T14:30:22",
    "medusa_version": "1.0.0"
  },
  "operation": {
    "mode": "autonomous",
    "target": "http://localhost:3001",
    "duration_seconds": 235.6,
    "summary": {
      "total_findings": 12,
      "critical": 0,
      "high": 3,
      "medium": 5,
      "low": 4
    },
    "phases": [...],
    "findings": [...],
    "mitre_coverage": [...]
  }
}
```

### HTML Reports

Professional reports with:
- Executive summary
- Vulnerability details with CVSS scores
- MITRE ATT&CK technique coverage
- Phase-by-phase breakdown
- Remediation recommendations

View latest:

```bash
medusa reports --open
```

---

## 🧪 Testing Environment

MEDUSA includes a Docker-based vulnerable test environment.

### Quick Start

```bash
medusa setup
# Choose "1. Local Docker environment"

# Then run tests
medusa run --target http://localhost:3001 --autonomous
```

### Manual Lab Environment Setup

If you want to run the MedCare EHR target lab separately:

```bash
cd ../lab-environment
docker-compose up -d

# Verify EHR API is running
curl http://localhost:3000/health
```

---

## 🔧 Advanced Configuration

### Custom Target

```bash
medusa run --target https://my-test-app.com --mode observe
```

### View Status

```bash
medusa status
```

Output:
```
Configuration:
  Version: 1.0.0
  Config Path: /Users/you/.medusa/config.yaml
  Target: http://localhost:3001
  Target Type: docker
  API Key: Configured

Risk Tolerance:
  Auto-approve LOW risk: Yes
  Auto-approve MEDIUM risk: No
  Auto-approve HIGH risk: No
```

### View Logs

```bash
# Show all logs
medusa logs

# Show latest only
medusa logs --latest

# Show last 50 lines
medusa logs --tail 50
```

---

## 🤖 How It Works

### AI-Powered Decision Making

MEDUSA uses Google's Gemini LLM to:

1. **Analyze reconnaissance data** - Identify attack vectors
2. **Plan exploitation strategy** - Choose optimal techniques
3. **Adapt in real-time** - Adjust based on success/failure
4. **Generate natural language explanations** - Explain each decision

### MITRE ATT&CK Mapping

All techniques are mapped to the MITRE ATT&CK framework:

- **T1046** - Network Service Discovery
- **T1590** - Gather Victim Network Information
- **T1190** - Exploit Public-Facing Application
- **T1041** - Exfiltration Over C2 Channel
- And more...

Reports show which techniques were:
- ✅ Executed successfully
- ❌ Failed
- ⊘ Skipped by user

---

## 🛠️ Development

### Project Structure

```
medusa-cli/
├── src/
│   └── medusa/
│       ├── __init__.py
│       ├── cli.py              # Typer CLI entry point
│       ├── config.py           # Configuration management
│       ├── client.py           # Backend API client
│       ├── display.py          # Rich terminal UI
│       ├── approval.py         # Approval gate system
│       ├── reporter.py         # Report generation
│       └── modes/
│           ├── autonomous.py   # Autonomous mode
│           ├── interactive.py  # Interactive shell
│           └── observe.py      # Observe mode
├── setup.py
├── requirements.txt
├── pyproject.toml
└── README.md
```

### Install for Development

```bash
git clone https://github.com/hidaroz/project-medusa
cd medusa-cli
pip install -e .
```

### Run Tests

```bash
pytest
```

### Code Quality

```bash
# Format code
black src/

# Type checking
mypy src/

# Linting
flake8 src/
```

---

## 📚 Examples

### Example 1: Quick Assessment

```bash
# Setup once
medusa setup

# Run quick assessment
medusa observe --target http://target.com

# Review intelligence report
medusa reports --open
```

### Example 2: Full Penetration Test

```bash
# Run autonomous test with approval gates
medusa run --target http://target.com --autonomous

# Agent will:
# 1. Scan network (auto-approved)
# 2. Find vulnerabilities (auto-approved)
# 3. Attempt exploitation (asks for approval)
# 4. Exfiltrate data (asks for approval)

# View results
medusa reports --open
```

### Example 3: Interactive Exploration

```bash
medusa shell

MEDUSA> set target http://test-app.com
MEDUSA> scan network
MEDUSA> enumerate services
MEDUSA> show findings
MEDUSA> exploit sql-injection --target /api/users
MEDUSA> exfiltrate data
MEDUSA> exit
```

---

## 🔧 Troubleshooting

### LLM Connection Issues

**Problem: `medusa llm verify` fails to connect**

Check what's configured:
```bash
medusa status
```

**For Local (Ollama) Provider:**

1. Verify Ollama is running:
   ```bash
   # Should return a version number
   curl http://localhost:11434/api/version
   ```

2. Check if model is pulled:
   ```bash
   ollama list
   # Should show: mistral:7b-instruct
   ```

3. If not pulled, download it:
   ```bash
   ollama pull mistral:7b-instruct
   ```

4. Start Ollama if stopped:
   ```bash
   # macOS/Linux
   ollama serve
   
   # Or if installed as service
   systemctl start ollama
   ```

**For Cloud Providers (OpenAI/Anthropic):**

1. Verify API key is set:
   ```bash
   echo $CLOUD_API_KEY  # Should not be empty
   ```

2. Install required SDK:
   ```bash
   # For OpenAI
   pip install openai
   
   # For Anthropic
   pip install anthropic
   ```

3. Check network connectivity:
   ```bash
   # For OpenAI
   curl https://api.openai.com/v1/models
   
   # For Anthropic
   curl https://api.anthropic.com/
   ```

### Configuration Issues

**Problem: Config file not found**

Reset configuration:
```bash
medusa setup --force
```

**Problem: Wrong LLM provider configured**

Edit configuration:
```bash
cat ~/.medusa/config.yaml  # View current config

medusa setup --force       # Reconfigure
```

### Performance Issues

**Problem: LLM responses are slow**

- Check internet connection (for cloud providers)
- Check local system resources (for Ollama): `top` or `Activity Monitor`
- Try a smaller model: `ollama pull mistral:7b` instead of `mistral:7b-instruct`

### Permission Issues

**Problem: Permission denied when accessing config**

```bash
# Fix permissions
chmod 600 ~/.medusa/config.yaml
chmod 700 ~/.medusa/
```

---

## ❓ FAQ

**Q: Is this legal to use?**
A: Only on systems you own or have written permission to test. Unauthorized access is illegal.

**Q: Does this require an API key?**
A: For AWS Bedrock (recommended): Yes, you need AWS credentials. For Ollama (local): No, completely free and offline.

**Q: Will it actually hack systems?**
A: MEDUSA can identify and exploit vulnerabilities, but it has safety gates. It's designed for authorized testing only.

**Q: Can I use this on production systems?**
A: **Only if you have explicit authorization.** Start with observe mode for minimal impact.

**Q: What if something goes wrong?**
A: Press `Ctrl+C` to abort at any time. All operations are logged for review.

**Q: How do I get the test environment?**
A: Run `medusa setup` and choose "Local Docker environment".

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution

- Additional attack modules
- New LLM providers (OpenAI, Anthropic, local models)
- Enhanced reporting
- More MITRE techniques
- Documentation improvements

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments
- MITRE for the ATT&CK framework
- The security research community

---

## 📞 Support

- **Documentation**: [https://docs.medusa.dev](https://docs.medusa.dev)
- **Issues**: [GitHub Issues](https://github.com/hidaroz/project-medusa/issues)
- **Discussions**: [GitHub Discussions](https://github.com/hidaroz/project-medusa/discussions)

---

**Remember: With great power comes great responsibility. Use MEDUSA ethically and legally.**

---

**Last Updated:** November 15, 2025
**Version:** 2.1 (Multi-Agent + AWS Bedrock)
**Documentation:** [Complete Docs](../docs/INDEX.md) | [Multi-Agent Guide](docs/multi-agent/USER_GUIDE.md)

 **MEDUSA CLI** - Multi-Agent AI-Powered Autonomous Penetration Testing
