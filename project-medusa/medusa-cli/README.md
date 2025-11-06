# MEDUSA - AI-Powered Penetration Testing CLI

**Autonomous penetration testing powered by Large Language Models**

MEDUSA is a professional-grade command-line tool that uses AI to intelligently plan and execute penetration tests. Built for security professionals to test their own infrastructure with minimal manual intervention.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## ⚠️ Legal Disclaimer

**This tool is for authorized security testing only.** You must have explicit permission to test any system. Unauthorized access to computer systems is illegal.

---

## Features

### 🤖 Three Operating Modes

1. **Autonomous Mode** - Full attack chain with approval gates
   - Agent plans and executes penetration test
   - Stops for approval on risky actions
   - Generates comprehensive reports

2. **Interactive Mode** - Natural language command shell
   - Give commands in plain English
   - Real-time feedback and results
   - Full control over each action

3. **Observe Mode** - Reconnaissance without exploitation
   - Intelligence gathering only
   - Builds attack plan without executing
   - Perfect for initial assessment

### 🛡️ Safety Features

- **Risk-based approval gates** - LOW/MEDIUM/HIGH/CRITICAL classifications
- **Configurable auto-approval** - Set your comfort level
- **Emergency abort** - Cancel operations instantly
- **Detailed logging** - Full audit trail of all actions

### 📊 Professional Reporting

Multiple report formats automatically generated after each assessment:

- **📄 Technical HTML Reports** - Dark-themed professional reports for security teams
- **📈 Executive Summaries** - Business-focused reports for management
- **📝 Markdown Reports** - Integration with documentation systems and Git
- **📁 JSON Logs** - Machine-readable structured data for automation
- **🎯 MITRE ATT&CK Mapping** - Complete technique coverage tracking
- **💎 Beautiful Terminal UI** - Real-time progress with Rich library

All reports include:
- Risk ratings and severity classifications
- Detailed findings with CVSS scores
- Remediation recommendations
- Attack timeline and phases
- MITRE ATT&CK technique visualization

---

## 🚀 Quick Start

### Installation

```bash
pip install medusa-pentest
```

Or install from source:

```bash
git clone https://github.com/hidaroz/project-medusa
cd medusa-cli
pip install -e .
```

### First-Time Setup

Run the setup wizard:

```bash
medusa setup
```

This will guide you through:
1. **Gemini API Key** - Get yours at [Google AI Studio](https://ai.google.dev/gemini-api/docs/quickstart)
2. **Target Environment** - Local Docker or remote infrastructure
3. **Risk Tolerance** - Configure auto-approval levels
4. **Docker Setup** (optional) - Vulnerable test environment

### Basic Usage

#### Run Autonomous Assessment

```bash
medusa run --target http://localhost:3001 --autonomous
```

The agent will:
- ✅ Perform reconnaissance
- ✅ Enumerate services
- ✅ Identify vulnerabilities
- ⏸️  Request approval for exploitation
- ✅ Generate comprehensive report

#### Interactive Shell

```bash
medusa shell

MEDUSA> scan network
MEDUSA> enumerate services
MEDUSA> show findings
MEDUSA> exploit sql-injection
MEDUSA> exit
```

#### Observe Mode (Safe Reconnaissance)

```bash
medusa observe --target http://target.com
```

Performs reconnaissance and generates attack plan **without** exploitation.

---

## 📖 Detailed Usage

### Commands

| Command | Description |
|---------|-------------|
| `medusa setup` | Run setup wizard |
| `medusa run --target <url>` | Run penetration test |
| `medusa shell` | Start interactive shell |
| `medusa observe --target <url>` | Reconnaissance only |
| `medusa status` | Show configuration |
| `medusa logs` | View operation logs |
| `medusa reports` | List all generated reports |
| `medusa reports --open` | Open latest report in browser |
| `medusa generate-report` | Generate reports from logs |
| `medusa version` | Show version |

### Autonomous Mode Options

```bash
medusa run --target http://target.com --autonomous

# Or use short mode flag
medusa run --target http://target.com --mode autonomous
```

**What happens:**

1. **Reconnaissance Phase** 🔍
   - Port scanning
   - Service enumeration
   - Technology detection
   - **Risk: LOW** (auto-approved)

2. **Enumeration Phase** 🔎
   - API endpoint discovery
   - Authentication analysis
   - Vulnerability scanning
   - **Risk: LOW** (auto-approved)

3. **Exploitation Phase** 💥
   - Vulnerability exploitation
   - Authentication bypass
   - Data extraction
   - **Risk: MEDIUM/HIGH** (requires approval)

4. **Post-Exploitation** 🎯
   - Data exfiltration
   - Privilege escalation
   - Persistence mechanisms
   - **Risk: HIGH/CRITICAL** (requires approval)

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

## ❓ FAQ

**Q: Is this legal to use?**
A: Only on systems you own or have written permission to test. Unauthorized access is illegal.

**Q: Does this require an API key?**
A: Yes, you need a free Google Gemini API key from [Google AI Studio](https://ai.google.dev/gemini-api/docs/quickstart).

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

- Google Gemini for AI capabilities
- MITRE for the ATT&CK framework
- The security research community

---

## 📞 Support

- **Documentation**: [https://docs.medusa.dev](https://docs.medusa.dev)
- **Issues**: [GitHub Issues](https://github.com/hidaroz/project-medusa/issues)
- **Discussions**: [GitHub Discussions](https://github.com/hidaroz/project-medusa/discussions)

---

**Remember: With great power comes great responsibility. Use MEDUSA ethically and legally.**

 **MEDUSA** - AI-Powered Autonomous Penetration Testing
