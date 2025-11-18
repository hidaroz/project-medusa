# MEDUSA Quick Start Guide

**Get up and running with MEDUSA Multi-Agent System in 15-20 minutes**

This guide covers the complete setup including LLM configuration and knowledge base indexing for the full multi-agent experience.

## Prerequisites

- Python 3.9+
- pip (Python package manager)
- **LLM Provider:** AWS Account (Bedrock) OR Ollama (local)
- Basic understanding of penetration testing concepts

**Time Estimate:**
- Installation: 2 minutes
- LLM Setup: 5-10 minutes
- Knowledge Base Indexing: 10 minutes (multi-agent mode)
- First scan: 2-5 minutes

---

## Step 1: Installation (2 minutes)

### Option A: Automated Install (Recommended)

```bash
# Clone repository
git clone https://github.com/your-org/medusa.git
cd medusa

# Run installation script
bash scripts/install.sh
```

### Option B: Manual Install

```bash
pip install -e .

# If "medusa: command not found":
python3 -m medusa.cli --help
```

### Verify Installation

```bash
medusa --version
# Output: MEDUSA CLI v1.0.0

medusa --help
# Shows help text
```

---

## Step 2: LLM Provider Setup (5-10 minutes)

Choose your LLM provider:

### Option A: AWS Bedrock (Recommended for Production)

```bash
# Install AWS CLI
pip install awscli

# Configure credentials
aws configure
# Enter: Access Key ID, Secret Key, Region (us-west-2)

# Set provider
export LLM_PROVIDER=bedrock

# Verify connection
medusa llm verify
```

**Expected output:**
```
✅ AWS Bedrock connected
✅ Smart routing enabled
💰 Typical assessment: $0.20-0.30
```

📚 **[Full Bedrock Setup Guide](00-getting-started/bedrock-setup.md)**

### Option B: Local Ollama (Free, Offline)

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

📚 **[Full Ollama Setup Guide](00-getting-started/llm-quickstart.md)**

---

## Step 3: Index Knowledge Bases (10 minutes)

**Required for multi-agent mode** - Enables CVE correlation, MITRE ATT&CK mapping, and tool selection.

```bash
cd medusa-cli

# Index MITRE ATT&CK framework (~5 min)
python scripts/index_mitre_attack.py

# Index security tool documentation (~2 min)
python scripts/index_tool_docs.py

# Index CVE database (~3 min)
python scripts/index_cves.py

# Verify indexing
python -c "from medusa.context.vector_store import VectorStore; vs = VectorStore(); print(vs.get_stats())"
```

**Expected output:**
```
📊 Vector Store Statistics:
  • MITRE Techniques: 230
  • CVE Entries: 150
  • Tool Docs: 45
  • Total Vectors: 425
```

**Skip this step** if you only want to use single-agent mode (observe/autonomous/shell).

---

## Step 4: Run Your First Assessment (2-5 minutes)

### Option 1: Multi-Agent Assessment (Recommended)

```bash
# Full assessment with all 6 agents
medusa agent run scanme.nmap.org --type recon_only
```

**What happens:**
1. **Orchestrator** coordinates the operation
2. **Recon Agent** performs discovery
3. **Vuln Analysis Agent** correlates with CVE database
4. **Planning Agent** develops strategy
5. **Reporting Agent** generates reports

**Expected output:**

```
🤖 MEDUSA Multi-Agent System

Target: scanme.nmap.org
Operation: recon_only

Phase 1: Initialization ⚙️
  ✓ Orchestrator started (2s)
  ✓ Vector database loaded (1s) - 425 vectors
  ✓ Neo4j connected (1s)
  ✓ 6 agents initialized (1s)

Phase 2: Reconnaissance 🔍
  ✓ Port scan complete (15s) - 3 open ports
  ✓ Service detection (8s) - HTTP, SSH, MySQL
  💰 Cost: $0.03 (Haiku)

Phase 3: Vulnerability Analysis 🔎
  ✓ CVE correlation (12s) - 2 potential matches
  ✓ Risk assessment (5s) - 1 HIGH, 1 MEDIUM
  💰 Cost: $0.04 (Haiku)

Phase 4: Strategic Planning 🧠
  ✓ Attack chain developed (18s)
  ✓ MITRE ATT&CK mapping (3s)
  💰 Cost: $0.08 (Sonnet - complex reasoning)

Phase 5: Reporting 📊
  ✓ Executive summary generated (5s)
  ✓ Technical report generated (3s)
  💰 Cost: $0.02 (Haiku)

✅ Assessment complete! (2min 35s)
💰 Total Cost: $0.17
📊 Smart Routing Savings: 65%

📊 Summary:
  • Ports: 3 open
  • Services: 3 identified
  • CVE Matches: 2
  • Findings: 2 (1 HIGH, 1 MEDIUM)

📄 Reports Generated:
  • Executive: ~/.medusa/reports/exec-20251115-001.md
  • Technical: ~/.medusa/reports/tech-20251115-001.html
  • JSON: ~/.medusa/logs/multi-agent-OP-20251115-001.json

View reports: medusa agent report --type technical
```

### Option 2: Quick Reconnaissance (Single-Agent)

```bash
medusa observe --target scanme.nmap.org
```

**Lightweight, read-only mode** - No multi-agent, no exploitation:
- Port scanning
- Service enumeration
- Technology fingerprinting

Perfect for:
- Quick initial assessment
- Production environments
- Testing MEDUSA setup

### Option 3: Interactive Shell (Legacy)

```bash
medusa shell
```

Classic interactive shell with AI assistance
- Control the testing flow manually

**Example session:**

```
MEDUSA> set target http://testapp.local
✓ Target set

MEDUSA> scan network
⚡ Scanning ports 1-1000...
✓ Found 3 open ports: 80 (HTTP), 22 (SSH), 3306 (MySQL)

MEDUSA> suggestions
💡 Based on findings, you might:
  1. enumerate web paths - HTTP service detected
  2. check for SQL injection - MySQL database found
  3. test SSH authentication - SSH service open

MEDUSA> enumerate web paths
⚡ Enumerating web paths...
✓ Found 12 paths including /admin, /api, /backup

MEDUSA> show findings
📋 Current findings:
  [HIGH] Exposed admin panel at /admin
  [MEDIUM] Directory listing enabled at /backup
  [LOW] Server version disclosed in headers
```

---

## Step 4: View Results

### View Latest Report

```bash
medusa reports --open
```

Opens the HTML report in your browser showing:
- Executive summary
- Detailed findings by severity
- Remediation recommendations
- Technical details for each vulnerability

### View All Reports

```bash
medusa reports
```

Lists all generated reports with timestamps.

### View Operation Logs

```bash
medusa logs --latest
```

Shows detailed logs of the most recent operation.

---

## Step 5: View Results

### Check Operation Status

```bash
# View latest operation
medusa agent status

# Detailed view with costs
medusa agent status --verbose
```

### Generate Reports

```bash
# Executive summary (for management)
medusa agent report --type executive

# Technical report (for security team)
medusa agent report --type technical --format html

# Remediation plan (for DevOps)
medusa agent report --type remediation
```

---

## Quick Command Reference

### Multi-Agent Operations
```bash
medusa agent run <target>                    # Full assessment
medusa agent run <target> --type recon_only  # Reconnaissance
medusa agent run <target> --type vuln_scan   # Vulnerability scan
medusa agent status                          # Check status
medusa agent status --verbose                # With costs
medusa agent report --type technical         # Generate report
medusa llm verify                            # Test LLM connection
```

### Single-Agent Operations (Legacy)
```bash
medusa observe <target>                      # Read-only mode
medusa autonomous <target>                   # AI-driven mode
medusa shell                                 # Interactive shell
```

### Knowledge Base Management
```bash
python scripts/index_mitre_attack.py         # Index MITRE ATT&CK
python scripts/index_tool_docs.py            # Index tool docs
python scripts/index_cves.py                 # Index CVEs
```

---

## Common Workflows

### Workflow 1: Quick Web App Assessment

```bash
# 1. Automated scan
medusa run --target https://webapp.com --mode auto

# 2. View report
medusa reports --open

# 3. Share with team
cp ~/.medusa/reports/report-*.html /path/to/share/
```

### Workflow 2: Careful Production Testing

```bash
# 1. Start with safe reconnaissance
medusa observe https://production-app.com

# 2. Review findings, get approval

# 3. If approved, run interactive mode for controlled testing
medusa shell

MEDUSA> set target https://production-app.com
MEDUSA> scan vulnerability --level 1  # Low-intensity
```

### Workflow 3: Internal Network Scan

```bash
# 1. Scan network range
medusa run --target 192.168.1.0/24 --mode auto

# 2. Generate executive summary for management
medusa generate-report --format exec --latest

# 3. View technical report
medusa reports --type html
```

---

## Next Steps

### Learn More

- **Full Documentation:** [docs/README.md](README.md)
- **Architecture:** [docs/01-architecture/](01-architecture/)
- **Usage Examples:** [docs/04-usage/](04-usage/)
- **Troubleshooting:** [docs/00-getting-started/troubleshooting.md](00-getting-started/troubleshooting.md)

### Advanced Features

```bash
# Custom risk tolerance
medusa setup --reconfigure

# Multiple targets
medusa run --targets-file targets.txt

# CI/CD integration
medusa run --ci-mode --quiet

# Custom wordlists
medusa run --wordlist custom.txt
```

### Get Help

```bash
# CLI help
medusa --help

# Command help
medusa run --help

# Interactive help
MEDUSA> help

# Issues
https://github.com/your-org/medusa/issues
```

---

## Troubleshooting

### "medusa: command not found"

**Solution 1 (Quick):**

```bash
python3 -m medusa.cli --help
```

**Solution 2 (Permanent):**

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$(python3 -m site --user-base)/bin:$PATH"

# Reload shell
source ~/.bashrc  # or source ~/.zshrc
```

### "ModuleNotFoundError: No module named 'X'"

**Solution:**

```bash
pip install -e . --force-reinstall
```

### "Cannot connect to target"

**Causes:**
- Target is offline or unreachable
- Firewall blocking connection
- Invalid URL format

**Solution:**

```bash
# Test connectivity
ping target-host
curl http://target-host

# Try observe mode (less intrusive)
medusa observe target-host

# Check network settings
netstat -an | grep target-port
```

### "API key invalid"

**Solution:**

```bash
# Reconfigure
medusa setup --reconfigure

# Or skip AI features
medusa run --no-ai
```

### Operation times out

**Solution:**

```bash
# Increase timeout
medusa run --timeout 600  # 10 minutes

# Use slower, more reliable scan
medusa run --mode observe  # No exploitation
```

---

## Tips & Tricks

### 1. Use Observe Mode First

Always start with observe mode on new targets:

```bash
medusa observe new-target.com
```

### 2. Tab Completion in Shell

The interactive shell supports tab completion:

```bash
MEDUSA> sca<TAB>  # Completes to "scan"
MEDUSA> enu<TAB>  # Completes to "enumerate"
```

### 3. Command History

Use up/down arrows to navigate command history in shell mode.

### 4. Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+C` | Cancel current operation |
| `Ctrl+D` | Exit shell mode |
| `Ctrl+L` | Clear screen |

### 5. Background Scans

For long scans, use screen or tmux:

```bash
screen -S medusa
medusa run --target large-network.com

# Detach: Ctrl+A, D
# Reattach: screen -r medusa
```

### 6. View Configuration

```bash
cat ~/.medusa/config.yaml
```

### 7. Reset Configuration

```bash
rm ~/.medusa/config.yaml
medusa setup  # Run setup again
```

---

## Performance Tips

### For Large Networks

```bash
# Adjust thread count
medusa run --threads 10 --target 192.168.1.0/24

# Use faster scanning
medusa run --mode observe --target 192.168.1.0/24
```

### For Slow Connections

```bash
# Increase timeout
medusa run --timeout 600

# Reduce parallelism
medusa run --threads 1 --delay 100
```

### For Stealthy Testing

```bash
# Rate limit requests
medusa run --rate-limit 10

# Add delays
medusa run --delay 1000  # 1 second between requests

# Use single thread
medusa run --threads 1
```

---

## Security Reminders

⚠️ **IMPORTANT:**

1. **Only test systems you own or have written permission to test**
2. **Always start with observe mode** on unfamiliar targets
3. **Inform system administrators** before testing production systems
4. **Keep scan reports confidential** - they contain sensitive information
5. **Review findings** before sharing with others

---

## Getting Support

If you encounter issues:

1. **Check logs:** `medusa logs --latest`
2. **Review docs:** See [Troubleshooting Guide](00-getting-started/troubleshooting.md)
3. **Search issues:** https://github.com/your-org/medusa/issues
4. **Report bug:**
   - Include error message
   - Include command that failed
   - Include Python version: `python3 --version`
   - Include MEDUSA version: `medusa --version`

---

**Ready to start? Run:** `medusa setup`

For more examples and advanced usage, see [EXAMPLES.md](../04-usage/usage-examples.md)

