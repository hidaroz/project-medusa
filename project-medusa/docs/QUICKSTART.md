# MEDUSA Quick Start Guide

Get up and running with MEDUSA in 5 minutes.

## Prerequisites

- Python 3.9+
- pip (Python package manager)
- Basic understanding of penetration testing concepts

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

## Step 2: Initial Setup (1 minute)

Run the setup wizard:

```bash
medusa setup
```

You'll be prompted for:

1. **Target URL** (e.g., `http://localhost:3000` or `192.168.1.100`)
2. **Target Type** (web, api, network)
3. **API Key** (optional, for AI features)
4. **Risk Tolerance** (auto-approve low/medium/high risk actions)

**Example:**

```
Target URL: http://localhost:8080
Target Type: web
API Key: sk-proj-abc123... (press Enter to skip)
Auto-approve low risk: Yes
Auto-approve medium risk: No
Auto-approve high risk: No
```

Once setup is complete, verify with:

```bash
medusa status
```

---

## Step 3: Run Your First Scan (2 minutes)

### Option 1: Automated Scan

```bash
medusa run --target http://testapp.local --mode auto
```

This will:
1. Run reconnaissance (port scan, service detection)
2. Enumerate services (web paths, technologies)
3. Scan for vulnerabilities
4. Generate a comprehensive report

**Expected output:**

```
🔴 Starting MEDUSA Autonomous Mode

Target: http://testapp.local

Phase 1: Reconnaissance ⚡
  ✓ Port scan complete (15s) - 3 open ports
  ✓ Service detection complete (8s) - HTTP, SSH, MySQL

Phase 2: Enumeration ⚡
  ✓ Web enumeration complete (45s) - 12 paths found
  ✓ Technology detection complete (5s) - PHP 8.0, Apache 2.4

Phase 3: Vulnerability Scan ⚡
  ✓ SQL injection test complete (120s) - 1 HIGH severity
  ✓ XSS test complete (30s) - 0 findings
  ✓ Misconfiguration scan complete (60s) - 3 MEDIUM severity

✅ Scan complete! (4min 23s)

📊 Summary:
  • Total findings: 7
  • Critical: 0 | High: 1 | Medium: 3 | Low: 3
  • Report: /Users/you/.medusa/reports/report-20251106_103422.html

View report: medusa reports --open
```

### Option 2: Safe Observation Mode

```bash
medusa observe http://testapp.local
```

This performs read-only reconnaissance:
- Port scanning
- Service enumeration
- Technology fingerprinting
- **NO exploitation or vulnerability testing**

Perfect for:
- Initial assessment
- Production environments
- When you need approval before testing

### Option 3: Interactive Shell

```bash
medusa shell
```

Start an interactive shell where you can:
- Type commands in natural language
- Get AI-powered suggestions
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

