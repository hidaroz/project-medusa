# MEDUSA CLI - Complete Mode Usage Reference

Quick reference guide for all three MEDUSA CLI operating modes.

---

## 📚 Documentation Locations

- **Quick Start:** `docs/00-getting-started/cli-quickstart.md`
- **Detailed Examples:** `docs/04-usage/usage-examples.md`
- **Main README:** `medusa-cli/README.md`

---

## Mode 1: Autonomous Mode 🤖

### Purpose
Full automated penetration test with approval gates for risky actions.

### Command Syntax
```bash
# Option 1: Using --autonomous flag
medusa run --target http://localhost:3001 --autonomous

# Option 2: Using --mode flag
medusa run --target http://localhost:3001 --mode autonomous

# Option 3: Using configured default target
medusa run --autonomous
```

### What It Does
1. ✅ **Reconnaissance** - Real nmap and web scanning (REAL DATA)
2. ✅ **Enumeration** - Real API endpoint discovery (REAL DATA)
3. ⚠️ **Exploitation** - Mock exploitation attempts (MOCK DATA)
4. ⚠️ **Post-Exploitation** - Mock data exfiltration (MOCK DATA)
5. ✅ **Report Generation** - Mixed (real recon/enum, mock exploit/post)

### Approval Gates
- **LOW Risk** (reconnaissance, enumeration): Auto-approved
- **MEDIUM Risk** (exploitation): User prompt required
- **HIGH Risk** (post-exploitation): User prompt required

### Approval Options
When prompted, you can:
- `y` - Approve this action
- `n` - Deny this action
- `s` - Skip this step
- `a` - Abort entire operation
- `all` - Approve all remaining actions

### Example Output
```
Starting Autonomous Assessment against http://localhost:3001
Operation ID: auto_20251106_172852

═══ Phase 1: Reconnaissance ═══
✓ Auto-approved (LOW risk): Network Service Discovery
[████████████████████] 100% Scanning network services...
✓ Port scan: 4 open ports found

═══ Phase 2: Enumeration ═══
✓ Auto-approved (LOW risk): Gather Victim Network Information
[████████████████████] 100% Enumerating API endpoints...
✓ API enumeration: 2 endpoints found

═══ Phase 3: Exploitation ═══
⚠️  MEDIUM RISK ACTION
Approve? [y/n/s/a/all]: y
```

### Best For
- Automated security assessments
- Regular penetration testing
- When you want full automation with safety controls

### Data Reality
- ✅ Reconnaissance: REAL (nmap, web scanner)
- ✅ Enumeration: REAL (API probing, vulnerability analysis)
- ❌ Exploitation: MOCK (random/hardcoded)
- ❌ Post-Exploitation: MOCK (hardcoded)

---

## Mode 2: Interactive Mode 💻

### Purpose
Interactive REPL (Read-Eval-Print Loop) with natural language commands and full user control.

### Command Syntax
```bash
# Start interactive shell
medusa shell

# Start with target specified
medusa shell --target http://localhost:3001

# Target can be changed in shell
MEDUSA> set target http://new-target.com
```

### What It Does
- Provides command-line interface for manual control
- Natural language command parsing
- Real-time feedback on each action
- Full control over execution flow

### Built-in Commands
```
help              - Show available commands
set target <url>  - Change target URL
show context      - Display session info
show findings     - List discovered issues
clear             - Clear screen
exit/quit         - Quit shell
```

### Natural Language Commands
```
scan network              - Perform network reconnaissance
enumerate services        - Discover services and endpoints
find vulnerabilities      - Scan for security vulnerabilities
exploit sql injection     - Attempt SQL injection exploitation
exfiltrate data           - Extract sensitive data
show findings             - Display discovered issues
```

### Example Session
```
🔴 MEDUSA Interactive Shell

Target: http://localhost:3001

MEDUSA> scan network
🤖 Agent Thinking: I'll perform a network scan...
✓ Auto-approved (LOW risk): Network Service Discovery
[████████████████████] 100% Scanning network...
✓ Scan complete! Found 4 items

MEDUSA> show findings
🟠 HIGH - Unauthenticated API Access
🟠 HIGH - SQL Injection Vulnerability

MEDUSA> exit
Session ended
```

### Best For
- Learning penetration testing
- Exploring targets interactively
- When you want full control over each step
- Testing specific commands or techniques

### Data Reality
- ✅ Reconnaissance: REAL (nmap, web scanner)
- ✅ Enumeration: REAL (API probing)
- ❌ Exploitation: MOCK (random/hardcoded)
- ❌ Post-Exploitation: MOCK (hardcoded)

---

## Mode 3: Observe Mode 👁️

### Purpose
Safe reconnaissance and intelligence gathering without exploitation.

### Command Syntax
```bash
medusa observe --target http://localhost:3001
```

### What It Does
1. ✅ **Reconnaissance** - Real nmap and web scanning (REAL DATA)
2. ✅ **Enumeration** - Real API endpoint discovery (REAL DATA)
3. ✅ **Vulnerability Assessment** - Real vulnerability identification (REAL DATA)
4. ✅ **Attack Plan Generation** - Creates attack strategy (NOT EXECUTED)
5. ✅ **Intelligence Report** - Comprehensive report without exploitation

### Key Feature
**NO EXPLOITATION** - Completely safe for initial assessment

### Example Output
```
Starting Observation Mode against http://localhost:3001
Reconnaissance only - no exploitation will be performed

═══ Phase 1: Passive Reconnaissance ═══
[████████████████████] 100% Passive reconnaissance...
✓ DNS resolution: Target resolved
✓ Service detection: 3 services detected

═══ Phase 2: Active Enumeration ═══
[████████████████████] 100% Active enumeration...
✓ API endpoint discovery: 2 endpoints found

═══ Phase 3: Vulnerability Assessment ═══
Identified 5 potential vulnerabilities:
🟠 HIGH - Unauthenticated API Access
🟠 HIGH - SQL Injection Vulnerability

═══ Phase 4: Attack Plan Generation ═══
Recommended Attack Strategy:
1. Exploit SQL Injection (Confidence: 85%)
2. Enumerate Databases (Confidence: 92%)

Note: Attack plan generated but NOT executed.
Use autonomous mode to execute.
```

### Best For
- Initial security assessment
- Safe reconnaissance on new targets
- Understanding attack surface without risk
- Compliance and audit purposes
- When exploitation is not authorized

### Data Reality
- ✅ Reconnaissance: REAL (nmap, web scanner)
- ✅ Enumeration: REAL (API probing, vulnerability analysis)
- ✅ Vulnerability Assessment: REAL (based on actual findings)
- ❌ Exploitation: N/A (not performed)
- ❌ Post-Exploitation: N/A (not performed)

---

## Quick Comparison Table

| Feature | Autonomous | Interactive | Observe |
|---------|-----------|-------------|---------|
| **Command** | `medusa run --autonomous` | `medusa shell` | `medusa observe` |
| **Reconnaissance** | ✅ Real | ✅ Real | ✅ Real |
| **Enumeration** | ✅ Real | ✅ Real | ✅ Real |
| **Exploitation** | ⚠️ Mock | ⚠️ Mock | ❌ None |
| **Post-Exploitation** | ⚠️ Mock | ⚠️ Mock | ❌ None |
| **User Control** | Limited | Full | N/A |
| **Approval Gates** | ✅ Yes | ✅ Yes | N/A |
| **Report Generation** | ✅ Auto | Manual | ✅ Auto |
| **Best For** | Automated testing | Learning/exploration | Initial assessment |
| **Risk Level** | Medium | Low | None |

---

## Common Workflows

### Workflow 1: Safe Initial Assessment
```bash
# Step 1: Safe reconnaissance
medusa observe --target http://target.com

# Step 2: Review findings
medusa reports --open

# Step 3: If comfortable, run full test
medusa run --target http://target.com --autonomous
```

### Workflow 2: Interactive Exploration
```bash
# Start interactive shell
medusa shell --target http://target.com

# Explore interactively
MEDUSA> scan network
MEDUSA> enumerate services
MEDUSA> show findings
MEDUSA> exploit sql injection  # Will prompt for approval
MEDUSA> exit
```

### Workflow 3: Automated Regular Testing
```bash
# Run autonomous mode (uses configured target)
medusa run --autonomous

# Review reports
medusa reports --open
```

---

## Configuration

### Risk Tolerance Settings
Edit `~/.medusa/config.yaml`:

```yaml
risk_tolerance:
  auto_approve_low: true      # Recon always runs
  auto_approve_medium: false  # Change to true for faster testing
  auto_approve_high: false    # Keep false for safety
```

### Default Target
```yaml
target:
  type: api
  url: http://localhost:3001
```

Then run without `--target`:
```bash
medusa run --autonomous  # Uses configured target
```

---

## Report Management

### View Reports
```bash
# List all reports
medusa reports

# Open latest report
medusa reports --open

# Filter by type
medusa reports --type html
medusa reports --type exec
medusa reports --type md
```

### View Logs
```bash
# Show latest log
medusa logs --latest

# Show all logs
medusa logs
```

---

## Important Notes

### ⚠️ Data Reality Warning

**Real Data:**
- ✅ Reconnaissance phase (nmap, web scanner)
- ✅ Enumeration phase (API probing, vulnerability analysis)

**Mock Data:**
- ❌ Exploitation phase (random/hardcoded results)
- ❌ Post-exploitation phase (hardcoded data)
- ❌ Final report summary (may contain mock data)

**See:** `docs/08-project-management/data-reality-analysis.md` for detailed analysis.

### Safety Reminders

1. ⚠️ **Only test systems you own or have permission to test**
2. 🛡️ Start with `observe` mode for new targets
3. 🚨 Press `Ctrl+C` to abort at any time
4. 📝 Review reports to understand what was done
5. 🔒 Never use on production systems without approval

---

## Troubleshooting

### "MEDUSA is not configured"
```bash
medusa setup
```

### "No API key found"
```bash
medusa setup --force
```

### "Target not reachable"
```bash
# Check if target is running
curl http://localhost:3001/health

# For Docker environment
docker ps
```

### Command not found: medusa
```bash
# Reinstall
cd medusa-cli
pip install -e .

# Or check installation
pip list | grep medusa
```

---

## Additional Resources

- **Quick Start:** `docs/00-getting-started/cli-quickstart.md`
- **Usage Examples:** `docs/04-usage/usage-examples.md`
- **Data Reality Analysis:** `docs/08-project-management/data-reality-analysis.md`
- **Main README:** `medusa-cli/README.md`

---

**Last Updated:** November 6, 2025

