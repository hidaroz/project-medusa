# MEDUSA Usage Examples

Quick reference guide for common MEDUSA operations.

## Installation & Setup

### Install from PyPI
```bash
pip install medusa-pentest
medusa setup
```

### Install from Source
```bash
git clone https://github.com/medusa-security/medusa-cli
cd medusa-cli
pip install -e .
medusa setup
```

### Setup Wizard Flow
```bash
$ medusa setup

╔══════════════════════════════════════╗
║   MEDUSA Setup Wizard                ║
╚══════════════════════════════════════╝

[1/4] Gemini API Key
Enter your Google AI API key: ****************************
✓ API key validated

[2/4] Target Environment
Do you want to test against:
  1. Local Docker environment (recommended for learning)
  2. Your own infrastructure
Choice [1]: 1
✓ Docker environment selected

[3/4] Risk Tolerance
Auto-approve actions rated as:
  - LOW risk (reconnaissance, safe commands) [y/n]: y
  - MEDIUM risk (exploitation attempts) [y/n]: n
  - HIGH risk (data destruction, persistence) [y/n]: n
✓ Risk settings saved

[4/4] Docker Setup
Setting up vulnerable test environment...
[████████████████████] 100% Complete

✓ Setup complete! Try: medusa run --help
```

---

## Mode 1: Autonomous

Full automated penetration test with approval gates.

### Basic Run
```bash
medusa run --target http://localhost:3001 --autonomous
```

### Expected Flow
```
🔴 MEDUSA - AI-Powered Penetration Testing

Starting Autonomous Assessment against http://localhost:3001
Operation ID: auto_20240129_143022

═══ Phase 1: Reconnaissance ═══

✓ Auto-approved (LOW risk): Network Service Discovery

🤖 Agent Thinking:
Initiating reconnaissance to map the attack surface.
I'll identify open ports, running services, and potential entry points.

[████████████████████] 100% Scanning network services...

Reconnaissance Phase
├─ ✓ Port scan: 3 open ports found
├─ ✓ Service enumeration: Identified web application
└─ ✓ Technology detection: React + Node.js detected


═══ Phase 2: Enumeration ═══

✓ Auto-approved (LOW risk): Gather Victim Network Information

🤖 Agent Thinking:
Analyzing the target application to identify API endpoints,
authentication mechanisms, and potential vulnerabilities.

[████████████████████] 100% Enumerating API endpoints...

Enumeration Phase
├─ ✓ API enumeration: 2 endpoints found
├─ ✓ Vulnerability scan: 1 vulnerabilities detected
└─ ✓ Configuration audit: Security misconfigurations identified

🟠 HIGH - Unauthenticated API Access
Critical API endpoints accessible without authentication

🟠 HIGH - SQL Injection Vulnerability
User input not properly sanitized in database queries


═══ Phase 3: Exploitation ═══

⚠️  MEDIUM RISK ACTION

Technique: T1190 (Exploit Public-Facing Application)
Command: sqlmap -u http://target/api --dbs
Impact: Attempt exploitation of identified vulnerabilities. May trigger security alerts.

Approve? [y/n/s/a/all]: y
✓ Approved

🤖 Agent Thinking:
Attempting to exploit 1 identified vulnerabilities.
I'll prioritize high-severity issues and attempt to gain unauthorized access.

[████████████████████] 100% Attempting exploitation...

✓ Exploitation Successful
Successfully exploited vulnerability! Gained database_read access.

Exploitation Phase
├─ ✓ Vulnerability exploitation: Access gained
├─ ✓ Data extraction: 150 records extracted
└─ ✓ Credential discovery: 3 credentials found


═══ Phase 4: Post-Exploitation ═══

⚠️  HIGH RISK ACTION

Technique: T1041 (Exfiltration Over C2 Channel)
Command: Exfiltrate patient medical records
Impact: Extract sensitive data from compromised system. May leave forensic traces.
Data at Risk: Patient medical records, PII, financial data

Approve? [y/n/s/a/all]: y
✓ Approved

🤖 Agent Thinking:
With access gained, I'll now attempt to exfiltrate sensitive data
to demonstrate the impact of the vulnerability.

[████████████████████] 100% Exfiltrating data...

Post-Exploitation Phase
├─ ✓ Data exfiltration: 2000 records exfiltrated
└─ ✓ Value assessment: Estimated value: $3,000,000


═══ Generating Reports ═══

✓ JSON log saved: /Users/you/.medusa/logs/run-20240129_143022-auto_001.json
✓ HTML report saved: /Users/you/.medusa/reports/report-20240129_143022-auto_001.html

MITRE ATT&CK Coverage:
T1046 - Network Service Discovery        ✓ Executed
T1590 - Gather Victim Network Information ✓ Executed
T1592 - Gather Victim Host Information    ✓ Executed
T1190 - Exploit Public-Facing Application ✓ Executed
T1041 - Exfiltration Over C2 Channel      ✓ Executed

Operation Summary:
  Total Findings: 12
  Critical: 0
  High: 3
  Medium: 5
  Low: 4
  Techniques Used: 8
  Success Rate: 75.0%

✓ Assessment complete! Total duration: 235.6s
```

---

## Mode 2: Interactive Shell

Interactive REPL with natural language commands.

### Start Shell
```bash
medusa shell
```

### Example Session
```
🔴 MEDUSA Interactive Shell

Enter natural language commands to control the agent.
Type 'help' for available commands or 'exit' to quit.

Target: http://localhost:3001


MEDUSA> help

Available Commands:

Built-in Commands:
  help                    - Show this help message
  set target <url>        - Set the target URL
  show context            - Display current session context
  show findings           - Display discovered findings
  clear                   - Clear the screen
  exit/quit               - Exit the shell

Natural Language Commands (examples):
  scan network            - Perform network reconnaissance
  enumerate services      - Discover services and endpoints
  find vulnerabilities    - Scan for security vulnerabilities
  exploit sql injection   - Attempt SQL injection exploitation
  exfiltrate data         - Extract sensitive data


MEDUSA> scan network

🤖 Agent Thinking:
I'll perform a network scan to identify open ports and running services.

✓ Auto-approved (LOW risk): Network Service Discovery

[████████████████████] 100% Scanning network...

✓ Scan complete! Found 4 items

🔵 INFO - Open Port: 80 (http/nginx 1.21.0)
🔵 INFO - Open Port: 443 (https/nginx 1.21.0)
🔵 INFO - Open Port: 3001 (http/Node.js Express)
🔵 INFO - Web Application: MedCare EHR System


MEDUSA> enumerate services

🤖 Agent Thinking:
I'll enumerate API endpoints and identify potential vulnerabilities.

✓ Auto-approved (LOW risk): Gather Victim Network Information

[████████████████████] 100% Enumerating services...

✓ Enumeration complete! Found 5 items

🟡 MEDIUM - Unauthenticated API Endpoint
Patient data endpoint accessible without authentication

🟠 HIGH - Employee Data Exposure
Employee credentials exposed via unauthenticated endpoint


MEDUSA> show findings

🟠 HIGH - Unauthenticated API Access
Critical API endpoints accessible without authentication

🟠 HIGH - Employee Data Exposure
Employee credentials exposed via unauthenticated endpoint

🟠 HIGH - SQL Injection Vulnerability
Possible SQL injection in search parameter


MEDUSA> exploit sql injection

🤖 Agent Thinking:
Attempting to exploit vulnerability based on command: exploit sql injection

⚠️  MEDIUM RISK ACTION

Technique: T1190 (Exploit Public-Facing Application)
Command: exploit sql injection
Impact: Attempt to exploit identified vulnerability

Approve? [y/n/s/a/all]: y
✓ Approved

[████████████████████] 100% Attempting exploitation...

✓ Exploitation successful!
Access gained: database_read


MEDUSA> show context

Session Context:
  Target: http://localhost:3001
  Session Started: 2024-01-29T14:30:22
  Findings: 8
  Techniques Used: 4


MEDUSA> exit

Session ended
```

---

## Mode 3: Observe

Reconnaissance only - no exploitation.

### Run Observe Mode
```bash
medusa observe --target http://localhost:3001
```

### Expected Output
```
🔴 MEDUSA - AI-Powered Penetration Testing

Starting Observation Mode against http://localhost:3001
Reconnaissance only - no exploitation will be performed

Operation ID: observe_20240129_150000


═══ Phase 1: Passive Reconnaissance ═══

🤖 Agent Thinking:
Performing passive reconnaissance with minimal detection footprint.
I'm gathering publicly available information about the target.

[████████████████████] 100% Passive reconnaissance...

Passive Reconnaissance
├─ ✓ DNS resolution: Target resolved
├─ ✓ Service detection: 3 services detected
└─ ✓ Technology fingerprinting: Web stack identified


═══ Phase 2: Active Enumeration ═══

🤖 Agent Thinking:
Actively probing the target to identify API endpoints,
authentication mechanisms, and potential attack vectors.

[████████████████████] 100% Active enumeration...

Active Enumeration
├─ ✓ API endpoint discovery: 2 endpoints found
├─ ✓ Authentication analysis: Unauthenticated endpoints identified
└─ ✓ Input validation testing: Potential injection points found


═══ Phase 3: Vulnerability Assessment ═══

🤖 Agent Thinking:
Analyzing identified weaknesses and assessing their severity.
No exploitation attempts will be made.

Identified 5 potential vulnerabilities:

🟠 HIGH - Unauthenticated API Access
🟠 HIGH - Employee Data Exposure
🟠 HIGH - SQL Injection Vulnerability
🟡 MEDIUM - CORS Misconfiguration
🔵 LOW - Server Version Disclosure

Vulnerability Summary:
  Critical: 0
  High: 3
  Medium: 1
  Low: 1
  Info: 0


═══ Phase 4: Attack Plan Generation ═══

🤖 Agent Thinking:
Based on the gathered intelligence, I'm formulating an attack strategy.
This plan will NOT be executed in observe mode.

Recommended Attack Strategy:

1. Exploit Sql Injection
   Confidence: 85%
   Reasoning: Detected SQL injection vulnerability with high success probability
   Risk Level: MEDIUM

2. Enumerate Databases
   Confidence: 92%
   Reasoning: Successful authentication allows database enumeration
   Risk Level: LOW


═══ Generating Intelligence Report ═══

✓ Intelligence log saved: /Users/you/.medusa/logs/run-20240129_150000-observe_001.json
✓ Intelligence report saved: /Users/you/.medusa/reports/report-20240129_150000-observe_001.html

Intelligence Summary:
  Total Findings: 5
  Critical: 0
  High: 3
  Medium: 1
  Low: 1
  Techniques Used: 2
  Success Rate: 100.0%

✓ Observation complete! Duration: 45.2s

Note: Attack plan generated but NOT executed. Use autonomous mode to execute.
```

---

## View Reports

### List Reports
```bash
medusa reports

Available Reports:

  • report-20240129_143022-auto_001.html
  • report-20240129_145633-auto_002.html
  • report-20240129_150000-observe_001.html

Location: /Users/you/.medusa/reports

Tip: Use --open to view latest report
```

### Open Latest Report
```bash
medusa reports --open
```

This opens the HTML report in your browser with:
- Executive summary
- Vulnerability details with CVSS scores
- MITRE ATT&CK coverage
- Phase breakdown
- Remediation recommendations

---

## View Logs

### Show Latest Log
```bash
medusa logs --latest

Log: run-20240129_143022-auto_001.json
Path: /Users/you/.medusa/logs/run-20240129_143022-auto_001.json

Operation ID: auto_20240129_143022
Timestamp: 2024-01-29T14:30:22
Duration: 235.6s
Total Findings: 12
```

### Show All Logs
```bash
medusa logs
```

---

## Check Status

```bash
medusa status

MEDUSA Status

Configuration:
  Version: 1.0.0
  Config Path: /Users/you/.medusa/config.yaml
  Logs Directory: /Users/you/.medusa/logs
  Reports Directory: /Users/you/.medusa/reports
  Target: http://localhost:3001
  Target Type: docker
  API Key: Configured

Risk Tolerance:
  Auto-approve LOW risk: Yes
  Auto-approve MEDIUM risk: No
  Auto-approve HIGH risk: No
```

---

## Tips & Tricks

### 1. Quick Assessment
```bash
# Fast recon without exploitation
medusa observe --target http://target.com
medusa reports --open
```

### 2. Batch Testing
```bash
# Test multiple targets
for target in target1.com target2.com target3.com; do
  medusa observe --target "http://$target"
done
```

### 3. Custom Risk Levels
Edit `~/.medusa/config.yaml`:
```yaml
risk_tolerance:
  auto_approve_low: true
  auto_approve_medium: true  # Enable for faster testing
  auto_approve_high: false
```

### 4. Emergency Abort
Press `Ctrl+C` at any time to abort the operation.

### 5. Review Before Executing
Always run `observe` mode first to see what will happen:
```bash
# 1. Observe
medusa observe --target http://new-target.com

# 2. Review findings
medusa reports --open

# 3. Execute if comfortable
medusa run --target http://new-target.com --autonomous
```

---

## Common Issues

### API Key Not Found
```bash
# Check configuration
medusa status

# Re-run setup
medusa setup --force
```

### Target Not Reachable
```bash
# Verify target is up
curl http://localhost:3001/health

# Check Docker containers
docker ps
```

### Permission Denied
```bash
# Check file permissions
ls -la ~/.medusa/

# Fix if needed
chmod 600 ~/.medusa/config.yaml
```

---

## Next Steps

1. **Learn More**: Read the full [README](README.md)
2. **Report Issues**: [GitHub Issues](https://github.com/medusa-security/medusa-cli/issues)
3. **Contribute**: [Contributing Guidelines](CONTRIBUTING.md)
4. **Get Help**: [Documentation](https://docs.medusa.dev)

---

**Happy (ethical) hacking! 🔴**

