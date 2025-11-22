# Security Policy

Security, ethical guidelines, and risk management for MEDUSA penetration testing framework.

## Purpose

MEDUSA is designed for **authorized security testing and educational purposes only**. This document outlines the security mechanisms, ethical guidelines, and legal considerations for using MEDUSA responsibly.

---

## Approval Gates System

MEDUSA implements a multi-layered approval system to prevent accidental or unauthorized destructive actions.

### Risk Levels

All operations are categorized into four risk levels:

| Risk Level | Description | Impact | Default Behavior |
|------------|-------------|--------|------------------|
| **LOW** | Read-only operations with no system changes | No impact on target systems | Auto-approved |
| **MEDIUM** | Active testing with minimal potential impact | May trigger IDS/IPS, logs created | Prompt user for approval |
| **HIGH** | Data modification or credential extraction | May corrupt data, create accounts | Requires explicit approval |
| **CRITICAL** | Destructive or permanent changes | Data loss, system unavailability | Always requires approval |

### Risk Level Examples

**LOW Risk Operations:**
- Port scanning (`nmap -sT`)
- DNS lookups
- Service version detection
- HTTP probing
- Network discovery
- WHOIS queries

**MEDIUM Risk Operations:**
- Vulnerability scanning (`nmap -sV --script vuln`)
- SQL injection testing (read-only)
- Authentication brute-force attempts
- Web vulnerability scanning
- Directory enumeration
- Subdomain enumeration

**HIGH Risk Operations:**
- SQL injection with data extraction
- File upload exploitation
- Credential dumping
- Command injection
- Session hijacking
- Local file inclusion

**CRITICAL Risk Operations:**
- Data destruction (`DROP TABLE`, `DELETE`)
- System shutdown/reboot
- User account creation
- Privilege escalation with persistence
- Backdoor installation
- Database structure modification

### Approval Configuration

Configure approval behavior in `~/.medusa/config.yaml`:

```yaml
risk_tolerance:
  auto_approve_low: true      # Auto-approve LOW risk (recommended)
  auto_approve_medium: false  # Prompt for MEDIUM risk (recommended)
  auto_approve_high: false    # Always prompt for HIGH risk (required)
  # CRITICAL actions always prompt (hardcoded for safety)
```

**Recommended Settings:**

**Conservative (Default):**
```yaml
risk_tolerance:
  auto_approve_low: true
  auto_approve_medium: false
  auto_approve_high: false
```

**Moderate (Trusted environments):**
```yaml
risk_tolerance:
  auto_approve_low: true
  auto_approve_medium: true
  auto_approve_high: false
```

**Aggressive (Testing/development only):**
```yaml
risk_tolerance:
  auto_approve_low: true
  auto_approve_medium: true
  auto_approve_high: false  # Never auto-approve HIGH or CRITICAL
```

### Approval Prompt Example

```
┌────────────── 🟠 Approval Required ──────────────┐
│ MEDIUM RISK ACTION                               │
│                                                  │
│ Technique: T1190 (Exploit Public-Facing App)    │
│ Command: sqlmap -u http://target/api --dbs      │
│ Impact: Attempt SQL injection to enumerate      │
│         databases                                │
│ Target: http://target/api                       │
│ Data at Risk: Database credentials              │
└──────────────────────────────────────────────────┘

Approve? yes / no / skip / abort / all (approve all)
```

**User Options:**
- `yes` (y) - Approve this action
- `no` (n) - Deny this action (default)
- `skip` (s) - Skip this action, continue with others
- `abort` (a) - Abort entire operation immediately
- `all` - Approve all remaining actions (use with caution!)

### Approval Gate Implementation

**Location:** `medusa/approval.py`

**Key Classes:**

```python
class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Action:
    command: str                    # Command to execute
    technique_id: str               # MITRE ATT&CK technique ID
    technique_name: str             # Human-readable technique name
    risk_level: RiskLevel          # Risk level
    impact_description: str         # Description of potential impact
    target: Optional[str]           # Target system/URL
    reversible: bool                # Whether action is reversible
    data_at_risk: Optional[str]     # Data potentially affected
```

**Usage in Code:**

```python
from medusa.approval import ApprovalGate, Action, RiskLevel

gate = ApprovalGate()

action = Action(
    command="sqlmap -u http://target/login --dbs",
    technique_id="T1190",
    technique_name="Exploit Public-Facing Application",
    risk_level=RiskLevel.MEDIUM,
    impact_description="Attempt SQL injection to enumerate databases",
    target="http://target/login",
    reversible=True,
    data_at_risk="Database credentials"
)

if gate.request_approval(action):
    # Execute action
    execute_sqlmap(action.command)
else:
    # Action denied
    log_denied_action(action)
```

---

## Ethical Guidelines

### Authorized Use Only

MEDUSA must **only** be used in authorized scenarios:

✅ **Permitted Use:**
- Penetration testing engagements with written authorization
- Security assessments on systems you own
- Educational environments (labs, VMs, CTF challenges)
- Vulnerability research with proper disclosure
- Security training and certification prep
- Defensive security testing (blue team exercises)

❌ **Prohibited Use:**
- Testing systems without explicit written authorization
- Scanning or attacking public websites/networks
- Bypassing security controls on production systems
- Accessing data you're not authorized to view
- Distributing or selling extracted data
- Creating malware or backdoors for malicious purposes

### Legal Considerations

**Before using MEDUSA, ensure:**

1. **Written Authorization**: Obtain written permission from system owner
2. **Scope Definition**: Clearly define testing scope and boundaries
3. **Legal Compliance**: Comply with relevant laws (CFAA, GDPR, etc.)
4. **Insurance**: Consider professional liability insurance
5. **Disclosure**: Follow responsible disclosure practices

**Legal Frameworks to Consider:**
- **United States**: Computer Fraud and Abuse Act (CFAA)
- **Europe**: General Data Protection Regulation (GDPR)
- **UK**: Computer Misuse Act 1990
- **Canada**: Criminal Code Section 342.1
- **Australia**: Cybercrime Act 2001

### Responsible Disclosure

If you discover vulnerabilities using MEDUSA:

1. **Document**: Record all findings with timestamps
2. **Report**: Notify the affected party immediately
3. **Confidentiality**: Do not disclose publicly until patched
4. **Cooperation**: Work with vendor on remediation timeline
5. **Public Disclosure**: Only after vendor approval or reasonable timeframe

**Recommended Timeline:**
- Day 0: Vulnerability discovered
- Day 1-3: Vendor notification
- Day 30-90: Coordination period for patching
- Day 90+: Public disclosure (if vendor unresponsive)

---

## Target Environment Isolation

### Recommended Test Environments

**Local Docker Environment (Safest):**
```bash
# Use provided MedCare EHR target
cd medcare-ehr
docker-compose up -d

# Test only against localhost
medusa run --target http://localhost:3001
```

**Isolated Virtual Network:**
- Use VMware/VirtualBox NAT network
- No external network connectivity
- Snapshot VMs before testing
- Reset to clean state between tests

**Cloud Sandbox (AWS, Azure, GCP):**
- Isolated VPC/subnet
- No production data
- Proper tagging (e.g., "pentest-lab")
- Auto-shutdown after testing

### Network Isolation Best Practices

```yaml
# config.yaml - Restrict target scope
target:
  type: docker
  url: http://localhost:3001
  allowed_networks:
    - "127.0.0.1/8"      # Localhost only
    - "172.16.0.0/12"    # Docker networks
  blocked_networks:
    - "0.0.0.0/0"        # Block internet by default
```

**Firewall Rules:**
```bash
# Example: Block outbound traffic from test VM
iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT    # Allow internal
iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT   # Allow localhost
iptables -A OUTPUT -j DROP                     # Block everything else
```

---

## Data Handling and Privacy

### Sensitive Data

MEDUSA may extract sensitive data during testing (credentials, PII, etc.).

**Best Practices:**

1. **Minimize Collection**: Only collect data necessary for testing
2. **Encryption**: Encrypt all extracted data at rest
3. **Access Control**: Restrict access to test results
4. **Secure Deletion**: Securely delete data after testing
5. **No Production Data**: Never test with real customer data

**Configuration:**
```yaml
# config.yaml
data_handling:
  encrypt_reports: true
  encrypt_logs: true
  auto_delete_after_days: 30
  redact_credentials: true  # Redact passwords in logs
  redact_pii: true          # Redact PII in reports
```

### Log Security

**Log Locations:**
- Operation logs: `~/.medusa/logs/`
- Reports: `~/.medusa/reports/`
- Configuration: `~/.medusa/config.yaml`

**Protect Log Files:**
```bash
# Secure permissions
chmod 700 ~/.medusa/
chmod 600 ~/.medusa/config.yaml
chmod 600 ~/.medusa/logs/*.log

# Encrypt sensitive logs
gpg --encrypt ~/.medusa/logs/operation_20240115.log
```

### Report Distribution

**When sharing reports:**
- Remove or redact credentials
- Remove personally identifiable information (PII)
- Use secure channels (encrypted email, secure file sharing)
- Password-protect documents
- Watermark confidential reports

---

## Operational Security

### LLM Provider Security

**Local LLM (Ollama) - Recommended:**
- Data stays on local machine
- No external API calls
- No usage tracking
- Full privacy control

**Cloud LLM Providers (OpenAI, Anthropic, AWS Bedrock):**
- Data sent to third-party servers
- Subject to provider's privacy policy
- May be logged for quality/safety
- Consider data classification before using

**Best Practice:**
```yaml
# Use local LLM for sensitive engagements
llm:
  provider: local
  local_model: mistral:7b-instruct
```

### API Key Security

**Never commit API keys to version control:**
```bash
# .gitignore
.env
config.yaml
*.key
```

**Use environment variables:**
```bash
export CLOUD_API_KEY="sk-..."
# Do NOT store in config file
```

**Rotate keys regularly:**
- Change API keys every 30-90 days
- Immediately revoke if compromised
- Use separate keys for different engagements

---

## Audit Trail

MEDUSA maintains comprehensive audit logs.

### What is Logged

- All commands executed
- Approval decisions (approved/denied)
- LLM queries and responses
- Tool execution and results
- Errors and exceptions
- Timestamps for all actions

### Log Format

**JSON Logs** (`~/.medusa/logs/operation_YYYYMMDD_HHMMSS.json`):
```json
{
  "operation_id": "op_20240115_143022",
  "timestamp": "2024-01-15T14:30:22Z",
  "action": "execute_tool",
  "tool": "nmap",
  "command": "nmap -sV 192.168.1.10",
  "risk_level": "LOW",
  "approved": true,
  "user": "analyst@company.com",
  "result": {
    "success": true,
    "findings": [...]
  }
}
```

### Audit Review

```bash
# View operation logs
medusa logs --latest

# Search for HIGH risk actions
jq '. | select(.risk_level == "HIGH")' ~/.medusa/logs/*.json

# Find denied actions
jq '. | select(.approved == false)' ~/.medusa/logs/*.json
```

---

## Incident Response

### If Unauthorized Access Occurs

1. **Stop Immediately**: Abort operation (`abort` in approval prompt)
2. **Document**: Save all logs and evidence
3. **Notify**: Inform system owner and legal counsel
4. **Contain**: Isolate affected systems
5. **Remediate**: Assist with patching and cleanup
6. **Report**: File incident report with details

### If Data Breach Occurs

1. **Assess Scope**: Determine what data was accessed
2. **Notify Stakeholders**: Alert affected parties
3. **Legal Consultation**: Consult legal/compliance teams
4. **Regulatory Reporting**: Comply with breach notification laws (GDPR, etc.)
5. **Remediation**: Implement controls to prevent recurrence

---

## Security Hardening

### Secure MEDUSA Installation

```bash
# 1. Install in isolated environment
python3 -m venv venv-medusa
source venv-medusa/bin/activate

# 2. Install with locked dependencies
pip install -r requirements.txt --require-hashes

# 3. Verify installation
medusa --version
medusa llm verify

# 4. Secure configuration directory
chmod 700 ~/.medusa/
chmod 600 ~/.medusa/config.yaml
```

### Configuration Security Checklist

- [ ] Use local LLM for sensitive engagements
- [ ] Enable approval gates for MEDIUM+ risk
- [ ] Configure network restrictions in target scope
- [ ] Enable log encryption
- [ ] Set auto-delete for old reports (30-90 days)
- [ ] Use environment variables for API keys
- [ ] Review and update risk tolerance settings
- [ ] Enable credential/PII redaction in reports
- [ ] Restrict file permissions on `~/.medusa/`
- [ ] Use dedicated service account (not admin/root)

---

## Compliance

### Industry Standards

MEDUSA operations should align with:

- **OWASP Testing Guide** - Web application testing methodology
- **PTES (Penetration Testing Execution Standard)** - Structured testing framework
- **NIST SP 800-115** - Technical Guide to Information Security Testing
- **PCI DSS** - Payment Card Industry standards (if applicable)
- **HIPAA** - Healthcare data protection (for medical targets like MedCare EHR)

### MITRE ATT&CK Mapping

All MEDUSA techniques are mapped to MITRE ATT&CK framework:

**Example Mappings:**
- Port Scanning → T1046 (Network Service Discovery)
- SQL Injection → T1190 (Exploit Public-Facing Application)
- Credential Extraction → T1078 (Valid Accounts)
- Privilege Escalation → T1068 (Exploitation for Privilege Escalation)

**View Mappings:**
```bash
# Reports include MITRE ATT&CK technique coverage
medusa reports view operation_20240115_143022
```

---

## Training and Awareness

### Before Using MEDUSA

1. **Read Documentation**: Understand capabilities and limitations
2. **Practice in Labs**: Test in safe environments first
3. **Legal Training**: Understand relevant laws and regulations
4. **Ethics Training**: Review ethical hacking principles
5. **Obtain Authorization**: Get written permission before testing

### Recommended Certifications

- **CEH (Certified Ethical Hacker)** - Ethical hacking fundamentals
- **OSCP (Offensive Security Certified Professional)** - Hands-on pentesting
- **GPEN (GIAC Penetration Tester)** - Comprehensive pentesting skills
- **eWPT (eLearnSecurity Web Penetration Tester)** - Web app testing

---

## Disclaimer

**IMPORTANT LEGAL NOTICE:**

MEDUSA is provided "as is" for educational and authorized security testing purposes only. The developers and contributors of MEDUSA:

- Do NOT authorize or condone unauthorized access to computer systems
- Are NOT responsible for misuse or illegal use of this tool
- Assume NO liability for damages caused by use of this tool
- Provide NO warranty, express or implied

**By using MEDUSA, you agree:**
- To use it only on systems you own or have explicit written authorization to test
- To comply with all applicable local, state, national, and international laws
- To assume full legal responsibility for your actions
- To hold harmless the developers and contributors

**Violation of laws may result in:**
- Criminal prosecution
- Civil lawsuits
- Substantial fines
- Imprisonment

**Use responsibly. Test ethically. Get authorization.**

---

## Contact

For security concerns or responsible disclosure:

- **Email**: security@medusa-project.org (if available)
- **GitHub Issues**: [Report Security Issue](https://github.com/yourusername/project-medusa/issues)
- **PGP Key**: [Public Key](https://keys.openpgp.org) (for sensitive disclosures)

---

## See Also

- [CLI API Reference](../05-api-reference/cli-api.md) - Command-line interface documentation
- [Agent API Reference](../05-api-reference/agent-api.md) - Multi-agent system API
- [Deployment Guide](../03-deployment/deployment-guide.md) - Secure deployment practices
- [Troubleshooting](../00-getting-started/troubleshooting.md) - Common issues and solutions
