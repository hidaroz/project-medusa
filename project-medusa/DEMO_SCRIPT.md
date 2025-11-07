# MEDUSA Demo Presentation Script
## AI-Powered Penetration Testing on Vulnerable EHR System

**Duration:** 30-45 minutes  
**Audience:** 3-person demo team  
**Setup:** 2 attackers (MEDUSA users) + 1 defender (EHR system narrator)

---

## 🎯 Demo Overview

This demo showcases MEDUSA's AI-powered penetration testing capabilities against a vulnerable healthcare EHR system. The demo is structured to demonstrate:

1. **Reconnaissance** - Network scanning and service discovery
2. **Enumeration** - API endpoint discovery and vulnerability identification
3. **Exploitation** - SQL injection, credential access, lateral movement
4. **Post-Exploitation** - Data exfiltration and persistence
5. **Reporting** - Comprehensive security assessment reports

---

## 👥 Team Roles

### **Attacker 1** (Primary MEDUSA Operator)
- Runs MEDUSA commands
- Demonstrates autonomous and interactive modes
- Explains MEDUSA's AI decision-making

### **Attacker 2** (Secondary Operator)
- Runs parallel reconnaissance
- Demonstrates observe mode
- Shows report generation

### **Defender** (EHR System Narrator)
- Explains the vulnerable EHR system architecture
- Describes vulnerabilities as they're discovered
- Provides context on healthcare security implications

---

## 📋 Pre-Demo Checklist

### Environment Setup

```bash
# 1. Start the vulnerable EHR lab environment
cd lab-environment
docker-compose up -d

# 2. Verify all services are running
docker-compose ps

# Expected output: 8 services running
# - ehr-webapp (port 8080)
# - ehr-api (port 3001)
# - ehr-database (port 3306)
# - ssh-server (port 2222)
# - file-server (port 21)
# - ldap-server (port 389)
# - log-collector (port 8081)
# - workstation (port 445)

# 3. Verify services are accessible
curl http://localhost:8080  # EHR Web Portal
curl http://localhost:3001/api/health  # EHR API

# 4. Check MEDUSA installation
medusa status

# 5. Verify MEDUSA configuration
cat ~/.medusa/config.yaml
```

### Pre-Demo Verification Commands

```bash
# Test network connectivity
nmap -p 8080,3001,3306,2222,21,389,8081 localhost

# Verify database is accessible
mysql -h localhost -P 3306 -u root -padmin123 -e "SHOW DATABASES;"

# Check SSH access
ssh -o StrictHostKeyChecking=no admin@localhost -p 2222 "echo 'SSH OK'"

# Verify FTP access
echo "quit" | ftp localhost 21
```

---

## 🎬 Demo Script

### **Phase 1: Introduction & Environment Overview** (5 minutes)

#### Defender Introduction

**Defender:** "Welcome to the MEDUSA demo. Today we'll demonstrate AI-powered penetration testing against a vulnerable healthcare EHR system. This lab environment simulates a real-world healthcare network with 8 intentionally vulnerable services."

**Key Points to Mention:**
- **EHR Web Portal** (port 8080) - Patient portal with SQL injection and XSS
- **EHR API** (port 3001) - REST API with missing authentication
- **MySQL Database** (port 3306) - Contains patient data with weak credentials
- **SSH Server** (port 2222) - Linux server with weak passwords
- **FTP Server** (port 21) - File server with anonymous access
- **LDAP Server** (port 389) - Directory service with anonymous bind
- **Log Collector** (port 8081) - Centralized logging
- **Workstation** (port 445) - SMB shares with weak permissions

**Defender:** "All services contain intentional vulnerabilities for educational purposes. This is a controlled, isolated environment."

---

### **Phase 2: Initial Reconnaissance** (5 minutes)

#### Attacker 1: Observe Mode (Safe Reconnaissance)

**Attacker 1:** "Let's start with MEDUSA's Observe mode - this performs safe reconnaissance without exploitation."

```bash
# Command 1: Safe reconnaissance
medusa observe --target http://localhost:3001
```

**Expected Output:**
- Network service discovery
- API endpoint enumeration
- Vulnerability identification
- Attack plan generation (not executed)

**Attacker 1:** "Observe mode is perfect for initial assessment. It gathers intelligence without any risk of exploitation."

#### Attacker 2: Parallel Network Scan

**Attacker 2:** "While Attacker 1 runs observe mode, I'll demonstrate MEDUSA's network scanning capabilities."

```bash
# Command 2: Network scan using MEDUSA's tools
medusa shell --target http://localhost:3001

# In the shell:
MEDUSA> scan network
MEDUSA> enumerate services
MEDUSA> show findings
MEDUSA> exit
```

**Expected Findings:**
- Port 8080: HTTP (EHR Web Portal)
- Port 3001: HTTP (EHR API)
- Port 3306: MySQL Database
- Port 2222: SSH Server
- Port 21: FTP Server
- Port 389: LDAP Server

**Defender:** "MEDUSA has discovered our entire network topology. In a real attack, this reconnaissance phase would map out the entire attack surface."

---

### **Phase 3: API Enumeration & Vulnerability Discovery** (7 minutes)

#### Attacker 1: Interactive Mode - API Discovery

**Attacker 1:** "Now let's use interactive mode to explore the EHR API in detail."

```bash
# Command 3: Start interactive shell
medusa shell --target http://localhost:3001

# In the shell:
MEDUSA> enumerate API endpoints
```

**Expected Output:**
- `/api/patients` - Patient data endpoint
- `/api/health` - Health check
- `/api/users` - User management
- `/api/records` - Medical records

**Attacker 1:** "MEDUSA's AI has identified multiple API endpoints. Let's check for authentication."

```bash
MEDUSA> test for authentication bypass
```

**Expected Finding:**
- Missing authentication on `/api/patients`
- Weak JWT secret detected

**Defender:** "This is a critical vulnerability. The API lacks proper authentication, allowing unauthorized access to patient data - a HIPAA violation."

#### Attacker 2: Web Portal Analysis

**Attacker 2:** "Let me analyze the web portal for vulnerabilities."

```bash
# Command 4: Web portal scanning
medusa shell --target http://localhost:8080

MEDUSA> scan for SQL injection
MEDUSA> test for XSS vulnerabilities
MEDUSA> check for IDOR vulnerabilities
```

**Expected Findings:**
- SQL Injection in login form
- SQL Injection in patient search
- XSS in patient notes
- IDOR in patient record access

**Defender:** "The web portal has multiple OWASP Top 10 vulnerabilities. SQL injection could allow complete database compromise."

---

### **Phase 4: Exploitation - SQL Injection** (8 minutes)

#### Attacker 1: Autonomous Mode - SQL Injection Exploitation

**Attacker 1:** "Now let's demonstrate autonomous mode with approval gates. MEDUSA will plan and execute attacks with our approval."

```bash
# Command 5: Autonomous mode with target
medusa run --target http://localhost:8080 --autonomous
```

**Expected Flow:**
1. **Phase 1: Reconnaissance** (Auto-approved - LOW risk)
   - Network scanning
   - Service enumeration
   - Vulnerability identification

2. **Phase 2: Enumeration** (Auto-approved - LOW risk)
   - API endpoint discovery
   - Database schema enumeration
   - User enumeration

3. **Phase 3: Exploitation** (Requires approval - MEDIUM risk)
   ```
   ⚠️  MEDIUM RISK ACTION
   
   Technique: T1190 (Exploit Public-Facing Application)
   Action: SQL Injection Exploitation
   Target: http://localhost:8080/search.php
   Impact: Extract database information
   
   Approve? [y/n/s/a/all]: y
   ```

**Attacker 1:** "MEDUSA is requesting approval for SQL injection. This demonstrates the approval gate system - risky actions require explicit consent."

**After Approval:**
- SQL injection payload execution
- Database enumeration
- Table discovery (users, patients, medical_records)
- Credential extraction

**Defender:** "MEDUSA has successfully exploited SQL injection and extracted database credentials. In our database, we store plaintext passwords in the comments table - another critical vulnerability."

#### Attacker 2: Database Access

**Attacker 2:** "With the extracted credentials, let's access the database directly."

```bash
# Command 6: Direct database access
mysql -h localhost -P 3306 -u root -padmin123 healthcare_db

# In MySQL:
mysql> SHOW TABLES;
mysql> SELECT * FROM comments WHERE plaintext_credential IS NOT NULL LIMIT 5;
mysql> SELECT username, password_hash FROM users LIMIT 5;
mysql> SELECT COUNT(*) FROM patients;
mysql> SELECT ssn FROM patients LIMIT 3;
mysql> exit;
```

**Expected Output:**
- Plaintext credentials (FTP, LDAP, SSH passwords)
- MD5 password hashes (crackable)
- Patient SSNs (HIPAA violation)
- Medical records count

**Defender:** "MEDUSA has accessed our database and found plaintext credentials. This demonstrates the severity of SQL injection - it can lead to complete system compromise."

---

### **Phase 5: Lateral Movement** (7 minutes)

#### Attacker 1: SSH Access Using Extracted Credentials

**Attacker 1:** "Using the credentials extracted from the database, let's pivot to the SSH server."

```bash
# Command 7: SSH access
ssh admin@localhost -p 2222
# Password: admin2024 (extracted from database)

# Once connected:
whoami
pwd
ls -la
cat .bash_history | grep -i password
sudo -l
```

**Expected Findings:**
- Sudo misconfigurations (NOPASSWD on vim, find, python3)
- Exposed private keys
- Command history with credentials
- Sensitive config files

**Defender:** "MEDUSA has gained SSH access and discovered privilege escalation opportunities through sudo misconfigurations."

#### Attacker 2: FTP Access & Data Exfiltration

**Attacker 2:** "Let's also access the FTP server using extracted credentials."

```bash
# Command 8: FTP access
ftp localhost 21
# Username: fileadmin
# Password: Files2024! (from database)

# In FTP:
ftp> ls
ftp> cd medical_records
ftp> ls
ftp> get patient_backup_2024.sql
ftp> quit
```

**Expected Output:**
- Anonymous FTP access available
- Medical records backup files
- Patient data exports

**Defender:** "FTP access reveals medical record backups. This demonstrates how one vulnerability can lead to multiple attack vectors."

---

### **Phase 6: Post-Exploitation & Data Exfiltration** (5 minutes)

#### Attacker 1: Comprehensive Data Collection

**Attacker 1:** "Let's demonstrate MEDUSA's post-exploitation capabilities."

```bash
# Command 9: Continue autonomous mode
# (If still running, approve post-exploitation actions)

# Or use interactive mode:
medusa shell --target http://localhost:8080

MEDUSA> exfiltrate patient data
MEDUSA> enumerate all credentials
MEDUSA> check for persistence mechanisms
```

**Expected Actions:**
- Patient data extraction
- Credential harvesting
- Persistence mechanism identification
- Network mapping

**Defender:** "MEDUSA has demonstrated a complete attack chain: initial access → privilege escalation → lateral movement → data exfiltration."

---

### **Phase 7: Report Generation & Analysis** (5 minutes)

#### Attacker 1: Generate Comprehensive Report

**Attacker 1:** "MEDUSA automatically generates comprehensive reports after each assessment."

```bash
# Command 10: View reports
medusa reports

# Command 11: Open latest report
medusa reports --open

# Command 12: View operation logs
medusa logs --latest

# Command 13: Generate additional report formats
medusa generate-report --type all
```

**Report Contents:**
- Executive summary
- Technical findings
- MITRE ATT&CK mapping
- Risk ratings (LOW/MEDIUM/HIGH/CRITICAL)
- Remediation recommendations
- Attack timeline
- CVSS scores

**Attacker 2: Show Report Statistics**

```bash
# Command 14: Report summary
medusa reports --summary

# Command 15: Filter logs
medusa logs --type autonomous --summary
```

**Defender:** "MEDUSA's reporting provides actionable intelligence for security teams. The reports include MITRE ATT&CK mappings, which help defenders understand attack techniques."

---

### **Phase 8: Advanced Features** (5 minutes)

#### Attacker 1: Graph Integration & Attack Visualization

**Attacker 1:** "MEDUSA can visualize attack paths using graph databases."

```bash
# Command 16: Check graph integration
medusa shell

MEDUSA> show attack graph
MEDUSA> visualize attack path
```

**Expected Output:**
- Attack path visualization
- Service relationships
- Data flow mapping

#### Attacker 2: Multiple Target Assessment

**Attacker 2:** "MEDUSA can assess multiple targets simultaneously."

```bash
# Command 17: Assess multiple services
medusa observe --target http://localhost:8080
medusa observe --target http://localhost:3001
medusa observe --target http://localhost:8081
```

**Defender:** "This demonstrates MEDUSA's scalability - it can assess entire networks, not just single targets."

---

## 🎯 Key Demo Points to Emphasize

### MEDUSA Capabilities Demonstrated

1. **AI-Powered Decision Making**
   - Natural language command interpretation
   - Context-aware vulnerability assessment
   - Intelligent attack planning

2. **Safety Features**
   - Approval gates for risky actions
   - Risk-based classification (LOW/MEDIUM/HIGH/CRITICAL)
   - Emergency abort capability

3. **Comprehensive Reporting**
   - Multiple report formats (HTML, Markdown, PDF)
   - MITRE ATT&CK mapping
   - Executive and technical summaries

4. **Multiple Operating Modes**
   - Observe mode (safe reconnaissance)
   - Autonomous mode (AI-driven with approval)
   - Interactive mode (full user control)

5. **Tool Integration**
   - Nmap for network scanning
   - Custom SQL injection testing
   - API endpoint enumeration
   - Web vulnerability scanning

---

## 📊 Expected Findings Summary

### Critical Vulnerabilities Found

| Vulnerability | Service | Impact | CVSS |
|--------------|---------|--------|------|
| SQL Injection | EHR Web Portal | Database compromise | 9.8 |
| Missing Authentication | EHR API | Unauthorized data access | 9.1 |
| Weak Database Credentials | MySQL | Full database access | 9.8 |
| Plaintext Credentials | Database | Complete system compromise | 9.6 |
| Weak SSH Credentials | SSH Server | Server access | 9.8 |
| Anonymous FTP | FTP Server | Data exfiltration | 8.2 |

### Attack Chain Demonstrated

1. **Initial Access** → SQL Injection on web portal
2. **Credential Access** → Database credential extraction
3. **Lateral Movement** → SSH and FTP access
4. **Collection** → Patient data exfiltration
5. **Impact** → Complete system compromise

---

## 🛡️ Post-Demo Cleanup

### Reset Environment

```bash
# Stop all containers
cd lab-environment
docker-compose down

# Remove all data (optional - for clean reset)
docker-compose down -v

# Restart for next demo
docker-compose up -d
```

### Clear MEDUSA Logs (Optional)

```bash
# View log directory
ls ~/.medusa/logs/

# Remove logs if needed (optional)
rm ~/.medusa/logs/*.json
```

---

## 🎤 Talking Points for Each Role

### Attacker 1 (Primary Operator)

**Key Messages:**
- "MEDUSA uses AI to intelligently plan attacks"
- "Approval gates ensure we maintain control"
- "The system adapts based on discovered vulnerabilities"
- "Reports provide actionable intelligence"

**Technical Highlights:**
- Natural language command interpretation
- Risk-based approval system
- Comprehensive tool integration
- MITRE ATT&CK mapping

### Attacker 2 (Secondary Operator)

**Key Messages:**
- "MEDUSA can run multiple assessments in parallel"
- "Observe mode provides safe reconnaissance"
- "The system scales to assess entire networks"
- "Graph visualization shows attack relationships"

**Technical Highlights:**
- Parallel reconnaissance
- Safe assessment modes
- Network-wide scanning
- Attack path visualization

### Defender (EHR Narrator)

**Key Messages:**
- "These vulnerabilities are common in healthcare systems"
- "SQL injection can lead to HIPAA violations"
- "Weak credentials are a critical security issue"
- "Defense-in-depth is essential"

**Security Context:**
- Healthcare compliance (HIPAA)
- Patient data protection
- Network segmentation importance
- Defense-in-depth strategies

---

## ⚠️ Important Notes

### Safety Reminders

1. **This is a controlled environment** - All vulnerabilities are intentional
2. **Never expose to internet** - Lab environment only
3. **Reset after demo** - Clean environment for next presentation
4. **Document findings** - Use reports for learning

### Demo Timing

- **Total Duration:** 30-45 minutes
- **Phase 1:** 5 min (Introduction)
- **Phase 2:** 5 min (Reconnaissance)
- **Phase 3:** 7 min (Enumeration)
- **Phase 4:** 8 min (Exploitation)
- **Phase 5:** 7 min (Lateral Movement)
- **Phase 6:** 5 min (Post-Exploitation)
- **Phase 7:** 5 min (Reporting)
- **Phase 8:** 5 min (Advanced Features)

### Backup Plans

**If MEDUSA fails:**
- Use manual commands (nmap, curl, mysql)
- Explain what MEDUSA would do
- Show tool integration capabilities

**If services don't start:**
- Check Docker status: `docker-compose ps`
- View logs: `docker-compose logs`
- Restart services: `docker-compose restart`

**If network issues:**
- Verify ports: `netstat -an | grep -E '8080|3001|3306'`
- Check firewall: `sudo ufw status`
- Test connectivity: `curl http://localhost:8080`

---

## 📝 Post-Demo Q&A Preparation

### Common Questions

**Q: How does MEDUSA's AI make decisions?**
A: MEDUSA uses Google Gemini to analyze discovered vulnerabilities and recommend attack strategies based on MITRE ATT&CK framework.

**Q: Is MEDUSA safe to use?**
A: Yes, with approval gates and risk classification. Always use in authorized environments only.

**Q: Can MEDUSA be used for real penetration testing?**
A: Yes, but ensure proper authorization and follow ethical guidelines.

**Q: How accurate are MEDUSA's findings?**
A: MEDUSA uses real tools (nmap, custom scanners) for reconnaissance and enumeration. Exploitation results may be simulated.

**Q: What makes MEDUSA different from other tools?**
A: AI-powered decision making, natural language interface, approval gates, and comprehensive reporting with MITRE ATT&CK mapping.

---

## 🎯 Success Criteria

### Demo is Successful If:

✅ All 8 services are discovered  
✅ SQL injection is successfully exploited  
✅ Database credentials are extracted  
✅ Lateral movement is demonstrated  
✅ Comprehensive report is generated  
✅ MITRE ATT&CK mapping is shown  
✅ Approval gates are demonstrated  
✅ All three modes are showcased  

---

## 📚 Additional Resources

- **MEDUSA Documentation:** `docs/`
- **Lab Environment Guide:** `lab-environment/README.md`
- **Vulnerability Documentation:** `lab-environment/docs/security/`
- **MITRE ATT&CK Mapping:** `docs/architecture/MITRE_ATTACK_MAPPING.md`

---

**Good luck with your demo! 🚀**

Remember: This is an educational demonstration. Always use MEDUSA responsibly and only on systems you own or have explicit permission to test.

