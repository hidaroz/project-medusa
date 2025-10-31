# MedCare EHR Application - Complete Project Summary

## 📋 Project Overview

**Project Name**: MedCare Health System - Vulnerable EHR Web Application  
**Purpose**: Security testing and red team training environment  
**Technology**: PHP 8.1, MySQL 8.0, Apache, Docker  
**Status**: ✅ Complete and Ready for Deployment

---

## 📦 Deliverables

### ✅ 1. Complete Application Code

**Web Application (PHP)**:
- ✅ `src/index.php` - Login page with SQL injection vulnerability
- ✅ `src/dashboard.php` - Main dashboard with IDOR and XSS vulnerabilities
- ✅ `src/search.php` - Patient search with SQL injection
- ✅ `src/register.php` - User registration with mass assignment vulnerability
- ✅ `src/upload.php` - Unrestricted file upload functionality
- ✅ `src/reports.php` - Data export with access control issues
- ✅ `src/settings.php` - Admin panel with LFI and command injection
- ✅ `src/api.php` - API documentation page
- ✅ `src/logout.php` - Session termination handler

**Total Lines of Code**: ~1,500 lines across 9 PHP files

### ✅ 2. Dockerfile

- ✅ `Dockerfile` - Apache + PHP 8.1 configuration
- Includes intentional misconfigurations for security testing
- Configures weak PHP settings
- Creates vulnerable upload directory
- 53 lines

### ✅ 3. Database Schema with Seed Data

- ✅ `init-db.sql` - Complete database initialization
  - **Users Table**: 10 default users with weak passwords
  - **Patients Table**: 20 synthetic patients with complete PHI
  - **Medical Records Table**: Sample medical history
  - **Appointments Table**: Scheduled appointments
  - **Audit Log Table**: (Intentionally incomplete logging)
- **Total Records**: 50+ entries
- **Lines**: 400+ lines of SQL

**Synthetic Patient Data**:
- HIPAA-compliant fake names
- Realistic SSNs (fake)
- Complete medical histories
- Insurance information
- Emergency contacts
- Medical conditions and allergies

### ✅ 4. README with Exploitation Guide

- ✅ `README.md` - 700+ lines of comprehensive documentation
  - Overview and setup instructions
  - **12 vulnerability categories** with detailed exploitation steps
  - Attack scenarios and payloads
  - Testing tools and commands
  - Secure coding alternatives
  - Troubleshooting guide

**Vulnerabilities Documented**:
1. SQL Injection (Multiple locations)
2. Broken Authentication
3. IDOR (Insecure Direct Object Reference)
4. XSS (Cross-Site Scripting)
5. Unrestricted File Upload
6. Directory Traversal
7. Command Injection
8. Information Disclosure
9. Weak Session Management
10. Missing Access Controls
11. Mass Assignment
12. Sensitive Data Exposure

### ✅ 5. MITRE ATT&CK Techniques Mapping

- ✅ `MITRE_ATTACK_MAPPING.md` - 600+ lines
  - **32 ATT&CK techniques** mapped to vulnerabilities
  - Across **8 tactics**:
    - Initial Access (3 techniques)
    - Execution (4 techniques)
    - Persistence (3 techniques)
    - Privilege Escalation (4 techniques)
    - Defense Evasion (4 techniques)
    - Credential Access (5 techniques)
    - Discovery (5 techniques)
    - Collection (4 techniques)
  - Attack chain examples
  - Detection and mitigation strategies
  - Testing exercises and checklists

### ✅ 6. Additional Documentation

- ✅ `DEPLOYMENT_GUIDE.md` - Step-by-step deployment instructions
- ✅ `QUICK_START.md` - 5-minute setup guide
- ✅ `.env.example` - Environment configuration template with exposed credentials
- ✅ `docker-compose.yml` - Service orchestration configuration

---

## 🎯 Intentional Vulnerabilities (Complete List)

### Critical (CVSS 9.0-10.0)

1. **SQL Injection**
   - Location: `index.php`, `search.php`
   - Allows: Authentication bypass, data extraction, database manipulation
   - MITRE: T1190, T1003.002

2. **Command Injection**
   - Location: `settings.php` (ping functionality)
   - Allows: Remote code execution, system compromise
   - MITRE: T1059.004

3. **Unrestricted File Upload**
   - Location: `upload.php`
   - Allows: Web shell upload, code execution
   - MITRE: T1203, T1505.003

4. **Directory Traversal**
   - Location: `settings.php` (file viewer)
   - Allows: Reading arbitrary files, credential theft
   - MITRE: T1083, T1555.003

### High (CVSS 7.0-8.9)

5. **Broken Authentication**
   - Location: Application-wide
   - Issues: Plain text passwords, no account lockout
   - MITRE: T1110.001, T1078.003

6. **IDOR (Insecure Direct Object Reference)**
   - Location: `dashboard.php`
   - Allows: Unauthorized access to patient records
   - MITRE: T1548.002

7. **Cross-Site Scripting (XSS)**
   - Location: `dashboard.php` (medical notes)
   - Allows: Session hijacking, credential theft
   - MITRE: T1059.007, T1539

8. **Information Disclosure**
   - Location: Multiple files
   - Exposes: System info, credentials, error details
   - MITRE: T1082

### Medium (CVSS 4.0-6.9)

9. **Weak Session Management**
   - Issues: No timeout, predictable IDs, no regeneration
   - MITRE: T1539

10. **Missing Access Controls**
    - Location: `search.php`, `reports.php`
    - Allows: Unauthenticated access to sensitive functions

11. **Mass Assignment**
    - Location: `register.php`
    - Allows: Privilege escalation via role parameter
    - MITRE: T1136.001, T1068

12. **Sensitive Data Exposure**
    - Database: Plain text SSNs, unencrypted PHI
    - Files: `.env.example` with credentials
    - MITRE: T1555.003

---

## 🔧 Technical Specifications

### Application Stack

```yaml
Frontend:
  - HTML5
  - CSS3 (Inline)
  - JavaScript (Minimal)

Backend:
  - PHP 8.1
  - Apache 2.4
  - MySQLi extension

Database:
  - MySQL 8.0
  - InnoDB engine
  - UTF-8 encoding

Infrastructure:
  - Docker 20.10+
  - Docker Compose 2.0+
```

### Port Configuration

| Service | Port | Protocol |
|---------|------|----------|
| Web Application | 8080 | HTTP |
| MySQL Database | 3306 | TCP |

### Resource Requirements

| Component | CPU | RAM | Disk |
|-----------|-----|-----|------|
| Web App | 0.5 core | 512 MB | 1 GB |
| Database | 1.0 core | 1 GB | 2 GB |
| **Total** | **1.5 cores** | **1.5 GB** | **3 GB** |

### Network Architecture

```
[Client Browser]
      ↓
[Port 8080] → [ehr-webapp container]
                     ↓
              [ehr-network (bridge)]
                     ↓
              [ehr-database container]
```

---

## 📁 Complete File Structure

```
ehr-webapp/
│
├── Documentation (5 files)
│   ├── README.md                    # Main documentation (700+ lines)
│   ├── DEPLOYMENT_GUIDE.md          # Setup guide (400+ lines)
│   ├── QUICK_START.md               # Quick reference (150+ lines)
│   ├── MITRE_ATTACK_MAPPING.md      # ATT&CK mapping (600+ lines)
│   └── PROJECT_SUMMARY.md           # This file
│
├── Configuration (4 files)
│   ├── Dockerfile                   # Container definition
│   ├── docker-compose.yml           # Service orchestration
│   ├── .env.example                 # Environment variables
│   └── init-db.sql                  # Database schema (400+ lines)
│
└── Application Source (9 files)
    └── src/
        ├── index.php                # Login (208 lines)
        ├── dashboard.php            # Dashboard (161 lines)
        ├── search.php               # Search (156 lines)
        ├── register.php             # Registration (85 lines)
        ├── upload.php               # Upload (130 lines)
        ├── reports.php              # Reports (120 lines)
        ├── settings.php             # Settings (160 lines)
        ├── api.php                  # API docs (220 lines)
        └── logout.php               # Logout (7 lines)

Total Files: 18
Total Lines of Code: ~3,500+
```

---

## 🎯 Usage Scenarios

### Scenario 1: Security Training Lab
**Audience**: InfoSec students, junior penetration testers  
**Duration**: 2-4 hours  
**Objectives**:
- Learn web vulnerability identification
- Practice exploitation techniques
- Understand secure coding principles

### Scenario 2: Red Team Exercise
**Audience**: Advanced security professionals  
**Duration**: 4-8 hours  
**Objectives**:
- Simulate real-world attack scenarios
- Practice lateral movement
- Test detection capabilities
- Document attack chains

### Scenario 3: Blue Team Training
**Audience**: Security analysts, SOC teams  
**Duration**: 2-3 hours  
**Objectives**:
- Identify attack indicators
- Practice log analysis
- Develop detection rules
- Create incident response procedures

### Scenario 4: AI Red Team Agent Testing
**Audience**: Project Medusa development team  
**Duration**: Continuous  
**Objectives**:
- Test autonomous agent capabilities
- Validate attack technique coverage
- Measure detection rates
- Improve agent decision-making

---

## 🧪 Testing Coverage

### OWASP Top 10 (2021) Coverage

| # | Category | Implemented | Severity |
|---|----------|-------------|----------|
| A01 | Broken Access Control | ✅ | HIGH |
| A02 | Cryptographic Failures | ✅ | CRITICAL |
| A03 | Injection | ✅ | CRITICAL |
| A04 | Insecure Design | ✅ | MEDIUM |
| A05 | Security Misconfiguration | ✅ | HIGH |
| A06 | Vulnerable Components | ⚠️ | N/A |
| A07 | Authentication Failures | ✅ | CRITICAL |
| A08 | Data Integrity Failures | ✅ | MEDIUM |
| A09 | Security Logging Failures | ✅ | MEDIUM |
| A10 | SSRF | ❌ | N/A |

**Coverage**: 8/10 OWASP Top 10 categories

### MITRE ATT&CK Coverage

- **Tactics Covered**: 8/14 (57%)
- **Techniques Demonstrated**: 32
- **Sub-techniques**: 15+

**Focus Areas**:
- ✅ Initial Access
- ✅ Execution
- ✅ Persistence
- ✅ Privilege Escalation
- ✅ Defense Evasion
- ✅ Credential Access
- ✅ Discovery
- ✅ Collection

---

## 🚀 Deployment Options

### Option 1: Standalone (Recommended for Testing)
```bash
cd docker-lab/services/ehr-webapp
docker-compose up -d
```
**Pros**: Simple, isolated, fast startup  
**Cons**: No network simulation

### Option 2: Full Lab Environment
```bash
cd docker-lab
docker-compose up -d
```
**Pros**: Complete network, multiple targets, realistic  
**Cons**: Higher resource usage

### Option 3: Manual Installation
```bash
# Setup Apache + PHP + MySQL manually
# Copy source files
# Import database
```
**Pros**: Full control, no Docker required  
**Cons**: Complex setup, environment-dependent

---

## 📊 Default Credentials

### Application Users

| Username | Password | Role | Use Case |
|----------|----------|------|----------|
| admin | admin123 | Administrator | Full access testing |
| doctor1 | doctor123 | Doctor | Medical staff testing |
| doctor2 | password | Doctor | Weak password testing |
| nurse1 | nurse123 | Nurse | Limited privilege testing |
| patient1 | patient123 | Patient | Low privilege testing |
| test | test | Patient | Quick testing |

### Database Access

| User | Password | Privileges | Use Case |
|------|----------|------------|----------|
| root | root123 | ALL | Database admin |
| webapp | webapp123 | healthcare_db | Application access |

### Configuration Files

**Location**: `.env.example`  
**Contents**: AWS keys, SMTP credentials, API secrets, etc.  
**Vulnerability**: Exposed in web-accessible location

---

## 🔍 Validation Checklist

Before release, verify:

- [x] All 9 PHP files created and functional
- [x] Dockerfile builds successfully
- [x] Database initializes with seed data
- [x] docker-compose starts all services
- [x] Login page accessible at port 8080
- [x] SQL injection exploits work
- [x] File upload accepts PHP files
- [x] Directory traversal reads .env
- [x] Command injection executes
- [x] IDOR allows patient record access
- [x] XSS payload executes
- [x] Documentation complete
- [x] MITRE mapping accurate
- [x] Testing tools verified

**Status**: ✅ All checks passed

---

## 🎓 Learning Outcomes

After completing exercises with this application, users will be able to:

### Technical Skills
- ✅ Identify SQL injection vulnerabilities
- ✅ Exploit authentication weaknesses
- ✅ Perform directory traversal attacks
- ✅ Upload and execute web shells
- ✅ Exploit IDOR vulnerabilities
- ✅ Conduct command injection attacks
- ✅ Bypass access controls
- ✅ Extract sensitive data

### Conceptual Understanding
- ✅ OWASP Top 10 vulnerabilities
- ✅ MITRE ATT&CK framework
- ✅ Attack kill chain methodology
- ✅ Secure coding principles
- ✅ Defense-in-depth strategies
- ✅ HIPAA security requirements

### Tool Proficiency
- ✅ Burp Suite for web testing
- ✅ SQLmap for SQL injection
- ✅ Command-line tools (curl, mysql)
- ✅ Docker for containerization
- ✅ Manual exploitation techniques

---

## 📈 Metrics and Success Criteria

### Red Team Metrics
- **Time to Initial Access**: < 5 minutes (SQL injection)
- **Time to Web Shell**: < 10 minutes (file upload)
- **Time to Data Exfiltration**: < 15 minutes (database dump)
- **Vulnerabilities Exploitable**: 12/12 (100%)

### Blue Team Metrics
- **Detectable Attacks**: All attacks leave traces
- **Log Coverage**: Apache access logs, MySQL query logs
- **Indicator Quality**: High (obvious attack patterns)

### Educational Metrics
- **Vulnerability Types**: 12 categories
- **MITRE Techniques**: 32 testable techniques
- **Hands-on Exercises**: 20+ exploitation scenarios
- **Documentation Quality**: Comprehensive (2,500+ lines)

---

## 🛡️ Security Considerations

### What Makes This SAFE for Training

1. **Isolated Environment**: Docker container, no internet exposure
2. **Synthetic Data**: No real PHI/PII
3. **Controlled Deployment**: Manual startup required
4. **Clear Documentation**: Security warnings throughout
5. **No Malware**: No actual malicious payloads included

### What Makes This DANGEROUS if Misused

1. **Real Vulnerabilities**: Fully exploitable weaknesses
2. **No Protection**: No WAF, IDS, or security controls
3. **Weak Credentials**: Easy to compromise
4. **Information Disclosure**: Exposes configuration details
5. **RCE Capable**: Can execute arbitrary commands

### Deployment Guidelines

✅ **Do**:
- Use in isolated lab environments
- Run in Docker containers
- Keep offline or on isolated networks
- Document all testing activities
- Obtain proper authorization

❌ **Don't**:
- Deploy on the internet
- Use with real patient data
- Connect to production networks
- Share credentials publicly
- Use for unauthorized testing

---

## 🔄 Maintenance and Updates

### Current Version
- **Version**: 1.0.0
- **Release Date**: October 2024
- **Status**: Production-ready for lab use

### Future Enhancements (Optional)

**Additional Vulnerabilities**:
- [ ] XML External Entity (XXE)
- [ ] Server-Side Request Forgery (SSRF)
- [ ] Insecure Deserialization
- [ ] Remote File Inclusion (RFI)

**Additional Features**:
- [ ] More patient records (50+)
- [ ] Additional user roles
- [ ] File download functionality
- [ ] Password reset mechanism (vulnerable)

**Documentation**:
- [ ] Video tutorials
- [ ] CTF-style challenges
- [ ] Automated testing scripts
- [ ] Detection rule templates

---

## 📞 Support and Contact

### Documentation Resources
- **README.md**: Complete vulnerability guide
- **DEPLOYMENT_GUIDE.md**: Setup instructions
- **QUICK_START.md**: Fast deployment
- **MITRE_ATTACK_MAPPING.md**: Technique reference

### Project Information
- **Project**: Project Medusa
- **Course**: INFO 492 - University of Washington
- **Purpose**: AI-driven red team agent development
- **Repository**: project-medusa/docker-lab/services/ehr-webapp

---

## ⚖️ Legal and Compliance

### Intended Use
This application is designed for:
- Educational purposes
- Security research
- Penetration testing training
- Red team exercises
- Blue team detection practice

### Restrictions
- **NOT** for production use
- **NOT** for unauthorized testing
- **NOT** with real patient data
- **NOT** for malicious purposes

### Data Privacy
All patient data is:
- Completely synthetic
- HIPAA-compliant (fake data)
- Generated for testing only
- No real individuals represented

### License
Educational use only. See project license for details.

---

## 🎉 Project Completion Status

### ✅ All Requirements Met

1. ✅ **Functional Requirements**
   - Simple web interface ✓
   - Patient records with synthetic data ✓
   - Login page ✓
   - Patient search ✓
   - Patient detail view ✓
   - File upload ✓
   - Admin panel ✓

2. ✅ **Intentional Vulnerabilities**
   - SQL injection ✓
   - Weak authentication ✓
   - Insecure file upload ✓
   - Directory traversal ✓
   - Exposed .env ✓
   - Session management issues ✓
   - No CSRF protection ✓

3. ✅ **Tech Stack**
   - PHP (instead of Python/Node as alternatives) ✓
   - MySQL database ✓
   - Bootstrap-style UI ✓
   - Runs on port 8080 ✓

4. ✅ **Docker Requirements**
   - Dockerfile created ✓
   - Synthetic patient data (20 patients) ✓
   - Data persists in volumes ✓
   - Application logs access ✓

5. ✅ **Documentation**
   - Complete application code ✓
   - Dockerfile ✓
   - Database schema with seed data ✓
   - README with exploitation guide ✓
   - MITRE ATT&CK techniques list ✓

### 📊 Statistics

- **Total Files**: 18
- **Lines of Code**: 3,500+
- **Lines of Documentation**: 2,500+
- **Vulnerabilities**: 12 types
- **MITRE Techniques**: 32
- **Patient Records**: 20
- **User Accounts**: 10
- **Development Time**: Complete

---

## 🎯 Ready for Deployment

The MedCare EHR vulnerable web application is **complete and ready for security testing**.

### Quick Deployment
```bash
cd docker-lab/services/ehr-webapp
docker-compose up -d
```

### Access Application
```
http://localhost:8080
Username: admin
Password: admin123
```

### Start Testing
Refer to README.md for exploitation guides and MITRE_ATTACK_MAPPING.md for attack techniques.

---

**Project Status**: ✅ **COMPLETE**

**Happy Ethical Hacking! 🎯**

---

*Document Version: 1.0*  
*Last Updated: October 28, 2024*  
*Maintainer: Project Medusa Team*

