# MEDUSA Healthcare Security Testing Lab

<div align="center">

🔬 **Isolated Docker Environment for AI-Driven Red Team Testing**

[![Docker](https://img.shields.io/badge/Docker-20.10+-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-Educational-green.svg)]()
[![Status](https://img.shields.io/badge/Status-Active-success.svg)]()

**⚠️ WARNING: Contains Intentional Security Vulnerabilities - For Testing Only ⚠️**

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Services](#services)
- [Documentation](#documentation)
- [Security Warning](#security-warning)
- [Usage](#usage)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## 🎯 Overview

MEDUSA Healthcare Lab is a **Docker-based vulnerable infrastructure** designed for testing the MEDUSA AI-driven red team agent. It simulates a small healthcare network with realistic services containing **intentional security vulnerabilities**.

### Purpose

- Test offensive security AI agents in a controlled environment
- Practice healthcare-specific security testing
- Develop and validate automated exploitation techniques
- Learn about healthcare infrastructure vulnerabilities

### Key Features

- ✅ **8 Vulnerable Services** - Complete healthcare infrastructure simulation
- ✅ **Realistic Vulnerabilities** - Real-world attack scenarios
- ✅ **Isolated Environment** - Safe testing in Docker containers
- ✅ **Easy Reset** - Rebuild entire environment in minutes
- ✅ **Comprehensive Logging** - Track all testing activities
- ✅ **Low Resource Usage** - Runs on standard laptop

---

## ⚡ Quick Start

### Prerequisites

- Docker Desktop 20.10+
- Docker Compose
- 8GB RAM minimum (16GB recommended)
- 20GB disk space

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/project-medusa.git
cd project-medusa/docker-lab

# Start all services
docker-compose up -d --build

# Verify all services are running
docker-compose ps

# View logs
docker-compose logs -f
```

### Access Services

| Service | URL/Command | Credentials |
|---------|-------------|-------------|
| **EHR Web Portal** | http://localhost:8080 | admin / admin123 |
| **EHR API** | http://localhost:3000 | No auth required |
| **Log Viewer** | http://localhost:8081 | No auth required |
| **SSH Server** | `ssh admin@localhost -p 2222` | admin / admin2024 |
| **MySQL DB** | `mysql -h localhost -P 3306 -u root -padmin123` | root / admin123 |
| **FTP Server** | `ftp localhost 21` | fileadmin / Files2024! |

**Setup Time:** 5-10 minutes (first time)  
**Reset Time:** 2-3 minutes

---

## 🏗️ Architecture

### Network Topology

```
                    ┌─────────────────────┐
                    │   Host Machine      │
                    │   (Your Laptop)     │
                    └──────────┬──────────┘
                               │
        ┌──────────────────────┴──────────────────────┐
        │                                              │
┌───────▼──────────┐                   ┌──────────────▼─────┐
│  DMZ Network     │                   │  Internal Network   │
│  172.20.0.0/24   │                   │  172.21.0.0/24     │
├──────────────────┤                   ├────────────────────┤
│ • EHR Web Portal │◄─────────────────►│ • MySQL Database   │
│ • EHR API        │                   │ • SSH Server       │
└──────────────────┘                   │ • FTP Server       │
                                       │ • LDAP Server      │
                                       │ • Workstation      │
                                       │ • Log Collector    │
                                       └────────────────────┘
```

### Two-Tier Design

**DMZ Network** - Public-facing services
- Web applications accessible from external networks
- First entry point for attacks

**Internal Network** - Backend systems
- Databases, file servers, workstations
- Requires pivoting or lateral movement to access

---

## 🔧 Services

### 1. EHR Web Portal (Apache/PHP)
**Port:** 8080  
**Vulnerabilities:**
- SQL Injection in login and search
- Cross-Site Scripting (XSS) in patient notes
- Insecure Direct Object Reference (IDOR)
- Information disclosure via error messages

### 2. EHR API (Node.js/Express)
**Port:** 3000  
**Vulnerabilities:**
- Missing authentication on sensitive endpoints
- Weak JWT secret
- Verbose error messages
- SQL injection via API parameters
- Arbitrary SQL execution endpoint

### 3. MySQL Database
**Port:** 3306  
**Vulnerabilities:**
- Weak root password (admin123)
- Exposed to external network
- Plain text passwords in database
- Overly permissive user privileges

### 4. SSH Server (Ubuntu)
**Port:** 2222  
**Vulnerabilities:**
- Weak user credentials
- Sudo misconfigurations (NOPASSWD on vim, find, python3)
- Exposed private keys (world-readable)
- Sensitive config files
- Command history with credentials

### 5. FTP Server (vsftpd)
**Port:** 21, 21000-21010  
**Vulnerabilities:**
- Anonymous FTP enabled
- Weak user credentials
- Unencrypted file transfer
- Sensitive files accessible
- Medical records backup available

### 6. LDAP Server (OpenLDAP)
**Port:** 389, 636  
**Vulnerabilities:**
- Anonymous bind enabled
- Weak admin password
- Unencrypted LDAP (not LDAPS)
- User enumeration possible

### 7. Log Collector (Syslog + Web UI)
**Port:** 8081, 514  
**Features:**
- Centralized logging from all services
- Web interface for log viewing
- Real-time monitoring

### 8. Workstation (Ubuntu + Samba)
**Port:** 445, 5900  
**Vulnerabilities:**
- SMB shares with guest access
- Cached credentials in config files
- Weak VNC password
- Sensitive documents accessible

---

## 📚 Documentation

All documentation has been reorganized into the `docs/` directory for better navigation:

### Quick Links

- **[Getting Started Guide](./docs/getting-started/SETUP_GUIDE.md)** - Complete setup instructions
- **[Quick Start](./docs/getting-started/QUICK_START_EHR.md)** - 5-minute deployment guide
- **[Network Architecture](./docs/architecture/NETWORK_ARCHITECTURE.md)** - Network design and topology
- **[Vulnerability Documentation](./docs/security/VULNERABILITY_DOCUMENTATION.md)** - Complete vulnerability catalog
- **[MITRE ATT&CK Mapping](./docs/security/MITRE_ATTACK_MAPPING.md)** - ATT&CK techniques mapping
- **[Documentation Index](./docs/README.md)** - Complete documentation navigation

### Documentation Categories

- **Getting Started**: `/docs/getting-started/` - Setup and deployment guides
- **Architecture**: `/docs/architecture/` - System design and overview
- **Security**: `/docs/security/` - Vulnerabilities and testing
- **Services**: `/docs/services/` - Service-specific documentation

---

## ⚠️ Security Warning

### 🚨 CRITICAL: READ BEFORE USE 🚨

This lab environment contains **INTENTIONAL SECURITY VULNERABILITIES** and must **NEVER** be:

❌ Exposed to the internet  
❌ Run on production networks  
❌ Used with real patient data  
❌ Left running unattended  
❌ Accessed without authorization  

### Proper Usage

✅ Use only in isolated test environments  
✅ Run on air-gapped or firewalled systems  
✅ Reset environment after each test session  
✅ Document all testing activities  
✅ Follow ethical hacking guidelines  
✅ Comply with applicable laws and regulations  

### Legal Notice

This lab is for **educational and authorized testing purposes only**. Unauthorized access to computer systems is illegal. Users are responsible for compliance with:

- Computer Fraud and Abuse Act (CFAA)
- HIPAA regulations (if applicable)
- Local and international cybersecurity laws
- Institutional policies and guidelines

**Use responsibly and ethically.**

---

## 🚀 Usage

### Basic Operations

```bash
# Start the lab
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f [service-name]

# Stop the lab
docker-compose down

# Complete reset (deletes all data)
docker-compose down -v
docker-compose up -d --build
```

### Testing Workflow

1. **Start Lab Environment**
   ```bash
   docker-compose up -d
   ```

2. **Verify All Services**
   ```bash
   docker-compose ps
   # Ensure all show "Up" status
   ```

3. **Run MEDUSA Agent**
   ```bash
   cd ../medusa-cli
   python medusa.py --target localhost --mode assessment
   ```

4. **Monitor Activity**
   ```bash
   # Real-time logs
   docker-compose logs -f
   
   # Web log viewer
   open http://localhost:8081
   ```

5. **Review Results**
   ```bash
   # MEDUSA report
   cat medusa_assessment_report.txt
   
   # Extracted data
   ls medusa_extracted_data/
   ```

6. **Reset for Next Test**
   ```bash
   docker-compose down -v
   docker-compose up -d
   ```

### Manual Testing

Before running MEDUSA, try manual exploitation:

```bash
# SQL Injection
curl -X POST http://localhost:8080/index.php \
  -d "username=admin' OR '1'='1' --" \
  -d "password=anything"

# Unauthenticated API access
curl http://localhost:3000/api/patients

# SSH brute force
hydra -l admin -P passwords.txt ssh://localhost:2222

# FTP anonymous access
ftp localhost 21
# User: anonymous, Password: (blank)

# Database access
mysql -h localhost -P 3306 -u root -padmin123
```

---

## 🔍 Troubleshooting

### Services Won't Start

**Problem:** Containers show "Exited" status

**Solution:**
```bash
# Check logs
docker-compose logs [service-name]

# Check for port conflicts
netstat -an | grep -E '8080|3000|3306'

# Restart Docker Desktop
```

### Database Connection Errors

**Problem:** Web portal can't connect to database

**Solution:**
```bash
# Wait for database to fully initialize
docker-compose logs ehr-database

# Restart web portal
docker-compose restart ehr-webapp

# Verify connectivity
docker-compose exec ehr-webapp ping ehr-database
```

### Out of Memory

**Problem:** Docker containers are slow or crashing

**Solution:**
```bash
# Check resource usage
docker stats

# Stop unnecessary services
docker-compose stop workstation ftp-server

# Increase Docker memory allocation
# Docker Desktop → Settings → Resources
```

### Cannot Access Services

**Problem:** Can't connect to http://localhost:8080

**Solution:**
```bash
# Verify container is running
docker-compose ps ehr-webapp

# Check port mapping
docker port medusa_ehr_web

# Test from inside container
docker-compose exec ehr-webapp curl localhost:80
```

**More Help:** See [docs/getting-started/SETUP_GUIDE.md - Troubleshooting](./docs/getting-started/SETUP_GUIDE.md#troubleshooting)

---

## 🤝 Contributing

### Adding New Vulnerabilities

1. Fork the repository
2. Create a feature branch
3. Add vulnerability to appropriate service
4. Document in [docs/security/VULNERABILITY_DOCUMENTATION.md](./docs/security/VULNERABILITY_DOCUMENTATION.md)
5. Test thoroughly
6. Submit pull request

### Improving Documentation

- Fix typos or unclear instructions
- Add more examples
- Create video tutorials
- Translate to other languages
- All documentation is in the `docs/` directory - organized by category

### Reporting Issues

- Use GitHub Issues
- Provide logs and error messages
- Describe steps to reproduce
- Specify your environment (OS, Docker version)

---

## 📊 Project Stats

| Metric | Value |
|--------|-------|
| **Services** | 8 |
| **Vulnerabilities** | 25+ |
| **Setup Time** | 5-10 min |
| **Reset Time** | 2-3 min |
| **Disk Space** | ~5-10 GB |
| **RAM Usage** | ~3-4 GB |
| **CPU Cores** | 2-4 cores |

---

## 📝 Version History

- **v1.0** (2024-01-30) - Initial release
  - 8 vulnerable services
  - Complete healthcare infrastructure
  - Comprehensive documentation

---

## 📄 License

This project is for **educational purposes only**. 

See [LICENSE](../LICENSE) for details.

---

## 📞 Support

- **Documentation:** [docs/](../docs/)
- **Issues:** GitHub Issues
- **Discussions:** GitHub Discussions

---

## 🙏 Acknowledgments

- OWASP for vulnerability taxonomy
- Docker community for containerization best practices
- Security researchers for vulnerability research
- Healthcare security professionals for realistic scenarios

---

<div align="center">

**Built with ❤️ for security research and education**

⚠️ **Remember: Use Responsibly and Ethically** ⚠️

[Getting Started](./docs/getting-started/SETUP_GUIDE.md) • [Architecture](./docs/architecture/NETWORK_ARCHITECTURE.md) • [Vulnerabilities](./docs/security/VULNERABILITY_DOCUMENTATION.md) • [All Docs](./docs/README.md)

</div>

