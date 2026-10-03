# MEDUSA Network Architecture

**Navigation**: [Home](../../README.md) → [Docs](../INDEX.md) → [Architecture](README.md) → Network Architecture

---

## Overview

This document describes the network architecture of the MEDUSA Healthcare Security Testing Lab - a Docker-based vulnerable infrastructure designed for testing AI-driven penetration testing agents.

**Purpose**: Provide a realistic, isolated environment with intentional security vulnerabilities for safe security testing.

---

## Network Topology

### Two-Tier Design

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Host Machine (Your Laptop)                   │
│                                                                     │
│  Port Mappings:                                                     │
│  • 8080 → EHR Web Portal                                            │
│  • 3000 → EHR API                                                   │
│  • 8081 → Log Viewer                                                │
│  • 2222 → SSH Server                                                │
│  • 3306 → MySQL Database                                            │
│  • 21   → FTP Server                                                │
│  • 389  → LDAP Server                                               │
│  • 445  → Samba/SMB                                                 │
│                                                                     │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
        ┌──────────────────┴──────────────────┐
        │                                     │
        ▼                                     ▼
┌───────────────────┐              ┌──────────────────────┐
│   DMZ Network     │              │  Internal Network    │
│   172.20.0.0/24   │              │   172.21.0.0/24      │
│                   │              │                      │
│  Public-facing    │◄────────────►│  Backend systems     │
│  services         │              │  (requires pivoting) │
└───────────────────┘              └──────────────────────┘
```

### Network Segmentation

#### DMZ Network (172.20.0.0/24)
**Purpose**: Public-facing services accessible from external networks

**Services**:
- **EHR Web Portal** (172.20.0.10:80)
- **EHR API** (172.20.0.20:3000)

**Characteristics**:
- First entry point for attacks
- Limited trust boundary
- Can communicate with Internal Network
- Exposed to host machine via port mapping

#### Internal Network (172.21.0.0/24)
**Purpose**: Backend systems requiring lateral movement or pivoting

**Services**:
- **MySQL Database** (172.21.0.30:3306)
- **SSH Server** (172.21.0.40:22)
- **FTP Server** (172.21.0.50:21)
- **LDAP Server** (172.21.0.60:389)
- **Workstation** (172.21.0.70:445)
- **Log Collector** (172.21.0.80:514)

**Characteristics**:
- Requires pivoting from DMZ or direct access
- More sensitive data and services
- Simulates internal corporate network
- Some services exposed to host for testing

---

## Service Details

### 1. EHR Web Portal

**Container**: `ehr-webapp`  
**Network**: DMZ (172.20.0.10)  
**Technology**: Apache 2.4 + PHP 7.4  
**Port Mapping**: `8080:80`

**Purpose**: Patient health records web application

**Vulnerabilities**:
- ✅ SQL Injection in login form (`username` parameter)
- ✅ SQL Injection in patient search (`search` parameter)
- ✅ Cross-Site Scripting (XSS) in patient notes
- ✅ Insecure Direct Object Reference (IDOR) in patient records
- ✅ Information disclosure via verbose error messages
- ✅ Weak session management (predictable session IDs)

**Default Credentials**:
- Username: `admin`
- Password: `admin123`

**Database Connection**:
- Connects to MySQL on Internal Network (172.21.0.30:3306)
- Uses hardcoded credentials in `config.php`

**Attack Scenarios**:
1. SQL injection to bypass authentication
2. Extract patient data via IDOR
3. Steal session cookies via XSS
4. Pivot to database server via connection strings

---

### 2. EHR API

**Container**: `ehr-api`  
**Network**: DMZ (172.20.0.20)  
**Technology**: Node.js 18 + Express 4.18  
**Port Mapping**: `3000:3000`

**Purpose**: RESTful API for EHR system

**Endpoints**:
- `GET /api/patients` - List all patients (no auth!)
- `GET /api/patients/:id` - Get patient details
- `POST /api/patients` - Create patient
- `PUT /api/patients/:id` - Update patient
- `DELETE /api/patients/:id` - Delete patient
- `POST /api/auth/login` - Authentication
- `GET /api/admin/users` - Admin users (weak JWT)
- `POST /api/admin/sql` - Execute SQL (!!!)

**Vulnerabilities**:
- ✅ Missing authentication on `/api/patients`
- ✅ Weak JWT secret (`secret123`)
- ✅ SQL injection via `/api/patients/:id`
- ✅ Arbitrary SQL execution via `/api/admin/sql`
- ✅ Verbose error messages with stack traces
- ✅ CORS misconfiguration (allows all origins)

**Database Connection**:
- Connects to MySQL on Internal Network (172.21.0.30:3306)
- Connection string in environment variables

**Attack Scenarios**:
1. Enumerate patients without authentication
2. Forge JWT tokens with weak secret
3. Execute arbitrary SQL via `/api/admin/sql`
4. Extract database credentials from error messages

---

### 3. MySQL Database

**Container**: `ehr-database`  
**Network**: Internal (172.21.0.30)  
**Technology**: MySQL 8.0  
**Port Mapping**: `3306:3306`

**Purpose**: Backend database for EHR system

**Credentials**:
- Root password: `admin123`
- App user: `ehr_user` / `ehr_pass123`

**Databases**:
- `ehr_db` - Patient records, appointments, medical history
- `mysql` - System database
- `information_schema` - Metadata

**Vulnerabilities**:
- ✅ Weak root password
- ✅ Exposed to external network (port 3306 mapped)
- ✅ Plain text passwords in `users` table
- ✅ Overly permissive user privileges
- ✅ No SSL/TLS encryption

**Sample Data**:
- 50 patient records with realistic PHI
- 10 user accounts (doctors, nurses, admin)
- Medical history, prescriptions, lab results

**Attack Scenarios**:
1. Brute force root password
2. Connect directly from host machine
3. Extract patient data
4. Dump password hashes
5. Modify records for privilege escalation

---

### 4. SSH Server

**Container**: `ssh-server`  
**Network**: Internal (172.21.0.40)  
**Technology**: Ubuntu 22.04 + OpenSSH 8.9  
**Port Mapping**: `2222:22`

**Purpose**: Remote administration server

**Credentials**:
- User: `admin` / Password: `admin2024`
- User: `developer` / Password: `dev123`

**Vulnerabilities**:
- ✅ Weak user passwords
- ✅ Sudo misconfigurations:
  - `admin` can run `vim`, `find`, `python3` with `NOPASSWD`
  - All are privilege escalation vectors
- ✅ World-readable private keys in `/home/admin/.ssh/backup_key`
- ✅ Sensitive config files in `/opt/config/`
- ✅ Command history with credentials in `/home/admin/.bash_history`

**Privilege Escalation Paths**:
```bash
# Via vim
sudo vim -c ':!/bin/bash'

# Via find
sudo find / -exec /bin/bash \;

# Via python3
sudo python3 -c 'import os; os.system("/bin/bash")'
```

**Sensitive Files**:
- `/opt/config/database.conf` - Database credentials
- `/home/admin/.ssh/backup_key` - Private SSH key
- `/home/admin/.bash_history` - Command history with passwords

**Attack Scenarios**:
1. SSH brute force
2. Privilege escalation via sudo misconfigurations
3. Extract credentials from config files
4. Use private key for lateral movement

---

### 5. FTP Server

**Container**: `ftp-server`  
**Network**: Internal (172.21.0.50)  
**Technology**: vsftpd 3.0.5  
**Port Mapping**: `21:21`, `21000-21010:21000-21010` (passive mode)

**Purpose**: File transfer for medical records backups

**Credentials**:
- User: `fileadmin` / Password: `Files2024!`
- Anonymous: Enabled (read-only)

**Vulnerabilities**:
- ✅ Anonymous FTP enabled
- ✅ Weak user password
- ✅ Unencrypted file transfer (no FTPS)
- ✅ Sensitive files accessible to anonymous users
- ✅ Medical records backup available

**Directory Structure**:
```
/ftp/
├── public/
│   ├── announcements.txt
│   └── policies.pdf
├── backups/
│   ├── patient_records_2024.csv  (world-readable!)
│   ├── database_dump.sql
│   └── config_backup.tar.gz
└── uploads/
    └── (writable by authenticated users)
```

**Attack Scenarios**:
1. Anonymous login to enumerate files
2. Download patient records backup
3. Extract database credentials from backup
4. Upload malicious files for web shell

---

### 6. LDAP Server

**Container**: `ldap-server`  
**Network**: Internal (172.21.0.60)  
**Technology**: OpenLDAP 2.5  
**Port Mapping**: `389:389`, `636:636`

**Purpose**: Directory service for user authentication

**Credentials**:
- Admin DN: `cn=admin,dc=medusa,dc=local`
- Admin Password: `admin123`

**Vulnerabilities**:
- ✅ Anonymous bind enabled
- ✅ Weak admin password
- ✅ Unencrypted LDAP (not LDAPS on 389)
- ✅ User enumeration possible
- ✅ Password policy not enforced

**Directory Structure**:
```
dc=medusa,dc=local
├── ou=users
│   ├── cn=john.doe
│   ├── cn=jane.smith
│   └── cn=admin.user
└── ou=groups
    ├── cn=doctors
    ├── cn=nurses
    └── cn=administrators
```

**Attack Scenarios**:
1. Anonymous bind to enumerate users
2. Brute force admin password
3. Extract user credentials
4. Modify user attributes for privilege escalation

---

### 7. Log Collector

**Container**: `log-collector`  
**Network**: Internal (172.21.0.80)  
**Technology**: Rsyslog + Python Flask  
**Port Mapping**: `8081:8080` (web UI), `514:514` (syslog)

**Purpose**: Centralized logging from all services

**Features**:
- Syslog server on UDP 514
- Web UI for log viewing on port 8080
- Real-time log streaming
- No authentication required (!)

**Vulnerabilities**:
- ✅ No authentication on web UI
- ✅ Sensitive information in logs (passwords, tokens)
- ✅ Log injection possible
- ✅ Path traversal in log viewer

**Logged Events**:
- SSH login attempts
- Database queries
- Web application access
- FTP transfers
- LDAP binds

**Attack Scenarios**:
1. Access logs without authentication
2. Extract credentials from logs
3. Inject malicious log entries
4. Path traversal to read system files

---

### 8. Workstation

**Container**: `workstation`  
**Network**: Internal (172.21.0.70)  
**Technology**: Ubuntu 22.04 + Samba 4.15  
**Port Mapping**: `445:445` (SMB), `5900:5900` (VNC)

**Purpose**: Simulated user workstation

**Credentials**:
- User: `doctor` / Password: `doctor123`
- VNC Password: `vnc123`

**Vulnerabilities**:
- ✅ SMB shares with guest access
- ✅ Cached credentials in config files
- ✅ Weak VNC password
- ✅ Sensitive documents accessible
- ✅ Browser saved passwords

**SMB Shares**:
```
\\172.21.0.70\public     (guest access, read-only)
\\172.21.0.70\documents  (requires auth, read-write)
\\172.21.0.70\medical    (requires auth, read-write)
```

**Sensitive Files**:
- `/home/doctor/Documents/passwords.txt` - Plaintext passwords
- `/home/doctor/.config/database_client.conf` - DB credentials
- `/home/doctor/Desktop/patient_list.xlsx` - Patient data

**Attack Scenarios**:
1. Access SMB shares as guest
2. Crack VNC password
3. Extract cached credentials
4. Steal sensitive documents

---

## Network Communication Matrix

| Source | Destination | Port | Protocol | Purpose |
|--------|-------------|------|----------|---------|
| Host | EHR Web Portal | 8080 | HTTP | Web access |
| Host | EHR API | 3000 | HTTP | API access |
| Host | Log Viewer | 8081 | HTTP | Log viewing |
| Host | SSH Server | 2222 | SSH | Remote admin |
| Host | MySQL | 3306 | MySQL | Database access |
| Host | FTP Server | 21 | FTP | File transfer |
| Host | LDAP Server | 389 | LDAP | Directory access |
| Host | Workstation | 445 | SMB | File sharing |
| EHR Web Portal | MySQL | 3306 | MySQL | Database queries |
| EHR API | MySQL | 3306 | MySQL | Database queries |
| All Services | Log Collector | 514 | Syslog | Centralized logging |
| SSH Server | MySQL | 3306 | MySQL | Admin access |
| Workstation | All Services | Various | Various | User access |

---

## Attack Paths

### Path 1: Web Application → Database

```
1. Exploit SQL injection in EHR Web Portal (172.20.0.10)
   ↓
2. Extract database credentials from error messages
   ↓
3. Connect directly to MySQL (172.21.0.30:3306)
   ↓
4. Dump all patient records
   ↓
5. Extract user password hashes
   ↓
6. Crack passwords for SSH access
```

### Path 2: API → Arbitrary SQL Execution

```
1. Access unauthenticated /api/patients endpoint (172.20.0.20)
   ↓
2. Enumerate patient IDs
   ↓
3. Forge JWT with weak secret
   ↓
4. Access /api/admin/sql endpoint
   ↓
5. Execute arbitrary SQL commands
   ↓
6. Create admin user or extract data
```

### Path 3: FTP → SSH → Privilege Escalation

```
1. Anonymous FTP login (172.21.0.50)
   ↓
2. Download patient_records_2024.csv
   ↓
3. Download config_backup.tar.gz
   ↓
4. Extract SSH credentials from backup
   ↓
5. SSH to server (172.21.0.40:22)
   ↓
6. Privilege escalation via sudo vim
   ↓
7. Root access achieved
```

### Path 4: LDAP → Lateral Movement

```
1. Anonymous LDAP bind (172.21.0.60:389)
   ↓
2. Enumerate all users
   ↓
3. Brute force weak passwords
   ↓
4. Extract user credentials
   ↓
5. Use credentials for SSH, SMB, or web access
   ↓
6. Lateral movement across network
```

### Path 5: Log Collector → Information Disclosure

```
1. Access log viewer without auth (172.21.0.80:8080)
   ↓
2. Search logs for "password" or "token"
   ↓
3. Extract credentials from logged events
   ↓
4. Use credentials for other services
```

---

## Docker Compose Configuration

### Network Definitions

```yaml
networks:
  dmz:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
  
  internal:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/24
```

### Service Network Assignments

```yaml
services:
  ehr-webapp:
    networks:
      dmz:
        ipv4_address: 172.20.0.10
      internal:  # Can access database
  
  ehr-api:
    networks:
      dmz:
        ipv4_address: 172.20.0.20
      internal:  # Can access database
  
  ehr-database:
    networks:
      internal:
        ipv4_address: 172.21.0.30
  
  ssh-server:
    networks:
      internal:
        ipv4_address: 172.21.0.40
  
  # ... other services
```

---

## Security Considerations

### Isolation

**Docker Networks**:
- Services are isolated within Docker networks
- No direct access to host network (except via port mapping)
- DMZ and Internal networks are bridged for realistic scenarios

**Firewall Rules** (on host):
- Only mapped ports are accessible from host
- No inbound connections from external networks
- Lab should run on air-gapped or firewalled system

### Reset and Cleanup

**Complete Reset**:
```bash
docker-compose down -v
docker-compose up -d --build
```

**Partial Reset** (keep database data):
```bash
docker-compose restart
```

**Cleanup**:
```bash
# Remove all containers and networks
docker-compose down

# Remove volumes (data)
docker volume prune

# Remove images
docker rmi $(docker images -q medusa/*)
```

---

## Deployment

### Quick Start

```bash
# Navigate to lab directory
cd lab-environment

# Start all services
docker-compose up -d --build

# Verify all services are running
docker-compose ps

# View logs
docker-compose logs -f
```

### Verification

```bash
# Check EHR Web Portal
curl http://localhost:8080

# Check EHR API
curl http://localhost:3000/api/patients

# Check MySQL
mysql -h localhost -P 3306 -u root -padmin123

# Check SSH
ssh admin@localhost -p 2222  # Password: admin2024

# Check FTP
ftp localhost 21  # User: anonymous

# Check Log Viewer
curl http://localhost:8081
```

### Troubleshooting

**Services won't start**:
```bash
# Check logs
docker-compose logs [service-name]

# Check port conflicts
netstat -an | grep -E '8080|3000|3306'

# Restart Docker Desktop
```

**Database connection errors**:
```bash
# Wait for database to initialize
docker-compose logs ehr-database

# Restart web portal
docker-compose restart ehr-webapp
```

---

## Testing Scenarios

### Scenario 1: Full Assessment

**Objective**: Complete penetration test of entire lab

**Steps**:
1. Run MEDUSA with `--type full_assessment`
2. Reconnaissance discovers all services
3. Vulnerability analysis identifies SQL injection, weak passwords, etc.
4. Planning creates multi-step attack plan
5. Exploitation (with approval) tests vulnerabilities
6. Reporting generates comprehensive report

**Expected Findings**: 25+ vulnerabilities across all services

### Scenario 2: Web Application Focus

**Objective**: Test only web-facing services

**Steps**:
1. Target: `http://localhost:8080`
2. Reconnaissance: Port scan, service detection
3. Vulnerability analysis: SQL injection, XSS, IDOR
4. Exploitation: Bypass authentication, extract data
5. Reporting: Web application security report

**Expected Findings**: 10+ web vulnerabilities

### Scenario 3: Internal Network Pivot

**Objective**: Gain access to internal network from DMZ

**Steps**:
1. Exploit web application
2. Extract database credentials
3. Connect to MySQL on internal network
4. Extract SSH credentials from database
5. SSH to internal server
6. Privilege escalation
7. Lateral movement to other internal services

**Expected Outcome**: Root access on SSH server, access to all internal services

---

## Related Documentation

- [System Overview](system-overview.md) - High-level architecture
- [Component Design](component-design.md) - Technical component details
- [Lab Environment README](../../lab-environment/README.md) - Lab setup guide
- [Vulnerability Documentation](../../lab-environment/docs/security/VULNERABILITY_DOCUMENTATION.md) - Complete vulnerability catalog

---

**Last Updated**: 2025-11-20  
**Version**: 1.0

**Navigation**: [Home](../../README.md) → [Docs](../INDEX.md) → [Architecture](README.md) → Network Architecture
