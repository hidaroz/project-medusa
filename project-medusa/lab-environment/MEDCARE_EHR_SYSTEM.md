# MedCare EHR System - Complete Vulnerable Healthcare Application

**This is the TARGET system that MEDUSA attacks for testing**

---

## 🎯 What is MedCare EHR?

MedCare EHR is a **complete, standalone Electronic Health Record (EHR) system** with intentional security vulnerabilities. It is designed as a realistic target environment for the MEDUSA AI penetration testing platform.

**IMPORTANT:** This is NOT the MEDUSA platform. This is the vulnerable application that MEDUSA tests against.

---

## 🏗️ Complete EHR Architecture

### Full Application Stack

```
┌─────────────────────────────────────────────────────────┐
│          MedCare EHR System (Complete Application)       │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────────┐                                        │
│  │   Frontend   │  (Next.js/React Application)           │
│  │  Port 8080   │  - Patient Portal                      │
│  └──────┬───────┘  - Provider Dashboard                  │
│         │          - Administrative UI                    │
│         │                                                 │
│         ▼                                                 │
│  ┌──────────────┐     ┌──────────────┐                  │
│  │   Backend    │────►│  Redis Cache │                  │
│  │  Port 3002   │     │  Port 6380   │                  │
│  └──────┬───────┘     └──────────────┘                  │
│         │                                                 │
│         ▼                                                 │
│  ┌──────────────┐     ┌──────────────┐                  │
│  │   REST API   │────►│   Database   │                  │
│  │  Port 3001   │     │  Port 3306   │                  │
│  └──────────────┘     └──────────────┘                  │
│                                                           │
│  Supporting Services:                                     │
│  • SSH Server (Port 2222)                                │
│  • FTP Server (Port 21)                                  │
│  • LDAP Directory (Port 389)                             │
│  • Log Collector (Port 8081)                             │
│  • Workstation (Ports 445/3389/5900)                     │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 System Components

### Core EHR Application (6 Services)

#### 1. **EHR Frontend** (`ehr-frontend`)
- **Technology:** Next.js/React
- **Port:** 8080 (external), 3000 (internal)
- **Purpose:** Modern user-facing web interface
- **Features:**
  - Patient management dashboard
  - Clinical documentation
  - Appointment scheduling
  - Medical records viewing
  - Reports and analytics
  - Administrative functions
- **Connects to:** Backend, API, Redis (via backend)
- **Container:** `medusa_ehr_frontend`

#### 2. **EHR Backend** (`ehr-backend`)
- **Technology:** Node.js
- **Port:** 3002
- **Purpose:** Business logic layer
- **Features:**
  - Authentication & authorization
  - Session management
  - Business rules enforcement
  - Data orchestration
- **Connects to:** API, Database, Redis
- **Container:** `medusa_ehr_backend`

#### 3. **EHR REST API** (`ehr-api`)
- **Technology:** Node.js/Express
- **Port:** 3001
- **Purpose:** RESTful API for data access
- **Features:**
  - CRUD operations
  - Patient records
  - Medical data
  - Prescriptions & labs
- **Connects to:** Database, Redis
- **Container:** `medusa_ehr_api`

#### 4. **EHR Database** (`ehr-database`)
- **Technology:** MySQL 8.0
- **Port:** 3306
- **Purpose:** Persistent data storage
- **Contains:**
  - Patient records
  - Medical history
  - Billing information
  - User accounts
- **Container:** `medusa_ehr_db`

#### 5. **EHR Cache** (`ehr-redis`)
- **Technology:** Redis 7
- **Port:** 6380
- **Purpose:** Session and data caching
- **Features:**
  - Session storage
  - API response caching
  - Temporary data
- **Container:** `medusa_ehr_redis`

#### 6. **Log Collector** (`log-collector`)
- **Technology:** Syslog + Web UI
- **Port:** 8081
- **Purpose:** Centralized logging
- **Features:**
  - Real-time log aggregation
  - Web-based log viewer
  - Activity monitoring
- **Container:** `medusa_logs`

### Supporting Infrastructure (2 Services)

#### 7. **SSH Server** (`ssh-server`)
- **Port:** 2222
- **Purpose:** Administrative access
- **Container:** `medusa_ssh_server`

#### 8. **FTP Server** (`file-server`)
- **Port:** 21
- **Purpose:** File transfer
- **Container:** `medusa_ftp_server`

#### 9. **LDAP Server** (`ldap-server`)
- **Port:** 389
- **Purpose:** Directory services
- **Container:** `medusa_ldap`

#### 10. **Workstation** (`workstation`)
- **Ports:** 445/3389/5900
- **Purpose:** Simulated Windows workstation
- **Container:** `medusa_workstation`

---

## 🚀 Quick Start

### Start the Complete EHR System

```bash
cd /Users/hidaroz/INFO492/devprojects/project-medusa/lab-environment

# Start all services
docker-compose up -d --build

# Wait for services to initialize
sleep 30

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

### Access the EHR System

| Service | URL/Command | Purpose |
|---------|-------------|---------|
| **Frontend** | http://localhost:8080 | Patient portal & provider dashboard |
| **API** | http://localhost:3001/api | REST API endpoints |
| **Backend** | http://localhost:3002 | Business logic layer |
| **Redis** | `redis-cli -h localhost -p 6380 -a Welcome123!` | Cache access |
| **Database** | `mysql -h localhost -P 3306 -u ehrapp -pWelcome123!` | Direct DB access |
| **Logs** | http://localhost:8081 | View system logs |

---

## 🔑 Default Credentials

### EHR Application
| Component | Username | Password | Notes |
|-----------|----------|----------|-------|
| Web Portal | admin | admin123 | Administrator account |
| Web Portal | doctor | doctor123 | Provider account |
| Database (root) | root | admin123 | MySQL root user |
| Database (app) | ehrapp | Welcome123! | Application user |
| Redis | - | Welcome123! | Cache password |

### Supporting Services
| Service | Username | Password |
|---------|----------|----------|
| SSH | admin | admin2024 |
| FTP | fileadmin | Files2024! |
| FTP | anonymous | (blank) |
| LDAP | cn=admin,dc=medcare,dc=local | admin123 |
| Workstation (SMB) | doctor | Doctor2024! |
| Workstation (VNC) | - | vnc123 |

---

## 🔧 Configuration

### Environment Variables

All services are configured via environment variables in `docker-compose.yml`:

```yaml
# Database connection
DB_HOST=ehr-database
DB_USER=ehrapp
DB_PASS=Welcome123!
DB_NAME=healthcare_db

# Redis connection
REDIS_HOST=ehr-redis
REDIS_PORT=6379
REDIS_PASSWORD=Welcome123!

# API endpoints
API_URL=http://ehr-api:3000
BACKEND_URL=http://ehr-backend:3000

# Security (intentionally weak)
JWT_SECRET=supersecret123
```

### Network Architecture

Two isolated networks:

1. **healthcare-dmz** (172.20.0.0/24)
   - Public-facing services
   - EHR webapp
   - EHR API

2. **healthcare-internal** (172.21.0.0/24)
   - Backend services
   - Database
   - Redis
   - Support services

---

## 🔍 Testing the System

### 1. Test Frontend

```bash
# Access web portal
open http://localhost:8080

# Login with admin credentials
# Username: admin
# Password: admin123
```

### 2. Test API

```bash
# Health check
curl http://localhost:3001/api/health

# List patients
curl http://localhost:3001/api/patients

# Get specific patient
curl http://localhost:3001/api/patients/P001
```

### 3. Test Backend

```bash
# Backend health check
curl http://localhost:3002/api/health
```

### 4. Test Redis Cache

```bash
# Connect to Redis
redis-cli -h localhost -p 6380 -a Welcome123!

# Check keys
KEYS *

# Get info
INFO
```

### 5. Test Database

```bash
# Connect to database
mysql -h localhost -P 3306 -u ehrapp -pWelcome123!

# Show databases
SHOW DATABASES;

# Use healthcare DB
USE healthcare_db;

# Show tables
SHOW TABLES;

# Query patients
SELECT * FROM patients LIMIT 5;
```

---

## 🛠️ Common Operations

### View Service Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f ehr-webapp
docker-compose logs -f ehr-api
docker-compose logs -f ehr-database
```

### Restart Services

```bash
# Restart all
docker-compose restart

# Restart specific service
docker-compose restart ehr-webapp
```

### Stop the System

```bash
# Stop all services (keeps data)
docker-compose stop

# Stop and remove containers (keeps volumes)
docker-compose down

# Complete reset (DELETES ALL DATA)
docker-compose down -v
```

### Rebuild After Changes

```bash
# Rebuild specific service
docker-compose build --no-cache ehr-webapp
docker-compose up -d ehr-webapp

# Rebuild everything
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

---

## 🎭 Intentional Vulnerabilities

This is a VULNERABLE system by design. Key vulnerabilities include:

### Frontend (ehr-webapp)
- ❌ SQL Injection in search
- ❌ Cross-Site Scripting (XSS)
- ❌ Insecure Direct Object Reference
- ❌ Session fixation
- ❌ Weak authentication

### Backend (ehr-backend)
- ❌ Missing input validation
- ❌ Insecure session management
- ❌ Exposed sensitive endpoints
- ❌ Weak JWT implementation

### API (ehr-api)
- ❌ No authentication on some endpoints
- ❌ Verbose error messages
- ❌ No rate limiting
- ❌ CORS misconfiguration
- ❌ SQL injection vectors

### Database (ehr-database)
- ❌ Weak passwords
- ❌ Exposed port
- ❌ Overly permissive accounts
- ❌ Unencrypted sensitive data

### Redis (ehr-redis)
- ❌ Weak password
- ❌ Exposed port
- ❌ No TLS encryption

### Supporting Services
- ❌ Weak SSH credentials
- ❌ Anonymous FTP access
- ❌ Anonymous LDAP bind
- ❌ SMB with weak passwords

**⚠️ DO NOT USE IN PRODUCTION! FOR TESTING ONLY! ⚠️**

---

## 📊 Resource Requirements

| Component | CPU | Memory | Disk |
|-----------|-----|--------|------|
| Frontend | 0.5 | 512MB | 1GB |
| Backend | 0.5 | 512MB | 500MB |
| API | 0.5 | 512MB | 500MB |
| Database | 1.0 | 1GB | 5GB |
| Redis | 0.2 | 256MB | 500MB |
| Support Services | 1.3 | 1.5GB | 2GB |
| **TOTAL** | **4.0 cores** | **4.5GB** | **10GB** |

---

## 🐛 Troubleshooting

### Services Won't Start

```bash
# Check logs
docker-compose logs [service-name]

# Check port conflicts
netstat -an | grep -E '8080|3001|3002|3306|6380'

# Restart Docker
# On macOS: Restart Docker Desktop
```

### Can't Connect to Database

```bash
# Ensure database is ready
docker-compose ps ehr-database

# Test connection
docker-compose exec ehr-database mysql -u root -padmin123

# Check logs
docker-compose logs ehr-database
```

### Redis Connection Issues

```bash
# Test Redis
redis-cli -h localhost -p 6380 -a Welcome123! PING

# Check logs
docker-compose logs ehr-redis
```

### Frontend Not Loading

```bash
# Check if Apache is running
docker-compose exec ehr-webapp curl localhost

# Check logs
docker-compose logs ehr-webapp

# Restart
docker-compose restart ehr-webapp
```

---

## 🔗 Integration with MEDUSA

This MedCare EHR system is designed to be attacked by the MEDUSA platform:

1. **MEDUSA** (at project root) - The attacker/pentesting platform
2. **MedCare EHR** (in lab-environment/) - The vulnerable target

To test MEDUSA against this system:

```bash
# Terminal 1: Start MedCare EHR (this system)
cd lab-environment
docker-compose up -d

# Terminal 2: Run MEDUSA against it
cd ../medusa-cli
python medusa.py --target localhost --port 8080 --mode full
```

---

## 📁 Directory Structure

```
lab-environment/
├── docker-compose.yml          # Main orchestration file
├── services/
│   ├── ehr-webapp/            # PHP frontend
│   ├── ehr-api/               # Node.js REST API (also used for backend)
│   ├── ssh-server/
│   ├── ftp-server/
│   ├── log-collector/
│   └── workstation/
├── init-scripts/
│   └── db/                    # Database initialization scripts
├── mock-data/
│   ├── documents/             # Sample documents
│   └── medical-records/       # Sample medical files
├── dev-data/                  # Persistent data (MySQL, LDAP, etc.)
├── dev-logs/                  # Service logs
└── docs/                      # Additional documentation
```

---

## ⚠️ Security Warnings

### DO NOT:
- ❌ Expose this system to the internet
- ❌ Use real patient data
- ❌ Run on production networks
- ❌ Leave running unattended
- ❌ Use in any real healthcare setting

### DO:
- ✅ Use in isolated test environments only
- ✅ Use synthetic data only
- ✅ Reset after each testing session
- ✅ Follow ethical hacking guidelines
- ✅ Comply with applicable laws

---

## 📞 Support

For issues with the MedCare EHR system:

1. Check logs: `docker-compose logs`
2. Review this documentation
3. Check parent project documentation
4. Verify Docker resources (CPU, memory, disk)

---

## 🏁 Summary

**MedCare EHR** is a complete, fully-functional EHR system with:

✅ Frontend (PHP webapp)  
✅ Backend (Node.js business logic)  
✅ REST API (Node.js)  
✅ Database (MySQL)  
✅ Cache (Redis)  
✅ Logging (Centralized)  
✅ Supporting Services (SSH, FTP, LDAP, Workstation)  

**Total:** 10 interconnected services forming a realistic healthcare application

This is the TARGET that MEDUSA attacks for penetration testing!

---

**Last Updated:** 2025-11-07  
**Status:** ✅ Complete and Ready for Testing

**Built with ❤️ for security research and education**  
⚠️ **Use Responsibly and Ethically** ⚠️

