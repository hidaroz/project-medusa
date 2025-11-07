# Project MEDUSA: Naming Conventions & System Architecture

**Clarifying the relationship between MEDUSA and MedCare EHR**

---

## 🏢 System Overview

```
┌─────────────────────────────────────────────────────┐
│         PROJECT MEDUSA                              │
│  AI-Driven Penetration Testing Platform             │
│                                                      │
│  Purpose: Analyze and attack MedCare EHR System    │
│  Components:                                        │
│  • MEDUSA CLI (Python-based analysis engine)       │
│  • MEDUSA Frontend (Next.js dashboard)             │
│  • MEDUSA Backend (FastAPI analysis engine)        │
│  • MEDUSA Database (PostgreSQL)                    │
│  • MEDUSA Cache (Redis)                            │
│  • MEDUSA Graph (Neo4j knowledge base)             │
└─────────────────────────────────────────────────────┘
                       │ targets
                       ▼
┌─────────────────────────────────────────────────────┐
│         MEDCARE EHR SYSTEM                          │
│  Vulnerable Healthcare Infrastructure (Lab)        │
│                                                      │
│  Purpose: Educational penetration testing target  │
│  Contains: 8 intentionally vulnerable services    │
│  • Web Portal (PHP - legacy)                       │
│  • REST API (Node.js)                              │
│  • Database (MySQL)                                │
│  • Directory (LDAP)                                │
│  • File Server (FTP)                               │
│  • SSH Server                                      │
│  • Workstation (Windows simulation)                │
│  • Log Aggregation                                 │
└─────────────────────────────────────────────────────┘
```

---

## 📝 Naming Convention Rules

### Rule 1: MEDUSA Services

All MEDUSA platform components use the prefix `medusa-` in service names:

```
medusa-frontend    → Container: medusa_frontend
medusa-backend     → Container: medusa_backend
medusa-postgres    → Container: medusa_postgres
medusa-redis       → Container: medusa_redis
medusa-neo4j       → Container: medusa_neo4j
```

**Naming Pattern:** `medusa-[component]`  
**Container Pattern:** `medusa_[component]`  
**Network Segment:** `medusa-dmz` (172.22.0.0/24)

### Rule 2: MedCare EHR Services

All MedCare EHR lab components use the prefix `ehr-` in service names:

```
ehr-webapp         → Container: medusa_ehr_web    (PHP app - legacy)
ehr-api            → Container: medusa_ehr_api    (Node.js API)
ehr-database       → Container: medusa_ehr_db     (MySQL)
ssh-server         → Container: medusa_ssh_server (SSH access)
ftp-server         → Container: medusa_ftp_server (FTP access)
ldap-server        → Container: medusa_ldap       (LDAP directory)
log-collector      → Container: medusa_logs       (Log aggregation)
workstation        → Container: medusa_workstation(Windows sim)
```

**Naming Pattern:** `ehr-[component]` or just `[component]` (legacy)  
**Container Pattern:** `medusa_[descriptive_name]`  
**Network Segments:** 
- `healthcare-dmz` (172.20.0.0/24) - Public-facing
- `healthcare-internal` (172.21.0.0/24) - Backend services

### Rule 3: Consistency Across Layers

Every service must be identifiable at all layers:

```
Service Name:      ehr-database
Container Name:    medusa_ehr_db
Hostname:          db-server
Port:              3306
Environment:       MYSQL_DATABASE=healthcare_db
Volume:            ehr-db-data
Network:           healthcare-internal
```

---

## 📋 Complete Service Naming Reference

### MEDUSA Services

| Layer | Service | Container | Hostname | Port | Network |
|-------|---------|-----------|----------|------|---------|
| **Frontend** | medusa-frontend | medusa_frontend | medusa-frontend | 3000→8080 | medusa-dmz |
| **Backend** | medusa-backend | medusa_backend | medusa-backend | 8000 | medusa-dmz |
| **Database** | medusa-postgres | medusa_postgres | medusa-postgres | 5432 | medusa-dmz |
| **Cache** | medusa-redis | medusa_redis | medusa-redis | 6379 | medusa-dmz |
| **Graph** | medusa-neo4j | medusa_neo4j | medusa-neo4j | 7474/7687 | medusa-dmz |

### MedCare EHR Services

| Layer | Service | Container | Hostname | Port | Network |
|-------|---------|-----------|----------|------|---------|
| **Frontend** | ehr-webapp | medusa_ehr_web | ehr-portal | 80→8081 | healthcare-dmz |
| **API** | ehr-api | medusa_ehr_api | api-server | 3000→3001 | healthcare-dmz/internal |
| **Database** | ehr-database | medusa_ehr_db | db-server | 3306 | healthcare-internal |
| **SSH** | ssh-server | medusa_ssh_server | admin-workstation | 22→2222 | healthcare-internal |
| **FTP** | ftp-server | medusa_ftp_server | file-storage | 21 | healthcare-internal |
| **LDAP** | ldap-server | medusa_ldap | ldap-server | 389 | healthcare-internal |
| **Logs** | log-collector | medusa_logs | log-server | 514/8081 | healthcare-internal |
| **Workstation** | workstation | medusa_workstation | ws-doctor01 | 445/5900 | healthcare-internal |

---

## 🔗 DNS & Service Discovery

### Internal Service Resolution

Within Docker networks, services are resolved by their service name (docker-compose.yml):

```yaml
# From medusa-frontend to medusa-backend
http://medusa-backend:8000

# From ehr-api to ehr-database
mysql -h ehr-database -u user -p
```

### External Access (From Host Machine)

Access services via localhost and exposed ports:

```
MEDUSA Frontend:    http://localhost:8080
MEDUSA Backend:     http://localhost:8000
EHR API:            http://localhost:3001
Database (MySQL):   localhost:3306
SSH:                ssh -p 2222 localhost
```

### Network Routing

```
┌─────────────────────────────────────────────────────┐
│          Host Machine (Your Laptop)                  │
└────────────┬────────────────────────────────────────┘
             │
    ┌────────┴──────────────────────────────────┐
    │                                             │
┌───▼───────────────┐        ┌──────────────────▼──┐
│  MEDUSA DMZ       │        │  Healthcare DMZ      │
│  172.22.0.0/24    │        │  172.20.0.0/24       │
│                   │        │                      │
│ • localhost:8080  │        │ • localhost:3001     │
│ • localhost:8000  │        │ • localhost:8081     │
└────────┬──────────┘        └──────────┬───────────┘
         │                              │
         └──────────────┬───────────────┘
                        │
                   ┌────▼────────────────┐
                   │ Healthcare Internal  │
                   │ 172.21.0.0/24        │
                   │                      │
                   │ • ehr-database       │
                   │ • ssh-server         │
                   │ • ftp-server         │
                   │ • ldap-server        │
                   │ • workstation        │
                   └─────────────────────┘
```

---

## 📂 Directory Structure & Naming

```
project-medusa/
│
├── medusa-cli/                    # MEDUSA CLI tool
│   ├── src/medusa/               # Main MEDUSA code
│   ├── requirements.txt           # Python dependencies
│   └── README.md                  # CLI documentation
│
├── medusa-webapp/                 # MEDUSA Next.js Frontend
│   ├── src/                       # Next.js source code
│   ├── Dockerfile                 # Frontend containerization
│   ├── package.json               # Node.js dependencies
│   └── README.md                  # Frontend documentation
│
├── lab-environment/               # MedCare EHR Infrastructure
│   ├── services/
│   │   ├── ehr-api/              # Node.js REST API
│   │   ├── ehr-webapp/           # PHP web app (legacy)
│   │   ├── ssh-server/           # SSH container
│   │   ├── ftp-server/           # FTP container
│   │   ├── ldap-server/          # LDAP (via image)
│   │   ├── log-collector/        # Syslog aggregator
│   │   └── workstation/          # Windows simulation
│   ├── init-scripts/             # Database initialization
│   ├── mock-data/                # Test data
│   └── README.md                  # Lab environment docs
│
├── neo4j-schema/                  # Neo4j Knowledge Graph
│   ├── init-schema.cypher        # Graph schema
│   └── README.md                  # Graph documentation
│
├── docs/                          # Centralized documentation
│   ├── 00-getting-started/       # Setup guides
│   ├── 01-architecture/          # Architecture docs
│   ├── 02-development/           # Development guides
│   ├── 03-deployment/            # Deployment guides
│   ├── 04-usage/                 # Usage documentation
│   ├── 05-api-reference/         # API documentation
│   ├── 06-security/              # Security/vulnerability docs
│   └── 07-research/              # Research documents
│
├── docker-compose.yml             # Main orchestration (ROOT LEVEL)
├── env.example                    # Environment template
├── .env                           # Environment configuration (created at runtime)
├── README.md                      # Project overview
│
├── NAMING_CONVENTIONS.md          # This file
├── MEDCARE_EHR_RECOVERY_PLAN.md  # Recovery & deployment
├── MEDCARE_DEPLOYMENT_GUIDE.md   # Quick deployment guide
│
└── archive/                       # Archived/deprecated code
    └── medusa-backend/           # Old backend (superseded by Python API)
```

---

## 🔄 Communication Patterns

### Pattern 1: MEDUSA → MedCare EHR (Analysis)

```
MEDUSA Backend (medusa-backend:8000)
       │
       ├─► Query EHR API (ehr-api:3000)
       ├─► Access SSH (ssh-server:22)
       ├─► Browse FTP (ftp-server:21)
       ├─► Query LDAP (ldap-server:389)
       └─► Direct DB (ehr-database:3306)
```

### Pattern 2: Frontend → Backend (UI)

```
MEDUSA Frontend (medusa-frontend:3000)
       │
       └─► Query MEDUSA Backend (medusa-backend:8000)
            │
            └─► Store results in Redis (medusa-redis:6379)
```

### Pattern 3: Backend → Supporting Services

```
MEDUSA Backend (medusa-backend:8000)
       │
       ├─► Store results in PostgreSQL (medusa-postgres:5432)
       ├─► Cache in Redis (medusa-redis:6379)
       └─► Store in Neo4j (medusa-neo4j:7474)
```

---

## 🏷️ Environment Variable Naming

### MEDUSA Configuration

```bash
# Frontend
NEXT_PUBLIC_MEDUSA_API_URL=http://localhost:8000
NEXT_PUBLIC_MEDUSA_WS_URL=ws://localhost:8000/ws

# Backend
DATABASE_URL=postgresql://medusa:password@medusa-postgres:5432/medusa_db
REDIS_URL=redis://medusa-redis:6379/0
NEO4J_URI=bolt://medusa-neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=medusa_graph_pass
```

### MedCare EHR Configuration

```bash
# Database
MYSQL_ROOT_PASSWORD=admin123
MYSQL_DATABASE=healthcare_db
MYSQL_USER=ehrapp
MYSQL_PASSWORD=Welcome123!

# SSH
ROOT_PASSWORD=password123
USER_NAME=admin
USER_PASSWORD=admin2024

# FTP
FTP_USER=fileadmin
FTP_PASS=Files2024!

# LDAP
LDAP_ORGANISATION="MedCare Health System"
LDAP_DOMAIN=medcare.local
LDAP_ADMIN_PASSWORD=admin123
```

---

## 🔑 Credentials Reference

### MEDUSA System

| Component | User | Password | Purpose |
|-----------|------|----------|---------|
| PostgreSQL | medusa | ${POSTGRES_PASSWORD} | Backend DB |
| Redis | N/A | N/A | Cache |
| Neo4j | neo4j | ${NEO4J_PASSWORD} | Graph DB |

### MedCare EHR System

| Service | User | Password | Purpose |
|---------|------|----------|---------|
| MySQL | root | admin123 | Root access |
| MySQL | ehrapp | Welcome123! | Application access |
| SSH | admin | admin2024 | SSH access |
| LDAP | admin | admin123 | Directory admin |
| FTP | fileadmin | Files2024! | FTP access |
| FTP | anonymous | (none) | Anonymous access |

---

## ✅ Naming Convention Checklist

When adding new services:

- [ ] Service name follows pattern (`medusa-*` or `ehr-*`)
- [ ] Container name is unique and descriptive
- [ ] Hostname matches service name or is descriptive
- [ ] Port is documented and not duplicated
- [ ] Network assignment is correct (medusa-dmz or healthcare-*)
- [ ] Environment variables use SCREAMING_SNAKE_CASE
- [ ] Volume naming follows pattern (`[service]-data`)
- [ ] Health checks are defined
- [ ] Credentials are in .env, not hardcoded

---

## 🚀 Quick Reference Commands

```bash
# List all services and containers
docker-compose ps

# Show service names and ports
docker-compose config | grep -A2 "^services:"

# Test internal DNS resolution
docker-compose exec medusa-frontend nslookup ehr-api

# Test service connectivity
docker-compose exec medusa-backend curl http://ehr-api:3000/api/health

# Show all networks
docker network ls

# Inspect network connectivity
docker network inspect medusa-dmz
```

---

## 📚 Related Documentation

- **[MedCare EHR Recovery Plan](./MEDCARE_EHR_RECOVERY_PLAN.md)** - Full architecture
- **[MedCare Deployment Guide](./MEDCARE_DEPLOYMENT_GUIDE.md)** - Quick start
- **[Architecture Overview](./docs/01-architecture/project-overview.md)** - System design
- **[Docker Compose Configuration](./docker-compose.yml)** - Configuration source

---

## 🔍 Troubleshooting Naming Issues

### Issue: Service can't reach another service by name

**Check:**
```bash
# 1. Verify both services are on same network
docker inspect medusa_ehr_api | grep -A10 '"Networks"'

# 2. Test DNS resolution
docker-compose exec ehr-api nslookup ehr-database

# 3. Test connectivity
docker-compose exec ehr-api ping ehr-database
```

### Issue: Port conflicts

**Check:**
```bash
# List all port bindings
docker-compose ps | grep -E '[0-9]+:[0-9]+'

# Find process using specific port
sudo lsof -i :8080
```

### Issue: Confused which container is which

**Check:**
```bash
# Show mapping of service → container → port
docker-compose ps --format "table {{.Service}}\t{{.Names}}\t{{.Ports}}"

# Show configuration details
docker-compose config | grep -A5 [service-name]
```

---

**This naming convention ensures clarity across all layers of the system.**

Use this as a reference when working with any component of Project MEDUSA and the MedCare EHR lab environment.

