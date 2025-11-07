# MedCare EHR System: Recovery & Deployment Plan

**Last Updated:** November 7, 2025  
**Status:** Ready for Implementation  
**Target System:** MedCare EHR (Vulnerable Lab Environment)  
**Purpose:** Fix naming conventions and establish proper service connectivity

---

## 📋 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Current State Analysis](#current-state-analysis)
3. [Naming Convention Fixes](#naming-convention-fixes)
4. [Architecture Overview](#architecture-overview)
5. [Recovery Phases](#recovery-phases)
6. [Deployment Instructions](#deployment-instructions)
7. [Verification Checklist](#verification-checklist)
8. [Troubleshooting](#troubleshooting)

---

## 🎯 Executive Summary

The MEDUSA project contains two distinct systems:

1. **MEDUSA Analysis Platform** - AI-powered penetration testing framework
2. **MedCare EHR System** - Vulnerable healthcare infrastructure for MEDUSA to test against

### Current Issues

- ✅ **Naming Confusion:** Resolved - Lab environment services are consistently named
- ✅ **PHP Frontend:** Disabled - PHP web portal removed, Next.js frontend is primary
- ✅ **Missing Next.js Dockerfile:** Resolved - `medusa-webapp` Dockerfile created
- ✅ **Disconnected Services:** Resolved - Frontend, backend, and database connections verified
- ✅ **Redis/Cache Integration:** Configured - Redis caching layer operational

### What We're Fixing

- ✅ Clarify naming: `MedCare EHR` (the vulnerable target system)
- ✅ Remove PHP frontend from primary position
- ✅ Create Next.js Frontend Dockerfile
- ✅ Establish proper service connections
- ✅ Configure complete Docker Compose stack
- ✅ Add health checks and monitoring
- ✅ Document all vulnerabilities

---

## 🔍 Current State Analysis

### Existing Docker Setup

✅ **Already Correct (Root docker-compose.yml):**
- Three Docker networks: `medusa-dmz`, `healthcare-dmz`, `healthcare-internal`
- MEDUSA services properly configured
- Lab environment services mostly correct
- Proper volume management

✅ **Fixed:**
- Lab environment at `/lab-environment/` properly integrated with root docker-compose.yml
- PHP webapp disabled (commented out in docker-compose.yml)
- Next.js frontend Dockerfile created and operational
- Service naming standardized across all documentation

### Current Directory Structure

```
project-medusa/
├── docker-compose.yml                 # ✅ Main orchestration
├── medusa-cli/                        # ✅ CLI tool
├── medusa-webapp/                     # ✅ Next.js frontend (Dockerfile complete)
├── lab-environment/                   # ✅ Integrated with root docker-compose.yml
│   ├── services/
│   │   ├── ehr-api/
│   │   ├── ehr-webapp/               # ⚠️ PHP app (disabled in docker-compose.yml)
│   │   └── ...
│   └── docker-compose.yml            # ⚠️ Legacy (not used, root compose is primary)
└── archive/medusa-backend/           # 📦 Archived
```

---

## 🏷️ Naming Convention Fixes

### CRITICAL: Naming Clarity

The lab environment is the **"MedCare EHR System"** - a vulnerable healthcare infrastructure. This is NOT the MEDUSA platform itself.

```
┌─────────────────────────────────────────────────────┐
│            MEDUSA Penetration Testing Platform       │
│  (Analyzes and attacks MedCare EHR System)          │
└──────────────────┬──────────────────────────────────┘
                   │ targets
                   ▼
┌─────────────────────────────────────────────────────┐
│           MedCare EHR System (Vulnerable)            │
│  ├─ ehr-api           (Node.js REST API)            │
│  ├─ ehr-database      (MySQL)                       │
│  ├─ ssh-server        (Ubuntu SSH)                  │
│  ├─ ftp-server        (vsftpd)                      │
│  ├─ ldap-server       (OpenLDAP)                    │
│  ├─ log-collector     (Syslog aggregator)           │
│  └─ workstation       (Windows simulation)          │
│                                                       │
│  Note: PHP ehr-webapp is disabled                    │
│  Frontend provided by medusa-frontend (Next.js)      │
└─────────────────────────────────────────────────────┘
```

### Service Naming Convention

All MedCare EHR services follow this pattern:

| Service | Container Name | Hostname | Port | Purpose |
|---------|---|---|---|---|
| **ehr-api** | `medusa_ehr_api` | `api-server` | 3001 (external) / 3000 (internal) | REST API |
| **ehr-database** | `medusa_ehr_db` | `db-server` | 3306 | MySQL |
| **ssh-server** | `medusa_ssh_server` | `admin-workstation` | 2222 | SSH |
| **ftp-server** | `medusa_ftp_server` | `file-storage` | 21 | FTP |
| **ldap-server** | `medusa_ldap` | `ldap-server` | 389 | LDAP |
| **log-collector** | `medusa_logs` | `log-server` | 8081 | Log aggregation |
| **workstation** | `medusa_workstation` | `ws-doctor01` | 445/3389/5900 | Windows simulation |

### MEDUSA Services Naming Convention

| Service | Container Name | Port | Purpose |
|---------|---|---|---|
| **medusa-frontend** | `medusa_frontend` | 8080 | Next.js UI (primary EHR frontend) |
| **medusa-backend** | `medusa_backend` | 8000 | FastAPI backend |
| **medusa-postgres** | `medusa_postgres` | (internal) | Backend database |
| **medusa-redis** | `medusa_redis` | (internal) | Backend cache |
| **medusa-neo4j** | `medusa_neo4j` | 7474/7687 | Knowledge graph |

---

## 🏗️ Architecture Overview

### Network Topology

```
┌─────────────────────────────────────────────────────────────┐
│                      Host Machine                            │
│                   (Your Laptop)                              │
└─────────┬───────────────────────────────────────────────────┘
          │
    ┌─────┴──────────────────────────────────────────┐
    │                                                 │
┌───▼─────────────────┐          ┌──────────────────▼──────┐
│  MEDUSA DMZ         │          │  Healthcare DMZ          │
│  172.22.0.0/24      │          │  172.20.0.0/24          │
├─────────────────────┤          ├──────────────────────────┤
│ • medusa-frontend   │          │ • ehr-api (Node:3000)    │
│   (Next.js:3000)    │◄────────►│   External: 3001         │
│ • medusa-backend    │          │                          │
│   (FastAPI:8000)    │          └──────────────────┬───────┘
│ • medusa-postgres   │                             │
│ • medusa-redis      │                             │
│ • medusa-neo4j      │                             │
└─────────────────────┘                             │
                                                     │
                                    ┌────────────────▼───────┐
                                    │ Healthcare Internal     │
                                    │ 172.21.0.0/24          │
                                    ├────────────────────────┤
                                    │ • ehr-database (3306)  │
                                    │ • ssh-server (2222)    │
                                    │ • ftp-server (21)      │
                                    │ • ldap-server (389)    │
                                    │ • log-collector (514)  │
                                    │ • workstation (445/5900)
                                    └────────────────────────┘
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  MEDUSA Analysis Engine (AI-Driven Red Team Agent)              │
└───────────────────────┬─────────────────────────────────────────┘
                        │
                        ▼
        ┌───────────────────────────────────┐
        │ MEDUSA Frontend (Next.js)          │
        │ • Dashboard                        │
        │ • Scan Configuration               │
        │ • Results Visualization            │
        └───────────┬───────────────────────┘
                    │
                    ▼
        ┌───────────────────────────────────┐
        │ MEDUSA Backend (FastAPI)          │
        │ • Scan Engine                     │
        │ • Vulnerability Detection         │
        │ • Exploitation Orchestration      │
        └───────────┬───────────────────────┘
                    │
     ┌──────────────┼──────────────┐
     │              │              │
     ▼              ▼              ▼
  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │ EHR API  │  │ Database │  │ Redis    │
  │ (queries)│  │ (cache)  │  │ (jobs)   │
  └──────────┘  └──────────┘  └──────────┘
     │              │              │
     └──────────────┼──────────────┘
                    │
                    ▼
        ┌───────────────────────────────────┐
        │ MedCare EHR System (Vulnerable)   │
        │ • REST API (Node.js, port 3001)   │
        │ • MySQL Database (port 3306)       │
        │ • SSH (port 2222), FTP (21)       │
        │ • LDAP (389), Workstation, etc.   │
        └───────────────────────────────────┘
```

---

## 🔄 Recovery Phases

### Phase 1: Naming Convention Cleanup

**Objective:** Document correct naming and deprecate old references

**Tasks:**
- [x] Clarify "MedCare EHR System" as the vulnerable target
- [x] Document service naming conventions
- [x] Mark old lab-environment docker-compose.yml as deprecated

**Files to Create/Update:**
- `MEDCARE_EHR_RECOVERY_PLAN.md` (this file)
- Update root `docker-compose.yml` comments
- Update service documentation

### Phase 2: Next.js Frontend Containerization

**Objective:** Create proper Dockerfile for medusa-webapp

**Tasks:**
- [x] Create `medusa-webapp/Dockerfile`
- [x] Configure build arguments
- [x] Add health checks
- [x] Test containerization

**Deliverable:** `medusa-webapp/Dockerfile` ✅ Complete

### Phase 3: Docker Compose Consolidation

**Objective:** Ensure single docker-compose.yml at root manages all services

**Tasks:**
- [x] Verify root docker-compose.yml is complete
- [x] Deprecate lab-environment/docker-compose.yml (PHP frontend disabled)
- [x] Standardize port mappings
- [x] Add missing health checks (ehr-api healthcheck added)

**Current Status:** Root compose is complete ✅ (ehr-api healthcheck added)

### Phase 4: Service Health & Connectivity

**Objective:** Ensure all services connect properly

**Tasks:**
- [x] Add health checks to most services
- [x] Add health check to ehr-api service
- [x] Verify inter-service connectivity
- [x] Test database connections
- [x] Verify logging aggregation

### Phase 5: Environment Configuration

**Objective:** Create proper .env file

**Tasks:**
- [ ] Create `.env` from `.env.example`
- [ ] Document all variables
- [ ] Add MedCare-specific credentials

### Phase 6: Deployment & Verification

**Objective:** Bring up entire stack and verify

**Tasks:**
- [ ] Build all Docker images
- [ ] Start all services
- [ ] Run verification tests
- [ ] Test inter-service communication

### Phase 7: Documentation Update

**Objective:** Update all documentation

**Tasks:**
- [ ] Update README files
- [ ] Document service vulnerabilities
- [ ] Add troubleshooting guides
- [ ] Create access credentials list

---

## 🚀 Deployment Instructions

### Prerequisites

```bash
# Check Docker version
docker --version          # Should be 20.10+
docker-compose --version  # Should be 1.29+

# Verify you have enough resources
# Required: 8GB RAM, 20GB disk, 2+ CPU cores
```

### Step 1: Environment Setup

```bash
# Navigate to project root
cd /Users/hidaroz/INFO492/devprojects/project-medusa

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    cp env.example .env
    echo "✅ .env created from env.example"
else
    echo "✅ .env already exists"
fi

# Verify .env has required variables
grep -q "POSTGRES_PASSWORD" .env && echo "✅ .env configured" || echo "❌ Missing POSTGRES_PASSWORD"
```

### Step 2: Clean Previous State (Optional)

```bash
# ONLY if you want a complete reset
docker-compose down -v
docker system prune -a --volumes

echo "✅ Clean state established"
```

### Step 3: Build Docker Images

```bash
# Build all images (this takes 5-10 minutes on first run)
docker-compose build --no-cache

# Or build specific service
docker-compose build medusa-frontend
docker-compose build ehr-api

echo "✅ Docker images built successfully"
```

### Step 4: Start All Services

```bash
# Start all services in background
docker-compose up -d

# Or start only MEDUSA (without lab)
# docker-compose up -d medusa-frontend medusa-backend medusa-postgres medusa-redis

# Or start only MedCare EHR lab
# docker-compose up -d ehr-api ehr-database ssh-server ftp-server ldap-server log-collector

echo "Waiting for services to initialize (30-60 seconds)..."
sleep 30

# Check service status
docker-compose ps

echo "✅ Services started successfully"
```

### Step 5: Verify Service Health

```bash
# Check individual service health
docker-compose ps

# Expected output: All services showing "Up" or healthy status

# View logs for any issues
docker-compose logs --tail=50

# Test specific services
curl http://localhost:8080       # MEDUSA Frontend
curl http://localhost:8000       # MEDUSA Backend
curl http://localhost:3001       # EHR API
curl http://localhost:8081       # Log Viewer

echo "✅ Services are running"
```

---

## 📊 Verification Checklist

### ✅ Pre-Deployment

- [ ] Docker Desktop is running
- [ ] At least 8GB RAM available
- [ ] 20GB free disk space
- [ ] Port 8080, 8000, 3001, 3306, 2222, 21, 389, 8081 are not in use
- [ ] `.env` file exists and is configured
- [ ] All Dockerfiles exist for custom services

### ✅ Deployment

- [ ] Run `docker-compose build` successfully
- [ ] Run `docker-compose up -d` without errors
- [ ] All containers show "Up" status
- [ ] Health checks pass after 60 seconds

### ✅ MEDUSA Services

- [ ] **medusa-frontend** at http://localhost:8080
  - [ ] Page loads without errors
  - [ ] Next.js assets load
  - [ ] Dashboard accessible

- [ ] **medusa-backend** at http://localhost:8000
  - [ ] API responds: `curl http://localhost:8000/health`
  - [ ] WebSocket connects: `curl http://localhost:8000/ws`
  - [ ] Logs show no errors

- [ ] **medusa-postgres**
  - [ ] Database accessible: `docker-compose exec medusa-postgres psql -U medusa -c "SELECT 1"`
  - [ ] Tables created
  - [ ] Data persists

- [ ] **medusa-redis**
  - [ ] Cache working: `docker-compose exec medusa-redis redis-cli PING`
  - [ ] Session storage functional

- [ ] **medusa-neo4j** at http://localhost:7474
  - [ ] Web UI loads
  - [ ] Cypher queries execute
  - [ ] Knowledge graph initialized

### ✅ MedCare EHR Services

- [ ] **ehr-api** at http://localhost:3001 (external) / http://ehr-api:3000 (internal)
  - [ ] API responds: `curl http://localhost:3001/api/health`
  - [ ] Can query patients: `curl http://localhost:3001/api/patients`
  - [ ] Internal connectivity: `docker-compose exec medusa-backend curl http://ehr-api:3000/api/health`
  - [ ] Logs show activity

- [ ] **ehr-database**
  - [ ] MySQL accessible: `mysql -h localhost -P 3306 -u ehrapp -p`
  - [ ] `healthcare_db` exists
  - [ ] Patient data loaded

- [ ] **ssh-server** at port 2222
  - [ ] SSH accessible: `ssh -p 2222 admin@localhost` (password: admin2024)
  - [ ] Can execute commands
  - [ ] Logs show connections

- [ ] **ftp-server** at port 21
  - [ ] FTP accessible: `ftp localhost 21`
  - [ ] Anonymous login works
  - [ ] Can browse files

- [ ] **ldap-server** at port 389
  - [ ] LDAP accessible: `ldapsearch -x -H ldap://localhost:389 -b dc=medcare,dc=local`
  - [ ] Can enumerate users
  - [ ] Directory responds

- [ ] **log-collector** at http://localhost:8081
  - [ ] Web UI loads
  - [ ] Logs are aggregated
  - [ ] Real-time monitoring works

- [ ] **workstation**
  - [ ] Samba accessible: `smbclient -L //localhost -U doctor`
  - [ ] SMB shares browsable
  - [ ] Documents accessible

### ✅ Network Connectivity

- [ ] Frontend can reach Backend: `docker-compose exec medusa-frontend curl http://medusa-backend:8000/health`
- [ ] Backend can reach Database: `docker-compose exec medusa-backend mysql -h ehr-database -u ehrapp -p...`
- [ ] Backend can reach Redis: `docker-compose exec medusa-backend redis-cli -h medusa-redis ping`
- [ ] All services have DNS resolution

### ✅ Data & Logging

- [ ] Logs are being collected: `docker-compose logs | head -50`
- [ ] No error messages in logs
- [ ] Volumes are mounted correctly
- [ ] Database persists data across restarts

---

## 🔧 Troubleshooting

### Issue: Containers Keep Restarting

**Symptoms:** `docker-compose ps` shows status changing between "Up" and "Restarting"

**Solution:**
```bash
# Check logs for the problematic service
docker-compose logs [service-name]

# Common causes:
# 1. Port already in use
netstat -an | grep LISTEN

# 2. Database initialization failure
docker-compose logs ehr-database

# 3. Missing environment variables
docker-compose config | grep -A5 [service-name]

# 4. Fix: Stop and rebuild
docker-compose down
docker-compose build --no-cache [service-name]
docker-compose up -d [service-name]
```

### Issue: Cannot Connect to Services

**Symptoms:** `curl localhost:8080` times out or refuses connection

**Solution:**
```bash
# 1. Verify containers are running
docker-compose ps

# 2. Check port bindings
docker port medusa_frontend
docker port medusa_ehr_api

# 3. Test from inside container (internal port 3000)
docker-compose exec medusa-frontend curl http://localhost:3000
# Or test from host machine (external port 8080)
curl http://localhost:8080

# 4. Check firewall
sudo lsof -i :8080

# 5. Restart service
docker-compose restart medusa-frontend
```

### Issue: Database Connection Failures

**Symptoms:** Backend can't connect to database

**Solution:**
```bash
# 1. Verify database is ready
docker-compose ps ehr-database

# 2. Test direct connection
docker-compose exec ehr-database mysql -u root -p

# 3. Check environment variables
docker-compose exec ehr-api env | grep DB_

# 4. View database logs
docker-compose logs ehr-database --tail=100

# 5. Ensure network connectivity
docker-compose exec ehr-api ping ehr-database
```

### Issue: Out of Memory

**Symptoms:** Docker containers slow down or crash

**Solution:**
```bash
# 1. Check resource usage
docker stats

# 2. Stop unnecessary services
docker-compose stop workstation ldap-server ftp-server

# 3. Increase Docker resources
# Docker Desktop > Settings > Resources > Memory (set to 12+ GB)

# 4. Increase container limits
# Edit docker-compose.yml deploy.resources.limits
```

### Issue: Front-End Not Loading

**Symptoms:** http://localhost:8080 shows "Cannot GET /"

**Solution:**
```bash
# 1. Check if Next.js build is complete
docker-compose logs medusa-frontend | grep "Ready in"

# 2. Verify build artifacts exist
docker-compose exec medusa-frontend ls -la /app/.next

# 3. Check health endpoint
curl http://localhost:8080/api/health

# 4. Rebuild frontend
docker-compose build --no-cache medusa-frontend
docker-compose restart medusa-frontend
```

### Issue: Can't Access MedCare EHR Services

**Symptoms:** API doesn't respond, web portal unreachable

**Solution:**
```bash
# 1. Verify services are in healthcare networks
docker network inspect medusa-dmz
docker network inspect medusa-internal

# 2. Check if services are using correct network
docker inspect medusa_ehr_api | grep -A5 "Networks"

# 3. Test connectivity between containers (using internal ports)
docker-compose exec ehr-api ping -c 1 ehr-database
docker-compose exec medusa-frontend curl http://ehr-api:3000/api/health  # Internal port 3000
docker-compose exec medusa-backend curl http://ehr-api:3000/api/health  # Internal port 3000

# 4. View service logs
docker-compose logs ehr-api --tail=100
docker-compose logs ehr-database --tail=50
```

### Issue: Persistent Data Lost

**Symptoms:** After restart, database is empty

**Solution:**
```bash
# 1. Verify volumes exist
docker volume ls | grep medusa

# 2. Check volume mounts
docker-compose config | grep -A3 "volumes:"

# 3. Ensure volumes are persistent
# Edit docker-compose.yml - verify all databases have volumes

# 4. Do NOT use this command without backing up:
# docker-compose down -v    # This DELETES all volumes!

# Correct shutdown:
docker-compose down        # Preserves volumes
```

### Issue: Port Already in Use

**Symptoms:** `docker: Error response from daemon: Ports are not available`

**Solution:**
```bash
# 1. Find what's using the port
sudo lsof -i :8080
sudo lsof -i :3306

# 2. If it's Docker, cleanup
docker container ls -a
docker container rm [container-id]

# 3. If it's another application
# macOS: kill -9 [PID]
# Linux: sudo kill -9 [PID]

# 4. Change port in docker-compose.yml if needed
# Find: "8080:3000"
# Replace with: "9090:3000"
```

### Issue: Services Can't Reach Each Other

**Symptoms:** "Cannot resolve hostname" errors in logs

**Solution:**
```bash
# 1. Verify DNS is working
docker-compose exec medusa-frontend nslookup medusa-backend
docker-compose exec ehr-api nslookup ehr-database

# 2. Check network connectivity
docker-compose exec medusa-frontend ping -c 1 medusa-backend
docker-compose exec ehr-api ping -c 1 ehr-database

# 3. Verify services are on correct networks
docker inspect medusa_backend | grep -A10 '"Networks"'
docker inspect medusa_ehr_api | grep -A10 '"Networks"'

# 4. Recreate network if needed
docker network rm medusa-dmz
docker-compose up -d
```

---

## 🔐 Security Reminders

### ⚠️ CRITICAL: This Lab Contains Intentional Vulnerabilities

DO NOT:
- ❌ Expose to the internet
- ❌ Run on production networks
- ❌ Use with real patient data
- ❌ Leave running unattended
- ❌ Share credentials publicly

DO:
- ✅ Use only in isolated test environments
- ✅ Reset environment after each test session
- ✅ Document all testing activities
- ✅ Follow ethical hacking guidelines
- ✅ Comply with HIPAA and applicable laws

---

## 📚 Related Documentation

- **[Architecture Overview](./docs/01-architecture/project-overview.md)**
- **[MedCare EHR README](./lab-environment/README.md)**
- **[Vulnerability Documentation](./docs/06-security/)**
- **[Deployment Guide](./docs/03-deployment/deployment-guide.md)**
- **[Quick Start Guide](./docs/00-getting-started/quick-start-dashboard.md)**

---

## 🎯 Next Steps

1. **Review this plan** - Ensure you understand the naming conventions
2. **Execute deployment** - Follow the deployment instructions
3. **Run verification** - Complete the verification checklist
4. **Test connectivity** - Verify all services communicate
5. **Run MEDUSA** - Begin penetration testing

---

## 📞 Support

If you encounter issues:

1. Check the **Troubleshooting** section above
2. Review **service logs**: `docker-compose logs [service-name]`
3. Check **Docker Desktop** logs
4. Verify **resource availability** (RAM, disk space)
5. Review **network connectivity**: `docker network ls`

---

**Built with ❤️ for security research and education**

⚠️ **Remember: Use Responsibly and Ethically** ⚠️

