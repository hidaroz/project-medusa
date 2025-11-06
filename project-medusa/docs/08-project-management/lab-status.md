# Lab Environment Status Report

> ⚠️ **HISTORICAL DOCUMENT** - This document describes an older architecture.
>
> **Current Architecture**:
> - **MEDUSA AI Agent** (Attacker): `medusa-cli` (Python), `medusa-webapp` (React control interface)
> - **MedCare EHR System** (Target): All services in `lab-environment/` including `ehr-api`, `ehr-webapp`, etc.
>
> The "medusa-backend" and "medusa-frontend" referenced below were early implementations that have been superseded.
> See current lab setup: [lab-environment/README.md](../../lab-environment/README.md)

---

**Generated:** $(date)

## ✅ Service Status Summary (Historical)

### Core MEDUSA Services (Deprecated)
- ⚠️ **medusa-frontend** (Next.js) - Port 3000 - **DEPRECATED** (now part of lab environment)
- ⚠️ **medusa-backend** (FastAPI) - Port 8000 - **DEPRECATED** (replaced by ehr-api in lab)
- ⚠️ **medusa-postgres** (PostgreSQL) - **DEPRECATED**
- ⚠️ **medusa-redis** (Redis) - **DEPRECATED**

### Lab Environment Services
- ✅ **medusa_ehr_web** (PHP Web Portal) - Port 8080 - **HEALTHY**
- ✅ **medusa_ehr_api** (Node.js API) - Port 3001 - **HEALTHY**
- ✅ **medusa_ehr_db** (MySQL Database) - Port 3306 - **RUNNING**
- ✅ **medusa_logs** (Log Collector) - Port 8081 - **HEALTHY**
- ✅ **medusa_ssh_server** (SSH Server) - Port 2222 - **HEALTHY**
- ⚠️ **medusa_ftp_server** (FTP Server) - Port 21 - **UNHEALTHY** (expected)
- ✅ **medusa_ldap** (LDAP Server) - Ports 389/636 - **RUNNING**
- ⚠️ **medusa_workstation** (Workstation) - **RESTARTING** (expected)

---

## 🔌 Connectivity Tests

### Frontend (Next.js) ✅
- **Accessible:** http://localhost:3000 ✅
- **Health Endpoint:** http://localhost:3000/api/health ✅
- **Backend Connection:** ✅ Can reach `medusa-backend:8000`
- **EHR API Connection:** ⚠️ Network configuration updated, needs verification

### Backend (FastAPI) ✅
- **Accessible:** http://localhost:8000 ✅
- **Health Endpoint:** http://localhost:8000/health ✅
- **Database:** ✅ Connected to PostgreSQL
- **Redis:** ✅ Connected

### EHR API ✅
- **Accessible:** http://localhost:3001 ✅
- **Health Endpoint:** http://localhost:3001/api/health ✅
- **Database:** ✅ Connected to MySQL (50 patients loaded)

### EHR Database ✅
- **Accessible:** localhost:3306 ✅
- **Patients:** 50 records loaded ✅
- **Connection:** ✅ EHR API connected successfully

---

## 🌐 Network Configuration

### Networks
- **medusa-dmz** (172.22.0.0/24)
  - medusa-frontend ✅
  - medusa-backend ✅

- **healthcare-dmz** (172.20.0.0/24)
  - medusa_ehr_web ✅
  - medusa_ehr_api ✅
  - medusa-frontend ✅ (added for EHR API access)

- **healthcare-internal** (172.21.0.0/24)
  - medusa_ehr_db ✅
  - medusa_ehr_api ✅
  - medusa_ehr_web ✅
  - medusa-backend ✅ (for lab access)

---

## 📊 Environment Variables

### Frontend Environment
```
NEXT_PUBLIC_MEDUSA_API_URL=http://localhost:8000
NEXT_PUBLIC_MEDUSA_WS_URL=ws://localhost:8000/ws
NEXT_PUBLIC_EHR_API_URL=http://localhost:3001/api
NODE_ENV=production
```

---

## 🔍 Verification Commands

### Check Service Status
```bash
docker-compose ps
```

### Test Frontend
```bash
curl http://localhost:3000/api/health
curl http://localhost:3000
```

### Test Backend
```bash
curl http://localhost:8000/health
```

### Test EHR API
```bash
curl http://localhost:3001/api/health
curl http://localhost:3001/api/patients | jq '.count'
```

### Test Database
```bash
docker exec medusa_ehr_db mysql -uehrapp -pWelcome123! -e "SELECT COUNT(*) FROM healthcare_db.patients;"
```

### Test Network Connectivity
```bash
# Frontend to Backend
docker exec medusa_frontend wget -qO- http://medusa-backend:8000/health

# Frontend to EHR API
docker exec medusa_frontend wget -qO- http://ehr-api:3000/api/health
```

---

## ⚠️ Known Issues

1. **Workstation Container** - Restarting (expected behavior for VNC setup)
2. **FTP Server** - Unhealthy (healthcheck may need adjustment)
3. **Frontend to EHR API** - Network connectivity added, needs verification after restart

---

## ✅ Success Criteria Met

- [x] Next.js frontend built and running
- [x] Frontend accessible on port 3000
- [x] Backend accessible on port 8000
- [x] EHR API accessible on port 3001
- [x] Database contains 50 patient records
- [x] Frontend can reach backend
- [x] Network configuration updated for EHR API access
- [ ] Frontend to EHR API connectivity verified (needs container restart)

---

## 🚀 Next Steps

1. Verify frontend can reach EHR API after network update
2. Test full application flow (login → dashboard → patient data)
3. Verify WebSocket connectivity for real-time updates
4. Test MEDUSA backend integration with lab environment

