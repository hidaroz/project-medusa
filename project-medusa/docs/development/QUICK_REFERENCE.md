# MEDUSA Integration - Quick Reference

## Current Status: PARTIALLY IMPLEMENTED (Est. 40% Complete)

### What Works
- Frontend UI: 100% - All pages render
- WebSocket: 100% - Connection and message handling
- Session Management: 50% - In-memory only (no persistence)
- Docker Integration: 100% - Can list containers/networks
- Backend Health Checks: 100%

### What's Broken/Missing
- EHR API Integration: 0% - Wrong endpoint
- Database Persistence: 0% - No ORM models
- Authentication: 0% - No auth system
- CLI Integration: 30% - WebSocket ready, no execution
- Data Endpoints: 0% - No /api/patients, /api/employees

---

## Critical Issue: Wrong API Endpoint

### File: `medusa-webapp/src/lib/api.ts` - Line 3
```typescript
// WRONG - Points to EHR API
const API_BASE_URL = 'http://localhost:3001/api';

// SHOULD BE - Points to MEDUSA Backend
const API_BASE_URL = 'http://localhost:8000/api';
```

**Impact**: ALL API calls to fetch patient/employee data fail silently

---

## File Locations

| Component | Location | Size |
|-----------|----------|------|
| Frontend | `medusa-webapp/src/` | 21 files |
| Backend | `medusa-backend/app/` | 5 files |
| API Client | `medusa-webapp/src/lib/api.ts` | 299 lines |
| Mock Data | `medusa-webapp/src/lib/patients.ts` | 788 lines |
| Mock Data | `medusa-webapp/src/lib/employees.ts` | 438 lines |
| Pentesting | `medusa-backend/app/websocket.py` | 322 lines |
| Sessions | `medusa-backend/app/session.py` | 111 lines |

---

## Database Situation

### PostgreSQL (Configured but UNUSED)
```
Host: medusa-postgres:5432
User: medusa
Pass: medusa_password
DB: medusa_db
Status: Running but empty - no tables created
```

### Redis (Configured but UNUSED)
```
Host: medusa-redis:6379
Status: Running but not used
```

### MySQL (EHR Database - SEPARATE)
```
Host: ehr-database:3306
User: ehrapp
Pass: Welcome123!
DB: healthcare_db
Status: Running with mock medical data
```

---

## API Endpoints (Backend)

### IMPLEMENTED
```
GET  /health                    ✅ Health check
GET  /api/health               ✅ Detailed health
POST /api/sessions             ✅ Create session
GET  /api/sessions             ✅ List sessions
GET  /api/sessions/{id}        ✅ Get session
DEL  /api/sessions/{id}        ✅ Delete session
WS   /ws/{session_id}          ✅ WebSocket
GET  /api/docker/containers    ✅ List containers
GET  /api/docker/networks      ✅ List networks
```

### MISSING
```
GET  /api/patients             ❌ CRITICAL
GET  /api/patients/{id}        ❌ CRITICAL
POST /api/patients             ❌ CRITICAL
GET  /api/employees            ❌ CRITICAL
GET  /api/employees/{id}       ❌ CRITICAL
GET  /api/employees/{id}/credentials ❌ CRITICAL
POST /api/auth/login           ❌ CRITICAL
```

---

## Environment Variables

### Frontend (docker-compose.yml)
```
NEXT_PUBLIC_MEDUSA_API_URL=http://localhost:8000        ✅ Correct
NEXT_PUBLIC_MEDUSA_WS_URL=ws://localhost:8000/ws        ✅ Correct
NEXT_PUBLIC_EHR_API_URL=http://localhost:3001/api       ✅ Correct
NODE_ENV=production                                     ✅ Correct
```

### Backend (docker-compose.yml)
```
ENVIRONMENT=production                                  ✅ Correct
API_HOST=0.0.0.0                                       ✅ Correct
API_PORT=8000                                          ✅ Correct
DATABASE_URL=postgresql://medusa:...@medusa-postgres   ⚠️ Not used
REDIS_URL=redis://medusa-redis:6379/0                  ⚠️ Not used
DOCKER_HOST=unix:///var/run/docker.sock               ✅ Correct
GEMINI_API_KEY=${GEMINI_API_KEY}                       ⚠️ Optional
```

---

## Mock Data Summary

### Patients (5 records)
- P001: Sarah Johnson (Diabetes, Depression)
- P002: Robert Martinez (Asthma, Substance abuse)
- P003: Emily Chen (Migraines, HIV+, Bipolar)
- P004: James Williams (Heart disease, Sleep apnea)
- P005: Lisa Anderson (Celiac, Anemia)

**File**: `medusa-webapp/src/lib/patients.ts`

### Employees (4 records)
- E001: Dr. Emily Chen (Physician) - Password: Password123!
- E002: Dr. James Wilson (Physician) - Password: SecurePass456!
- E003: Sarah Thompson (CMO) - Password: AdminPass789!
- E004: Nurse Smith (RN) - Password: NursePass123!

**File**: `medusa-webapp/src/lib/employees.ts`

### System Config (Hardcoded)
- Database: prod-db.medcare.internal / SuperSecurePassword123!
- API Key: sk-prod-1234567890abcdef
- JWT Secret: jwt-secret-key-for-token-signing
- AWS: AKIAIOSFODNN7EXAMPLE

**File**: `medusa-webapp/src/lib/api.ts` (lines 275-298)

---

## Docker Architecture

### Networks
| Network | Subnet | Purpose |
|---------|--------|---------|
| medusa-dmz | 172.22.0.0/24 | Frontend + Backend |
| healthcare-dmz | 172.20.0.0/24 | Public lab services |
| healthcare-internal | 172.21.0.0/24 | Internal lab services |

### Services
| Service | Port | Technology | Status |
|---------|------|-----------|--------|
| medusa-frontend | 3000 | Next.js | Running |
| medusa-backend | 8000 | FastAPI | Running |
| medusa-postgres | 5432 | PostgreSQL | Unused |
| medusa-redis | 6379 | Redis | Unused |
| ehr-api | 3001 | Node.js | Running |
| ehr-database | 3306 | MySQL | Running |
| ehr-webapp | 8080 | PHP | Running |

---

## Minimum Work to Make Working

### Phase 1: Fix Endpoint (1 hour)
1. Change `const API_BASE_URL = 'http://localhost:8000/api'` in `api.ts`
2. Test frontend API calls

### Phase 2: Add Backend Endpoints (2-3 hours)
1. Create endpoints in `medusa-backend/app/main.py`:
   - `GET /api/patients`
   - `GET /api/patients/{id}`
   - `GET /api/employees`
   - `GET /api/employees/{id}`

2. Return mock data from memory (temporary)

### Phase 3: Add Database Models (4-5 hours)
1. Create `medusa-backend/app/models.py`
2. Define SQLAlchemy models
3. Initialize PostgreSQL connection
4. Migrate mock data to database

### Phase 4: Add Authentication (3-4 hours)
1. Add JWT generation
2. Create `/api/auth/login` endpoint
3. Add auth middleware to endpoints
4. Secure sensitive endpoints

### Phase 5: CLI Integration (5-6 hours)
1. Connect medusa-cli to backend
2. Route WebSocket commands to CLI
3. Stream output back to frontend
4. Persist findings to database

**Estimated Total: 15-18 hours for working integration**

---

## Quick Commands

### Start Everything
```bash
cd /Users/hidaroz/INFO492/devprojects/project-medusa
docker-compose up -d
```

### Start Only MEDUSA (No Lab)
```bash
docker-compose up -d medusa-frontend medusa-backend medusa-postgres medusa-redis
```

### View Logs
```bash
docker-compose logs -f medusa-backend
docker-compose logs -f medusa-frontend
```

### Test Endpoints
```bash
# Health check
curl http://localhost:8000/health

# Detailed health
curl http://localhost:8000/api/health

# List sessions
curl http://localhost:8000/api/sessions

# Create session
curl -X POST http://localhost:8000/api/sessions \
  -H "Content-Type: application/json" \
  -d '{"target":"192.168.1.1","mode":"observe"}'

# WebSocket test
wscat -c ws://localhost:8000/ws/test-session
```

### Database Access
```bash
# PostgreSQL
psql -h localhost -p 5432 -U medusa -d medusa_db

# MySQL (EHR)
mysql -h localhost -P 3306 -u ehrapp -pWelcome123! healthcare_db
```

---

## Sensitive Data Exposed

### In Frontend Code
- 5 complete patient records with SSN, credit cards, medical history
- 4 complete employee records with passwords, credentials
- System configuration with database credentials

### In Configuration
- EHR database password: Welcome123!
- SSH server credentials
- LDAP admin password: admin123

**Security Note**: This is intentional for security testing, but clearly marks sensitive data in code.

---

## Key Dependencies

### Backend (Python)
- FastAPI 0.109.0
- Uvicorn 0.27.0
- SQLAlchemy 2.0.25
- Pydantic 2.5.3
- Docker SDK 7.0.0

### Frontend (Node.js)
- Next.js 14
- React 18
- TypeScript
- Tailwind CSS

---

## Contact Points

### Frontend → Backend
```
Port: 8000
Protocol: HTTP + WebSocket
Base Path: /api
Auth: None (TODO)
```

### Backend → Database
```
PostgreSQL: postgres://medusa@medusa-postgres:5432/medusa_db
Redis: redis://medusa-redis:6379/0
Status: Configured but unused
```

### Backend → Lab Services
```
EHR API: http://ehr-api:3000
MySQL: ehr-database:3306
SSH: ssh-server:22
LDAP: ldap-server:389
Docker: /var/run/docker.sock
```

---

## Debugging Checklist

- [ ] Frontend loads on localhost:3000?
- [ ] Backend responds to localhost:8000/health?
- [ ] WebSocket connects on ws://localhost:8000/ws/test?
- [ ] Database containers running?
- [ ] Check logs for errors?
- [ ] API endpoint URL correct in frontend?
- [ ] CORS issues in browser console?
- [ ] Network connectivity between services?

---

## References

- Full Analysis: `INTEGRATION_ANALYSIS.md`
- Technical Details: `TECHNICAL_REFERENCE.md`
- Docker Compose: `docker-compose.yml`
- Backend Entry: `medusa-backend/app/main.py`
- Frontend API: `medusa-webapp/src/lib/api.ts`

