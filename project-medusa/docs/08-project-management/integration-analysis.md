# MEDUSA Frontend-Backend Integration Analysis

## Executive Summary
The MEDUSA project has a **partial but incomplete integration** between the frontend (Next.js) and backend (FastAPI). The system is designed as a penetration testing platform with an integrated EHR system for testing purposes. Current implementation shows scaffolding in place but lacks actual database-backed API endpoints.

---

## 1. FRONTEND STRUCTURE (medusa-webapp)

### Technology Stack
- **Framework**: Next.js 14 (with TypeScript)
- **UI Framework**: Tailwind CSS
- **State Management**: React Hooks
- **API Communication**: Fetch API

### Pages and Components
```
medusa-webapp/src/
├── app/
│   ├── api/
│   │   └── health/route.ts              # Basic health check endpoint
│   ├── patients/
│   │   ├── page.tsx                     # Patient list view
│   │   └── search/page.tsx              # Patient search
│   ├── patient/[id]/page.tsx            # Individual patient details
│   ├── clinical/
│   │   ├── notes/page.tsx               # Clinical notes
│   │   ├── orders/page.tsx              # Medical orders
│   │   └── results/page.tsx             # Lab results
│   ├── medications/page.tsx             # Medication management
│   ├── appointments/page.tsx            # Appointment scheduling
│   ├── dashboard/page.tsx               # Main dashboard
│   ├── medusa/page.tsx                  # MEDUSA pentesting interface
│   ├── reports/page.tsx                 # Report generation
│   └── admin/sensitive-data/page.tsx    # Sensitive data dashboard
├── components/
│   ├── Layout.tsx                       # Main layout wrapper
│   └── Navigation.tsx                   # Navigation component
└── lib/
    ├── api.ts                           # API client with mock functions
    ├── patients.ts                      # Patient data definitions (mock)
    ├── employees.ts                     # Employee data definitions (mock)
    └── system-config.ts                 # System configuration (mock)
```

### API Integration Points
The frontend uses `src/lib/api.ts` as the centralized API client:
- **Base URL**: `http://localhost:3001/api` (configured in docker-compose)
- **Functions Implemented**:
  - `getAllPatients()` - Fetch all patient records
  - `getPatientById(id)` - Fetch specific patient
  - `getPatientSensitiveData(id)` - Fetch sensitive patient data
  - `getAllEmployees()` - Fetch all employees
  - `getEmployeeById(id)` - Fetch specific employee
  - `getEmployeeCredentials(id)` - Fetch employee credentials
  - `checkHealth()` - Health check endpoint
  - `getSystemConfig()` - Mock system configuration

### Data Models in Frontend
**Patient Interface** includes:
- Basic info: ID, name, DOB, gender, blood type
- Contact: phone, email, address
- Medical: allergies, conditions, medications
- Records: vital signs, lab results, appointments
- **Sensitive**: SSN, driver's license, financial info, biometric data, family history

**Employee Interface** includes:
- Basic info: ID, name, email, department
- **Sensitive**: SSN, credentials, salary, financial info, background check data

---

## 2. BACKEND STRUCTURE (medusa-backend)

### Technology Stack
- **Framework**: FastAPI (Python 3.11)
- **Server**: Uvicorn
- **WebSocket**: Native FastAPI WebSocket support
- **Database**: PostgreSQL (configured but not actively used for EHR)
- **Cache**: Redis (configured but not actively used)
- **Container Runtime**: Docker client integration

### Backend Endpoints Implemented

#### Health Check Endpoints
```
GET /health                 → Basic health status
GET /api/health            → Detailed health with component status
```

#### Session Management Endpoints
```
POST /api/sessions              → Create new penetration test session
GET /api/sessions              → List all active sessions
GET /api/sessions/{session_id} → Get specific session details
DELETE /api/sessions/{session_id} → Delete session
```

#### WebSocket Endpoint
```
WS /ws/{session_id}  → Real-time communication channel
    Supports message types:
    - ping/pong
    - start_scan
    - command (CLI integration pending)
    - approval_response
    - stop
    - terminal_output
    - finding (vulnerability reports)
```

#### Docker Management Endpoints
```
GET /api/docker/containers → List MEDUSA containers
GET /api/docker/networks   → List lab environment networks
```

### Backend File Structure
```
medusa-backend/
├── app/
│   ├── main.py             # FastAPI application (11KB)
│   ├── config.py           # Configuration management
│   ├── session.py          # Session management (112 lines)
│   ├── websocket.py        # WebSocket handlers (322 lines)
│   └── __init__.py         # Package init
├── Dockerfile              # Multi-stage build
└── requirements.txt        # Python dependencies
```

### Key Classes/Components
1. **Session**: Represents a pentesting session
   - Fields: session_id, status, mode, target, findings, history
   
2. **SessionManager**: Manages active sessions
   - Methods: create, get, update, delete, cleanup
   
3. **ConnectionManager**: Manages WebSocket connections
   - Methods: connect, disconnect, send_message, broadcast

---

## 3. DOCKER ARCHITECTURE & NETWORKING

### Service Stack (docker-compose.yml)

#### MEDUSA Services
| Service | Port | Technology | Status |
|---------|------|-----------|--------|
| medusa-frontend | 3000 | Next.js | Health checked |
| medusa-backend | 8000 | FastAPI | Health checked |
| medusa-postgres | 5432 | PostgreSQL | Configured, not used |
| medusa-redis | 6379 | Redis | Configured, not used |

#### Lab Environment (Vulnerable by Design)
| Service | Port | Technology | Purpose |
|---------|------|-----------|---------|
| ehr-webapp | 8080 | PHP | Public EHR portal |
| ehr-api | 3001 | Node.js | EHR REST API |
| ehr-database | 3306 | MySQL | Patient data store |
| ssh-server | 2222 | OpenSSH | Admin access |
| ftp-server | 21 | vsftp | File storage |
| ldap-server | 389/636 | OpenLDAP | User directory |
| log-collector | 5514/8081 | Syslog | Log aggregation |
| workstation | 445/3389 | Simulated Windows | SMB/RDP access |

### Networks
```
medusa-dmz (172.22.0.0/24)           ← Frontend & Backend only
healthcare-dmz (172.20.0.0/24)       ← Public lab services
healthcare-internal (172.21.0.0/24)  ← Internal lab services
```

### Environment Configuration
Frontend configured to reach:
- MEDUSA Backend: `http://localhost:8000`
- MEDUSA WebSocket: `ws://localhost:8000/ws`
- EHR API: `http://localhost:3001/api`

---

## 4. WHAT'S CURRENTLY IMPLEMENTED

### Working Components
1. **Frontend Pages**: All UI pages render successfully
2. **Mock Data**: Patient/employee data fully mocked in TypeScript
3. **WebSocket Infrastructure**: Connection manager and message handling
4. **Session Management**: Basic session lifecycle (create, store, delete)
5. **Docker Integration**: Can list containers and networks
6. **Health Checks**: Basic and detailed health endpoints

### Partial Implementations
1. **API Client**: Functions defined but returning mock data
2. **Database Configuration**: PostgreSQL configured, not connected
3. **CLI Integration**: WebSocket ready but no actual CLI calls
4. **EHR API Integration**: Docker-compose references it (port 3001) but frontend not actually calling it

---

## 5. WHAT'S MISSING FOR WORKING INTEGRATION

### Critical Gaps

#### 1. Backend API Endpoints for EHR Data
**Missing**: No actual API endpoints for patient/employee data
```python
# MISSING in medusa-backend/app/main.py:
@app.get("/api/patients")
@app.get("/api/patients/{id}")
@app.post("/api/patients")
@app.put("/api/patients/{id}")
@app.delete("/api/patients/{id}")

@app.get("/api/employees")
@app.get("/api/employees/{id}")
@app.get("/api/employees/{id}/credentials")
# ... etc
```

#### 2. Database Models & ORM
**Missing**: No SQLAlchemy models for:
- Patient records
- Employee records
- Medical history
- Findings/reports

#### 3. Database Connection
**Missing**: 
- No actual PostgreSQL connection in backend
- Redis client not initialized
- Session storage still in-memory only

#### 4. EHR API Integration
The EHR API (Node.js on port 3001) exists but:
- Backend doesn't call it
- No proxy endpoints
- Frontend doesn't have endpoints for actual EHR data

#### 5. Authentication/Authorization
**Missing Entirely**:
- No JWT token generation
- No user authentication
- No permission checking
- No role-based access control

#### 6. Data Persistence
**Missing**:
- Sessions stored in memory (lost on restart)
- Findings not persisted
- No audit trail

#### 7. CLI Integration
**Pending**: WebSocket ready but no actual:
- Command execution routing
- Tool integration (nmap, web scanners, etc.)
- Output capture and streaming

---

## 6. INTEGRATION FLOW (Current vs. Needed)

### Current Flow (Broken)
```
Frontend (Mock Data)
  → api.ts client function
  → fetch("http://localhost:3001/api/...")
  → ??? (No actual endpoint)
  → Returns error/nothing
```

### Needed Flow
```
Frontend (Next.js)
  → Calls api.ts functions
  → HTTP request to medusa-backend:8000/api/...
  → Backend validates request
  → Queries PostgreSQL via SQLAlchemy ORM
  → Returns EHR data as JSON
  → Frontend displays data
  → User initiates pentest via MEDUSA page
  → WebSocket connects: ws://medusa-backend:8000/ws/{sessionId}
  → Backend executes CLI via Docker
  → Streams results back via WebSocket
  → Frontend displays findings
```

---

## 7. CONFIGURATION REVIEW

### Frontend Configuration
```typescript
// src/lib/api.ts
const API_BASE_URL = 'http://localhost:3001/api';  // Wrong! Should be :8000
```
**Issue**: Frontend points to EHR API (port 3001) instead of MEDUSA Backend (port 8000)

### Backend Configuration
```python
# app/config.py
database_url = "postgresql://medusa:medusa_password@postgres:5432/medusa_db"
redis_url = "redis://redis:6379/0"
```
**Status**: Configured but not used

### Docker Compose Configuration
```yaml
# Correct setup:
- medusa-frontend → medusa-backend (8000)
- medusa-backend → medusa-postgres (5432)
- medusa-backend → medusa-redis (6379)
- ehr-api → ehr-database (3306)
```
**Status**: Correct, all connections defined

---

## 8. RECOMMENDATIONS FOR COMPLETE INTEGRATION

### Phase 1: Fix Frontend-Backend Communication (High Priority)
1. **Fix API endpoint** in `src/lib/api.ts`:
   ```typescript
   const API_BASE_URL = 'http://localhost:8000/api';  // Change from 3001 to 8000
   ```

2. **Implement backend endpoints** in `medusa-backend/app/main.py`:
   ```python
   @app.get("/api/patients")
   async def list_patients():
       # Query database via ORM
       patients = await db.query(Patient).all()
       return {"success": True, "data": patients}
   ```

### Phase 2: Database Integration (High Priority)
1. Create SQLAlchemy models in `medusa-backend/app/models.py`
2. Initialize PostgreSQL connection in `main.py`
3. Add database initialization scripts
4. Migrate mock data to database

### Phase 3: Authentication (Medium Priority)
1. Add JWT token generation
2. Implement login endpoint
3. Add auth middleware
4. Secure sensitive endpoints

### Phase 4: CLI Integration (Medium Priority)
1. Integrate medusa-cli module
2. Handle WebSocket messages → CLI calls
3. Stream output back to frontend
4. Persist findings to database

### Phase 5: EHR API Integration (Low Priority - Optional)
- Option A: Use MEDUSA backend as proxy to EHR API
- Option B: Replace EHR API with MEDUSA backend endpoints

---

## 9. TECHNOLOGY DEBT & ISSUES

1. **Mock Data Hardcoded**: Patient/employee data in TypeScript (should be database)
2. **Sensitive Data Exposed**: Credentials, SSN, credit cards visible in code
3. **No Input Validation**: API doesn't validate incoming requests
4. **No Error Handling**: Limited error handling in WebSocket
5. **No Logging**: Minimal structured logging
6. **No Tests**: No unit/integration tests visible
7. **In-Memory Sessions**: Will be lost on server restart
8. **No Rate Limiting**: No protection against abuse

---

## 10. QUICK TEST CHECKLIST

To verify current state:
```bash
# Check if services start
docker-compose up -d

# Check frontend
curl http://localhost:3000/api/health

# Check backend  
curl http://localhost:8000/health
curl http://localhost:8000/api/health

# Check EHR API (if running)
curl http://localhost:3001/api/patients

# Try frontend API call (will fail)
curl http://localhost:3001/api/patients  # Wrong URL!

# WebSocket test (won't work without proper session)
wscat -c ws://localhost:8000/ws/test-session-id
```

---

## Summary Table

| Area | Status | Implementation | Notes |
|------|--------|-----------------|-------|
| Frontend UI | ✅ Complete | All pages present | Using mock data |
| Backend API Endpoints | ❌ Missing | 0% | Critical gap |
| Database Models | ❌ Missing | 0% | Critical gap |
| Database Connection | ❌ Missing | 0% | Critical gap |
| WebSocket Infrastructure | ✅ Complete | 100% | Ready for use |
| Session Management | ⚠️ Partial | 50% | In-memory only |
| Authentication | ❌ Missing | 0% | Not implemented |
| CLI Integration | ⚠️ Partial | 30% | WebSocket ready, CLI not connected |
| EHR Data Integration | ❌ Missing | 0% | Wrong API endpoint |
| Docker Setup | ✅ Complete | 100% | All services defined |
| Configuration | ✅ Complete | 100% | But not used |

