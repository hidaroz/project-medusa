# MEDUSA - Technical Reference & Implementation Details

## File Structure Overview

### Frontend File Locations
```
/Users/hidaroz/INFO492/devprojects/project-medusa/medusa-webapp/
├── src/
│   ├── app/
│   │   ├── api/health/route.ts                          # Health check (13 lines)
│   │   ├── admin/sensitive-data/page.tsx                # Sensitive data dashboard (378 lines)
│   │   ├── patient/[id]/page.tsx                        # Patient detail view
│   │   ├── patients/page.tsx                            # Patient list (268 lines)
│   │   ├── patients/search/page.tsx                     # Patient search
│   │   ├── clinical/{notes,orders,results}/page.tsx    # Clinical data views
│   │   ├── medications/page.tsx                         # Medication management
│   │   ├── appointments/page.tsx                        # Appointment booking
│   │   ├── dashboard/page.tsx                           # Main dashboard
│   │   ├── medusa/page.tsx                              # Pentesting interface
│   │   ├── reports/page.tsx                             # Report generation
│   │   └── layout.tsx                                   # Root layout
│   ├── components/
│   │   ├── Layout.tsx                                   # Main layout wrapper
│   │   └── Navigation.tsx                               # Navigation bar
│   └── lib/
│       ├── api.ts                                       # API client (299 lines)
│       ├── patients.ts                                  # Patient mock data (788 lines)
│       ├── employees.ts                                 # Employee mock data (438 lines)
│       └── system-config.ts                             # System config mock
├── Dockerfile                                           # Next.js container
├── package.json
├── tsconfig.json
└── tailwind.config.js
```

### Backend File Locations
```
/Users/hidaroz/INFO492/devprojects/project-medusa/medusa-backend/
├── app/
│   ├── main.py                                          # FastAPI app (370 lines)
│   ├── config.py                                        # Settings (61 lines)
│   ├── session.py                                       # Session management (111 lines)
│   ├── websocket.py                                     # WebSocket handlers (322 lines)
│   └── __init__.py                                      # Package init
├── Dockerfile                                           # Python container
├── requirements.txt                                     # Python dependencies
└── README.md
```

### EHR System Files
```
/Users/hidaroz/INFO492/devprojects/project-medusa/lab-environment/services/
├── ehr-api/
│   └── src/server.js                                    # Node.js API
├── ehr-webapp/
│   └── [PHP application]                               # Public web interface
├── ehr-database/
│   └── [MySQL database initialization]
├── ssh-server/                                          # SSH access point
├── ftp-server/                                          # File storage
├── ldap-server/                                         # Directory service
├── workstation/                                         # Windows simulation
└── log-collector/                                       # Centralized logging
```

---

## API Endpoint Specifications

### Current Frontend API Calls (from src/lib/api.ts)

#### Patient Endpoints
```typescript
// GET /api/patients
getAllPatients(): Promise<Patient[]>
  Returns: Array of 5 mock patients (P001-P005)
  Current Status: BROKEN - points to port 3001 instead of 8000

// GET /api/patients/{id}
getPatientById(id: string): Promise<Patient>
  Returns: Single patient object
  Current Status: BROKEN

// GET /api/patients/{id}/sensitive
getPatientSensitiveData(id: string): Promise<Patient>
  Returns: Patient with full sensitive data
  Current Status: BROKEN
```

#### Employee Endpoints
```typescript
// GET /api/employees
getAllEmployees(): Promise<Employee[]>
  Returns: Array of 4 mock employees
  Current Status: BROKEN

// GET /api/employees/{id}
getEmployeeById(id: string): Promise<Employee>
  Returns: Single employee object
  Current Status: BROKEN

// GET /api/employees/{id}/credentials
getEmployeeCredentials(id: string): Promise<Employee>
  Returns: Employee with credentials exposed
  Current Status: BROKEN
```

#### Health Check
```typescript
// GET /health (on port 3001)
checkHealth(): Promise<{status: string, timestamp: string}>
  Returns: Health status
  Current Status: WORKS (but hardcoded port)
```

---

## Backend Endpoint Details

### Health & Status Endpoints

#### GET /health
```
Status Code: 200 OK
Response:
{
  "status": "healthy",
  "timestamp": "2024-11-04T20:30:00.123Z",
  "service": "medusa-backend",
  "version": "1.0.0"
}
```

#### GET /api/health (Detailed)
```
Status Code: 200 OK
Response:
{
  "status": "healthy",
  "timestamp": "2024-11-04T20:30:00.123Z",
  "service": "medusa-backend",
  "version": "1.0.0",
  "components": {
    "docker": "available" | "unavailable",
    "gemini_api": "configured" | "not_configured",
    "websocket": "available",
    "sessions": {
      "active": 0,
      "connections": 0
    }
  }
}
```

### Session Management Endpoints

#### POST /api/sessions
```
Request:
{
  "target": "192.168.1.100" (optional),
  "mode": "observe" | "interactive" | "autonomous"
}

Response: 201 Created
{
  "success": true,
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "created_at": "2024-11-04T20:30:00.123Z",
  "status": "initialized",
  "mode": "observe"
}
```

#### GET /api/sessions
```
Response: 200 OK
{
  "sessions": [
    {
      "session_id": "uuid",
      "status": "running",
      "mode": "observe",
      "target": "192.168.1.100",
      "created_at": "2024-11-04T20:30:00.123Z"
    }
  ],
  "count": 1
}
```

#### GET /api/sessions/{session_id}
```
Response: 200 OK
{
  "session_id": "uuid",
  "status": "running",
  "mode": "observe",
  "target": "192.168.1.100",
  "created_at": "2024-11-04T20:30:00.123Z",
  "findings_count": 5,
  "current_phase": "enumeration"
}
```

#### DELETE /api/sessions/{session_id}
```
Response: 200 OK
{
  "success": true,
  "message": "Session deleted"
}
```

### WebSocket Endpoint

#### WS /ws/{session_id}

**Connection Flow:**
```
1. Client connects to ws://backend:8000/ws/session-uuid
2. Server accepts connection
3. Server sends welcome message:
   {
     "type": "connected",
     "session_id": "uuid",
     "timestamp": "2024-11-04T20:30:00.123Z",
     "message": "Connected to MEDUSA Backend"
   }
```

**Message Types:**

1. **Ping/Pong** (Health Check)
```
Client sends:
{
  "type": "ping",
  "data": {}
}

Server responds:
{
  "type": "pong",
  "session_id": "uuid",
  "timestamp": "2024-11-04T20:30:00.123Z"
}
```

2. **Start Scan**
```
Client sends:
{
  "type": "start_scan",
  "data": {
    "target": "192.168.1.100",
    "mode": "observe"
  }
}

Server responds:
{
  "type": "scan_started",
  "session_id": "uuid",
  "target": "192.168.1.100",
  "mode": "observe",
  "timestamp": "2024-11-04T20:30:00.123Z"
}
```

3. **Terminal Output**
```
Server sends (streamed):
{
  "type": "terminal_output",
  "output": "[MEDUSA] Phase: RECONNAISSANCE\n",
  "timestamp": "2024-11-04T20:30:00.123Z"
}
```

4. **Finding** (Vulnerability Discovery)
```
Server sends:
{
  "type": "finding",
  "finding": {
    "phase": "enumeration",
    "type": "info",
    "title": "Open port detected",
    "severity": "medium",
    "timestamp": "2024-11-04T20:30:00.123Z"
  }
}
```

5. **Phase Complete**
```
Server sends:
{
  "type": "phase_complete",
  "phase": "reconnaissance",
  "timestamp": "2024-11-04T20:30:00.123Z"
}
```

6. **Scan Complete**
```
Server sends:
{
  "type": "scan_complete",
  "session_id": "uuid",
  "total_findings": 12,
  "timestamp": "2024-11-04T20:30:00.123Z"
}
```

### Docker Management Endpoints

#### GET /api/docker/containers
```
Response: 200 OK
{
  "containers": [
    {
      "id": "abc123def456",
      "name": "medusa_ehr_web",
      "status": "running",
      "image": "medusa/ehr-webapp:latest",
      "ports": {
        "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]
      }
    }
  ],
  "count": 1
}
```

#### GET /api/docker/networks
```
Response: 200 OK
{
  "networks": [
    {
      "id": "net123abc456",
      "name": "medusa-dmz",
      "driver": "bridge",
      "scope": "local"
    }
  ],
  "count": 1
}
```

---

## Data Models

### Frontend Session Data (In-Memory)
```typescript
interface Session {
  session_id: string;           // UUID
  created_at: datetime;
  status: string;               // "initialized" | "running" | "paused" | "completed" | "error"
  mode: string;                 // "observe" | "interactive" | "autonomous"
  target: string;               // Target IP/hostname
  current_phase: string;        // "reconnaissance" | "enumeration" | "exploitation" | "reporting"
  findings: Finding[];          // Array of discovered vulnerabilities
  history: HistoryEntry[];      // Array of commands executed
  metadata: object;             // Additional context
}

interface Finding {
  timestamp: string;
  phase: string;
  type: string;
  title: string;
  severity: string;             // "critical" | "high" | "medium" | "low" | "info"
  details?: string;
}
```

### Patient Data Model
```typescript
interface Patient {
  id: string;                   // P001, P002, etc.
  firstName: string;
  lastName: string;
  dateOfBirth: string;          // YYYY-MM-DD
  gender: string;               // "Male" | "Female"
  bloodType: string;            // "O+", "A-", etc.
  
  // Contact
  phone: string;
  email: string;
  address: string;
  
  // Medical
  allergies: string[];
  conditions: string[];
  medications: Medication[];
  
  // Records
  vitalSigns: VitalSigns[];
  labResults: LabResult[];
  appointments: Appointment[];
  
  // Identifiers
  mrn: string;                  // Medical Record Number
  ssn: string;                  // Social Security Number (SENSITIVE)
  driverLicense: string;        // (SENSITIVE)
  
  // Financial (SENSITIVE)
  financialInfo: {
    creditCardNumber: string;
    creditCardExpiry: string;
    creditCardCVV: string;
    bankAccountNumber: string;
    bankRoutingNumber: string;
    outstandingBalance: number;
  };
  
  // Medical sensitivity
  sensitiveConditions: string[]; // Mental health, HIV, etc.
  familyHistory: string[];
  
  // Biometric (SENSITIVE)
  biometricData: {
    fingerprints?: string;      // Base64 encoded
    retinalScan?: string;       // Base64 encoded
    dnaProfile?: string;        // Genetic markers
  };
}

interface Medication {
  id: string;
  name: string;
  dosage: string;
  frequency: string;
  route: string;                // "Oral", "Inhalation", etc.
  startDate: string;
  endDate?: string;
  prescribingPhysician: string;
  status: "active" | "discontinued" | "completed";
}

interface VitalSigns {
  temperature?: number;         // Celsius
  bloodPressure?: string;       // "120/80"
  heartRate?: number;           // BPM
  respiratoryRate?: number;     // Breaths/min
  oxygenSaturation?: number;    // O2 %
  weight?: number;              // kg
  height?: number;              // cm
  bmi?: number;
  recordedDate: string;
  recordedBy: string;
}

interface LabResult {
  id: string;
  testName: string;
  result: string;
  unit?: string;
  referenceRange?: string;
  status: "normal" | "abnormal" | "critical";
  orderDate: string;
  resultDate: string;
  orderingPhysician: string;
}
```

### Employee Data Model
```typescript
interface Employee {
  id: string;                   // E001, E002, etc.
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  address: string;
  dateOfBirth: string;
  ssn: string;                  // (SENSITIVE)
  
  // Employment
  employeeId: string;
  department: string;
  position: string;
  salary: number;               // (SENSITIVE)
  hireDate: string;
  status: "active" | "inactive" | "terminated";
  
  // Credentials (SENSITIVE)
  credentials: {
    username: string;
    password: string;           // (SENSITIVE - plaintext!)
    lastLogin: string;
    failedLoginAttempts: number;
    passwordLastChanged: string;
    mfaEnabled: boolean;
    mfaSecret?: string;         // (SENSITIVE)
    accessLevel: "admin" | "physician" | "nurse" | "staff";
    permissions: string[];
  };
  
  // Financial (SENSITIVE)
  financialInfo: {
    bankAccountNumber: string;
    bankRoutingNumber: string;
    directDepositAmount: number;
    taxWithholding: number;
    retirementContribution: number;
  };
  
  // Background Check (SENSITIVE)
  backgroundCheck: {
    criminalHistory: string[];
    creditScore: number;
    drugTestResults: string;
    referenceChecks: ReferenceCheck[];
  };
  
  // Performance & Discipline (SENSITIVE)
  performanceReviews: PerformanceReview[];
  disciplinaryActions: DisciplinaryAction[];
  
  // Benefits
  benefits: BenefitsInfo;
}
```

---

## Mock Data Summary

### Patient Records
- **Count**: 5 patients (P001-P005)
- **Names**: Sarah Johnson, Robert Martinez, Emily Chen, James Williams, Lisa Anderson
- **Storage**: `/Users/hidaroz/INFO492/devprojects/project-medusa/medusa-webapp/src/lib/patients.ts`
- **Sensitive Data Included**: 
  - SSN, credit card, bank account details
  - Medical conditions (HIV+, mental health, substance abuse)
  - Biometric data (fingerprints, retinal scans, DNA)
  - Financial history with specific transactions

### Employee Records
- **Count**: 4 employees (E001-E004)
- **Roles**: 2 Physicians, 1 Chief Medical Officer, 1 Nurse
- **Names**: Dr. Emily Chen, Dr. James Wilson, Sarah Thompson, Nurse Smith
- **Storage**: `/Users/hidaroz/INFO492/devprojects/project-medusa/medusa-webapp/src/lib/employees.ts`
- **Sensitive Data Included**:
  - Plaintext passwords (Password123!, SecurePass456!, etc.)
  - MFA secrets
  - Bank account and routing numbers
  - Salary information
  - Background checks including criminal history
  - Performance reviews and disciplinary actions

### System Configuration (Hardcoded)
```typescript
// In src/lib/api.ts - getSystemConfig()
database: {
  host: "prod-db.medcare.internal",
  username: "medcare_admin",
  password: "SuperSecurePassword123!",
  connectionString: "postgresql://medcare_admin:...",
  encryptionKey: "aes-256-gcm-key-32bytes-long-secret"
},
api: {
  apiKey: "sk-prod-1234567890abcdef",
  secretKey: "secret-key-very-long-and-secure",
  jwtSecret: "jwt-secret-key-for-token-signing",
  encryptionKey: "api-encryption-key-32-chars"
},
backup: {
  cloudCredentials: {
    accessKey: "AKIAIOSFODNN7EXAMPLE",
    secretKey: "wJalrXUtnFEMI/K7MDENG/...",
    bucketName: "medcare-backup-prod"
  }
}
```

---

## Configuration Details

### Frontend Environment Variables
```
NEXT_PUBLIC_MEDUSA_API_URL=http://localhost:8000
NEXT_PUBLIC_MEDUSA_WS_URL=ws://localhost:8000/ws
NEXT_PUBLIC_EHR_API_URL=http://localhost:3001/api
NODE_ENV=production
```

### Backend Environment Variables
```
ENVIRONMENT=production
API_HOST=0.0.0.0
API_PORT=8000
GEMINI_API_KEY=${GEMINI_API_KEY}
DATABASE_URL=postgresql://medusa:medusa_password@medusa-postgres:5432/medusa_db
REDIS_URL=redis://medusa-redis:6379/0
DOCKER_HOST=unix:///var/run/docker.sock
FRONTEND_URL=http://medusa-frontend:3000
LOG_LEVEL=INFO
```

### EHR API Configuration
```
DB_HOST=ehr-database
DB_USER=ehrapp
DB_PASS=Welcome123!
DB_NAME=healthcare_db
JWT_SECRET=supersecret123
NODE_ENV=production
```

### Database Credentials
```
MySQL (EHR Database):
  Host: localhost:3306
  Root: admin123
  User: ehrapp
  Pass: Welcome123!
  DB: healthcare_db

PostgreSQL (MEDUSA):
  Host: localhost:5432
  User: medusa
  Pass: medusa_password (from docker-compose or env)
  DB: medusa_db

Redis (MEDUSA Cache):
  Host: localhost:6379
  DB: 0
```

---

## Dependencies & Requirements

### Backend (medusa-backend/requirements.txt)
```
fastapi==0.109.0
uvicorn[standard]==0.27.0
websockets==12.0
python-multipart==0.0.6
pydantic==2.5.3
pydantic-settings==2.1.0
docker==7.0.0
sqlalchemy==2.0.25
asyncpg==0.29.0
psycopg2-binary==2.9.9
redis==5.0.1
aioredis==2.0.1
google-generativeai==0.3.2
httpx==0.26.0
python-dotenv==1.0.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-json-logger==2.0.7
```

### Frontend (medusa-webapp/package.json)
- Next.js 14
- React 18
- TypeScript
- Tailwind CSS

---

## Architecture Diagrams

### Current Network Topology
```
┌─────────────────────────────────┐
│      MEDUSA DMZ (172.22.0.0/24) │
│                                 │
│  ┌──────────────┐               │
│  │   Frontend   │               │
│  │  :3000       │               │
│  │  Next.js     │──────┐        │
│  └──────────────┘      │        │
│                        │        │
│  ┌──────────────┐      │        │
│  │   Backend    │◄─────┘        │
│  │  :8000       │               │
│  │  FastAPI     │──────┐        │
│  └──────────────┘      │        │
│         │              │        │
│         │ Docker       │        │
│         │ Socket       │        │
└─────────────────────────────────┘
         │              │
         │              │
    ┌────▼──────────────▼────────────────────────────┐
    │    Healthcare Internal (172.21.0.0/24)        │
    │                                                 │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
    │  │ EHR DB   │  │ SSH      │  │ LDAP     │    │
    │  │ MySQL    │  │ Server   │  │ Server   │    │
    │  │ :3306    │  │ :2222    │  │ :389     │    │
    │  └──────────┘  └──────────┘  └──────────┘    │
    │                                                 │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
    │  │ FTP      │  │ Log      │  │ Postgres │    │
    │  │ Server   │  │ Coll.    │  │ :5432    │    │
    │  │ :21      │  │ :5514    │  │          │    │
    │  └──────────┘  └──────────┘  └──────────┘    │
    └─────────────────────────────────────────────────┘

    ┌─────────────────────────────────┐
    │  Healthcare DMZ (172.20.0.0/24) │
    │                                  │
    │  ┌──────────────┐  ┌──────────┐│
    │  │  EHR Web     │  │ Workst.  ││
    │  │  PHP :8080   │  │ :445/RDP ││
    │  └──────────────┘  └──────────┘│
    └─────────────────────────────────┘
```

### API Call Flow (Currently Broken)
```
User clicks "View Patients" on Frontend
    │
    ▼
React calls getAllPatients()
    │
    ▼
Fetch to http://localhost:3001/api/patients  [WRONG PORT!]
    │
    ▼
FAILS: No endpoint on EHR API for this call
    │
    ▼
Error displayed to user
```

### WebSocket Flow (Partially Working)
```
User initiates pentesting scan
    │
    ▼
Frontend creates WebSocket: ws://localhost:8000/ws/{sessionId}
    │
    ▼
Backend accepts connection
    │
    ▼
Simulation runs: reconnaissance → enumeration → exploitation → reporting
    │
    ▼
Backend sends phase updates, terminal output, findings via WS
    │
    ▼
Frontend displays in real-time
    │
    ▼
Completed (no CLI actually executed)
```

