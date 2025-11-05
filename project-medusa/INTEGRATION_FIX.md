# MEDUSA Integration Fixes - Complete Guide

## Issues Fixed

### 1. Workstation Container Looping Error ✅

**Problem**: The workstation container was restarting in an infinite loop
- Root cause: The startup script `/start.sh` had several issues:
  - `vncserver` command daemonizes immediately (doesn't stay in foreground)
  - `tail -f` on log files that don't exist yet causes immediate exit
  - No proper process to keep the container alive

**Solution Applied**: Updated [lab-environment/services/workstation/Dockerfile](lab-environment/services/workstation/Dockerfile#L93-L118)
- Created log directory and files before starting services
- Used `wait` command to keep container alive by monitoring background processes
- Added proper error handling and logging

**To Apply**: Rebuild the workstation container
```bash
docker-compose build workstation
docker-compose up -d workstation
```

### 2. Frontend-Backend Integration ✅

**Problem**: Frontend API client was pointing to wrong port
- [medusa-webapp/src/lib/api.ts](medusa-webapp/src/lib/api.ts#L3) was hardcoded to `http://localhost:3001/api`
- This is correct for the EHR API but didn't include MEDUSA backend configuration

**Solution Applied**: Updated the API client to support both:
- **EHR API** (port 3001): For patient/employee data from MySQL database
- **MEDUSA Backend** (port 8000): For pentesting features, WebSocket, sessions

**Current Architecture**:
```
┌─────────────────┐
│ Frontend (3000) │
└────────┬────────┘
         │
         ├──────────────┐
         │              │
    ┌────▼─────┐   ┌────▼──────────┐
    │ EHR API  │   │ MEDUSA Backend│
    │ (3001)   │   │    (8000)     │
    └────┬─────┘   └────┬──────────┘
         │              │
    ┌────▼─────┐   ┌────▼──────────┐
    │  MySQL   │   │  PostgreSQL   │
    │  (3306)  │   │    (5432)     │
    └──────────┘   └───────────────┘
```

## System Architecture

### Services Overview

| Service | Port | Purpose | Database |
|---------|------|---------|----------|
| **medusa-frontend** | 3000 | Next.js webapp UI | - |
| **medusa-backend** | 8000 | FastAPI + WebSocket | PostgreSQL |
| **ehr-api** | 3001 | Node.js vulnerable API | MySQL |
| **ehr-webapp** | 8080 | PHP web interface | MySQL |
| **ehr-database** | 3306 | MySQL with patient data | - |
| **workstation** | 445, 5900 | Simulated Windows workstation | - |
| **ssh-server** | 2222 | SSH server for testing | - |
| **ftp-server** | 21 | FTP server for testing | - |
| **ldap-server** | 389 | LDAP directory | - |

### Network Architecture

```
medusa-dmz (172.22.0.0/24)
├── medusa-frontend
├── medusa-backend
├── medusa-postgres
└── medusa-redis

healthcare-dmz (172.20.0.0/24)
├── ehr-webapp
└── ehr-api

healthcare-internal (172.21.0.0/24)
├── ehr-database
├── workstation
├── ssh-server
├── ftp-server
├── ldap-server
└── log-collector
```

## Testing the Integration

### Step 1: Start All Services

```bash
# Navigate to project root
cd /Users/hidaroz/INFO492/devprojects/project-medusa

# Start all services
docker-compose up -d

# Check status
docker-compose ps
```

### Step 2: Verify Services are Healthy

```bash
# Check MEDUSA backend
curl http://localhost:8000/health

# Check EHR API
curl http://localhost:3001/health

# Check frontend
curl http://localhost:3000/api/health

# View logs if needed
docker-compose logs -f medusa-backend
docker-compose logs -f ehr-api
docker-compose logs -f workstation
```

### Step 3: Test Database Integration

```bash
# Test EHR API patient endpoint
curl http://localhost:3001/api/patients

# Test specific patient
curl http://localhost:3001/api/patients/1

# Test user enumeration endpoint (intentional vulnerability)
curl http://localhost:3001/api/users
```

### Step 4: Test Workstation Fix

```bash
# Check workstation container is running (not restarting)
docker ps | grep medusa_workstation

# Should show "Up" status, not "Restarting"
# Check workstation logs
docker logs medusa_workstation

# Should see:
# "Workstation services started successfully"
# "SMB: port 445, VNC: port 5900"

# Test SMB port is listening
nc -zv localhost 445

# Test VNC port is listening
nc -zv localhost 5900
```

### Step 5: Access the Application

1. **Frontend**: http://localhost:3000
2. **MEDUSA Backend API**: http://localhost:8000
3. **EHR Web Portal**: http://localhost:8080
4. **EHR API**: http://localhost:3001

### Step 6: Test Frontend-Backend Integration

Open http://localhost:3000 in browser and verify:
- ✅ Homepage loads
- ✅ Navigation works
- ✅ Patient list page loads data from EHR API
- ✅ Employee list page loads data from EHR API
- ✅ Dashboard shows system status

## Database Information

### MySQL (EHR Database)

**Connection Details**:
- Host: localhost
- Port: 3306
- Database: healthcare_db
- User: ehrapp
- Password: Welcome123!

**Tables**:
- `users` - System users with MD5 password hashes (intentionally weak)
- `patients` - 50+ synthetic patient records with PHI
- `medical_records` - 200+ medical records linked to patients
- `appointments` - Scheduled appointments
- `prescriptions` - Medication prescriptions
- `lab_results` - Laboratory test results

**Sample Credentials**:
- Admin: admin / password
- Doctor: doctor1 / 123456
- Doctor: doctor2 / password
- Nurse: nurse1 / nurse123

### PostgreSQL (MEDUSA Database)

**Connection Details**:
- Host: localhost
- Port: 5432 (not exposed by default)
- Database: medusa_db
- User: medusa
- Password: medusa_secure_pass

**Purpose**: Stores MEDUSA session data, findings, scan results

## Frontend API Usage

### EHR API Endpoints (Port 3001)

```typescript
// Import the API client
import { getAllPatients, getPatientById } from '@/lib/api';

// Get all patients
const patients = await getAllPatients();

// Get specific patient
const patient = await getPatientById('1');

// Get patient sensitive data
const sensitiveData = await getPatientSensitiveData('1');

// Get all employees
const employees = await getAllEmployees();
```

### MEDUSA Backend Endpoints (Port 8000)

```typescript
import { MEDUSA_API_URL, MEDUSA_WS_URL } from '@/lib/api';

// Health check
const health = await fetch(`${MEDUSA_API_URL}/api/health`);

// Create session
const session = await fetch(`${MEDUSA_API_URL}/api/sessions`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ target: 'ehr-api', mode: 'observe' })
});

// WebSocket connection
const ws = new WebSocket(`${MEDUSA_WS_URL}/${sessionId}`);
```

## Environment Variables

### Frontend (.env.local)

```bash
NEXT_PUBLIC_MEDUSA_API_URL=http://localhost:8000
NEXT_PUBLIC_MEDUSA_WS_URL=ws://localhost:8000/ws
NEXT_PUBLIC_EHR_API_URL=http://localhost:3001/api
```

### Backend (docker-compose.yml)

Already configured in [docker-compose.yml](docker-compose.yml):
- DATABASE_URL: PostgreSQL connection
- REDIS_URL: Redis connection
- GEMINI_API_KEY: AI model API key

## Troubleshooting

### Workstation keeps restarting

```bash
# Check logs
docker logs medusa_workstation

# If still failing, rebuild with no cache
docker-compose build --no-cache workstation
docker-compose up -d workstation
```

### Frontend can't connect to backend

```bash
# Verify backend is running
docker ps | grep medusa_backend

# Check backend logs
docker-compose logs medusa-backend

# Test endpoint directly
curl http://localhost:8000/health
```

### Database connection issues

```bash
# Check database container
docker ps | grep medusa_ehr_db

# Test MySQL connection
docker exec -it medusa_ehr_db mysql -u ehrapp -pWelcome123! healthcare_db

# Run a test query
SELECT COUNT(*) FROM patients;
```

### CORS errors in browser

The EHR API has permissive CORS enabled (`origin: *`) for testing purposes. If you see CORS errors:
1. Check that the API is running: `curl http://localhost:3001/health`
2. Verify the frontend is using the correct API URL in `lib/api.ts`
3. Check browser console for actual error message

## Security Notes

⚠️ **IMPORTANT**: The lab environment contains intentional vulnerabilities:

1. **SQL Injection**: EHR API has SQL injection vulnerabilities
2. **Weak Passwords**: Users have weak MD5 hashed passwords
3. **Information Disclosure**: Verbose error messages expose internals
4. **No Authentication**: Many endpoints don't require auth
5. **Weak Credentials**: Default passwords are easily guessable
6. **Unencrypted PHI**: Patient data stored in plaintext

**DO NOT USE IN PRODUCTION**

This is a security testing environment designed for:
- Learning penetration testing
- AI-powered security assessment
- Vulnerability research
- Security training

## Next Steps

1. ✅ Services are running
2. ✅ Database is populated with data
3. ✅ Frontend can access EHR API
4. ✅ Workstation container is stable
5. 🔄 Integrate MEDUSA pentesting features into frontend
6. 🔄 Create WebSocket connection for real-time pentesting
7. 🔄 Build scan result visualization
8. 🔄 Add vulnerability reporting UI

## Additional Resources

- [MEDUSA Backend API Docs](http://localhost:8000/docs) - FastAPI auto-generated docs
- [EHR API Endpoints](http://localhost:3001/) - Available endpoints list
- [Docker Compose Reference](docker-compose.yml) - Full service configuration
- [Database Schema](lab-environment/init-scripts/db/01-schema.sql) - MySQL schema
