# Medusa Project - Backend Implementation Plan

## Overview

This document outlines the specific implementation plan for creating a backend API system that will serve as the attack target for the Medusa CLI AI agent. The goal is to separate the frontend (Next.js) from the backend (Node.js/Express) and create a realistic attack surface for security research.

## Current State Analysis

### Existing Components
- **Frontend**: Next.js webapp with static data in `medusa-webapp/src/lib/`
- **CLI**: Python-based command-line interface in `medusa-cli/`
- **Data**: Mock patient, employee, and system data embedded in frontend

### Data Locations
- **Source Data**: `medusa-webapp/src/lib/patients.ts`, `employees.ts`, `system-config.ts`
- **Static HTML**: Generated pages in root-level folders (`/patient/`, `/patients/`, `/reports/`, etc.)
- **Build Output**: Next.js compiled files in `_next/` folder

## Target Architecture

```
project-medusa/
├── medusa-webapp/          # Frontend (Next.js) - UI only
│   └── src/
│       └── app/            # Pages with API calls
├── medusa-backend/         # Backend API (Node.js/Express)
│   ├── src/
│   │   ├── routes/         # API endpoints
│   │   └── app.js          # Express setup
│   └── server.js           # Entry point
├── data/                   # Centralized data storage (separate folder)
│   ├── patients.ts
│   └── employees.ts
├── medusa-cli/             # CLI (Python) - Attack simulation
└── docs/
```

## Implementation Phases

### Phase 1: Backend Infrastructure Setup

#### 1.1 Create Backend Directory Structure
```bash
# Create backend directory
mkdir -p medusa-backend/data
mkdir -p medusa-backend/src/routes
mkdir -p medusa-backend/src/middleware
mkdir -p medusa-backend/src/utils
```

#### 1.2 Initialize Node.js Project
```bash
cd medusa-backend
npm init -y
```

#### 1.3 Install Dependencies
```bash
npm install express cors dotenv helmet morgan
npm install -D nodemon @types/node typescript ts-node
```

#### 1.4 Create Package.json Scripts
```json
{
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "build": "tsc",
    "test": "jest"
  }
}
```

### Phase 2: Data Migration and Centralization

#### 2.1 Create Separate Data Folder
```bash
# Create separate data folder at project root
mkdir -p data

# Copy data files from frontend to separate data folder
cp medusa-webapp/src/lib/patients.ts data/
cp medusa-webapp/src/lib/employees.ts data/
```

### Phase 3: Express API Server Implementation

#### 3.1 Main Server File

**File: `medusa-backend/server.js`**
```javascript
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json());

// Routes
app.use('/api/patients', require('./src/routes/patients'));
app.use('/api/employees', require('./src/routes/employees'));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.listen(PORT, () => {
  console.log(`Medusa Backend API running on port ${PORT}`);
});
```

#### 3.2 Patient Routes

**File: `medusa-backend/src/routes/patients.js`**
```javascript
const express = require('express');
const {
  getAllPatients,
  getPatientById,
  getPatientSensitiveData
} = require('../../data/patients');

const router = express.Router();

// GET /api/patients
router.get('/', (req, res) => {
  try {
    const patients = getAllPatients();
    res.json(patients);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch patients' });
  }
});

// GET /api/patients/:id
router.get('/:id', (req, res) => {
  try {
    const patient = getPatientById(req.params.id);
    if (patient) {
      res.json(patient);
    } else {
      res.status(404).json({ error: 'Patient not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch patient' });
  }
});

// GET /api/patients/:id/sensitive
router.get('/:id/sensitive', (req, res) => {
  try {
    const sensitiveData = getPatientSensitiveData(req.params.id);
    if (sensitiveData) {
      res.json(sensitiveData);
    } else {
      res.status(404).json({ error: 'Patient not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch sensitive data' });
  }
});

module.exports = router;
```

#### 3.3 Employee Routes

**File: `medusa-backend/src/routes/employees.js`**
```javascript
const express = require('express');
const {
  getAllEmployees,
  getEmployeeById,
  getEmployeeCredentials
} = require('../../data/employees');

const router = express.Router();

// GET /api/employees
router.get('/', (req, res) => {
  try {
    const employees = getAllEmployees();
    res.json(employees);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch employees' });
  }
});

// GET /api/employees/:id
router.get('/:id', (req, res) => {
  try {
    const employee = getEmployeeById(req.params.id);
    if (employee) {
      res.json(employee);
    } else {
      res.status(404).json({ error: 'Employee not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch employee' });
  }
});

// GET /api/employees/:id/credentials
router.get('/:id/credentials', (req, res) => {
  try {
    const credentials = getEmployeeCredentials(req.params.id);
    if (credentials) {
      res.json(credentials);
    } else {
      res.status(404).json({ error: 'Employee not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch credentials' });
  }
});

module.exports = router;
```


### Phase 4: Frontend API Integration

#### 4.1 Create API Client

**File: `medusa-webapp/src/lib/api.ts`**
```typescript
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001/api';

export async function getAllPatients() {
  const response = await fetch(`${API_BASE_URL}/patients`);
  if (!response.ok) {
    throw new Error('Failed to fetch patients');
  }
  return response.json();
}

export async function getPatientById(id: string) {
  const response = await fetch(`${API_BASE_URL}/patients/${id}`);
  if (!response.ok) {
    throw new Error('Failed to fetch patient');
  }
  return response.json();
}

export async function getPatientSensitiveData(id: string) {
  const response = await fetch(`${API_BASE_URL}/patients/${id}/sensitive`);
  if (!response.ok) {
    throw new Error('Failed to fetch sensitive data');
  }
  return response.json();
}

export async function getAllEmployees() {
  const response = await fetch(`${API_BASE_URL}/employees`);
  if (!response.ok) {
    throw new Error('Failed to fetch employees');
  }
  return response.json();
}

export async function getEmployeeCredentials(id: string) {
  const response = await fetch(`${API_BASE_URL}/employees/${id}/credentials`);
  if (!response.ok) {
    throw new Error('Failed to fetch employee credentials');
  }
  return response.json();
}
```

#### 4.2 Update Frontend Pages

**File: `medusa-webapp/src/app/dashboard/page.tsx`**
```typescript
'use client';
import { useEffect, useState } from 'react';
import { getAllPatients } from '@/lib/api';

export default function DashboardPage() {
  const [patients, setPatients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    getAllPatients()
      .then(data => {
        setPatients(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;

  // Rest of component...
}
```

### Phase 5: Data Centralization

#### 5.1 Data Folder Structure

The data folder is separate from the backend and contains all mock data files:

**File Structure:**
```
project-medusa/
├── data/                   # Separate data folder
│   ├── patients.ts         # Patient records with sensitive data
│   └── employees.ts        # Employee records with credentials
├── medusa-backend/         # Backend API
│   ├── src/
│   │   ├── routes/         # API endpoints
│   │   └── app.js
│   └── server.js
└── medusa-webapp/          # Frontend
```

**Benefits:**
- **Independent from backend** - data can be shared across services
- **Single source of truth** for all data
- **Easy to manage** and update
- **Clear separation** from API logic
- **Scalable** for future additions

### Phase 6: Testing and Validation

#### 6.1 Backend API Testing
```bash
# Test API endpoints
curl http://localhost:3001/health
curl http://localhost:3001/api/patients
curl http://localhost:3001/api/patients/P001
curl http://localhost:3001/api/patients/P001/sensitive
curl http://localhost:3001/api/employees
curl http://localhost:3001/api/employees/E001/credentials
```

#### 6.2 Frontend Integration Testing
```bash
# Start backend
cd medusa-backend && npm run dev

# Start frontend (in another terminal)
cd medusa-webapp && npm run dev
```

#### 6.3 Data Integration Testing
```bash
# Test data loading from centralized folder
curl http://localhost:3001/api/patients
curl http://localhost:3001/api/employees

# Verify data integrity
curl http://localhost:3001/api/patients/P001
curl http://localhost:3001/api/employees/E001
```

## Security Considerations

### 1. Intentionally Weak Security
- **No authentication** on any endpoints
- **No rate limiting** for attack simulation
- **No input validation** to allow various attack vectors
- **Exposed sensitive data** for realistic attack scenarios

### 2. Attack Surface Design
- **Patient data** (medical records, sensitive info)
- **Employee data** (credentials, access info)
- **Different access levels** (public, sensitive)
- **Realistic data structure** for authentic attacks

### 3. Monitoring and Logging
- **Request logging** for attack analysis
- **Error tracking** for vulnerability identification
- **Performance metrics** for system impact assessment

## Deployment Strategy

### 1. Development Environment
- **Local development** with hot reload
- **Docker containers** for isolation
- **Environment variables** for configuration

### 2. Production Simulation
- **Containerized deployment** for realistic testing
- **Network isolation** between components
- **Monitoring and alerting** for attack detection

## Success Metrics

### 1. Technical Metrics
- **API response time** < 100ms
- **Data extraction success rate** > 95%
- **Attack simulation coverage** > 90%

### 2. Security Metrics
- **Patient data extraction** > 90%
- **Employee credential harvesting** > 90%
- **Sensitive data access** > 85%

## Timeline

### Day 1: Backend Infrastructure (3-4 hours)
- [ ] Create backend directory structure
- [ ] Set up Express server with 6 API endpoints
- [ ] Move patient and employee data files to backend
- [ ] Test all API endpoints

### Day 2: Frontend Integration (2-3 hours)
- [ ] Create API client functions
- [ ] Update frontend pages to use APIs
- [ ] Test frontend-backend communication
- [ ] Fix any integration issues

### Day 3: Data Centralization (1-2 hours)
- [ ] Create separate data folder at project root
- [ ] Move data files to separate data folder
- [ ] Update API routes to import from data folder
- [ ] Test data integration

## Risk Mitigation

### 1. Data Security
- **Mock data only** - no real patient information
- **Isolated environment** - no external network access
- **Regular backups** - data recovery procedures

### 2. System Stability
- **Error handling** - graceful failure modes
- **Resource limits** - prevent system overload
- **Monitoring** - real-time system health

### 3. Development Risks
- **Version control** - track all changes
- **Testing coverage** - comprehensive test suite
- **Documentation** - maintain up-to-date docs

## Conclusion

This implementation plan provides a focused roadmap for creating a backend API system with centralized data storage. The backend will serve as a realistic target for security research and AI agent training.

The 3-day timeline ensures rapid development of a functional system with proper data organization. The centralized data folder approach provides a clean, maintainable structure that separates data from API logic.

**Key Deliverables:**
- Backend API server with 6 endpoints
- Separate data folder with patient and employee data
- Frontend integration with API calls
- Clean separation of data, backend, and frontend
