# MedCare EHR Frontend (Next.js)

This is the **primary frontend application** for the MedCare EHR system. It's a modern React/Next.js application that provides the user interface for healthcare providers and administrators.

## Overview

- **Technology:** Next.js 15 with React 19
- **Port:** 3000 (internal), 8080 (external)
- **Purpose:** User interface for EHR system
- **Connects to:**
  - EHR API (http://ehr-api:3000)
  - EHR Backend (http://ehr-backend:3000)
  - EHR Redis (via backend)

## Features

- Patient management dashboard
- Clinical documentation
- Appointment scheduling
- Medical records viewing
- Reports and analytics
- Administrative functions

## Building

```bash
# Build the Docker image
docker build -t ehr-frontend .

# Or use docker-compose from lab-environment root
cd ../../..
docker-compose build ehr-frontend
```

## Running

```bash
# Run standalone
docker run -p 8080:3000 \
  -e NEXT_PUBLIC_EHR_API_URL=http://ehr-api:3000 \
  -e NEXT_PUBLIC_EHR_BACKEND_URL=http://ehr-backend:3000 \
  ehr-frontend

# Or use docker-compose
docker-compose up ehr-frontend
```

## Environment Variables

- `NEXT_PUBLIC_EHR_API_URL` - URL of the EHR REST API (default: http://ehr-api:3000)
- `NEXT_PUBLIC_EHR_BACKEND_URL` - URL of the EHR Backend (default: http://ehr-backend:3000)
- `NODE_ENV` - Node environment (production)
- `PORT` - Port to run on (3000)

## Development

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

## Notes

- This frontend replaces the legacy PHP webapp
- It connects to the EHR API for all data operations
- Authentication is currently mocked (any credentials work)
- All API calls go through the EHR API service
