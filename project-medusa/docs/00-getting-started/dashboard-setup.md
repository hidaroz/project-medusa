# Medusa Dashboard Setup Guide

## Overview

The Medusa Dashboard provides a web interface for monitoring and controlling Medusa operations. It consists of:

1. **Python API Server** - Flask-based REST API that wraps Medusa CLI operations
2. **Next.js Dashboard** - React frontend for visualizing operations and status

## Architecture

```
┌─────────────────────────────────────┐
│   Next.js Dashboard (Port 3000)    │
│   /medusa                           │
└──────────────┬──────────────────────┘
               │ HTTP Requests
               ▼
┌─────────────────────────────────────┐
│   Flask API Server (Port 5000)     │
│   /api/*                            │
└──────────────┬──────────────────────┘
               │ Python CLI
               ▼
┌─────────────────────────────────────┐
│   Medusa CLI                        │
│   medusa.py                         │
└─────────────────────────────────────┘
```

## Setup Instructions

### 1. Install Python Dependencies

```bash
cd medusa-cli
pip install -r requirements.txt
```

This will install:
- Flask (web framework)
- Flask-CORS (CORS support)
- Other Medusa dependencies

### 2. Start the API Server

```bash
cd medusa-cli
python api_server.py
```

The API server will start on `http://localhost:5000`

**Available Endpoints:**
- `GET /api/health` - Health check
- `GET /api/status` - Get current system status
- `GET /api/operations` - Get list of operations
- `POST /api/operations` - Start a new operation
- `POST /api/operations/stop` - Stop current operation
- `GET /api/logs` - Get operation logs
- `GET /api/metrics` - Get operation metrics

### 3. Start the Next.js Dashboard

In a separate terminal:

```bash
cd medusa-webapp
npm install
npm run dev
```

The dashboard will be available at:
- **Main EHR**: `http://localhost:3000`
- **Medusa Dashboard**: `http://localhost:3000/medusa`

### 4. Access the Dashboard

Navigate to `http://localhost:3000/medusa` in your browser.

The dashboard includes:
- **System Status** - Current operation status and metrics
- **Operation Control** - Start/stop operations
- **Operations Log** - Real-time log of all operations

## Configuration

### API URL Configuration

The dashboard connects to the API server at `http://localhost:5000` by default.

To change this, set the environment variable:

```bash
NEXT_PUBLIC_MEDUSA_API_URL=http://your-api-url:5000
```

Or update `medusa-webapp/src/app/medusa/page.tsx`:

```typescript
const API_URL = process.env.NEXT_PUBLIC_MEDUSA_API_URL || 'http://localhost:5000';
```

## Testing the Dashboard

1. **Start both servers:**
   - API server on port 5000
   - Next.js dev server on port 3000

2. **Access the dashboard:**
   - Go to `http://localhost:3000/medusa`

3. **Start a test operation:**
   - Select operation type (Assess, Find, Deploy)
   - Enter an objective (if needed)
   - Click "Start Operation"

4. **Monitor operations:**
   - Watch the status update in real-time
   - View logs in the operations log section

## API Server Features

### Operation Types

1. **Security Assessment** (`assess`)
   - Runs comprehensive security assessment
   - Outputs report to `medusa_assessment_report.txt`

2. **Find Data** (`find`)
   - Searches for specific data types
   - Requires objective: e.g., "medical records", "passwords"

3. **Deploy Agent** (`deploy`)
   - Deploys AI agent with strategic objective
   - Requires objective: e.g., "Locate patient database"

### Status States

- `idle` - No operation running
- `running` - Operation in progress
- `completed` - Operation finished successfully
- `error` - Operation failed

## Troubleshooting

### API Server Won't Start

- Check if port 5000 is already in use
- Verify Python dependencies are installed
- Check Flask is in requirements.txt

### Dashboard Can't Connect to API

- Verify API server is running on port 5000
- Check CORS is enabled in `api_server.py`
- Verify `NEXT_PUBLIC_MEDUSA_API_URL` is correct

### Operations Not Appearing

- Check browser console for errors
- Verify API server logs for issues
- Check network tab in browser dev tools

## Production Deployment

For production deployment:

1. **API Server:**
   - Use a production WSGI server (gunicorn)
   - Set up proper CORS configuration
   - Add authentication/authorization

2. **Dashboard:**
   - Build static export: `npm run build`
   - Deploy to GitHub Pages or similar
   - Update API URL to production endpoint

## Security Notes

⚠️ **This dashboard is for demonstration purposes**

- The API server has no authentication
- CORS is enabled for all origins
- Operations are not sandboxed in the current implementation

For production use, add:
- Authentication/authorization
- Rate limiting
- Input validation
- Proper error handling
- Security headers




