# Quick Start: Medusa Dashboard

## Problem: "Failed to start operations"

If you see "Failed to start operations" in the dashboard, the API server is not running.

## Solution: Start the API Server

### Step 1: Install Dependencies (if not already done)

```bash
cd medusa-cli
pip install -r requirements.txt
```

This installs Flask and Flask-CORS.

### Step 2: Start the API Server

Open a **new terminal window** and run:

```bash
cd medusa-cli
python3 api_server.py
```

You should see:
```
 * Running on http://0.0.0.0:5000
 * Debug mode: on
```

**Keep this terminal open** - the API server needs to keep running.

### Step 3: Verify It's Working

In another terminal, test the API:

```bash
curl http://localhost:5000/api/health
```

You should get a JSON response:
```json
{
  "status": "ok",
  "service": "Medusa API Server",
  "version": "0.1.0-alpha",
  "timestamp": "..."
}
```

### Step 4: Access the Dashboard

1. Make sure the Next.js app is running: `npm run dev` in `medusa-webapp/`
2. Go to: `http://localhost:3000/medusa`
3. The dashboard should now connect successfully!

## Running Both Servers

You need **two terminal windows**:

**Terminal 1 - API Server:**
```bash
cd medusa-cli
python3 api_server.py
```

**Terminal 2 - Next.js Dashboard:**
```bash
cd medusa-webapp
npm run dev
```

Then visit: `http://localhost:3000/medusa`

## Troubleshooting

### "Connection refused" error
- Make sure the API server is running on port 5000
- Check: `curl http://localhost:5000/api/health`

### CORS errors in browser console
- Make sure Flask-CORS is installed: `pip install flask-cors`
- Verify it's in `requirements.txt`

### Port 5000 already in use
- Find the process: `lsof -ti:5000`
- Kill it: `kill -9 <PID>`
- Or change the port in `api_server.py` (line 192)

## Next Steps

Once both servers are running:
1. Go to `http://localhost:3000/medusa`
2. Select an operation type (Assess, Find, or Deploy)
3. Enter an objective (if needed)
4. Click "Start Operation"
5. Watch the logs update in real-time!




