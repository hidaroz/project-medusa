# 🔄 MEDUSA Migration Guide: PHP to Next.js

This guide documents the migration from the PHP-based frontend to the Next.js-based web interface with Docker integration.

---

## 📋 Migration Summary

### What Changed

| Component | Before | After |
|-----------|--------|-------|
| **Frontend** | PHP webapp in lab-environment | Next.js with xterm.js terminal |
| **Backend** | None (PHP served directly) | FastAPI with WebSocket support |
| **Database** | None | PostgreSQL for session persistence |
| **Cache** | None | Redis for session management |
| **CLI Integration** | Standalone | Integrated via Docker socket |
| **Architecture** | Monolithic PHP app | Microservices with Docker |

### New Features

✅ Real-time terminal interface via WebSocket  
✅ Session management and persistence  
✅ Multi-user support  
✅ AI agent integration via backend  
✅ Docker-aware CLI execution  
✅ Comprehensive API with documentation  
✅ Health checks and monitoring  
✅ Environment-based configuration  

---

## 🏗️ Architecture Changes

### Before: PHP-Based

```
┌──────────────────────┐
│   EHR Webapp (PHP)   │
│   Apache + MySQL     │
│   Port 8080          │
└──────────────────────┘
         │
         └──→ Direct database queries
```

### After: Microservices

```
┌────────────┐   WebSocket   ┌────────────┐   Docker   ┌────────────┐
│  Next.js   │ ←──────────→  │  FastAPI   │ ←────────→ │ Lab Svcs   │
│  Frontend  │               │  Backend   │            │ Containers │
└────────────┘               └─────┬──────┘            └────────────┘
                                   │
                            ┌──────┴──────┐
                            │ PostgreSQL  │
                            │   + Redis   │
                            └─────────────┘
```

---

## 🚀 Migration Steps

### Step 1: Backup Existing Setup

```bash
# Backup lab environment configuration
cp -r lab-environment lab-environment.backup

# Export existing data (if any)
docker-compose -f lab-environment/docker-compose.yml exec ehr-database \
  mysqldump -u root -padmin123 healthcare_db > backup.sql
```

### Step 2: Stop Old Services

```bash
# Stop lab environment
cd lab-environment
docker-compose down

# Or stop specific service
docker-compose stop ehr-webapp
```

### Step 3: Update Repository

```bash
# Pull latest changes
git pull origin main

# Review new structure
ls -la
# Should see:
# - docker-compose.yml (new root-level)
# - medusa-backend/ (new)
# - medusa-webapp/ (updated)
# - .env.example (new)
```

### Step 4: Configure Environment

```bash
# Create environment file
cp .env.example .env

# Edit and add your Gemini API key
nano .env

# Required:
# GEMINI_API_KEY=your_key_here
```

### Step 5: Build and Start New Stack

```bash
# Use the startup script
./scripts/start-medusa.sh

# Or manually
docker-compose build --parallel
docker-compose up -d
```

### Step 6: Verify Services

```bash
# Run integration tests
./scripts/test-integration.sh

# Or manually check each service
curl http://localhost:8000/health  # Backend
curl http://localhost:3000/api/health  # Frontend
curl http://localhost:8080  # Lab EHR webapp (still available)
```

### Step 7: Test Functionality

1. Open http://localhost:3000
2. Create a new session
3. Run a test scan against lab environment
4. Verify WebSocket communication
5. Check report generation

---

## 🔄 Breaking Changes

### Removed

❌ **PHP EHR Webapp as primary interface** - Now a lab target only  
❌ **Direct database access from frontend** - Now via backend API  
❌ **Hardcoded configuration** - Now environment-based  

### Changed

⚠️ **Port Mapping**:
- Frontend: Now 3000 (was integrated with lab)
- Backend API: Now 8000 (new)
- Lab EHR Webapp: Still 8080 (unchanged)

⚠️ **Network Architecture**:
- Added `medusa-dmz` network for platform services
- Kept `healthcare-dmz` and `healthcare-internal` for lab

⚠️ **Environment Variables**:
- Now required: `GEMINI_API_KEY`
- New optional: `POSTGRES_PASSWORD`, `LOG_LEVEL`, etc.

### Added

✅ PostgreSQL database (port 5432, internal only)  
✅ Redis cache (port 6379, internal only)  
✅ FastAPI backend (port 8000)  
✅ WebSocket endpoint (ws://localhost:8000/ws/{session_id})  

---

## 🔧 Configuration Migration

### Old: PHP Configuration

```php
// config.php
define('DB_HOST', 'ehr-database');
define('DB_USER', 'ehrapp');
define('DB_PASS', 'Welcome123!');
```

### New: Environment Variables

```bash
# .env
DATABASE_URL=postgresql://medusa:password@medusa-postgres:5432/medusa_db
EHR_DB_HOST=ehr-database
EHR_DB_USER=ehrapp
EHR_DB_PASS=Welcome123!
```

---

## 📊 Data Migration

### Sessions

**Before**: No session management  
**After**: PostgreSQL-backed sessions

```python
# Sessions are now persisted
# Access via API:
GET /api/sessions
POST /api/sessions
GET /api/sessions/{id}
DELETE /api/sessions/{id}
```

### Findings

**Before**: No persistence  
**After**: Stored in PostgreSQL

```python
# Findings attached to sessions
# Access via session endpoint
GET /api/sessions/{id}
# Returns: { findings: [...], history: [...] }
```

---

## 🐛 Common Issues

### Issue: Port Conflicts

**Symptom**: Services fail to start with "port already in use"

**Solution**:
```bash
# Check which process is using the port
lsof -i :3000
lsof -i :8000

# Kill process or change port in docker-compose.yml
```

### Issue: Frontend Can't Connect to Backend

**Symptom**: WebSocket connection failed

**Solution**:
```bash
# Check backend is running
docker-compose ps medusa-backend

# Check logs
docker-compose logs medusa-backend

# Verify environment variables
docker-compose exec medusa-frontend env | grep MEDUSA_API_URL
```

### Issue: Docker Socket Permission Denied

**Symptom**: Backend can't execute Docker commands

**Solution**:
```bash
# Check Docker socket mount
docker-compose exec medusa-backend ls -la /var/run/docker.sock

# Verify backend can run docker commands
docker-compose exec medusa-backend docker ps
```

### Issue: Missing Gemini API Key

**Symptom**: AI features don't work, errors in backend logs

**Solution**:
```bash
# Check .env file
grep GEMINI_API_KEY .env

# Restart backend after adding key
docker-compose restart medusa-backend
```

---

## 📝 API Changes

### New Endpoints

```
GET  /health                       # Health check
GET  /api/health                   # Detailed health
GET  /api/sessions                 # List sessions
POST /api/sessions                 # Create session
GET  /api/sessions/{id}            # Get session
DELETE /api/sessions/{id}          # Delete session
GET  /api/docker/containers        # List containers
GET  /api/docker/networks          # List networks
WS   /ws/{session_id}              # WebSocket connection
```

### WebSocket Protocol

```json
// Client -> Server
{
  "type": "start_scan",
  "data": {
    "target": "ehr-portal",
    "mode": "observe"
  }
}

// Server -> Client
{
  "type": "terminal_output",
  "output": "Starting scan...\n",
  "timestamp": "2025-11-05T12:00:00Z"
}
```

---

## 🧪 Testing Checklist

After migration, verify:

- [ ] Frontend accessible at http://localhost:3000
- [ ] Backend API accessible at http://localhost:8000
- [ ] API docs at http://localhost:8000/docs
- [ ] WebSocket connection works
- [ ] Can create new session
- [ ] Can start scan
- [ ] Real-time terminal output appears
- [ ] Lab services still accessible
- [ ] Can download reports
- [ ] Database persists sessions
- [ ] Redis caches active data
- [ ] Docker integration works
- [ ] CLI commands execute in containers
- [ ] Health checks pass

---

## 🔄 Rollback Procedure

If you need to rollback to PHP-based setup:

```bash
# Stop new stack
docker-compose down

# Restore backup
rm -rf lab-environment
mv lab-environment.backup lab-environment

# Start old stack
cd lab-environment
docker-compose up -d

# Restore database (if needed)
docker-compose exec ehr-database mysql -u root -padmin123 healthcare_db < ../backup.sql
```

---

## 📚 Additional Resources

- [Main README](README.md) - Complete documentation
- [Backend README](medusa-backend/README.md) - API details
- [CLI README](medusa-cli/README.md) - CLI usage
- [Docker Compose Reference](https://docs.docker.com/compose/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Next.js Documentation](https://nextjs.org/docs)

---

## ❓ FAQ

**Q: Can I use both PHP and Next.js frontends?**  
A: Yes! The PHP EHR webapp still runs on port 8080 as a lab target. The Next.js app on port 3000 is the MEDUSA interface.

**Q: Do I need to migrate existing data?**  
A: No. The new system starts fresh. Old lab data remains in MySQL for testing purposes.

**Q: Will my custom lab services still work?**  
A: Yes! All lab services remain unchanged. Only the MEDUSA control interface changed.

**Q: Can I deploy this to production?**  
A: **NO!** This contains intentionally vulnerable services for educational purposes only.

**Q: What about the CLI tool?**  
A: Still works! Now integrated with backend for Docker-aware execution.

---

## 📞 Support

If you encounter issues during migration:

1. Check logs: `docker-compose logs -f`
2. Run tests: `./scripts/test-integration.sh`
3. Review this guide
4. Check [Troubleshooting](#-common-issues)
5. Create an issue on GitHub

---

**Migration completed successfully! 🎉**

Now you can access MEDUSA at http://localhost:3000 and start your AI-powered penetration testing sessions.

