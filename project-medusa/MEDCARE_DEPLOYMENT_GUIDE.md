# MedCare EHR System: Quick Deployment Guide

**Quick Reference for Standing Up the Full Stack**

---

## 🚀 Super Quick Start (5 Minutes)

```bash
# 1. Navigate to project root
cd /Users/hidaroz/INFO492/devprojects/project-medusa

# 2. Ensure .env exists
[ -f .env ] || cp env.example .env

# 3. Start everything
docker-compose up -d --build

# 4. Wait 30 seconds for services to initialize
sleep 30

# 5. Check status
docker-compose ps

# 6. Access services
echo "MEDUSA Frontend: http://localhost:8080"
echo "MEDUSA Backend:  http://localhost:8000"
echo "EHR API:         http://localhost:3001"
echo "Log Viewer:      http://localhost:8081"
```

**That's it! All services should now be running.**

---

## 🎯 What's Running

### MEDUSA Platform
| Service | URL | Purpose |
|---------|-----|---------|
| Frontend | http://localhost:8080 | Next.js dashboard |
| Backend | http://localhost:8000 | FastAPI analysis engine |
| Neo4j | http://localhost:7474 | Knowledge graph |

### MedCare EHR (Vulnerable Lab)
| Service | External Port | Internal Port | Purpose |
|---------|---------------|--------------|---------|
| EHR API | 3001 | 3000 | REST API |
| MySQL DB | 3306 | 3306 | Patient database |
| SSH | 2222 | 22 | Linux server |
| FTP | 21 | 21 | File server |
| LDAP | 389 | 389 | Directory service |
| Log Viewer | 8081 | 80 | Log aggregation |
| Workstation | 445/3389/5900 | 445/3389/5900 | Windows simulation (SMB/RDP/VNC) |

---

## 📊 Monitor Services

```bash
# View all service status
docker-compose ps

# View logs for specific service
docker-compose logs -f medusa-backend
docker-compose logs -f ehr-api

# View all logs (real-time)
docker-compose logs -f

# Get resource usage
docker stats
```

---

## 🔍 Verify Connectivity

```bash
# Test MEDUSA services
curl http://localhost:8000/health     # Should return 200
curl http://localhost:8080/api/health # Should return 200

# Test MedCare EHR services
curl http://localhost:3001/api/health # Should return 200 (external port)

# Test internal connectivity (using internal port 3000)
docker-compose exec medusa-backend curl http://ehr-api:3000/api/health
docker-compose exec medusa-frontend curl http://medusa-backend:8000/health
```

---

## 🛑 Stop & Cleanup

```bash
# Stop all services (preserves data)
docker-compose stop

# Stop and remove containers (preserves volumes)
docker-compose down

# Full reset (DELETES all data!)
docker-compose down -v
docker system prune -a

# Restart single service
docker-compose restart medusa-backend
```

---

## 🔧 Common Tasks

### Access MySQL Database
```bash
# Using docker-compose
docker-compose exec ehr-database mysql -u root -padmin123

# Or from your machine
mysql -h localhost -P 3306 -u ehrapp -pWelcome123!
```

### SSH into Linux Server
```bash
ssh -p 2222 admin@localhost
# Password: admin2024
```

### Connect to FTP Server
```bash
ftp localhost 21
# User: anonymous
# Password: (leave blank)
```

### View Application Logs
```bash
# MEDUSA Backend logs
docker-compose logs medusa-backend

# EHR API logs
docker-compose logs ehr-api

# Entire stack logs
docker-compose logs --tail=100
```

### Rebuild Single Service
```bash
docker-compose build --no-cache medusa-frontend
docker-compose up -d medusa-frontend
```

---

## ⚡ Performance Tips

### Reduce Resource Usage
```bash
# Start only MEDUSA (no lab environment)
docker-compose up -d medusa-frontend medusa-backend medusa-postgres medusa-redis

# Start only MedCare EHR (no MEDUSA)
docker-compose up -d ehr-api ehr-database ssh-server ftp-server
```

### Speed Up Builds
```bash
# Use BuildKit for faster builds
DOCKER_BUILDKIT=1 docker-compose build

# Or set as environment variable
export DOCKER_BUILDKIT=1
docker-compose build
```

---

## 🆘 Quick Troubleshooting

### Service Won't Start
```bash
# Check logs
docker-compose logs [service-name]

# Likely issue: port in use
netstat -an | grep 8080

# Kill existing process or change port in docker-compose.yml
```

### Can't Connect to Database
```bash
# Ensure database is ready
docker-compose ps ehr-database

# Check environment variables
docker-compose exec ehr-api env | grep DB_

# Test connection from inside container (using internal hostname)
docker-compose exec ehr-api mysql -h ehr-database -u ehrapp -pWelcome123! -e "SELECT 1"

# Or test from host machine (using external port)
mysql -h localhost -P 3306 -u ehrapp -pWelcome123! -e "SELECT 1"
```

### Frontend Not Loading
```bash
# Check if build completed
docker-compose logs medusa-frontend | grep "Ready"

# Verify health endpoint
curl http://localhost:8080/api/health

# Rebuild if needed
docker-compose build --no-cache medusa-frontend
```

### Out of Memory
```bash
# Check resource usage
docker stats

# Stop services you don't need
docker-compose stop workstation ldap-server

# Or increase Docker memory in Docker Desktop settings
```

---

## 📚 Full Documentation

For detailed information, see:
- **[MedCare Recovery Plan](./MEDCARE_EHR_RECOVERY_PLAN.md)** - Complete architecture & configuration
- **[Lab Environment README](./lab-environment/README.md)** - Service details
- **[Architecture Guide](./docs/01-architecture/project-overview.md)** - System design
- **[Troubleshooting Guide](./docs/00-getting-started/troubleshooting.md)** - Detailed debugging

---

## 🎓 Next Steps

1. **Verify all services are running** - `docker-compose ps`
2. **Test frontend** - Visit http://localhost:8080
3. **Test backend** - Visit http://localhost:8000
4. **Review vulnerabilities** - Check `/docs/06-security/`
5. **Run MEDUSA** - Begin penetration testing
6. **Monitor logs** - Watch activity in real-time

---

**That's all you need to get started! Happy testing! 🎯**

