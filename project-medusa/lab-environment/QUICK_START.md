# MedCare EHR System - Quick Start Guide

**Complete standalone EHR system for MEDUSA to attack**

---

## 🚀 5-Minute Start

```bash
# 1. Navigate to lab environment
cd /Users/hidaroz/INFO492/devprojects/project-medusa/lab-environment

# 2. Start all services
docker-compose up -d --build

# 3. Wait 30 seconds
sleep 30

# 4. Check status
docker-compose ps

# 5. Access the system!
echo "✅ MedCare EHR System is running!"
echo ""
echo "Frontend:  http://localhost:8080"
echo "API:       http://localhost:3001"
echo "Backend:   http://localhost:3002"
echo "Database:  mysql -h localhost -P 3306 -u ehrapp -pWelcome123!"
echo "Redis:     redis-cli -h localhost -p 6380 -a Welcome123!"
echo "Logs:      http://localhost:8081"
```

---

## 📊 What's Running

### Core EHR Application (Complete Stack)
✅ **Frontend** - Next.js/React web app (port 8080)  
✅ **Backend** - Business logic layer (port 3002)  
✅ **REST API** - Data access layer (port 3001)  
✅ **Database** - MySQL 8.0 (port 3306)  
✅ **Cache** - Redis 7 (port 6380)  
✅ **Logs** - Centralized logging (port 8081)  

### Supporting Services
✅ SSH Server (port 2222)  
✅ FTP Server (port 21)  
✅ LDAP Directory (port 389)  
✅ Workstation (ports 445/3389/5900)  

**Total: 10 services = Complete EHR System**

---

## 🔑 Login Credentials

### Web Portal (http://localhost:8080)
```
Any username/password works (mock authentication)
Example: admin / admin123
```

### Database
```bash
mysql -h localhost -P 3306 -u ehrapp -pWelcome123!
```

### Redis
```bash
redis-cli -h localhost -p 6380 -a Welcome123!
```

---

## ✅ Quick Health Check

```bash
# Test all core services
curl http://localhost:8080                    # Frontend
curl http://localhost:3001/api/health         # API
curl http://localhost:3002/api/health         # Backend
mysql -h localhost -P 3306 -u ehrapp -pWelcome123! -e "SELECT 1"  # Database
redis-cli -h localhost -p 6380 -a Welcome123! PING                # Redis
```

---

## 🛑 Stop the System

```bash
# Stop (keep data)
docker-compose stop

# Stop and remove containers (keep volumes)
docker-compose down

# Complete reset (DELETE ALL DATA!)
docker-compose down -v
```

---

## 🎯 Use with MEDUSA

This is the TARGET system. To attack it with MEDUSA:

```bash
# Terminal 1: Keep MedCare EHR running
cd lab-environment
docker-compose up -d

# Terminal 2: Run MEDUSA
cd ../medusa-cli
python medusa.py --target localhost:8080
```

---

## 📚 Full Documentation

For complete information, see:
- **[MEDCARE_EHR_SYSTEM.md](./MEDCARE_EHR_SYSTEM.md)** - Complete documentation
- **[docker-compose.yml](./docker-compose.yml)** - Service configuration
- **[README.md](./README.md)** - Lab overview

---

**That's it! You now have a complete, vulnerable EHR system running!**

⚠️ **Remember: For testing only! DO NOT expose to internet!** ⚠️

