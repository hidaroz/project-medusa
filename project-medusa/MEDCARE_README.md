# MedCare EHR System - Quick Reference

**The vulnerable healthcare infrastructure that MEDUSA tests against**

---

## 🎯 What is MedCare EHR?

MedCare EHR is a **vulnerable healthcare lab environment** designed as a testing target for the MEDUSA penetration testing platform. It simulates a realistic healthcare infrastructure with **intentional security vulnerabilities** for educational purposes.

**NOT the same as MEDUSA** - MedCare is what MEDUSA analyzes and attacks.

---

## 🚀 Quick Start (5 Minutes)

```bash
# 1. Go to project root
cd /Users/hidaroz/INFO492/devprojects/project-medusa

# 2. Setup environment (if needed)
cp env.example .env

# 3. Deploy everything
docker-compose up -d --build

# 4. Wait 30 seconds for initialization
sleep 30

# 5. Check status
docker-compose ps

# 6. Access services
echo "✅ Ready!"
echo "MEDUSA Frontend: http://localhost:8080"
echo "EHR API:         http://localhost:3001"
echo "Log Viewer:      http://localhost:8081"
```

---

## 📊 7 Vulnerable Services

| Service | Port | What It Does |
|---------|------|--------------|
| **EHR API** | 3001 | REST API for patient data (internal: 3000) |
| **MySQL DB** | 3306 | Patient records database |
| **SSH** | 2222 | Linux system access |
| **FTP** | 21 | File server with medical records |
| **LDAP** | 389 | User directory service |
| **Log Viewer** | 8081 | Centralized logging web UI |
| **Workstation** | 445/3389/5900 | Windows PC simulation (SMB/RDP/VNC) |

---

## 🔑 Default Credentials

| Service | User | Password | Notes |
|---------|------|----------|-------|
| MySQL (app user) | ehrapp | Welcome123! | Application database user |
| MySQL (root) | root | admin123 | Root database user |
| SSH | admin | admin2024 | Linux server access |
| FTP | fileadmin | Files2024! | Authenticated FTP user |
| FTP | anonymous | (blank) | Anonymous FTP access enabled |
| LDAP | cn=admin,dc=medcare,dc=local | admin123 | LDAP admin user |
| Workstation (SMB) | doctor | Doctor2024! | Windows workstation SMB access |
| Workstation (VNC) | - | vnc123 | VNC remote desktop password |

---

## 🔍 Accessing Services

### Web Interfaces
```bash
# MEDUSA Frontend (Primary Dashboard)
open http://localhost:8080

# EHR API (REST Endpoints) - External port 3001, internal port 3000
curl http://localhost:3001/api/patients

# Log Viewer
open http://localhost:8081
```

### Database Access
```bash
# MySQL from your machine
mysql -h localhost -u ehrapp -pWelcome123! -e "SELECT * FROM patients;"

# MySQL from inside container
docker-compose exec ehr-database mysql -u root -padmin123
```

### SSH Access
```bash
ssh -p 2222 admin@localhost
# Password: admin2024
```

### FTP Access
```bash
ftp localhost 21
# Username: anonymous (or fileadmin)
# Password: (blank for anonymous)
```

### LDAP Queries
```bash
ldapsearch -x -H ldap://localhost:389 -b dc=medcare,dc=local
```

---

## 🛑 Stop Everything

```bash
# Gracefully stop (preserves data)
docker-compose down

# Remove everything (preserves volumes)
docker-compose down -v

# Total reset (deletes all data!)
docker-compose down -v
docker volume prune
```

---

## 📋 Service Status

```bash
# Check all services
docker-compose ps

# View logs for specific service
docker-compose logs ehr-api -f

# Check entire system
docker-compose logs -f
```

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────┐
│    MEDUSA Platform (Analyzer)       │
│    • Frontend at :8080              │
│    • Backend at :8000               │
└────────────┬────────────────────────┘
             │ analyzes/attacks
             ▼
┌─────────────────────────────────────┐
│  MedCare EHR System (Vulnerable)    │
├─────────────────────────────────────┤
│ DMZ (Public):                       │
│ • EHR API at :3001                  │
│ • Log Viewer at :8081               │
├─────────────────────────────────────┤
│ Internal (Backend):                 │
│ • MySQL at :3306                    │
│ • SSH at :2222                      │
│ • FTP at :21                        │
│ • LDAP at :389                      │
│ • Workstation at :445/:5900         │
└─────────────────────────────────────┘
```

---

## 🎓 Intentional Vulnerabilities

### EHR API
- ✗ SQL injection in patient queries
- ✗ Missing authentication on some endpoints
- ✗ Weak JWT secrets
- ✗ Verbose error messages

### Database
- ✗ Weak credentials (ehrapp/Welcome123!)
- ✗ Exposed to network
- ✗ Plain text passwords

### SSH Server
- ✗ Weak passwords
- ✗ Sudo misconfigurations
- ✗ Exposed private keys
- ✗ Sensitive files readable

### FTP Server
- ✗ Anonymous login enabled
- ✗ Unencrypted file transfer
- ✗ Medical records accessible

### LDAP Server
- ✗ Anonymous bind enabled
- ✗ User enumeration possible
- ✗ Weak passwords

### Workstation
- ✗ SMB shares with guest access
- ✗ Cached credentials
- ✗ Unpatched simulation

---

## 🔧 Common Tasks

### Restart Single Service
```bash
docker-compose restart ehr-api
```

### Rebuild Service
```bash
docker-compose build --no-cache ehr-api
docker-compose up -d ehr-api
```

### View Real-Time Logs
```bash
docker-compose logs -f ehr-database
```

### Test API Endpoint
```bash
# List all patients
curl http://localhost:3001/api/patients

# Query specific patient
curl http://localhost:3001/api/patients/P001

# Health check
curl http://localhost:3001/api/health

# Note: External port is 3001, internal container port is 3000
```

### Database Query
```bash
docker-compose exec ehr-database \
  mysql -u ehrapp -pWelcome123! healthcare_db \
  -e "SELECT patient_id, name FROM patients LIMIT 5;"
```

---

## ⚙️ Environment Setup

### File: `.env`

```bash
# Created automatically from env.example
# Contains passwords and configuration

# Key variables for MedCare:
MYSQL_ROOT_PASSWORD=admin123
MYSQL_USER=ehrapp
MYSQL_PASSWORD=Welcome123!
```

### Create from Template
```bash
cp env.example .env
# Edit .env if needed
```

---

## 🐛 Quick Troubleshooting

### "Port already in use"
```bash
# Find what's using the port
sudo lsof -i :3306

# Change port in docker-compose.yml if needed
```

### "Cannot connect to database"
```bash
# Check if database container is running
docker-compose ps ehr-database

# Wait longer (databases take 30+ seconds)
docker-compose logs ehr-database
```

### "Services won't start"
```bash
# Check resource availability
docker stats

# View error logs
docker-compose logs
```

### "Lost all data after restart"
```bash
# You ran: docker-compose down -v
# This deletes all volumes (data)

# Use instead:
docker-compose down  # Keeps data
```

---

## 📊 Performance

| Task | Time |
|------|------|
| First build | 5-10 min |
| Startup | 30-60 sec |
| Memory (full stack) | 3-4 GB |
| Disk space | 5-10 GB |

---

## 🔒 Security Reminders

⚠️ **DO NOT:**
- Expose to the internet
- Use real patient data
- Run on production networks
- Leave running unattended

✅ **DO:**
- Use in isolated test environment
- Document your testing
- Reset between sessions
- Follow ethical guidelines

---

## 📚 Full Documentation

For complete information:

1. **[Deployment Guide](./MEDCARE_DEPLOYMENT_GUIDE.md)** - Full deployment steps
2. **[Recovery Plan](./MEDCARE_EHR_RECOVERY_PLAN.md)** - Comprehensive guide
3. **[Naming Conventions](./NAMING_CONVENTIONS.md)** - Service naming reference
4. **[Status Report](./MEDCARE_EHR_STATUS.md)** - Current state & progress
5. **[Lab Environment](./lab-environment/README.md)** - Detailed service info

---

## 🎯 Next Steps

1. Run the quick start above
2. Verify all services are running
3. Test a few API endpoints
4. Start MEDUSA penetration testing
5. Monitor results in log viewer

---

## 💡 Pro Tips

```bash
# Run only MedCare (skip MEDUSA platform)
docker-compose up -d ehr-api ehr-database ssh-server ftp-server ldap-server

# Check all port bindings
docker-compose ps --format "table {{.Service}}\t{{.Ports}}"

# Monitor in real-time
docker stats --no-stream

# Clean up unused Docker resources
docker system prune -a

# Export database for backup
docker-compose exec ehr-database mysqldump -u root -padmin123 healthcare_db > backup.sql
```

---

## ❓ FAQ

**Q: Is this real patient data?**  
A: No, all data is synthetic mock data for testing.

**Q: Can I modify the vulnerabilities?**  
A: Yes! Edit service code and rebuild with `docker-compose build --no-cache`.

**Q: How do I backup the database?**  
A: See "Pro Tips" section above.

**Q: Can I run this on my server?**  
A: Only in isolated test environments, never on production networks.

**Q: What if I want more services?**  
A: Add to docker-compose.yml and rebuild.

---

## 📞 Getting Help

1. Check troubleshooting section above
2. Review full documentation files
3. Check Docker logs: `docker-compose logs`
4. Inspect containers: `docker inspect [container]`

---

**Built for security research and education.**

⚠️ **Use Responsibly and Ethically** ⚠️

