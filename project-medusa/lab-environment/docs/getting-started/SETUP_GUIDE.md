# MEDUSA Healthcare Lab - Setup Guide

## Quick Start (5 Minutes)

```bash
# Clone or navigate to the project
cd /path/to/project-medusa/docker-lab

# Build and start all services
docker-compose up -d --build

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

**Access Points:**
- EHR Web Portal: http://localhost:8080
- EHR API: http://localhost:3000
- Log Viewer: http://localhost:8081
- SSH: `ssh admin@localhost -p 2222` (password: admin2024)
- MySQL: `mysql -h localhost -P 3306 -u root -padmin123`
- FTP: `ftp localhost 21` (user: fileadmin, pass: Files2024!)

---

## Prerequisites

### System Requirements

**Minimum:**
- CPU: 4 cores
- RAM: 8 GB
- Disk: 20 GB free space
- OS: macOS, Linux, or Windows with WSL2

**Recommended:**
- CPU: 8 cores
- RAM: 16 GB
- Disk: 50 GB free space (SSD preferred)

### Software Requirements

1. **Docker Desktop** (v20.10 or later)
   ```bash
   # Verify installation
   docker --version
   docker-compose --version
   ```

2. **Git** (for cloning the repository)
   ```bash
   git --version
   ```

3. **Optional Tools:**
   - MySQL client: `brew install mysql-client` (macOS)
   - FTP client: Usually pre-installed
   - SSH client: Pre-installed on most systems

---

## Installation Steps

### Step 1: Clone the Repository (If Needed)

```bash
git clone https://github.com/your-org/project-medusa.git
cd project-medusa/docker-lab
```

### Step 2: Review Configuration

Check the `docker-compose.yml` file to ensure port mappings don't conflict with existing services:

**Default Ports:**
- 8080 - EHR Web Portal
- 8081 - Log Viewer
- 3000 - EHR API
- 2222 - SSH Server
- 3306 - MySQL Database
- 21, 21000-21010 - FTP Server
- 389, 636 - LDAP Server
- 445, 5900 - Workstation (SMB/VNC)

**To change ports:** Edit `docker-compose.yml` and modify the port mappings:
```yaml
ports:
  - "8080:80"  # Change 8080 to your preferred port
```

### Step 3: Build the Environment

```bash
# Build all images (first time setup)
docker-compose build

# This will take 5-10 minutes depending on your internet speed
```

### Step 4: Start Services

```bash
# Start all services in detached mode
docker-compose up -d

# Watch startup logs
docker-compose logs -f
```

### Step 5: Verify All Services Are Running

```bash
# Check container status
docker-compose ps

# All containers should show "Up" status
# If any show "Exited", check logs:
docker-compose logs [service-name]
```

### Step 6: Test Connectivity

```bash
# Test web portal
curl http://localhost:8080

# Test API
curl http://localhost:3000/health

# Test database
mysql -h localhost -P 3306 -u root -padmin123 -e "SHOW DATABASES;"

# Test SSH
ssh admin@localhost -p 2222  # password: admin2024

# Test FTP
echo "ls" | ftp -n localhost 21
```

---

## Detailed Service Setup

### EHR Web Portal

**URL:** http://localhost:8080

**Test Credentials:**
- Admin: `admin` / `admin123`
- Doctor: `doctor1` / `doctor123`
- Patient: `patient1` / `patient123`

**Features:**
- Patient portal login
- Patient search functionality
- Medical records dashboard
- File upload capability

**Logs:**
```bash
docker-compose logs -f ehr-webapp
```

---

### EHR API

**URL:** http://localhost:3000

**Endpoints:**
- Health check: `GET /health`
- Login: `POST /api/login`
- Patients: `GET /api/patients`
- User info: `GET /api/users`
- Admin config: `GET /api/admin/config`

**Example API Calls:**
```bash
# Health check
curl http://localhost:3000/health

# Get all patients (no auth required - vulnerability!)
curl http://localhost:3000/api/patients

# Login
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

---

### MySQL Database

**Connection Details:**
- Host: localhost
- Port: 3306
- Database: healthcare_db
- Root Password: admin123
- App User: ehrapp / Welcome123!

**Connect:**
```bash
# Using MySQL client
mysql -h localhost -P 3306 -u root -padmin123

# Show databases
mysql -h localhost -P 3306 -u root -padmin123 -e "SHOW DATABASES;"

# Query patients
mysql -h localhost -P 3306 -u root -padmin123 healthcare_db \
  -e "SELECT id, first_name, last_name, ssn FROM patients LIMIT 5;"
```

**Database Structure:**
- `users` - System user accounts
- `patients` - Patient demographics and PHI
- `appointments` - Scheduled appointments
- `medical_records` - Medical history and notes
- `prescriptions` - Medication prescriptions
- `lab_results` - Laboratory test results
- `audit_log` - System access logs

---

### SSH Server

**Connection:**
```bash
ssh admin@localhost -p 2222
# Password: admin2024
```

**Available Users:**
- root: password123
- admin: admin2024
- doctor: Doctor2024!
- nurse: Nurse123

**Post-Connection:**
```bash
# Check sudo privileges
sudo -l

# Explore filesystem
ls -la /opt/config/
cat /opt/config/app.conf

# Check for sensitive files
find / -name "*password*" 2>/dev/null
find / -name "*.conf" 2>/dev/null
```

---

### FTP Server

**Connect:**
```bash
ftp localhost 21
# Username: fileadmin
# Password: Files2024!
# OR use anonymous login
```

**Anonymous Access:**
```bash
ftp localhost 21
# Name: anonymous
# Password: (just press Enter)

ftp> ls
ftp> cd medical_records
ftp> get patients.csv
ftp> quit
```

**Using Command Line:**
```bash
# Download file via curl
curl ftp://fileadmin:Files2024!@localhost/backups/README.txt

# List directory
curl ftp://anonymous:@localhost/
```

---

### LDAP Server

**Connection Details:**
- Host: localhost
- Port: 389 (LDAP), 636 (LDAPS - not configured)
- Base DN: dc=medcare,dc=local
- Admin DN: cn=admin,dc=medcare,dc=local
- Admin Password: admin123

**Query LDAP:**
```bash
# Anonymous bind (enumerate users)
ldapsearch -x -H ldap://localhost:389 -b "dc=medcare,dc=local"

# Authenticated bind
ldapsearch -x -H ldap://localhost:389 \
  -D "cn=admin,dc=medcare,dc=local" -w admin123 \
  -b "dc=medcare,dc=local"
```

---

### Workstation (SMB/VNC)

**SMB Access:**
```bash
# List shares
smbclient -L //localhost -N

# Access shared folder (no auth)
smbclient //localhost/Shared -N

# Access with credentials
smbclient //localhost/Documents -U doctor
# Password: Doctor2024!
```

**VNC Access:**
```bash
# Connect using VNC client
# Host: localhost:5900
# Password: vnc123
```

---

### Log Collector

**Web Interface:** http://localhost:8081

**Features:**
- Real-time log viewing
- Aggregated logs from all services
- Basic statistics and metrics

**Manual Log Access:**
```bash
# View collected logs
docker exec medusa_logs cat /var/log/collected/all.log

# Export logs
docker cp medusa_logs:/var/log/collected/all.log ./logs-export.txt
```

---

## Network Architecture

```
Host Machine (Your Laptop)
    ↓
Docker Networks:
    ├── healthcare-dmz (172.20.0.0/24)
    │   ├── ehr-webapp (172.20.0.x)
    │   └── ehr-api (172.20.0.x)
    │
    └── healthcare-internal (172.21.0.0/24)
        ├── ehr-database (172.21.0.x)
        ├── ssh-server (172.21.0.x)
        ├── file-server (172.21.0.x)
        ├── ldap-server (172.21.0.x)
        ├── log-collector (172.21.0.x)
        └── workstation (172.21.0.x)
```

**Network Inspection:**
```bash
# View network details
docker network ls
docker network inspect medusa-dmz
docker network inspect medusa-internal

# View container IPs
docker-compose ps -q | xargs docker inspect \
  --format='{{.Name}}: {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
```

---

## Troubleshooting

### Problem: Containers Won't Start

**Solution:**
```bash
# Check Docker service
docker ps

# Check for port conflicts
netstat -an | grep -E '8080|3000|3306|2222'

# Check Docker logs
docker-compose logs [service-name]

# Restart Docker Desktop
# macOS: Restart Docker Desktop app
# Linux: sudo systemctl restart docker
```

### Problem: Database Connection Fails

**Solution:**
```bash
# Check if database is running
docker-compose ps ehr-database

# Check database logs
docker-compose logs ehr-database

# Wait for database to fully initialize (may take 30-60 seconds)
docker-compose exec ehr-database mysqladmin ping -h localhost -u root -padmin123

# Reset database
docker-compose down -v
docker-compose up -d ehr-database
```

### Problem: Web Portal Shows Database Error

**Solution:**
```bash
# Ensure database is ready before webapp starts
docker-compose restart ehr-webapp

# Check connectivity
docker-compose exec ehr-webapp ping -c 3 ehr-database
```

### Problem: Out of Memory

**Solution:**
```bash
# Check Docker resource usage
docker stats

# Reduce service limits in docker-compose.yml:
# Change memory: 1G → memory: 512M

# Or stop some services
docker-compose stop workstation ftp-server
```

### Problem: Slow Performance

**Solutions:**
1. Close unnecessary applications
2. Increase Docker resource allocation (Docker Desktop → Settings → Resources)
3. Use SSD instead of HDD
4. Disable some services you don't need for testing

### Problem: Cannot Connect to Services

**Solution:**
```bash
# Check firewall settings
# macOS: System Preferences → Security & Privacy → Firewall
# Linux: sudo ufw status

# Verify port mappings
docker-compose ps

# Test connectivity from inside container
docker-compose exec ehr-webapp curl http://ehr-database:3306
```

---

## Maintenance Commands

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f ehr-webapp

# Last 100 lines
docker-compose logs --tail=100 ehr-api
```

### Restart Services
```bash
# Restart all
docker-compose restart

# Restart specific service
docker-compose restart ehr-webapp

# Force recreate
docker-compose up -d --force-recreate ehr-webapp
```

### Update Configuration
```bash
# After modifying docker-compose.yml
docker-compose up -d

# After modifying Dockerfile
docker-compose up -d --build [service-name]
```

### Backup Data
```bash
# Backup database
docker-compose exec ehr-database mysqldump -u root -padmin123 healthcare_db > backup.sql

# Backup all volumes
docker run --rm -v medusa_db-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/db-data-backup.tar.gz /data

# Backup logs
docker cp medusa_logs:/var/log/collected ./logs-backup/
```

### Restore Data
```bash
# Restore database
cat backup.sql | docker-compose exec -T ehr-database mysql -u root -padmin123 healthcare_db
```

---

## Complete Reset

### Soft Reset (Keep Volumes)
```bash
docker-compose down
docker-compose up -d
```

### Hard Reset (Delete Everything)
```bash
# Stop and remove containers, networks, volumes
docker-compose down -v

# Remove images
docker-compose down --rmi all

# Clean up everything
docker system prune -a --volumes

# Rebuild from scratch
docker-compose up -d --build
```

---

## Testing with MEDUSA

### 1. Start the Lab
```bash
cd docker-lab
docker-compose up -d
```

### 2. Wait for All Services
```bash
# Monitor until all services are healthy
watch docker-compose ps
```

### 3. Run MEDUSA Agent
```bash
cd ../medusa-cli
python medusa.py --target localhost --mode full-assessment
```

### 4. Monitor Activity
```bash
# Watch logs in real-time
docker-compose logs -f

# View consolidated logs
open http://localhost:8081
```

### 5. Review Results
```bash
# Export MEDUSA report
cat medusa_assessment_report.txt

# Export compromised data
ls -la medusa_extracted_data/

# Review container logs
docker-compose logs > full-lab-logs.txt
```

### 6. Reset for Next Test
```bash
docker-compose down -v
docker-compose up -d --build
```

---

## Security Best Practices for Lab Operation

### DO:
✅ Run in isolated environment (isolated network)  
✅ Use strong passwords on host machine  
✅ Keep Docker updated  
✅ Review logs regularly  
✅ Reset environment after each test  
✅ Document all testing activities  

### DO NOT:
❌ Expose to the internet  
❌ Run on production networks  
❌ Use real patient data  
❌ Leave running when not testing  
❌ Share credentials outside team  
❌ Run without authorization  

---

## Advanced Configuration

### Enable Complete Network Isolation

Edit `docker-compose.yml`:
```yaml
networks:
  healthcare-internal:
    internal: true  # Change from false to true
```

This prevents containers from accessing the internet.

### Custom Resource Limits

Adjust per-service limits in `docker-compose.yml`:
```yaml
deploy:
  resources:
    limits:
      cpus: '0.5'      # Adjust CPU
      memory: 512M     # Adjust RAM
```

### Enable Additional Logging

Add to individual services:
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

---

## Getting Help

### Check Documentation
- [Network Architecture](./NETWORK_ARCHITECTURE.md)
- [Vulnerability Documentation](./VULNERABILITY_DOCUMENTATION.md)
- [Docker Compose Reference](https://docs.docker.com/compose/)

### Debug Mode
```bash
# Enable verbose logging
docker-compose --verbose up

# Check individual container
docker-compose exec [service-name] /bin/bash
```

### Common Issues
- Port conflicts: Change port mappings
- Memory issues: Reduce service limits or stop unnecessary services
- Network issues: Check Docker network settings
- Database issues: Ensure proper startup order

---

## Next Steps

1. **Read Vulnerability Documentation**
   - Review [VULNERABILITY_DOCUMENTATION.md](./VULNERABILITY_DOCUMENTATION.md)
   - Understand each vulnerability and exploitation method

2. **Manual Testing**
   - Try exploiting vulnerabilities manually first
   - Understand attack chains
   - Document your findings

3. **MEDUSA Testing**
   - Run MEDUSA against the lab
   - Compare MEDUSA results with manual findings
   - Improve MEDUSA based on gaps

4. **Contribute**
   - Add new vulnerabilities
   - Improve documentation
   - Share findings with team

---

## Appendix: Quick Reference

### Container Names
- `medusa_ehr_web` - EHR Web Portal
- `medusa_ehr_db` - MySQL Database
- `medusa_ehr_api` - API Server
- `medusa_ssh_server` - SSH Server
- `medusa_ftp_server` - FTP Server
- `medusa_ldap` - LDAP Server
- `medusa_logs` - Log Collector
- `medusa_workstation` - Workstation

### Network Names
- `medusa-dmz` - DMZ Network
- `medusa-internal` - Internal Network

### Volume Names
- `medusa_db-data` - Database data
- `medusa_db-logs` - Database logs
- `medusa_ehr-logs` - Web portal logs
- `medusa_api-logs` - API logs
- `medusa_centralized-logs` - All logs

### Useful Commands Cheat Sheet
```bash
# Start lab
docker-compose up -d

# Stop lab
docker-compose down

# View status
docker-compose ps

# View logs
docker-compose logs -f

# Execute command in container
docker-compose exec [service] [command]

# Reset everything
docker-compose down -v && docker-compose up -d --build

# View resource usage
docker stats

# Inspect network
docker network inspect medusa-internal

# Backup database
docker-compose exec ehr-database mysqldump -u root -padmin123 healthcare_db > backup.sql
```

---

**Setup Guide Version:** 1.0  
**Last Updated:** 2024-01-30  
**For:** MEDUSA Project - Healthcare Security Testing Lab

