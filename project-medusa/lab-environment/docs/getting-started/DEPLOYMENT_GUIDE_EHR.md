# MedCare EHR Application - Deployment Guide

## 🚀 Quick Start

### Option 1: Standalone Deployment (Recommended for Testing)

```bash
cd docker-lab/services/ehr-webapp
docker-compose up -d
```

This will start:
- EHR Web Application on port 8080
- MySQL Database on port 3306

Access the application:
```
http://localhost:8080
```

Default credentials:
```
Username: admin
Password: admin123
```

### Option 2: Full Lab Environment

```bash
cd docker-lab
docker-compose up -d
```

This starts the complete healthcare network simulation with multiple services.

---

## 📋 Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 2GB free RAM
- 5GB free disk space

---

## 🔧 Installation Steps

### 1. Clone/Navigate to Project

```bash
cd /path/to/project-medusa/docker-lab/services/ehr-webapp
```

### 2. Copy Environment File

```bash
cp .env.example .env
```

### 3. Build the Application

```bash
docker-compose build
```

### 4. Start Services

```bash
docker-compose up -d
```

### 5. Verify Deployment

```bash
# Check running containers
docker-compose ps

# Check logs
docker-compose logs -f ehr-webapp

# Test database connection
docker exec ehr_database mysql -uwebapp -pwebapp123 -e "SHOW DATABASES;"
```

### 6. Access the Application

Open browser: `http://localhost:8080`

---

## 🗄️ Database Initialization

The database is automatically initialized with:
- **10 users** (various roles: admin, doctor, nurse, patient)
- **20 patients** (synthetic HIPAA-compliant data)
- **Medical records** and **appointments**

### Manual Database Initialization (if needed)

```bash
# Copy SQL file to container
docker cp init-db.sql ehr_database:/tmp/

# Execute initialization
docker exec -i ehr_database mysql -uroot -proot123 < init-db.sql

# Or from host
docker exec -i ehr_database mysql -uroot -proot123 healthcare_db < init-db.sql
```

### Verify Database

```bash
docker exec ehr_database mysql -uwebapp -pwebapp123 -e "
USE healthcare_db;
SELECT COUNT(*) as user_count FROM users;
SELECT COUNT(*) as patient_count FROM patients;
"
```

Expected output:
```
user_count
10

patient_count
20
```

---

## 🌐 Accessing Services

### Web Application
- **URL**: http://localhost:8080
- **Login**: admin / admin123

### MySQL Database
```bash
mysql -h localhost -P 3306 -u webapp -pwebapp123 healthcare_db
```

Or using Docker:
```bash
docker exec -it ehr_database mysql -uwebapp -pwebapp123 healthcare_db
```

### Application Logs
```bash
docker-compose logs -f ehr-webapp
```

### Database Logs
```bash
docker-compose logs -f ehr-database
```

---

## 🛠️ Common Operations

### Stop Services

```bash
docker-compose stop
```

### Start Services

```bash
docker-compose start
```

### Restart Services

```bash
docker-compose restart
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f ehr-webapp
docker-compose logs -f ehr-database
```

### Execute Commands in Container

```bash
# Web application container
docker exec -it ehr_webapp bash

# Database container
docker exec -it ehr_database bash
```

### Reset Database (Fresh Start)

```bash
docker-compose down -v
docker-compose up -d
```

⚠️ **Warning**: This deletes all data!

---

## 📊 Testing the Deployment

### 1. Test Web Application

```bash
curl http://localhost:8080
```

Should return HTML login page.

### 2. Test Login (SQL Injection)

```bash
curl -X POST http://localhost:8080/index.php \
  -d "username=admin' OR '1'='1' -- &password=anything"
```

Should bypass authentication.

### 3. Test Patient Search

```bash
curl "http://localhost:8080/search.php?search=John"
```

### 4. Test Database Connectivity

```bash
docker exec ehr_database mysql -uwebapp -pwebapp123 -e "
SELECT * FROM healthcare_db.users LIMIT 5;
"
```

### 5. Test File Upload

```bash
echo "<?php phpinfo(); ?>" > test.php

curl -F "file=@test.php" http://localhost:8080/upload.php \
  -b "PHPSESSID=your_session_id"
```

---

## 🔍 Troubleshooting

### Container Won't Start

**Issue**: Port already in use
```bash
# Check what's using port 8080
lsof -i :8080

# Change port in docker-compose.yml
ports:
  - "8081:80"  # Use 8081 instead
```

**Issue**: Database connection failed
```bash
# Check if database is running
docker-compose ps

# Restart database
docker-compose restart ehr-database

# Check database logs
docker-compose logs ehr-database
```

### Database Not Initialized

```bash
# Check if init script ran
docker exec ehr_database ls -la /docker-entrypoint-initdb.d/

# Manually run initialization
docker exec -i ehr_database mysql -uroot -proot123 < init-db.sql
```

### PHP Errors Not Displaying

```bash
# Check PHP configuration
docker exec ehr_webapp php -i | grep display_errors

# Should show: display_errors => On
```

### Upload Directory Permission Issues

```bash
# Fix permissions
docker exec ehr_webapp chmod 777 /var/www/html/uploads

# Verify
docker exec ehr_webapp ls -la /var/www/html/uploads
```

### Cannot Connect to Database

```bash
# Test from web container
docker exec ehr_webapp ping ehr-database

# Test MySQL connection
docker exec ehr_webapp mysql -h ehr-database -u webapp -pwebapp123 -e "SHOW DATABASES;"
```

---

## 🔐 Security Testing Setup

### 1. Install Testing Tools (on host)

```bash
# Burp Suite (for web testing)
# https://portswigger.net/burp

# SQLmap (for SQL injection)
sudo apt install sqlmap

# OWASP ZAP
sudo apt install zaproxy

# Nikto
sudo apt install nikto
```

### 2. Configure Proxy

Set browser proxy to Burp Suite:
- Host: localhost
- Port: 8080

Or configure in Burp:
- Proxy > Options > Proxy Listeners > Add
- Bind to port: 8080
- Target: localhost:8080

### 3. Run Basic Scans

```bash
# Nikto scan
nikto -h http://localhost:8080

# SQLmap
sqlmap -u "http://localhost:8080/search.php?search=test" --batch

# OWASP ZAP (automated scan)
zap-cli quick-scan http://localhost:8080
```

---

## 📁 Directory Structure

```
ehr-webapp/
├── Dockerfile                  # Container definition
├── docker-compose.yml          # Service orchestration
├── init-db.sql                 # Database schema & seed data
├── .env.example                # Environment variables template
├── README.md                   # Main documentation
├── DEPLOYMENT_GUIDE.md         # This file
├── MITRE_ATTACK_MAPPING.md     # ATT&CK framework mapping
├── src/                        # Application source code
│   ├── index.php               # Login page
│   ├── dashboard.php           # Main dashboard
│   ├── search.php              # Patient search
│   ├── register.php            # User registration
│   ├── upload.php              # File upload
│   ├── reports.php             # Reporting functions
│   ├── settings.php            # Admin settings
│   ├── api.php                 # API documentation
│   └── logout.php              # Logout handler
├── uploads/                    # File upload directory (created at runtime)
└── logs/                       # Apache logs (created at runtime)
```

---

## 🔄 Updating the Application

### Update Application Code

```bash
# Rebuild containers
docker-compose build --no-cache

# Restart with new image
docker-compose up -d
```

### Update Database Schema

```bash
# Method 1: Complete reset (loses data)
docker-compose down -v
docker-compose up -d

# Method 2: Manual update (preserves data)
docker exec -i ehr_database mysql -uroot -proot123 healthcare_db < update.sql
```

---

## 📊 Monitoring

### Resource Usage

```bash
# View resource consumption
docker stats

# Specific container
docker stats ehr_webapp ehr_database
```

### Access Logs

```bash
# Real-time Apache access logs
docker exec ehr_webapp tail -f /var/log/apache2/access.log

# Real-time error logs
docker exec ehr_webapp tail -f /var/log/apache2/error.log
```

### Database Queries

```bash
# Enable query logging (if not already enabled)
docker exec ehr_database mysql -uroot -proot123 -e "
SET GLOBAL general_log = 'ON';
"

# View query log
docker exec ehr_database tail -f /var/log/mysql/query.log
```

---

## 🧹 Cleanup

### Remove Containers (Keep Data)

```bash
docker-compose down
```

### Remove Everything (Including Data)

```bash
docker-compose down -v
```

### Remove Images

```bash
docker rmi ehr-webapp_ehr-webapp
docker rmi mysql:8.0
```

### Complete Cleanup

```bash
docker-compose down -v --rmi all
docker system prune -a
```

---

## 🌐 Network Configuration

### Default Network Setup

- **Network Name**: `ehr-network`
- **Driver**: bridge
- **Webapp IP**: Assigned by Docker
- **Database IP**: Assigned by Docker

### Custom Network Configuration

Edit `docker-compose.yml`:

```yaml
networks:
  ehr-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.25.0.0/24
          gateway: 172.25.0.1
```

---

## 🔒 Production Hardening (What NOT to Do)

This is a vulnerable application. If you were to secure it:

### ❌ Current (Vulnerable)
- Plain text passwords
- No input validation
- SQL queries with string concatenation
- No CSRF protection
- Unrestricted file upload
- Display errors enabled

### ✅ Secure Alternative
- Bcrypt/Argon2 password hashing
- Input validation and sanitization
- Prepared statements for all queries
- CSRF tokens on all forms
- File type validation, size limits, rename uploads
- Error logging only (no display)
- HTTPS only
- Rate limiting
- WAF deployment

---

## 📞 Support

For issues with the lab environment:
- Check logs: `docker-compose logs`
- Review README.md for vulnerability documentation
- Consult MITRE_ATTACK_MAPPING.md for testing guidance

---

## ⚖️ Legal Notice

This application is for **EDUCATIONAL PURPOSES ONLY**.

- Use only in isolated lab environments
- Never deploy with real data
- Never expose to the internet
- Obtain proper authorization before testing

---

## 📚 Additional Resources

- **Main Documentation**: README.md
- **Attack Techniques**: MITRE_ATTACK_MAPPING.md
- **Lab Setup**: ../../SETUP_GUIDE.md
- **Project Overview**: ../../PROJECT_SUMMARY.md

---

**Happy Ethical Hacking! 🎯**

