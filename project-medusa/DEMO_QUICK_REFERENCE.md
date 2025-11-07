# MEDUSA Demo - Quick Reference Card

**Duration:** 10 minutes demo + 5 minutes Q&A  
**Reference:** `docs/04-usage/complete-mode-reference.md` (all commands & modes)

## 🚀 Pre-Demo Setup (2 minutes)

```bash
# 1. Start lab environment
cd lab-environment
docker-compose up -d

# 2. Verify services
docker-compose ps
curl http://localhost:8080
curl http://localhost:3001/api/health

# 3. Check MEDUSA
medusa status
```

## 📋 Service Quick Reference

| Service | Port | URL/Command | Credentials |
|---------|------|-------------|-------------|
| EHR Web Portal | 8080 | http://localhost:8080 | admin/admin123 |
| EHR API | 3001 | http://localhost:3001 | None (vulnerable) |
| MySQL DB | 3306 | `mysql -h localhost -P 3306 -u root -padmin123` | root/admin123 |
| SSH Server | 2222 | `ssh admin@localhost -p 2222` | admin/admin2024 |
| FTP Server | 21 | `ftp localhost 21` | fileadmin/Files2024! |
| LDAP Server | 389 | `ldapsearch -x -H ldap://localhost:389` | Anonymous |
| Log Viewer | 8081 | http://localhost:8081 | None |
| Workstation | 445 | `smbclient //localhost/shared` | doctor/Doctor2024! |

## 🎯 10-Minute Demo Commands

### Phase 1: Observe Mode (2 min)
```bash
medusa observe --target http://localhost:3001
```

### Phase 2: Autonomous Mode (5 min)
```bash
medusa run --target http://localhost:8080 --autonomous
# Approve prompts with 'y' when they appear
```

### Phase 3: Interactive Mode (1 min)
```bash
medusa shell --target http://localhost:3001
MEDUSA> scan network
MEDUSA> show findings
MEDUSA> exit
```

### Phase 4: Reporting (1 min)
```bash
medusa reports --open
```

## 📋 All MEDUSA Commands

| Command | Purpose |
|---------|---------|
| `medusa setup` | Configure MEDUSA |
| `medusa status` | Show configuration |
| `medusa run --target <url> --autonomous` | Autonomous mode |
| `medusa run --target <url> --mode observe` | Observe mode |
| `medusa shell` | Interactive mode |
| `medusa observe --target <url>` | Safe reconnaissance |
| `medusa reports --open` | Open latest report |
| `medusa logs --latest` | Show latest log |
| `medusa version` | Show version |

**Full reference:** `docs/04-usage/complete-mode-reference.md`

## 🎤 Talking Points

### Attacker 1 (Primary)
- "MEDUSA uses AI to intelligently plan attacks"
- "Approval gates ensure we maintain control"
- "The system adapts based on discovered vulnerabilities"

### Attacker 2 (Secondary)
- "MEDUSA can run multiple assessments in parallel"
- "Observe mode provides safe reconnaissance"
- "The system scales to assess entire networks"

### Defender (Narrator)
- "These vulnerabilities are common in healthcare systems"
- "SQL injection can lead to HIPAA violations"
- "Weak credentials are a critical security issue"

## ⚠️ Emergency Commands

```bash
# Stop MEDUSA
Ctrl+C

# Abort operation
# Type 'a' when prompted for approval

# Reset environment
cd lab-environment
docker-compose down -v
docker-compose up -d
```

## 📊 Expected Findings

### Critical Vulnerabilities
- SQL Injection (EHR Web Portal) - CVSS 9.8
- Missing Authentication (EHR API) - CVSS 9.1
- Weak Database Credentials - CVSS 9.8
- Plaintext Credentials in DB - CVSS 9.6
- Weak SSH Credentials - CVSS 9.8

### Attack Chain
1. SQL Injection → Database Access
2. Credential Extraction → SSH/FTP Access
3. Lateral Movement → Complete Compromise
4. Data Exfiltration → Patient Records

## 🛠️ Troubleshooting

```bash
# Services not starting
docker-compose logs [service-name]
docker-compose restart [service-name]

# MEDUSA not configured
medusa setup

# Port conflicts
netstat -an | grep -E '8080|3001|3306'

# Database connection issues
docker-compose exec ehr-webapp ping ehr-database
```

## 📝 10-Minute Demo Checklist

- [ ] Lab environment started (`docker-compose ps`)
- [ ] Services accessible (`curl http://localhost:8080`)
- [ ] MEDUSA configured (`medusa status`)
- [ ] Browser ready for reports
- [ ] Team roles assigned
- [ ] Q&A topics reviewed

---

**Duration:** 10 minutes demo + 5 minutes Q&A  
**Team:** 2 attackers + 1 defender  
**Focus:** AI-powered penetration testing  
**Reference:** `docs/04-usage/complete-mode-reference.md`

