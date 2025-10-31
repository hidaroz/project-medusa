# MEDUSA Healthcare Network Simulation - Architecture

## Network Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         EXTERNAL ACCESS (Host)                          │
│                                                                         │
│  Port Mappings:                                                         │
│  • 8080  → EHR Web Portal                                              │
│  • 8081  → Log Viewer                                                  │
│  • 3000  → EHR API                                                     │
│  • 2222  → SSH Server                                                  │
│  • 3306  → MySQL Database                                              │
│  • 21    → FTP Server                                                  │
│  • 389   → LDAP Server                                                 │
│  • 445   → SMB Shares                                                  │
│  • 5900  → VNC (Workstation)                                           │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────────────────┐
│                      HEALTHCARE-DMZ NETWORK                             │
│                      Subnet: 172.20.0.0/24                              │
│                                                                         │
│  ┌─────────────────────┐           ┌──────────────────────┐           │
│  │   EHR Web Portal    │           │     EHR API Server   │           │
│  │   (ehr-webapp)      │◄─────────►│     (ehr-api)        │           │
│  │   172.20.0.x:80     │           │     172.20.0.x:3000  │           │
│  │                     │           │                      │           │
│  │ • Apache/PHP        │           │ • Node.js/Express    │           │
│  │ • Patient Portal    │           │ • REST API           │           │
│  │ • SQL Injection     │           │ • JWT Auth (Weak)    │           │
│  │ • XSS Vulnerable    │           │ • No Rate Limiting   │           │
│  └──────────┬──────────┘           └──────────┬───────────┘           │
│             │                                  │                        │
│             │         ┌───────────────────────┘                        │
└─────────────┼─────────┼────────────────────────────────────────────────┘
              │         │
              │         │
┌─────────────┴─────────┴────────────────────────────────────────────────┐
│                  HEALTHCARE-INTERNAL NETWORK                            │
│                  Subnet: 172.21.0.0/24                                  │
│                                                                         │
│  ┌─────────────────┐   ┌─────────────────┐   ┌──────────────────┐    │
│  │  MySQL Database │   │   LDAP Server   │   │   Log Collector  │    │
│  │  (ehr-database) │   │  (ldap-server)  │   │  (log-collector) │    │
│  │  172.21.0.x:3306│   │  172.21.0.x:389 │   │  172.21.0.x:514  │    │
│  │                 │   │                 │   │                  │    │
│  │ • Patient Data  │   │ • User Accounts │   │ • Syslog Server  │    │
│  │ • Weak Root PW  │   │ • Anonymous Bind│   │ • Web Dashboard  │    │
│  │ • Open Port     │   │ • Plaintext     │   │ • Event Monitor  │    │
│  └─────────────────┘   └─────────────────┘   └──────────────────┘    │
│                                                                         │
│  ┌─────────────────┐   ┌─────────────────┐   ┌──────────────────┐    │
│  │   FTP Server    │   │   SSH Server    │   │   Workstation    │    │
│  │  (file-server)  │   │  (ssh-server)   │   │  (workstation)   │    │
│  │  172.21.0.x:21  │   │  172.21.0.x:22  │   │  172.21.0.x:445  │    │
│  │                 │   │                 │   │                  │    │
│  │ • Medical Files │   │ • Admin Access  │   │ • SMB Shares     │    │
│  │ • Anon FTP ON   │   │ • Weak Creds    │   │ • Cached Creds   │    │
│  │ • No Encryption │   │ • Sudo Misconfig│   │ • VNC Access     │    │
│  └─────────────────┘   └─────────────────┘   └──────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Network Segmentation

### DMZ Network (172.20.0.0/24)
**Purpose**: Simulates a perimeter network with externally accessible services.

**Connected Services**:
- `ehr-webapp` - Public-facing patient portal
- `ehr-api` - REST API for EHR system

**Security Characteristics**:
- More exposed to external threats
- Should have restricted access to internal network
- Typical first entry point for attacks

### Internal Network (172.21.0.0/24)
**Purpose**: Simulates internal corporate network with sensitive resources.

**Connected Services**:
- `ehr-database` - MySQL with patient data
- `ssh-server` - Administrative access server
- `file-server` - FTP server with medical records
- `ldap-server` - Authentication directory
- `log-collector` - Centralized logging
- `workstation` - Employee workstation
- `ehr-api` - Also connected here for database access
- `ehr-webapp` - Also connected here for database access

**Security Characteristics**:
- Contains sensitive data and systems
- Typically harder to access (requires pivoting)
- Lateral movement playground

## Attack Surface Analysis

### External Attack Vectors (Direct Access)
1. **Web Application** (Port 8080)
   - SQL Injection entry point
   - XSS for credential harvesting
   - IDOR for data enumeration

2. **API Server** (Port 3000)
   - Unauthenticated endpoints
   - JWT cracking opportunity
   - Information disclosure via errors

3. **SSH Server** (Port 2222)
   - Credential brute-forcing
   - Key-based authentication bypass

4. **MySQL** (Port 3306)
   - Direct database access
   - Credential stuffing
   - Data exfiltration

5. **FTP Server** (Port 21)
   - Anonymous access
   - File enumeration
   - Backdoor upload potential

6. **LDAP** (Port 389)
   - User enumeration
   - Anonymous bind exploitation
   - Credential extraction

### Internal Attack Vectors (Post-Compromise)
1. **Lateral Movement**
   - SMB shares from workstation
   - Credential reuse across services
   - LDAP information gathering

2. **Privilege Escalation**
   - SSH sudo misconfigurations
   - Database privilege escalation
   - Container escape attempts

3. **Data Exfiltration**
   - Database dumps
   - FTP file downloads
   - Log file analysis

## Service Dependencies

```
┌─────────────────┐
│   ehr-webapp    │
│                 │
│   Depends on:   │
│   • ehr-database│
└────────┬────────┘
         │
         ▼
┌─────────────────┐       ┌─────────────────┐
│   ehr-api       │◄─────►│  ehr-database   │
│                 │       │                 │
│   Depends on:   │       │  (Independent)  │
│   • ehr-database│       └─────────────────┘
└─────────────────┘

┌─────────────────┐       ┌─────────────────┐
│   ssh-server    │       │   file-server   │
│                 │       │                 │
│  (Independent)  │       │  (Independent)  │
└─────────────────┘       └─────────────────┘

┌─────────────────┐       ┌─────────────────┐
│   ldap-server   │       │  log-collector  │
│                 │       │                 │
│  (Independent)  │       │  (Independent)  │
└─────────────────┘       └─────────────────┘

┌─────────────────┐
│   workstation   │
│                 │
│  (Independent)  │
└─────────────────┘
```

## Resource Allocation

### Total Estimated Resources
- **CPU**: ~3.6 cores (burst)
- **Memory**: ~3.6 GB RAM
- **Disk**: ~5-10 GB (including logs and data)

### Per-Service Allocation
| Service | CPU Limit | Memory Limit | Priority |
|---------|-----------|--------------|----------|
| ehr-webapp | 0.5 core | 512 MB | High |
| ehr-database | 1.0 core | 1 GB | Critical |
| ehr-api | 0.5 core | 512 MB | High |
| ssh-server | 0.3 core | 256 MB | Medium |
| file-server | 0.2 core | 256 MB | Low |
| ldap-server | 0.3 core | 256 MB | Medium |
| log-collector | 0.3 core | 384 MB | Medium |
| workstation | 0.5 core | 512 MB | Medium |

**Note**: These are limits, not reservations. Actual usage will be lower during idle periods.

## Volume Strategy

### Persistent Volumes
All volumes use Docker's local driver for simplicity:

1. **Database Volumes** (`db-data`, `db-logs`)
   - Persist patient data between restarts
   - Maintain query logs for analysis

2. **Application Volumes** (`ehr-logs`, `ehr-uploads`, `api-logs`)
   - Store application logs
   - Maintain uploaded files (potential backdoors)

3. **Service Volumes** (`ssh-logs`, `ftp-logs`, `ldap-logs`, etc.)
   - Capture all service activities
   - Enable post-exploitation forensics

4. **Centralized Logs** (`centralized-logs`)
   - Aggregates logs from all services
   - Single point for MEDUSA activity analysis

### Host Mounts
Read-only mounts for static data:
- `./mock-data/medical-records` → FTP server
- `./mock-data/documents` → Workstation
- `./shared-files` → SSH server
- `./init-scripts/db` → Database initialization

### Analysis Mount
- `./analysis` → Writable mount for log analysis output

## Security Considerations

### Intentional Vulnerabilities (DOCUMENTED)
All vulnerabilities are intentional for testing purposes:

1. **Weak Credentials**: All services use weak, predictable passwords
2. **Missing Authentication**: Some API endpoints lack auth checks
3. **Insecure Protocols**: Plain FTP, unencrypted LDAP
4. **Misconfigurations**: Open ports, permissive sudo, anonymous access
5. **Web Vulnerabilities**: SQLi, XSS, IDOR, CSRF
6. **Information Disclosure**: Verbose errors, exposed services

### Isolation Strategy
While the lab contains vulnerabilities:
- **DO NOT** expose to the internet
- **DO NOT** run on production networks
- **USE** on isolated test networks only
- **FIREWALL** the host machine appropriately
- **RESET** environment after each test session

### Network Isolation Options

**Current Configuration**: 
- Networks are bridged to host for easy access
- Internet access enabled for updates if needed

**Full Isolation Mode**:
To completely isolate from the internet, modify `docker-compose.yml`:
```yaml
networks:
  healthcare-internal:
    internal: true  # Change from false to true
```

This prevents containers from accessing external networks but maintains inter-container communication.

## Setup Time Breakdown

### Initial Setup (~8-10 minutes)
1. Image pulls: 3-5 minutes
2. Image builds: 4-5 minutes
3. Container startup: 30-60 seconds
4. Database initialization: 30-60 seconds

### Subsequent Starts (~1-2 minutes)
1. Container startup: 30-60 seconds
2. Service ready: 30-60 seconds

### Complete Reset (~5-7 minutes)
1. Teardown: 30 seconds
2. Volume cleanup: 10 seconds
3. Rebuild & restart: 4-6 minutes

## Monitoring and Logging

### Access Points
- **Centralized Logs**: http://localhost:8081
- **Individual Service Logs**: `docker-compose logs -f [service]`
- **Volume Inspection**: `docker volume inspect medusa_[volume-name]`
- **Network Traffic**: Use `tcpdump` on docker networks

### Log Locations
All logs stored in Docker volumes:
```bash
# View log volume contents
docker run --rm -v medusa_centralized-logs:/logs alpine ls -lah /logs

# Export logs for analysis
docker run --rm -v medusa_centralized-logs:/logs -v $(pwd):/backup alpine \
  tar czf /backup/logs-backup.tar.gz /logs
```

## Expansion Possibilities

### Future Services (Optional)
1. **Email Server** - Phishing target
2. **VPN Server** - Remote access simulation
3. **PACS System** - Medical imaging server
4. **IoT Devices** - Medical device simulation
5. **Backup Server** - Data backup/recovery testing
6. **Print Server** - Network printer simulation

### Advanced Features
1. **Network Traffic Capture** - Integrate tcpdump/Wireshark
2. **IDS/IPS Simulation** - Add Snort/Suricata containers
3. **SIEM Integration** - Add ELK stack for log analysis
4. **Honey Pots** - Decoy services for detection testing
5. **Active Directory** - Full Windows domain simulation

## Testing Scenarios

### Reconnaissance Phase
1. Network scanning and enumeration
2. Service fingerprinting
3. User enumeration (LDAP, SMB)
4. Web application mapping

### Initial Access
1. SQL injection on web portal
2. Weak credential attacks
3. Anonymous FTP access
4. Unauthenticated API endpoints

### Lateral Movement
1. Credential reuse across services
2. SMB share enumeration
3. SSH key extraction and reuse
4. Database credential extraction

### Privilege Escalation
1. Sudo misconfigurations
2. Database privilege escalation
3. Weak file permissions
4. Container escape attempts

### Data Exfiltration
1. Patient database dumps
2. Medical record downloads
3. Credential harvesting
4. Log file analysis

## Maintenance

### Regular Tasks
- **Daily**: Check container health
- **Weekly**: Review logs for anomalies
- **Monthly**: Update base images (rebuild)
- **Per Test**: Reset environment completely

### Cleanup Commands
```bash
# Stop all containers
docker-compose down

# Remove all volumes (COMPLETE RESET)
docker-compose down -v

# Remove specific volume
docker volume rm medusa_db-data

# Remove all project images
docker-compose down --rmi all

# Full cleanup (nuclear option)
docker-compose down -v --rmi all --remove-orphans
```

## Troubleshooting

### Common Issues

1. **Port Conflicts**
   - Check if ports 8080, 3000, 2222, 3306, 21, 389, 445, 5900 are in use
   - Modify port mappings in `docker-compose.yml` if needed

2. **Memory Issues**
   - Reduce service limits in `docker-compose.yml`
   - Close unnecessary applications
   - Consider disabling some services

3. **Database Won't Start**
   - Check db-data volume isn't corrupted
   - Reset: `docker volume rm medusa_db-data`

4. **Network Connectivity**
   - Verify Docker network: `docker network ls`
   - Inspect: `docker network inspect medusa-internal`

5. **Build Failures**
   - Clear build cache: `docker system prune -a`
   - Check Dockerfile syntax
   - Verify base image availability

### Debug Mode
Enable verbose logging:
```bash
# View all container logs
docker-compose logs -f

# Debug specific service
docker-compose logs -f ehr-webapp

# Check container status
docker-compose ps

# Execute commands in running container
docker-compose exec ehr-webapp bash
```

## Security Reminder

⚠️ **IMPORTANT**: This lab environment contains intentional security vulnerabilities and should NEVER be exposed to the internet or used in production environments. All vulnerabilities are documented and designed for educational and testing purposes only.

Use responsibly and in accordance with applicable laws and regulations.

