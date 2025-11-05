# Lab Environment Frontend Container Status & Configuration

## 📍 Frontend Container Location

### Container Name
- **Service Name**: `ehr-webapp`
- **Container Name**: `medusa_ehr_web`
- **Hostname**: `ehr-portal`

### Configuration Files
1. **Main Docker Compose**: `lab-environment/docker-compose.yml` (lines 23-50)
2. **Development Override**: `lab-environment/docker-compose.override.yml` (lines 23-42)
3. **Dockerfile**: `lab-environment/services/ehr-webapp/Dockerfile`
4. **Source Code**: `lab-environment/services/ehr-webapp/src/`

---

## 🔌 Service Connections

### Network Configuration
The frontend container is connected to **two Docker networks**:

1. **`healthcare-dmz`** (172.20.0.0/24)
   - External-facing network for web services
   - Allows public access via port 8080

2. **`healthcare-internal`** (172.21.0.0/24)
   - Internal network for backend services
   - Used for database communication

### Connected Services

#### 1. **Database Connection** (Primary Dependency)
- **Service**: `ehr-database` (MySQL 8.0)
- **Container Name**: `medusa_ehr_db`
- **Hostname**: `db-server`
- **Connection Details**:
  ```env
  DB_HOST=ehr-database
  DB_USER=ehrapp
  DB_PASS=Welcome123!
  DB_NAME=healthcare_db
  ```
- **Port**: 3306 (internal network only)
- **Dependency**: `depends_on: ehr-database`

#### 2. **EHR API Service** (Same Network)
- **Service**: `ehr-api`
- **Container Name**: `medusa_ehr_api`
- **Hostname**: `api-server`
- **Port**: 3000
- **Network**: Both `healthcare-dmz` and `healthcare-internal`
- **Note**: Webapp can communicate with API via internal network

#### 3. **Log Collector** (Same Network)
- **Service**: `log-collector`
- **Container Name**: `medusa_logs`
- **Network**: `healthcare-internal`
- **Port**: 8081 (for web UI)

---

## 🌐 Port Mapping

### Exposed Ports
- **Host Port**: `8080`
- **Container Port**: `80`
- **Protocol**: HTTP
- **Access URL**: `http://localhost:8080`

### Environment Variables
```yaml
environment:
  - DB_HOST=ehr-database
  - DB_USER=ehrapp
  - DB_PASS=Welcome123!
  - DB_NAME=healthcare_db
  - APACHE_RUN_USER=www-data
  - APACHE_RUN_GROUP=www-data
```

### Development Override (if using docker-compose.override.yml)
```yaml
environment:
  - PHP_DISPLAY_ERRORS=On
  - PHP_ERROR_REPORTING=E_ALL
  - XDEBUG_MODE=debug
  - XDEBUG_CONFIG=client_host=host.docker.internal client_port=9003
```

---

## 💾 Volume Mounts

### Production Volumes
```yaml
volumes:
  - ehr-logs:/var/log/apache2          # Apache logs
  - ehr-uploads:/var/www/html/uploads  # File uploads
```

### Development Override Volumes
```yaml
volumes:
  - ./services/ehr-webapp/src:/var/www/html:rw          # Live code editing
  - ./dev-logs/ehr-webapp:/var/log/apache2:rw          # Accessible logs
```

---

## 🔍 Database Connection Code

The frontend uses environment variables for database connection:

**Example from `dashboard.php`**:
```php
$conn = new mysqli(
    getenv('DB_HOST'),      // ehr-database
    getenv('DB_USER'),      // ehrapp
    getenv('DB_PASS'),      // Welcome123!
    getenv('DB_NAME')       // healthcare_db
);
```

**Files using database connection**:
- `src/index.php` (login)
- `src/dashboard.php` (patient dashboard)
- `src/search.php` (patient search)
- `src/reports.php` (reporting)
- `src/register.php` (user registration)
- `src/settings.php` (admin settings)

---

## ✅ Current Status Check

### Check Container Status
```bash
cd lab-environment
docker-compose ps
```

### Expected Output (when running)
```
NAME                 STATUS                          PORTS
medusa_ehr_web      Up X minutes (healthy)          0.0.0.0:8080->80/tcp
medusa_ehr_db       Up X minutes                    0.0.0.0:3306->3306/tcp
```

### Verify Container is Running
```bash
docker ps | grep medusa_ehr_web
```

### Check Network Connectivity
```bash
# List networks
docker network ls | grep healthcare

# Inspect network connections
docker network inspect lab-environment_healthcare-dmz
docker network inspect lab-environment_healthcare-internal
```

### Test Database Connection (from webapp container)
```bash
docker exec medusa_ehr_web php -r "
try {
    \$conn = new mysqli('ehr-database', 'ehrapp', 'Welcome123!', 'healthcare_db');
    echo 'Database connection: SUCCESS\n';
    \$conn->close();
} catch (Exception \$e) {
    echo 'Database connection: FAILED - ' . \$e->getMessage() . '\n';
}
"
```

### Test Web Service
```bash
# From host
curl http://localhost:8080 | head -20

# From container
docker exec medusa_ehr_web curl -s http://localhost/ | head -20
```

---

## 🚀 Starting the Frontend Service

### Start All Services
```bash
cd lab-environment
docker-compose up -d
```

### Start Only Frontend (requires database)
```bash
cd lab-environment
docker-compose up -d ehr-database ehr-webapp
```

### Rebuild Frontend Container
```bash
cd lab-environment
docker-compose build ehr-webapp
docker-compose up -d ehr-webapp
```

### View Logs
```bash
# All logs
docker-compose logs -f ehr-webapp

# Recent logs
docker-compose logs --tail=50 ehr-webapp
```

---

## 🔧 Troubleshooting

### Container Not Starting

1. **Check if database is running**:
   ```bash
   docker-compose ps ehr-database
   ```

2. **Check logs for errors**:
   ```bash
   docker-compose logs ehr-webapp
   ```

3. **Verify network exists**:
   ```bash
   docker network ls | grep healthcare
   ```

### Database Connection Failed

1. **Verify database is accessible**:
   ```bash
   docker exec medusa_ehr_db mysql -uehrapp -pWelcome123! -e "SHOW DATABASES;"
   ```

2. **Check environment variables**:
   ```bash
   docker exec medusa_ehr_web env | grep DB_
   ```

3. **Test network connectivity**:
   ```bash
   docker exec medusa_ehr_web getent hosts ehr-database
   ```

### Port Already in Use

If port 8080 is already in use:
```bash
# Find what's using the port
lsof -i :8080

# Or change port in docker-compose.yml:
ports:
  - "8081:80"  # Change 8080 to 8081
```

### Source Code Not Updating

If using development override:
1. Verify volume mount is correct in `docker-compose.override.yml`
2. Check file permissions in `services/ehr-webapp/src/`
3. Restart container: `docker-compose restart ehr-webapp`

---

## 📊 Service Health Check

Run the health check script:
```bash
cd lab-environment
python3 healthcheck.py
```

This will verify:
- ✅ Web service is responding
- ✅ Database connectivity
- ✅ Network configuration
- ✅ Port accessibility

---

## 🔗 Related Services Integration

### How Frontend Connects to Other Services:

1. **Direct Database Access**:
   - Frontend connects directly to MySQL database
   - Uses hostname `ehr-database` (resolved by Docker DNS)
   - Connection via `healthcare-internal` network

2. **Potential API Integration**:
   - Frontend could call EHR API on `http://api-server:3000`
   - Currently uses direct database queries
   - API available on same networks

3. **Log Collection**:
   - Apache logs can be forwarded to log collector
   - Log collector on `healthcare-internal` network

---

## 📝 Summary

### Container Configuration ✅
- **Location**: Defined in `lab-environment/docker-compose.yml`
- **Service**: `ehr-webapp`
- **Container**: `medusa_ehr_web`

### Network Setup ✅
- **DMZ Network**: `healthcare-dmz` (external access)
- **Internal Network**: `healthcare-internal` (database access)
- **Both networks configured correctly**

### Service Connections ✅
- **Database**: ✅ Connected via `ehr-database` hostname
- **API**: ✅ Available on same network
- **Log Collector**: ✅ Available on same network

### Status Check ⚠️
- **Current Status**: Containers not running (need to start)
- **To Start**: Run `docker-compose up -d` in `lab-environment/` directory

---

## 🎯 Quick Verification Commands

```bash
# 1. Check if containers are running
cd lab-environment && docker-compose ps

# 2. Start all services
docker-compose up -d

# 3. Verify frontend is accessible
curl http://localhost:8080

# 4. Test database connection
docker exec medusa_ehr_web php -r "\$conn = new mysqli('ehr-database', 'ehrapp', 'Welcome123!', 'healthcare_db'); echo 'SUCCESS'; \$conn->close();"

# 5. Check logs
docker-compose logs -f ehr-webapp
```

---

*Last Updated: $(date)*
*Location: lab-environment/FRONTEND_STATUS.md*

