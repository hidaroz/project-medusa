#!/bin/bash
# Smart setup script for MEDUSA lab environment

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   MEDUSA Lab Smart Setup Wizard       ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
echo ""

# Navigate to lab-environment
cd "$(dirname "$0")/../lab-environment"

# Check if .env exists
if [ -f .env ]; then
    echo -e "${YELLOW}⚠${NC} Found existing .env file"
    read -p "Overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}✓${NC} Keeping existing configuration"
        exit 0
    fi
fi

# Generate secure passwords
generate_password() {
    openssl rand -base64 12 | tr -d "=+/" | cut -c1-16
}

echo -e "${CYAN}→ Generating secure passwords...${NC}"
MYSQL_ROOT_PASSWORD=$(generate_password)
MYSQL_PASSWORD=$(generate_password)
POSTGRES_PASSWORD=$(generate_password)
REDIS_PASSWORD=$(generate_password)

echo -e "${GREEN}✓${NC} Passwords generated"

# Get user preferences
echo ""
echo -e "${CYAN}Configure ports (press Enter for defaults):${NC}"
read -p "EHR Web App port [8080]: " WEB_PORT
WEB_PORT=${WEB_PORT:-8080}

read -p "EHR API port [3000]: " API_PORT
API_PORT=${API_PORT:-3000}

read -p "Log Viewer port [8081]: " LOG_PORT
LOG_PORT=${LOG_PORT:-8081}

# Create .env file
cat > .env << EOF
# MEDUSA Lab Environment Configuration
# Generated: $(date)
# ⚠️  DO NOT commit this file to version control

# =============================================================================
# Database Credentials
# =============================================================================
MYSQL_ROOT_PASSWORD=${MYSQL_ROOT_PASSWORD}
MYSQL_DATABASE=ehr_db
MYSQL_USER=ehr_user
MYSQL_PASSWORD=${MYSQL_PASSWORD}

POSTGRES_USER=medusa
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=medusa_db

REDIS_PASSWORD=${REDIS_PASSWORD}

# =============================================================================
# Application Ports
# =============================================================================
WEB_APP_PORT=${WEB_PORT}
API_PORT=${API_PORT}
LOG_VIEWER_PORT=${LOG_PORT}
FTP_PORT=21
SSH_PORT=2222
LDAP_PORT=389

# =============================================================================
# Network Configuration
# =============================================================================
DMZ_SUBNET=172.20.0.0/24
INTERNAL_SUBNET=172.21.0.0/24

# =============================================================================
# Application Settings
# =============================================================================
APP_ENV=development
APP_DEBUG=true
LOG_LEVEL=INFO

# =============================================================================
# Vulnerable Service Credentials (INTENTIONAL)
# =============================================================================
# These are INTENTIONALLY weak for educational purposes
FTP_USER=fileadmin
FTP_PASS=Files2024!
SSH_USER=labuser
SSH_PASS=password123
LDAP_ADMIN_PASS=admin

# =============================================================================
# API Keys (Optional)
# =============================================================================
# GEMINI_API_KEY=your_key_here
# Uncomment and add your Gemini API key if using AI features

EOF

echo -e "${GREEN}✓${NC} Created .env file"

# Create credentials file for user reference
cat > CREDENTIALS.md << EOF
# Lab Environment Credentials

**Generated:** $(date)

## Database Access

### MySQL
- **Host:** localhost:3306
- **Root Password:** \`${MYSQL_ROOT_PASSWORD}\`
- **Database:** ehr_db
- **User:** ehr_user
- **Password:** \`${MYSQL_PASSWORD}\`

### PostgreSQL
- **Host:** localhost:5432
- **User:** medusa
- **Password:** \`${POSTGRES_PASSWORD}\`
- **Database:** medusa_db

### Redis
- **Host:** localhost:6379
- **Password:** \`${REDIS_PASSWORD}\`

## Service Access

### Web Application
- **URL:** http://localhost:${WEB_PORT}
- **Default Login:** admin / admin

### API Server
- **URL:** http://localhost:${API_PORT}
- **Health Check:** http://localhost:${API_PORT}/health

### Log Viewer
- **URL:** http://localhost:${LOG_PORT}

### FTP Server
- **Host:** localhost:${FTP_PORT:-21}
- **User:** fileadmin
- **Password:** Files2024!
- **Anonymous:** Yes

### SSH Server
- **Host:** localhost:${SSH_PORT:-2222}
- **User:** labuser
- **Password:** password123

### LDAP Server
- **Host:** localhost:${LDAP_PORT:-389}
- **Admin DN:** cn=admin,dc=medcare,dc=local
- **Password:** admin

⚠️  **SECURITY NOTICE:** These credentials are INTENTIONALLY WEAK for educational purposes.
**NEVER** use similar credentials in production environments.

EOF

echo -e "${GREEN}✓${NC} Created CREDENTIALS.md reference file"

# Offer to start services
echo ""
echo -e "${CYAN}Configuration complete!${NC}"
echo ""
read -p "Start lab services now? (Y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo -e "${CYAN}→ Starting services...${NC}"
    docker-compose up -d

    echo ""
    echo -e "${GREEN}✓${NC} Services starting..."
    echo ""
    echo "Check status with: docker-compose ps"
    echo "View logs with: docker-compose logs -f"
    echo "Stop services with: docker-compose down"
    echo ""
    echo -e "${CYAN}Access Points:${NC}"
    echo "  🌐 Web App:    http://localhost:${WEB_PORT}"
    echo "  📊 API:        http://localhost:${API_PORT}"
    echo "  🔍 Logs:       http://localhost:${LOG_PORT}"
    echo ""
    echo -e "${YELLOW}📋 Credentials saved to: CREDENTIALS.md${NC}"
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Setup Complete! Happy Hacking! 🎉   ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
