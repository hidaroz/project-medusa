#!/bin/bash
# DigitalOcean Deployment Script for MEDUSA
# Run this on your Droplet after SSH'ing in

set -e  # Exit on error

echo "🚀 MEDUSA Deployment Script for DigitalOcean"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DROPLET_IP="143.198.65.195"
GITHUB_REPO="https://github.com/hidaroz/project-medusa.git"
INSTALL_DIR="/opt/project-medusa"
CONFIG_DIR="/var/medusa/config"
LOG_DIR="/var/medusa/logs"
ENV_FILE="/etc/medusa/medusa.env"

# Step 1: Update system
echo -e "${GREEN}[1/10]${NC} Updating system packages..."
apt update && apt upgrade -y

# Step 2: Install dependencies
echo -e "${GREEN}[2/10]${NC} Installing dependencies..."
apt install -y \
    git \
    curl \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    nginx \
    ufw \
    supervisor

# Install Node.js 18
echo -e "${GREEN}[2.5/10]${NC} Installing Node.js 18..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

# Verify installations
echo -e "${GREEN}✓${NC} Python: $(python3 --version)"
echo -e "${GREEN}✓${NC} Node: $(node --version)"
echo -e "${GREEN}✓${NC} npm: $(npm --version)"

# Step 3: Set up firewall
echo -e "${GREEN}[3/10]${NC} Configuring firewall (UFW)..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 80/tcp   # HTTP (Nginx)
ufw allow 443/tcp  # HTTPS (optional, for future SSL)
ufw allow 8080/tcp # EHR Frontend (lab environment)
ufw allow 3001/tcp # EHR API (lab environment)
ufw --force reload
echo -e "${GREEN}✓${NC} Firewall configured. Allowed ports: 22, 80, 443, 8080, 3001"

# Step 4: Create directories
echo -e "${GREEN}[4/10]${NC} Creating directories..."
mkdir -p $INSTALL_DIR
mkdir -p $CONFIG_DIR
mkdir -p $LOG_DIR
mkdir -p /etc/medusa
echo -e "${GREEN}✓${NC} Directories created"

# Step 5: Clone repository
echo -e "${GREEN}[5/10]${NC} Cloning repository..."
if [ -d "$INSTALL_DIR/project-medusa" ]; then
    echo -e "${YELLOW}⚠${NC} Directory exists, pulling latest changes..."
    cd $INSTALL_DIR/project-medusa
    git pull
else
    cd $INSTALL_DIR
    git clone $GITHUB_REPO
fi
echo -e "${GREEN}✓${NC} Repository cloned/updated"

# Step 6: Set up environment variables
echo -e "${GREEN}[6/10]${NC} Setting up environment variables..."
if [ ! -f "$ENV_FILE" ]; then
    cat <<EOF > $ENV_FILE
# Google Gemini API Key (REQUIRED - REPLACE WITH YOUR KEY!)
GOOGLE_API_KEY=your-gemini-api-key-here

# API Server Configuration
MEDUSA_API_HOST=127.0.0.1
MEDUSA_API_PORT=5001

# Next.js Dashboard Configuration
NEXT_PUBLIC_MEDUSA_API_URL=http://${DROPLET_IP}/api
NODE_ENV=production

# Config Directory
MEDUSA_CONFIG_DIR=${CONFIG_DIR}

# Optional: Ollama (if you install it later)
# OLLAMA_URL=http://127.0.0.1:11434
# OLLAMA_MODEL=mistral:7b-instruct
EOF
    chmod 600 $ENV_FILE
    echo -e "${YELLOW}⚠${NC} Created $ENV_FILE - PLEASE EDIT IT AND ADD YOUR GEMINI API KEY!"
    echo -e "${YELLOW}   Run: nano $ENV_FILE${NC}"
else
    echo -e "${GREEN}✓${NC} Environment file already exists"
fi

# Step 7: Set up Medusa API Server
echo -e "${GREEN}[7/10]${NC} Setting up Medusa API Server..."
cd $INSTALL_DIR/project-medusa/project-medusa/medusa-cli

# Create virtual environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Create config file
mkdir -p $CONFIG_DIR
cat <<EOF > $CONFIG_DIR/config.yaml
target:
  url: http://localhost:3001  # Lab environment (if running locally)

llm:
  provider: google  # Use Google Gemini
  cloud_model: gemini-1.5-flash-latest
  temperature: 0.7
  max_tokens: 2048
  timeout: 60
  max_retries: 3
EOF

echo -e "${GREEN}✓${NC} API server dependencies installed"

# Step 8: Set up Next.js Webapp
echo -e "${GREEN}[8/10]${NC} Setting up Next.js Webapp..."
cd $INSTALL_DIR/project-medusa/project-medusa/medusa-webapp

npm install
source $ENV_FILE
npm run build

echo -e "${GREEN}✓${NC} Webapp built"

# Step 8.5: Install Docker and set up Lab Environment
echo -e "${GREEN}[8.5/10]${NC} Installing Docker and setting up Lab Environment..."
apt install -y docker.io docker-compose
systemctl start docker
systemctl enable docker

# Start lab environment
echo -e "${GREEN}[8.6/10]${NC} Starting Lab Environment (EHR target)..."
cd $INSTALL_DIR/project-medusa/project-medusa/lab-environment
docker-compose up -d --build

echo -e "${GREEN}✓${NC} Lab environment starting (this may take a few minutes)"
echo -e "${YELLOW}  Note:${NC} Lab services will be available on:"
echo -e "  - EHR Frontend: http://${DROPLET_IP}:8080"
echo -e "  - EHR API: http://${DROPLET_IP}:3001"

# Step 9: Update Medusa config to point to lab environment
echo -e "${GREEN}[9/10]${NC} Updating Medusa config to target lab environment..."
cat <<EOF > $CONFIG_DIR/config.yaml
target:
  url: http://localhost:3001  # Lab environment EHR API

llm:
  provider: google  # Use Google Gemini
  cloud_model: gemini-1.5-flash-latest
  temperature: 0.7
  max_tokens: 2048
  timeout: 60
  max_retries: 3
EOF

# Step 10: Set up Nginx reverse proxy
echo -e "${GREEN}[9/10]${NC} Configuring Nginx..."
cat <<EOF > /etc/nginx/sites-available/medusa
server {
    listen 80;
    server_name ${DROPLET_IP};

    # API Server
    location /api {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # CORS headers (if needed)
        add_header Access-Control-Allow-Origin *;
    }

    # Next.js Dashboard
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/medusa /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test and restart nginx
nginx -t
systemctl restart nginx
systemctl enable nginx

echo -e "${GREEN}✓${NC} Nginx configured"

# Step 11: Set up systemd services
echo -e "${GREEN}[11/11]${NC} Setting up systemd services..."

# API Server Service
cat <<EOF > /etc/systemd/system/medusa-api.service
[Unit]
Description=Medusa API Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/project-medusa/project-medusa/medusa-cli
EnvironmentFile=${ENV_FILE}
Environment="PYTHONPATH=${INSTALL_DIR}/project-medusa/project-medusa/medusa-cli/src:${INSTALL_DIR}/project-medusa/project-medusa/medusa-cli"
ExecStart=${INSTALL_DIR}/project-medusa/project-medusa/medusa-cli/venv/bin/python3 api_server.py
Restart=always
RestartSec=10
StandardOutput=append:${LOG_DIR}/api.log
StandardError=append:${LOG_DIR}/api.log

[Install]
WantedBy=multi-user.target
EOF

# Webapp Service
cat <<EOF > /etc/systemd/system/medusa-web.service
[Unit]
Description=Medusa Web Dashboard
After=network.target medusa-api.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/project-medusa/project-medusa/medusa-webapp
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/npm run start -- --hostname 0.0.0.0 --port 3000
Restart=always
RestartSec=10
StandardOutput=append:${LOG_DIR}/web.log
StandardError=append:${LOG_DIR}/web.log

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable services
systemctl daemon-reload
systemctl enable medusa-api medusa-web

echo -e "${GREEN}✓${NC} Systemd services configured"

# Final steps
echo ""
echo -e "${GREEN}=============================================="
echo "✅ Deployment Complete!"
echo "=============================================="
echo ""
echo -e "${YELLOW}⚠ IMPORTANT:${NC} Before starting services, edit the environment file:"
echo "   nano $ENV_FILE"
echo "   Add your Google Gemini API key!"
echo ""
echo "To start services:"
echo "   systemctl start medusa-api"
echo "   systemctl start medusa-web"
echo ""
echo "To check status:"
echo "   systemctl status medusa-api"
echo "   systemctl status medusa-web"
echo ""
echo "To view logs:"
echo "   tail -f ${LOG_DIR}/api.log"
echo "   tail -f ${LOG_DIR}/web.log"
echo ""
echo "Access your deployment:"
echo "   Medusa Dashboard: http://${DROPLET_IP}/medusa"
echo "   Medusa API Health: http://${DROPLET_IP}/api/health"
echo "   Lab EHR Frontend: http://${DROPLET_IP}:8080"
echo "   Lab EHR API: http://${DROPLET_IP}:3001"
echo ""
echo -e "${GREEN}Firewall Status:${NC}"
ufw status
echo ""

