#!/bin/bash
# Quick script to set up systemd services for MEDUSA
# Run this on your DigitalOcean server

INSTALL_DIR="/opt/project-medusa/project-medusa/project-medusa"
LOG_DIR="/var/medusa/logs"
ENV_FILE="/etc/medusa/medusa.env"
DROPLET_IP="143.198.65.195"

# Create log directory
mkdir -p $LOG_DIR

# Create API service
cat <<EOF > /etc/systemd/system/medusa-api.service
[Unit]
Description=Medusa API Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/medusa-cli
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_DIR}/medusa-cli/venv/bin/python3 ${INSTALL_DIR}/medusa-cli/api_server.py
Restart=always
RestartSec=10
StandardOutput=append:${LOG_DIR}/api.log
StandardError=append:${LOG_DIR}/api.log

[Install]
WantedBy=multi-user.target
EOF

# Create Webapp service
cat <<EOF > /etc/systemd/system/medusa-web.service
[Unit]
Description=Medusa Webapp (Next.js)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/medusa-webapp
EnvironmentFile=${ENV_FILE}
Environment="NEXT_PUBLIC_MEDUSA_API_URL=http://${DROPLET_IP}/api"
Environment="NODE_ENV=production"
ExecStart=/usr/bin/npm run start
Restart=always
RestartSec=10
StandardOutput=append:${LOG_DIR}/web.log
StandardError=append:${LOG_DIR}/web.log

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

echo "✅ Services created!"
echo ""
echo "Now you can start them with:"
echo "  sudo systemctl start medusa-api medusa-web"
echo "  sudo systemctl enable medusa-api medusa-web"

