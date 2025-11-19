#!/bin/bash

# Usage: ./ship_it.sh user@remote-server-ip

REMOTE=$1
if [ -z "$REMOTE" ]; then
    echo "Usage: ./ship_it.sh user@ip"
    exit 1
fi

echo "📦 Packaging MEDUSA for deployment..."

# 1. Create a temporary build folder
mkdir -p dist/medusa-deploy
cp -r ../medusa-cli dist/medusa-deploy/
cp -r ../medusa-webapp dist/medusa-deploy/
cp -r ../docker dist/medusa-deploy/
cp docker-compose.prod.yml dist/medusa-deploy/docker-compose.yml
cp .env.prod.template dist/medusa-deploy/.env

# 2. Transfer to remote server
echo "🚀 Shipping to $REMOTE..."
scp -r dist/medusa-deploy/* $REMOTE:~/medusa/

# 3. Instructions
echo "✅ Upload complete."
echo "------------------------------------------------"
echo "1. SSH into server: ssh $REMOTE"
echo "2. cd medusa"
echo "3. Edit config: nano .env"
echo "4. Run: docker-compose up -d --build"
echo "5. Initialize: docker compose exec medusa-core python scripts/index_mitre_attack.py"
echo "------------------------------------------------"

