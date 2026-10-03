#!/bin/bash
set -e

# Usage: ./deploy_remote.sh user@host
if [ -z "$1" ]; then
    echo "Usage: $0 user@host"
    echo "Example: $0 ubuntu@192.168.1.100"
    exit 1
fi

REMOTE="$1"
REMOTE_DIR="~/project-medusa"

echo "🚀 Deploying Medusa to $REMOTE..."

# 1. Setup remote directories
echo "📂 Creating remote directories..."
ssh "$REMOTE" "mkdir -p $REMOTE_DIR ~/.medusa/logs ~/.medusa/reports"

# 2. Check for config.yaml on remote, upload default if missing
if ssh "$REMOTE" "[ ! -f ~/.medusa/config.yaml ]"; then
    echo "⚙️  Uploading default configuration..."
    # Check if we have a local config, otherwise use default template
    if [ -f ~/.medusa/config.yaml ]; then
        scp ~/.medusa/config.yaml "$REMOTE:~/.medusa/config.yaml"
    elif [ -f medusa-cli/config.yaml ]; then
         scp medusa-cli/config.yaml "$REMOTE:~/.medusa/config.yaml"
    else
        # Create a basic default config if none exists
        echo "llm:\n  provider: local\n  model: mistral" | ssh "$REMOTE" "cat > ~/.medusa/config.yaml"
    fi
fi

# 3. Sync project files
echo "wu  Syncing project files (this may take a minute)..."
rsync -avz --progress \
    --exclude '.git' \
    --exclude 'node_modules' \
    --exclude 'venv' \
    --exclude '__pycache__' \
    --exclude '.next' \
    --exclude 'dist' \
    --exclude '.DS_Store' \
    --exclude 'medusa-backend/node_modules' \
    --exclude 'lab-environment/services/*/node_modules' \
    . "$REMOTE:$REMOTE_DIR"

# 4. Start services remotely
echo "🔥 Starting Medusa services on remote server..."
ssh "$REMOTE" "cd $REMOTE_DIR && docker-compose -f docker-compose.deploy.yml up -d --build"

echo "✅ Deployment complete!"
echo "---------------------------------------------------"
echo "🌐 Web Dashboard: http://\${REMOTE#*@}:3000"
echo "🔌 API Server:    http://\${REMOTE#*@}:5001"
echo "---------------------------------------------------"

