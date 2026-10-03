#!/bin/bash
# Start Medusa API Server
# Usage: ./start_api.sh

cd "$(dirname "$0")/../medusa-cli"
echo "Starting Medusa API Server..."
echo "Server will be available at: http://localhost:${MEDUSA_API_PORT:-5001}"
python3 api_server.py




