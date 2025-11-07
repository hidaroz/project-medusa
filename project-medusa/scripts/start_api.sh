#!/bin/bash
# Start Medusa API Server
# Usage: ./start_api.sh

cd "$(dirname "$0")"
echo "Starting Medusa API Server..."
echo "Server will be available at: http://localhost:5000"
python3 api_server.py




