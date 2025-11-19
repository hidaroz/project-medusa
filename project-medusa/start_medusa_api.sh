#!/bin/bash
set -e

# Check if docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: docker is not installed"
    exit 1
fi

# Check if docker-compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Error: docker-compose is not installed"
    exit 1
fi

echo "Starting Medusa API Server..."
cd medusa-cli
docker-compose -f docker-compose.api.yml up -d --build

echo "Medusa API Server is running on http://localhost:5001"
echo "To view logs: docker-compose -f medusa-cli/docker-compose.api.yml logs -f"

