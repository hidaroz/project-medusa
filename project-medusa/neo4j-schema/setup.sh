#!/bin/bash

# ============================================================================
# MEDUSA Neo4j Setup Script
# ============================================================================
# This script sets up the Neo4j database for MEDUSA's World Model
# ============================================================================

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "============================================================================"
echo "MEDUSA World Model - Neo4j Setup"
echo "============================================================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}!${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if Docker is running
echo "[1] Checking Docker..."
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi
print_success "Docker is running"

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    print_error "docker-compose is not installed"
    exit 1
fi
print_success "docker-compose is available"

# Start Neo4j container
echo ""
echo "[2] Starting Neo4j container..."
cd "$PROJECT_ROOT"
docker-compose up -d medusa-neo4j

# Wait for Neo4j to be ready
echo ""
echo "[3] Waiting for Neo4j to be ready..."
MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if docker exec medusa_neo4j cypher-shell -u neo4j -p "${NEO4J_PASSWORD:-medusa_graph_pass}" "RETURN 1;" > /dev/null 2>&1; then
        print_success "Neo4j is ready"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo "  Waiting... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 2
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    print_error "Neo4j failed to start within expected time"
    echo "Check logs with: docker-compose logs medusa-neo4j"
    exit 1
fi

# Initialize schema
echo ""
echo "[4] Initializing schema..."
if docker exec -i medusa_neo4j cypher-shell -u neo4j -p "${NEO4J_PASSWORD:-medusa_graph_pass}" < "$SCRIPT_DIR/init-schema.cypher" > /dev/null 2>&1; then
    print_success "Schema initialized successfully"
else
    print_error "Failed to initialize schema"
    exit 1
fi

# Ask if user wants to load sample data
echo ""
read -p "Load sample data? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "[5] Loading sample data..."
    if docker exec -i medusa_neo4j cypher-shell -u neo4j -p "${NEO4J_PASSWORD:-medusa_graph_pass}" < "$SCRIPT_DIR/sample-data.cypher" > /dev/null 2>&1; then
        print_success "Sample data loaded successfully"
    else
        print_error "Failed to load sample data"
    fi
fi

# Install Python dependencies
echo ""
read -p "Install Python dependencies (neo4j, pydantic)? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "[6] Installing Python dependencies..."
    cd "$PROJECT_ROOT/medusa-cli"
    if pip install neo4j==5.14.1 pydantic==2.5.3; then
        print_success "Python dependencies installed"
    else
        print_warning "Failed to install Python dependencies. You may need to install them manually."
    fi
fi

# Summary
echo ""
echo "============================================================================"
echo "Setup Complete!"
echo "============================================================================"
echo ""
echo "Neo4j Connection Details:"
echo "  Browser:  http://localhost:7474"
echo "  Bolt URI: bolt://localhost:7687"
echo "  Username: neo4j"
echo "  Password: ${NEO4J_PASSWORD:-medusa_graph_pass}"
echo ""
echo "Next Steps:"
echo "  1. Open Neo4j Browser: http://localhost:7474"
echo "  2. Try example queries from README.md"
echo "  3. Run example script: python neo4j-schema/example_usage.py"
echo "  4. Integrate World Model into MEDUSA CLI"
echo ""
echo "Useful Commands:"
echo "  View logs:    docker-compose logs -f medusa-neo4j"
echo "  Stop Neo4j:   docker-compose stop medusa-neo4j"
echo "  Restart:      docker-compose restart medusa-neo4j"
echo "  Reset data:   docker-compose down -v medusa-neo4j"
echo ""
echo "============================================================================"
