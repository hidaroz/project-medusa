#!/bin/bash

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🚀 Setting up MEDUSA Local Test Environment...${NC}"

# 1. Start Neo4j (Required for API)
echo -e "\n${BLUE}📦 Checking Neo4j...${NC}"
if [ ! "$(docker ps -q -f name=medusa_neo4j_test)" ]; then
    if [ "$(docker ps -aq -f name=medusa_neo4j_test)" ]; then
        echo "Starting existing Neo4j container..."
        docker start medusa_neo4j_test
    else
        echo "Starting new Neo4j container..."
        docker run -d \
            --name medusa_neo4j_test \
            -p 7474:7474 -p 7687:7687 \
            -e NEO4J_AUTH=neo4j/password \
            neo4j:5.15-community
    fi
    echo "Waiting for Neo4j to be ready..."
    sleep 10
else
    echo -e "${GREEN}✓ Neo4j is running${NC}"
fi

# 2. Install Python Dependencies & CLI
echo -e "\n${BLUE}🐍 Installing MEDUSA CLI...${NC}"
cd medusa-cli
pip install -e .
pip install -r requirements.txt
cd ..

# 3. Install Webapp Dependencies
echo -e "\n${BLUE}⚛️  Installing Dashboard Dependencies...${NC}"
cd medusa-webapp
npm install
cd ..

# 4. Start API Server
echo -e "\n${BLUE}🔌 Starting API Server...${NC}"
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USERNAME=neo4j
export NEO4J_PASSWORD=password
export MEDUSA_API_PORT=5000

# Kill any existing instance on port 5000
lsof -ti:5000 | xargs kill -9 2>/dev/null

cd medusa-cli
python3 api_server.py > ../api.log 2>&1 &
API_PID=$!
echo -e "${GREEN}✓ API Server running (PID: $API_PID)${NC}"
cd ..

# 5. Start Dashboard
echo -e "\n${BLUE}🖥️  Starting Dashboard...${NC}"
echo -e "${GREEN}✓ Dashboard will be available at http://localhost:3000${NC}"
echo -e "${GREEN}✓ API Server is available at http://localhost:5000${NC}"
echo -e "${RED}Press Ctrl+C to stop everything${NC}"

cd medusa-webapp
npm run dev

# Cleanup on exit
kill $API_PID

