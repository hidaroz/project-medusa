# Neo4j World Model - Quick Start Guide

Get MEDUSA's Neo4j World Model up and running in 5 minutes.

## Prerequisites

- Docker and Docker Compose installed
- Python 3.8+ (for Python client)
- 2GB free RAM for Neo4j

## Option 1: Automated Setup (Recommended)

Run the setup script:

```bash
cd neo4j-schema
./setup.sh
```

This will:
1. Start Neo4j container
2. Initialize schema
3. Optionally load sample data
4. Optionally install Python dependencies

## Option 2: Manual Setup

### Step 1: Start Neo4j

```bash
# From project root
docker-compose up -d medusa-neo4j

# Wait for Neo4j to be ready (check logs)
docker-compose logs -f medusa-neo4j
```

### Step 2: Initialize Schema

```bash
# Initialize constraints and indexes
docker exec -i medusa_neo4j cypher-shell -u neo4j -p medusa_graph_pass < neo4j-schema/init-schema.cypher
```

### Step 3: Load Sample Data (Optional)

```bash
# Load sample data for testing
docker exec -i medusa_neo4j cypher-shell -u neo4j -p medusa_graph_pass < neo4j-schema/sample-data.cypher
```

### Step 4: Install Python Dependencies

```bash
cd medusa-cli
pip install neo4j==5.14.1 pydantic==2.5.3
```

## Verify Installation

### 1. Access Neo4j Browser

Open [http://localhost:7474](http://localhost:7474) in your browser.

**Login:**
- Username: `neo4j`
- Password: `medusa_graph_pass`

### 2. Run Test Query

In the Neo4j Browser, run:

```cypher
MATCH (n) RETURN labels(n), count(n) ORDER BY count(n) DESC;
```

You should see constraints and indexes listed, and node counts if you loaded sample data.

### 3. Test Python Client

```bash
cd neo4j-schema
python example_usage.py
```

## Quick Test Queries

Try these in Neo4j Browser:

**View all hosts:**
```cypher
MATCH (h:Host) RETURN h LIMIT 10;
```

**View schema:**
```cypher
CALL db.schema.visualization();
```

**Show constraints:**
```cypher
SHOW CONSTRAINTS;
```

**Show indexes:**
```cypher
SHOW INDEXES;
```

**Find attack surface:**
```cypher
MATCH path = (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(h:Host)
RETURN path LIMIT 5;
```

## Using the Python Client

### Basic Usage

```python
from medusa.world_model import WorldModelClient, Host

# Connect to Neo4j
client = WorldModelClient()

# Create a host
host = Host(
    ip="192.168.1.100",
    hostname="web-server",
    os_name="Linux"
)
client.create_host(host)

# Query hosts
hosts = client.get_all_hosts()
for h in hosts:
    print(f"{h['ip']} - {h['hostname']}")

# Close connection
client.close()
```

### Using Context Manager

```python
from medusa.world_model import WorldModelClient

with WorldModelClient() as client:
    stats = client.get_graph_statistics()
    print(stats)
```

## Environment Variables

Override default settings with environment variables:

```bash
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USERNAME="neo4j"
export NEO4J_PASSWORD="your_password"
export NEO4J_DATABASE="neo4j"
```

## Troubleshooting

### Cannot connect to Neo4j

```bash
# Check if container is running
docker-compose ps medusa-neo4j

# View logs
docker-compose logs medusa-neo4j

# Restart container
docker-compose restart medusa-neo4j
```

### Authentication failed

The default password is `medusa_graph_pass`. To change it:

```bash
# Set environment variable
export NEO4J_PASSWORD="your_new_password"

# Restart Neo4j
docker-compose down medusa-neo4j
docker-compose up -d medusa-neo4j
```

### Reset everything

```bash
# WARNING: This deletes all data!
docker-compose down medusa-neo4j
docker volume rm medusa-neo4j-data medusa-neo4j-logs medusa-neo4j-import
docker-compose up -d medusa-neo4j

# Re-initialize
./setup.sh
```

### Port conflicts

If ports 7474 or 7687 are already in use, edit `docker-compose.yml`:

```yaml
ports:
  - "17474:7474"  # Changed from 7474
  - "17687:7687"  # Changed from 7687
```

Then update `NEO4J_URI`:
```bash
export NEO4J_URI="bolt://localhost:17687"
```

## Next Steps

1. **Read the full documentation**: [README.md](README.md)
2. **Explore the schema**: Review [init-schema.cypher](init-schema.cypher)
3. **Study examples**: Check [example_usage.py](example_usage.py)
4. **Integration**: Integrate World Model into MEDUSA CLI tools

## Useful Commands

```bash
# Start Neo4j
docker-compose up -d medusa-neo4j

# Stop Neo4j
docker-compose stop medusa-neo4j

# View logs
docker-compose logs -f medusa-neo4j

# Execute Cypher command
docker exec medusa_neo4j cypher-shell -u neo4j -p medusa_graph_pass "MATCH (n) RETURN count(n);"

# Backup data
docker run --rm -v medusa-neo4j-data:/data -v $(pwd)/backups:/backup ubuntu tar czf /backup/neo4j-backup.tar.gz /data

# Shell into container
docker exec -it medusa_neo4j bash
```

## Configuration Files

- **[docker-compose.yml](../docker-compose.yml)**: Neo4j service definition
- **[init-schema.cypher](init-schema.cypher)**: Schema initialization
- **[sample-data.cypher](sample-data.cypher)**: Sample data
- **[neo4j-config.yaml](neo4j-config.yaml)**: Application configuration
- **[neo4j-config.py](neo4j-config.py)**: Python configuration

## Support

For detailed documentation, see [README.md](README.md).

For issues:
1. Check logs: `docker-compose logs medusa-neo4j`
2. Verify schema: `SHOW CONSTRAINTS; SHOW INDEXES;`
3. Review [Troubleshooting](#troubleshooting) section

---

**Ready to go?** Open Neo4j Browser at [http://localhost:7474](http://localhost:7474) and start exploring!
