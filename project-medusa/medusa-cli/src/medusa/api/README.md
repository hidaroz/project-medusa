# MEDUSA Graph API Service

A secure Flask-based REST API for accessing the MEDUSA World Model Neo4j graph database.

## Overview

The Graph API Service provides an abstraction layer between MEDUSA components and the Neo4j database. It offers:

- **Natural Language Query Translation**: Convert plain English questions into Cypher queries
- **Secure Query Execution**: Parameterized queries with safety validation
- **Rate Limiting**: Prevent abuse with configurable request limits
- **API Key Authentication**: Secure access control
- **Comprehensive Logging**: Track all API requests and database operations

## Quick Start

### 1. Environment Setup

Copy and configure the environment file:

```bash
cp env.example .env
```

Edit `.env` and configure:

```bash
# Neo4j Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=medusa_graph_pass

# Graph API Configuration
GRAPH_API_PORT=5002
GRAPH_API_ENABLE_AUTH=true
GRAPH_API_KEY=your-secure-api-key-here
```

### 2. Install Dependencies

```bash
cd medusa-cli
pip install -r requirements.txt
```

### 3. Start the API Server

```bash
# From medusa-cli directory
python -m medusa.api.graph_api

# Or use Python directly
python src/medusa/api/graph_api.py
```

The API will be available at: `http://localhost:5002`

### 4. Verify Health

```bash
curl http://localhost:5002/health
```

Expected response:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-06T10:30:00",
  "database_connected": true,
  "version": "1.0.0",
  "uptime_seconds": 125.5
}
```

## API Endpoints

### 1. Health Check

**Endpoint**: `GET /health`

Check the service and database health status.

**Example Request**:
```bash
curl http://localhost:5002/health
```

**Example Response**:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-06T10:30:00",
  "database_connected": true,
  "version": "1.0.0",
  "uptime_seconds": 125.5
}
```

**Status Codes**:
- `200`: Service is healthy
- `503`: Service is degraded (database connection failed)

---

### 2. Natural Language Query

**Endpoint**: `POST /query`

Execute a natural language question and get results.

**Authentication**: Required (API Key)

**Request Headers**:
```
X-API-Key: your-api-key
Content-Type: application/json
```

**Request Body**:
```json
{
  "question": "vulnerable web servers",
  "limit": 100
}
```

**Parameters**:
- `question` (required): Natural language question (max 500 characters)
- `limit` (optional): Maximum number of results (default: 100, max: 1000)

**Example Request**:
```bash
curl -X POST http://localhost:5002/query \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "vulnerable web servers",
    "limit": 10
  }'
```

**Example Response**:
```json
{
  "success": true,
  "data": [
    {
      "url": "http://192.168.1.100",
      "status": 200,
      "vulnerabilities": [
        {
          "type": "SQL Injection",
          "severity": "high",
          "id": "vuln-001"
        }
      ]
    }
  ],
  "cypher_used": "MATCH (w:WebServer)-[:IS_VULNERABLE_TO]->(v:Vulnerability)...",
  "record_count": 1,
  "execution_time_ms": 45.2
}
```

**Status Codes**:
- `200`: Query executed successfully
- `400`: Invalid request (question not recognized, validation error)
- `401`: Authentication failed
- `429`: Rate limit exceeded
- `503`: Database unavailable

---

### 3. Direct Cypher Query (Read-Only)

**Endpoint**: `POST /direct-query`

Execute a direct Cypher query for read operations.

**Authentication**: Required (API Key)

**Request Body**:
```json
{
  "query": "MATCH (h:Host) RETURN h.ip as ip, h.hostname as hostname LIMIT 10",
  "parameters": {}
}
```

**Parameters**:
- `query` (required): Cypher query string (max 10,000 characters)
- `parameters` (optional): Query parameters as key-value pairs

**Example Request**:
```bash
curl -X POST http://localhost:5002/direct-query \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "MATCH (h:Host) WHERE h.os_name CONTAINS $os RETURN h",
    "parameters": {"os": "Windows"}
  }'
```

**Example Response**:
```json
{
  "success": true,
  "data": [
    {
      "ip": "192.168.1.10",
      "hostname": "DC01",
      "os_name": "Windows Server 2019"
    }
  ],
  "cypher_used": "MATCH (h:Host) WHERE h.os_name CONTAINS $os RETURN h",
  "record_count": 1,
  "execution_time_ms": 32.1
}
```

**Query Safety**:
- Destructive operations (`DELETE`, `DROP`, `REMOVE`) are blocked
- Maximum query length: 10,000 characters
- Multiple statements not allowed

**Status Codes**:
- `200`: Query executed successfully
- `400`: Invalid query syntax or unsafe operation
- `401`: Authentication failed
- `429`: Rate limit exceeded
- `503`: Database unavailable

---

### 4. Update Graph (Write Operations)

**Endpoint**: `POST /update`

Execute a write query to create or update graph data.

**Authentication**: Required (API Key)

**Request Body**:
```json
{
  "query": "MERGE (h:Host {ip: $ip}) SET h.hostname = $hostname RETURN h",
  "parameters": {
    "ip": "192.168.1.50",
    "hostname": "NEW-HOST"
  }
}
```

**Parameters**:
- `query` (required): Cypher write query (CREATE, MERGE, SET)
- `parameters` (optional): Query parameters for safe parameterized queries

**Example Request**:
```bash
curl -X POST http://localhost:5002/update \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "MERGE (h:Host {ip: $ip}) SET h.hostname = $hostname RETURN h",
    "parameters": {
      "ip": "192.168.1.50",
      "hostname": "NEW-HOST"
    }
  }'
```

**Example Response**:
```json
{
  "success": true,
  "records_affected": 1,
  "execution_time_ms": 67.3,
  "error": null
}
```

**Allowed Write Operations**:
- `CREATE`: Create new nodes/relationships
- `MERGE`: Create or match existing nodes/relationships
- `SET`: Update properties

**Blocked Operations**:
- `DELETE`, `DETACH DELETE`
- `REMOVE`
- `DROP CONSTRAINT`, `CREATE CONSTRAINT`
- `DROP INDEX`, `CREATE INDEX`

**Status Codes**:
- `200`: Update executed successfully
- `400`: Invalid query syntax or unsafe operation
- `401`: Authentication failed
- `429`: Rate limit exceeded
- `503`: Database unavailable

---

### 5. List Available Patterns

**Endpoint**: `GET /patterns`

Get a list of all available natural language query patterns.

**Authentication**: Required (API Key)

**Example Request**:
```bash
curl http://localhost:5002/patterns \
  -H "X-API-Key: your-api-key"
```

**Example Response**:
```json
{
  "success": true,
  "patterns": {
    "vulnerable web servers": "Find web servers with known vulnerabilities",
    "vulnerable hosts": "Find hosts with known vulnerabilities",
    "users with credentials": "Find users with associated credentials",
    "roastable users": "Find users vulnerable to AS-REP or Kerberoasting attacks",
    "all hosts": "List all discovered hosts",
    "open ports": "List all open ports across hosts",
    "web servers": "List all discovered web servers",
    "domains": "List all domains with subdomain counts",
    "attack paths": "Find potential attack paths from domains to vulnerable assets",
    "statistics": "Get overall statistics of the graph database"
  },
  "count": 10
}
```

## Natural Language Query Patterns

The API supports the following natural language patterns:

| Question Pattern | Description | Example Data Returned |
|-----------------|-------------|----------------------|
| **vulnerable web servers** | Web servers with vulnerabilities | URL, status, vulnerabilities list |
| **vulnerable hosts** | Hosts with vulnerabilities | IP, hostname, OS, vulnerabilities |
| **high severity vulnerabilities** | Critical and high severity vulns | ID, type, severity, target |
| **users with credentials** | Users and their credentials | Username, domain, credentials |
| **roastable users** | AS-REP/Kerberoastable users | Username, domain, roastable flags |
| **all users** | All users in the database | Username, domain, credential count |
| **all hosts** | All discovered hosts | IP, hostname, OS, open ports |
| **open ports** | Open ports across all hosts | Host IP, port numbers, services |
| **web servers** | Discovered web servers | Host IP, URL, status, technologies |
| **domains** | All domains | Domain name, status, subdomain count |
| **subdomains** | All subdomains | Domain, subdomain, resolved IP |
| **attack paths** | Potential attack vectors | Domain, host, vulnerabilities, users |
| **attack surface** | Comprehensive metrics | Hosts, ports, web servers, vulns |
| **statistics** | Overall graph statistics | Total counts for all node types |

### Fuzzy Matching

The query translator also supports fuzzy keyword matching:

- "vuln" → vulnerable hosts
- "cred" or "password" → users with credentials
- "asrep" or "kerberos" → roastable users
- "port" or "service" → open ports
- "webapp" or "http" → web servers
- "domain" → domains
- "sub" → subdomains
- "path" → attack paths
- "surface" → attack surface
- "stat" or "count" → statistics

## Authentication

All endpoints except `/health` require API key authentication.

**Header Format**:
```
X-API-Key: your-api-key-here
```

**Configuration**:
```bash
# In .env file
GRAPH_API_ENABLE_AUTH=true
GRAPH_API_KEY=your-secure-api-key-here
```

**Example**:
```bash
curl -X POST http://localhost:5002/query \
  -H "X-API-Key: medusa-dev-key-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{"question": "all hosts"}'
```

**Error Response** (401):
```json
{
  "success": false,
  "error": "Invalid or missing API key"
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse.

**Default Limits**:
- 100 requests per 60 seconds (per IP address)

**Configuration**:
```bash
# In .env file
GRAPH_API_RATE_LIMIT=100
GRAPH_API_RATE_WINDOW=60
```

**Rate Limit Headers**:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Window: 60
```

**Error Response** (429):
```json
{
  "success": false,
  "error": "Rate limit exceeded: 100 requests per 60 seconds"
}
```

## Query Safety

The API validates all queries for safety before execution.

### Safety Rules

1. **Blocked Operations**:
   - `DELETE`, `DETACH DELETE`
   - `REMOVE`
   - `DROP CONSTRAINT`, `CREATE CONSTRAINT`
   - `DROP INDEX`, `CREATE INDEX`

2. **Query Length Limit**: Maximum 10,000 characters

3. **Single Statement Only**: Multiple statements (`;`) not allowed

4. **Write Operation Validation**: `/update` endpoint must contain CREATE, MERGE, or SET

### Example Blocked Queries

```cypher
-- BLOCKED: Delete operation
DELETE n

-- BLOCKED: Drop constraint
DROP CONSTRAINT user_unique

-- BLOCKED: Multiple statements
MATCH (n) RETURN n; DELETE n
```

## Error Handling

The API provides detailed error messages for troubleshooting.

### Common Error Responses

**Validation Error (400)**:
```json
{
  "success": false,
  "error": "Invalid request data",
  "details": [
    {
      "loc": ["body", "question"],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```

**Authentication Error (401)**:
```json
{
  "success": false,
  "error": "Invalid or missing API key"
}
```

**Rate Limit Error (429)**:
```json
{
  "success": false,
  "error": "Rate limit exceeded: 100 requests per 60 seconds"
}
```

**Query Pattern Not Found (400)**:
```json
{
  "success": false,
  "error": "Could not translate question to query",
  "available_patterns": {
    "vulnerable web servers": "Find web servers with known vulnerabilities",
    "all hosts": "List all discovered hosts"
  }
}
```

**Cypher Syntax Error (400)**:
```json
{
  "success": false,
  "error": "Invalid Cypher syntax: Unknown function 'INVALID'"
}
```

**Database Unavailable (503)**:
```json
{
  "success": false,
  "error": "Database service unavailable"
}
```

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection URI |
| `NEO4J_USERNAME` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `medusa_graph_pass` | Neo4j password |
| `NEO4J_DATABASE` | `neo4j` | Neo4j database name |
| `GRAPH_API_PORT` | `5002` | API server port |
| `GRAPH_API_HOST` | `0.0.0.0` | API server host |
| `GRAPH_API_ENABLE_AUTH` | `true` | Enable API key authentication |
| `GRAPH_API_KEY` | `medusa-dev-key-change-in-production` | API key for authentication |
| `GRAPH_API_RATE_LIMIT` | `100` | Max requests per window |
| `GRAPH_API_RATE_WINDOW` | `60` | Rate limit window (seconds) |
| `GRAPH_API_MAX_QUERY_LENGTH` | `10000` | Maximum query length |
| `GRAPH_API_QUERY_TIMEOUT` | `30` | Query timeout (seconds) |
| `FLASK_ENV` | `production` | Flask environment |
| `APP_DEBUG` | `false` | Enable debug mode |

## Usage Examples

### Python Client

```python
import requests

class GraphAPIClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json"
        }

    def query(self, question: str, limit: int = 100):
        """Execute a natural language query."""
        response = requests.post(
            f"{self.base_url}/query",
            headers=self.headers,
            json={"question": question, "limit": limit}
        )
        return response.json()

    def update(self, cypher: str, parameters: dict = None):
        """Execute a write query."""
        response = requests.post(
            f"{self.base_url}/update",
            headers=self.headers,
            json={"query": cypher, "parameters": parameters or {}}
        )
        return response.json()

# Usage
client = GraphAPIClient(
    base_url="http://localhost:5002",
    api_key="medusa-dev-key-change-in-production"
)

# Get all vulnerable hosts
result = client.query("vulnerable hosts", limit=10)
print(f"Found {result['record_count']} vulnerable hosts")

for host in result['data']:
    print(f"Host: {host['ip']} ({host['hostname']})")
    for vuln in host['vulnerabilities']:
        print(f"  - {vuln['type']} ({vuln['severity']})")
```

### JavaScript/Node.js Client

```javascript
class GraphAPIClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
  }

  async query(question, limit = 100) {
    const response = await fetch(`${this.baseUrl}/query`, {
      method: 'POST',
      headers: {
        'X-API-Key': this.apiKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ question, limit })
    });
    return await response.json();
  }

  async update(cypher, parameters = {}) {
    const response = await fetch(`${this.baseUrl}/update`, {
      method: 'POST',
      headers: {
        'X-API-Key': this.apiKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ query: cypher, parameters })
    });
    return await response.json();
  }
}

// Usage
const client = new GraphAPIClient(
  'http://localhost:5002',
  'medusa-dev-key-change-in-production'
);

// Get roastable users
const result = await client.query('roastable users');
console.log(`Found ${result.record_count} roastable users`);

result.data.forEach(user => {
  console.log(`${user.username}@${user.domain}`);
  if (user.asrep_roastable) console.log('  - AS-REP Roastable');
  if (user.kerberoastable) console.log('  - Kerberoastable');
});
```

### cURL Examples

```bash
# Get health status
curl http://localhost:5002/health

# Get all available patterns
curl -H "X-API-Key: medusa-dev-key-change-in-production" \
  http://localhost:5002/patterns

# Query vulnerable web servers
curl -X POST http://localhost:5002/query \
  -H "X-API-Key: medusa-dev-key-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{"question": "vulnerable web servers", "limit": 5}'

# Get attack surface
curl -X POST http://localhost:5002/query \
  -H "X-API-Key: medusa-dev-key-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{"question": "attack surface"}'

# Direct Cypher query
curl -X POST http://localhost:5002/direct-query \
  -H "X-API-Key: medusa-dev-key-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "MATCH (h:Host)-[:HAS_PORT]->(p:Port) WHERE p.number = $port RETURN h, p",
    "parameters": {"port": 445}
  }'

# Update graph (create host)
curl -X POST http://localhost:5002/update \
  -H "X-API-Key: medusa-dev-key-change-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "MERGE (h:Host {ip: $ip}) SET h.hostname = $hostname, h.last_seen = datetime() RETURN h",
    "parameters": {
      "ip": "192.168.1.100",
      "hostname": "WEB-SERVER-01"
    }
  }'
```

## Docker Deployment

### Using Docker Compose

The Graph API can be deployed alongside Neo4j using Docker Compose.

**Add to `docker-compose.yml`**:

```yaml
services:
  medusa-neo4j:
    image: neo4j:5.14
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      NEO4J_AUTH: neo4j/medusa_graph_pass
    volumes:
      - medusa-neo4j-data:/data
      - medusa-neo4j-logs:/logs

  graph-api:
    build:
      context: ./medusa-cli
      dockerfile: Dockerfile.graph-api
    ports:
      - "5002:5002"
    environment:
      NEO4J_URI: bolt://medusa-neo4j:7687
      NEO4J_USERNAME: neo4j
      NEO4J_PASSWORD: medusa_graph_pass
      GRAPH_API_PORT: 5002
      GRAPH_API_ENABLE_AUTH: "true"
      GRAPH_API_KEY: ${GRAPH_API_KEY}
    depends_on:
      - medusa-neo4j

volumes:
  medusa-neo4j-data:
  medusa-neo4j-logs:
```

**Create `Dockerfile.graph-api`**:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/

EXPOSE 5002

CMD ["python", "-m", "medusa.api.graph_api"]
```

**Start services**:

```bash
docker-compose up -d
```

## Security Best Practices

1. **Change Default API Key**: Always use a strong, unique API key in production
2. **Use HTTPS**: Deploy behind a reverse proxy with TLS/SSL
3. **Restrict Network Access**: Use firewall rules to limit access
4. **Enable Authentication**: Never disable auth in production
5. **Monitor Rate Limits**: Adjust based on your usage patterns
6. **Review Logs**: Monitor API logs for suspicious activity
7. **Rotate API Keys**: Regularly rotate API keys
8. **Use Strong Neo4j Password**: Change default Neo4j credentials

## Troubleshooting

### Connection Issues

**Problem**: `Database service unavailable`

**Solutions**:
1. Check Neo4j is running: `docker ps | grep neo4j`
2. Verify connection URI: `NEO4J_URI=bolt://localhost:7687`
3. Test Neo4j connectivity: `cypher-shell -a bolt://localhost:7687`
4. Check firewall rules

### Authentication Failures

**Problem**: `Invalid or missing API key`

**Solutions**:
1. Verify API key in `.env` file
2. Check header format: `X-API-Key: your-key`
3. Ensure API key matches server configuration

### Query Translation Issues

**Problem**: `Could not translate question to query`

**Solutions**:
1. Check available patterns: `GET /patterns`
2. Use exact pattern match or fuzzy keywords
3. Try direct query endpoint with custom Cypher

### Rate Limit Errors

**Problem**: `Rate limit exceeded`

**Solutions**:
1. Increase rate limit: `GRAPH_API_RATE_LIMIT=200`
2. Increase window: `GRAPH_API_RATE_WINDOW=120`
3. Implement request queuing in client

## Development

### Running Tests

```bash
cd medusa-cli
pytest tests/api/ -v
```

### Adding New Query Patterns

Edit [graph_api.py:159](src/medusa/api/graph_api.py#L159) and add to `QueryTranslator.PATTERNS`:

```python
"new pattern": {
    "cypher": """
        MATCH (n:NodeType)
        WHERE n.property = $param
        RETURN n
        LIMIT $limit
    """,
    "description": "Description of what this pattern does"
}
```

### Extending the API

Create new endpoints in [graph_api.py](src/medusa/api/graph_api.py):

```python
@app.route('/custom-endpoint', methods=['POST'])
@require_auth
@check_rate_limit
def custom_endpoint():
    # Your implementation
    pass
```

## Support

For issues, questions, or contributions:
- GitHub Issues: [project-medusa/issues](https://github.com/your-org/project-medusa/issues)
- Documentation: [MEDUSA Docs](https://docs.medusa-project.io)

## License

Copyright (c) 2025 MEDUSA Project. All rights reserved.
