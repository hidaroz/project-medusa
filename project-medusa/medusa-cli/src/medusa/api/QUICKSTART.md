# Graph API Quick Start Guide

Get started with the MEDUSA Graph API in 5 minutes.

## Prerequisites

- Python 3.11+
- Neo4j running (Docker or local)
- MEDUSA CLI dependencies installed

## Setup (60 seconds)

### 1. Configure Environment

```bash
cd project-medusa
cp env.example .env
```

Edit `.env` and set:
```bash
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=medusa_graph_pass
GRAPH_API_KEY=my-secure-api-key
```

### 2. Install Dependencies

```bash
cd medusa-cli
pip install -r requirements.txt
```

### 3. Start the API

```bash
python run_graph_api.py
```

Expected output:
```
============================================================
MEDUSA Graph API Service Starting
============================================================
Neo4j URI: bolt://localhost:7687
API Port: 5002
Authentication: Enabled
Rate Limit: 100 requests per 60s
============================================================
 * Running on http://0.0.0.0:5002
```

## Test It (30 seconds)

### Health Check

```bash
curl http://localhost:5002/health
```

### List Available Queries

```bash
curl -H "X-API-Key: my-secure-api-key" \
  http://localhost:5002/patterns
```

### Run Your First Query

```bash
curl -X POST http://localhost:5002/query \
  -H "X-API-Key: my-secure-api-key" \
  -H "Content-Type: application/json" \
  -d '{"question": "all hosts", "limit": 10}'
```

## Common Queries

### Find Vulnerable Hosts

```bash
curl -X POST http://localhost:5002/query \
  -H "X-API-Key: my-secure-api-key" \
  -H "Content-Type: application/json" \
  -d '{"question": "vulnerable hosts"}'
```

### Find Users with Credentials

```bash
curl -X POST http://localhost:5002/query \
  -H "X-API-Key: my-secure-api-key" \
  -H "Content-Type: application/json" \
  -d '{"question": "users with credentials"}'
```

### Get Attack Surface

```bash
curl -X POST http://localhost:5002/query \
  -H "X-API-Key: my-secure-api-key" \
  -H "Content-Type: application/json" \
  -d '{"question": "attack surface"}'
```

### Get Statistics

```bash
curl -X POST http://localhost:5002/query \
  -H "X-API-Key: my-secure-api-key" \
  -H "Content-Type: application/json" \
  -d '{"question": "statistics"}'
```

## Python Client Example

```python
import requests

class GraphAPI:
    def __init__(self, url="http://localhost:5002", api_key="my-secure-api-key"):
        self.url = url
        self.headers = {"X-API-Key": api_key, "Content-Type": "application/json"}

    def query(self, question, limit=100):
        r = requests.post(f"{self.url}/query",
                         headers=self.headers,
                         json={"question": question, "limit": limit})
        return r.json()

# Usage
api = GraphAPI()
result = api.query("vulnerable hosts")

for host in result["data"]:
    print(f"{host['ip']}: {len(host['vulnerabilities'])} vulnerabilities")
```

## Troubleshooting

### "Database service unavailable"

1. Check Neo4j is running: `docker ps | grep neo4j`
2. Test connection: `cypher-shell -a bolt://localhost:7687`
3. Verify credentials in `.env`

### "Invalid or missing API key"

1. Check API key in `.env`: `GRAPH_API_KEY=...`
2. Use same key in header: `X-API-Key: ...`
3. Ensure no extra whitespace

### "Could not translate question"

1. Get available patterns: `GET /patterns`
2. Use exact pattern or fuzzy keyword
3. Or use `/direct-query` with custom Cypher

## Next Steps

- Read the full [API Documentation](README.md)
- Learn about [available query patterns](README.md#natural-language-query-patterns)
- Explore [Python/JavaScript client examples](README.md#usage-examples)
- Review [security best practices](README.md#security-best-practices)

## Quick Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `GRAPH_API_PORT` | `5002` | API port |
| `GRAPH_API_KEY` | `medusa-dev-key-change-in-production` | API key |
| `GRAPH_API_ENABLE_AUTH` | `true` | Enable auth |
| `GRAPH_API_RATE_LIMIT` | `100` | Requests per window |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j URI |
| `NEO4J_USERNAME` | `neo4j` | Neo4j user |
| `NEO4J_PASSWORD` | `medusa_graph_pass` | Neo4j password |

## Support

- Full docs: [README.md](README.md)
- GitHub Issues: [project-medusa/issues](https://github.com/your-org/project-medusa/issues)
- Run tests: `pytest tests/api/ -v`
