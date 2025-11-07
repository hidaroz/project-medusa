# MEDUSA World Model - Neo4j Graph Database

Complete Neo4j setup and schema documentation for MEDUSA's autonomous penetration testing knowledge graph.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Database Setup](#database-setup)
  - [Option 1: Docker Setup (Recommended)](#option-1-docker-setup-recommended)
  - [Option 2: Neo4j AuraDB (Cloud)](#option-2-neo4j-auradb-cloud)
- [Schema Design](#schema-design)
- [Node Types](#node-types)
- [Relationship Types](#relationship-types)
- [Indexes and Constraints](#indexes-and-constraints)
- [Usage Examples](#usage-examples)
- [Connection Configuration](#connection-configuration)
- [Access Patterns](#access-patterns)
- [Maintenance](#maintenance)
- [Troubleshooting](#troubleshooting)

---

## Overview

The MEDUSA World Model uses Neo4j graph database to store and query relationships between discovered assets during penetration testing operations. This knowledge graph enables the AI agent to reason about attack paths, vulnerabilities, and exploitation chains.

**Key Features:**
- Complete schema with 8 node types and 8 relationship types
- Optimized indexes for common query patterns
- Full-text search capabilities
- Constraint enforcement for data integrity
- Sample data for testing and development

---

## Quick Start

### 1. Start Neo4j with Docker Compose

```bash
# Start Neo4j service
docker-compose up -d medusa-neo4j

# Check service health
docker-compose ps medusa-neo4j

# View logs
docker-compose logs -f medusa-neo4j
```

### 2. Initialize Schema

```bash
# Initialize schema (constraints and indexes)
docker exec -i medusa_neo4j cypher-shell -u neo4j -p medusa_graph_pass < neo4j-schema/init-schema.cypher

# Load sample data (optional)
docker exec -i medusa_neo4j cypher-shell -u neo4j -p medusa_graph_pass < neo4j-schema/sample-data.cypher
```

### 3. Access Neo4j Browser

Open your browser to: [http://localhost:7474](http://localhost:7474)

**Default Credentials:**
- Username: `neo4j`
- Password: `medusa_graph_pass`

---

## Database Setup

### Option 1: Docker Setup (Recommended)

The Neo4j service is already configured in `docker-compose.yml`:

**Service Configuration:**
```yaml
medusa-neo4j:
  image: neo4j:5.15-community
  ports:
    - "7474:7474"  # HTTP Browser Interface
    - "7687:7687"  # Bolt Protocol
  environment:
    - NEO4J_AUTH=neo4j/medusa_graph_pass
  volumes:
    - medusa-neo4j-data:/data
    - medusa-neo4j-logs:/logs
```

**Connection Details:**
- **Bolt URI**: `bolt://localhost:7687`
- **Browser**: `http://localhost:7474`
- **Username**: `neo4j`
- **Password**: `medusa_graph_pass` (change via `NEO4J_PASSWORD` env var)

**From other Docker containers:**
- **Bolt URI**: `bolt://medusa-neo4j:7687`
- **Network**: `medusa-dmz`

### Option 2: Neo4j AuraDB (Cloud)

For cloud deployment, use Neo4j AuraDB free tier:

1. **Create Free Instance**
   - Go to [Neo4j AuraDB](https://neo4j.com/cloud/aura/)
   - Sign up and create a free instance
   - Note the connection URI and credentials

2. **Update Configuration**
   ```yaml
   # neo4j-config.yaml
   auradb:
     enabled: true
     uri: "neo4j+s://<instance-id>.databases.neo4j.io"
     username: "neo4j"
     password: "<your-password>"
   ```

3. **Initialize Schema**
   ```bash
   # Using cypher-shell
   cat init-schema.cypher | cypher-shell -a neo4j+s://<instance>.databases.neo4j.io -u neo4j -p <password>
   ```

---

## Schema Design

### Graph Structure Overview

```
Domain
  └─[HAS_SUBDOMAIN]─> Subdomain
                        └─[RESOLVES_TO]─> Host
                                           ├─[HAS_PORT]─> Port
                                           ├─[RUNS_WEBAPP]─> WebServer
                                           ├─[HAS_USER]─> User
                                           │               └─[OWNS_CREDENTIAL]─> Credential
                                           └─[IS_VULNERABLE_TO]─> Vulnerability
```

### Design Principles

1. **Asset-Centric**: Hosts are the central nodes connecting services, users, and vulnerabilities
2. **Bidirectional Discovery**: Relationships support both top-down (domain → host) and bottom-up (vuln → host) queries
3. **Temporal Tracking**: All nodes include `discovered_at` and relevant timestamp fields
4. **Flexibility**: Properties support arrays and optional fields for varying data richness

---

## Node Types

### 1. Domain
Represents root domains discovered during reconnaissance.

**Properties:**
- `name` (string, unique, required): Domain name (e.g., "medcare.local")
- `discovered_at` (datetime): When domain was discovered
- `scan_status` (string): Current scan status

**Example:**
```cypher
CREATE (d:Domain {
  name: 'medcare.local',
  discovered_at: datetime(),
  scan_status: 'completed'
})
```

---

### 2. Subdomain
Represents subdomains under a root domain.

**Properties:**
- `name` (string, unique, required): Fully qualified subdomain name
- `discovered_at` (datetime): Discovery timestamp

**Example:**
```cypher
CREATE (s:Subdomain {
  name: 'www.medcare.local',
  discovered_at: datetime()
})
```

---

### 3. Host
Represents physical or virtual hosts/IP addresses.

**Properties:**
- `ip` (string, unique, required): IP address
- `hostname` (string): DNS hostname
- `os_name` (string): Operating system name
- `os_accuracy` (integer): OS detection confidence (0-100)
- `discovered_at` (datetime): Discovery timestamp
- `last_seen` (datetime): Last activity timestamp

**Example:**
```cypher
CREATE (h:Host {
  ip: '172.20.0.10',
  hostname: 'ehr-portal',
  os_name: 'Linux',
  os_accuracy: 95,
  discovered_at: datetime(),
  last_seen: datetime()
})
```

---

### 4. Port
Represents network ports and services on hosts.

**Properties:**
- `number` (integer, required): Port number (1-65535)
- `protocol` (string, required): Protocol (tcp/udp)
- `state` (string): Port state (open/closed/filtered)
- `service` (string): Service name (http, ssh, mysql, etc.)
- `product` (string): Product name (Apache, OpenSSH, etc.)
- `version` (string): Service version
- `service_string` (string): Full service banner
- `host_id` (string, required): Reference to host IP (for uniqueness)
- `discovered_at` (datetime): Discovery timestamp

**Unique Constraint**: Combination of `(number, protocol, host_id)`

**Example:**
```cypher
CREATE (p:Port {
  number: 80,
  protocol: 'tcp',
  state: 'open',
  service: 'http',
  product: 'Apache',
  version: '2.4.41',
  service_string: 'Apache httpd 2.4.41 ((Ubuntu))',
  host_id: '172.20.0.10',
  discovered_at: datetime()
})
```

---

### 5. WebServer
Represents web applications and HTTP services.

**Properties:**
- `url` (string, unique, required): Full URL including protocol and port
- `status_code` (integer): HTTP response code
- `title` (string): Page title from HTML
- `web_server` (string): Web server software
- `technologies` (array of strings): Detected technologies (frameworks, libraries)
- `ssl` (boolean): Whether HTTPS is used
- `discovered_at` (datetime): Discovery timestamp
- `last_checked` (datetime): Last time service was verified

**Example:**
```cypher
CREATE (w:WebServer {
  url: 'https://portal.medcare.local',
  status_code: 200,
  title: 'MedCare EHR - Secure Login',
  web_server: 'Apache/2.4.41',
  technologies: ['PHP', 'MySQL', 'jQuery'],
  ssl: true,
  discovered_at: datetime(),
  last_checked: datetime()
})
```

---

### 6. User
Represents user accounts discovered on systems.

**Properties:**
- `name` (string): Full name
- `username` (string, required): Login username
- `domain` (string, required): Domain or realm
- `asrep_roastable` (boolean): Whether account is AS-REP roastable (Kerberos)
- `discovered_at` (datetime): Discovery timestamp

**Unique Constraint**: Combination of `(username, domain)`

**Example:**
```cypher
CREATE (u:User {
  name: 'Dr. Sarah Johnson',
  username: 'sjohnson',
  domain: 'medcare.local',
  asrep_roastable: false,
  discovered_at: datetime()
})
```

---

### 7. Credential
Represents discovered credentials (passwords, keys, tokens).

**Properties:**
- `id` (string, unique, required): Unique credential identifier
- `value` (string, required): The actual credential value (encrypted in production!)
- `type` (string): Credential type (password, ssh_key, jwt_secret, api_key, etc.)
- `username` (string): Associated username
- `domain` (string): Associated domain
- `discovered_at` (datetime): Discovery timestamp
- `source` (string): How credential was obtained (brute_force, config_file, etc.)

**Example:**
```cypher
CREATE (c:Credential {
  id: 'cred_001',
  value: 'admin2024',
  type: 'password',
  username: 'admin',
  domain: 'medcare.local',
  discovered_at: datetime(),
  source: 'brute_force'
})
```

---

### 8. Vulnerability
Represents security vulnerabilities discovered during testing.

**Properties:**
- `id` (string, unique, required): Unique vulnerability identifier
- `type` (string, required): Vulnerability type (SQL Injection, XSS, etc.)
- `parameter` (string): Vulnerable parameter name
- `location` (string): URL or file path where vulnerability exists
- `dbms` (string): Database management system (for SQL injection)
- `databases` (array of strings): Accessible database names
- `tables` (array of strings): Accessible table names
- `severity` (string): Severity level (low, medium, high, critical)
- `discovered_at` (datetime): Discovery timestamp
- `exploited` (boolean): Whether vulnerability has been successfully exploited

**Example:**
```cypher
CREATE (v:Vulnerability {
  id: 'vuln_001',
  type: 'SQL Injection',
  parameter: 'patient_id',
  location: 'http://www.medcare.local/patient_lookup.php',
  severity: 'high',
  discovered_at: datetime(),
  exploited: false
})
```

---

## Relationship Types

### 1. HAS_SUBDOMAIN
**From**: Domain → **To**: Subdomain

Links root domains to their subdomains.

**Example:**
```cypher
MATCH (d:Domain {name: 'medcare.local'})
MATCH (s:Subdomain {name: 'www.medcare.local'})
CREATE (d)-[:HAS_SUBDOMAIN]->(s)
```

---

### 2. RESOLVES_TO
**From**: Subdomain → **To**: Host

Links subdomains to their IP addresses/hosts.

**Example:**
```cypher
MATCH (s:Subdomain {name: 'www.medcare.local'})
MATCH (h:Host {ip: '172.20.0.10'})
CREATE (s)-[:RESOLVES_TO]->(h)
```

---

### 3. HAS_PORT
**From**: Host → **To**: Port

Links hosts to their open ports.

**Example:**
```cypher
MATCH (h:Host {ip: '172.20.0.10'})
MATCH (p:Port {number: 80, host_id: '172.20.0.10'})
CREATE (h)-[:HAS_PORT]->(p)
```

---

### 4. RUNS_WEBAPP
**From**: Host → **To**: WebServer

Links hosts to web applications running on them.

**Example:**
```cypher
MATCH (h:Host {ip: '172.20.0.10'})
MATCH (w:WebServer {url: 'http://www.medcare.local'})
CREATE (h)-[:RUNS_WEBAPP]->(w)
```

---

### 5. HAS_USER
**From**: Host → **To**: User

Links hosts to user accounts that exist on them.

**Example:**
```cypher
MATCH (h:Host {ip: '172.21.0.30'})
MATCH (u:User {username: 'admin'})
CREATE (h)-[:HAS_USER]->(u)
```

---

### 6. OWNS_CREDENTIAL
**From**: User → **To**: Credential

Links users to their credentials.

**Example:**
```cypher
MATCH (u:User {username: 'admin'})
MATCH (c:Credential {id: 'cred_001'})
CREATE (u)-[:OWNS_CREDENTIAL]->(c)
```

---

### 7. IS_VULNERABLE_TO
**From**: Host | WebServer → **To**: Vulnerability

Links hosts or web servers to vulnerabilities affecting them.

**Example:**
```cypher
MATCH (w:WebServer {url: 'http://www.medcare.local'})
MATCH (v:Vulnerability {id: 'vuln_001'})
CREATE (w)-[:IS_VULNERABLE_TO]->(v)
```

---

## Indexes and Constraints

### Constraints

All constraints are automatically created by `init-schema.cypher`:

- **Domain**: `name` (unique, not null)
- **Subdomain**: `name` (unique, not null)
- **Host**: `ip` (unique, not null)
- **WebServer**: `url` (unique, not null)
- **Port**: `(number, protocol, host_id)` (composite unique)
- **User**: `(username, domain)` (composite unique)
- **Credential**: `id` (unique)
- **Vulnerability**: `id` (unique)

### Indexes

**Single Property Indexes:**
- Host: `hostname`, `os_name`
- WebServer: `status_code`, `technologies`
- Port: `service`, `state`
- User: `domain`, `asrep_roastable`
- Credential: `type`, `username`
- Vulnerability: `type`, `location`

**Full-Text Indexes:**
- `hostFullText`: Host hostname and OS name
- `webserverFullText`: WebServer URL, title, and web_server
- `userFullText`: User username, name, and domain

---

## Usage Examples

### Basic Queries

**1. Find all hosts:**
```cypher
MATCH (h:Host)
RETURN h.ip, h.hostname, h.os_name
LIMIT 10;
```

**2. Find all open web ports:**
```cypher
MATCH (h:Host)-[:HAS_PORT]->(p:Port)
WHERE p.service IN ['http', 'https']
AND p.state = 'open'
RETURN h.ip, p.number, p.service, p.product;
```

**3. Find all SQL injection vulnerabilities:**
```cypher
MATCH (v:Vulnerability)
WHERE v.type = 'SQL Injection'
RETURN v.id, v.location, v.severity;
```

### Attack Path Queries

**4. Find path from domain to vulnerabilities:**
```cypher
MATCH path = (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(h:Host)
-[:RUNS_WEBAPP]->(w:WebServer)-[:IS_VULNERABLE_TO]->(v:Vulnerability)
WHERE d.name = 'medcare.local'
RETURN path
LIMIT 5;
```

**5. Find hosts with exploitable vulnerabilities:**
```cypher
MATCH (h:Host)-[:IS_VULNERABLE_TO]->(v:Vulnerability)
WHERE v.severity IN ['high', 'critical']
AND v.exploited = false
RETURN h.ip, h.hostname, v.type, v.severity
ORDER BY v.severity DESC;
```

**6. Find users with weak credentials:**
```cypher
MATCH (u:User)-[:OWNS_CREDENTIAL]->(c:Credential)
WHERE c.source = 'brute_force'
RETURN u.username, u.domain, c.type;
```

### Complex Queries

**7. Find all services on a host:**
```cypher
MATCH (h:Host {ip: '172.20.0.10'})
OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
OPTIONAL MATCH (h)-[:RUNS_WEBAPP]->(w:WebServer)
RETURN h.ip, h.hostname,
       collect(DISTINCT p.service) as services,
       collect(DISTINCT w.url) as webapps;
```

**8. Find attack chains (multi-hop):**
```cypher
MATCH path = (d:Domain)-[*1..5]-(v:Vulnerability)
WHERE v.exploited = true
RETURN path
LIMIT 10;
```

**9. Full-text search for hosts:**
```cypher
CALL db.index.fulltext.queryNodes('hostFullText', 'portal')
YIELD node, score
RETURN node.ip, node.hostname, score
ORDER BY score DESC;
```

---

## Connection Configuration

### Python Connection

```python
from neo4j import GraphDatabase

# Load configuration
from neo4j_config import NEO4J_CONFIG

# Create driver
driver = GraphDatabase.driver(
    NEO4J_CONFIG["uri"],
    auth=NEO4J_CONFIG["auth"],
    max_connection_lifetime=NEO4J_CONFIG["max_connection_lifetime"],
    max_connection_pool_size=NEO4J_CONFIG["max_connection_pool_size"]
)

# Use driver
with driver.session(database=NEO4J_CONFIG["database"]) as session:
    result = session.run("MATCH (h:Host) RETURN count(h) as host_count")
    print(result.single()["host_count"])

# Close driver
driver.close()
```

### Environment Variables

```bash
# Set custom connection parameters
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USERNAME="neo4j"
export NEO4J_PASSWORD="your_secure_password"
export NEO4J_DATABASE="neo4j"
```

---

## Access Patterns

### Common Query Patterns

1. **Asset Discovery**: Domain → Subdomain → Host
2. **Service Enumeration**: Host → Port → Service Details
3. **Vulnerability Mapping**: Host/WebServer → Vulnerabilities
4. **Credential Access**: User → Credentials → Access Paths
5. **Attack Chain Analysis**: Multi-hop paths through relationships

### Performance Considerations

- **Use indexes**: All frequently queried properties are indexed
- **Limit results**: Always use `LIMIT` for exploratory queries
- **Use parameters**: Parameterized queries for security and caching
- **Profile queries**: Use `PROFILE` or `EXPLAIN` to optimize complex queries

---

## Maintenance

### Backup Database

```bash
# Stop Neo4j
docker-compose stop medusa-neo4j

# Backup data volume
docker run --rm -v medusa-neo4j-data:/data -v $(pwd)/backups:/backup ubuntu tar czf /backup/neo4j-backup-$(date +%Y%m%d).tar.gz /data

# Start Neo4j
docker-compose start medusa-neo4j
```

### Reset Database

```bash
# WARNING: This deletes all data!
docker-compose down -v medusa-neo4j
docker-compose up -d medusa-neo4j

# Re-initialize schema
docker exec -i medusa_neo4j cypher-shell -u neo4j -p medusa_graph_pass < neo4j-schema/init-schema.cypher
```

### Update Schema

```bash
# Apply schema updates
docker exec -i medusa_neo4j cypher-shell -u neo4j -p medusa_graph_pass < neo4j-schema/init-schema.cypher
```

---

## Troubleshooting

### Connection Issues

**Problem**: Cannot connect to Neo4j

**Solutions**:
```bash
# Check if container is running
docker-compose ps medusa-neo4j

# Check logs
docker-compose logs medusa-neo4j

# Verify port is accessible
nc -zv localhost 7687

# Test connection
docker exec medusa_neo4j cypher-shell -u neo4j -p medusa_graph_pass "RETURN 1;"
```

### Authentication Errors

**Problem**: Authentication failed

**Solution**:
```bash
# Reset password (if needed)
docker-compose down medusa-neo4j
docker volume rm medusa-neo4j-data
docker-compose up -d medusa-neo4j
```

### Performance Issues

**Problem**: Queries are slow

**Solutions**:
```cypher
-- Check query execution plan
EXPLAIN MATCH (h:Host)-[:HAS_PORT]->(p:Port) RETURN h, p;

-- Verify indexes are used
PROFILE MATCH (h:Host {ip: '172.20.0.10'}) RETURN h;

-- Check index usage
SHOW INDEXES;
```

---

## Additional Resources

- [Neo4j Documentation](https://neo4j.com/docs/)
- [Cypher Query Language](https://neo4j.com/docs/cypher-manual/current/)
- [Neo4j Python Driver](https://neo4j.com/docs/python-manual/current/)
- [Graph Data Modeling](https://neo4j.com/developer/guide-data-modeling/)

---

## Support

For issues or questions:
1. Check Neo4j logs: `docker-compose logs medusa-neo4j`
2. Verify schema: `SHOW CONSTRAINTS; SHOW INDEXES;`
3. Review this documentation
4. Consult Neo4j community forums

---

**Version**: 1.0.0
**Last Updated**: 2024
**License**: Project MEDUSA
