# Neo4j World Model - Schema Diagram

## Visual Representation

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        MEDUSA WORLD MODEL SCHEMA                          │
│                         Neo4j Knowledge Graph                             │
└──────────────────────────────────────────────────────────────────────────┘

                            ┌─────────────┐
                            │   Domain    │
                            │             │
                            │ • name      │
                            └──────┬──────┘
                                   │
                            [HAS_SUBDOMAIN]
                                   │
                                   ↓
                            ┌─────────────┐
                            │  Subdomain  │
                            │             │
                            │ • name      │
                            └──────┬──────┘
                                   │
                            [RESOLVES_TO]
                                   │
                                   ↓
┌────────────────────────────────────────────────────────────────────────┐
│                            ┌─────────────┐                              │
│                            │    Host     │                              │
│                            │             │                              │
│                            │ • ip        │                              │
│                            │ • hostname  │                              │
│                            │ • os_name   │                              │
│                            │ • os_accur. │                              │
│                            └──────┬──────┘                              │
│                                   │                                     │
│         ┌─────────────────────────┼─────────────────────────┐           │
│         │                         │                         │           │
│    [HAS_PORT]              [RUNS_WEBAPP]              [HAS_USER]        │
│         │                         │                         │           │
│         ↓                         ↓                         ↓           │
│  ┌─────────────┐          ┌─────────────┐          ┌─────────────┐     │
│  │    Port     │          │  WebServer  │          │    User     │     │
│  │             │          │             │          │             │     │
│  │ • number    │          │ • url       │          │ • username  │     │
│  │ • protocol  │          │ • status    │          │ • domain    │     │
│  │ • service   │          │ • title     │          │ • name      │     │
│  │ • product   │          │ • tech[]    │          │ • asrep     │     │
│  │ • version   │          │ • ssl       │          └──────┬──────┘     │
│  └─────────────┘          └──────┬──────┘                 │            │
│                                   │                        │            │
│                                   │                 [OWNS_CREDENTIAL]   │
│                                   │                        │            │
│                                   │                        ↓            │
│                          [IS_VULNERABLE_TO]        ┌─────────────┐     │
│                                   │                │ Credential  │     │
│                                   │                │             │     │
│                                   │                │ • id        │     │
│                                   │                │ • value     │     │
│                                   │                │ • type      │     │
│                                   ↓                │ • username  │     │
│                            ┌─────────────┐         └─────────────┘     │
│                            │Vulnerability│                             │
│                            │             │                             │
│                            │ • id        │                             │
│                            │ • type      │                             │
│                            │ • severity  │                             │
│                            │ • location  │                             │
│                            │ • exploited │                             │
│                            └─────────────┘                             │
│                                                                         │
│  Note: Host can also directly connect to Vulnerability                 │
│        via [IS_VULNERABLE_TO] relationship                             │
└─────────────────────────────────────────────────────────────────────────┘

Legend:
  ┌─────────┐
  │  Node   │  = Entity/Node Type
  └─────────┘

  [RELATION] = Relationship Type (directional)

  • property = Node property/attribute

  [] = Array property


═══════════════════════════════════════════════════════════════════════════
Node Types: 8
═══════════════════════════════════════════════════════════════════════════

1. Domain          - Root domains (e.g., medcare.local)
2. Subdomain       - Subdomains under root domains
3. Host            - IP addresses and hostnames (CENTRAL NODE)
4. Port            - Network ports and services
5. WebServer       - Web applications and HTTP services
6. User            - User accounts on systems
7. Credential      - Discovered credentials (passwords, keys, tokens)
8. Vulnerability   - Security vulnerabilities

═══════════════════════════════════════════════════════════════════════════
Relationship Types: 8
═══════════════════════════════════════════════════════════════════════════

1. HAS_SUBDOMAIN       Domain → Subdomain
2. RESOLVES_TO         Subdomain → Host
3. HAS_PORT            Host → Port
4. RUNS_WEBAPP         Host → WebServer
5. HAS_USER            Host → User
6. OWNS_CREDENTIAL     User → Credential
7. IS_VULNERABLE_TO    Host/WebServer → Vulnerability
8. (Future: Additional relationships for lateral movement, privilege escalation)

═══════════════════════════════════════════════════════════════════════════
Example Attack Path
═══════════════════════════════════════════════════════════════════════════

Domain (medcare.local)
    ↓ [HAS_SUBDOMAIN]
Subdomain (www.medcare.local)
    ↓ [RESOLVES_TO]
Host (172.20.0.10)
    ↓ [RUNS_WEBAPP]
WebServer (http://www.medcare.local)
    ↓ [IS_VULNERABLE_TO]
Vulnerability (SQL Injection)
    → Exploited!
    → Access to database
    → Extract credentials
    → Lateral movement

═══════════════════════════════════════════════════════════════════════════
Key Features
═══════════════════════════════════════════════════════════════════════════

✓ Host as central node - connects all assets
✓ Bidirectional queries - top-down and bottom-up traversal
✓ Temporal tracking - discovered_at timestamps
✓ Flexible properties - optional fields for varying data
✓ Array support - technologies[], databases[], tables[]
✓ Status tracking - scan_status, exploited, asrep_roastable
✓ Full-text search - on hosts, webservers, users
✓ Optimized indexes - 18 indexes for fast queries

═══════════════════════════════════════════════════════════════════════════
Query Patterns
═══════════════════════════════════════════════════════════════════════════

1. Asset Discovery
   MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(h:Host)

2. Service Enumeration
   MATCH (h:Host)-[:HAS_PORT]->(p:Port) WHERE p.state = 'open'

3. Vulnerability Mapping
   MATCH (h:Host)-[:IS_VULNERABLE_TO]->(v:Vulnerability)
   WHERE v.severity IN ['high', 'critical']

4. Credential Access
   MATCH (u:User)-[:OWNS_CREDENTIAL]->(c:Credential)

5. Attack Surface
   MATCH path = (d:Domain)-[*1..5]-(v:Vulnerability) RETURN path

6. Multi-hop Paths
   MATCH path = (d:Domain)-[*]-(v:Vulnerability)
   WHERE v.exploited = false RETURN path

═══════════════════════════════════════════════════════════════════════════
Indexes & Constraints
═══════════════════════════════════════════════════════════════════════════

Uniqueness Constraints:
  • Domain.name
  • Subdomain.name
  • Host.ip
  • WebServer.url
  • Port(number, protocol, host_id)
  • User(username, domain)
  • Credential.id
  • Vulnerability.id

Property Indexes (15):
  • Host: hostname, os_name
  • WebServer: status_code, technologies
  • Port: service, state
  • User: domain, asrep_roastable
  • Credential: type, username
  • Vulnerability: type, location

Full-Text Indexes (3):
  • hostFullText (hostname, os_name)
  • webserverFullText (url, title, web_server)
  • userFullText (username, name, domain)

═══════════════════════════════════════════════════════════════════════════
