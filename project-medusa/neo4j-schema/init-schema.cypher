// ============================================================================
// MEDUSA World Model - Neo4j Schema Initialization
// ============================================================================
// This script initializes the complete graph database schema for MEDUSA's
// World Model, including nodes, relationships, constraints, and indexes.
//
// USAGE:
//   cat init-schema.cypher | cypher-shell -u neo4j -p <password>
//
// OR from within Docker container:
//   docker exec -i medusa_neo4j cypher-shell -u neo4j -p <password> < init-schema.cypher
// ============================================================================

// ============================================================================
// STEP 1: Clean Up (Optional - Use with caution in production!)
// ============================================================================
// Uncomment the following lines to reset the database completely
// WARNING: This will delete ALL data and constraints

// MATCH (n) DETACH DELETE n;
// CALL apoc.schema.assert({}, {});

// ============================================================================
// STEP 2: Create Constraints
// ============================================================================
// Constraints ensure data integrity and automatically create indexes

// Domain Constraints
CREATE CONSTRAINT domain_name_unique IF NOT EXISTS
FOR (d:Domain) REQUIRE d.name IS UNIQUE;

CREATE CONSTRAINT domain_name_not_null IF NOT EXISTS
FOR (d:Domain) REQUIRE d.name IS NOT NULL;

// Subdomain Constraints
CREATE CONSTRAINT subdomain_name_unique IF NOT EXISTS
FOR (s:Subdomain) REQUIRE s.name IS UNIQUE;

CREATE CONSTRAINT subdomain_name_not_null IF NOT EXISTS
FOR (s:Subdomain) REQUIRE s.name IS NOT NULL;

// Host Constraints
CREATE CONSTRAINT host_ip_unique IF NOT EXISTS
FOR (h:Host) REQUIRE h.ip IS UNIQUE;

CREATE CONSTRAINT host_ip_not_null IF NOT EXISTS
FOR (h:Host) REQUIRE h.ip IS NOT NULL;

// WebServer Constraints
CREATE CONSTRAINT webserver_url_unique IF NOT EXISTS
FOR (w:WebServer) REQUIRE w.url IS UNIQUE;

CREATE CONSTRAINT webserver_url_not_null IF NOT EXISTS
FOR (w:WebServer) REQUIRE w.url IS NOT NULL;

// Port Constraints
// Composite constraint: A port is unique by the combination of number + protocol + host
// Note: Neo4j requires creating this via node property pattern
CREATE CONSTRAINT port_unique IF NOT EXISTS
FOR (p:Port) REQUIRE (p.number, p.protocol, p.host_id) IS UNIQUE;

CREATE CONSTRAINT port_number_not_null IF NOT EXISTS
FOR (p:Port) REQUIRE p.number IS NOT NULL;

CREATE CONSTRAINT port_protocol_not_null IF NOT EXISTS
FOR (p:Port) REQUIRE p.protocol IS NOT NULL;

// User Constraints
// Composite constraint: username + domain makes a unique user
CREATE CONSTRAINT user_unique IF NOT EXISTS
FOR (u:User) REQUIRE (u.username, u.domain) IS UNIQUE;

CREATE CONSTRAINT user_username_not_null IF NOT EXISTS
FOR (u:User) REQUIRE u.username IS NOT NULL;

// Credential Constraints
CREATE CONSTRAINT credential_id_unique IF NOT EXISTS
FOR (c:Credential) REQUIRE c.id IS UNIQUE;

CREATE CONSTRAINT credential_value_not_null IF NOT EXISTS
FOR (c:Credential) REQUIRE c.value IS NOT NULL;

// Vulnerability Constraints
CREATE CONSTRAINT vulnerability_id_unique IF NOT EXISTS
FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;

CREATE CONSTRAINT vulnerability_type_not_null IF NOT EXISTS
FOR (v:Vulnerability) REQUIRE v.type IS NOT NULL;

// ============================================================================
// STEP 3: Create Additional Indexes for Query Optimization
// ============================================================================
// These indexes optimize common query patterns not covered by constraints

// Host Indexes
CREATE INDEX host_hostname IF NOT EXISTS
FOR (h:Host) ON (h.hostname);

CREATE INDEX host_os_name IF NOT EXISTS
FOR (h:Host) ON (h.os_name);

// WebServer Indexes
CREATE INDEX webserver_status_code IF NOT EXISTS
FOR (w:WebServer) ON (w.status_code);

CREATE INDEX webserver_technologies IF NOT EXISTS
FOR (w:WebServer) ON (w.technologies);

// Port Indexes
CREATE INDEX port_service IF NOT EXISTS
FOR (p:Port) ON (p.service);

CREATE INDEX port_state IF NOT EXISTS
FOR (p:Port) ON (p.state);

// User Indexes
CREATE INDEX user_domain IF NOT EXISTS
FOR (u:User) ON (u.domain);

CREATE INDEX user_asrep_roastable IF NOT EXISTS
FOR (u:User) ON (u.asrep_roastable);

// Credential Indexes
CREATE INDEX credential_type IF NOT EXISTS
FOR (c:Credential) ON (c.type);

CREATE INDEX credential_username IF NOT EXISTS
FOR (c:Credential) ON (c.username);

// Vulnerability Indexes
CREATE INDEX vulnerability_type IF NOT EXISTS
FOR (v:Vulnerability) ON (v.type);

CREATE INDEX vulnerability_location IF NOT EXISTS
FOR (v:Vulnerability) ON (v.location);

// ============================================================================
// STEP 4: Create Full-Text Search Indexes
// ============================================================================
// Full-text indexes for advanced searching capabilities

// Full-text search for hosts
CALL db.index.fulltext.createNodeIndex(
  'hostFullText',
  ['Host'],
  ['hostname', 'os_name']
) IF NOT EXISTS;

// Full-text search for web servers
CALL db.index.fulltext.createNodeIndex(
  'webserverFullText',
  ['WebServer'],
  ['url', 'title', 'web_server']
) IF NOT EXISTS;

// Full-text search for users
CALL db.index.fulltext.createNodeIndex(
  'userFullText',
  ['User'],
  ['username', 'name', 'domain']
) IF NOT EXISTS;

// ============================================================================
// STEP 5: Create Sample Metadata Node (Optional)
// ============================================================================
// This node stores metadata about the World Model state

MERGE (m:Metadata {id: 'world_model_v1'})
SET m.created_at = datetime(),
    m.version = '1.0.0',
    m.description = 'MEDUSA World Model - Autonomous Penetration Testing Knowledge Graph',
    m.last_updated = datetime();

// ============================================================================
// Schema Initialization Complete
// ============================================================================

// Verify schema creation
CALL db.schema.visualization();

// Display constraint summary
SHOW CONSTRAINTS;

// Display index summary
SHOW INDEXES;
