// ============================================================================
// MEDUSA World Model - Sample Data
// ============================================================================
// This script creates sample data to demonstrate the graph structure
// and relationships in the MEDUSA World Model.
//
// USAGE:
//   cat sample-data.cypher | cypher-shell -u neo4j -p <password>
// ============================================================================

// ============================================================================
// STEP 1: Create Domain Structure
// ============================================================================

// Create root domain
CREATE (domain:Domain {
  name: 'medcare.local',
  discovered_at: datetime(),
  scan_status: 'completed'
});

// Create subdomains
CREATE (www:Subdomain {
  name: 'www.medcare.local',
  discovered_at: datetime()
}),
(api:Subdomain {
  name: 'api.medcare.local',
  discovered_at: datetime()
}),
(portal:Subdomain {
  name: 'portal.medcare.local',
  discovered_at: datetime()
}),
(admin:Subdomain {
  name: 'admin.medcare.local',
  discovered_at: datetime()
});

// Link subdomains to domain
MATCH (d:Domain {name: 'medcare.local'})
MATCH (www:Subdomain {name: 'www.medcare.local'})
MATCH (api:Subdomain {name: 'api.medcare.local'})
MATCH (portal:Subdomain {name: 'portal.medcare.local'})
MATCH (admin:Subdomain {name: 'admin.medcare.local'})
CREATE (d)-[:HAS_SUBDOMAIN]->(www),
       (d)-[:HAS_SUBDOMAIN]->(api),
       (d)-[:HAS_SUBDOMAIN]->(portal),
       (d)-[:HAS_SUBDOMAIN]->(admin);

// ============================================================================
// STEP 2: Create Hosts
// ============================================================================

CREATE (h1:Host {
  ip: '172.20.0.10',
  hostname: 'ehr-portal',
  os_name: 'Linux',
  os_accuracy: 95,
  discovered_at: datetime(),
  last_seen: datetime()
}),
(h2:Host {
  ip: '172.20.0.11',
  hostname: 'api-server',
  os_name: 'Linux',
  os_accuracy: 98,
  discovered_at: datetime(),
  last_seen: datetime()
}),
(h3:Host {
  ip: '172.21.0.20',
  hostname: 'db-server',
  os_name: 'Linux',
  os_accuracy: 99,
  discovered_at: datetime(),
  last_seen: datetime()
}),
(h4:Host {
  ip: '172.21.0.30',
  hostname: 'admin-workstation',
  os_name: 'Linux',
  os_accuracy: 90,
  discovered_at: datetime(),
  last_seen: datetime()
});

// Link subdomains to hosts
MATCH (www:Subdomain {name: 'www.medcare.local'}), (h1:Host {ip: '172.20.0.10'})
CREATE (www)-[:RESOLVES_TO]->(h1);

MATCH (api:Subdomain {name: 'api.medcare.local'}), (h2:Host {ip: '172.20.0.11'})
CREATE (api)-[:RESOLVES_TO]->(h2);

MATCH (portal:Subdomain {name: 'portal.medcare.local'}), (h1:Host {ip: '172.20.0.10'})
CREATE (portal)-[:RESOLVES_TO]->(h1);

MATCH (admin:Subdomain {name: 'admin.medcare.local'}), (h4:Host {ip: '172.21.0.30'})
CREATE (admin)-[:RESOLVES_TO]->(h4);

// ============================================================================
// STEP 3: Create Ports and Services
// ============================================================================

// Web server ports
CREATE (p1:Port {
  number: 80,
  protocol: 'tcp',
  state: 'open',
  service: 'http',
  product: 'Apache',
  version: '2.4.41',
  service_string: 'Apache httpd 2.4.41 ((Ubuntu))',
  host_id: '172.20.0.10',
  discovered_at: datetime()
}),
(p2:Port {
  number: 443,
  protocol: 'tcp',
  state: 'open',
  service: 'https',
  product: 'Apache',
  version: '2.4.41',
  service_string: 'Apache httpd 2.4.41 ((Ubuntu))',
  host_id: '172.20.0.10',
  discovered_at: datetime()
});

// API server ports
CREATE (p3:Port {
  number: 3000,
  protocol: 'tcp',
  state: 'open',
  service: 'http',
  product: 'Node.js',
  version: '18.x',
  service_string: 'Node.js Express API',
  host_id: '172.20.0.11',
  discovered_at: datetime()
});

// Database port
CREATE (p4:Port {
  number: 3306,
  protocol: 'tcp',
  state: 'open',
  service: 'mysql',
  product: 'MySQL',
  version: '8.0',
  service_string: 'MySQL 8.0.33',
  host_id: '172.21.0.20',
  discovered_at: datetime()
});

// SSH ports
CREATE (p5:Port {
  number: 22,
  protocol: 'tcp',
  state: 'open',
  service: 'ssh',
  product: 'OpenSSH',
  version: '8.2p1',
  service_string: 'OpenSSH 8.2p1 Ubuntu',
  host_id: '172.21.0.30',
  discovered_at: datetime()
});

// Link ports to hosts
MATCH (h:Host {ip: '172.20.0.10'}), (p1:Port {number: 80, host_id: '172.20.0.10'})
CREATE (h)-[:HAS_PORT]->(p1);

MATCH (h:Host {ip: '172.20.0.10'}), (p2:Port {number: 443, host_id: '172.20.0.10'})
CREATE (h)-[:HAS_PORT]->(p2);

MATCH (h:Host {ip: '172.20.0.11'}), (p3:Port {number: 3000, host_id: '172.20.0.11'})
CREATE (h)-[:HAS_PORT]->(p3);

MATCH (h:Host {ip: '172.21.0.20'}), (p4:Port {number: 3306, host_id: '172.21.0.20'})
CREATE (h)-[:HAS_PORT]->(p4);

MATCH (h:Host {ip: '172.21.0.30'}), (p5:Port {number: 22, host_id: '172.21.0.30'})
CREATE (h)-[:HAS_PORT]->(p5);

// ============================================================================
// STEP 4: Create Web Servers
// ============================================================================

CREATE (ws1:WebServer {
  url: 'http://www.medcare.local',
  status_code: 200,
  title: 'MedCare Health System - Patient Portal',
  web_server: 'Apache/2.4.41',
  technologies: ['PHP', 'MySQL', 'jQuery', 'Bootstrap'],
  ssl: false,
  discovered_at: datetime(),
  last_checked: datetime()
}),
(ws2:WebServer {
  url: 'https://portal.medcare.local',
  status_code: 200,
  title: 'MedCare EHR - Secure Login',
  web_server: 'Apache/2.4.41',
  technologies: ['PHP', 'MySQL', 'jQuery'],
  ssl: true,
  discovered_at: datetime(),
  last_checked: datetime()
}),
(ws3:WebServer {
  url: 'http://api.medcare.local:3000',
  status_code: 200,
  title: 'MedCare API',
  web_server: 'Express',
  technologies: ['Node.js', 'Express', 'MySQL'],
  ssl: false,
  discovered_at: datetime(),
  last_checked: datetime()
});

// Link web servers to hosts
MATCH (h:Host {ip: '172.20.0.10'}), (ws1:WebServer {url: 'http://www.medcare.local'})
CREATE (h)-[:RUNS_WEBAPP]->(ws1);

MATCH (h:Host {ip: '172.20.0.10'}), (ws2:WebServer {url: 'https://portal.medcare.local'})
CREATE (h)-[:RUNS_WEBAPP]->(ws2);

MATCH (h:Host {ip: '172.20.0.11'}), (ws3:WebServer {url: 'http://api.medcare.local:3000'})
CREATE (h)-[:RUNS_WEBAPP]->(ws3);

// ============================================================================
// STEP 5: Create Users
// ============================================================================

CREATE (u1:User {
  name: 'Dr. Sarah Johnson',
  username: 'sjohnson',
  domain: 'medcare.local',
  asrep_roastable: false,
  discovered_at: datetime()
}),
(u2:User {
  name: 'Administrator',
  username: 'admin',
  domain: 'medcare.local',
  asrep_roastable: false,
  discovered_at: datetime()
}),
(u3:User {
  name: 'Database Admin',
  username: 'dbadmin',
  domain: 'medcare.local',
  asrep_roastable: false,
  discovered_at: datetime()
}),
(u4:User {
  name: 'Service Account',
  username: 'svc_backup',
  domain: 'medcare.local',
  asrep_roastable: true,
  discovered_at: datetime()
});

// Link users to hosts
MATCH (h:Host {ip: '172.21.0.30'}), (u2:User {username: 'admin'})
CREATE (h)-[:HAS_USER]->(u2);

MATCH (h:Host {ip: '172.21.0.20'}), (u3:User {username: 'dbadmin'})
CREATE (h)-[:HAS_USER]->(u3);

// ============================================================================
// STEP 6: Create Credentials
// ============================================================================

CREATE (c1:Credential {
  id: 'cred_001',
  value: 'admin2024',
  type: 'password',
  username: 'admin',
  domain: 'medcare.local',
  discovered_at: datetime(),
  source: 'brute_force'
}),
(c2:Credential {
  id: 'cred_002',
  value: 'Welcome123!',
  type: 'password',
  username: 'ehrapp',
  domain: 'db-server',
  discovered_at: datetime(),
  source: 'configuration_file'
}),
(c3:Credential {
  id: 'cred_003',
  value: 'supersecret123',
  type: 'jwt_secret',
  username: 'api',
  domain: 'medcare.local',
  discovered_at: datetime(),
  source: 'source_code'
});

// Link credentials to users
MATCH (u:User {username: 'admin'}), (c:Credential {id: 'cred_001'})
CREATE (u)-[:OWNS_CREDENTIAL]->(c);

// ============================================================================
// STEP 7: Create Vulnerabilities
// ============================================================================

CREATE (v1:Vulnerability {
  id: 'vuln_001',
  type: 'SQL Injection',
  parameter: 'patient_id',
  location: 'http://www.medcare.local/patient_lookup.php',
  severity: 'high',
  discovered_at: datetime(),
  exploited: false
}),
(v2:Vulnerability {
  id: 'vuln_002',
  type: 'SQL Injection',
  parameter: 'user_id',
  location: 'http://api.medcare.local:3000/api/users',
  dbms: 'MySQL',
  databases: ['healthcare_db'],
  tables: ['users', 'patients', 'appointments'],
  severity: 'critical',
  discovered_at: datetime(),
  exploited: true
}),
(v3:Vulnerability {
  id: 'vuln_003',
  type: 'Weak Credentials',
  parameter: 'password',
  location: 'ssh://172.21.0.30:22',
  severity: 'medium',
  discovered_at: datetime(),
  exploited: true
}),
(v4:Vulnerability {
  id: 'vuln_004',
  type: 'JWT Secret Disclosure',
  parameter: 'jwt_secret',
  location: 'http://api.medcare.local:3000/.git/config',
  severity: 'high',
  discovered_at: datetime(),
  exploited: false
});

// Link vulnerabilities to web servers
MATCH (ws:WebServer {url: 'http://www.medcare.local'}), (v:Vulnerability {id: 'vuln_001'})
CREATE (ws)-[:IS_VULNERABLE_TO]->(v);

MATCH (ws:WebServer {url: 'http://api.medcare.local:3000'}), (v:Vulnerability {id: 'vuln_002'})
CREATE (ws)-[:IS_VULNERABLE_TO]->(v);

MATCH (ws:WebServer {url: 'http://api.medcare.local:3000'}), (v:Vulnerability {id: 'vuln_004'})
CREATE (ws)-[:IS_VULNERABLE_TO]->(v);

// Link vulnerabilities to hosts
MATCH (h:Host {ip: '172.21.0.30'}), (v:Vulnerability {id: 'vuln_003'})
CREATE (h)-[:IS_VULNERABLE_TO]->(v);

// ============================================================================
// Sample Data Creation Complete
// ============================================================================

// Verify the graph structure
MATCH (n) RETURN labels(n), count(n) as count ORDER BY count DESC;

// Show some sample paths
MATCH p=(:Domain)-[:HAS_SUBDOMAIN]->(:Subdomain)-[:RESOLVES_TO]->(:Host)
RETURN p LIMIT 5;
