"""
MEDUSA World Model - Neo4j Client
High-level client for interacting with the Neo4j knowledge graph
"""

import os
import logging
from typing import Optional, List, Dict, Any, Union
from datetime import datetime
from neo4j import GraphDatabase, Driver, Session, Result
from neo4j.exceptions import ServiceUnavailable, AuthError

from .models import (
    Domain,
    Subdomain,
    Host,
    Port,
    WebServer,
    User,
    Credential,
    Vulnerability,
)

logger = logging.getLogger(__name__)


class Neo4jClient:
    """Low-level Neo4j database client"""

    def __init__(
        self,
        uri: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        database: str = "neo4j",
        **kwargs,
    ):
        """
        Initialize Neo4j client

        Args:
            uri: Neo4j connection URI (default: from env or bolt://localhost:7687)
            username: Neo4j username (default: from env or 'neo4j')
            password: Neo4j password (default: from env)
            database: Database name (default: 'neo4j')
            **kwargs: Additional driver configuration
        """
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.username = username or os.getenv("NEO4J_USERNAME", "neo4j")
        self.password = password or os.getenv(
            "NEO4J_PASSWORD", "medusa_graph_pass"
        )
        self.database = database or os.getenv("NEO4J_DATABASE", "neo4j")

        # Auto-detect Docker environment
        if self._is_docker_environment() and "localhost" in self.uri:
            self.uri = self.uri.replace("localhost", "medusa-neo4j")
            logger.info(f"Docker environment detected, using URI: {self.uri}")

        self.driver: Optional[Driver] = None
        self.connected = False

        # Driver configuration
        self.driver_config = {
            "max_connection_lifetime": kwargs.get("max_connection_lifetime", 3600),
            "max_connection_pool_size": kwargs.get("max_connection_pool_size", 50),
            "connection_acquisition_timeout": kwargs.get(
                "connection_acquisition_timeout", 60
            ),
            "encrypted": kwargs.get("encrypted", False),
            "trust": kwargs.get("trust", "TRUST_ALL_CERTIFICATES"),
        }

    @staticmethod
    def _is_docker_environment() -> bool:
        """Detect if running inside Docker container"""
        return (
            os.path.exists("/.dockerenv")
            or os.getenv("DOCKER_CONTAINER") == "true"
            or os.getenv("RUNNING_IN_DOCKER") == "true"
        )

    def connect(self) -> None:
        """Establish connection to Neo4j database"""
        try:
            logger.info(f"Connecting to Neo4j at {self.uri}...")
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password),
                **self.driver_config,
            )
            # Test connection
            with self.driver.session(database=self.database) as session:
                result = session.run("RETURN 1 as test")
                result.single()
            self.connected = True
            logger.info("Successfully connected to Neo4j")
        except AuthError as e:
            logger.error(f"Authentication failed: {e}")
            raise
        except ServiceUnavailable as e:
            logger.error(f"Neo4j service unavailable: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise

    def close(self) -> None:
        """Close connection to Neo4j database"""
        if self.driver:
            self.driver.close()
            self.connected = False
            logger.info("Closed Neo4j connection")

    def execute_query(
        self, query: str, parameters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute a Cypher query

        Args:
            query: Cypher query string
            parameters: Query parameters

        Returns:
            List of result records as dictionaries
        """
        if not self.connected:
            self.connect()

        with self.driver.session(database=self.database) as session:
            result = session.run(query, parameters or {})
            return [dict(record) for record in result]

    def execute_write(
        self, query: str, parameters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute a write transaction

        Args:
            query: Cypher query string
            parameters: Query parameters

        Returns:
            List of result records as dictionaries
        """
        if not self.connected:
            self.connect()

        def _transaction_function(tx):
            result = tx.run(query, parameters or {})
            return [dict(record) for record in result]

        with self.driver.session(database=self.database) as session:
            return session.execute_write(_transaction_function)

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


class WorldModelClient:
    """High-level client for MEDUSA World Model operations"""

    def __init__(self, neo4j_client: Optional[Neo4jClient] = None):
        """
        Initialize World Model client

        Args:
            neo4j_client: Neo4jClient instance (creates default if not provided)
        """
        self.client = neo4j_client or Neo4jClient()
        if not self.client.connected:
            self.client.connect()

    # ========================================================================
    # Domain Operations
    # ========================================================================

    def create_domain(self, domain: Domain) -> Dict[str, Any]:
        """Create or update a domain node"""
        query = """
        MERGE (d:Domain {name: $name})
        SET d.discovered_at = COALESCE(d.discovered_at, datetime($discovered_at)),
            d.scan_status = $scan_status
        RETURN d
        """
        params = {
            "name": domain.name,
            "discovered_at": domain.discovered_at.isoformat(),
            "scan_status": domain.scan_status,
        }
        result = self.client.execute_write(query, params)
        return result[0]["d"] if result else {}

    def get_domain(self, name: str) -> Optional[Dict[str, Any]]:
        """Get domain by name"""
        query = "MATCH (d:Domain {name: $name}) RETURN d"
        result = self.client.execute_query(query, {"name": name})
        return result[0]["d"] if result else None

    # ========================================================================
    # Subdomain Operations
    # ========================================================================

    def create_subdomain(
        self, subdomain: Subdomain, parent_domain: str
    ) -> Dict[str, Any]:
        """Create subdomain and link to parent domain"""
        query = """
        MATCH (d:Domain {name: $parent_domain})
        MERGE (s:Subdomain {name: $name})
        SET s.discovered_at = COALESCE(s.discovered_at, datetime($discovered_at))
        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
        RETURN s
        """
        params = {
            "name": subdomain.name,
            "parent_domain": parent_domain,
            "discovered_at": subdomain.discovered_at.isoformat(),
        }
        result = self.client.execute_write(query, params)
        return result[0]["s"] if result else {}

    def get_subdomains(self, domain: str) -> List[Dict[str, Any]]:
        """Get all subdomains for a domain"""
        query = """
        MATCH (d:Domain {name: $domain})-[:HAS_SUBDOMAIN]->(s:Subdomain)
        RETURN s
        """
        result = self.client.execute_query(query, {"domain": domain})
        return [r["s"] for r in result]

    # ========================================================================
    # Host Operations
    # ========================================================================

    def create_host(self, host: Host) -> Dict[str, Any]:
        """Create or update a host node"""
        query = """
        MERGE (h:Host {ip: $ip})
        SET h.hostname = $hostname,
            h.os_name = $os_name,
            h.os_accuracy = $os_accuracy,
            h.discovered_at = COALESCE(h.discovered_at, datetime($discovered_at)),
            h.last_seen = datetime($last_seen)
        RETURN h
        """
        params = {
            "ip": host.ip,
            "hostname": host.hostname,
            "os_name": host.os_name,
            "os_accuracy": host.os_accuracy,
            "discovered_at": host.discovered_at.isoformat(),
            "last_seen": host.last_seen.isoformat(),
        }
        result = self.client.execute_write(query, params)
        return result[0]["h"] if result else {}

    def link_subdomain_to_host(self, subdomain: str, host_ip: str) -> None:
        """Create RESOLVES_TO relationship between subdomain and host"""
        query = """
        MATCH (s:Subdomain {name: $subdomain})
        MATCH (h:Host {ip: $host_ip})
        MERGE (s)-[:RESOLVES_TO]->(h)
        """
        self.client.execute_write(
            query, {"subdomain": subdomain, "host_ip": host_ip}
        )

    def get_host(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get host by IP address"""
        query = "MATCH (h:Host {ip: $ip}) RETURN h"
        result = self.client.execute_query(query, {"ip": ip})
        return result[0]["h"] if result else None

    def get_all_hosts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all hosts"""
        query = "MATCH (h:Host) RETURN h LIMIT $limit"
        result = self.client.execute_query(query, {"limit": limit})
        return [r["h"] for r in result]

    # ========================================================================
    # Port Operations
    # ========================================================================

    def create_port(self, port: Port, host_ip: str) -> Dict[str, Any]:
        """Create port and link to host"""
        query = """
        MATCH (h:Host {ip: $host_ip})
        MERGE (p:Port {number: $number, protocol: $protocol, host_id: $host_id})
        SET p.state = $state,
            p.service = $service,
            p.product = $product,
            p.version = $version,
            p.service_string = $service_string,
            p.discovered_at = COALESCE(p.discovered_at, datetime($discovered_at))
        MERGE (h)-[:HAS_PORT]->(p)
        RETURN p
        """
        params = {
            "host_ip": host_ip,
            "number": port.number,
            "protocol": port.protocol,
            "host_id": port.host_id,
            "state": port.state,
            "service": port.service,
            "product": port.product,
            "version": port.version,
            "service_string": port.service_string,
            "discovered_at": port.discovered_at.isoformat(),
        }
        result = self.client.execute_write(query, params)
        return result[0]["p"] if result else {}

    def get_host_ports(self, host_ip: str) -> List[Dict[str, Any]]:
        """Get all ports for a host"""
        query = """
        MATCH (h:Host {ip: $host_ip})-[:HAS_PORT]->(p:Port)
        RETURN p
        ORDER BY p.number
        """
        result = self.client.execute_query(query, {"host_ip": host_ip})
        return [r["p"] for r in result]

    # ========================================================================
    # WebServer Operations
    # ========================================================================

    def create_webserver(self, webserver: WebServer, host_ip: str) -> Dict[str, Any]:
        """Create web server and link to host"""
        query = """
        MATCH (h:Host {ip: $host_ip})
        MERGE (w:WebServer {url: $url})
        SET w.status_code = $status_code,
            w.title = $title,
            w.web_server = $web_server,
            w.technologies = $technologies,
            w.ssl = $ssl,
            w.discovered_at = COALESCE(w.discovered_at, datetime($discovered_at)),
            w.last_checked = datetime($last_checked)
        MERGE (h)-[:RUNS_WEBAPP]->(w)
        RETURN w
        """
        params = {
            "host_ip": host_ip,
            "url": webserver.url,
            "status_code": webserver.status_code,
            "title": webserver.title,
            "web_server": webserver.web_server,
            "technologies": webserver.technologies,
            "ssl": webserver.ssl,
            "discovered_at": webserver.discovered_at.isoformat(),
            "last_checked": webserver.last_checked.isoformat(),
        }
        result = self.client.execute_write(query, params)
        return result[0]["w"] if result else {}

    def get_webservers(self, host_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get web servers, optionally filtered by host"""
        if host_ip:
            query = """
            MATCH (h:Host {ip: $host_ip})-[:RUNS_WEBAPP]->(w:WebServer)
            RETURN w
            """
            params = {"host_ip": host_ip}
        else:
            query = "MATCH (w:WebServer) RETURN w LIMIT 100"
            params = {}

        result = self.client.execute_query(query, params)
        return [r["w"] for r in result]

    # ========================================================================
    # User Operations
    # ========================================================================

    def create_user(self, user: User, host_ip: Optional[str] = None) -> Dict[str, Any]:
        """Create user, optionally linked to a host"""
        if host_ip:
            query = """
            MATCH (h:Host {ip: $host_ip})
            MERGE (u:User {username: $username, domain: $domain})
            SET u.name = $name,
                u.asrep_roastable = $asrep_roastable,
                u.discovered_at = COALESCE(u.discovered_at, datetime($discovered_at))
            MERGE (h)-[:HAS_USER]->(u)
            RETURN u
            """
            params = {"host_ip": host_ip}
        else:
            query = """
            MERGE (u:User {username: $username, domain: $domain})
            SET u.name = $name,
                u.asrep_roastable = $asrep_roastable,
                u.discovered_at = COALESCE(u.discovered_at, datetime($discovered_at))
            RETURN u
            """
            params = {}

        params.update(
            {
                "username": user.username,
                "domain": user.domain,
                "name": user.name,
                "asrep_roastable": user.asrep_roastable,
                "discovered_at": user.discovered_at.isoformat(),
            }
        )
        result = self.client.execute_write(query, params)
        return result[0]["u"] if result else {}

    def get_users(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get users, optionally filtered by domain"""
        if domain:
            query = "MATCH (u:User {domain: $domain}) RETURN u"
            params = {"domain": domain}
        else:
            query = "MATCH (u:User) RETURN u LIMIT 100"
            params = {}

        result = self.client.execute_query(query, params)
        return [r["u"] for r in result]

    # ========================================================================
    # Credential Operations
    # ========================================================================

    def create_credential(
        self, credential: Credential, username: str, domain: str
    ) -> Dict[str, Any]:
        """Create credential and link to user"""
        query = """
        MATCH (u:User {username: $username, domain: $domain})
        MERGE (c:Credential {id: $id})
        SET c.value = $value,
            c.type = $type,
            c.username = $cred_username,
            c.domain = $cred_domain,
            c.source = $source,
            c.discovered_at = COALESCE(c.discovered_at, datetime($discovered_at))
        MERGE (u)-[:OWNS_CREDENTIAL]->(c)
        RETURN c
        """
        params = {
            "username": username,
            "domain": domain,
            "id": credential.id,
            "value": credential.value,
            "type": credential.type,
            "cred_username": credential.username,
            "cred_domain": credential.domain,
            "source": credential.source,
            "discovered_at": credential.discovered_at.isoformat(),
        }
        result = self.client.execute_write(query, params)
        return result[0]["c"] if result else {}

    # ========================================================================
    # Vulnerability Operations
    # ========================================================================

    def create_vulnerability(
        self,
        vulnerability: Vulnerability,
        target_ip: Optional[str] = None,
        target_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create vulnerability and link to host or webserver"""
        if target_ip:
            query = """
            MATCH (h:Host {ip: $target_ip})
            MERGE (v:Vulnerability {id: $id})
            SET v.type = $type,
                v.parameter = $parameter,
                v.location = $location,
                v.dbms = $dbms,
                v.databases = $databases,
                v.tables = $tables,
                v.severity = $severity,
                v.exploited = $exploited,
                v.discovered_at = COALESCE(v.discovered_at, datetime($discovered_at))
            MERGE (h)-[:IS_VULNERABLE_TO]->(v)
            RETURN v
            """
            params = {"target_ip": target_ip}
        elif target_url:
            query = """
            MATCH (w:WebServer {url: $target_url})
            MERGE (v:Vulnerability {id: $id})
            SET v.type = $type,
                v.parameter = $parameter,
                v.location = $location,
                v.dbms = $dbms,
                v.databases = $databases,
                v.tables = $tables,
                v.severity = $severity,
                v.exploited = $exploited,
                v.discovered_at = COALESCE(v.discovered_at, datetime($discovered_at))
            MERGE (w)-[:IS_VULNERABLE_TO]->(v)
            RETURN v
            """
            params = {"target_url": target_url}
        else:
            raise ValueError("Either target_ip or target_url must be provided")

        params.update(
            {
                "id": vulnerability.id,
                "type": vulnerability.type,
                "parameter": vulnerability.parameter,
                "location": vulnerability.location,
                "dbms": vulnerability.dbms,
                "databases": vulnerability.databases,
                "tables": vulnerability.tables,
                "severity": vulnerability.severity,
                "exploited": vulnerability.exploited,
                "discovered_at": vulnerability.discovered_at.isoformat(),
            }
        )
        result = self.client.execute_write(query, params)
        return result[0]["v"] if result else {}

    def get_vulnerabilities(
        self, severity: Optional[str] = None, exploited: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """Get vulnerabilities with optional filters"""
        conditions = []
        params = {}

        if severity:
            conditions.append("v.severity = $severity")
            params["severity"] = severity

        if exploited is not None:
            conditions.append("v.exploited = $exploited")
            params["exploited"] = exploited

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        query = f"MATCH (v:Vulnerability) {where_clause} RETURN v LIMIT 100"

        result = self.client.execute_query(query, params)
        return [r["v"] for r in result]

    # ========================================================================
    # Advanced Query Operations
    # ========================================================================

    def get_attack_surface(self, domain: str) -> Dict[str, Any]:
        """Get complete attack surface for a domain"""
        query = """
        MATCH (d:Domain {name: $domain})
        OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
        OPTIONAL MATCH (s)-[:RESOLVES_TO]->(h:Host)
        OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
        OPTIONAL MATCH (h)-[:RUNS_WEBAPP]->(w:WebServer)
        OPTIONAL MATCH (h)-[:IS_VULNERABLE_TO]->(v:Vulnerability)
        RETURN d,
               collect(DISTINCT s) as subdomains,
               collect(DISTINCT h) as hosts,
               collect(DISTINCT p) as ports,
               collect(DISTINCT w) as webservers,
               collect(DISTINCT v) as vulnerabilities
        """
        result = self.client.execute_query(query, {"domain": domain})
        return result[0] if result else {}

    def find_attack_paths(
        self, start_domain: str, max_hops: int = 5
    ) -> List[Dict[str, Any]]:
        """Find potential attack paths from domain to vulnerabilities"""
        query = """
        MATCH path = (d:Domain {name: $domain})-[*1..$max_hops]-(v:Vulnerability)
        WHERE v.exploited = false
        RETURN path
        LIMIT 20
        """
        result = self.client.execute_query(
            query, {"domain": start_domain, "max_hops": max_hops}
        )
        return result

    def get_graph_statistics(self) -> Dict[str, int]:
        """Get statistics about the knowledge graph"""
        query = """
        MATCH (n)
        RETURN labels(n)[0] as label, count(n) as count
        ORDER BY count DESC
        """
        result = self.client.execute_query(query)
        stats = {r["label"]: r["count"] for r in result}

        # Add relationship counts
        rel_query = """
        MATCH ()-[r]->()
        RETURN type(r) as rel_type, count(r) as count
        """
        rel_result = self.client.execute_query(rel_query)
        stats["relationships"] = {r["rel_type"]: r["count"] for r in rel_result}

        return stats

    def close(self) -> None:
        """Close the Neo4j connection"""
        self.client.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
