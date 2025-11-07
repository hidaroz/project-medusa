"""
MEDUSA Graph API Service
A Flask-based REST API for secure access to the Neo4j World Model graph database.

This service provides:
- Natural language query translation to Cypher
- Secure parameterized query execution
- Rate limiting and authentication
- Comprehensive error handling
"""

import os
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Any, Optional
from collections import defaultdict

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from pydantic import BaseModel, Field, ValidationError
from neo4j.exceptions import CypherSyntaxError, ServiceUnavailable

from medusa.world_model.client import WorldModelClient, Neo4jClient
from medusa.world_model.models import Host, Domain, User, Vulnerability


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================

class APIConfig:
    """API Configuration from environment variables."""

    # Neo4j Configuration
    NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "medusa_graph_pass")
    NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

    # API Configuration
    API_PORT = int(os.getenv("GRAPH_API_PORT", "5002"))
    API_HOST = os.getenv("GRAPH_API_HOST", "0.0.0.0")

    # Security Configuration
    API_KEY = os.getenv("GRAPH_API_KEY", "medusa-dev-key-change-in-production")
    ENABLE_AUTH = os.getenv("GRAPH_API_ENABLE_AUTH", "true").lower() == "true"

    # Rate Limiting Configuration
    RATE_LIMIT_REQUESTS = int(os.getenv("GRAPH_API_RATE_LIMIT", "100"))
    RATE_LIMIT_WINDOW = int(os.getenv("GRAPH_API_RATE_WINDOW", "60"))  # seconds

    # Query Safety Configuration
    MAX_QUERY_LENGTH = int(os.getenv("GRAPH_API_MAX_QUERY_LENGTH", "10000"))
    QUERY_TIMEOUT = int(os.getenv("GRAPH_API_QUERY_TIMEOUT", "30"))  # seconds

    # Environment
    DEBUG = os.getenv("APP_DEBUG", "false").lower() == "true"
    FLASK_ENV = os.getenv("FLASK_ENV", "production")


# ============================================================================
# Pydantic Request/Response Models
# ============================================================================

class UpdateRequest(BaseModel):
    """Request model for /update endpoint."""
    query: str = Field(..., min_length=1, max_length=APIConfig.MAX_QUERY_LENGTH)
    parameters: Dict[str, Any] = Field(default_factory=dict)


class UpdateResponse(BaseModel):
    """Response model for /update endpoint."""
    success: bool
    records_affected: int = 0
    error: Optional[str] = None
    execution_time_ms: Optional[float] = None


class QueryRequest(BaseModel):
    """Request model for /query endpoint."""
    question: str = Field(..., min_length=1, max_length=500)
    limit: Optional[int] = Field(default=100, ge=1, le=1000)


class QueryResponse(BaseModel):
    """Response model for /query endpoint."""
    success: bool
    data: List[Dict[str, Any]] = Field(default_factory=list)
    cypher_used: Optional[str] = None
    error: Optional[str] = None
    execution_time_ms: Optional[float] = None
    record_count: int = 0


class HealthResponse(BaseModel):
    """Response model for /health endpoint."""
    status: str
    timestamp: str
    database_connected: bool
    version: str = "1.0.0"
    uptime_seconds: Optional[float] = None


# ============================================================================
# Query Translator
# ============================================================================

class QueryTranslator:
    """
    Translates natural language questions into Cypher queries.
    Uses pattern matching for common reconnaissance queries.
    """

    # Pattern definitions for natural language queries
    PATTERNS = {
        # Vulnerability queries
        "vulnerable web servers": {
            "cypher": """
                MATCH (w:WebServer)-[:IS_VULNERABLE_TO]->(v:Vulnerability)
                WHERE v.exploited = false
                RETURN w.url as url, w.status_code as status,
                       collect({
                           type: v.type,
                           severity: v.severity,
                           id: v.id
                       }) as vulnerabilities
                ORDER BY w.url
                LIMIT $limit
            """,
            "description": "Find web servers with known vulnerabilities"
        },

        "vulnerable hosts": {
            "cypher": """
                MATCH (h:Host)-[:IS_VULNERABLE_TO]->(v:Vulnerability)
                WHERE v.exploited = false
                RETURN h.ip as ip, h.hostname as hostname, h.os_name as os,
                       collect({
                           type: v.type,
                           severity: v.severity,
                           id: v.id
                       }) as vulnerabilities
                ORDER BY h.ip
                LIMIT $limit
            """,
            "description": "Find hosts with known vulnerabilities"
        },

        "high severity vulnerabilities": {
            "cypher": """
                MATCH (v:Vulnerability)
                WHERE v.severity IN ['high', 'critical'] AND v.exploited = false
                OPTIONAL MATCH (h:Host)-[:IS_VULNERABLE_TO]->(v)
                OPTIONAL MATCH (w:WebServer)-[:IS_VULNERABLE_TO]->(v)
                RETURN v.id as id, v.type as type, v.severity as severity,
                       COALESCE(h.ip, w.url) as target,
                       v.description as description
                ORDER BY v.severity DESC
                LIMIT $limit
            """,
            "description": "Find high and critical severity vulnerabilities"
        },

        # User and credential queries
        "users with credentials": {
            "cypher": """
                MATCH (u:User)-[:OWNS_CREDENTIAL]->(c:Credential)
                RETURN u.username as username, u.domain as domain,
                       collect({
                           type: c.type,
                           value: c.value,
                           source: c.source
                       }) as credentials
                ORDER BY u.username
                LIMIT $limit
            """,
            "description": "Find users with associated credentials"
        },

        "roastable users": {
            "cypher": """
                MATCH (u:User)
                WHERE u.asrep_roastable = true OR u.kerberoastable = true
                RETURN u.username as username, u.domain as domain,
                       u.asrep_roastable as asrep_roastable,
                       u.kerberoastable as kerberoastable,
                       u.description as description
                ORDER BY u.username
                LIMIT $limit
            """,
            "description": "Find users vulnerable to AS-REP or Kerberoasting attacks"
        },

        "all users": {
            "cypher": """
                MATCH (u:User)
                OPTIONAL MATCH (u)-[:OWNS_CREDENTIAL]->(c:Credential)
                RETURN u.username as username, u.domain as domain,
                       u.asrep_roastable as asrep_roastable,
                       u.kerberoastable as kerberoastable,
                       count(c) as credential_count
                ORDER BY u.username
                LIMIT $limit
            """,
            "description": "List all users in the database"
        },

        # Network reconnaissance queries
        "all hosts": {
            "cypher": """
                MATCH (h:Host)
                OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port)
                RETURN h.ip as ip, h.hostname as hostname, h.os_name as os,
                       count(DISTINCT p) as open_ports,
                       h.last_seen as last_seen
                ORDER BY h.ip
                LIMIT $limit
            """,
            "description": "List all discovered hosts"
        },

        "open ports": {
            "cypher": """
                MATCH (h:Host)-[:HAS_PORT]->(p:Port)
                WHERE p.state = 'open'
                RETURN h.ip as host_ip, h.hostname as hostname,
                       collect({
                           number: p.number,
                           protocol: p.protocol,
                           service: p.service,
                           version: p.version
                       }) as ports
                ORDER BY h.ip
                LIMIT $limit
            """,
            "description": "List all open ports across hosts"
        },

        "web servers": {
            "cypher": """
                MATCH (h:Host)-[:RUNS_WEBAPP]->(w:WebServer)
                RETURN h.ip as host_ip, w.url as url,
                       w.status_code as status, w.title as title,
                       w.server as server, w.technologies as technologies
                ORDER BY w.url
                LIMIT $limit
            """,
            "description": "List all discovered web servers"
        },

        # Domain queries
        "domains": {
            "cypher": """
                MATCH (d:Domain)
                OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                RETURN d.name as domain, d.scan_status as status,
                       count(s) as subdomain_count,
                       d.discovered_at as discovered_at
                ORDER BY d.name
                LIMIT $limit
            """,
            "description": "List all domains with subdomain counts"
        },

        "subdomains": {
            "cypher": """
                MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                OPTIONAL MATCH (s)-[:RESOLVES_TO]->(h:Host)
                RETURN d.name as domain, s.name as subdomain,
                       h.ip as resolved_ip, s.discovered_at as discovered_at
                ORDER BY d.name, s.name
                LIMIT $limit
            """,
            "description": "List all subdomains with DNS resolution"
        },

        # Attack path queries
        "attack paths": {
            "cypher": """
                MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(h:Host)
                OPTIONAL MATCH (h)-[:IS_VULNERABLE_TO]->(v:Vulnerability)
                WHERE v.exploited = false AND v.severity IN ['high', 'critical']
                OPTIONAL MATCH (h)-[:HAS_USER]->(u:User)
                WHERE u.asrep_roastable = true OR u.kerberoastable = true
                WITH d, s, h, collect(DISTINCT v) as vulns, collect(DISTINCT u) as users
                WHERE size(vulns) > 0 OR size(users) > 0
                RETURN d.name as domain, s.name as subdomain, h.ip as host,
                       vulns, users
                ORDER BY size(vulns) DESC, size(users) DESC
                LIMIT $limit
            """,
            "description": "Find potential attack paths from domains to vulnerable assets"
        },

        "attack surface": {
            "cypher": """
                MATCH (d:Domain)
                OPTIONAL MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain)
                OPTIONAL MATCH (s)-[:RESOLVES_TO]->(h:Host)
                OPTIONAL MATCH (h)-[:HAS_PORT]->(p:Port) WHERE p.state = 'open'
                OPTIONAL MATCH (h)-[:RUNS_WEBAPP]->(w:WebServer)
                OPTIONAL MATCH (h)-[:IS_VULNERABLE_TO]->(v:Vulnerability)
                WITH d,
                     count(DISTINCT s) as subdomains,
                     count(DISTINCT h) as hosts,
                     count(DISTINCT p) as open_ports,
                     count(DISTINCT w) as web_servers,
                     count(DISTINCT v) as vulnerabilities
                RETURN d.name as domain, subdomains, hosts, open_ports,
                       web_servers, vulnerabilities
                ORDER BY vulnerabilities DESC, hosts DESC
                LIMIT $limit
            """,
            "description": "Get comprehensive attack surface metrics for all domains"
        },

        # Statistics queries
        "statistics": {
            "cypher": """
                MATCH (d:Domain) WITH count(d) as domains
                MATCH (h:Host) WITH domains, count(h) as hosts
                MATCH (u:User) WITH domains, hosts, count(u) as users
                MATCH (v:Vulnerability) WITH domains, hosts, users, count(v) as vulnerabilities
                MATCH (w:WebServer) WITH domains, hosts, users, vulnerabilities, count(w) as web_servers
                RETURN domains, hosts, users, vulnerabilities, web_servers
            """,
            "description": "Get overall statistics of the graph database"
        }
    }

    @classmethod
    def translate(cls, question: str, limit: int = 100) -> tuple[Optional[str], Optional[str]]:
        """
        Translate a natural language question into a Cypher query.

        Args:
            question: Natural language question
            limit: Maximum number of results to return

        Returns:
            Tuple of (cypher_query, description) or (None, None) if no match
        """
        question_lower = question.lower().strip()

        # Direct pattern matching
        for pattern, config in cls.PATTERNS.items():
            if pattern in question_lower:
                logger.info(f"Matched pattern: {pattern}")
                return config["cypher"], config["description"]

        # Fuzzy matching for common variations
        fuzzy_matches = {
            "vuln": "vulnerable hosts",
            "cred": "users with credentials",
            "password": "users with credentials",
            "asrep": "roastable users",
            "kerberos": "roastable users",
            "port": "open ports",
            "service": "open ports",
            "webapp": "web servers",
            "http": "web servers",
            "domain": "domains",
            "sub": "subdomains",
            "path": "attack paths",
            "surface": "attack surface",
            "stat": "statistics",
            "count": "statistics",
        }

        for keyword, pattern in fuzzy_matches.items():
            if keyword in question_lower:
                if pattern in cls.PATTERNS:
                    logger.info(f"Fuzzy matched keyword '{keyword}' to pattern: {pattern}")
                    return cls.PATTERNS[pattern]["cypher"], cls.PATTERNS[pattern]["description"]

        logger.warning(f"No pattern match found for question: {question}")
        return None, None

    @classmethod
    def list_available_patterns(cls) -> Dict[str, str]:
        """Return all available query patterns with descriptions."""
        return {pattern: config["description"] for pattern, config in cls.PATTERNS.items()}


# ============================================================================
# Query Safety Validator
# ============================================================================

class QueryValidator:
    """Validates Cypher queries for safety before execution."""

    # Dangerous Cypher keywords that should be restricted
    DANGEROUS_KEYWORDS = [
        "DELETE", "DETACH DELETE",
        "REMOVE",
        "DROP",
        "CREATE CONSTRAINT",
        "DROP CONSTRAINT",
        "CREATE INDEX",
        "DROP INDEX",
    ]

    # Allowed write operations
    ALLOWED_WRITE_KEYWORDS = [
        "CREATE",
        "MERGE",
        "SET",
    ]

    @classmethod
    def is_safe(cls, query: str) -> tuple[bool, Optional[str]]:
        """
        Check if a Cypher query is safe to execute.

        Args:
            query: Cypher query string

        Returns:
            Tuple of (is_safe, error_message)
        """
        query_upper = query.upper()

        # Check for dangerous operations
        for keyword in cls.DANGEROUS_KEYWORDS:
            if keyword in query_upper:
                return False, f"Dangerous operation detected: {keyword}"

        # Check query length
        if len(query) > APIConfig.MAX_QUERY_LENGTH:
            return False, f"Query exceeds maximum length of {APIConfig.MAX_QUERY_LENGTH} characters"

        # Check for multiple statements (prevent injection)
        if query.count(";") > 1:
            return False, "Multiple statements not allowed"

        return True, None

    @classmethod
    def validate_write_query(cls, query: str) -> tuple[bool, Optional[str]]:
        """
        Validate that a write query only contains allowed operations.

        Args:
            query: Cypher query string

        Returns:
            Tuple of (is_valid, error_message)
        """
        # First check basic safety
        is_safe, error = cls.is_safe(query)
        if not is_safe:
            return False, error

        query_upper = query.upper()

        # Must contain at least one write operation
        has_write = any(keyword in query_upper for keyword in cls.ALLOWED_WRITE_KEYWORDS)
        if not has_write:
            return False, "Query must contain a write operation (CREATE, MERGE, or SET)"

        return True, None


# ============================================================================
# Rate Limiting
# ============================================================================

class RateLimiter:
    """Simple in-memory rate limiter based on IP address."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def is_allowed(self, identifier: str) -> tuple[bool, Optional[str]]:
        """
        Check if a request is allowed based on rate limits.

        Args:
            identifier: Unique identifier (e.g., IP address or API key)

        Returns:
            Tuple of (is_allowed, error_message)
        """
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)

        # Clean up old requests
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if req_time > cutoff
        ]

        # Check if limit exceeded
        if len(self.requests[identifier]) >= self.max_requests:
            return False, f"Rate limit exceeded: {self.max_requests} requests per {self.window_seconds} seconds"

        # Record this request
        self.requests[identifier].append(now)
        return True, None

    def get_stats(self, identifier: str) -> Dict[str, Any]:
        """Get current rate limit statistics for an identifier."""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.window_seconds)

        recent_requests = [
            req_time for req_time in self.requests[identifier]
            if req_time > cutoff
        ]

        return {
            "requests_in_window": len(recent_requests),
            "max_requests": self.max_requests,
            "window_seconds": self.window_seconds,
            "remaining": max(0, self.max_requests - len(recent_requests))
        }


# ============================================================================
# Flask Application Factory
# ============================================================================

def create_app(config: APIConfig = APIConfig) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        config: API configuration object

    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    app.config.from_object(config)

    # Enable CORS for frontend access
    CORS(app, resources={r"/*": {"origins": "*"}})

    # Initialize rate limiter
    rate_limiter = RateLimiter(
        max_requests=config.RATE_LIMIT_REQUESTS,
        window_seconds=config.RATE_LIMIT_WINDOW
    )

    # Store start time for uptime calculation
    app.start_time = datetime.now()

    # ========================================================================
    # Middleware and Decorators
    # ========================================================================

    def require_auth(f):
        """Decorator to require API key authentication."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not config.ENABLE_AUTH:
                return f(*args, **kwargs)

            api_key = request.headers.get('X-API-Key')
            if not api_key or api_key != config.API_KEY:
                logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
                return jsonify({
                    "success": False,
                    "error": "Invalid or missing API key"
                }), 401

            return f(*args, **kwargs)
        return decorated_function

    def check_rate_limit(f):
        """Decorator to check rate limits."""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            identifier = request.remote_addr
            allowed, error = rate_limiter.is_allowed(identifier)

            if not allowed:
                logger.warning(f"Rate limit exceeded for {identifier}")
                return jsonify({
                    "success": False,
                    "error": error
                }), 429

            # Add rate limit stats to response headers
            stats = rate_limiter.get_stats(identifier)
            g.rate_limit_stats = stats

            return f(*args, **kwargs)
        return decorated_function

    @app.before_request
    def log_request():
        """Log incoming requests."""
        logger.info(f"{request.method} {request.path} from {request.remote_addr}")

    @app.after_request
    def add_headers(response):
        """Add custom headers to responses."""
        response.headers['X-API-Version'] = '1.0.0'

        # Add rate limit headers if available
        if hasattr(g, 'rate_limit_stats'):
            stats = g.rate_limit_stats
            response.headers['X-RateLimit-Limit'] = str(stats['max_requests'])
            response.headers['X-RateLimit-Remaining'] = str(stats['remaining'])
            response.headers['X-RateLimit-Window'] = str(stats['window_seconds'])

        return response

    # ========================================================================
    # Error Handlers
    # ========================================================================

    @app.errorhandler(ValidationError)
    def handle_validation_error(error):
        """Handle Pydantic validation errors."""
        logger.error(f"Validation error: {error}")
        return jsonify({
            "success": False,
            "error": "Invalid request data",
            "details": error.errors()
        }), 400

    @app.errorhandler(Exception)
    def handle_generic_error(error):
        """Handle unexpected errors."""
        logger.error(f"Unexpected error: {error}", exc_info=True)
        return jsonify({
            "success": False,
            "error": "Internal server error"
        }), 500

    # ========================================================================
    # API Endpoints
    # ========================================================================

    @app.route('/health', methods=['GET'])
    def health_check():
        """
        Health check endpoint.

        Returns:
            JSON response with service health status
        """
        try:
            # Try to connect to Neo4j
            with Neo4jClient(
                uri=config.NEO4J_URI,
                username=config.NEO4J_USERNAME,
                password=config.NEO4J_PASSWORD,
                database=config.NEO4J_DATABASE
            ) as client:
                # Simple query to verify connection
                result = client.execute_query("RETURN 1 as test")
                database_connected = bool(result)
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            database_connected = False

        uptime = (datetime.now() - app.start_time).total_seconds()

        response = HealthResponse(
            status="healthy" if database_connected else "degraded",
            timestamp=datetime.now().isoformat(),
            database_connected=database_connected,
            uptime_seconds=uptime
        )

        status_code = 200 if database_connected else 503
        return jsonify(response.model_dump()), status_code

    @app.route('/update', methods=['POST'])
    @require_auth
    @check_rate_limit
    def update_graph():
        """
        Execute a write query against the graph database.

        Request body:
            {
                "query": "<cypher>",
                "parameters": {<params>}
            }

        Returns:
            JSON response with execution results
        """
        start_time = datetime.now()

        try:
            # Validate request body
            data = request.get_json()
            if not data:
                return jsonify({
                    "success": False,
                    "error": "Request body must be JSON"
                }), 400

            req = UpdateRequest(**data)

            # Validate query safety
            is_valid, error = QueryValidator.validate_write_query(req.query)
            if not is_valid:
                logger.warning(f"Unsafe query rejected: {error}")
                return jsonify({
                    "success": False,
                    "error": f"Query validation failed: {error}"
                }), 400

            # Execute query
            with Neo4jClient(
                uri=config.NEO4J_URI,
                username=config.NEO4J_USERNAME,
                password=config.NEO4J_PASSWORD,
                database=config.NEO4J_DATABASE
            ) as client:
                result = client.execute_write(req.query, req.parameters)
                records_affected = len(result) if result else 0

            execution_time = (datetime.now() - start_time).total_seconds() * 1000

            response = UpdateResponse(
                success=True,
                records_affected=records_affected,
                execution_time_ms=execution_time
            )

            logger.info(f"Update query executed successfully: {records_affected} records affected")
            return jsonify(response.model_dump()), 200

        except CypherSyntaxError as e:
            logger.error(f"Cypher syntax error: {e}")
            return jsonify({
                "success": False,
                "error": f"Invalid Cypher syntax: {str(e)}"
            }), 400

        except ServiceUnavailable as e:
            logger.error(f"Database unavailable: {e}")
            return jsonify({
                "success": False,
                "error": "Database service unavailable"
            }), 503

        except Exception as e:
            logger.error(f"Update query failed: {e}", exc_info=True)
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500

    @app.route('/query', methods=['POST'])
    @require_auth
    @check_rate_limit
    def query_graph():
        """
        Execute a natural language query against the graph database.

        Request body:
            {
                "question": "<natural_language>",
                "limit": 100  // optional
            }

        Returns:
            JSON response with query results
        """
        start_time = datetime.now()

        try:
            # Validate request body
            data = request.get_json()
            if not data:
                return jsonify({
                    "success": False,
                    "error": "Request body must be JSON"
                }), 400

            req = QueryRequest(**data)

            # Translate natural language to Cypher
            cypher, description = QueryTranslator.translate(req.question, req.limit)

            if not cypher:
                # Return helpful message with available patterns
                patterns = QueryTranslator.list_available_patterns()
                return jsonify({
                    "success": False,
                    "error": "Could not translate question to query",
                    "available_patterns": patterns
                }), 400

            logger.info(f"Translated question to: {description}")

            # Execute query
            with Neo4jClient(
                uri=config.NEO4J_URI,
                username=config.NEO4J_USERNAME,
                password=config.NEO4J_PASSWORD,
                database=config.NEO4J_DATABASE
            ) as client:
                result = client.execute_query(cypher, {"limit": req.limit})

                # Convert result to list of dicts
                data_list = [dict(record) for record in result] if result else []

            execution_time = (datetime.now() - start_time).total_seconds() * 1000

            response = QueryResponse(
                success=True,
                data=data_list,
                cypher_used=cypher.strip(),
                record_count=len(data_list),
                execution_time_ms=execution_time
            )

            logger.info(f"Query executed successfully: {len(data_list)} records returned")
            return jsonify(response.model_dump()), 200

        except ServiceUnavailable as e:
            logger.error(f"Database unavailable: {e}")
            return jsonify({
                "success": False,
                "error": "Database service unavailable"
            }), 503

        except Exception as e:
            logger.error(f"Query failed: {e}", exc_info=True)
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500

    @app.route('/patterns', methods=['GET'])
    @require_auth
    def list_patterns():
        """
        List all available query patterns.

        Returns:
            JSON response with pattern descriptions
        """
        patterns = QueryTranslator.list_available_patterns()
        return jsonify({
            "success": True,
            "patterns": patterns,
            "count": len(patterns)
        }), 200

    @app.route('/direct-query', methods=['POST'])
    @require_auth
    @check_rate_limit
    def direct_query():
        """
        Execute a direct Cypher query (read-only).

        Request body:
            {
                "query": "<cypher>",
                "parameters": {<params>}
            }

        Returns:
            JSON response with query results
        """
        start_time = datetime.now()

        try:
            # Validate request body
            data = request.get_json()
            if not data:
                return jsonify({
                    "success": False,
                    "error": "Request body must be JSON"
                }), 400

            query = data.get("query")
            parameters = data.get("parameters", {})

            if not query:
                return jsonify({
                    "success": False,
                    "error": "Query is required"
                }), 400

            # Validate query safety (read-only check)
            is_safe, error = QueryValidator.is_safe(query)
            if not is_safe:
                logger.warning(f"Unsafe query rejected: {error}")
                return jsonify({
                    "success": False,
                    "error": f"Query validation failed: {error}"
                }), 400

            # Execute query
            with Neo4jClient(
                uri=config.NEO4J_URI,
                username=config.NEO4J_USERNAME,
                password=config.NEO4J_PASSWORD,
                database=config.NEO4J_DATABASE
            ) as client:
                result = client.execute_query(query, parameters)

                # Convert result to list of dicts
                data_list = [dict(record) for record in result] if result else []

            execution_time = (datetime.now() - start_time).total_seconds() * 1000

            response = QueryResponse(
                success=True,
                data=data_list,
                cypher_used=query.strip(),
                record_count=len(data_list),
                execution_time_ms=execution_time
            )

            logger.info(f"Direct query executed successfully: {len(data_list)} records returned")
            return jsonify(response.model_dump()), 200

        except CypherSyntaxError as e:
            logger.error(f"Cypher syntax error: {e}")
            return jsonify({
                "success": False,
                "error": f"Invalid Cypher syntax: {str(e)}"
            }), 400

        except ServiceUnavailable as e:
            logger.error(f"Database unavailable: {e}")
            return jsonify({
                "success": False,
                "error": "Database service unavailable"
            }), 503

        except Exception as e:
            logger.error(f"Direct query failed: {e}", exc_info=True)
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500

    return app


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point for running the API server."""
    app = create_app()

    logger.info("=" * 60)
    logger.info("MEDUSA Graph API Service Starting")
    logger.info("=" * 60)
    logger.info(f"Neo4j URI: {APIConfig.NEO4J_URI}")
    logger.info(f"API Port: {APIConfig.API_PORT}")
    logger.info(f"Authentication: {'Enabled' if APIConfig.ENABLE_AUTH else 'Disabled'}")
    logger.info(f"Rate Limit: {APIConfig.RATE_LIMIT_REQUESTS} requests per {APIConfig.RATE_LIMIT_WINDOW}s")
    logger.info("=" * 60)

    app.run(
        host=APIConfig.API_HOST,
        port=APIConfig.API_PORT,
        debug=APIConfig.DEBUG
    )


if __name__ == "__main__":
    main()
