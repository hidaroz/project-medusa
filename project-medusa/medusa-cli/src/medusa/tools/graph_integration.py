"""
Graph Database Integration for MEDUSA Tool Parsers

This module provides utilities for updating the Neo4j World Model graph
from tool findings. It's designed to be non-blocking and fail gracefully.
"""

import os
import logging
import requests
from typing import Dict, Any, Optional
from functools import wraps


logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================

class GraphConfig:
    """Configuration for graph API integration."""

    # Enable/disable graph updates
    ENABLED = os.getenv("GRAPH_UPDATES_ENABLED", "true").lower() == "true"

    # Graph API URL
    API_URL = os.getenv("GRAPH_API_URL", "http://localhost:5002")

    # API authentication
    API_KEY = os.getenv("GRAPH_API_KEY", "medusa-dev-key-change-in-production")

    # Request timeout (seconds)
    TIMEOUT = int(os.getenv("GRAPH_API_TIMEOUT", "5"))

    # Retry settings
    MAX_RETRIES = int(os.getenv("GRAPH_API_MAX_RETRIES", "1"))

    # Log all graph updates
    LOG_UPDATES = os.getenv("GRAPH_LOG_UPDATES", "true").lower() == "true"


# ============================================================================
# Cypher Query Templates
# ============================================================================

class CypherTemplates:
    """Cypher query templates for different tool types."""

    # Amass: Domain → Subdomain → Host relationships
    AMASS_SUBDOMAIN = """
    // Create or update Domain
    MERGE (d:Domain {name: $domain})
    ON CREATE SET d.discovered_at = datetime()

    // Create or update Subdomain
    MERGE (s:Subdomain {name: $subdomain})
    ON CREATE SET s.discovered_at = datetime()
    SET s.confidence = $confidence,
        s.sources = $sources,
        s.last_seen = datetime()

    // Create Domain → Subdomain relationship
    MERGE (d)-[r:HAS_SUBDOMAIN]->(s)
    ON CREATE SET r.created_at = datetime()
    SET r.last_seen = datetime()

    // Create Host nodes for IP addresses
    WITH s
    UNWIND $ip_addresses AS ip
    MERGE (h:Host {ip: ip})
    ON CREATE SET h.discovered_at = datetime()
    SET h.last_seen = datetime()

    // Create Subdomain → Host relationship
    MERGE (s)-[r2:RESOLVES_TO]->(h)
    ON CREATE SET r2.created_at = datetime()
    SET r2.last_seen = datetime()

    RETURN d, s, collect(h) as hosts
    """

    # httpx: WebServer nodes with properties
    HTTPX_WEBSERVER = """
    // Create or update WebServer
    MERGE (w:WebServer {url: $url})
    ON CREATE SET w.discovered_at = datetime()
    SET w.status_code = $status_code,
        w.status_text = $status_text,
        w.title = $title,
        w.web_server = $web_server,
        w.content_type = $content_type,
        w.content_length = $content_length,
        w.technologies = $technologies,
        w.ssl = $ssl,
        w.last_seen = datetime()

    // Extract hostname from URL and find/create Host
    WITH w, split(replace(replace($url, 'https://', ''), 'http://', ''), '/')[0] AS hostname
    WITH w, split(hostname, ':')[0] AS clean_hostname

    // Try to find host by hostname or create placeholder
    MERGE (h:Host {hostname: clean_hostname})
    ON CREATE SET h.discovered_at = datetime()
    SET h.last_seen = datetime()

    // Create Host → WebServer relationship
    MERGE (h)-[r:RUNS_WEBAPP]->(w)
    ON CREATE SET r.created_at = datetime()
    SET r.last_seen = datetime()

    RETURN w, h
    """

    # Nmap: Host → Port relationships with service details
    NMAP_PORT = """
    // Create or update Host
    MERGE (h:Host {ip: $host_ip})
    ON CREATE SET h.discovered_at = datetime()
    SET h.hostname = $hostname,
        h.last_seen = datetime()

    // Create or update Port
    MERGE (p:Port {host_ip: $host_ip, number: $port_number, protocol: $protocol})
    ON CREATE SET p.discovered_at = datetime()
    SET p.state = $state,
        p.service = $service,
        p.service_string = $service_string,
        p.product = $product,
        p.version = $version,
        p.extrainfo = $extrainfo,
        p.last_seen = datetime()

    // Create Host → Port relationship
    MERGE (h)-[r:HAS_PORT]->(p)
    ON CREATE SET r.created_at = datetime()
    SET r.last_seen = datetime()

    RETURN h, p
    """

    # Nmap: OS detection
    NMAP_OS = """
    // Update Host with OS information
    MERGE (h:Host {ip: $host_ip})
    ON CREATE SET h.discovered_at = datetime()
    SET h.os_name = $os_name,
        h.os_accuracy = $os_accuracy,
        h.hostname = $hostname,
        h.last_seen = datetime()

    RETURN h
    """

    # Kerbrute: Domain → User relationships
    KERBRUTE_USER = """
    // Create or update Domain
    MERGE (d:Domain {name: $domain})
    ON CREATE SET d.discovered_at = datetime()

    // Create or update User
    MERGE (u:User {username: $username, domain: $domain})
    ON CREATE SET u.discovered_at = datetime()
    SET u.valid = $valid,
        u.asrep_roastable = $asrep_roastable,
        u.requires_preauth = $requires_preauth,
        u.last_seen = datetime()

    // Create Domain → User relationship
    MERGE (d)-[r:HAS_USER]->(u)
    ON CREATE SET r.created_at = datetime()
    SET r.last_seen = datetime()

    RETURN d, u
    """

    # Kerbrute: User → Credential relationships
    KERBRUTE_CREDENTIAL = """
    // Create or update User
    MERGE (u:User {username: $username, domain: $domain})
    ON CREATE SET u.discovered_at = datetime()
    SET u.last_seen = datetime()

    // Create Credential
    CREATE (c:Credential {
        id: randomUUID(),
        value: $password,
        type: 'password',
        source: 'kerbrute',
        discovered_at: datetime()
    })

    // Create User → Credential relationship
    CREATE (u)-[r:OWNS_CREDENTIAL]->(c)
    SET r.created_at = datetime()

    RETURN u, c
    """

    # SQLMap: WebServer → Vulnerability relationships
    SQLMAP_VULNERABILITY = """
    // Find or create WebServer (using URL from metadata)
    MERGE (w:WebServer {url: $url})
    ON CREATE SET w.discovered_at = datetime()
    SET w.last_seen = datetime()

    // Create Vulnerability
    CREATE (v:Vulnerability {
        id: randomUUID(),
        type: 'sql_injection',
        parameter: $parameter,
        location: $location,
        injection_types: $injection_types,
        dbms: $dbms,
        databases: $databases,
        tables: $tables,
        severity: $severity,
        exploited: false,
        discovered_at: datetime()
    })

    // Create WebServer → Vulnerability relationship
    CREATE (w)-[r:IS_VULNERABLE_TO]->(v)
    SET r.created_at = datetime()

    RETURN w, v
    """


# ============================================================================
# Graph Update Functions
# ============================================================================

def update_graph(
    query: str,
    parameters: Dict[str, Any],
    tool_name: str = "unknown"
) -> bool:
    """
    Send a Cypher query to the Graph API to update the World Model.

    This function is designed to be non-blocking and fail gracefully.
    It will log errors but not raise exceptions that would break tool execution.

    Args:
        query: Cypher query template
        parameters: Query parameters
        tool_name: Name of the tool making the update (for logging)

    Returns:
        True if update succeeded, False otherwise
    """
    # Check if graph updates are enabled
    if not GraphConfig.ENABLED:
        logger.debug(f"[{tool_name}] Graph updates disabled, skipping")
        return False

    try:
        # Prepare request
        url = f"{GraphConfig.API_URL}/update"
        headers = {
            "X-API-Key": GraphConfig.API_KEY,
            "Content-Type": "application/json"
        }
        payload = {
            "query": query,
            "parameters": parameters
        }

        # Log update if enabled
        if GraphConfig.LOG_UPDATES:
            logger.info(f"[{tool_name}] Updating graph: {parameters.get('type', 'unknown')}")
            logger.debug(f"[{tool_name}] Parameters: {parameters}")

        # Send request with timeout
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=GraphConfig.TIMEOUT
        )

        # Check response
        if response.ok:
            logger.debug(f"[{tool_name}] Graph update successful")
            return True
        else:
            logger.warning(
                f"[{tool_name}] Graph update failed: {response.status_code} - {response.text}"
            )
            return False

    except requests.exceptions.Timeout:
        logger.warning(f"[{tool_name}] Graph update timeout after {GraphConfig.TIMEOUT}s")
        return False

    except requests.exceptions.ConnectionError:
        logger.warning(f"[{tool_name}] Graph API unavailable at {GraphConfig.API_URL}")
        return False

    except Exception as e:
        logger.error(f"[{tool_name}] Graph update error: {e}", exc_info=True)
        return False


def update_graph_with_retry(
    query: str,
    parameters: Dict[str, Any],
    tool_name: str = "unknown",
    max_retries: Optional[int] = None
) -> bool:
    """
    Update graph with retry logic.

    Args:
        query: Cypher query
        parameters: Query parameters
        tool_name: Tool name for logging
        max_retries: Maximum retry attempts (defaults to config)

    Returns:
        True if update succeeded, False otherwise
    """
    retries = max_retries or GraphConfig.MAX_RETRIES

    for attempt in range(retries + 1):
        if update_graph(query, parameters, tool_name):
            return True

        if attempt < retries:
            logger.debug(f"[{tool_name}] Retrying graph update ({attempt + 1}/{retries})")

    logger.warning(f"[{tool_name}] Graph update failed after {retries} retries")
    return False


def batch_update_graph(
    updates: list[tuple[str, Dict[str, Any]]],
    tool_name: str = "unknown"
) -> tuple[int, int]:
    """
    Perform batch updates to the graph.

    Args:
        updates: List of (query, parameters) tuples
        tool_name: Tool name for logging

    Returns:
        Tuple of (successful_count, failed_count)
    """
    if not GraphConfig.ENABLED:
        logger.debug(f"[{tool_name}] Graph updates disabled, skipping batch")
        return 0, len(updates)

    successful = 0
    failed = 0

    for query, parameters in updates:
        if update_graph(query, parameters, tool_name):
            successful += 1
        else:
            failed += 1

    logger.info(
        f"[{tool_name}] Batch update complete: {successful} succeeded, {failed} failed"
    )

    return successful, failed


# ============================================================================
# Decorator for automatic graph updates
# ============================================================================

def with_graph_update(query_template: str, param_mapper: callable):
    """
    Decorator to automatically update graph after tool execution.

    Args:
        query_template: Cypher query template
        param_mapper: Function to map finding dict to query parameters

    Example:
        @with_graph_update(
            CypherTemplates.AMASS_SUBDOMAIN,
            lambda f: {"domain": f["domain"], "subdomain": f["subdomain"], ...}
        )
        def parse_output(self, stdout, stderr):
            # ... parsing logic ...
            return findings
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Execute original function
            result = func(*args, **kwargs)

            # Update graph if result contains findings
            if isinstance(result, list):
                findings = result
            elif isinstance(result, dict) and "findings" in result:
                findings = result["findings"]
            else:
                return result

            # Get tool name from class if available
            tool_name = "unknown"
            if args and hasattr(args[0], "tool_name"):
                tool_name = args[0].tool_name

            # Update graph for each finding
            for finding in findings:
                try:
                    parameters = param_mapper(finding)
                    update_graph(query_template, parameters, tool_name)
                except Exception as e:
                    logger.error(f"[{tool_name}] Failed to map finding to parameters: {e}")

            return result
        return wrapper
    return decorator


# ============================================================================
# Utility Functions
# ============================================================================

def check_graph_api_health() -> bool:
    """
    Check if the Graph API is available and healthy.

    Returns:
        True if API is healthy, False otherwise
    """
    if not GraphConfig.ENABLED:
        return False

    try:
        url = f"{GraphConfig.API_URL}/health"
        response = requests.get(url, timeout=GraphConfig.TIMEOUT)
        return response.ok
    except Exception:
        return False


def get_graph_api_status() -> Dict[str, Any]:
    """
    Get detailed status of Graph API connection.

    Returns:
        Dictionary with status information
    """
    status = {
        "enabled": GraphConfig.ENABLED,
        "api_url": GraphConfig.API_URL,
        "healthy": False,
        "error": None
    }

    if not GraphConfig.ENABLED:
        status["error"] = "Graph updates disabled"
        return status

    try:
        url = f"{GraphConfig.API_URL}/health"
        response = requests.get(url, timeout=GraphConfig.TIMEOUT)

        if response.ok:
            status["healthy"] = True
            status["details"] = response.json()
        else:
            status["error"] = f"HTTP {response.status_code}: {response.text}"

    except requests.exceptions.Timeout:
        status["error"] = f"Timeout after {GraphConfig.TIMEOUT}s"
    except requests.exceptions.ConnectionError:
        status["error"] = "Connection refused"
    except Exception as e:
        status["error"] = str(e)

    return status
