"""
MEDUSA Neo4j Configuration
Python configuration module for Neo4j database connection
"""

import os
from typing import Dict, Any

# ============================================================================
# Environment Variables
# ============================================================================
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "medusa_graph_pass")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

# Docker internal URI (when connecting from another container)
NEO4J_DOCKER_URI = os.getenv("NEO4J_DOCKER_URI", "bolt://medusa-neo4j:7687")

# ============================================================================
# Connection Configuration
# ============================================================================
NEO4J_CONFIG: Dict[str, Any] = {
    "uri": NEO4J_URI,
    "auth": (NEO4J_USERNAME, NEO4J_PASSWORD),
    "database": NEO4J_DATABASE,
    "max_connection_lifetime": 3600,
    "max_connection_pool_size": 50,
    "connection_acquisition_timeout": 60,
    "encrypted": False,
    "trust": "TRUST_ALL_CERTIFICATES",
}

# Docker configuration (use this when running inside Docker)
NEO4J_DOCKER_CONFIG: Dict[str, Any] = {
    **NEO4J_CONFIG,
    "uri": NEO4J_DOCKER_URI,
}

# ============================================================================
# Schema Paths
# ============================================================================
SCHEMA_DIR = os.path.dirname(os.path.abspath(__file__))
INIT_SCHEMA_PATH = os.path.join(SCHEMA_DIR, "init-schema.cypher")
SAMPLE_DATA_PATH = os.path.join(SCHEMA_DIR, "sample-data.cypher")

# ============================================================================
# Application Settings
# ============================================================================
APP_CONFIG: Dict[str, Any] = {
    "log_level": os.getenv("NEO4J_LOG_LEVEL", "INFO"),
    "log_queries": os.getenv("NEO4J_LOG_QUERIES", "false").lower() == "true",
    "cache_results": True,
    "cache_ttl": 300,
    "default_query_limit": 100,
    "max_query_limit": 1000,
    "query_timeout": 30000,  # milliseconds
    "auto_initialize": True,
    "verify_schema": True,
}

# ============================================================================
# Helper Functions
# ============================================================================


def get_connection_config(use_docker: bool = False) -> Dict[str, Any]:
    """
    Get Neo4j connection configuration.

    Args:
        use_docker: Whether to use Docker internal URI

    Returns:
        Connection configuration dictionary
    """
    return NEO4J_DOCKER_CONFIG if use_docker else NEO4J_CONFIG


def get_connection_uri(use_docker: bool = False) -> str:
    """
    Get Neo4j connection URI.

    Args:
        use_docker: Whether to use Docker internal URI

    Returns:
        Connection URI string
    """
    return NEO4J_DOCKER_URI if use_docker else NEO4J_URI


def is_docker_environment() -> bool:
    """
    Detect if running inside Docker container.

    Returns:
        True if running in Docker, False otherwise
    """
    return (
        os.path.exists("/.dockerenv")
        or os.getenv("DOCKER_CONTAINER") == "true"
        or os.getenv("RUNNING_IN_DOCKER") == "true"
    )


def get_auto_config() -> Dict[str, Any]:
    """
    Automatically detect environment and return appropriate configuration.

    Returns:
        Connection configuration dictionary
    """
    return get_connection_config(use_docker=is_docker_environment())


# ============================================================================
# Neo4j Browser URLs
# ============================================================================
NEO4J_BROWSER_URL = "http://localhost:7474"
NEO4J_BROWSER_URL_DOCKER = "http://medusa-neo4j:7474"
