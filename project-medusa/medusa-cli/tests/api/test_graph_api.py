"""
Unit tests for the Graph API Service.

Tests cover:
- Query translator pattern matching
- Query validator safety checks
- Rate limiter functionality
- API endpoints
- Authentication
- Error handling
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from medusa.api.graph_api import (
    QueryTranslator,
    QueryValidator,
    RateLimiter,
    create_app,
    APIConfig,
)


# ============================================================================
# Query Translator Tests
# ============================================================================

class TestQueryTranslator:
    """Tests for the QueryTranslator class."""

    def test_direct_pattern_match(self):
        """Test direct pattern matching for known queries."""
        cypher, description = QueryTranslator.translate("vulnerable web servers")

        assert cypher is not None
        assert "WebServer" in cypher
        assert "IS_VULNERABLE_TO" in cypher
        assert "Vulnerability" in cypher
        assert description == "Find web servers with known vulnerabilities"

    def test_case_insensitive_matching(self):
        """Test that pattern matching is case-insensitive."""
        cypher1, _ = QueryTranslator.translate("VULNERABLE WEB SERVERS")
        cypher2, _ = QueryTranslator.translate("vulnerable web servers")

        assert cypher1 == cypher2

    def test_whitespace_handling(self):
        """Test that extra whitespace doesn't break matching."""
        cypher, description = QueryTranslator.translate("  vulnerable web servers  ")

        assert cypher is not None
        assert description is not None

    def test_fuzzy_matching_vuln(self):
        """Test fuzzy matching for 'vuln' keyword."""
        cypher, description = QueryTranslator.translate("show me vuln")

        assert cypher is not None
        assert "Host" in cypher
        assert "IS_VULNERABLE_TO" in cypher
        assert "vulnerable hosts" in description.lower()

    def test_fuzzy_matching_cred(self):
        """Test fuzzy matching for 'cred' keyword."""
        cypher, description = QueryTranslator.translate("users with cred")

        assert cypher is not None
        assert "OWNS_CREDENTIAL" in cypher
        assert "credentials" in description.lower()

    def test_fuzzy_matching_password(self):
        """Test fuzzy matching for 'password' keyword."""
        cypher, description = QueryTranslator.translate("find password")

        assert cypher is not None
        assert "OWNS_CREDENTIAL" in cypher

    def test_fuzzy_matching_asrep(self):
        """Test fuzzy matching for 'asrep' keyword."""
        cypher, description = QueryTranslator.translate("asrep users")

        assert cypher is not None
        assert "asrep_roastable" in cypher or "kerberoastable" in cypher
        assert "roast" in description.lower()

    def test_fuzzy_matching_port(self):
        """Test fuzzy matching for 'port' keyword."""
        cypher, description = QueryTranslator.translate("show ports")

        assert cypher is not None
        assert "Port" in cypher
        assert "HAS_PORT" in cypher

    def test_all_hosts_pattern(self):
        """Test 'all hosts' pattern."""
        cypher, description = QueryTranslator.translate("all hosts")

        assert cypher is not None
        assert "MATCH (h:Host)" in cypher
        assert "hosts" in description.lower()

    def test_roastable_users_pattern(self):
        """Test 'roastable users' pattern."""
        cypher, description = QueryTranslator.translate("roastable users")

        assert cypher is not None
        assert "asrep_roastable" in cypher
        assert "kerberoastable" in cypher
        assert "roast" in description.lower()

    def test_attack_paths_pattern(self):
        """Test 'attack paths' pattern."""
        cypher, description = QueryTranslator.translate("attack paths")

        assert cypher is not None
        assert "Domain" in cypher
        assert "Vulnerability" in cypher
        assert "attack" in description.lower()

    def test_attack_surface_pattern(self):
        """Test 'attack surface' pattern."""
        cypher, description = QueryTranslator.translate("attack surface")

        assert cypher is not None
        assert "count" in cypher.lower()
        assert "attack surface" in description.lower()

    def test_statistics_pattern(self):
        """Test 'statistics' pattern."""
        cypher, description = QueryTranslator.translate("statistics")

        assert cypher is not None
        assert "count" in cypher.lower()
        assert "statistic" in description.lower()

    def test_domains_pattern(self):
        """Test 'domains' pattern."""
        cypher, description = QueryTranslator.translate("domains")

        assert cypher is not None
        assert "Domain" in cypher
        assert "domain" in description.lower()

    def test_subdomains_pattern(self):
        """Test 'subdomains' pattern."""
        cypher, description = QueryTranslator.translate("subdomains")

        assert cypher is not None
        assert "Subdomain" in cypher
        assert "subdomain" in description.lower()

    def test_web_servers_pattern(self):
        """Test 'web servers' pattern."""
        cypher, description = QueryTranslator.translate("web servers")

        assert cypher is not None
        assert "WebServer" in cypher
        assert "RUNS_WEBAPP" in cypher

    def test_unknown_pattern(self):
        """Test that unknown patterns return None."""
        cypher, description = QueryTranslator.translate("this is not a valid pattern xyz123")

        assert cypher is None
        assert description is None

    def test_empty_question(self):
        """Test handling of empty questions."""
        cypher, description = QueryTranslator.translate("")

        assert cypher is None
        assert description is None

    def test_list_available_patterns(self):
        """Test listing all available patterns."""
        patterns = QueryTranslator.list_available_patterns()

        assert isinstance(patterns, dict)
        assert len(patterns) > 0
        assert "vulnerable web servers" in patterns
        assert "all hosts" in patterns
        assert "roastable users" in patterns

        # Check that all patterns have descriptions
        for pattern, description in patterns.items():
            assert isinstance(pattern, str)
            assert isinstance(description, str)
            assert len(description) > 0

    def test_limit_parameter_injection(self):
        """Test that limit parameter is properly used in queries."""
        cypher, _ = QueryTranslator.translate("all hosts", limit=50)

        assert "$limit" in cypher or "LIMIT $limit" in cypher


# ============================================================================
# Query Validator Tests
# ============================================================================

class TestQueryValidator:
    """Tests for the QueryValidator class."""

    def test_safe_read_query(self):
        """Test that safe read queries pass validation."""
        query = "MATCH (h:Host) RETURN h.ip, h.hostname LIMIT 10"
        is_safe, error = QueryValidator.is_safe(query)

        assert is_safe is True
        assert error is None

    def test_safe_write_query(self):
        """Test that safe write queries pass validation."""
        query = "MERGE (h:Host {ip: $ip}) SET h.hostname = $hostname RETURN h"
        is_safe, error = QueryValidator.is_safe(query)

        assert is_safe is True
        assert error is None

    def test_block_delete_operation(self):
        """Test that DELETE operations are blocked."""
        query = "MATCH (h:Host) DELETE h"
        is_safe, error = QueryValidator.is_safe(query)

        assert is_safe is False
        assert "DELETE" in error

    def test_block_detach_delete_operation(self):
        """Test that DETACH DELETE operations are blocked."""
        query = "MATCH (h:Host) DETACH DELETE h"
        is_safe, error = QueryValidator.is_safe(query)

        assert is_safe is False
        assert "DETACH DELETE" in error

    def test_block_remove_operation(self):
        """Test that REMOVE operations are blocked."""
        query = "MATCH (h:Host) REMOVE h.hostname"
        is_safe, error = QueryValidator.is_safe(query)

        assert is_safe is False
        assert "REMOVE" in error

    def test_block_drop_constraint(self):
        """Test that DROP CONSTRAINT operations are blocked."""
        query = "DROP CONSTRAINT host_unique"
        is_safe, error = QueryValidator.is_safe(query)

        assert is_safe is False
        assert error is not None

    def test_block_create_constraint(self):
        """Test that CREATE CONSTRAINT operations are blocked."""
        query = "CREATE CONSTRAINT FOR (h:Host) REQUIRE h.ip IS UNIQUE"
        is_safe, error = QueryValidator.is_safe(query)

        assert is_safe is False
        assert "CONSTRAINT" in error

    def test_block_drop_index(self):
        """Test that DROP INDEX operations are blocked."""
        query = "DROP INDEX host_ip_index"
        is_safe, error = QueryValidator.is_safe(query)

        assert is_safe is False
        assert error is not None

    def test_block_create_index(self):
        """Test that CREATE INDEX operations are blocked."""
        query = "CREATE INDEX FOR (h:Host) ON (h.ip)"
        is_safe, error = QueryValidator.is_safe(query)

        assert is_safe is False
        assert "INDEX" in error

    def test_block_multiple_statements(self):
        """Test that multiple statements are blocked."""
        query = "MATCH (h:Host) RETURN h; MATCH (u:User) RETURN u;"
        is_safe, error = QueryValidator.is_safe(query)

        assert is_safe is False
        assert "Multiple statements" in error

    def test_query_length_limit(self):
        """Test that overly long queries are blocked."""
        query = "MATCH (h:Host) RETURN h" + " " * 20000  # Exceeds max length
        is_safe, error = QueryValidator.is_safe(query)

        assert is_safe is False
        assert "maximum length" in error

    def test_validate_write_query_with_create(self):
        """Test validation of write query with CREATE."""
        query = "CREATE (h:Host {ip: $ip, hostname: $hostname})"
        is_valid, error = QueryValidator.validate_write_query(query)

        assert is_valid is True
        assert error is None

    def test_validate_write_query_with_merge(self):
        """Test validation of write query with MERGE."""
        query = "MERGE (h:Host {ip: $ip}) SET h.hostname = $hostname"
        is_valid, error = QueryValidator.validate_write_query(query)

        assert is_valid is True
        assert error is None

    def test_validate_write_query_with_set(self):
        """Test validation of write query with SET."""
        query = "MATCH (h:Host {ip: $ip}) SET h.last_seen = datetime()"
        is_valid, error = QueryValidator.validate_write_query(query)

        assert is_valid is True
        assert error is None

    def test_validate_write_query_without_write_operation(self):
        """Test that read-only queries fail write validation."""
        query = "MATCH (h:Host) RETURN h"
        is_valid, error = QueryValidator.validate_write_query(query)

        assert is_valid is False
        assert "write operation" in error

    def test_validate_write_query_with_dangerous_operation(self):
        """Test that dangerous operations fail write validation."""
        query = "CREATE (h:Host {ip: $ip}) DELETE h"
        is_valid, error = QueryValidator.validate_write_query(query)

        assert is_valid is False
        assert error is not None

    def test_case_insensitive_keyword_detection(self):
        """Test that dangerous keywords are detected case-insensitively."""
        queries = [
            "match (h) delete h",
            "MATCH (h) DELETE h",
            "Match (h) Delete h",
        ]

        for query in queries:
            is_safe, error = QueryValidator.is_safe(query)
            assert is_safe is False
            assert error is not None


# ============================================================================
# Rate Limiter Tests
# ============================================================================

class TestRateLimiter:
    """Tests for the RateLimiter class."""

    def test_first_request_allowed(self):
        """Test that first request is always allowed."""
        limiter = RateLimiter(max_requests=10, window_seconds=60)
        allowed, error = limiter.is_allowed("test-client")

        assert allowed is True
        assert error is None

    def test_within_limit_allowed(self):
        """Test that requests within limit are allowed."""
        limiter = RateLimiter(max_requests=5, window_seconds=60)

        for i in range(5):
            allowed, error = limiter.is_allowed("test-client")
            assert allowed is True
            assert error is None

    def test_exceeding_limit_blocked(self):
        """Test that requests exceeding limit are blocked."""
        limiter = RateLimiter(max_requests=3, window_seconds=60)

        # Make 3 requests (max limit)
        for i in range(3):
            allowed, _ = limiter.is_allowed("test-client")
            assert allowed is True

        # 4th request should be blocked
        allowed, error = limiter.is_allowed("test-client")
        assert allowed is False
        assert "Rate limit exceeded" in error

    def test_different_clients_independent(self):
        """Test that different clients have independent rate limits."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)

        # Client 1 makes 2 requests
        for i in range(2):
            allowed, _ = limiter.is_allowed("client-1")
            assert allowed is True

        # Client 1 is now at limit
        allowed, _ = limiter.is_allowed("client-1")
        assert allowed is False

        # Client 2 should still be allowed
        allowed, _ = limiter.is_allowed("client-2")
        assert allowed is True

    def test_window_reset(self):
        """Test that rate limit resets after window expires."""
        limiter = RateLimiter(max_requests=2, window_seconds=1)  # 1 second window

        # Make 2 requests
        limiter.is_allowed("test-client")
        limiter.is_allowed("test-client")

        # 3rd request blocked
        allowed, _ = limiter.is_allowed("test-client")
        assert allowed is False

        # Wait for window to expire
        import time
        time.sleep(1.1)

        # Should be allowed again
        allowed, _ = limiter.is_allowed("test-client")
        assert allowed is True

    def test_get_stats(self):
        """Test rate limit statistics."""
        limiter = RateLimiter(max_requests=10, window_seconds=60)

        # Initial stats
        stats = limiter.get_stats("test-client")
        assert stats["requests_in_window"] == 0
        assert stats["max_requests"] == 10
        assert stats["remaining"] == 10

        # After 3 requests
        for i in range(3):
            limiter.is_allowed("test-client")

        stats = limiter.get_stats("test-client")
        assert stats["requests_in_window"] == 3
        assert stats["remaining"] == 7

    def test_zero_remaining_at_limit(self):
        """Test that remaining is zero when at limit."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)

        limiter.is_allowed("test-client")
        limiter.is_allowed("test-client")

        stats = limiter.get_stats("test-client")
        assert stats["remaining"] == 0


# ============================================================================
# Flask Application Tests
# ============================================================================

@pytest.fixture
def app():
    """Create a test Flask application."""
    # Create test config
    class TestConfig:
        NEO4J_URI = "bolt://localhost:7687"
        NEO4J_USERNAME = "neo4j"
        NEO4J_PASSWORD = "test"
        NEO4J_DATABASE = "neo4j"
        API_PORT = 5002
        API_HOST = "0.0.0.0"
        API_KEY = "test-api-key"
        ENABLE_AUTH = True
        RATE_LIMIT_REQUESTS = 100
        RATE_LIMIT_WINDOW = 60
        MAX_QUERY_LENGTH = 10000
        QUERY_TIMEOUT = 30
        DEBUG = True
        FLASK_ENV = "testing"

    app = create_app(TestConfig)
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


class TestHealthEndpoint:
    """Tests for the /health endpoint."""

    def test_health_endpoint_exists(self, client):
        """Test that health endpoint responds."""
        response = client.get("/health")
        assert response.status_code in [200, 503]

    def test_health_response_structure(self, client):
        """Test that health response has correct structure."""
        response = client.get("/health")
        data = response.get_json()

        assert "status" in data
        assert "timestamp" in data
        assert "database_connected" in data
        assert "version" in data
        assert "uptime_seconds" in data

    def test_health_no_auth_required(self, client):
        """Test that health endpoint doesn't require authentication."""
        response = client.get("/health")
        # Should not return 401
        assert response.status_code != 401


class TestQueryEndpoint:
    """Tests for the /query endpoint."""

    def test_query_requires_auth(self, client):
        """Test that query endpoint requires authentication."""
        response = client.post("/query", json={"question": "all hosts"})
        assert response.status_code == 401

    def test_query_with_invalid_api_key(self, client):
        """Test query with invalid API key."""
        response = client.post(
            "/query",
            headers={"X-API-Key": "invalid-key"},
            json={"question": "all hosts"}
        )
        assert response.status_code == 401

    def test_query_requires_json(self, client):
        """Test that query endpoint requires JSON body."""
        response = client.post(
            "/query",
            headers={"X-API-Key": "test-api-key"}
        )
        assert response.status_code == 400

    def test_query_requires_question(self, client):
        """Test that question field is required."""
        response = client.post(
            "/query",
            headers={"X-API-Key": "test-api-key"},
            json={}
        )
        assert response.status_code == 400

    def test_query_unknown_pattern(self, client):
        """Test query with unknown pattern."""
        response = client.post(
            "/query",
            headers={"X-API-Key": "test-api-key"},
            json={"question": "xyz invalid pattern 123"}
        )
        data = response.get_json()

        assert response.status_code == 400
        assert data["success"] is False
        assert "available_patterns" in data


class TestUpdateEndpoint:
    """Tests for the /update endpoint."""

    def test_update_requires_auth(self, client):
        """Test that update endpoint requires authentication."""
        response = client.post(
            "/update",
            json={"query": "CREATE (h:Host {ip: '1.2.3.4'})"}
        )
        assert response.status_code == 401

    def test_update_requires_json(self, client):
        """Test that update endpoint requires JSON body."""
        response = client.post(
            "/update",
            headers={"X-API-Key": "test-api-key"}
        )
        assert response.status_code == 400

    def test_update_requires_query(self, client):
        """Test that query field is required."""
        response = client.post(
            "/update",
            headers={"X-API-Key": "test-api-key"},
            json={}
        )
        assert response.status_code == 400

    def test_update_blocks_dangerous_query(self, client):
        """Test that dangerous queries are blocked."""
        response = client.post(
            "/update",
            headers={"X-API-Key": "test-api-key"},
            json={"query": "MATCH (h:Host) DELETE h"}
        )
        data = response.get_json()

        assert response.status_code == 400
        assert data["success"] is False
        assert "validation failed" in data["error"].lower()


class TestPatternsEndpoint:
    """Tests for the /patterns endpoint."""

    def test_patterns_requires_auth(self, client):
        """Test that patterns endpoint requires authentication."""
        response = client.get("/patterns")
        assert response.status_code == 401

    def test_patterns_returns_list(self, client):
        """Test that patterns endpoint returns pattern list."""
        response = client.get(
            "/patterns",
            headers={"X-API-Key": "test-api-key"}
        )
        data = response.get_json()

        assert response.status_code == 200
        assert data["success"] is True
        assert "patterns" in data
        assert "count" in data
        assert isinstance(data["patterns"], dict)
        assert data["count"] > 0


class TestDirectQueryEndpoint:
    """Tests for the /direct-query endpoint."""

    def test_direct_query_requires_auth(self, client):
        """Test that direct-query endpoint requires authentication."""
        response = client.post(
            "/direct-query",
            json={"query": "MATCH (h:Host) RETURN h LIMIT 5"}
        )
        assert response.status_code == 401

    def test_direct_query_requires_query_field(self, client):
        """Test that query field is required."""
        response = client.post(
            "/direct-query",
            headers={"X-API-Key": "test-api-key"},
            json={}
        )
        data = response.get_json()

        assert response.status_code == 400
        assert "query" in data["error"].lower()

    def test_direct_query_blocks_dangerous_operations(self, client):
        """Test that dangerous operations are blocked."""
        response = client.post(
            "/direct-query",
            headers={"X-API-Key": "test-api-key"},
            json={"query": "MATCH (h:Host) DELETE h"}
        )
        data = response.get_json()

        assert response.status_code == 400
        assert data["success"] is False


# ============================================================================
# Integration Tests
# ============================================================================

class TestAPIIntegration:
    """Integration tests for API workflows."""

    def test_complete_query_workflow(self, client):
        """Test complete workflow: patterns -> query."""
        # Step 1: Get available patterns
        response = client.get(
            "/patterns",
            headers={"X-API-Key": "test-api-key"}
        )
        assert response.status_code == 200
        patterns = response.get_json()["patterns"]

        # Step 2: Use one of the patterns
        pattern = list(patterns.keys())[0]
        # Note: This will fail if database not connected, but structure is valid
        response = client.post(
            "/query",
            headers={"X-API-Key": "test-api-key"},
            json={"question": pattern, "limit": 10}
        )
        # We expect either success or database unavailable
        assert response.status_code in [200, 503]

    def test_rate_limit_headers(self, client):
        """Test that rate limit headers are included in responses."""
        response = client.post(
            "/query",
            headers={"X-API-Key": "test-api-key"},
            json={"question": "all hosts"}
        )

        # Check for rate limit headers
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
        assert "X-RateLimit-Window" in response.headers

    def test_api_version_header(self, client):
        """Test that API version header is included."""
        response = client.get("/health")
        assert "X-API-Version" in response.headers
        assert response.headers["X-API-Version"] == "1.0.0"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
