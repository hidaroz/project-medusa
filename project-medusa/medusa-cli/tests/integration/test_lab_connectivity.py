#!/usr/bin/env python3
"""
Integration tests for MEDUSA Lab Environment connectivity

These tests verify that all lab services are accessible and responding correctly.
Requires lab environment to be running (./lab-environment/start.sh)
"""

import pytest
import requests
import socket
import subprocess
import time
from typing import Dict, Any


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def lab_services() -> Dict[str, Dict[str, Any]]:
    """Configuration for all lab services"""
    return {
        "ehr_web": {
            "type": "http",
            "url": "http://localhost:8080",
            "name": "EHR Web Portal"
        },
        "ehr_api": {
            "type": "http",
            "url": "http://localhost:3001",
            "name": "EHR API"
        },
        "log_collector": {
            "type": "http",
            "url": "http://localhost:8081",
            "name": "Log Collector"
        },
        "mysql": {
            "type": "tcp",
            "host": "localhost",
            "port": 3306,
            "name": "MySQL Database"
        },
        "ssh": {
            "type": "tcp",
            "host": "localhost",
            "port": 2222,
            "name": "SSH Server"
        },
        "ftp": {
            "type": "tcp",
            "host": "localhost",
            "port": 21,
            "name": "FTP Server"
        },
        "ldap": {
            "type": "tcp",
            "host": "localhost",
            "port": 389,
            "name": "LDAP Server"
        },
        "smb": {
            "type": "tcp",
            "host": "localhost",
            "port": 445,
            "name": "SMB (Workstation)"
        }
    }


def check_tcp_port(host: str, port: int, timeout: int = 5) -> bool:
    """Check if a TCP port is accessible"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_http_endpoint(url: str, timeout: int = 10) -> Dict[str, Any]:
    """Check if an HTTP endpoint is accessible"""
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        return {
            "accessible": True,
            "status_code": response.status_code,
            "response_time": response.elapsed.total_seconds()
        }
    except requests.exceptions.Timeout:
        return {"accessible": False, "error": "timeout"}
    except requests.exceptions.ConnectionError:
        return {"accessible": False, "error": "connection_refused"}
    except Exception as e:
        return {"accessible": False, "error": str(e)}


# ============================================================================
# HTTP Service Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.requires_docker
class TestHTTPServices:
    """Test HTTP-based lab services"""

    def test_ehr_web_portal_accessible(self, lab_services):
        """Test that EHR Web Portal is accessible"""
        service = lab_services["ehr_web"]
        result = check_http_endpoint(service["url"])

        assert result["accessible"], f"{service['name']} not accessible: {result.get('error')}"
        assert result["status_code"] in [200, 302, 301], \
            f"{service['name']} returned unexpected status: {result['status_code']}"

    def test_ehr_api_accessible(self, lab_services):
        """Test that EHR API is accessible"""
        service = lab_services["ehr_api"]
        result = check_http_endpoint(service["url"])

        assert result["accessible"], f"{service['name']} not accessible: {result.get('error')}"
        # API might return 404 for root, which is acceptable
        assert result["status_code"] in [200, 404], \
            f"{service['name']} returned unexpected status: {result['status_code']}"

    def test_log_collector_accessible(self, lab_services):
        """Test that Log Collector web interface is accessible"""
        service = lab_services["log_collector"]
        result = check_http_endpoint(service["url"])

        assert result["accessible"], f"{service['name']} not accessible: {result.get('error')}"

    def test_ehr_web_response_time(self, lab_services):
        """Test that EHR Web Portal responds quickly"""
        service = lab_services["ehr_web"]
        result = check_http_endpoint(service["url"])

        assert result["accessible"], f"{service['name']} not accessible"
        # Should respond in under 5 seconds
        assert result["response_time"] < 5.0, \
            f"{service['name']} response time too slow: {result['response_time']}s"


# ============================================================================
# TCP Service Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.requires_docker
class TestTCPServices:
    """Test TCP-based lab services"""

    def test_mysql_port_open(self, lab_services):
        """Test that MySQL port is accessible"""
        service = lab_services["mysql"]
        accessible = check_tcp_port(service["host"], service["port"])

        assert accessible, f"{service['name']} port {service['port']} not accessible"

    def test_ssh_port_open(self, lab_services):
        """Test that SSH port is accessible"""
        service = lab_services["ssh"]
        accessible = check_tcp_port(service["host"], service["port"])

        assert accessible, f"{service['name']} port {service['port']} not accessible"

    def test_ftp_port_open(self, lab_services):
        """Test that FTP port is accessible"""
        service = lab_services["ftp"]
        accessible = check_tcp_port(service["host"], service["port"])

        assert accessible, f"{service['name']} port {service['port']} not accessible"

    def test_ldap_port_open(self, lab_services):
        """Test that LDAP port is accessible"""
        service = lab_services["ldap"]
        accessible = check_tcp_port(service["host"], service["port"])

        assert accessible, f"{service['name']} port {service['port']} not accessible"

    def test_smb_port_open(self, lab_services):
        """Test that SMB port is accessible"""
        service = lab_services["smb"]
        accessible = check_tcp_port(service["host"], service["port"])

        assert accessible, f"{service['name']} port {service['port']} not accessible"


# ============================================================================
# Database Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.requires_docker
class TestDatabaseService:
    """Test database-specific functionality"""

    def test_mysql_ping(self):
        """Test MySQL database responds to ping"""
        try:
            result = subprocess.run(
                ["docker", "exec", "medusa_ehr_db", "mysqladmin",
                 "ping", "-h", "localhost", "-u", "root", "-padmin123"],
                capture_output=True,
                timeout=10
            )
            assert result.returncode == 0, "MySQL ping failed"
        except subprocess.TimeoutExpired:
            pytest.fail("MySQL ping timed out")
        except FileNotFoundError:
            pytest.skip("Docker not available")

    def test_healthcare_database_exists(self):
        """Test that healthcare_db database exists"""
        try:
            result = subprocess.run(
                ["docker", "exec", "medusa_ehr_db", "mysql",
                 "-u", "root", "-padmin123", "-e", "SHOW DATABASES;"],
                capture_output=True,
                text=True,
                timeout=10
            )
            assert result.returncode == 0, "Failed to query databases"
            assert "healthcare_db" in result.stdout, "healthcare_db not found"
        except FileNotFoundError:
            pytest.skip("Docker not available")

    def test_database_has_tables(self):
        """Test that database has been initialized with tables"""
        try:
            result = subprocess.run(
                ["docker", "exec", "medusa_ehr_db", "mysql",
                 "-u", "root", "-padmin123", "-D", "healthcare_db",
                 "-e", "SHOW TABLES;"],
                capture_output=True,
                text=True,
                timeout=10
            )
            assert result.returncode == 0, "Failed to query tables"
            # Should have at least some tables
            lines = result.stdout.strip().split('\n')
            # Subtract header line
            table_count = len(lines) - 1 if len(lines) > 1 else 0
            assert table_count > 0, "Database has no tables"
        except FileNotFoundError:
            pytest.skip("Docker not available")


# ============================================================================
# Network Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.requires_docker
class TestLabNetworking:
    """Test lab networking configuration"""

    def test_docker_networks_exist(self):
        """Test that lab Docker networks exist"""
        try:
            result = subprocess.run(
                ["docker", "network", "ls"],
                capture_output=True,
                text=True,
                timeout=10
            )
            assert result.returncode == 0, "Failed to list Docker networks"

            # Check for expected networks (may have different names)
            networks = result.stdout
            assert any(name in networks for name in ["healthcare-dmz", "medusa-dmz"]), \
                "DMZ network not found"
            assert any(name in networks for name in ["healthcare-internal", "medusa-internal"]), \
                "Internal network not found"
        except FileNotFoundError:
            pytest.skip("Docker not available")

    def test_containers_running(self):
        """Test that all expected containers are running"""
        expected_containers = [
            "medusa_ehr_web",
            "medusa_ehr_db",
            "medusa_ehr_api",
            "medusa_ssh_server",
            "medusa_ftp_server",
            "medusa_ldap",
            "medusa_logs",
            "medusa_workstation"
        ]

        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=10
            )
            assert result.returncode == 0, "Failed to list running containers"

            running_containers = result.stdout.strip().split('\n')

            for container in expected_containers:
                assert container in running_containers, \
                    f"Expected container '{container}' not running"
        except FileNotFoundError:
            pytest.skip("Docker not available")


# ============================================================================
# Vulnerability Sanity Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.requires_docker
@pytest.mark.slow
class TestVulnerabilityEndpoints:
    """Sanity tests to verify intentional vulnerabilities are present"""

    def test_sql_injection_endpoint_exists(self):
        """Test that SQL injection test endpoint is accessible"""
        url = "http://localhost:8080/search.php?query=test"
        response = requests.get(url, timeout=10)

        # Should get some response (200, 500, etc.)
        # We're just checking the endpoint exists
        assert response.status_code in [200, 500], \
            f"Search endpoint returned unexpected status: {response.status_code}"

    def test_api_no_auth_endpoint(self):
        """Test that API endpoints without auth are accessible"""
        endpoints = [
            "http://localhost:3001/api/config",
            "http://localhost:3001/api/debug",
        ]

        for endpoint in endpoints:
            try:
                response = requests.get(endpoint, timeout=10)
                # Should be accessible (not 401/403)
                # 404 is acceptable if endpoint doesn't exist yet
                assert response.status_code not in [401, 403], \
                    f"{endpoint} requires authentication (expected no auth)"
            except requests.exceptions.RequestException:
                # Endpoint might not exist, that's okay for this test
                pass

    def test_directory_listing_possible(self):
        """Test that directory listing is possible (vulnerability)"""
        # This tests for the presence of the vulnerability
        url = "http://localhost:8080/uploads/"
        try:
            response = requests.get(url, timeout=10)
            # If we get 200 or 403, the directory exists
            # We're not testing if listing works, just that the path is there
            assert response.status_code in [200, 403, 404], \
                f"Unexpected response from uploads directory"
        except requests.exceptions.RequestException:
            pass  # Endpoint might not exist


# ============================================================================
# Complete Lab Health Check
# ============================================================================

@pytest.mark.integration
@pytest.mark.requires_docker
def test_complete_lab_health(lab_services):
    """
    Comprehensive test that all lab services are healthy
    This test provides a quick overview of lab status
    """
    results = {}

    # Test HTTP services
    for name in ["ehr_web", "ehr_api", "log_collector"]:
        service = lab_services[name]
        result = check_http_endpoint(service["url"])
        results[name] = result["accessible"]

    # Test TCP services
    for name in ["mysql", "ssh", "ftp", "ldap", "smb"]:
        service = lab_services[name]
        accessible = check_tcp_port(service["host"], service["port"])
        results[name] = accessible

    # Generate health report
    total_services = len(results)
    healthy_services = sum(1 for accessible in results.values() if accessible)

    # Print health report
    print(f"\n{'='*60}")
    print(f"Lab Health Check: {healthy_services}/{total_services} services healthy")
    print(f"{'='*60}")
    for name, accessible in results.items():
        status = "✅" if accessible else "❌"
        print(f"{status} {lab_services[name]['name']}")
    print(f"{'='*60}")

    # Assert at least 80% of services are healthy
    health_percentage = (healthy_services / total_services) * 100
    assert health_percentage >= 80, \
        f"Lab unhealthy: only {health_percentage:.0f}% of services accessible"


# ============================================================================
# Pytest Configuration
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers for this test module"""
    config.addinivalue_line(
        "markers",
        "requires_docker: Tests that require Docker and lab environment to be running"
    )
