#!/usr/bin/env python3
"""
MEDUSA Lab - Health Check Script
=================================
Comprehensive Python-based health monitoring for all lab services.
Returns JSON status report suitable for monitoring tools.

Usage:
    python3 healthcheck.py [--format json|text] [--quiet]
"""

import sys
import json
import socket
import subprocess
from typing import Dict, List, Tuple
from datetime import datetime
import argparse

try:
    import requests
except ImportError:
    print("Warning: requests library not found. HTTP checks will be limited.", file=sys.stderr)
    requests = None


# ANSI color codes
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color


class ServiceHealthCheck:
    """Health check manager for MEDUSA lab services."""
    
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.results = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'services': {},
            'summary': {
                'total': 0,
                'healthy': 0,
                'unhealthy': 0,
                'degraded': 0
            }
        }
    
    def log(self, message: str, color: str = ''):
        """Log message to stdout if not in quiet mode."""
        if not self.quiet:
            if color:
                print(f"{color}{message}{Colors.NC}")
            else:
                print(message)
    
    def check_port(self, host: str, port: int, timeout: int = 2) -> bool:
        """Check if a port is open and accepting connections."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except socket.error:
            return False
    
    def check_http(self, url: str, timeout: int = 5) -> Tuple[bool, int]:
        """Check HTTP endpoint and return (success, status_code)."""
        if requests is None:
            # Fallback to basic port check
            host = url.split('://')[1].split(':')[0]
            port = int(url.split(':')[-1].split('/')[0]) if ':' in url.split('://')[1] else 80
            return self.check_port(host, port), 0
        
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            return response.status_code < 500, response.status_code
        except requests.RequestException:
            return False, 0
    
    def check_docker_container(self, container_name: str) -> Dict:
        """Check Docker container status."""
        try:
            # Check if container is running
            result = subprocess.run(
                ['docker', 'ps', '--filter', f'name={container_name}', '--format', '{{.Status}}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                status = result.stdout.strip()
                is_healthy = 'Up' in status and 'unhealthy' not in status.lower()
                
                return {
                    'running': True,
                    'status': status,
                    'healthy': is_healthy
                }
            else:
                return {
                    'running': False,
                    'status': 'Not running',
                    'healthy': False
                }
        except Exception as e:
            return {
                'running': False,
                'status': f'Error: {str(e)}',
                'healthy': False
            }
    
    def check_mysql(self) -> Dict:
        """Check MySQL database health."""
        service_name = "MySQL Database"
        self.log(f"Checking {service_name}...", Colors.CYAN)
        
        health = {
            'name': service_name,
            'status': 'unknown',
            'checks': {}
        }
        
        # Check container
        container = self.check_docker_container('medusa_ehr_db')
        health['checks']['container'] = container
        
        # Check port
        port_open = self.check_port('localhost', 3306)
        health['checks']['port_3306'] = {'accessible': port_open}
        
        # Try MySQL ping
        try:
            result = subprocess.run(
                ['docker', 'exec', 'medusa_ehr_db', 'mysqladmin', 
                 'ping', '-h', 'localhost', '-u', 'root', '-padmin123'],
                capture_output=True,
                timeout=5
            )
            mysql_responsive = result.returncode == 0
            health['checks']['mysql_ping'] = {'responsive': mysql_responsive}
        except Exception as e:
            health['checks']['mysql_ping'] = {'responsive': False, 'error': str(e)}
            mysql_responsive = False
        
        # Determine overall health
        if container['healthy'] and port_open and mysql_responsive:
            health['status'] = 'healthy'
            self.log(f"  ✓ {service_name}: Healthy", Colors.GREEN)
        elif port_open or container['running']:
            health['status'] = 'degraded'
            self.log(f"  ! {service_name}: Degraded", Colors.YELLOW)
        else:
            health['status'] = 'unhealthy'
            self.log(f"  ✗ {service_name}: Unhealthy", Colors.RED)
        
        return health
    
    def check_web_service(self, name: str, container: str, url: str, port: int) -> Dict:
        """Check web service health."""
        self.log(f"Checking {name}...", Colors.CYAN)
        
        health = {
            'name': name,
            'status': 'unknown',
            'checks': {}
        }
        
        # Check container
        container_status = self.check_docker_container(container)
        health['checks']['container'] = container_status
        
        # Check HTTP endpoint
        http_ok, status_code = self.check_http(url)
        health['checks']['http'] = {
            'accessible': http_ok,
            'status_code': status_code
        }
        
        # Check port
        port_open = self.check_port('localhost', port)
        health['checks'][f'port_{port}'] = {'accessible': port_open}
        
        # Determine overall health
        if container_status['healthy'] and http_ok and port_open:
            health['status'] = 'healthy'
            self.log(f"  ✓ {name}: Healthy (HTTP {status_code})", Colors.GREEN)
        elif port_open or container_status['running']:
            health['status'] = 'degraded'
            self.log(f"  ! {name}: Degraded", Colors.YELLOW)
        else:
            health['status'] = 'unhealthy'
            self.log(f"  ✗ {name}: Unhealthy", Colors.RED)
        
        return health
    
    def check_network_service(self, name: str, container: str, port: int, protocol: str = "TCP") -> Dict:
        """Check network service (SSH, FTP, LDAP, etc.)."""
        self.log(f"Checking {name}...", Colors.CYAN)
        
        health = {
            'name': name,
            'status': 'unknown',
            'checks': {}
        }
        
        # Check container
        container_status = self.check_docker_container(container)
        health['checks']['container'] = container_status
        
        # Check port
        port_open = self.check_port('localhost', port)
        health['checks'][f'port_{port}'] = {
            'accessible': port_open,
            'protocol': protocol
        }
        
        # Determine overall health
        if container_status['healthy'] and port_open:
            health['status'] = 'healthy'
            self.log(f"  ✓ {name}: Healthy (Port {port})", Colors.GREEN)
        elif port_open or container_status['running']:
            health['status'] = 'degraded'
            self.log(f"  ! {name}: Degraded", Colors.YELLOW)
        else:
            health['status'] = 'unhealthy'
            self.log(f"  ✗ {name}: Unhealthy", Colors.RED)
        
        return health
    
    def check_all_services(self):
        """Run health checks on all MEDUSA lab services."""
        self.log("\n" + "="*60, Colors.BOLD)
        self.log("MEDUSA Lab - Health Check Report", Colors.BOLD)
        self.log("="*60 + "\n", Colors.BOLD)
        
        # Web services
        self.results['services']['ehr_webapp'] = self.check_web_service(
            "EHR Web Portal", "medusa_ehr_web", "http://localhost:8080", 8080
        )
        
        self.results['services']['ehr_api'] = self.check_web_service(
            "EHR API", "medusa_ehr_api", "http://localhost:3000", 3000
        )
        
        self.results['services']['log_collector'] = self.check_web_service(
            "Log Collector", "medusa_logs", "http://localhost:8081", 8081
        )
        
        # Database
        self.results['services']['mysql'] = self.check_mysql()
        
        # Network services
        self.results['services']['ssh'] = self.check_network_service(
            "SSH Server", "medusa_ssh_server", 2222, "SSH"
        )
        
        self.results['services']['ftp'] = self.check_network_service(
            "FTP Server", "medusa_ftp_server", 21, "FTP"
        )
        
        self.results['services']['ldap'] = self.check_network_service(
            "LDAP Server", "medusa_ldap", 389, "LDAP"
        )
        
        self.results['services']['workstation'] = self.check_network_service(
            "Workstation (SMB)", "medusa_workstation", 445, "SMB"
        )
        
        # Calculate summary
        self.calculate_summary()
    
    def calculate_summary(self):
        """Calculate summary statistics."""
        for service in self.results['services'].values():
            self.results['summary']['total'] += 1
            status = service['status']
            
            if status == 'healthy':
                self.results['summary']['healthy'] += 1
            elif status == 'degraded':
                self.results['summary']['degraded'] += 1
            else:
                self.results['summary']['unhealthy'] += 1
    
    def print_summary(self):
        """Print summary of health check results."""
        summary = self.results['summary']
        
        self.log("\n" + "="*60, Colors.BOLD)
        self.log("Summary", Colors.BOLD)
        self.log("="*60, Colors.BOLD)
        
        self.log(f"\nTotal Services:    {summary['total']}")
        self.log(f"Healthy:           {summary['healthy']}", Colors.GREEN)
        self.log(f"Degraded:          {summary['degraded']}", Colors.YELLOW)
        self.log(f"Unhealthy:         {summary['unhealthy']}", Colors.RED)
        
        if summary['healthy'] == summary['total']:
            self.log("\n✓ All services are healthy!", Colors.GREEN + Colors.BOLD)
            self.log("The lab is fully operational.\n", Colors.GREEN)
        elif summary['unhealthy'] > 0:
            self.log("\n✗ Some services are unhealthy!", Colors.RED + Colors.BOLD)
            self.log("Review the output above and check container logs.\n", Colors.RED)
        else:
            self.log("\n! Some services are degraded.", Colors.YELLOW + Colors.BOLD)
            self.log("Services may be starting or experiencing issues.\n", Colors.YELLOW)
    
    def get_json_report(self) -> str:
        """Get results as JSON string."""
        return json.dumps(self.results, indent=2)
    
    def is_healthy(self) -> bool:
        """Return True if all services are healthy."""
        return self.results['summary']['unhealthy'] == 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="MEDUSA Lab Health Check - Monitor service status"
    )
    parser.add_argument(
        '--format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress progress messages (useful for JSON output)'
    )
    
    args = parser.parse_args()
    
    # Create health checker
    checker = ServiceHealthCheck(quiet=args.quiet or args.format == 'json')
    
    # Run checks
    checker.check_all_services()
    
    # Output results
    if args.format == 'json':
        print(checker.get_json_report())
    else:
        checker.print_summary()
    
    # Exit with appropriate code
    sys.exit(0 if checker.is_healthy() else 1)


if __name__ == '__main__':
    main()

