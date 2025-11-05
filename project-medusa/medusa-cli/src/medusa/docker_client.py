"""
Docker client integration for MEDUSA
Enables execution of commands in Docker containers from the backend
"""

import logging
import os
import docker
from typing import Dict, Any, Optional, List
from docker.models.containers import Container
from docker.errors import DockerException, NotFound, APIError

logger = logging.getLogger(__name__)


class DockerClient:
    """
    Docker client for managing and executing commands in lab environment containers
    """
    
    def __init__(self):
        """Initialize Docker client"""
        try:
            self.client = docker.from_env()
            self.client.ping()
            self.is_available = True
            logger.info("Docker client initialized successfully")
        except DockerException as e:
            logger.warning(f"Docker not available: {e}")
            self.client = None
            self.is_available = False
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def close(self):
        """Close Docker client connection"""
        if self.client:
            self.client.close()
    
    def is_running_in_docker(self) -> bool:
        """Check if current process is running inside Docker"""
        return os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv')
    
    def list_containers(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        List Docker containers
        
        Args:
            filters: Docker filters dict (e.g., {"name": "medusa"})
        
        Returns:
            List of container info dicts
        """
        if not self.is_available:
            logger.warning("Docker not available")
            return []
        
        try:
            containers = self.client.containers.list(all=True, filters=filters)
            return [
                {
                    "id": c.id[:12],
                    "name": c.name,
                    "status": c.status,
                    "image": c.image.tags[0] if c.image.tags else c.image.id[:12],
                    "labels": c.labels,
                    "networks": list(c.attrs.get("NetworkSettings", {}).get("Networks", {}).keys())
                }
                for c in containers
            ]
        except Exception as e:
            logger.error(f"Failed to list containers: {e}")
            return []
    
    def get_container(self, name_or_id: str) -> Optional[Container]:
        """Get container by name or ID"""
        if not self.is_available:
            return None
        
        try:
            return self.client.containers.get(name_or_id)
        except NotFound:
            logger.warning(f"Container not found: {name_or_id}")
            return None
        except Exception as e:
            logger.error(f"Failed to get container: {e}")
            return None
    
    def execute_command(
        self,
        container_name: str,
        command: str,
        workdir: Optional[str] = None,
        user: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute command in a container
        
        Args:
            container_name: Name or ID of container
            command: Command to execute
            workdir: Working directory in container
            user: User to run command as
        
        Returns:
            Dict with exit_code, output, and error
        """
        if not self.is_available:
            return {
                "exit_code": -1,
                "output": "",
                "error": "Docker not available"
            }
        
        container = self.get_container(container_name)
        if not container:
            return {
                "exit_code": -1,
                "output": "",
                "error": f"Container '{container_name}' not found"
            }
        
        try:
            logger.info(f"Executing in {container_name}: {command}")
            
            # Execute command
            exec_result = container.exec_run(
                cmd=command,
                workdir=workdir,
                user=user,
                stdout=True,
                stderr=True,
                demux=True
            )
            
            exit_code = exec_result.exit_code
            stdout, stderr = exec_result.output if exec_result.output else (b"", b"")
            
            output = stdout.decode('utf-8') if stdout else ""
            error = stderr.decode('utf-8') if stderr else ""
            
            logger.debug(f"Command exit code: {exit_code}")
            
            return {
                "exit_code": exit_code,
                "output": output,
                "error": error
            }
            
        except APIError as e:
            logger.error(f"Docker API error: {e}")
            return {
                "exit_code": -1,
                "output": "",
                "error": f"Docker API error: {str(e)}"
            }
        except Exception as e:
            logger.error(f"Failed to execute command: {e}")
            return {
                "exit_code": -1,
                "output": "",
                "error": str(e)
            }
    
    def get_container_logs(
        self,
        container_name: str,
        tail: int = 100,
        since: Optional[str] = None
    ) -> str:
        """
        Get container logs
        
        Args:
            container_name: Name or ID of container
            tail: Number of lines to return
            since: Timestamp to start from
        
        Returns:
            Container logs as string
        """
        if not self.is_available:
            return "Docker not available"
        
        container = self.get_container(container_name)
        if not container:
            return f"Container '{container_name}' not found"
        
        try:
            logs = container.logs(tail=tail, since=since, timestamps=True)
            return logs.decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to get logs: {e}")
            return f"Error getting logs: {str(e)}"
    
    def get_container_stats(self, container_name: str) -> Dict[str, Any]:
        """Get container resource usage statistics"""
        if not self.is_available:
            return {}
        
        container = self.get_container(container_name)
        if not container:
            return {}
        
        try:
            stats = container.stats(stream=False)
            
            # Calculate CPU percentage
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                       stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                          stats['precpu_stats']['system_cpu_usage']
            cpu_percent = (cpu_delta / system_delta) * 100.0 if system_delta > 0 else 0.0
            
            # Calculate memory usage
            memory_usage = stats['memory_stats'].get('usage', 0)
            memory_limit = stats['memory_stats'].get('limit', 0)
            memory_percent = (memory_usage / memory_limit) * 100.0 if memory_limit > 0 else 0.0
            
            return {
                "cpu_percent": round(cpu_percent, 2),
                "memory_usage": memory_usage,
                "memory_limit": memory_limit,
                "memory_percent": round(memory_percent, 2),
                "network_rx": stats.get('networks', {}).get('eth0', {}).get('rx_bytes', 0),
                "network_tx": stats.get('networks', {}).get('eth0', {}).get('tx_bytes', 0)
            }
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {}
    
    def check_network_connectivity(
        self,
        source_container: str,
        target_host: str,
        port: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Check network connectivity between containers or to external hosts
        
        Args:
            source_container: Container to run test from
            target_host: Target hostname or IP
            port: Optional port to test
        
        Returns:
            Dict with success status and details
        """
        if port:
            # Test specific port with nc (netcat)
            command = f"nc -zv {target_host} {port}"
        else:
            # Simple ping test
            command = f"ping -c 3 {target_host}"
        
        result = self.execute_command(source_container, command)
        
        return {
            "success": result["exit_code"] == 0,
            "target": target_host,
            "port": port,
            "output": result["output"],
            "error": result["error"]
        }
    
    def get_network_info(self, network_name: str) -> Dict[str, Any]:
        """Get information about a Docker network"""
        if not self.is_available:
            return {}
        
        try:
            network = self.client.networks.get(network_name)
            return {
                "id": network.id[:12],
                "name": network.name,
                "driver": network.attrs.get("Driver"),
                "scope": network.attrs.get("Scope"),
                "subnet": network.attrs.get("IPAM", {}).get("Config", [{}])[0].get("Subnet"),
                "gateway": network.attrs.get("IPAM", {}).get("Config", [{}])[0].get("Gateway"),
                "containers": list(network.attrs.get("Containers", {}).keys())
            }
        except NotFound:
            logger.warning(f"Network not found: {network_name}")
            return {}
        except Exception as e:
            logger.error(f"Failed to get network info: {e}")
            return {}


# Singleton instance
_docker_client = None


def get_docker_client() -> DockerClient:
    """Get or create Docker client singleton"""
    global _docker_client
    if _docker_client is None:
        _docker_client = DockerClient()
    return _docker_client

