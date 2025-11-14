"""
Scope Validator
Validates targets against authorized scope
"""

import ipaddress
from typing import List, Set, Union
import logging


class ScopeValidator:
    """
    Validates targets against authorized scope

    Prevents accidental attacks on out-of-scope targets
    """

    def __init__(self, authorized_scope: List[str]):
        """
        Initialize Scope Validator

        Args:
            authorized_scope: List of authorized IP/CIDR ranges
        """
        self.logger = logging.getLogger(__name__)
        self.authorized_networks: Set[ipaddress.IPv4Network] = set()
        self.authorized_hosts: Set[ipaddress.IPv4Address] = set()

        self._parse_scope(authorized_scope)

    def _parse_scope(self, scope: List[str]):
        """Parse authorized scope"""
        for item in scope:
            try:
                # Try as network (CIDR)
                network = ipaddress.ip_network(item, strict=False)
                self.authorized_networks.add(network)
                self.logger.debug(f"Added network to scope: {network}")

            except ValueError:
                try:
                    # Try as single IP
                    host = ipaddress.ip_address(item)
                    self.authorized_hosts.add(host)
                    self.logger.debug(f"Added host to scope: {host}")

                except ValueError:
                    self.logger.warning(f"Invalid scope item: {item}")

    def is_in_scope(self, target: str) -> bool:
        """
        Check if target is in authorized scope

        Args:
            target: IP address or hostname

        Returns:
            True if target is in scope
        """
        try:
            # Parse target IP
            target_ip = ipaddress.ip_address(target)

            # Check against hosts
            if target_ip in self.authorized_hosts:
                return True

            # Check against networks
            for network in self.authorized_networks:
                if target_ip in network:
                    return True

            return False

        except ValueError:
            # Not a valid IP - could be hostname
            # For now, reject (should implement DNS resolution)
            self.logger.warning(f"Cannot validate hostname: {target}")
            return False

    def validate_targets(self, targets: List[str]) -> tuple[List[str], List[str]]:
        """
        Validate multiple targets

        Args:
            targets: List of targets to validate

        Returns:
            Tuple of (valid_targets, invalid_targets)
        """
        valid = []
        invalid = []

        for target in targets:
            if self.is_in_scope(target):
                valid.append(target)
            else:
                invalid.append(target)

        return valid, invalid

    def add_to_scope(self, target: str):
        """
        Add target to authorized scope

        Args:
            target: IP/CIDR to add
        """
        try:
            network = ipaddress.ip_network(target, strict=False)
            self.authorized_networks.add(network)
            self.logger.info(f"Added to scope: {network}")

        except ValueError:
            try:
                host = ipaddress.ip_address(target)
                self.authorized_hosts.add(host)
                self.logger.info(f"Added to scope: {host}")

            except ValueError:
                self.logger.error(f"Invalid target: {target}")

    def remove_from_scope(self, target: str):
        """
        Remove target from authorized scope

        Args:
            target: IP/CIDR to remove
        """
        try:
            network = ipaddress.ip_network(target, strict=False)
            self.authorized_networks.discard(network)

        except ValueError:
            try:
                host = ipaddress.ip_address(target)
                self.authorized_hosts.discard(host)

            except ValueError:
                pass

    def get_scope(self) -> List[str]:
        """Get current authorized scope"""
        scope = []
        scope.extend(str(net) for net in self.authorized_networks)
        scope.extend(str(host) for host in self.authorized_hosts)
        return scope
