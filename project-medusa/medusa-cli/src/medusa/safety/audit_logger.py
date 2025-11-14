"""
Audit Logger
Immutable audit logging for all operations
"""

from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import logging
import json
import hashlib


class AuditLogger:
    """
    Immutable audit logger for security operations

    Features:
    - Immutable log entries
    - Cryptographic integrity
    - Structured logging
    - Compliance ready
    """

    def __init__(self, log_path: Optional[Path] = None):
        """
        Initialize Audit Logger

        Args:
            log_path: Path to audit log file
        """
        self.log_path = log_path or Path.home() / ".medusa" / "audit.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger(__name__)

        # Previous entry hash for chain integrity
        self.previous_hash = self._get_last_hash()

    def log_operation(
        self,
        operation_type: str,
        action: str,
        target: Optional[str] = None,
        user: Optional[str] = None,
        risk_level: str = "medium",
        status: str = "initiated",
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Log an operation

        Args:
            operation_type: Type of operation (scan, exploit, etc.)
            action: Specific action taken
            target: Target IP/hostname
            user: User performing action
            risk_level: Risk level
            status: Operation status
            details: Additional details
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "operation_type": operation_type,
            "action": action,
            "target": target,
            "user": user or self._get_current_user(),
            "risk_level": risk_level,
            "status": status,
            "details": details or {},
            "previous_hash": self.previous_hash,
        }

        # Calculate entry hash
        entry_hash = self._calculate_hash(entry)
        entry["hash"] = entry_hash

        # Write to log
        self._write_entry(entry)

        # Update previous hash
        self.previous_hash = entry_hash

        self.logger.info(f"Audit log: {operation_type}/{action} - {status}")

    def log_scan(
        self,
        target: str,
        scan_type: str,
        status: str = "initiated",
        details: Optional[Dict[str, Any]] = None
    ):
        """Log a scan operation"""
        self.log_operation(
            operation_type="scan",
            action=scan_type,
            target=target,
            risk_level="low",
            status=status,
            details=details
        )

    def log_exploit(
        self,
        target: str,
        exploit_name: str,
        status: str = "initiated",
        details: Optional[Dict[str, Any]] = None
    ):
        """Log an exploitation attempt"""
        self.log_operation(
            operation_type="exploit",
            action=exploit_name,
            target=target,
            risk_level="high",
            status=status,
            details=details
        )

    def log_post_exploit(
        self,
        target: str,
        module_name: str,
        status: str = "initiated",
        details: Optional[Dict[str, Any]] = None
    ):
        """Log post-exploitation activity"""
        self.log_operation(
            operation_type="post_exploit",
            action=module_name,
            target=target,
            risk_level="high",
            status=status,
            details=details
        )

    def log_data_exfiltration(
        self,
        target: str,
        data_type: str,
        status: str = "initiated",
        details: Optional[Dict[str, Any]] = None
    ):
        """Log data exfiltration"""
        self.log_operation(
            operation_type="exfiltration",
            action=data_type,
            target=target,
            risk_level="critical",
            status=status,
            details=details
        )

    def log_authorization(
        self,
        operation: str,
        authorized: bool,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log authorization decision"""
        self.log_operation(
            operation_type="authorization",
            action=operation,
            risk_level="medium",
            status="approved" if authorized else "denied",
            details=details
        )

    def verify_integrity(self) -> bool:
        """
        Verify audit log integrity

        Returns:
            True if log is intact
        """
        if not self.log_path.exists():
            self.logger.warning("Audit log does not exist")
            return True  # Empty log is valid

        try:
            with open(self.log_path) as f:
                entries = [json.loads(line) for line in f if line.strip()]

            if not entries:
                return True

            # Verify chain
            previous_hash = None
            for entry in entries:
                # Check previous hash
                if entry.get("previous_hash") != previous_hash:
                    self.logger.error(
                        f"Integrity violation: Invalid previous_hash in entry {entry.get('timestamp')}"
                    )
                    return False

                # Verify entry hash
                entry_hash = entry.pop("hash")
                calculated_hash = self._calculate_hash(entry)

                if entry_hash != calculated_hash:
                    self.logger.error(
                        f"Integrity violation: Invalid hash in entry {entry.get('timestamp')}"
                    )
                    return False

                previous_hash = entry_hash

            self.logger.info("Audit log integrity verified")
            return True

        except Exception as e:
            self.logger.error(f"Failed to verify integrity: {e}")
            return False

    def get_recent_entries(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent audit log entries

        Args:
            limit: Maximum number of entries

        Returns:
            List of entries
        """
        if not self.log_path.exists():
            return []

        try:
            with open(self.log_path) as f:
                lines = f.readlines()

            entries = [json.loads(line) for line in lines[-limit:] if line.strip()]
            return entries

        except Exception as e:
            self.logger.error(f"Failed to read entries: {e}")
            return []

    def _write_entry(self, entry: Dict[str, Any]):
        """Write entry to log file"""
        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(entry) + "\n")

        except Exception as e:
            self.logger.error(f"Failed to write audit log: {e}")

    def _calculate_hash(self, entry: Dict[str, Any]) -> str:
        """Calculate cryptographic hash of entry"""
        # Create copy without hash field
        entry_copy = {k: v for k, v in entry.items() if k != "hash"}

        # Convert to JSON (sorted keys for consistency)
        entry_json = json.dumps(entry_copy, sort_keys=True)

        # Calculate SHA-256 hash
        return hashlib.sha256(entry_json.encode()).hexdigest()

    def _get_last_hash(self) -> Optional[str]:
        """Get hash of last entry"""
        if not self.log_path.exists():
            return None

        try:
            with open(self.log_path) as f:
                lines = f.readlines()

            if not lines:
                return None

            last_entry = json.loads(lines[-1])
            return last_entry.get("hash")

        except Exception:
            return None

    def _get_current_user(self) -> str:
        """Get current system user"""
        import os
        return os.getenv("USER", "unknown")
