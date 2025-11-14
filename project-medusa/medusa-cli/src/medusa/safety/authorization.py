"""
Authorization Manager
Manages authorization for high-risk operations
"""

from typing import Dict, Any, Optional, Callable
from enum import Enum
import logging
from pathlib import Path


class RiskLevel(Enum):
    """Risk levels for operations"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthorizationManager:
    """
    Manages authorization for operations

    Requires explicit approval for high-risk actions
    """

    def __init__(
        self,
        require_authorization: bool = True,
        auto_approve_level: Optional[RiskLevel] = None,
        approval_callback: Optional[Callable] = None
    ):
        """
        Initialize Authorization Manager

        Args:
            require_authorization: Require authorization
            auto_approve_level: Auto-approve up to this risk level
            approval_callback: Custom approval callback
        """
        self.require_authorization = require_authorization
        self.auto_approve_level = auto_approve_level or RiskLevel.LOW
        self.approval_callback = approval_callback
        self.logger = logging.getLogger(__name__)

        # Track approvals
        self.approved_operations: Dict[str, bool] = {}

    def request_authorization(
        self,
        operation: str,
        risk_level: RiskLevel,
        details: Dict[str, Any]
    ) -> bool:
        """
        Request authorization for an operation

        Args:
            operation: Operation name
            risk_level: Risk level
            details: Operation details

        Returns:
            True if authorized
        """
        # Check if authorization is required
        if not self.require_authorization:
            self.logger.info(f"Authorization bypassed for: {operation}")
            return True

        # Check if auto-approved
        if self._is_auto_approved(risk_level):
            self.logger.info(f"Auto-approved {risk_level.value} operation: {operation}")
            return True

        # Check if already approved
        operation_key = self._get_operation_key(operation, details)
        if operation_key in self.approved_operations:
            return self.approved_operations[operation_key]

        # Request approval
        approved = self._request_approval(operation, risk_level, details)

        # Cache result
        self.approved_operations[operation_key] = approved

        return approved

    def _is_auto_approved(self, risk_level: RiskLevel) -> bool:
        """Check if risk level is auto-approved"""
        risk_order = {
            RiskLevel.INFO: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }

        return risk_order[risk_level] <= risk_order[self.auto_approve_level]

    def _request_approval(
        self,
        operation: str,
        risk_level: RiskLevel,
        details: Dict[str, Any]
    ) -> bool:
        """Request approval from user"""
        if self.approval_callback:
            return self.approval_callback(operation, risk_level, details)

        # Default: CLI prompt
        print(f"\n{'='*60}")
        print(f"AUTHORIZATION REQUIRED")
        print(f"{'='*60}")
        print(f"Operation: {operation}")
        print(f"Risk Level: {risk_level.value.upper()}")
        print(f"\nDetails:")
        for key, value in details.items():
            print(f"  {key}: {value}")
        print(f"{'='*60}")

        response = input("Approve this operation? (yes/no): ").strip().lower()

        approved = response in ["yes", "y"]

        if approved:
            self.logger.warning(f"Operation APPROVED: {operation}")
        else:
            self.logger.warning(f"Operation DENIED: {operation}")

        return approved

    def _get_operation_key(self, operation: str, details: Dict[str, Any]) -> str:
        """Generate unique key for operation"""
        import hashlib
        import json

        details_str = json.dumps(details, sort_keys=True)
        key = f"{operation}:{details_str}"

        return hashlib.md5(key.encode()).hexdigest()

    def clear_approvals(self):
        """Clear all cached approvals"""
        self.approved_operations.clear()
        self.logger.info("Cleared all cached approvals")

    def set_auto_approve_level(self, level: RiskLevel):
        """Set auto-approve level"""
        self.auto_approve_level = level
        self.logger.info(f"Auto-approve level set to: {level.value}")
