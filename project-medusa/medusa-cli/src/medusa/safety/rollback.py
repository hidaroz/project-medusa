"""
Rollback Manager
Handles automatic rollback of failed operations
"""

from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
import logging
import json


class RollbackManager:
    """
    Manages rollback of failed operations

    Tracks changes and can revert them on failure
    """

    def __init__(self, auto_rollback: bool = True):
        """
        Initialize Rollback Manager

        Args:
            auto_rollback: Automatically rollback on failure
        """
        self.auto_rollback = auto_rollback
        self.logger = logging.getLogger(__name__)

        # Stack of operations
        self.operation_stack: List[Dict[str, Any]] = []

    def register_operation(
        self,
        operation_id: str,
        operation_type: str,
        rollback_func: Callable,
        context: Dict[str, Any]
    ):
        """
        Register an operation for potential rollback

        Args:
            operation_id: Unique operation ID
            operation_type: Type of operation
            rollback_func: Function to call for rollback
            context: Context data for rollback
        """
        operation = {
            "id": operation_id,
            "type": operation_type,
            "rollback_func": rollback_func,
            "context": context,
            "timestamp": datetime.now().isoformat(),
        }

        self.operation_stack.append(operation)
        self.logger.debug(f"Registered operation for rollback: {operation_id}")

    def rollback_last(self) -> bool:
        """
        Rollback the last operation

        Returns:
            True if rollback successful
        """
        if not self.operation_stack:
            self.logger.warning("No operations to rollback")
            return False

        operation = self.operation_stack.pop()

        return self._execute_rollback(operation)

    def rollback_all(self) -> bool:
        """
        Rollback all operations in reverse order

        Returns:
            True if all rollbacks successful
        """
        success = True

        while self.operation_stack:
            if not self.rollback_last():
                success = False

        return success

    def rollback_operation(self, operation_id: str) -> bool:
        """
        Rollback a specific operation

        Args:
            operation_id: Operation ID to rollback

        Returns:
            True if rollback successful
        """
        # Find operation
        operation = None
        for i, op in enumerate(self.operation_stack):
            if op["id"] == operation_id:
                operation = self.operation_stack.pop(i)
                break

        if not operation:
            self.logger.error(f"Operation not found: {operation_id}")
            return False

        return self._execute_rollback(operation)

    def _execute_rollback(self, operation: Dict[str, Any]) -> bool:
        """Execute rollback for an operation"""
        try:
            self.logger.warning(f"Rolling back operation: {operation['id']}")

            rollback_func = operation["rollback_func"]
            context = operation["context"]

            # Execute rollback
            rollback_func(context)

            self.logger.info(f"Rollback successful: {operation['id']}")
            return True

        except Exception as e:
            self.logger.error(f"Rollback failed for {operation['id']}: {e}")
            return False

    def clear(self):
        """Clear operation stack"""
        self.operation_stack.clear()
        self.logger.info("Cleared rollback stack")

    def get_operations(self) -> List[Dict[str, Any]]:
        """Get list of registered operations"""
        return [
            {
                "id": op["id"],
                "type": op["type"],
                "timestamp": op["timestamp"],
            }
            for op in self.operation_stack
        ]
