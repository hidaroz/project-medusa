"""
Operation Manager - Handles graceful shutdown and operation lifecycle.

This module provides signal handling and state management to ensure that
MEDUSA operations can be interrupted gracefully and resumed from checkpoints.
"""

import asyncio
import signal
import logging
from typing import Optional, Callable
from datetime import datetime

logger = logging.getLogger(__name__)


class OperationManager:
    """
    Manages operation lifecycle and graceful shutdown.

    Features:
    - Signal handling for SIGINT (Ctrl+C) and SIGTERM
    - Graceful shutdown coordination with LangGraph checkpointing
    - Operation state tracking
    """

    def __init__(self, operation_id: str):
        """
        Initialize the Operation Manager.

        Args:
            operation_id: Unique identifier for this operation
        """
        self.operation_id = operation_id
        self.shutdown_requested = False
        self.pause_requested = False
        self.current_node: Optional[str] = None
        self.shutdown_callback: Optional[Callable] = None
        self._original_handlers = {}

        logger.info(f"OperationManager initialized for operation: {operation_id}")

    def setup_signal_handlers(self) -> None:
        """
        Register signal handlers for graceful shutdown.

        Handles:
        - SIGINT (Ctrl+C): Request graceful pause
        - SIGTERM: Request graceful shutdown
        """
        # Store original handlers for cleanup
        self._original_handlers[signal.SIGINT] = signal.getsignal(signal.SIGINT)
        self._original_handlers[signal.SIGTERM] = signal.getsignal(signal.SIGTERM)

        # Register new handlers
        signal.signal(signal.SIGINT, self._handle_sigint)
        signal.signal(signal.SIGTERM, self._handle_sigterm)

        logger.info("Signal handlers registered")

    def _handle_sigint(self, signum, frame):
        """
        Handle SIGINT (Ctrl+C) - Request graceful pause.

        On first SIGINT: Request pause (allows current node to finish)
        On second SIGINT: Force shutdown
        """
        if not self.shutdown_requested:
            print("\n🛑 Graceful shutdown requested. Current node will finish and state will be saved...")
            print("   Press Ctrl+C again to force quit (not recommended)")
            self.shutdown_requested = True
            self.pause_requested = True
            logger.warning(f"SIGINT received - graceful shutdown requested for operation {self.operation_id}")
        else:
            print("\n⚠️  Force quit requested - state may not be saved!")
            logger.error(f"Force quit - operation {self.operation_id} may have incomplete state")
            # Restore original handler and re-raise
            signal.signal(signal.SIGINT, self._original_handlers[signal.SIGINT])
            raise KeyboardInterrupt()

    def _handle_sigterm(self, signum, frame):
        """
        Handle SIGTERM - Request graceful shutdown.
        """
        print("\n🛑 Termination signal received. Gracefully shutting down...")
        self.shutdown_requested = True
        self.pause_requested = True
        logger.warning(f"SIGTERM received - graceful shutdown requested for operation {self.operation_id}")

    def should_continue(self, current_node: str) -> bool:
        """
        Check if the operation should continue execution.

        This method should be called by the Supervisor before routing
        to the next node.

        Args:
            current_node: The current node name

        Returns:
            True if operation should continue, False if it should pause/stop
        """
        self.current_node = current_node

        if self.shutdown_requested or self.pause_requested:
            logger.info(
                f"Operation {self.operation_id} pausing at node '{current_node}' "
                f"due to shutdown request"
            )
            return False

        return True

    def set_shutdown_callback(self, callback: Callable) -> None:
        """
        Register a callback to be called before shutdown.

        Args:
            callback: Async function to call before shutdown
        """
        self.shutdown_callback = callback

    async def cleanup(self) -> None:
        """
        Perform cleanup operations before shutdown.

        Calls the shutdown callback if registered and restores
        original signal handlers.
        """
        logger.info(f"Cleaning up operation {self.operation_id}")

        # Call shutdown callback if registered
        if self.shutdown_callback:
            try:
                await self.shutdown_callback()
            except Exception as e:
                logger.error(f"Error in shutdown callback: {e}")

        # Restore original signal handlers
        for sig, handler in self._original_handlers.items():
            signal.signal(sig, handler)

        logger.info("Operation cleanup complete")

    def get_status(self) -> dict:
        """
        Get current operation status.

        Returns:
            Dictionary containing operation status information
        """
        return {
            "operation_id": self.operation_id,
            "shutdown_requested": self.shutdown_requested,
            "pause_requested": self.pause_requested,
            "current_node": self.current_node,
            "timestamp": datetime.utcnow().isoformat()
        }

    def restore_handlers(self) -> None:
        """
        Restore original signal handlers.

        Should be called when the operation completes normally.
        """
        for sig, handler in self._original_handlers.items():
            signal.signal(sig, handler)

        logger.info("Original signal handlers restored")


# Global instance for easy access (optional pattern)
_current_operation_manager: Optional[OperationManager] = None


def get_current_operation_manager() -> Optional[OperationManager]:
    """
    Get the current global operation manager instance.

    Returns:
        Current OperationManager instance or None
    """
    return _current_operation_manager


def set_current_operation_manager(manager: Optional[OperationManager]) -> None:
    """
    Set the global operation manager instance.

    Args:
        manager: OperationManager instance to set as current
    """
    global _current_operation_manager
    _current_operation_manager = manager
