"""
Application-Level Watchdog Service for MEDUSA CLI

Monitors the health of the MEDUSA API and detects "zombie" states where
the process is alive but the logic is stuck (e.g., infinite loops, deadlocks).

Key Features:
- Regular health endpoint pings
- State update timestamp monitoring
- Alert and restart on stuck operations
- Docker-friendly logging and exit codes
"""

import asyncio
import sys
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import logging
import httpx
from rich.console import Console

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)
console = Console(stderr=True)


class WatchdogConfig:
    """Configuration for the Watchdog Service"""

    def __init__(
        self,
        api_base_url: str = "http://localhost:8000",
        health_check_interval: int = 30,  # seconds
        stuck_threshold: int = 600,  # 10 minutes in seconds
        max_consecutive_failures: int = 3,
        request_timeout: int = 10,  # seconds
        enable_auto_restart: bool = False,  # Cautious default
    ):
        self.api_base_url = api_base_url.rstrip("/")
        self.health_check_interval = health_check_interval
        self.stuck_threshold = stuck_threshold
        self.max_consecutive_failures = max_consecutive_failures
        self.request_timeout = request_timeout
        self.enable_auto_restart = enable_auto_restart

    @classmethod
    def from_env(cls) -> "WatchdogConfig":
        """Load configuration from environment variables"""
        import os
        return cls(
            api_base_url=os.getenv("MEDUSA_API_URL", "http://localhost:8000"),
            health_check_interval=int(os.getenv("WATCHDOG_CHECK_INTERVAL", "30")),
            stuck_threshold=int(os.getenv("WATCHDOG_STUCK_THRESHOLD", "600")),
            max_consecutive_failures=int(os.getenv("WATCHDOG_MAX_FAILURES", "3")),
            request_timeout=int(os.getenv("WATCHDOG_REQUEST_TIMEOUT", "10")),
            enable_auto_restart=os.getenv("WATCHDOG_AUTO_RESTART", "false").lower() == "true",
        )


class WatchdogService:
    """
    Application-Level Watchdog Service

    Monitors the MEDUSA API for:
    1. Health endpoint availability
    2. Stuck operations (zombie states)
    3. Logic deadlocks
    """

    def __init__(self, config: Optional[WatchdogConfig] = None):
        self.config = config or WatchdogConfig()
        self.consecutive_failures = 0
        self.last_successful_check = datetime.now()
        self.running = False

        logger.info(f"Watchdog initialized: {self.config.api_base_url}")
        logger.info(f"Check interval: {self.config.health_check_interval}s")
        logger.info(f"Stuck threshold: {self.config.stuck_threshold}s")
        logger.info(f"Auto-restart: {self.config.enable_auto_restart}")

    async def check_health(self) -> Dict[str, Any]:
        """
        Check the /health endpoint

        Returns:
            Dict with health status or error information
        """
        try:
            async with httpx.AsyncClient(timeout=self.config.request_timeout) as client:
                response = await client.get(f"{self.config.api_base_url}/health")
                response.raise_for_status()
                return {
                    "success": True,
                    "status_code": response.status_code,
                    "data": response.json(),
                    "timestamp": datetime.now()
                }
        except httpx.TimeoutException as e:
            logger.error(f"Health check timeout: {e}")
            return {
                "success": False,
                "error": "timeout",
                "message": str(e),
                "timestamp": datetime.now()
            }
        except httpx.HTTPStatusError as e:
            logger.error(f"Health check HTTP error: {e.response.status_code}")
            return {
                "success": False,
                "error": "http_error",
                "status_code": e.response.status_code,
                "message": str(e),
                "timestamp": datetime.now()
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "success": False,
                "error": "unknown",
                "message": str(e),
                "timestamp": datetime.now()
            }

    async def check_operation_state(self, operation_id: str) -> Dict[str, Any]:
        """
        Check if an operation is stuck (zombie state)

        Args:
            operation_id: The operation ID to monitor

        Returns:
            Dict with operation status and stuck detection
        """
        try:
            async with httpx.AsyncClient(timeout=self.config.request_timeout) as client:
                # Get operation status
                response = await client.get(
                    f"{self.config.api_base_url}/api/operations/{operation_id}/status"
                )
                response.raise_for_status()
                data = response.json()

                # Extract relevant fields
                status = data.get("status", "UNKNOWN")
                last_update_str = data.get("last_state_update_timestamp")

                if not last_update_str:
                    logger.warning(f"No last_state_update_timestamp for operation {operation_id}")
                    return {
                        "success": True,
                        "operation_id": operation_id,
                        "status": status,
                        "is_stuck": False,
                        "reason": "no_timestamp",
                        "timestamp": datetime.now()
                    }

                # Parse timestamp
                try:
                    last_update = datetime.fromisoformat(last_update_str.replace("Z", "+00:00"))
                except Exception as e:
                    logger.error(f"Failed to parse timestamp {last_update_str}: {e}")
                    return {
                        "success": True,
                        "operation_id": operation_id,
                        "status": status,
                        "is_stuck": False,
                        "reason": "invalid_timestamp",
                        "timestamp": datetime.now()
                    }

                # Calculate time since last update
                now = datetime.now(last_update.tzinfo)
                time_since_update = (now - last_update).total_seconds()

                # Check for stuck state
                is_stuck = (
                    status == "RUNNING" and
                    time_since_update > self.config.stuck_threshold
                )

                return {
                    "success": True,
                    "operation_id": operation_id,
                    "status": status,
                    "last_update": last_update_str,
                    "time_since_update": time_since_update,
                    "is_stuck": is_stuck,
                    "threshold": self.config.stuck_threshold,
                    "timestamp": datetime.now()
                }

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning(f"Operation {operation_id} not found")
                return {
                    "success": False,
                    "error": "not_found",
                    "operation_id": operation_id,
                    "timestamp": datetime.now()
                }
            logger.error(f"Operation state check HTTP error: {e.response.status_code}")
            return {
                "success": False,
                "error": "http_error",
                "status_code": e.response.status_code,
                "timestamp": datetime.now()
            }
        except Exception as e:
            logger.error(f"Operation state check failed: {e}")
            return {
                "success": False,
                "error": "unknown",
                "message": str(e),
                "timestamp": datetime.now()
            }

    async def get_running_operations(self) -> list[str]:
        """
        Get list of running operation IDs

        Returns:
            List of operation IDs currently in RUNNING state
        """
        try:
            async with httpx.AsyncClient(timeout=self.config.request_timeout) as client:
                response = await client.get(
                    f"{self.config.api_base_url}/api/operations",
                    params={"status": "RUNNING"}
                )
                response.raise_for_status()
                operations = response.json()

                return [op["id"] for op in operations if op.get("status") == "RUNNING"]

        except Exception as e:
            logger.error(f"Failed to get running operations: {e}")
            return []

    def handle_health_failure(self, check_result: Dict[str, Any]):
        """
        Handle a failed health check

        Args:
            check_result: Result from check_health()
        """
        self.consecutive_failures += 1

        logger.error(
            f"Health check failed ({self.consecutive_failures}/{self.config.max_consecutive_failures}): "
            f"{check_result.get('error', 'unknown')}"
        )

        if self.consecutive_failures >= self.config.max_consecutive_failures:
            console.print(
                f"[bold red]CRITICAL: Health check failed {self.consecutive_failures} times![/bold red]"
            )
            console.print(f"[yellow]Last error: {check_result.get('message', 'Unknown')}[/yellow]")

            if self.config.enable_auto_restart:
                logger.critical("Auto-restart enabled. Exiting with non-zero code for Docker restart.")
                sys.exit(1)
            else:
                logger.error("Auto-restart disabled. Manual intervention required.")

    def handle_stuck_operation(self, operation_id: str, check_result: Dict[str, Any]):
        """
        Handle a stuck operation (zombie state)

        Args:
            operation_id: The stuck operation ID
            check_result: Result from check_operation_state()
        """
        time_stuck = check_result.get("time_since_update", 0)

        logger.critical(
            f"STUCK OPERATION DETECTED: {operation_id} has been stuck for "
            f"{time_stuck:.0f}s (threshold: {self.config.stuck_threshold}s)"
        )

        console.print(
            f"[bold red]ALERT: Operation {operation_id} is stuck![/bold red]"
        )
        console.print(
            f"[yellow]Status: {check_result.get('status')}[/yellow]"
        )
        console.print(
            f"[yellow]Last update: {check_result.get('last_update')}[/yellow]"
        )
        console.print(
            f"[yellow]Time since update: {time_stuck:.0f}s[/yellow]"
        )

        if self.config.enable_auto_restart:
            logger.critical("Auto-restart enabled. Exiting with non-zero code for Docker restart.")
            sys.exit(2)  # Different exit code for stuck vs. health failure
        else:
            logger.error("Auto-restart disabled. Manual intervention required.")

    async def monitor_loop(self, operation_id: Optional[str] = None):
        """
        Main monitoring loop

        Args:
            operation_id: Specific operation to monitor (optional)
                         If None, monitors all running operations
        """
        self.running = True
        logger.info("Watchdog monitoring started")

        if operation_id:
            logger.info(f"Monitoring specific operation: {operation_id}")
        else:
            logger.info("Monitoring all running operations")

        try:
            while self.running:
                # 1. Check API health
                health_result = await self.check_health()

                if not health_result["success"]:
                    self.handle_health_failure(health_result)
                else:
                    # Reset failure counter on success
                    if self.consecutive_failures > 0:
                        logger.info("Health check recovered")
                        self.consecutive_failures = 0

                    self.last_successful_check = datetime.now()
                    logger.debug(f"Health check OK: {health_result['data']}")

                    # 2. Check for stuck operations
                    if operation_id:
                        # Monitor specific operation
                        state_result = await self.check_operation_state(operation_id)

                        if state_result.get("success") and state_result.get("is_stuck"):
                            self.handle_stuck_operation(operation_id, state_result)
                        elif state_result.get("success"):
                            logger.debug(
                                f"Operation {operation_id} OK: "
                                f"{state_result.get('time_since_update', 0):.0f}s since update"
                            )
                    else:
                        # Monitor all running operations
                        running_ops = await self.get_running_operations()

                        if running_ops:
                            logger.debug(f"Monitoring {len(running_ops)} running operations")

                            for op_id in running_ops:
                                state_result = await self.check_operation_state(op_id)

                                if state_result.get("success") and state_result.get("is_stuck"):
                                    self.handle_stuck_operation(op_id, state_result)
                        else:
                            logger.debug("No running operations to monitor")

                # Wait for next check
                await asyncio.sleep(self.config.health_check_interval)

        except asyncio.CancelledError:
            logger.info("Watchdog monitoring cancelled")
            self.running = False
        except KeyboardInterrupt:
            logger.info("Watchdog monitoring interrupted by user")
            self.running = False
        except Exception as e:
            logger.critical(f"Watchdog monitoring crashed: {e}", exc_info=True)
            if self.config.enable_auto_restart:
                sys.exit(3)  # Different exit code for watchdog crash
            raise

    def stop(self):
        """Stop the monitoring loop"""
        logger.info("Stopping watchdog monitoring")
        self.running = False


async def run_watchdog(
    api_url: str = "http://localhost:8000",
    operation_id: Optional[str] = None,
    check_interval: int = 30,
    stuck_threshold: int = 600,
    auto_restart: bool = False
):
    """
    Convenience function to run the watchdog

    Args:
        api_url: Base URL of the MEDUSA API
        operation_id: Specific operation to monitor (optional)
        check_interval: Seconds between health checks
        stuck_threshold: Seconds before considering operation stuck
        auto_restart: Enable auto-restart on failures
    """
    config = WatchdogConfig(
        api_base_url=api_url,
        health_check_interval=check_interval,
        stuck_threshold=stuck_threshold,
        enable_auto_restart=auto_restart
    )

    watchdog = WatchdogService(config)
    await watchdog.monitor_loop(operation_id=operation_id)


if __name__ == "__main__":
    # CLI entry point for standalone watchdog service
    import argparse

    parser = argparse.ArgumentParser(description="MEDUSA Application Watchdog")
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="MEDUSA API base URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--operation-id",
        help="Specific operation ID to monitor (optional)"
    )
    parser.add_argument(
        "--check-interval",
        type=int,
        default=30,
        help="Seconds between health checks (default: 30)"
    )
    parser.add_argument(
        "--stuck-threshold",
        type=int,
        default=600,
        help="Seconds before considering operation stuck (default: 600)"
    )
    parser.add_argument(
        "--auto-restart",
        action="store_true",
        help="Enable auto-restart on failures (exits with non-zero code)"
    )
    parser.add_argument(
        "--env-config",
        action="store_true",
        help="Load configuration from environment variables"
    )

    args = parser.parse_args()

    if args.env_config:
        config = WatchdogConfig.from_env()
        watchdog = WatchdogService(config)
    else:
        config = WatchdogConfig(
            api_base_url=args.api_url,
            health_check_interval=args.check_interval,
            stuck_threshold=args.stuck_threshold,
            enable_auto_restart=args.auto_restart
        )
        watchdog = WatchdogService(config)

    try:
        asyncio.run(watchdog.monitor_loop(operation_id=args.operation_id))
    except KeyboardInterrupt:
        console.print("\n[yellow]Watchdog stopped by user[/yellow]")
        sys.exit(0)