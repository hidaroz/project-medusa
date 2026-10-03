"""
Checkpointer initialization and management for LangGraph state persistence.

This module provides utilities for creating and managing LangGraph checkpointers,
enabling crash recovery and pause/resume functionality.
"""

import os
import logging
from typing import Optional
from langgraph.checkpoint.postgres import AsyncPostgresSaver

logger = logging.getLogger(__name__)


async def create_postgres_checkpointer(
    connection_string: Optional[str] = None
) -> Optional[AsyncPostgresSaver]:
    """
    Create a PostgreSQL-backed checkpointer for LangGraph.

    Args:
        connection_string: PostgreSQL connection string.
                          If not provided, attempts to read from environment
                          variable POSTGRES_CONNECTION_STRING or construct
                          from individual components.

    Returns:
        AsyncPostgresSaver instance or None if configuration is missing

    Environment Variables (if connection_string not provided):
        - POSTGRES_CONNECTION_STRING: Full connection string
        - POSTGRES_HOST: Database host (default: localhost)
        - POSTGRES_PORT: Database port (default: 5432)
        - POSTGRES_DB: Database name (default: medusa)
        - POSTGRES_USER: Database user (default: medusa)
        - POSTGRES_PASSWORD: Database password (required)

    Example:
        >>> checkpointer = await create_postgres_checkpointer()
        >>> graph = create_medusa_graph(checkpointer=checkpointer)
    """
    # Try to get connection string
    if not connection_string:
        connection_string = os.getenv("POSTGRES_CONNECTION_STRING")

    # If still no connection string, try to construct from components
    if not connection_string:
        host = os.getenv("POSTGRES_HOST", "localhost")
        port = os.getenv("POSTGRES_PORT", "5432")
        database = os.getenv("POSTGRES_DB", "medusa")
        user = os.getenv("POSTGRES_USER", "medusa")
        password = os.getenv("POSTGRES_PASSWORD")

        if not password:
            logger.warning(
                "No PostgreSQL password provided. Checkpointing disabled. "
                "Set POSTGRES_PASSWORD or POSTGRES_CONNECTION_STRING environment variable."
            )
            return None

        connection_string = (
            f"postgresql://{user}:{password}@{host}:{port}/{database}"
        )

    try:
        # Create the checkpointer
        checkpointer = AsyncPostgresSaver.from_conn_string(connection_string)

        # Setup tables (creates checkpoint tables if they don't exist)
        await checkpointer.setup()

        logger.info("PostgreSQL checkpointer initialized successfully")
        return checkpointer

    except Exception as e:
        logger.error(f"Failed to initialize PostgreSQL checkpointer: {e}")
        logger.info("Continuing without checkpointing. Operations cannot be resumed.")
        return None


async def cleanup_checkpointer(checkpointer: Optional[AsyncPostgresSaver]) -> None:
    """
    Clean up checkpointer resources.

    Args:
        checkpointer: The checkpointer to clean up
    """
    if checkpointer:
        try:
            # Close any open connections
            # Note: AsyncPostgresSaver should handle this automatically,
            # but we'll be explicit
            await checkpointer.aclose()
            logger.info("Checkpointer cleaned up successfully")
        except Exception as e:
            logger.error(f"Error cleaning up checkpointer: {e}")


def get_thread_id(operation_id: str, session_id: Optional[str] = None) -> str:
    """
    Generate a thread ID for LangGraph checkpointing.

    The thread ID is used by LangGraph to identify and resume operations.
    Using the same thread ID will resume from the last checkpoint.

    Args:
        operation_id: Unique operation identifier
        session_id: Optional session identifier for grouping operations

    Returns:
        Thread ID string

    Example:
        >>> thread_id = get_thread_id("pentest-001", "session-abc")
        >>> config = {"configurable": {"thread_id": thread_id}}
        >>> result = await graph.ainvoke(initial_state, config)
    """
    if session_id:
        return f"{session_id}::{operation_id}"
    return operation_id


async def list_checkpoints(
    checkpointer: AsyncPostgresSaver,
    thread_id: Optional[str] = None
) -> list:
    """
    List available checkpoints.

    Args:
        checkpointer: The checkpointer instance
        thread_id: Optional thread ID to filter checkpoints

    Returns:
        List of checkpoint metadata

    Example:
        >>> checkpoints = await list_checkpoints(checkpointer, "pentest-001")
        >>> for cp in checkpoints:
        ...     print(f"Checkpoint at {cp['ts']}")
    """
    try:
        if thread_id:
            config = {"configurable": {"thread_id": thread_id}}
            checkpoints = []
            async for checkpoint in checkpointer.aget_tuple(config):
                checkpoints.append(checkpoint)
            return checkpoints
        else:
            # List all checkpoints (implementation depends on checkpointer API)
            logger.warning("Listing all checkpoints not yet implemented")
            return []
    except Exception as e:
        logger.error(f"Error listing checkpoints: {e}")
        return []


async def get_latest_checkpoint(
    checkpointer: AsyncPostgresSaver,
    thread_id: str
) -> Optional[dict]:
    """
    Get the latest checkpoint for a thread.

    Args:
        checkpointer: The checkpointer instance
        thread_id: Thread ID to look up

    Returns:
        Latest checkpoint data or None if no checkpoint exists

    Example:
        >>> checkpoint = await get_latest_checkpoint(checkpointer, "pentest-001")
        >>> if checkpoint:
        ...     print(f"Can resume from checkpoint at {checkpoint['ts']}")
    """
    try:
        config = {"configurable": {"thread_id": thread_id}}
        checkpoint = await checkpointer.aget(config)
        return checkpoint
    except Exception as e:
        logger.error(f"Error getting checkpoint: {e}")
        return None
