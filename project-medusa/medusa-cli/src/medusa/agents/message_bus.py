"""
Message Bus for inter-agent communication
Enables asynchronous message passing between agents
"""

import asyncio
import logging
from typing import Dict, List, Callable, Awaitable
from collections import defaultdict
from .data_models import AgentMessage


class MessageBus:
    """
    Asynchronous message bus for agent communication

    Features:
    - Publish-subscribe pattern
    - Topic-based routing
    - Broadcast messages
    - Message queuing per agent
    """

    def __init__(self):
        """Initialize message bus"""
        self.subscribers: Dict[str, List[Callable[[AgentMessage], Awaitable[None]]]] = defaultdict(list)
        self.message_history: List[AgentMessage] = []
        self.logger = logging.getLogger(__name__)
        self.max_history = 1000  # Keep last 1000 messages

    def subscribe(
        self,
        agent_name: str,
        callback: Callable[[AgentMessage], Awaitable[None]]
    ):
        """
        Subscribe an agent to receive messages

        Args:
            agent_name: Name of the subscribing agent
            callback: Async function to call when message received
        """
        self.subscribers[agent_name].append(callback)
        self.logger.info(f"Agent '{agent_name}' subscribed to message bus")

    def unsubscribe(self, agent_name: str):
        """
        Unsubscribe an agent from receiving messages

        Args:
            agent_name: Name of the agent to unsubscribe
        """
        if agent_name in self.subscribers:
            del self.subscribers[agent_name]
            self.logger.info(f"Agent '{agent_name}' unsubscribed from message bus")

    async def publish(self, message: AgentMessage):
        """
        Publish a message to the bus

        Args:
            message: AgentMessage to publish
        """
        self.logger.debug(
            f"Publishing message: {message.sender} -> {message.recipient} "
            f"({message.message_type})"
        )

        # Store in history
        self.message_history.append(message)
        if len(self.message_history) > self.max_history:
            self.message_history = self.message_history[-self.max_history:]

        # Deliver message
        if message.recipient == "broadcast":
            # Broadcast to all subscribers except sender
            await self._broadcast(message)
        else:
            # Deliver to specific recipient
            await self._deliver(message)

    async def _broadcast(self, message: AgentMessage):
        """Broadcast message to all agents except sender"""
        tasks = []
        for agent_name, callbacks in self.subscribers.items():
            if agent_name != message.sender:
                for callback in callbacks:
                    tasks.append(callback(message))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _deliver(self, message: AgentMessage):
        """Deliver message to specific recipient"""
        if message.recipient in self.subscribers:
            callbacks = self.subscribers[message.recipient]
            tasks = [callback(message) for callback in callbacks]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        else:
            self.logger.warning(
                f"No subscriber found for recipient: {message.recipient}"
            )

    def get_conversation_history(
        self,
        agent_name: str,
        limit: int = 50
    ) -> List[AgentMessage]:
        """
        Get conversation history for an agent

        Args:
            agent_name: Agent name to get history for
            limit: Maximum messages to return

        Returns:
            List of messages involving the agent
        """
        relevant_messages = [
            msg for msg in self.message_history
            if msg.sender == agent_name or msg.recipient == agent_name or msg.recipient == "broadcast"
        ]
        return relevant_messages[-limit:]

    def get_all_messages(self, limit: int = 100) -> List[AgentMessage]:
        """Get all recent messages"""
        return self.message_history[-limit:]

    def clear_history(self):
        """Clear message history"""
        self.message_history = []
        self.logger.info("Message history cleared")

    def get_stats(self) -> Dict[str, any]:
        """Get message bus statistics"""
        message_types = defaultdict(int)
        for msg in self.message_history:
            message_types[msg.message_type] += 1

        return {
            "total_messages": len(self.message_history),
            "subscribers": len(self.subscribers),
            "message_types": dict(message_types)
        }
