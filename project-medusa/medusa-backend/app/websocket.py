"""
WebSocket connection and message handling
"""

import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        logger.info("ConnectionManager initialized")
    
    async def connect(self, websocket: WebSocket, session_id: str):
        """Accept and store WebSocket connection"""
        await websocket.accept()
        self.active_connections[session_id] = websocket
        logger.info(f"WebSocket connected: {session_id} (total: {len(self.active_connections)})")
    
    def disconnect(self, session_id: str):
        """Remove WebSocket connection"""
        if session_id in self.active_connections:
            del self.active_connections[session_id]
            logger.info(f"WebSocket disconnected: {session_id} (remaining: {len(self.active_connections)})")
    
    async def send_message(self, session_id: str, message: Dict[str, Any]):
        """Send message to specific session"""
        if session_id in self.active_connections:
            try:
                await self.active_connections[session_id].send_json(message)
                logger.debug(f"Sent message to {session_id}: {message.get('type')}")
            except Exception as e:
                logger.error(f"Failed to send message to {session_id}: {e}")
                self.disconnect(session_id)
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected sessions"""
        disconnected = []
        for session_id, websocket in self.active_connections.items():
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Failed to broadcast to {session_id}: {e}")
                disconnected.append(session_id)
        
        # Clean up disconnected clients
        for session_id in disconnected:
            self.disconnect(session_id)


async def handle_websocket_message(
    session_id: str,
    message: Dict[str, Any],
    session_manager,
    connection_manager: ConnectionManager
) -> Optional[Dict[str, Any]]:
    """
    Handle incoming WebSocket messages
    
    Message types:
    - ping: Health check
    - start_scan: Start a penetration test
    - command: Execute a command
    - approval_response: Respond to approval gate
    - stop: Stop current operation
    """
    msg_type = message.get("type")
    data = message.get("data", {})
    
    logger.info(f"Handling message type '{msg_type}' for session {session_id}")
    
    try:
        if msg_type == "ping":
            return handle_ping(session_id)
        
        elif msg_type == "start_scan":
            return await handle_start_scan(session_id, data, session_manager, connection_manager)
        
        elif msg_type == "command":
            return await handle_command(session_id, data, session_manager, connection_manager)
        
        elif msg_type == "approval_response":
            return await handle_approval_response(session_id, data, session_manager)
        
        elif msg_type == "stop":
            return await handle_stop(session_id, session_manager)
        
        else:
            logger.warning(f"Unknown message type: {msg_type}")
            return {
                "type": "error",
                "error": f"Unknown message type: {msg_type}",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    except Exception as e:
        logger.error(f"Error handling message: {e}", exc_info=True)
        return {
            "type": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


def handle_ping(session_id: str) -> Dict[str, Any]:
    """Handle ping message"""
    return {
        "type": "pong",
        "session_id": session_id,
        "timestamp": datetime.utcnow().isoformat()
    }


async def handle_start_scan(
    session_id: str,
    data: Dict[str, Any],
    session_manager,
    connection_manager: ConnectionManager
) -> Dict[str, Any]:
    """Handle start scan request"""
    target = data.get("target")
    mode = data.get("mode", "observe")
    
    logger.info(f"Starting scan for session {session_id}: target={target}, mode={mode}")
    
    # Update session
    session = session_manager.get_session(session_id)
    if not session:
        return {
            "type": "error",
            "error": "Session not found",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    session.target = target
    session.mode = mode
    session_manager.update_session_status(session_id, "running")
    session_manager.update_phase(session_id, "initialization")
    
    # Send acknowledgment
    await connection_manager.send_message(session_id, {
        "type": "scan_started",
        "session_id": session_id,
        "target": target,
        "mode": mode,
        "timestamp": datetime.utcnow().isoformat()
    })
    
    # Start scan in background
    asyncio.create_task(
        run_scan_simulation(session_id, target, mode, session_manager, connection_manager)
    )
    
    return None  # Already sent response


async def handle_command(
    session_id: str,
    data: Dict[str, Any],
    session_manager,
    connection_manager: ConnectionManager
) -> Dict[str, Any]:
    """Handle command execution"""
    command = data.get("command", "")
    
    logger.info(f"Executing command for session {session_id}: {command}")
    
    # Add to history
    session_manager.add_history_entry(session_id, {
        "type": "command",
        "command": command
    })
    
    # Send output simulation
    await connection_manager.send_message(session_id, {
        "type": "command_output",
        "command": command,
        "output": f"Executing: {command}\n[This is a simulated output - CLI integration pending]",
        "timestamp": datetime.utcnow().isoformat()
    })
    
    return None


async def handle_approval_response(
    session_id: str,
    data: Dict[str, Any],
    session_manager
) -> Dict[str, Any]:
    """Handle approval gate response"""
    approved = data.get("approved", False)
    action_id = data.get("action_id")
    
    logger.info(f"Approval response for session {session_id}: action={action_id}, approved={approved}")
    
    # Add to history
    session_manager.add_history_entry(session_id, {
        "type": "approval",
        "action_id": action_id,
        "approved": approved
    })
    
    return {
        "type": "approval_recorded",
        "action_id": action_id,
        "approved": approved,
        "timestamp": datetime.utcnow().isoformat()
    }


async def handle_stop(session_id: str, session_manager) -> Dict[str, Any]:
    """Handle stop request"""
    logger.info(f"Stopping scan for session {session_id}")
    
    session_manager.update_session_status(session_id, "paused")
    
    return {
        "type": "scan_stopped",
        "session_id": session_id,
        "timestamp": datetime.utcnow().isoformat()
    }


async def run_scan_simulation(
    session_id: str,
    target: str,
    mode: str,
    session_manager,
    connection_manager: ConnectionManager
):
    """
    Simulate a penetration test scan
    TODO: Replace with actual CLI integration
    """
    phases = ["reconnaissance", "enumeration", "exploitation", "reporting"]
    
    try:
        for phase in phases:
            session = session_manager.get_session(session_id)
            if not session or session.status != "running":
                break
            
            # Update phase
            session_manager.update_phase(session_id, phase)
            
            # Send phase start
            await connection_manager.send_message(session_id, {
                "type": "phase_start",
                "phase": phase,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            # Simulate phase execution
            await asyncio.sleep(2)
            
            # Send terminal output
            await connection_manager.send_message(session_id, {
                "type": "terminal_output",
                "output": f"\n[MEDUSA] Phase: {phase.upper()}\n",
                "timestamp": datetime.utcnow().isoformat()
            })
            
            await asyncio.sleep(1)
            
            # Send terminal output
            await connection_manager.send_message(session_id, {
                "type": "terminal_output",
                "output": f"[MEDUSA] Target: {target}\n",
                "timestamp": datetime.utcnow().isoformat()
            })
            
            await asyncio.sleep(1)
            
            # Add mock finding
            finding = {
                "phase": phase,
                "type": "info",
                "title": f"Phase {phase} completed",
                "severity": "info"
            }
            session_manager.add_finding(session_id, finding)
            
            # Send finding
            await connection_manager.send_message(session_id, {
                "type": "finding",
                "finding": finding,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            # Send phase complete
            await connection_manager.send_message(session_id, {
                "type": "phase_complete",
                "phase": phase,
                "timestamp": datetime.utcnow().isoformat()
            })
        
        # Complete scan
        session_manager.update_session_status(session_id, "completed")
        await connection_manager.send_message(session_id, {
            "type": "scan_complete",
            "session_id": session_id,
            "total_findings": len(session.findings),
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Scan simulation error: {e}", exc_info=True)
        session_manager.update_session_status(session_id, "error")
        await connection_manager.send_message(session_id, {
            "type": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        })

