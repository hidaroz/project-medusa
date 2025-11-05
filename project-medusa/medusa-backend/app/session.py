"""
Session management for MEDUSA operations
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Session:
    """MEDUSA operation session"""
    session_id: str
    created_at: datetime
    status: str = "initialized"  # initialized, running, paused, completed, error
    mode: str = "observe"  # observe, interactive, autonomous
    target: Optional[str] = None
    current_phase: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    history: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class SessionManager:
    """Manages MEDUSA operation sessions"""
    
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        logger.info("SessionManager initialized")
    
    async def create_session(
        self,
        target: Optional[str] = None,
        mode: str = "observe"
    ) -> Session:
        """Create a new session"""
        session_id = str(uuid.uuid4())
        
        session = Session(
            session_id=session_id,
            created_at=datetime.utcnow(),
            status="initialized",
            mode=mode,
            target=target
        )
        
        self.sessions[session_id] = session
        logger.info(f"Created session {session_id} (mode: {mode}, target: {target})")
        
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID"""
        return self.sessions.get(session_id)
    
    def update_session_status(self, session_id: str, status: str) -> bool:
        """Update session status"""
        session = self.get_session(session_id)
        if session:
            old_status = session.status
            session.status = status
            logger.info(f"Session {session_id} status: {old_status} -> {status}")
            return True
        return False
    
    def add_finding(self, session_id: str, finding: Dict[str, Any]) -> bool:
        """Add a finding to session"""
        session = self.get_session(session_id)
        if session:
            finding["timestamp"] = datetime.utcnow().isoformat()
            session.findings.append(finding)
            logger.info(f"Added finding to session {session_id}: {finding.get('type', 'unknown')}")
            return True
        return False
    
    def add_history_entry(self, session_id: str, entry: Dict[str, Any]) -> bool:
        """Add a history entry to session"""
        session = self.get_session(session_id)
        if session:
            entry["timestamp"] = datetime.utcnow().isoformat()
            session.history.append(entry)
            return True
        return False
    
    def update_phase(self, session_id: str, phase: str) -> bool:
        """Update current phase"""
        session = self.get_session(session_id)
        if session:
            old_phase = session.current_phase
            session.current_phase = phase
            logger.info(f"Session {session_id} phase: {old_phase} -> {phase}")
            return True
        return False
    
    async def delete_session(self, session_id: str) -> bool:
        """Delete a session"""
        if session_id in self.sessions:
            session = self.sessions.pop(session_id)
            logger.info(f"Deleted session {session_id}")
            return True
        return False
    
    async def cleanup_all(self):
        """Clean up all sessions on shutdown"""
        logger.info(f"Cleaning up {len(self.sessions)} sessions")
        self.sessions.clear()

