"""
MEDUSA Backend API
FastAPI application with WebSocket support for AI-powered penetration testing
"""

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import docker

from app.websocket import ConnectionManager, handle_websocket_message
from app.session import SessionManager
from app.config import get_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize managers
connection_manager = ConnectionManager()
session_manager = SessionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown tasks"""
    # Startup
    logger.info("Starting MEDUSA Backend API")
    settings = get_settings()
    
    # Test Docker connection
    try:
        docker_client = docker.from_env()
        docker_client.ping()
        logger.info("✅ Docker connection successful")
        docker_client.close()
    except Exception as e:
        logger.warning(f"⚠️  Docker connection failed: {e}")
        logger.warning("Docker commands will not be available")
    
    # Log configuration
    logger.info(f"Environment: {settings.environment}")
    logger.info(f"CORS Origins: {settings.cors_origins}")
    logger.info(f"Gemini API configured: {'GEMINI_API_KEY' in os.environ}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down MEDUSA Backend API")
    await session_manager.cleanup_all()


# Create FastAPI application
app = FastAPI(
    title="MEDUSA Backend API",
    description="AI-Powered Autonomous Penetration Testing Platform",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Health Check Endpoints
# ============================================================================

@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint for Docker health checks"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "medusa-backend",
        "version": "1.0.0"
    }


@app.get("/api/health")
async def api_health_check() -> Dict[str, Any]:
    """Detailed API health check"""
    try:
        # Check Docker connection
        docker_available = False
        try:
            client = docker.from_env()
            client.ping()
            docker_available = True
            client.close()
        except:
            pass
        
        # Check Gemini API key
        gemini_configured = bool(os.getenv("GEMINI_API_KEY"))
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "service": "medusa-backend",
            "version": "1.0.0",
            "components": {
                "docker": "available" if docker_available else "unavailable",
                "gemini_api": "configured" if gemini_configured else "not_configured",
                "websocket": "available",
                "sessions": {
                    "active": len(session_manager.sessions),
                    "connections": len(connection_manager.active_connections)
                }
            }
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Session Management Endpoints
# ============================================================================

@app.post("/api/sessions")
async def create_session(target: str = None, mode: str = "observe") -> Dict[str, Any]:
    """Create a new MEDUSA session"""
    try:
        session = await session_manager.create_session(target=target, mode=mode)
        return {
            "success": True,
            "session_id": session.session_id,
            "created_at": session.created_at.isoformat(),
            "status": session.status,
            "mode": session.mode
        }
    except Exception as e:
        logger.error(f"Failed to create session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str) -> Dict[str, Any]:
    """Get session details"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "session_id": session.session_id,
        "status": session.status,
        "mode": session.mode,
        "target": session.target,
        "created_at": session.created_at.isoformat(),
        "findings_count": len(session.findings),
        "current_phase": session.current_phase
    }


@app.get("/api/sessions")
async def list_sessions() -> Dict[str, Any]:
    """List all active sessions"""
    sessions = [
        {
            "session_id": session.session_id,
            "status": session.status,
            "mode": session.mode,
            "target": session.target,
            "created_at": session.created_at.isoformat()
        }
        for session in session_manager.sessions.values()
    ]
    return {"sessions": sessions, "count": len(sessions)}


@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str) -> Dict[str, Any]:
    """Delete a session"""
    success = await session_manager.delete_session(session_id)
    if not success:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"success": True, "message": "Session deleted"}


# ============================================================================
# WebSocket Endpoint
# ============================================================================

@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint for real-time communication with frontend
    
    Message format:
    {
        "type": "start_scan" | "command" | "approval_response" | "ping",
        "data": {...}
    }
    """
    await connection_manager.connect(websocket, session_id)
    logger.info(f"WebSocket connected for session: {session_id}")
    
    # Send welcome message
    await connection_manager.send_message(
        session_id,
        {
            "type": "connected",
            "session_id": session_id,
            "timestamp": datetime.utcnow().isoformat(),
            "message": "Connected to MEDUSA Backend"
        }
    )
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_json()
            logger.debug(f"Received message: {data.get('type')} for session {session_id}")
            
            # Handle message
            response = await handle_websocket_message(
                session_id=session_id,
                message=data,
                session_manager=session_manager,
                connection_manager=connection_manager
            )
            
            # Send response if any
            if response:
                await connection_manager.send_message(session_id, response)
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for session: {session_id}")
        connection_manager.disconnect(session_id)
    except Exception as e:
        logger.error(f"WebSocket error for session {session_id}: {e}", exc_info=True)
        try:
            await connection_manager.send_message(
                session_id,
                {
                    "type": "error",
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
        except:
            pass
        connection_manager.disconnect(session_id)


# ============================================================================
# Docker Management Endpoints
# ============================================================================

@app.get("/api/docker/containers")
async def list_containers() -> Dict[str, Any]:
    """List all Docker containers in the lab environment"""
    try:
        client = docker.from_env()
        containers = client.containers.list(all=True)
        
        container_list = [
            {
                "id": c.id[:12],
                "name": c.name,
                "status": c.status,
                "image": c.image.tags[0] if c.image.tags else c.image.id[:12],
                "ports": c.ports
            }
            for c in containers
            if "medusa" in c.name.lower()
        ]
        
        client.close()
        return {"containers": container_list, "count": len(container_list)}
    except Exception as e:
        logger.error(f"Failed to list containers: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/docker/networks")
async def list_networks() -> Dict[str, Any]:
    """List Docker networks"""
    try:
        client = docker.from_env()
        networks = client.networks.list()
        
        network_list = [
            {
                "id": n.id[:12],
                "name": n.name,
                "driver": n.attrs.get("Driver"),
                "scope": n.attrs.get("Scope")
            }
            for n in networks
            if "medusa" in n.name.lower() or "healthcare" in n.name.lower()
        ]
        
        client.close()
        return {"networks": network_list, "count": len(network_list)}
    except Exception as e:
        logger.error(f"Failed to list networks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"error": "Not found", "detail": str(exc)}
    )


@app.exception_handler(500)
async def internal_error_handler(request, exc):
    logger.error(f"Internal server error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)}
    )


# ============================================================================
# Root Endpoint
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "MEDUSA Backend API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "api_health": "/api/health",
            "websocket": "/ws/{session_id}",
            "sessions": "/api/sessions",
            "docker": "/api/docker/containers"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

