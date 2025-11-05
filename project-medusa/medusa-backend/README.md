# MEDUSA Backend

FastAPI backend for MEDUSA AI-powered penetration testing platform.

## Features

- **WebSocket Support**: Real-time communication with frontend
- **Session Management**: Track multiple penetration testing sessions
- **Docker Integration**: Execute commands in lab environment containers
- **LLM Integration**: Google Gemini API for AI-powered decisions
- **Health Checks**: Docker-compatible health monitoring
- **CORS Configured**: Ready for frontend communication

## Architecture

```
medusa-backend/
├── app/
│   ├── __init__.py
│   ├── main.py           # FastAPI application entry point
│   ├── config.py         # Configuration and settings
│   ├── session.py        # Session management
│   ├── websocket.py      # WebSocket handlers
│   └── agent.py          # AI agent integration (to be added)
├── Dockerfile
├── requirements.txt
└── README.md
```

## API Endpoints

### Health Checks
- `GET /health` - Basic health check
- `GET /api/health` - Detailed health status

### Session Management
- `POST /api/sessions` - Create new session
- `GET /api/sessions` - List all sessions
- `GET /api/sessions/{id}` - Get session details
- `DELETE /api/sessions/{id}` - Delete session

### Docker Management
- `GET /api/docker/containers` - List lab containers
- `GET /api/docker/networks` - List Docker networks

### WebSocket
- `WS /ws/{session_id}` - WebSocket connection for real-time updates

## WebSocket Message Format

### Client → Server

```json
{
  "type": "start_scan" | "command" | "approval_response" | "stop" | "ping",
  "data": {
    // Type-specific data
  }
}
```

### Server → Client

```json
{
  "type": "connected" | "terminal_output" | "finding" | "phase_start" | "error",
  "data": {
    // Type-specific data
  },
  "timestamp": "ISO 8601 timestamp"
}
```

## Environment Variables

Required:
- `GEMINI_API_KEY` - Google Gemini API key

Optional:
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string
- `API_HOST` - API host (default: 0.0.0.0)
- `API_PORT` - API port (default: 8000)
- `ENVIRONMENT` - Environment name (default: development)
- `LOG_LEVEL` - Logging level (default: INFO)

## Development

### Local Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Run development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Docker Setup

```bash
# Build image
docker build -t medusa-backend .

# Run container
docker run -p 8000:8000 \
  -e GEMINI_API_KEY=your_key_here \
  -v /var/run/docker.sock:/var/run/docker.sock \
  medusa-backend
```

## Integration with MEDUSA CLI

The backend integrates with the Python CLI located in `../medusa-cli`:

1. Imports MEDUSA CLI modules
2. Executes CLI commands via subprocess or direct import
3. Streams output to WebSocket clients
4. Handles approval gates for high-risk actions

## Security Considerations

- ✅ Non-root user in Docker
- ✅ Environment variable-based configuration
- ✅ CORS configured for specific origins
- ✅ Health checks enabled
- ⚠️ Docker socket access (required for container management)

## Next Steps

1. Complete CLI integration (Phase 8)
2. Add database models and persistence
3. Implement Redis session caching
4. Add authentication/authorization
5. Enhance error handling
6. Add comprehensive tests

