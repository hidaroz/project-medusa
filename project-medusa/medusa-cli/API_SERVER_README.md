# Medusa API Server

The Medusa API Server provides a RESTful interface for the Medusa CLI, allowing it to be controlled by the Medusa Web Dashboard.

## Setup

The API server is containerized and can be run using Docker Compose.

### Prerequisites

- Docker
- Docker Compose

### Starting the Server

To start the API server, run the provided helper script from the project root:

```bash
./start_medusa_api.sh
```

Or manually using Docker Compose:

```bash
cd medusa-cli
docker-compose -f docker-compose.api.yml up -d --build
```

The server will be available at `http://localhost:5001`.

## Server Deployment

For full server deployment (API + Web Dashboard), see [DEPLOYMENT.md](../DEPLOYMENT.md).

## API Endpoints

- `GET /api/health`: Health check
- `GET /api/status`: Get current system status
- `GET /api/operations`: Get list of operations
- `POST /api/operations`: Start a new operation
- `POST /api/operations/stop`: Stop current operation
- `GET /api/metrics`: Get operation metrics
- `GET /api/logs`: Get operation logs

## Configuration

The server is configured via environment variables in `docker-compose.api.yml`:

- `MEDUSA_API_PORT`: Internal port (default: 5000)
- `PYTHONUNBUFFERED`: Python output buffering (default: 1)

## Development

To develop locally, you can mount the source code into the container by uncommenting the volume mappings in `docker-compose.api.yml`.

