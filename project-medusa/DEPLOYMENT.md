# Medusa Server Deployment Guide

This guide explains how to deploy the Medusa system (API Server + Web Dashboard) to a server.

## Prerequisites

- Docker
- Docker Compose

## Deployment

1.  **Upload the project to your server.**
    You can use `scp`, `rsync`, or `git clone` to get the project files onto your server.

2.  **Configure the environment.**
    Ensure you have a `~/.medusa/config.yaml` file or let the system generate a default one.

3.  **Start the services.**
    Run the deployment Compose file:

    ```bash
    docker-compose -f docker-compose.deploy.yml up -d --build
    ```

## Interaction

Once deployed, you can interact with Medusa in two ways:

### 1. Web Dashboard (Recommended)

Access the web interface in your browser:

- **URL:** `http://<your-server-ip>:3000`

From here, you can:
- View system status
- Start new operations (Scan, Vulnerability Analysis, etc.)
- Monitor logs and progress
- Review findings

### 2. Command Line Interface (CLI)

You can also interact with the CLI directly on the server.

**Option A: Inside the Container**
Execute commands inside the running API container:

```bash
docker exec -it medusa_api medusa --help
docker exec -it medusa_api medusa agent run <target>
```

**Option B: Host CLI**
If you have `medusa` installed on the host machine (via `pip install .`), you can run it directly.

## API Access

The API server is exposed on port 5001.
- **Health Check:** `http://<your-server-ip>:5001/api/health`

