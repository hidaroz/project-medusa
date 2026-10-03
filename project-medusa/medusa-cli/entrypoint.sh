#!/bin/bash
set -e

# MEDUSA API Production Entrypoint
# Updated: Fixes SQLAlchemy scheme mismatch for Fly.io

echo "========================================"
echo "MEDUSA API Production Startup"
echo "========================================"

# --- CRITICAL FIX ---
# Fly.io provides DATABASE_URL starting with "postgres://".
# SQLAlchemy 1.4+ requires "postgresql://".
# We must fix this globally before running any Python code.
if [ -n "$DATABASE_URL" ]; then
    echo "DEBUG: Fixing DATABASE_URL scheme for SQLAlchemy..."
    export DATABASE_URL=$(echo "$DATABASE_URL" | sed 's/^postgres:/postgresql:/')
fi

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL..."
MAX_RETRIES=30
RETRY_COUNT=0

if [ -n "$DATABASE_URL" ]; then
    echo "DEBUG: DATABASE_URL detected (Fly.io environment)"
    echo "Testing connection using Python SQLAlchemy..."

    while true; do
        python3 << 'PYEOF'
import os
import sys
from sqlalchemy import create_engine, text

# This will now pick up the FIXED environment variable
database_url = os.getenv('DATABASE_URL')

try:
    # Connect timeout is crucial for Fly.io cold starts
    engine = create_engine(database_url, connect_args={"connect_timeout": 5})
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    print("✓ PostgreSQL connection successful!")
    sys.exit(0)
except Exception as e:
    # Print error to stderr so it shows in Fly logs
    print(f"✗ PostgreSQL connection failed: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF

        if [ $? -eq 0 ]; then
            echo "PostgreSQL is ready!"
            break
        fi

        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
            echo "Error: PostgreSQL is not available after ${MAX_RETRIES} attempts"
            echo "Tip: Check 'fly status' to see if the DB machine is suspended."
            exit 1
        fi
        echo "PostgreSQL is unavailable - sleeping (${RETRY_COUNT}/${MAX_RETRIES})"
        sleep 2
    done

else
    # Fallback for local Docker where we use separate host/user/pass vars
    echo "DEBUG: DATABASE_URL not set, using component variables"
    PG_HOST=${POSTGRES_HOST:-postgres}
    PG_USER=${POSTGRES_USER:-medusa}
    PG_DB=${POSTGRES_DB:-medusa}
    
    echo "Checking PostgreSQL at ${PG_HOST}..."
    
    # Note: Make sure postgresql-client is installed in Dockerfile for pg_isready
    while ! pg_isready -h "${PG_HOST}" -U "${PG_USER}" -d "${PG_DB}" > /dev/null 2>&1; do
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
            echo "Error: PostgreSQL is not available after ${MAX_RETRIES} attempts"
            exit 1
        fi
        echo "PostgreSQL is unavailable - sleeping (${RETRY_COUNT}/${MAX_RETRIES})"
        sleep 2
    done

    echo "PostgreSQL is ready!"
fi

# Initialize database schema
echo "Initializing database schema..."
python3 -u << 'PYEOF'
import os
import sys
from sqlalchemy import create_engine, text

# Prioritize DATABASE_URL, fall back to POSTGRES_URI
# (The shell script has already fixed the scheme in DATABASE_URL)
postgres_uri = os.getenv('DATABASE_URL') or os.getenv('POSTGRES_URI')

if not postgres_uri:
    print("CRITICAL: No database configuration found!", file=sys.stderr)
    sys.exit(1)

try:
    engine = create_engine(postgres_uri)
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
        
        # Create checkpoints table for LangGraph
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS checkpoints (
                thread_id TEXT NOT NULL,
                checkpoint_id TEXT NOT NULL,
                parent_checkpoint_id TEXT,
                checkpoint JSONB NOT NULL,
                metadata JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (thread_id, checkpoint_id)
            )
        """))

        # Create index
        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_checkpoints_thread
            ON checkpoints(thread_id, created_at DESC)
        """))

        conn.commit()
        print("Database schema initialized successfully!")

except Exception as e:
    print(f"Database initialization error: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF

if [ $? -ne 0 ]; then
    echo "Database initialization failed!"
    exit 1
fi

# Ensure medusa home directory exists
echo "Setting up Medusa home directory..."
mkdir -p /home/medusa/.medusa/logs
mkdir -p /home/medusa/.medusa/reports
mkdir -p /home/medusa/.medusa/checkpoints

# Fix for running as root (default in this container)
# Copy config from medusa user home to root home if needed
mkdir -p /root/.medusa
if [ -f /home/medusa/.medusa/config.yaml ] && [ ! -f /root/.medusa/config.yaml ]; then
    echo "Copying default config to /root/.medusa/config.yaml"
    cp /home/medusa/.medusa/config.yaml /root/.medusa/config.yaml
fi

# Create first-run marker to skip wizard for both users
touch /home/medusa/.medusa/.first_run_complete
touch /root/.medusa/.first_run_complete

# Starting Server
echo "========================================"
echo "Starting Uvicorn ASGI Server (FastAPI)"
echo "========================================"

# Using exec to replace shell process with python process
exec uvicorn api_server:app \
    --host 0.0.0.0 \
    --port ${PORT:-8000} \
    --workers 4 \
    --timeout-keep-alive 120 \
    --log-level ${LOG_LEVEL:-info} \
    --no-use-colors