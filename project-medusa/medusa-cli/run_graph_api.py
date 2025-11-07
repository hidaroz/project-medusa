#!/usr/bin/env python3
"""
Standalone script to run the MEDUSA Graph API Service.

This script provides a convenient way to start the Graph API server
with proper environment configuration and logging.

Usage:
    python run_graph_api.py

    # Or with custom port
    GRAPH_API_PORT=5003 python run_graph_api.py

    # Or disable authentication for development
    GRAPH_API_ENABLE_AUTH=false python run_graph_api.py
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add src directory to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

# Load environment variables from .env file
env_file = Path(__file__).parent.parent / ".env"
if env_file.exists():
    load_dotenv(env_file)
    print(f"Loaded environment from: {env_file}")
else:
    print(f"Warning: .env file not found at {env_file}")
    print("Using default configuration values")

# Import and run the application
from medusa.api.graph_api import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nShutting down Graph API server...")
        sys.exit(0)
    except Exception as e:
        print(f"\n\nError starting Graph API server: {e}")
        sys.exit(1)
