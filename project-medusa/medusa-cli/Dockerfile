FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    sqlmap \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir .

# Create non-root user
RUN useradd -m medusa
USER medusa
WORKDIR /home/medusa

# Set entrypoint
ENTRYPOINT ["medusa"]
CMD ["--help"]
