# ============================================================================
# EHR API Server - Vulnerable REST API
# ============================================================================
# Base: Node.js with Express
# Intentional Vulnerabilities: Missing auth, weak JWT, verbose errors
# ============================================================================

FROM node:18-alpine

WORKDIR /app

# Install dependencies
RUN apk add --no-cache \
    curl \
    bash \
    netcat-openbsd

# Copy package files
COPY package*.json ./

# Install npm packages
RUN npm install

# Copy application code
COPY ./src ./src

# Create log directory
RUN mkdir -p /var/log/api && \
    chmod 777 /var/log/api

# Expose API port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:3000/health || exit 1

CMD ["node", "src/server.js"]

