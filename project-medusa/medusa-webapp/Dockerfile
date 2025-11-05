# MEDUSA Web Application - Next.js Frontend
# Multi-stage build for optimized production image

# ============================================================================
# Stage 1: Base - Dependencies installation
# ============================================================================
FROM node:20-alpine AS base
WORKDIR /app

# Install dependencies only when needed
COPY package.json ./
COPY package*.json ./
RUN npm ci --only=production && \
    npm cache clean --force

# ============================================================================
# Stage 2: Builder - Build the application
# ============================================================================
FROM node:20-alpine AS builder
WORKDIR /app

# Copy dependencies from base stage
COPY --from=base /app/node_modules ./node_modules
COPY package.json ./
# Copy package-lock.json if it exists, otherwise just package.json
COPY package*.json ./

# Install all dependencies (including dev dependencies for build)
RUN npm ci

# Copy source code
COPY . .

# Set environment variables for build
# These will be replaced by actual values during docker build
ARG NEXT_PUBLIC_MEDUSA_API_URL
ARG NEXT_PUBLIC_MEDUSA_WS_URL
ARG NEXT_PUBLIC_EHR_API_URL

ENV NEXT_PUBLIC_MEDUSA_API_URL=${NEXT_PUBLIC_MEDUSA_API_URL}
ENV NEXT_PUBLIC_MEDUSA_WS_URL=${NEXT_PUBLIC_MEDUSA_WS_URL}
ENV NEXT_PUBLIC_EHR_API_URL=${NEXT_PUBLIC_EHR_API_URL}
ENV NEXT_TELEMETRY_DISABLED=1
ENV DOCKER_BUILD=true

# Build Next.js application in standalone mode
RUN npm run build

# ============================================================================
# Stage 3: Runner - Production runtime
# ============================================================================
FROM node:20-alpine AS runner
WORKDIR /app

# Set production environment
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Create non-root user for security
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy necessary files from builder
COPY --from=builder /app/public ./public
COPY --from=builder /app/package.json ./package.json

# Copy built application with proper ownership
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3000

# Set environment variable for port
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/api/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})" || exit 1

# Start the application
CMD ["node", "server.js"]

