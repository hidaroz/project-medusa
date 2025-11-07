# ============================================================================
# Dockerfile: MedCare EHR Frontend (Next.js Application)
# ============================================================================
# This is the PRIMARY frontend for the MedCare EHR system
# Connects to: EHR Backend, EHR API, EHR Database (via API), EHR Redis
# ============================================================================

# ============================================================================
# Stage 1: Build Stage
# ============================================================================
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files for dependency installation
COPY package*.json ./

# Install dependencies (use npm install to generate lock file)
RUN npm install && \
    npm cache clean --force

# Copy application source code
COPY . .

# Set environment variables for build
ENV NEXT_PUBLIC_EHR_API_URL=http://ehr-api:3000
ENV NEXT_PUBLIC_EHR_BACKEND_URL=http://ehr-backend:3000
ENV NODE_ENV=production

# Build the Next.js application
RUN npm run build

# ============================================================================
# Stage 2: Production Runtime
# ============================================================================
FROM node:18-alpine

# Set environment for production
ENV NODE_ENV=production
ENV NEXT_PUBLIC_EHR_API_URL=http://ehr-api:3000
ENV NEXT_PUBLIC_EHR_BACKEND_URL=http://ehr-backend:3000
ENV PORT=3000

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Set working directory
WORKDIR /app

# Copy built artifacts from builder stage
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /app/package*.json ./
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/next.config.ts ./
COPY --from=builder --chown=nextjs:nodejs /app/tsconfig.json ./

# Switch to non-root user
USER nextjs

# Expose port 3000 (internal to container)
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})" || exit 1

# Start the Next.js application in server mode
CMD ["npm", "start"]
