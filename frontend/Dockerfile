# =============================================================================
# Pat Fortress Frontend - Multi-stage Production Dockerfile
# =============================================================================

# ================================
# Stage 1: Dependencies
# ================================
FROM node:18-alpine AS deps

RUN apk --no-cache add libc6-compat ca-certificates && \
    addgroup -g 1001 fortress && \
    adduser -D -s /bin/sh -u 1001 -G fortress fortress

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY yarn.lock* ./

# Install dependencies based on lock file
RUN if [ -f yarn.lock ]; then yarn --frozen-lockfile; \
    elif [ -f package-lock.json ]; then npm ci; \
    else npm install; fi

# ================================
# Stage 2: Builder
# ================================
FROM node:18-alpine AS builder

WORKDIR /app

# Copy dependencies from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy source code
COPY . .

# Build arguments for environment variables
ARG NEXT_PUBLIC_API_URL=http://localhost:8025
ARG NEXT_PUBLIC_WS_URL=ws://localhost:8025
ARG NEXT_PUBLIC_ENVIRONMENT=production
ARG NEXT_PUBLIC_SENTRY_DSN
ARG NEXT_PUBLIC_ANALYTICS_ID

# Set build environment variables
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_PUBLIC_WS_URL=${NEXT_PUBLIC_WS_URL} \
    NEXT_PUBLIC_ENVIRONMENT=${NEXT_PUBLIC_ENVIRONMENT} \
    NEXT_PUBLIC_SENTRY_DSN=${NEXT_PUBLIC_SENTRY_DSN} \
    NEXT_PUBLIC_ANALYTICS_ID=${NEXT_PUBLIC_ANALYTICS_ID} \
    NEXT_TELEMETRY_DISABLED=1

# Build the application
RUN npm run build

# ================================
# Stage 3: Production Runner
# ================================
FROM node:18-alpine AS production

RUN apk --no-cache add ca-certificates curl dumb-init && \
    addgroup -g 1001 fortress && \
    adduser -D -s /bin/sh -u 1001 -G fortress fortress

WORKDIR /app

# Copy built application
COPY --from=builder --chown=1001:1001 /app/public ./public
COPY --from=builder --chown=1001:1001 /app/.next/standalone ./
COPY --from=builder --chown=1001:1001 /app/.next/static ./.next/static

# Copy package.json for runtime dependencies
COPY --from=builder --chown=1001:1001 /app/package.json ./

# Create necessary directories
RUN mkdir -p /app/logs /app/temp && \
    chown -R 1001:1001 /app

# Switch to non-root user
USER 1001:1001

# Environment variables
ENV NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    NEXT_TELEMETRY_DISABLED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

# Expose port
EXPOSE 3000

# Graceful shutdown
STOPSIGNAL SIGTERM

# Use dumb-init for proper signal handling
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Start the Next.js server
CMD ["node", "server.js"]

# ================================
# Development Stage
# ================================
FROM node:18-alpine AS development

RUN apk --no-cache add ca-certificates curl git && \
    addgroup -g 1001 fortress && \
    adduser -D -s /bin/sh -u 1001 -G fortress fortress

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY yarn.lock* ./

# Install all dependencies (including dev)
RUN if [ -f yarn.lock ]; then yarn; \
    elif [ -f package-lock.json ]; then npm install; \
    else npm install; fi

# Copy source code
COPY . .

# Create directories
RUN mkdir -p logs temp && \
    chown -R 1001:1001 /app

USER 1001:1001

# Development environment variables
ENV NODE_ENV=development \
    NEXT_TELEMETRY_DISABLED=1 \
    WATCHPACK_POLLING=true

# Development health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

EXPOSE 3000

# Development server with hot reload
CMD ["npm", "run", "dev"]

# ================================
# Static Export Stage (for CDN deployment)
# ================================
FROM node:18-alpine AS static

WORKDIR /app

# Copy dependencies from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy source code
COPY . .

# Build arguments for static export
ARG NEXT_PUBLIC_API_URL
ARG NEXT_PUBLIC_WS_URL
ARG NEXT_PUBLIC_ENVIRONMENT=production

ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL} \
    NEXT_PUBLIC_WS_URL=${NEXT_PUBLIC_WS_URL} \
    NEXT_PUBLIC_ENVIRONMENT=${NEXT_PUBLIC_ENVIRONMENT} \
    NEXT_TELEMETRY_DISABLED=1

# Build and export static files
RUN npm run build && \
    npm run export

# Copy static files to nginx
FROM nginx:1.24-alpine AS static-server

RUN addgroup -g 1001 fortress && \
    adduser -D -s /bin/sh -u 1001 -G fortress fortress

# Copy static files
COPY --from=static --chown=1001:1001 /app/out /usr/share/nginx/html

# Copy nginx configuration
COPY nginx/static.conf /etc/nginx/conf.d/default.conf

# Health check for static server
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost/ || exit 1

EXPOSE 80

# Use non-root nginx user
USER 1001:1001

CMD ["nginx", "-g", "daemon off;"]