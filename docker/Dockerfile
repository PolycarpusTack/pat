# Multi-stage Dockerfile for Pat

# Stage 1: Go Builder
FROM golang:1.21-alpine AS go-builder

RUN apk add --no-cache git make gcc musl-dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o pat-server ./cmd/server

# Stage 2: Node Builder
FROM node:18-alpine AS node-builder

WORKDIR /build
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

# Stage 3: Runtime
FROM alpine:3.18

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 pat && \
    adduser -u 1000 -G pat -s /bin/sh -D pat

WORKDIR /app

# Copy binaries and assets
COPY --from=go-builder /build/pat-server /app/
COPY --from=node-builder /build/dist /app/dist
COPY --from=node-builder /build/node_modules /app/node_modules

# Set ownership
RUN chown -R pat:pat /app

USER pat

EXPOSE 1025 8025

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/pat-server", "health"]

ENTRYPOINT ["/app/pat-server"]