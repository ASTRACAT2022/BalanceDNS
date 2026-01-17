# Stage 1: Build the Go application
FROM golang:1.23.2-alpine AS builder

# Install build dependencies
# build-base: for compilation (gcc, etc.)
# unbound-dev: for libunbound headers
# lmdb-dev: for lmdb headers
RUN apk add --no-cache build-base gcc unbound-dev lmdb-dev

WORKDIR /app

# Copy Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with CGO enabled (required for unbound)
# -ldflags "-s -w": Strip debug information for smaller binary
RUN CGO_ENABLED=1 go build -o /app/dns-resolver -tags="unbound cgo" -ldflags "-s -w" .

# Stage 2: Create the final lightweight image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache unbound ca-certificates lmdb-dev

# Set GOMAXPROCS to 1 (can be overridden by K8s resource limits/env vars)
ENV GOMAXPROCS=1

WORKDIR /app

# Generate DNSSEC root key
# We do this in the build but for K8s it's often better to mount it or generate at runtime if missing.
# Here we ensure it exists at the path expected by our config (/etc/unbound/root.key).
RUN mkdir -p /etc/unbound && \
    unbound-anchor -a /etc/unbound/root.key || true

# Copy the compiled binary from the builder stage
COPY --from=builder /app/dns-resolver /app/dns-resolver

# Copy configuration files for standalone usage (K8s will usually override config.yaml via ConfigMap)
COPY config.yaml /app/config.yaml
COPY hosts /app/hosts

# Create directory for persistent cache
# Matches "cache_path: cache/dns.db" in config.yaml
RUN mkdir -p /app/cache

# Expose ports:
# 53: DNS (UDP/TCP)
# 9090: Prometheus Metrics
# 8080: Admin Panel
# 443: DoH / ODoH
# 853: DoT
EXPOSE 53/udp 53/tcp 9090/tcp 8080/tcp 443/tcp 853/tcp

# Set the entrypoint
ENTRYPOINT ["/app/dns-resolver"]
