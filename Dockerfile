# Stage 1: Build the application
FROM golang:1.25-alpine AS builder

# Install build dependencies (git needed for modules, build-base might be needed if CGO is ever used)
# Removed gcc, musl-dev as they are likely not needed for pure Go build
RUN apk add --no-cache git build-base

WORKDIR /app

# Copy go mod files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application statically
# Ensure 'appVersion' exists in main package or remove -X flag
ARG APP_VERSION=2.0.0
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.appVersion=${APP_VERSION} -extldflags '-static'" \
    -o hardend cmd/hardend/main.go

# Stage 2: Create the minimal final image
FROM alpine:latest

# Install runtime dependencies needed for the *checks* (not the app itself)
# Keep only what's essential for your checks to run
RUN apk add --no-cache \
    ca-certificates \
    util-linux \
    procps \
    coreutils \
    && rm -rf /var/cache/apk/*
# Removed: openssh, iptables, net-tools (add back ONLY if checks directly call these binaries)

WORKDIR /root/

# Copy the static binary from the builder stage
COPY --from=builder /app/hardend .
# Copy default configuration
COPY --from=builder /app/configs/ ./configs/

# Make binary executable
RUN chmod +x ./hardend

# Standard entrypoint message
RUN echo '#!/bin/sh' > /entrypoint.sh && \
    echo 'echo "HARDEND Security Assessment Tool Container"' >> /entrypoint.sh && \
    echo 'echo "Running command: $@" ' >> /entrypoint.sh && \
    echo 'exec "$@"' >> /entrypoint.sh && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
# Default command: Show help
CMD ["./hardend", "--help"]

# Metadata
LABEL maintainer="constantine.ctf@proton.me"
LABEL description="Professional Linux Security Hardening Assessment Tool"
LABEL version="2.0.0"