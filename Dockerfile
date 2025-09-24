FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o hardend cmd/hardend/main.go

# Final stage - minimal image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    util-linux \
    procps \
    coreutils \
    systemd \
    openssh \
    iptables \
    net-tools \
    && rm -rf /var/cache/apk/*

WORKDIR /root/

# Copy the binary
COPY --from=builder /app/hardend .
COPY --from=builder /app/configs/ ./configs/

# Make it executable
RUN chmod +x ./hardend

# Add cyberpunk banner
RUN echo '#!/bin/sh' > /entrypoint.sh && \
    echo 'echo "◢◤ HARDEND NEURAL INTERFACE CONTAINER ACTIVE ◢◤"' >> /entrypoint.sh && \
    echo 'echo "Ready for cybersecurity assessment..."' >> /entrypoint.sh && \
    echo 'exec "$@"' >> /entrypoint.sh && \
    chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["./hardend", "--help"]

# Metadata
LABEL maintainer="constantine.ctf@proton.me"
LABEL description="Cyberpunk Linux Security Hardening Assessment Tool"
LABEL version="2077.1.0"
