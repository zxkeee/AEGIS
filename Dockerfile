# ── Build stage ────────────────────────────────────────────────────────────────
# Pinned to the toolchain in go.mod (avoid silent compiler drift from a moving
# golang:alpine tag).
FROM golang:1.26-alpine AS builder

WORKDIR /build

# Cache dependency download layer
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o gateway ./cmd/gateway

# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -S aegis && adduser -S -G aegis aegis

WORKDIR /app

COPY --from=builder /build/gateway .
COPY --from=builder /build/config ./config

# Drop root: run as an unprivileged user.
USER aegis

EXPOSE 8080 8081

# Liveness probe against the admin readiness endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8081/health >/dev/null 2>&1 || exit 1

ENTRYPOINT ["./gateway"]
CMD ["--config", "config/gateway.yaml"]
