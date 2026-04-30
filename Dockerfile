# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:alpine AS builder

WORKDIR /build

# Cache dependency download layer
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o gateway ./cmd/gateway

# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/gateway .
COPY --from=builder /build/config ./config

EXPOSE 8080 8081

ENTRYPOINT ["./gateway"]
CMD ["--config", "config/gateway.yaml"]
