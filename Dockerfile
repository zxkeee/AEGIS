# ── Build stage ────────────────────────────────────────────────────────────────
# Pinned to the toolchain in go.mod (avoid silent compiler drift from a moving
# golang:alpine tag).
FROM golang:1.26-alpine@sha256:111d79159b2326f7e80c4a4706e1ba166acb0e2611df853955f3621828cd49e8 AS builder

WORKDIR /build

# Cache dependency download layer
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Licensing (see docs/licensing.md). The gateway refuses to boot without a valid
# signed licence, so a plain `go build` here produced an image that panicked on
# start — `docker compose up`, the documented way to try AEGIS, was broken.
#
# LICENSE_PUBKEY is how a real release is built: pass the public half of your
# offline key, ship the customer their own .lic, and the hard gate applies
# normally.
#
# Left empty (the default, i.e. someone evaluating the project) the build mints
# a throwaway keypair and issues itself a short-lived **trial** licence. That is
# deliberately the weakest thing it can issue: a trial tier is coerced into
# Observe mode by license.Claims.RequiresObserve, so an evaluation image
# inspects and reports but cannot enforce — which is exactly the non-production
# use the BUSL grant in LICENSE already permits for free. The private half never
# leaves this build stage.
ARG LICENSE_PUBKEY=""
RUN set -eu; \
    if [ -z "$LICENSE_PUBKEY" ]; then \
        go run ./cmd/licensegen -genkey -out /tmp/eval > /tmp/genkey.txt; \
        LICENSE_PUBKEY="$(grep -oE '^  [A-Za-z0-9+/=]{40,}$' /tmp/genkey.txt | tr -d ' ')"; \
        go run ./cmd/licensegen -issue -key /tmp/eval.key \
            -licensee "Evaluation build (docker)" -tier trial -days 30 \
            -out /build/aegis-eval.lic; \
        rm -f /tmp/eval.key; \
    else \
        : > /build/aegis-eval.lic; \
    fi; \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w -X api-gateway/internal/license.publicKeyB64=$LICENSE_PUBKEY" \
        -o gateway ./cmd/gateway

# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM alpine:3.19@sha256:b58899f069c47216f6002a6850143dc6fae0d35eb8b0df9300bbe6327b9c2171

RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -S aegis && adduser -S -G aegis aegis

WORKDIR /app

COPY --from=builder /build/gateway .
COPY --from=builder /build/config ./config
# The evaluation licence minted above (empty file when the image was built with
# a real LICENSE_PUBKEY — in that case mount the customer's own .lic and point
# AEGIS_LICENSE_PATH at it).
COPY --from=builder /build/aegis-eval.lic ./aegis-eval.lic
ENV AEGIS_LICENSE_PATH=/app/aegis-eval.lic

# Drop root: run as an unprivileged user.
USER aegis

EXPOSE 8080 8081

# Liveness probe against the admin readiness endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8081/health >/dev/null 2>&1 || exit 1

ENTRYPOINT ["./gateway"]
CMD ["--config", "config/gateway.yaml"]
