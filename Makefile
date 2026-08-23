.PHONY: build run test clean docker loadgen check-binaries check-secrets check-image-pins lint-invariants hooks console console-dev

build:
	go build -ldflags="-s -w" -o bin/gateway ./cmd/gateway

# Build the React admin console into internal/api/console_dist, which is embedded
# via go:embed. The built bundle IS committed so `go build` works without Node;
# rerun this after changing anything under web/console/.
console:
	cd web/console && npm ci && npm run build

# Run the console dev server (Vite HMR) proxied to a local gateway on :8081.
console-dev:
	cd web/console && npm install && npm run dev

# Build the load/outage generator into bin/ (gitignored) so it never lands as a
# stray binary in the repo root, the way `go build ./tests/load` does.
loadgen:
	go build -o bin/loadgen ./tests/load

# Fail if a compiled binary or oversized blob got committed. Also runs in CI.
check-binaries:
	./scripts/check-no-binaries.sh

lint-invariants:
	./scripts/lint-invariants.sh

# Install the versioned git hooks (.githooks/) for this clone.
hooks:
	git config core.hooksPath .githooks
	@echo "git hooks installed: core.hooksPath -> .githooks"

run: build
	./bin/gateway --config config/gateway.yaml

test:
	go test ./... -v -race

clean:
	rm -rf bin/

# AEGIS_REDIS_PASSWORD/POSTGRES_PASSWORD/GRAFANA_ADMIN_PASSWORD are consumed
# directly by docker-compose.yml, never through internal/config, so
# config.Validate's placeholder rejection can't see them. Check separately.
check-secrets:
	./scripts/check-weak-secrets.sh

# Catches a docker-compose.yml image reference that regressed to tag-only
# pinning (or a newly added one that was never pinned), unless explicitly
# tracked with a "TODO(security-audit): pin by digest" comment.
check-image-pins:
	./scripts/check-image-pins.sh

docker: check-secrets
	docker compose up -d --build

docker-down:
	docker compose down

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...
	goimports -w .
