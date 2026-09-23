.PHONY: build run test clean docker loadgen demo demo-auto doc-drift support-bundle check-binaries check-secrets check-image-pins lint-invariants hooks console console-dev sample-report render-pdf preflight stand stand-down stand-test

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

# -timeout 180s matches CI: a deadlocked test must report as a failure, not sit
# for the default ten minutes looking like an infrastructure problem.
test:
	go test ./... -v -race -timeout 180s

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

# Regenerate docs/assets/AEGIS-Sample-Findings-Report.{html,pdf} end to end:
# stand up a gateway in front of the deliberately flawed demo backend, drive
# traffic through it, export what it actually observed, and render.
#
# Every figure in that document comes from a real run, so it can only stay
# honest if regenerating it is one command — a three-step ritual remembered by
# hand is how a committed PDF ends up showing numbers the code no longer
# produces. Needs go, curl, redis-server, Chrome and a reachable PostgreSQL
# (override with POSTGRES_DSN).
sample-report:
	./demo/sample-report/generate.sh
	python3 demo/sample-report/render.py
	$(MAKE) render-pdf

# HTML -> PDF for every document in docs/assets/. Drives Chrome over the
# DevTools protocol rather than the --print-to-pdf flag, because the flag cannot
# set a footer template and silently dropped the page numbering from the NDA and
# the "fictional data" mark from the report. See scripts/render-pdf.py.
render-pdf:
	python3 ./scripts/render-pdf.py

# Everything CI runs, the way CI runs it — including the pinned golangci-lint
# version, the second Go module under web/, and both npm lockfiles. Run this
# before pushing; `make lint` alone has missed real failures three times.
preflight:
	./scripts/preflight.sh

# Do the documents still describe the product the code implements? Answers the
# question that needed a person reading two files side by side four times in one
# session. See docs/capabilities.json for what it knows about.
CONFIG ?= config/gateway.yaml

doc-drift:
	python3 ./scripts/check-doc-drift.py

support-bundle:
	./scripts/support-bundle.sh -c $(CONFIG) $(if $(ADMIN),-a $(ADMIN),)

# A complete, disposable AEGIS on this machine: PostgreSQL, Redis, a throwaway
# license, an upstream and the gateway itself — the stand the dynamic security
# scan builds in CI out of Docker containers. `make stand-test` goes from
# nothing to a full WAF/auth pentest result in a few seconds.
# The three-minute walkthrough for an audience: real traffic through a real
# gateway, the signed compliance report it produces, and the verifier refusing
# a tampered copy — and refusing to run at all without a key pinned out of band.
demo:
	./demo/evidence-demo.sh

demo-auto:
	./demo/evidence-demo.sh -y

stand:
	./scripts/pentest-stand.sh up

stand-test:
	./scripts/pentest-stand.sh test

stand-down:
	./scripts/pentest-stand.sh down

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...
	goimports -w .
