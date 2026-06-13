# 🛡️ AEGIS — Enterprise API Security Gateway

<div align="center">

![AEGIS Logo](https://img.shields.io/badge/Security-Enterprise-black?style=for-the-badge&logo=shield)
![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Kubernetes Ready](https://img.shields.io/badge/Kubernetes-Helm-326CE5?style=for-the-badge&logo=kubernetes)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker)

**AEGIS** is a high-performance enterprise-grade API security gateway written in Go. A competitive alternative to Imperva, Cloudflare Enterprise, and Akamai.

[🚀 Quick Start](#-quick-start) • [📖 Documentation](#-documentation) • [🔧 Configuration](#-configuration) • [🐛 Issues](https://github.com/zxkeee/AEGIS/issues) • [💬 Discussions](https://github.com/zxkeee/AEGIS/discussions)

</div>

---

## 📌 Overview

AEGIS protects both external and internal APIs from:
- 🔴 **SQL Injection and XSS** (OWASP Top 10)
- 🤖 **Automated Attacks and Bots** (JA3 Fingerprinting)
- 📈 **DDoS and Traffic Floods** (Advanced Rate Limiting)
- 🔑 **Unauthorized Access** (Zero-Trust JWT/JWKS)
- 💾 **Data Leakage** (Data Loss Prevention with PII Masking)
- 👻 **Shadow APIs** (Automatic Endpoint Inventory)

Ensures uninterrupted backend operation and meets banking and enterprise sector requirements.

---

## ✨ Key Features

### 🧱 WAF (Web Application Firewall)
- **Coraza v3** with complete **OWASP Core Rule Set**
- Blocks SQL injection, XSS, RCE, LFI, SSRF, XXE, Request Smuggling
- Block and detection modes
- Custom rules via ModSecurity syntax

### 🤖 Bot and Automation Protection
- **JA3 Fingerprinting** — cryptographic TLS fingerprint analysis
- Automatic detection of scripts masquerading as browsers
- Behavioral scoring and IP "karma"
- Automatic banning for port scanning and anomalies

### ⏱️ Intelligent Rate Limiting
- Advanced limiter with burst support
- Built on Redis for distributed systems
- Per-IP, per-endpoint, per-user limits
- Graceful degradation on Redis unavailability

### 🔑 Zero-Trust Authorization
- **JWT validation** (HMAC, RSA/ECDSA)
- **Automatic JWKS download** from Auth0, Keycloak, Okta
- **Cryptographic signature** of approved requests (`X-Gateway-Signature`)
- **JTI Blacklist** for instant token revocation
- Timing attack protection via Constant-Time comparison

### 🗺️ API Discovery & Posture Management
Passive API Security platform (Akamai/Neosec-style), built from live traffic:
- **Automatic API catalog** — real endpoints discovered from traffic, with path
  templating (`/users/42` → `/users/{id}`) so the inventory stays bounded
- **Security posture** — every endpoint classified as **protected / partial /
  unprotected / shadow** from the effective controls (global + per-route)
- **Risk scoring** — unauthenticated access, missing WAF/rate-limit, and observed
  PII raise an endpoint's 0–100 risk score
- **Consumer analytics** — *who* calls each API (JWT subject, API key, or IP),
  request volumes and error rates
- **Effectiveness & coverage** — blocks per control, coverage %, top-risk endpoints
- **Reporting** — full posture report via `/api/report` (JSON or CSV)
- Persists to PostgreSQL (set `AEGIS_FORENSIC_DSN`); real-time console on `:8081`
  with **API Catalog**, **Posture**, and **Consumers** dashboards

Admin endpoints: `GET /api/catalog`, `/api/catalog/{id}`, `/api/consumers`,
`/api/posture/summary`, `/api/effectiveness`, `/api/report?format=csv`.

### 🕵️ Data Loss Prevention (DLP)
- Intercepts outbound traffic before client delivery
- Automatic PII masking:
  - Credit cards (VISA, MasterCard, Amex)
  - Social security numbers (SSN)
  - API keys and tokens
  - Data truncation (cards: `****-****-****-1234`)
- Custom masking patterns

### 🔒 Forensic & Compliance
- Asynchronous logging of all attack attempts to PostgreSQL
- Batching and buffering to minimize performance impact
- Complete audit trail for compliance (PCI-DSS, HIPAA)
- Request signatures for non-repudiation

### 🔥 Zero-Downtime Hot Reload
- Configuration change tracking via `fsnotify`
- Atomic handler replacement without connection interruption
- Configuration validation before applying (Preview Mode)

### 📊 Observability
- **Prometheus metrics** (requests, latency, attacks, bots)
- **Built-in Grafana Dashboard** (Premium "Linear-inspired" design)
- **Structured logging** (JSON format)
- **Real-time analysis** via Admin Dashboard

### 🌐 Load Balancing
- **Round-Robin** balancing across multiple upstreams
- Backend health checks
- Optional sticky sessions
- Connection pooling and keep-alive optimization

### ☸️ Kubernetes-Ready
- **Helm Chart** for quick deployment
- **ConfigMap** with auto-pod reload
- **HorizontalPodAutoscaler** for DDoS scaling
- **PodDisruptionBudget** for HA guarantee
- SecurityContext (read-only FS, non-root user)

---

## 🏗️ Architecture

### High-Level Diagram

```
[ Internet / Clients ]
       │
       ▼  (Port 8080)
┌────────────────────────────────────────────────────────┐
│                      AEGIS GATEWAY                     │
│                                                        │
│  1. 🧹 CleanHeaders (removes spoofed headers)         │
│  2. 🌍 IP Guard (GeoIP, Whitelist, Blacklist)         │
│  3. ⏱  Rate Limiter (flood protection)                │
│  4. 🤖 Bot Protection (JA3, behavioral scoring)       │
│  5. 🧱 WAF (Coraza: SQLi, XSS, RCE)                   │
│  6. 🔑 JWT Auth (JWKS check + Signature generation)   │
│  7. 🗺  API Inventory (Traffic analysis)              │
│  8. 🕵️ DLP (PII masking in responses)                │
│                                                        │
└───────────────────────┬────────────────────────────────┘
                        │ X-Gateway-Subject
                        │ X-Gateway-Signature
                        ▼
            [ YOUR BACKEND SERVICES ]
                (protected behind NAT)
```

### Components

**External Interface (Port 8080):**
- Middleware Chain (sequential request processing)
- Load Balancer (distribution across upstreams)
- Response Processing (DLP masking before client delivery)

**Admin API (Port 8081):**
- REST API for management (JWT/Static Token)
- Web Dashboard for monitoring and configuration
- Real-time metrics and analytics
- IP blacklist/whitelist, WAF configuration

**Backend Storage:**
- **Redis** — rate limit cache, JTI Blacklist, IP metadata
- **PostgreSQL** — long-term attack log storage for Compliance
- **File System** — config (with hot reload)

### Request Processing Flow

1. **Incoming Request** → Gateway listens on `:8080`
2. **CleanHeaders** → Removes spoofed `X-Gateway-*` headers
3. **IP Guard** → Checks IP against whitelist/blacklist, GeoIP policies
4. **Rate Limiter** → Checks Redis for traffic limits (Per-IP, Per-Route)
5. **Bot Protection** → JA3 Fingerprinting, User-Agent analysis, behavioral scoring
6. **WAF** → Coraza parses request and applies OWASP rules
7. **JWT Auth** → Validates token (JWKS with caching), checks JTI Blacklist
8. **API Inventory** → Records request metadata (endpoint, method, parameters)
9. **Upstream Selection** → Load Balancer picks backend (Round-Robin)
10. **Backend Request** → Adds signed headers (`X-Gateway-Subject`, `X-Gateway-Signature`)
11. **Response Processing** → DLP masks PII (credit cards, keys) in response
12. **Logging** → Asynchronously writes to PostgreSQL (attack attempts only)
13. **Client Response** → Returns response with masked data

---

## ⚙️ Technology Stack

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Core** | Go | 1.22+ | Main language (performance, goroutines) |
| **WAF** | Coraza | v3.7+ | Web Application Firewall (OWASP CRS) |
| **State Management** | Redis | 7.0+ | Rate limit cache, JTI Blacklist, IP metadata |
| **Audit Log** | PostgreSQL | 14+ | Long-term attack log storage |
| **JWT** | golang-jwt | v5.3+ | JWT parsing and validation |
| **JWKS** | keyfunc | v3.8+ | Public key download and caching |
| **Container** | Docker | 20.10+ | Application containerization |
| **Orchestration** | Kubernetes + Helm | 1.25+ | K8s deployment |
| **Observability** | Prometheus + Grafana | - | Monitoring and analytics |
| **Config** | YAML | - | Gateway configuration |

---

## 🚀 Quick Start

### Option 1️⃣: Docker Compose (Recommended for Beginners)

**Requirements:** Docker 20.10+, Docker Compose 2.0+

```bash
# Clone the repository
git clone https://github.com/zxkeee/AEGIS.git
cd AEGIS

# Start the environment (Gateway + Redis + PostgreSQL + Prometheus + Grafana)
docker-compose up -d --build

# Check status
docker-compose ps
```

**Available Services:**
- 🌐 **Gateway API:** http://localhost:8080
- 🎛️ **Admin Dashboard:** http://localhost:8081 (default: admin/password)
- 📊 **Prometheus:** http://localhost:9090
- 📈 **Grafana:** http://localhost:3000 (admin/admin)
- 🔴 **Redis:** localhost:6379
- 🗄️ **PostgreSQL:** localhost:5432 (postgres/postgres)

**Testing:**

```bash
# 1. Normal request (should pass)
curl -X GET http://localhost:8080/api/v1/health \
  -H "Content-Type: application/json"

# 2. SQL injection (should be blocked by WAF)
curl -X GET "http://localhost:8080/api/v1/users?id=1' OR '1'='1" \
  -H "Content-Type: application/json"

# Response: 403 Forbidden (WAF Block)

# 3. Rate limiting (exceed limit)
for i in {1..100}; do curl http://localhost:8080/api/v1/health; done

# After limit: 429 Too Many Requests
```

### Option 2️⃣: Local Build (For Development)

**Requirements:** Go 1.22+, Redis running on localhost:6379

```bash
# Download dependencies
go mod download

# Build binary
go build -o bin/gateway ./cmd/gateway

# Run
./bin/gateway --config config/gateway.yaml

# Logs will appear in console
# [INFO] Gateway started on :8080
# [INFO] Admin API started on :8081
```

### Option 3️⃣: Kubernetes + Helm (For Production)

**Requirements:** K8s 1.25+, Helm 3.0+

```bash
# Add Helm repository (when published)
# helm repo add aegis https://charts.aegis-gateway.io
# helm repo update

# Install in "security" namespace
kubectl create namespace security
helm install aegis-gateway ./charts/aegis \
  -f ./charts/aegis/values.yaml \
  -n security

# Check deployment
kubectl get pods -n security
kubectl logs -n security -l app=aegis-gateway -f

# Check service
kubectl get svc -n security
```

**Access Gateway in K8s:**

```bash
# Port-forward for local testing
kubectl port-forward -n security svc/aegis-gateway 8080:8080 &
curl http://localhost:8080/api/v1/health
```

---

## 🔧 Configuration

All configuration is in **`config/gateway.yaml`**. Changes are applied instantly without restart.

### Basic Configuration

```yaml
# === Main Ports ===
listen: ":8080"           # Gateway listens here
admin_listen: ":8081"     # Admin API listens here

# === Admin API Security ===
admin_auth: true                              # Enable authentication
admin_secret: "your-super-secret-admin-key"  # JWT/Bearer token

# === Data Storage ===
redis:
  addr: "localhost:6379"
  db: 0
  password: ""  # If authentication needed

# PostgreSQL for attack logs (optional)
forensic_dsn: "postgres://user:pass@localhost:5432/aegis?sslmode=disable"

# === Security: WAF ===
security:
  waf:
    enabled: true
    block_mode: true  # true = block attacks, false = log only
    log_body: true    # Log request body

  # === DDoS and Flood Protection ===
  rate_limit:
    enabled: true
    requests: 200          # Request limit
    window: "60s"          # Time window
    burst: 50              # Allowed burst above limit

  # === Bot Protection ===
  bot_protection:
    enabled: true
    ja3_fingerprinting: true
    behavioral_scoring: true
    auto_ban_threshold: 3   # Ban after 3 violations
    ban_duration: "1h"

  # === IP Filters ===
  ip_guard:
    whitelist: []           # Always allowed IPs
    blacklist: []           # Blocked IPs
    geo_blocking:
      enabled: false
      blocked_countries: ["KP", "IR"]  # ISO country codes

  # === JWT and Zero-Trust ===
  auth:
    enabled: true
    jwks_url: "https://your-domain.auth0.com/.well-known/jwks.json"
    secret: "your-hmac-secret-key"  # For HS256/HS512
    verify_signature: true
    require_token: false  # true = all requests require JWT

  # === Data Loss Prevention ===
  dlp:
    enabled: true
    mask_credit_cards: true
    mask_ssn: true
    mask_api_keys: true
    custom_patterns:
      - pattern: '\b\d{3}-\d{2}-\d{4}\b'  # SSN
        replacement: '***-**-****'

  # === API Discovery ===
  api_discovery:
    enabled: true
    log_endpoints: true

# === Routes (Reverse Proxy) ===
routes:
  # Example 1: Simple route
  - path: "/api/v1/"
    upstreams:
      - "http://backend-1:3000"
      - "http://backend-2:3000"
    load_balance: "round_robin"
    timeout: "15s"
    preserve_host: true

  # Example 2: Route with custom limits
  - path: "/api/v2/internal/"
    upstreams:
      - "http://internal-service:8080"
    rate_limit:
      requests: 1000
      window: "60s"
    waf:
      enabled: false  # Disable WAF for internal traffic

  # Example 3: Route with custom authentication
  - path: "/payments/"
    upstreams:
      - "http://payment-service:8080"
    require_auth: true
    require_jwt: true
```

### Advanced Configuration Examples

**Example: Strict Security for APIs with PII**

```yaml
security:
  waf:
    enabled: true
    block_mode: true
    log_body: true

  rate_limit:
    enabled: true
    requests: 50
    window: "60s"
    burst: 10

  bot_protection:
    enabled: true
    ja3_fingerprinting: true
    behavioral_scoring: true

  auth:
    enabled: true
    jwks_url: "https://keycloak.example.com/auth/realms/master/protocol/openid-connect/certs"
    require_token: true

  dlp:
    enabled: true
    mask_credit_cards: true
    mask_ssn: true

routes:
  - path: "/payments/"
    upstreams:
      - "http://payments-service:8080"
    require_auth: true
    require_jwt: true
    timeout: "30s"
```

**Example: High-Performance Public API**

```yaml
security:
  waf:
    enabled: false  # Disable WAF for speed

  rate_limit:
    enabled: true
    requests: 10000  # Many requests per second
    window: "1s"

  bot_protection:
    enabled: false

  auth:
    enabled: false  # Open API

routes:
  - path: "/public/"
    upstreams:
      - "http://public-api-1:8080"
      - "http://public-api-2:8080"
      - "http://public-api-3:8080"
    load_balance: "round_robin"
    timeout: "5s"
```

---

## 📊 Admin Dashboard

Built-in web interface for monitoring and management available at **`:8081`**.

**Features:**
- 📈 Real-time metrics (RPS, latency, error rate)
- 🔴 Active attacks and blocks list
- 🤖 Bot Detection Dashboard
- 🔑 JWT Blacklist management
- 🌍 IP Whitelist/Blacklist
- 📋 API Inventory (discovered endpoints)
- ⚙️ Config editing (with Preview Mode)
- 📊 Grafana Integration (metric links)

**Access:**

```bash
# Default credentials
URL: http://localhost:8081
Username: admin
Password: password

# Change in config/gateway.yaml:
admin_secret: "your-custom-secret"
```

---

## 📈 Monitoring and Metrics

### Prometheus Metrics

All metrics available at **`http://localhost:8081/metrics`** in Prometheus format.

**Key Metrics:**

```
# Requests
aegis_requests_total{method="GET", path="/api/v1/health", status="200"} 1523

# Latency (milliseconds)
aegis_request_duration_ms{path="/api/v1/users"} 15

# Attacks
aegis_waf_blocks_total{rule="SQLi", action="block"} 42
aegis_bot_detections_total{ja3_match="true"} 123

# Rate limiting
aegis_rate_limit_exceeded_total{endpoint="/api/v1/"} 15

# Backend health
aegis_upstream_health{upstream="backend-1:3000"} 1  # 1 = healthy, 0 = down
```

### Grafana Dashboard

Imported Dashboard shows:
- 📊 Traffic (RPS)
- ⏱️ Latency (P50, P95, P99)
- 🔴 Errors and WAF blocks
- 🤖 Bot Detection rate
- 💾 Resource usage (CPU, Memory, Goroutines)
- 🔒 JWT/Auth success/errors

**Access:** http://localhost:3000/d/aegis-gateway

---

## 🔒 AEGIS Security

AEGIS itself is built with strict security requirements:

### Admin API Protection
1. ✅ **JWT/Bearer Token authentication** with Constant-Time comparison
2. ✅ **Separate rate limit** on admin panel (5 req/sec)
3. ✅ **Timing attack protection** via cryptographic functions
4. ✅ **HTTPS support** (TLS 1.3) for all connections

### Gateway Protection
1. ✅ **Spoofed header removal** — removes client `X-Gateway-*`
2. ✅ **Cryptographic signature** of approved requests (HMAC)
3. ✅ **Config integrity verification** (hash-based validation)
4. ✅ **Memory-safe PII handling** (overwrite in memory)

### Zero-Downtime Safety
- ✅ **Atomic config reload** — old config removed only after new one loads successfully
- ✅ **Graceful shutdown** — in-flight requests handled correctly
- ✅ **No data loss** — async logs to PostgreSQL never lost

---

## 📚 Documentation

- **[CONTRIBUTING.md](./CONTRIBUTING.md)** — How to contribute
- **[CHANGELOG.md](./CHANGELOG.md)** — Version history and changes
- **[SECURITY.md](./SECURITY.md)** — Security policy and vulnerability reporting
- **[QUICK_START.md](./docs/QUICK_START.md)** — Get started in 5 minutes
- **[DEPLOYMENT.md](./docs/DEPLOYMENT.md)** — Production deployment guide

---

## 🛠️ Development and Testing

### Local Development

```bash
# Requirements
- Go 1.22+
- Docker & Docker Compose (for testing)
- golangci-lint (for linting)

# Download dependencies
go mod download

# Run tests
make test

# Lint code
make lint

# Format code
make fmt
```

### Project Structure

```
.
├── cmd/
│   └── gateway/               # Application entry point
│       └── main.go
├── internal/
│   ├── api/                   # HTTP handlers (Admin API)
│   │   ├── handlers.go
│   │   └── metrics.go
│   ├── middleware/            # Security middleware chain
│   │   ├── waf.go             # WAF (Coraza)
│   │   ├── rate_limit.go
│   │   ├── jwt_auth.go
│   │   ├── bot_protection.go
│   │   ├── dlp.go
│   │   └── ...
│   ├── config/                # Config parsing
│   ├── forensic/              # PostgreSQL logging
│   ├── store/                 # Redis/PostgreSQL integration
│   ├── proxy/                 # Reverse proxy logic
│   ├── logger/                # Structured logging
│   └── alert/                 # Alert system
├── charts/
│   └── aegis/                 # Helm Chart for K8s
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
│           ├── deployment.yaml
│           ├── service.yaml
│           ├── configmap.yaml
│           ├── hpa.yaml
│           └── pdb.yaml
├── config/
│   └── gateway.yaml           # Example configuration
├── Dockerfile                 # Multi-stage Docker build
├── docker-compose.yml         # Complete stack
├── Makefile                   # Development commands
├── go.mod / go.sum            # Go dependencies
└── README.md                  # This file
```

### Testing

```bash
# All tests
go test ./... -v -race

# Tests with coverage
go test ./... -v -race -coverprofile=coverage.out
go tool cover -html=coverage.out

# Integration tests with Docker
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

---

## 🤝 Contributing

Pull requests and issues are welcome! Please read [CONTRIBUTING.md](./CONTRIBUTING.md) before submitting a PR.

**Areas for Contribution:**
- 🔒 Security — new protection mechanisms
- 🚀 Performance — optimization
- 📚 Documentation — doc improvements
- 🧪 Testing — unit and integration tests
- 🐛 Bug fixes — fix issues

---

## 📝 License

This project is licensed under the **MIT License**. See [LICENSE](./LICENSE) file for details.

---

## 🙏 Acknowledgments

Thanks to projects that AEGIS is built on:
- [Coraza WAF](https://coraza.io/) — powerful WAF engine
- [golang-jwt](https://github.com/golang-jwt/jwt) — JWT parsing
- [redis](https://github.com/redis/go-redis) — Redis client
- [fsnotify](https://github.com/fsnotify/fsnotify) — File system notifications
- Go community — for an excellent programming language!

---

## 📞 Support and Contact

- 🐛 **Issues & Bugs:** [GitHub Issues](https://github.com/zxkeee/AEGIS/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/zxkeee/AEGIS/discussions)
- 🔒 **Security Issues:** Use [Security Advisory](https://github.com/zxkeee/AEGIS/security/advisories)
- 📧 **Email:** Coming soon

---

<div align="center">

**Made with ❤️ for API Security**

⭐ If you like this project, please star us on GitHub!

</div>
