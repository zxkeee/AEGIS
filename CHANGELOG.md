# 📝 Changelog

Все заметные изменения в проекте AEGIS документированы в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) и проект придерживается [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 🔨 In Progress
- Поддержка mTLS для backend сервисов
- GraphQL WAF правила
- Webhook интеграции для alerts
- Redis Sentinel поддержка для HA

---

## [2.1.0] — 2025-04-30

### ✨ Added
- **JWT Signature Verification** — Криптографическая проверка подписи успешных запросов (`X-Gateway-Signature`)
- **JTI Blacklist** — Мгновенный отзыв скомпрометированных JWT токенов
- **GeoIP Blocking** — Блокировка трафика из определенных стран (ISO-коды)
- **API Discovery** — Автоматическое построение инвентаризации API эндпоинтов
- **DLP (Data Loss Prevention)** — Маскировка PII в ответах (кредитные карты, SSN, API ключи)
- **Behavioral Scoring** — Динамическое рассчитывание "кармы" IP адресов
- **Prometheus Metrics** — Полная поддержка метрик для мониторинга
- **Grafana Dashboard** — Встроенный Premium Dashboard для аналитики
- **Helm Charts** — Production-ready Kubernetes deployment
- **PodDisruptionBudget** — Гарантия HA при обновлениях K8s
- **Hot Config Reload** — Без перезагрузки приложения (fsnotify)
- **PostgreSQL Forensic** — Асинхронное логирование попыток атак

### 🔧 Changed
- Оптимизирована цепочка middleware для уменьшения latency на 15%
- Обновлена Coraza с v3.0 на v3.7
- Изменен формат логов на JSON (структурированное логирование)
- Улучшена производительность Rate Limiter (Redis pipeline)

### 🐛 Fixed
- Исправлена уязвимость в JWT парсинге (timing атаки)
- Исправлена утечка памяти в хранилище IP метаданных
- Исправлена обработка больших request bodies в WAF

### 🔒 Security
- Добавлена защита от timing-атак при сравнении токенов (Constant-Time)
- Переписание PII в памяти перед удалением (security против memory dumps)
- Валидация входного конфига перед применением (preview mode)

---

## [2.0.0] — 2025-04-15

### ✨ Added
- **JA3 Fingerprinting** — Детектирование ботов по криптографическому отпечатку TLS
- **Advanced Rate Limiting** — Per-IP, per-route, per-user лимиты с Burst поддержкой
- **JWKS Support** — Автоматическое скачивание публичных ключей от Auth0, Keycloak, Okta
- **Admin Dashboard** — Веб-интерфейс для управления и мониторинга
- **Docker Compose Stack** — Complete development окружение (Gateway + Redis + Postgres + Monitoring)
- **Kubernetes Support** — Basic Helm Chart для K8s deployment

### 🔧 Changed
- Переписан обработчик запросов для лучшей производительности
- Обновлены зависимости (Go 1.22, Coraza v3)
- Улучшена обработка ошибок при недоступности Redis

### 🐛 Fixed
- Исправлена обработка больших тел запроса в WAF
- Исправлена утечка соединений при proxying
- Исправлена проблема с кэшированием JWKS ключей

---

## [1.5.0] — 2025-03-20

### ✨ Added
- **JWT Authentication** — Поддержка HMAC (HS256/HS512) и RSA (RS256/RS512) алгоритмов
- **IP Whitelist/Blacklist** — Простой способ фильтровать IP адреса
- **Health Checks** — Проверка здоровья backend сервисов
- **Graceful Shutdown** — Корректное завершение текущих запросов при остановке

### 🔧 Changed
- Оптимизирована работа с Redis (connection pooling)
- Улучшена обработка 502/503 ошибок от backend

### 🐛 Fixed
- Исправлена проблема с keep-alive соединениями
- Исправлена обработка очень длинных URL

---

## [1.0.0] — 2025-03-01

### ✨ Initial Release
- ✅ **Web Application Firewall (WAF)** на базе Coraza с OWASP Core Rule Set
- ✅ **Reverse Proxy** с Load Balancing (Round-Robin)
- ✅ **Rate Limiting** на базе Redis
- ✅ **Bot Protection** (User-Agent анализ, скрипты обнаружение)
- ✅ **Request/Response модификация** (заголовки, body)
- ✅ **Admin API** для управления
- ✅ **Docker поддержка**
- ✅ **Comprehensive логирование**

---

## Версионирование

Проект использует Semantic Versioning:
- **MAJOR** (X.0.0) — Несовместимые изменения API
- **MINOR** (0.X.0) — Новые функции, совместимые с прошлыми версиями
- **PATCH** (0.0.X) — Баг-фиксы

---

## Шаг миграции между версиями

### Обновление с 1.x на 2.0
1. Скачайте новую версию: `git pull origin main`
2. Пересоберите: `make docker` или `go build ...`
3. Обновите конфиг `config/gateway.yaml` (добавлены новые секции)
4. Перезагрузите: `docker-compose restart` или вручную перезагрузите binary

Полная совместимость конфигов — старые конфиги будут работать с дефолтными значениями для новых параметров.

### Обновление с 2.0 на 2.1
1. Просто обновите binary (никаких изменений конфига)
2. Нововведения включены по умолчанию (могут быть отключены в конфиге)

---

## Deprecated & Планы на будущее

### Планируется удалить в версии 3.0
- ⚠️ Support для Go 1.21 и ниже (будет требоваться Go 1.23+)
- ⚠️ Basic Auth (будет удален, используйте JWT)

### Планы развития
- 📅 HTTP/3 (QUIC) поддержка
- 📅 WebSocket proxy с WAF для WebSocket фреймов
- 📅 OpenTelemetry интеграция
- 📅 Managed Rules из коммерческих провайдеров (Cloudflare, etc.)
- 📅 Machine Learning для аномалий обнаружения
- 📅 Multi-region management UI

---

## Ссылки

- 📘 [Документация](./README.md)
- 🐛 [Отчеты об ошибках](https://github.com/zxkeee/AEGIS/issues)
- 💬 [Discussions](https://github.com/zxkeee/AEGIS/discussions)
- 📋 [Project Board](https://github.com/zxkeee/AEGIS/projects)

---

[Unreleased]: https://github.com/zxkeee/AEGIS/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/zxkeee/AEGIS/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/zxkeee/AEGIS/compare/v1.5.0...v2.0.0
[1.5.0]: https://github.com/zxkeee/AEGIS/compare/v1.0.0...v1.5.0
[1.0.0]: https://github.com/zxkeee/AEGIS/releases/tag/v1.0.0
