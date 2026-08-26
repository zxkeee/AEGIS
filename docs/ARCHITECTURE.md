# AEGIS — Техническая архитектура

> Справочник для разработчиков и ревьюеров по безопасности. Описывает **как
> система работает на самом деле**, по коду, а не по маркетингу. Каждый раздел
> ссылается на конкретные файлы. Раздел 14 честно перечисляет пробелы — читайте
> его первым, если вы оцениваете зрелость.

Версия документа соответствует ветке `main`. Спорные утверждения проверяйте
`grep`ом — это документация к security-продукту, а не рекламный буклет.

---

## 1. Что это и модель угроз

AEGIS — **inline API Security Gateway** на Go. Это reverse proxy, который
пропускает каждый входящий HTTP-запрос через цепочку security-middleware, а
затем форвардит на backend. Параллельно он **пассивно строит каталог API** и
оценивает его защищённость (posture).

**Позиционирование:** класс продуктов Salt / Noname / Akamai API Security.

**Что защищаем (assets):** backend-API клиента и данные, которые они отдают.

**От кого (threat actors):**
- Внешний атакующий на data plane (:8080) — инъекции, обход авторизации,
  enumeration/BOLA, эксфильтрация PII, боты/сканеры.
- Клиент, который дотянулся до backend в обход гейта, и пытается подделать
  «доверенную» идентичность (`X-Gateway-*`).
- Кросс-тенантный доступ (один клиент читает данные другого).
- Инсайдер/оператор на admin plane (:8081) — покрывается RBAC + audit log.

**Ключевой архитектурный принцип:** identity, forwarding-заголовки и tenant
резолвятся/очищаются **на входе** и распространяются через `context.Context`, а
не «доверяются» из клиентских заголовков.

**Лицензионная модель** (раздел 13) — отдельный, но тоже security-relevant
гейт: без валидной подписанной лицензии гейтвей не стартует вообще.

---

## 2. Топология процесса

Один бинарь (`cmd/gateway/main.go`) поднимает **два независимых HTTP-сервера**:

| Сервер | Порт (default) | Назначение | Аутентификация |
|--------|---------------|------------|----------------|
| **Gateway (data plane)** | `:8080` | Reverse proxy + цепочка security-middleware | per-route (JWT / нет) |
| **Admin (control plane)** | `:8081` | Консоль (`/`), health/metrics, каталог/posture/findings, управление IP/JWT, CRUD тенантов/юзеров, статус лицензии | Bearer-токен ИЛИ session-cookie + CSRF |

Почему разделены: data plane — публичная, высоконагруженная, враждебная среда;
admin plane — приватная панель управления. Разные trust-модели, разные порты,
разный auth. Их **нельзя** объединять.

**Lifecycle** (`cmd/gateway/main.go`):
- `main()` читает конфиг, применяет env-override секретов, валидирует
  (`config.Validate`), **проверяет лицензию как жёсткий гейт** (раздел 13),
  инициализирует Redis/PostgreSQL/каталог.
- Флаг `-print-fingerprint` — служебный режим: печатает аппаратный отпечаток
  этой машины и выходит, без поднятия серверов (нужен клиенту до выдачи
  лицензии, см. раздел 13).
- Хендлер data plane хранится в `atomic.Value` и **горячо перестраивается** при
  изменении конфиг-файла (`watchConfigFile`, fsnotify) — без рестарта,
  in-flight запросы дорабатывают на старой цепочке. Лицензия **тоже**
  перепроверяется на каждый hot-reload и периодически в фоне между ними
  (раздел 13) — не только при старте.
- Graceful shutdown по SIGINT/SIGTERM: опциональный drain-период, затем
  `Server.Shutdown(ctx)` с дедлайном.
- Фоновые воркеры: catalog-flush (discovery), retention (очистка старых
  forensic-логов), alert-engine, периодическая перепроверка лицензии.

---

## 3. Жизненный цикл запроса (data plane) — цепочка middleware

Собирается в `internal/gateway/chain.go` → `chainSteps()`. **Первый в списке —
самый внешний** (outermost). Порядок — несущий; он зафиксирован тестом
`chain_test.go`, так что случайная перестановка падает в CI.

```
Входящий запрос
  │
  1  TenantResolve        резолвит tenant (route/host), режет клиентские X-Tenant-*
  2  CleanHeaders         срезает поддельные X-Gateway-* / X-JA3 / X-Forwarded-*
  3  LicenseRateLimit     коммерческий потолок RPS из лицензии (fail-OPEN: не security-контроль)
  4  UpstreamFingerprint  доверяет JA3 от upstream (Cloudflare) ТОЛЬКО с trusted_proxies
  5  TLSFingerprint       вычисляет реальный JA3 из ClientHello (если гейт терминирует TLS)
  6  SecurityHeaders      HSTS, X-Frame-Options, CSP-совместимые заголовки на ответ
  7  RequestID            X-Request-ID для корреляции логов (клиентский — санитайзится)
  8  PathSanity           отклоняет traversal / закодированные разделители ДО любых prefix-политик
  9  CORS                 CORS-политика data plane
  10 IPGuard              CIDR-aware блок/allow-листы IP (fail_closed опционально)
  11 ThreatFeed           блок по внешним threat-фидам
  12 RateLimit            fixed-window rate limit на Redis (per-route, fail_closed опц.)
  13 BotProtection        детект ботов/сканеров (UA, JA3-консистентность)
  14 Challenge            anti-bot challenge (проверенно fail-open при недоступности стора)
  15 WAF                  Coraza: starter-правила ИЛИ полный OWASP CRS v4 + XXE-предфильтр (fail_closed опц.)
  ── Discovery ──         пассивно фиксирует наблюдение (внутри WAF/bot, снаружи auth/DLP);
                          на graphql_path парсит операцию → каталог по операции, не по /graphql
  16 Auth                 JWT (HMAC или JWKS), подписывает identity вниз (X-Gateway-*)
  17 SchemaValidation     positive security: валидация против OpenAPI-контракта (per-tenant спека)
  18 AbuseDetection       BOLA/BFLA (нужны проверенные роли из JWT → идёт после Auth);
                          object-ID берётся из пути, query, JSON-тела И аргументов GraphQL-операции
  19 DLP                  маскирует PII/PCI в ответах
  20 BehaviorAnalysis     поведенческий скоринг → авто-бан (fail-open намеренно)
  │
  ▼
Reverse proxy (internal/proxy) → backend
```

**Почему такой порядок (это спрашивают на ревью):**
- `TenantResolve` **первый** — всё ниже читает tenant из контекста.
- `CleanHeaders` рано — срезает поддельную идентичность/forwarding **до того**,
  как кто-либо им поверит.
- `LicenseRateLimit` **после** `CleanHeaders`, а не перед ним: его deny-путь
  зовёт `RealIP()`, а ни один контроль не должен читать клиентский forwarding-
  заголовок до санитизации. Сегодня безвредно (`RealIP` и так доверяет XFF
  только от `trusted_proxies`), но так инвариант «никто не читает identity-
  заголовки раньше CleanHeaders» остаётся тотальным, а не «тотальным, кроме
  одного лицензионного контроля».
- `PathSanity` до prefix-политик — чтобы `..%2f` не обошёл route/tenant matching.
  Все сайты сравнения путей по префиксу (route-gate, posture, tenant, JWT
  `Exclude`) обязаны идти через сегмент-безопасный `config.PathHasPrefix`, а не
  сырой `strings.HasPrefix` — это уже дважды ловилось как реальный баг (обход
  auth/WAF/DLP через соседний более открытый роут) и теперь энфорсится
  `scripts/lint-invariants.sh` (Invariant 1).
- `Discovery` сидит **внутри** WAF/rate-limit/bot (чтобы атаки не попадали в
  каталог) но **снаружи** auth/DLP (чтобы видеть идентичность, PII и финальный
  статус).
- `AbuseDetection` **после** `Auth` — ему нужны проверенные роли из JWT.
- `DLP` глубоко внутри — инспектирует **ответ** backend'а на обратном пути.

Каждый middleware — `func(http.Handler) http.Handler` (`internal/middleware/`).
Выключенная фича возвращает `passthrough` (no-op). Контролируемые per-route
(auth/WAF/DLP/rate-limit) оборачиваются в `RouteGate` — так override маршрута
реально энфорсится в data plane, а не только показывается в дашборде. Сам
резолвер route-override (`internal/discovery/posture.go`) — тоже
сегмент-безопасный (см. выше).

**Reverse proxy** (`internal/proxy/proxy.go`) — за цепочкой middleware: LB
(round-robin), circuit breaker per-upstream, ретрай только идемпотентных
методов. `routes[].methods` и `routes[].strip_prefix` реально энфорсятся на
этом уровне (не только видны в конфиге) — неразрешённый метод получает `405` с
`Allow`, `strip_prefix` обрезает совпавший префикс перед проксированием.

---

## 4. Разбор middleware

| Middleware | Файл | Что делает / на что смотреть при ревью |
|-----------|------|----------------------------------------|
| **TenantResolve** | `middleware/tenant.go` | tenant по route `tenant_id` (авторитетно) и/или Host, **регистронезависимо**. Mismatch/unresolved → 404 (без enumeration). Матч префикса — **сегментный** (`config.PathHasPrefix`), не сырой. |
| **CleanHeaders** | `middleware/clean_headers.go` | Срезает `X-Gateway-*` (подписанная идентичность), `X-JA3-Fingerprint`, и весь `X-Forwarded-*`/`Forwarded` семейство — если непосредственный peer **не** `trusted_proxy`. Затем сам ставит авторитетный `X-Real-IP`. |
| **TLSFingerprint** | `middleware/tlsfp.go`, `internal/tlsfp` | JA3-подобный фингерпринт из ClientHello (когда гейт терминирует TLS), биндится к соединению. Спуфящийся входной заголовок всегда срезан. |
| **RealIP** (helper) | `middleware/helpers.go` | `X-Forwarded-For` парсится **справа-налево**, доверяются только IP из `trusted_proxies`. Первый недоверенный = реальный клиент. `trusted_proxies` пересобирается атомарно на hot-reload (не полу-применённое состояние на гонке). Мисконфиг ломает все per-IP контроли. |
| **IPGuard** | `middleware/ipguard.go` | Whitelist (всегда пропуск) / статич. blacklist / динамич. blocklist (Redis) — **CIDR-aware**, не только точные IP. `fail_closed` → deny при недоступности Redis. |
| **RateLimit** | `middleware/ratelimit.go` + `store/redis.go` | Fixed-window через Lua-скрипт (EXPIRE только при создании ключа — иначе окно «зависает» навечно). Per-route ключи, `fail_closed` опционально. |
| **WAF** | `middleware/waf.go` | Coraza. См. раздел 8. Опциональный `fail_closed` — deny вместо тихого passthrough, если движок не смог инициализироваться (битый `ruleset_path`/CRS-директивы). |
| **Auth (JWT)** | `middleware/jwt.go` | HMAC или JWKS. Защита от alg-confusion, fail-closed при недоступном JWKS, `exp` обязателен, JTI-revocation. Подписывает identity вниз. См. раздел 7. |
| **AbuseDetection** | `middleware/abuse.go` | BOLA (enumeration объектов — из **пути, query и тела**, включая batch-параметры `?id=1&id=2` и `+json`-варианты content-type), BFLA. Адаптивный baseline per-consumer, allowlist, ownership-детект по телу ответа. Proactive ownership-block умеет `fail_closed`. |
| **DLP** | `middleware/dlp.go` + `internal/classify` | Буферизует ответ (до 4 МБ), маскирует карты (Luhn), SSN, email, телефоны + кастомные regex. SSE/upgrade/сжатые тела — passthrough. |
| **BehaviorAnalysis** | `middleware/behavior.go` + `store/redis.go` | Скоринг per-IP (объём, доля ошибок, энтропия путей, burst) → авто-бан. **Намеренно fail-open** (пропуск скоринга безопаснее блокировки всего трафика). |
| **SchemaValidation** | `middleware/schema.go` | Positive security: валидирует запрос против OpenAPI-спеки, **скопированной по tenant** (`discovery.spec_path` — дефолт, per-tenant спека переопределяет). |
| **PathSanity** | `middleware/path_sanity.go` | Режет traversal и закодированные разделители до prefix-политик. |
| **Challenge** | `middleware/challenge.go` | Anti-bot challenge; недоступность стора — **fail-open** (не блокирует легитимный трафик из-за сбоя Redis). |

---

## 5. Backends состояния

### Redis (`internal/store/redis.go`)
Быстрое эфемерное состояние. **Все ключи скоупятся по tenant**:
`tkey(ctx, suffix)` → `gw:t:<tenant>:<suffix>`. Fail-fast таймауты (гейт в hot
path: 1s dial / 500ms read-write) — чтобы outage Redis деградировал быстро, а не
копил горутины.

Семейства ключей (суффиксы): `rate:` (rate-limit окна), `blocked_ips`,
`behavior:<ip>:{reqs,errs,paths,burst,penalty,score}`, `ja3:<ip>`,
`autoban:<ip>`, `challenge:`/`challenge_solved:`, `metrics:`, `api_inventory` +
`api_params:`, `bola:`/`blbase:`/`objown:`/`objowner:` (abuse-детект),
`loginfail:` (per-IP и per-account брутфорс-гейт логина, включая
bootstrap-secret путь — см. раздел 6), `jwt:revoked:<jti>`, `forensic_log`
(кольцевой буфер, LTRIM 1000).

Исключения из tenant-скоупа (осознанно): `gw:session:<token>` и
`gw:oidc:flow:<state>` — сессия/флоу происходят **до** резолвинга tenant, а сам
tenant лежит внутри payload'а. Токены — случайные 64-hex, глобально уникальны.

### PostgreSQL (`internal/discovery` = каталог, `internal/forensic` = логи,
`internal/iam` = юзеры/тенанты, `internal/audit` = аудит)
Включается **только** если задан `forensic_dsn`. Без DSN каталог = nil, а
Discovery-middleware деградирует до passthrough. Схема идемпотентна (создаётся
на старте), tenant-изоляция через `tenant_id` + composite PK + (для каталога и
forensic) **RLS-политики** как fail-closed backstop.

Таблицы: `api_endpoints`, `api_endpoint_status`, `api_consumers`,
`api_endpoint_consumers`, `api_specs` (каталог); `forensic_logs`;
`tenants`, `admin_users` (`auth_source` = local/oidc); `admin_audit_log`.

---

## 6. Мультитенантность (ADR-001 — `docs/design/multitenancy.md`)

Жёсткая изоляция данных между организациями, резолвится на входе, тянется через
контекст:

- `internal/tenant` — **листовой** пакет (`tenant.With`/`tenant.From`, default
  `"default"`), импортируется всеми слоями без циклов. Tenant читается из `ctx`,
  никогда не протягивается руками через сигнатуры.
- `TenantResolve` (самый внешний) — резолвинг + срез клиентских `X-Tenant-*`,
  регистронезависимое сравнение маршрута/Host.
- Redis — префикс `gw:t:<tenant>:`.
- PostgreSQL — `tenant_id` в каждой таблице, `WHERE tenant_id` в каждом запросе,
  + RLS (`FORCE ROW LEVEL SECURITY`, GUC `app.tenant_id` через `set_config` в
  транзакции) как backstop.
- Admin-сессия несёт `tenant_id` + `role`; `AdminAuth` пинит запрос к tenant'у
  сессии (перекрывает то, что мог поставить TenantResolve).
- Брутфорс-гейт логина (`internal/api/auth_handlers.go`) считает попытки и
  по IP, и по (tenant, email) независимо, плюс отдельный, более широкий бюджет
  для bootstrap-secret пути (общий secret на весь деплой — не годится
  копировать per-account порог, иначе легитимный многоклиентский трафик
  ложно-срабатывает).
- При `multitenancy.enabled: false` всё работает как единственный tenant
  `default` (legacy single-tenant).

---

## 7. Распространение идентичности (`sdk/gatewayverify`)

После JWT-аутентификации гейт **подписывает** пробрасываемую вниз идентичность,
чтобы backend доверял `X-Gateway-*` только когда их произвёл гейт (а не клиент,
дотянувшийся до backend напрямую).

```
payload   = subject : roles : scopes : identity : ts : nonce
signature = hex( HMAC-SHA256(secret, payload) )      → X-Gateway-Signature
```

Заголовки: `X-Gateway-Subject / -Roles / -Scopes / -Identity / -Timestamp /
-Nonce / -Signature`. Backend через reference-SDK (`sdk/gatewayverify`)
проверяет **три** свойства: HMAC совпал (подлинность), `ts` свежий (≤ окна;
anti-replay старого перехвата), nonce не встречался (anti-replay внутри окна).
`CleanHeaders` срезает входные `X-Gateway-*`, так что клиент их не подделает.
Каждый выставляемый `X-Gateway-*` identity-заголовок обязан участвовать в
подписи — это отдельно энфорсится `scripts/lint-invariants.sh` (Invariant 2),
поймает будущий заголовок, который добавили в код, но забыли включить в payload.

Ключ подписи: `auth.propagation_secret` (env `AEGIS_PROPAGATION_SECRET`),
работает и в HMAC-, и в JWKS-режиме; fallback на `auth.secret`. Без секрета
подпись не ставится — и SDK backend'а отклонит запрос (правильный fail-closed).

---

## 8. WAF (`internal/middleware/waf.go`, движок Coraza)

Два режима:

1. **Starter-правила** (default при `waf.enabled: true`) — 13 правил под OWASP
   Top-10 (SQLi/XSS/RCE/LFI/SSRF/XXE/Log4Shell/request-smuggling/…), явный
   `deny 403` по паттерну. Каждое payload-инспектирующее правило (смотрящее в
   `ARGS`/`REQUEST_BODY`) обязано смотреть **и в `REQUEST_URI`** с
   трансформацией `t:urlDecodeUni` — иначе пейлоад, вставленный прямо в сегмент
   пути (`/orders/{payload}` вместо `/orders?id={payload}`), полностью обходил
   детект, несмотря на совпадение с паттерном (это ловилось как реальный баг
   дважды — на общем наборе правил и отдельно на SSRF-правиле). Это
   энфорсится `scripts/lint-invariants.sh` (Invariant 4) для каждого нового
   правила. Быстро, но паттерн-специфично — это **стартовый** набор, не
   полноценная защита.
2. **Полный OWASP CRS v4** (`waf.use_crs: true`) — ~900 правил + anomaly scoring,
   paranoia 1–4, порог блокировки настраивается. `block_mode: false` = только
   детект (DetectionOnly), чтобы отстроить false-positive перед энфорсом.

`waf.fail_closed` (опционально, default false — как и у RateLimit/IPGuard):
если движок Coraza не смог инициализироваться (битый `ruleset_path` или
CRS-директивы), запросы **отклоняются**, а не тихо проходят passthrough;
инцидент инициализации теперь считается в метрике `waf_init_failed`
**независимо** от этого флага, так что плохой деплой правил никогда не остаётся
незамеченным ни при одной настройке.

**XXE-предфильтр (`screenXXE`)**: у CRS v4 нет надёжного детекта XXE (его
XML-процессор «съедает» DTD-пролог). Поэтому в CRS-режиме перед Coraza работает
Go-предфильтр: читает ограниченную «голову» XML-тела, ловит структурный маркер
`<!DOCTYPE/ENTITY … SYSTEM/PUBLIC>`, блокирует (уважая `block_mode`) и
перематывает тело обратно. Без него включение CRS **убирало** защиту от XXE,
которая есть в starter-правилах. Покрыто тестами + live-фаззингом (43/43).

Тело инспектируется и для JSON, и для сырых типов: `jsonBodyDirectives`
принудительно включают body-processor (иначе body-borne payload обходил бы WAF
простым выбором `Content-Type`). Лимит тела 13 МБ, превышение — reject.

---

## 9. Пассивный discovery (`internal/discovery`)

`Discovery`-middleware эмитит `Observation` на каждый запрос. `Catalog`-воркер
агрегирует наблюдения в памяти по 5-секундным окнам и флашит роллап-дельты в
PostgreSQL (`upsert*` с `ON CONFLICT`-аккумуляцией).

- **Нормализация путей** (`normalize.go`): `/users/42` → `/users/{id}`.
- **Posture** (`posture.go`): классифицирует эндпоинт (protected / partial /
  unprotected / shadow) и считает risk-score 0–100. Резолвер маршрута —
  сегмент-безопасный (раздел 3).
- **Findings** (`findings.go`): API3 (PII без auth), API9 (shadow-эндпоинт с
  PII) и т.п. → `GET /api/findings` (critical-first).
- Чтения для admin API идут из PostgreSQL.

Это — **та самая продающая ценность**: «вот твои shadow-API и эндпоинты, что
отдают PII без авторизации, и кто их дёргает».

---

## 10. Конфигурация и секреты

- Конфиг — YAML (`config/gateway.yaml`), горячо перечитывается.
- **Секреты — только из окружения**, никогда из файла
  (`applyEnvOverrides`): `AEGIS_ADMIN_SECRET`, `AEGIS_JWT_SECRET`,
  `AEGIS_PROPAGATION_SECRET`, `AEGIS_REDIS_PASSWORD`, `AEGIS_FORENSIC_DSN`,
  `AEGIS_ALERT_WEBHOOK_URL`, `AEGIS_OIDC_CLIENT_ID`, `AEGIS_OIDC_CLIENT_SECRET`,
  `AEGIS_LICENSE_PATH`. Каждое такое поле обязано быть force-blanked в Helm
  ConfigMap (не течь в открытом виде, если оператор впишет его напрямую в
  `values.yaml`) — список выводится из самого `applyEnvOverrides`, а не
  копируется руками, и энфорсится `scripts/lint-invariants.sh` (Invariant 3):
  новое `AEGIS_*`-поле без парного «бланка» в ConfigMap ломает CI.
- `config.Validate` отклоняет: плейсхолдер-секреты **и низкоэнтропийные**
  секреты (повтор символа/короткий период — не только буквальный список
  плейсхолдеров), короткие admin/auth-секреты (< 32), несогласованные
  TLS/CORS/tenant-настройки, неизвестные стратегии LB, пустой
  `redis.password`, `require_tls` без `tls.enabled`. При hot-reload валидация,
  `InitTrustedProxies` и проверка лицензии прогоняются заново (иначе
  небезопасная правка уходила бы в прод без проверки).
- `scripts/check-weak-secrets.sh` — тот же класс проверки (включая
  низкоэнтропийные значения) для трёх секретов, которые идут напрямую в
  docker-compose и никогда не проходят через `config.Validate`:
  `AEGIS_REDIS_PASSWORD`, `POSTGRES_PASSWORD`, `GRAFANA_ADMIN_PASSWORD`.

---

## 11. Модель безопасности: fail-open vs fail-closed

Осознанный, per-control выбор поведения при отказе backing-store (Redis):

| Контроль | При отказе Redis | Почему |
|----------|-----------------|--------|
| RateLimit | `fail_closed` опц. (default open) | Оператор выбирает доступность vs строгость |
| IPGuard | `fail_closed` опц. (default open) | То же |
| JWT revocation | `fail_closed` опц. (default open) | High-assurance режим не пропустит отозванный токен |
| Admin-логин (per-IP/per-account брутфорс) | `admin_login_fail_closed` опц. (default open) | Самохостится — блип Redis не должен запирать оператора вне его же консоли |
| BOLA ownership-block | `ownership_fail_closed` опц. (default open) | Тот же принцип, что и выше — явный выбор оператора |
| WAF (init failure) | `waf.fail_closed` опц. (default open) | Битый ruleset — редкий deploy-time случай, не runtime-outage |
| BehaviorAnalysis, Challenge | **всегда fail-open** | Пропуск скоринга/challenge безопаснее блокировки всего трафика |
| Auth (подпись identity), лицензия | fail-closed по природе | Нет ключа/валидной лицензии → deny |

**Известный, осознанно не закрытый trade-off:** admin rate-limit, per-IP и
per-account `/api/login` гейты **каждый** по отдельности default
`fail_closed: false` — но один сбой Redis роняет все три одновременно,
оставляя только `subtle.ConstantTimeCompare` на сам секрет как последний
рубеж. Решение задокументировано в `RELEASE-CHECKLIST.md` (CHAIN-801):
осознанно оставлено fail-open по умолчанию (самохостимый продукт — блип Redis
не должен запирать оператора из его же консоли), при этом `admin_login_fail_closed`
и парные флаги доступны сегодня без изменения кода для тех, кому нужнее строгость.

Прочее, что закрыто в коде (по `RELEASE-CHECKLIST.md`): constant-time сравнения
(challenge, CSRF, admin-secret, HMAC), защита от JWT alg-confusion, stored XSS в
консоли (экранирование + event-delegation), CSV/formula-injection в экспорте,
ретрай прокси только для идемпотентных методов, санитайз `X-Request-ID`,
раздельный `admin_cors`, concurrency-стойкий throttle bootstrap-secret логина
(семафор с bounded-queue вместо голого `time.Sleep`, который таксировал только
latency, а не пропускную способность атакующего с множеством соединений —
раздел 6).

---

## 12. Маркетинговый сайт (`web/`) — отдельный периметр

`web/server.go` (бинарь `aegis-site`) — не gateway, отдельный маленький сервис
для визитки/лендинга и формы pilot-заявки, свой процесс, свой Dockerfile. Не
разделяет ни код, ни секреты с гейтвеем, но живёт в том же репозитории и стоит
знать его модель:

- `clientIP()` доверяет `CF-Connecting-IP`/`X-Forwarded-For` **только** за
  явным `TRUST_PROXY_HEADERS=1` (default off) — иначе прямой запрос мог бы
  подделывать IP на каждый вызов, обходя per-IP rate-limit формы и раздувая
  внутреннюю карту `seen` без ограничения.
- Карта `seen` дополнительно ограничена периодической чисткой (`sweep()`,
  каждые 5 минут) и жёстким потолком на число различных IP.
- Отправка email на успешную заявку — асинхронная, но число одновременных
  SMTP-отправок ограничено семафором, а не растёт неограниченно с потоком
  заявок.

---

## 13. Лицензирование (`internal/license`, `cmd/licensegen`)

Репозиторий — **Business Source License 1.1** (переход с MIT), см. `LICENSE`:
продакшн-использование требует коммерческой лицензии или письменного
соглашения; через 4 года после каждого релиза код переходит на Apache 2.0.

**Механизм.** `internal/license` + офлайн `cmd/licensegen` выпускают подписанные
Ed25519-лицензии (`licensee`, `tier`, `expiry`, `features`, `max_rps`,
`hardware_id`); публичный ключ вшивается в бинарь на этапе сборки
(`-ldflags`), приватный никогда не попадает в репозиторий. Гейтвей проверяет
лицензию:

- **на старте** — невалидная (отсутствует/просрочена/подделана/чужое железо)
  получает **то же обращение, что и провал `config.Validate`**: старт
  отказывает, деградированного бесплатного режима нет;
- **на каждом hot-reload** — невалидная лицензия отклоняет reload, старый
  конфиг продолжает работать (симметрично любому другому провалу валидации);
- **непрерывно между reload'ами** — долгоживущий процесс, чей `gateway.yaml`
  никто не трогает месяцами, не может вечно работать на снимке статуса,
  снятом при старте; поэтому истечение срока/смена железа обнаруживаются и
  без правки конфига.

**Node-locking.** `gateway -print-fingerprint` печатает детерминированный
отпечаток машины (SHA-256 от MAC-адресов невиртуальных сетевых интерфейсов).
Клиент снимает его на целевой машине **до** выдачи лицензии и передаёт вам;
вы вшиваете его в лицензию через `licensegen -hardware-id`. Смена железа не
роняет гейтвей мгновенно: первое расхождение фингерпринта открывает
персистентный grace-период (`license.LoadWithGrace`/`DefaultHardwareGrace`,
72 часа) — гейтвей полностью функционален, но громко предупреждает в логах и
в консоли; по истечении окна без переиздания — жёсткий отказ, как при
просрочке. В Docker/k8s без закреплённого MAC обычный редеплой контейнера
выглядит как «смена железа» — см. `docs/licensing.md`.

**Энфорсмент прав (tier / features / max_rps).** Поля в claims не декоративные:
`trial`/`pilot` — предкоммерческие тарифы, их `RequiresObserve()` принудительно
переводит гейтвей в Observe **вне зависимости** от конфига оператора (enforce
на триале невозможен в принципе, а не «не рекомендуется»). `CheckFeatureGates`
отклоняет **старт/reload**, если конфиг включает неоплаченную фичу
(`multitenancy`, `oidc`) — не тихий даунгрейд: оператор не должен считать, что
контроль защищает трафик, когда он структурно не запущен. Пустой список
`features` — безрестрикционный, поэтому все ранее выданные лицензии продолжают
работать без изменений. `max_rps` — реальный глобальный потолок
(`middleware.LicenseRateLimit`, шаг 3 цепочки), и он **fail-OPEN** при
недоступности стора: это коммерческое ограничение, а не security-контроль, и
лицензионная формальность не имеет права превращаться в аутэйдж.

Граница, которую стоит знать: tier/features применяются в `loadValidatedConfig`,
т.е. на старте и на hot-reload. Периодическая перепроверка их **не** переприменяет
(она по дизайну только делает статус громким и актуальным, не трогая поведение
трафика на ходу) — значит tier это решение на момент старта, а не непрерывно
энфорсимое свойство. Подробности и почему так — `docs/licensing.md`.

**Self-service переиздание.** `cmd/licenseserver` автоматизирует случай «сменилось
железо, срок тот же»: `POST /reissue` проверяет подпись предъявленной лицензии
этим же ключом, отклоняет уже просроченную (402 — бесплатного продления нет),
переносит остальные claims без изменений и переподписывает под новый отпечаток.
Держит приватный ключ в памяти — осознанный отход от полностью офлайнового
`licensegen`, с прописанными в `docs/licensing.md` ограничениями развёртывания.

**Видимость.** `GET /api/license` (`Server.SetLicenseStatus`, обновляется на
каждом boot/reload/периодической перепроверке) + баннер в консоли
(`web/console/src/components/LicenseBanner.tsx`) — молчит, когда всё в
порядке, предупреждает заранее до истечения, жёстко предупреждает во время
grace-периода или при невалидном статусе. Статус виден в UI, а не только в
логах гейтвея.

Криптографическое ядро (Ed25519 sign/verify, fail-closed по умолчанию,
отсутствие обхода/бэкдора/«звонков домой») подтверждено отдельным
восьмиагентным аудитом — см. `RELEASE-CHECKLIST.md`, P2-2.

---

## 14. Тестирование и CI

- `make test` — `go test ./... -v -race`. Интеграционные тесты (`store`,
  `discovery`, `iam`, `api`, `forensic`, `retention`, `audit`) скипаются без env-переменных Redis/PostgreSQL; в CI
  поднимаются service-контейнерами.
- **Coverage gate** (`scripts/coverage-gate.sh`) — пер-пакетные пороги,
  ratchet к 70% (включая `internal/license` floor 90%, `internal/gql` 90%,
  `internal/forensic` 80%).
- **Lint-инварианты** (`scripts/lint-invariants.sh`) — 4 проектных
  security-правила, которые обычный линтер не выразит:
  1. запрет сырого `strings.HasPrefix` на переменной-пути (не только буквально
     `r.URL.Path` — любой идентификатор, оканчивающийся на `path`/`Path`);
  2. каждый `X-Gateway-*` identity-заголовок обязан быть в подписи;
  3. каждое `AEGIS_*`-секретное поле обязано быть force-blanked в Helm
     ConfigMap (список derive'ится из `applyEnvOverrides`);
  4. каждое payload-инспектирующее WAF-правило обязано смотреть в
     `REQUEST_URI`.

  Каждый инвариант кодирует реально случившийся (и не один раз) баг.
- **Dynamic scan** (`.github/workflows/security-scan.yml`) — `tests/pentest.sh`
  (WAF/auth smoke, включая path-embedded-инъекции — не только query-string) +
  nuclei по admin-плоскости. Воркфлоу генерируют одноразовый Ed25519-ключ и
  тестовую лицензию через сам `cmd/licensegen`, чтобы лицензионный hard-gate
  не ронял CI.
- CI-воркфлоу: `test.yml`, `lint.yml`, `security.yml` (gosec + govulncheck),
  `security-scan.yml`, `e2e-smoke.yml`.

Проверено динамически (нативный стенд): `pentest.sh` зелёный после каждого
раунда фиксов; WAF-фаззинг 43/43 после фикса XXE; nuclei admin-плоскость —
0 high/critical; DLP-редакция доказана end-to-end через реальный ReverseProxy
на chunked-ответе.

---

## 15. Честные пробелы (читайте это на ревью)

Не скрываю — эти люди всё равно спросят:

- **Внешнего независимого пентеста не было.** Внутреннее adversarial-тестирование
  проведено многократно, разными заходами (см. раздел 14 +
  `docs/security/external-pentest-scope.md`), но оно **не заменяет** внешний.
  Это гейт до платного пилота (ROADMAP P0-1).
- **Повторяющийся класс багов, который стоит явно назвать самим:** несколько
  фиксов в истории этой ветки применяли паттерн исправления к *некоторым*
  экземплярам класса бага (одно WAF-правило, один сайт сравнения путей, один
  Redis-backed hard-block), пропуская родственные экземпляры того же класса в
  той же кодовой базе — ловилось только благодаря повторным аудитам той же
  ветки. Разделы 3, 7, 8, 10 выше отмечают, какие из четырёх lint-инвариантов
  теперь делают соответствующий класс самоэнфорсящимся — но это признание
  паттерна, а не гарантия, что других таких классов не осталось.
- **Детект атак на API — частично.** BOLA/BFLA + data-exposure findings есть и
  недавно расширены (query-batching, body-based ID, `+json`-варианты). Mass
  assignment (API6), injection-паттерны, broken-auth velocity, полноценный
  anomaly-baseline per-consumer — **не готовы**. Это главная продуктовая
  ценность и она наполовину (ROADMAP P1-1, P1-2).
- **Deployment только inline.** Out-of-band (зеркалирование трафика) и интеграции
  с Kong/Apigee/AWS API GW — нет (P1-5).
- **Интеграции/алертинг** (Slack/PagerDuty/SIEM) — минимальны (P1-3).
- **Не фаззилось глубоко:** HTTP request smuggling на TCP-уровне, ReDoS под
  нагрузкой, blind/OOB XXE. Вписано в scope внешнего пентеста.
- **Лицензирование — v1, не полноценный metering.** Node-locking и hard-gate
  реальны и работают; тарифное принуждение по `tier`/`features`/`max_rps`,
  self-service переиздание при смене железа, revocation-лист — не готовы (см.
  ROADMAP P2-2).
- **Ноль реальных внедрений.** Сейчас это сильное техно-демо, не боевой продукт.

Источник правды по «сделано vs открыто» — `ROADMAP.md` и `RELEASE-CHECKLIST.md`,
они поддерживаются в актуальном состоянии.

---

## Приложение: карта репозитория

```
cmd/gateway/main.go        точка входа: два сервера, lifecycle, hot-reload, лицензия
cmd/licensegen/             офлайн-утилита выпуска подписанных лицензий
cmd/licenseserver/          self-service переиздание лицензии при смене железа (ключ онлайн!)
internal/gateway/chain.go  сборка data-plane цепочки (порядок middleware)
internal/middleware/       все middleware + ports.go (интерфейсы) + fakes_test.go
internal/proxy/            reverse proxy, LB, circuit breaker, retry, methods/strip_prefix
internal/store/            Redis: rate/blocklist/behavior/bola/session/forensic/login-throttle
internal/discovery/        пассивный каталог, нормализация, posture, findings, PG
internal/forensic/         forensic-логи в PostgreSQL (батчинг)
internal/iam/              тенанты + admin-юзеры (bcrypt), OIDC-провижининг
internal/sso/              OIDC: Authorization Code + PKCE, валидация ID-токена
internal/audit/            audit log админ-действий (PostgreSQL)
internal/license/           верификация Ed25519-лицензий, hardware-fingerprint, grace-период
internal/config/           конфиг, env-override секретов, Validate
internal/tenant/           листовой пакет tenant.With/From
internal/tlsfp/            JA3 из ClientHello
internal/classify/         типизированный детект PII (Luhn, SSN, email, phone)
internal/gql/              парсер GraphQL-over-HTTP (операция/поля/аргументы) для discovery+BOLA
internal/api/              admin API: хендлеры каталога/posture/auth/tenants/license/…
sdk/gatewayverify/         reference-SDK для backend'ов (проверка подписи)
web/                        отдельный маркетинговый сайт + pilot-форма (свой периметр, раздел 12)
scripts/lint-invariants.sh  4 проектных security-инварианта (раздел 14)
tests/pentest.sh            детерминированный WAF/auth smoke, включая path-embedded кейсы
docs/design/                ADR (мультитенантность и др.)
docs/security/              scope внешнего пентеста
docs/licensing.md           лицензионный workflow для операторов
ROADMAP.md, RELEASE-CHECKLIST.md   источник правды по готовности
```
