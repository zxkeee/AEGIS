# 🛡️ AEGIS — Roadmap to a Commercial Product

Дорожная карта превращения AEGIS из сильного MVP в коммерческий продукт класса
API Security (Akamai / Salt / Noname). Оценка основана на фактическом состоянии
кода.

> Статус-легенда: ✅ готово · 🟡 частично · ❌ нет

---

## 1. Что уже работает

### Ядро шлюза
- ✅ Reverse proxy + round-robin LB + circuit breaker + retry (идемпотентные методы)
- ✅ Rate limiting на Redis (fixed-window, баг с вечным окном исправлен)
- ✅ JWT auth: HMAC + JWKS, защита от alg-confusion, fail-closed при недоступном JWKS
- ✅ DLP-маскирование ответов (стриминг, Flusher, Hijacker/WebSocket)
- ✅ IP-guard, threat feed, behavior scoring, challenge, security headers
- ✅ WAF на Coraza (🟡 12 самописных правил, не полный OWASP CRS)
- ✅ Hot-reload конфига, graceful shutdown
- ✅ Forensic-логи в PostgreSQL (батчинг)

### API Security слой
- ✅ Пассивный discovery с нормализацией путей (`/users/42` → `/users/{id}`)
- ✅ Posture (protected / partial / unprotected / shadow) + risk-scoring 0–100
- ✅ Per-route security override (require_auth / waf / dlp / rate_limit)
- ✅ Аналитика потребителей (JWT subject / API key / IP)
- ✅ Эффективность, coverage, отчёты (JSON/CSV)
- ✅ Дашборд: Catalog / Posture / Consumers

### Упаковка
- ✅ Helm chart, docker-compose, Prometheus-конфиг

**Вердикт:** сильный MVP / технологическое демо. Архитектура добротная.
До коммерческого продукта — разрывы ниже.

---

## 2. Разрывы до продукта

### 🔴 P0 — блокеры для платного пилота

| # | Разрыв | Что сделать | Критерий готовности |
|---|--------|-------------|---------------------|
| P0-1 | **Тести майже відсутні** 🟡 | Зроблено: regression-тести на всі недавні security-фікси (JA3-спуф, fail-closed rate-limit/IP-guard, підпис/replay ідентичності) + reference-SDK з тестами; CI-гейт покриття (`scripts/coverage-gate.sh`) із пер-пакетними порогами, що ratchet'яться до 70%. Поточно: proxy 89%, gatewayverify 93.4%, tlsfp 100%, config 82.7%, alert 75.6%, middleware 60.7%; discovery 39.5% unit + PG-інтеграційні тести (бігають у CI), api 18.4% (чисті хелпери). proxy/discovery/api було 26/23/11%. Нагрузочні — k6 у `tests/load/`. Залишилось: handler-інтеграційні тести api проти Redis/PG, опублікувати числа. | ≥70% покриття критичних пакетів; CI блокує merge при падінні |
| P0-2 | **Нет реальной аутентификации консоли** 🟡 | Сделано: email+password логин через `internal/iam` (bcrypt, таблица admin_users в PG), HttpOnly session-cookie с CSRF, роли admin/viewer (viewer 403 на мутации), сессии с TTL, BootstrapRoot из env, bearer secret сохранён как super-admin для CLI/bootstrap. Осталось: OIDC/SAML SSO, MFA. | Вход через OIDC; роли admin/viewer; сессии с истечением |
| P0-3 | **Нет мультитенантности** 🟡 | ADR `docs/design/multitenancy.md` (модель B+A). **Этапы 1–2 готовы**: (1) `TenantResolve` middleware (route+host, mismatch/unresolved→404, срез `X-Tenant-*`), конфиг+валидация, `TenantID(ctx)`. (2) **PG-изоляция**: `tenant_id` во всех 5 таблицах (каталог+forensic), composite PK, tenant-leading индексы, идемпотентная миграция+backfill `default`, `WHERE tenant_id` в каждом запросе, проброс через листовой пакет `internal/tenant`; cross-tenant deny-тест. (3) **Redis-изоляция**: все ~15 семейств ключей через `tkey(ctx)` → `gw:t:<tenant>:<suffix>`, `GetMetrics` скоупится; cross-tenant deny-тесты (blocklist/metrics/rate/session/forensic). (4) **Console sessions + RBAC**: пакет `internal/iam` (таблицы `tenants`/`admin_users`, bcrypt, BootstrapRoot), сессия несёт `tenant_id`+`role` (admin/viewer), `AdminAuth` пинит запрос к tenant сессии и блокирует мутации viewer'а (403). Bearer secret = super-admin/default (бэкстоп). Логин принимает `{secret}` или `{email,password,tenant}`. Cross-tenant deny подтверждено: VerifyPassword (чужой tenant ⇒ ErrUserNotFound, без enumeration), middleware (viewer mutation ⇒ 403). (5) **Tenant + user CRUD API**: `/api/tenants` (super-admin) + `/api/users` (admin own-tenant or super-admin), `iam.SuperAdmin` в context, 12 cross-tenant deny + RBAC тестов против live PG. (2b) **RLS fail-closed backstop**: `ENABLE/FORCE ROW LEVEL SECURITY` + policy `current_setting('app.tenant_id', true)` на всех 5 таблицах каталога+forensic; `pgStore.withTenantTx` пинит GUC через `set_config(...,is_local=true)` в транзакции; `TestPG_RLS_FailsClosedWithoutGUC` (unscoped SELECT=0 rows) + `TestPG_RLS_RejectsCrossTenantWrite` (`WITH CHECK` блокирует кросс-tenant INSERT). (6) **Нагрузка/HA**: `tests/load/multitenant_load.js` — k6-сценарий с tenant-микс трафиком и optional attack-каналом, per-tenant p50/p95/p99 в summary; `docs/runbooks/ha.md` — топология (Sentinel + PG streaming repl), матрица failure modes (что fail-open/fail-closed), capacity rules-of-thumb + **RLS-gotcha role hardening** (`ALTER ROLE … NOSUPERUSER NOBYPASSRLS`, startup-warning в `newPGStore`). Первый прогон в `tests/load/results-2026-06-21.md`: **MT overhead в шуме** (373.6→375.7 RPS, p50 +0.6ms). **МТ закрыта на 6/6 этапов** end-to-end (код + тесты + доки + жива валідація). | Данные каталога/forensic скоупятся по tenant_id |
| P0-4 | **JA3 фіктивний** ✅ | Зроблено: спуфящийся заголовок `X-JA3-Fingerprint` тепер зрізається (`CleanHeaders`); реальний фінгерпринт рахується з TLS ClientHello на gateway (`internal/tlsfp`, JA3-style по доступних у stdlib полях, GREASE відфільтровано), і gateway реально термінує TLS (`ListenAndServeTLS`). Канонічний JA3 (список розширень) — майбутнє уточнення. | Фінгерпринт із ClientHello, не із заголовка ✅ |
| P0-5 | **Fail-open при падінні Redis** 🟡 | Зроблено: `fail_closed` для rate limiter **і** IP-guard (deny при недоступності Redis, покрито тестами). Behavior-scoring навмисно лишається fail-open (gap у скорингу безпечніший за блок усього трафіку). Залишилось: HA Redis (Sentinel/Cluster) у docs. | `fail_closed` для enforcement-контролів + тести ✅ |

### 🟠 P1 — нужно для реальных сделок

| # | Разрыв | Что сделать |
|---|--------|-------------|
| P1-1 | **OWASP API Top-10 detection** 🟡 | Сделано: BOLA/BFLA (`AbuseDetection`, + adaptive baseline A2 + allowlist A6); **data-exposure findings** (`discovery.DetectFindings`): API3 (PII без auth — confirmed critical при анонимном трафике, latent warning при не-enforced auth), API9 (shadow-endpoint, отдающий PII); вид `GET /api/findings` (critical-first, by_severity). Дальше: mass assignment (API6), injection-паттерны, broken-auth velocity. **Главная продуктовая ценность.** |
| P1-2 | **Anomaly detection** | Поведенческий baseline per-consumer, анализ последовательностей, отклонения объёма/паттернов. |
| P1-3 | **Интеграции/алертинг** | Slack / PagerDuty / SIEM (Splunk, Elastic), настраиваемые вебхуки, экспорт событий. Сейчас webhook захардкожен пустым. |
| P1-4 | **OpenAPI / spec drift** | Импорт спецификации; сравнение «задокументировано vs реально в трафике»; валидация схемы. |
| P1-5 | **Модели развёртывания** | Out-of-band (зеркалирование трафика/tap) + интеграция с Kong/Apigee/AWS API GW. Сейчас только inline. |
| P1-6 | **Retention / масштаб данных** | Политики хранения, rollup агрегатов, бэкапы. `api_consumers`/forensic растут без ограничений. |
| P1-7 | **HA / scale** | Бенчмарки латентности/RPS, описание кластеризации, отказоустойчивость PG. |

### 🟡 P2 — конкурентная дифференциация

| # | Разрыв | Что сделать |
|---|--------|-------------|
| P2-1 | **Compliance-отчётность** | Шаблоны PCI-DSS / HIPAA / GDPR, классификация PII (сейчас regex), data residency, DSAR. |
| P2-2 | **Лицензирование/метеринг** | License-ключи, тарифы, учёт потребления. |
| P2-3 | **WAF maturity** | Полный OWASP CRS, управление false-positive, тюнинг правил из UI. |
| P2-4 | **UI-зрелость** | Временные диапазоны, пагинация каталога, нормальная библиотека графиков, drill-down фильтры. |
| P2-5 | **Документация** | Runbooks, upgrade path, миграции, SLA. |

---

## 3. Предлагаемая последовательность

1. **Надёжность** (P0-1) — тесты + CI-гейты. Право предлагать пилот.
2. **Идентичность** (P0-2, P0-3) — RBAC + SSO/MFA + мультитенантность. Допуск в enterprise.
3. **Killer-фича** (P1-1) — детект OWASP API Top-10, начиная с **BOLA/BFLA** на базе
   существующего consumer-графа. За это платят.
4. **Встраивание** (P1-3, P1-4) — SIEM/алертинг + OpenAPI drift.
5. **Рынок** (P1-5, P0-5, P1-7) — out-of-band режим + HA.

---

## 4. Стратегическое преимущество

У AEGIS уже есть **catalog + consumer-граф** (кто ходит → в какие endpoint'ы, с
auth/без, с PII/без). Это готовый фундамент для:
- **BOLA-детекта** (потребитель обращается к объектам, которые ему не принадлежат),
- **anomaly-ML** (baseline по потребителю),

чего нет у многих конкурентов уровня «WAF-обёртка». На этом строится
дифференциация.

---

## 5. Открытые вопросы для бизнеса

- Целевой сегмент: SMB self-hosted vs enterprise SaaS? (влияет на мультитенантность/биллинг)
- Модель поставки: self-managed (Helm) vs managed SaaS?
- Приоритет рынка: inline-защита vs out-of-band observability?

---

# Часть II. Competitive Bets — путь к топ-уровню

> Честный контекст: это план «довести каждый пункт до идеала». В одиночку это
> работа на годы. Единственный способ её осилить — строгая последовательность:
> один пункт доводится до конца, только потом следующий. Оценки усилий грубые и
> предполагают одного опытного разработчика.

## Фаза A. Detection moat (главный ров — за это платят)

Цель: перестать быть «WAF-обёрткой» и ловить то, что не ловит сигнатурный WAF.

| Ставка | Что построить | Опора на текущее | Усилие |
|---|---|---|---|
| A1. **BOLA/BFLA** ✅ v1 | Сделано: middleware `AbuseDetection` — BOLA через детект перебора object-ID одним потребителем (HLL distinct-count в окне), BFLA через privileged-path + required-roles на проверенных JWT-ролях. Detect-only/block режимы. Дальше: per-consumer baseline вместо фикс-порога (A2). | consumer-граф + catalog | сделано |
| A2. **Behavioral baseline на потребителя** 🟡 v1 | Сделано: онлайн per-consumer baseline для BOLA — EWMA (alpha=0.05) distinct-object-count на endpoint в Redis (`TrackBaseline`, Lua-атомарно), адаптивный порог `current > baseline*sensitivity` поверх абсолютного hard-ceiling `enum_threshold`; ловит спайк потребителя с низкой нормой (3→30), НЕ флагует легитимно-высокий профиль (норма 60); `adaptive_min_objects` floor против шума на крошечной базе; baseline не отравляется атакой (learn=false при пробое ceiling). Дальше: объём/время/гео/error-rate профиль, percentile вместо EWMA-множителя, peer-group, режим обучения. | observations | 3–4 нед |
| A3. **Account Takeover / credential stuffing** | Velocity логинов, impossible travel, смена устройства/JA3, всплеск 401→200. Отдельный высокоценный сценарий. | forensic + consumer | 2–3 нед |
| A4. **Business-logic abuse** | Enumeration, scraping, inventory-hoarding: детект перебора ID, аномальной полноты обхода ресурса. | normalize + catalog | 2 нед |
| A5. **Sequence anomaly** | Цепочки вызовов (Markov/n-gram); необычные последовательности как сигнал. | observations | 3–4 нед |
| A6. **Low false-positive tuning** 🟡 v1 | Сделано: `abuse.allowlist` — потребители (JWT subject или `ip:<addr>`), полностью исключённые из детекта (главный FP-killer для батч-джоб/индексеров/админов); severity на каждом событии (BFLA=critical на проверенных ролях, BOLA=warning как эвристика); поле `why` с человекочитаемым объяснением в forensic-записи (объяснимость «почему алерт»). Дальше: режим обучения (auto-baseline порогов, A2), per-rule severity-override. | весь detect | сквозной |

## Фаза B. Discovery breadth (рычаг внедрения)

| Ставка | Что построить | Усилие |
|---|---|---|
| B1. **Out-of-band сенсор (mirror/eBPF)** | Обнаружение без inline-развёртывания: приём зеркалированного трафика или eBPF-сенсор. Снимает барьер «боюсь ставить в прод». Часто решает сделку. | 4–8 нед |
| B2. **OpenAPI import + drift** | Импорт спеки, сравнение «задокументировано vs реально», schema-валидация, авто-генерация спеки из трафика. | 2–3 нед |
| B3. **Мульти-источники** | Логи cloud-LB (ALB/Cloud Armor), service mesh, gateway-логи — не только наш прокси. | 3–4 нед |
| B4. **Zombie/deprecated/versioning** | Трекинг устаревших и неиспользуемых API, версий. | 1–2 нед |

## Фаза C. Data-centric posture (язык покупателя)

| Ставка | Что построить | Усилие |
|---|---|---|
| C1. **Классификация данных** 🟡 v1 | Сделано: пакет `internal/classify` — типизированные детекторы (credit_card/ssn/email/phone) с валидацией (Luhn для карт, range-check для SSN) → категории PCI/PII; DLP редактирует и классифицирует из одного источника; типы персистятся per-endpoint (`api_endpoints.pii_types`, union на upsert) и протекают в находки («PCI (credit_card) отдаётся анонимам»). Дальше: PHI/secrets-словари, контекст (имя поля), confidence-скоринг. | 3–4 нед |
| C2. **Data lineage** | Карта «API → класс данных → защита → риск»; «эти 3 API светят карты без auth». | 2–3 нед |
| C3. **Compliance-маппинг** | Привязка к PCI-DSS/HIPAA/GDPR/SOC2, отчёты, drift-алерты, DSAR. | 3–4 нед |

## Фаза D. Response & integration (встраивание в стек)

| Ставка | Что построить | Усилие |
|---|---|---|
| D1. **SIEM/SOAR** | Splunk/Elastic экспорт, вебхуки, тикетинг (Jira/ServiceNow). | 2–3 нед |
| D2. **Алертинг** 🟡 v1 | Сделано: `alerting`-блок конфига — webhook URL, формат `generic`/`slack`, порог `min_severity`, env-override `AEGIS_ALERT_WEBHOOK_URL`. Дальше: per-rule routing, Teams/PagerDuty-шаблоны. | 1–2 нед |
| D3. **Prometheus-native** ✅ | Сделано: `GET /metrics` в text-формате 0.0.4 из Redis-счётчиков (`aegis_*`), за admin-bearer; scrape-конфиг в `prometheus.yml`. | сделано |
| D4. **Автоматический response** | Авто-блок с feedback-loop, simulation mode. | 2–3 нед |
| D5. **Shift-left / CI** | Проверка OpenAPI/posture на PR — заход к разработчикам. | 2 нед |

## Фаза E. Enterprise table-stakes (без них крупный клиент не купит)

| Ставка | Усилие |
|---|---|
| E1. Мультитенантность (организации, изоляция по tenant) | 4–6 нед |
| E2. SSO (OIDC/SAML) + SCIM + RBAC + MFA | 4–6 нед |
| E3. Audit log, retention/residency | 2–3 нед |
| E4. Лицензирование/метеринг/тарифы | 2–3 нед |
| E5. SOC2/ISO (процесс, не код) | месяцы |

## Фаза F. Scale & reliability (доказать «отлично работает»)

| Ставка | Усилие |
|---|---|
| F1. HA: Redis Sentinel/Cluster, реплики PG, fail-closed для всех контролей (🟡 fail-closed для rate-limit + IP-guard готов; HA Redis/PG — осталось) | 3–4 нед |
| F2. Бенчмарки latency/RPS (k6/vegeta), published numbers | 1–2 нед |
| F3. Distributed: central control plane + sensors, мульти-кластер | 6–10 нед |
| F4. Покрытие тестами ≥70% + интеграционные + e2e + нагрузочные | сквозной |

---

## Рекомендуемый порядок «геройства»

Сначала закрыть P0-блокеры релиза (аутентификация консоли, тесты), затем
строить ров и рычаги в таком порядке:

1. **A1 BOLA/BFLA** — самый ценный детект, опирается на готовый consumer-граф.
2. **A6 + A2** — baseline и контроль false-positive (без этого детект бесполезен).
3. **B1 out-of-band** — снять барьер внедрения.
4. **C1–C2 data-centric** — обоснование бюджета для покупателя.
5. **D1–D3 интеграции** — встраивание в стек клиента.
6. **A3/A4/B2 → E → F** — добивание до enterprise/scale.

> Реальность: фазы A–D в одиночку — это ~год плотной работы; E–F добавляют ещё
> столько же. «До идеала всё» = многолетний проект. Поэтому порядок критичен:
> каждый доведённый пункт уже даёт ценность, даже если следующие ещё не начаты.
