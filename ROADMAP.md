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
- ✅ WAF на Coraza: встроенные starter-правила ИЛИ полный **OWASP CRS v4** (`waf.use_crs`, ~900 правил + anomaly scoring, paranoia 1–4, monitor/block)
- ✅ Hot-reload конфига, graceful shutdown
- ✅ Forensic-логи в PostgreSQL (батчинг)
- ✅ Audit log админ-действий в PostgreSQL (`internal/audit`, async; `GET /api/audit`)

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
| P0-1 | **Тести майже відсутні** ✅ | Зроблено: regression-тести на всі недавні security-фікси (JA3-спуф, fail-closed rate-limit/IP-guard, підпис/replay ідентичності) + reference-SDK з тестами; CI-гейт покриття (`scripts/coverage-gate.sh`) із пер-пакетними порогами, що ratchet'яться до 70%. Поточно (перевірено проти живого Redis+PostgreSQL стенду): middleware 82%, store 85%, iam 82%, audit 80%, discovery 84%, gateway 87%, config 90%, proxy 92%, classify 93%, tlsfp/tenant 100%, gatewayverify 93%, sso 88%, retention 81%, **api 76%** (catalog/posture хендлери покрито через seeded live-каталог + requireAuth/error-шляхи). **Усі критичні пакети ≥70%** (у переліку floors). CI coverage-gate запускає інтеграційні тести (env Redis/PG на gate-кроці), floors зафіксовані на досягнутих рівнях (api ratchet 60→70). Нагрузочні — k6 у `tests/load/`. **Знайдено цим аудитом:** `internal/forensic` (PG forensic-sink, 279 рядків) — 0 тестів, немає у coverage-gate.sh, тобто фактично поза списком "критичні пакети". Залишилось: тест на `internal/forensic` + зовнішній незалежний pentest (не self-certify; scope вже описано в `docs/security/external-pentest-scope.md`). | ≥70% покриття критичних пакетів ✅; CI блокує merge при падінні ✅ |
| P0-2 | **Нет реальной аутентификации консоли** ✅ | Сделано: email+password логин через `internal/iam` (bcrypt, таблица admin_users в PG), HttpOnly session-cookie с CSRF, роли admin/viewer (viewer 403 на мутации), сессии с TTL, BootstrapRoot из env, bearer secret как super-admin для CLI/bootstrap. **OIDC SSO готов** (`internal/sso`): Authorization Code + PKCE, discovery, валидация ID-токена (подпись по JWKS провайдера, iss/aud/exp, nonce), маппинг claim→tenant/role, JIT-провижининг пользователя; `GET /api/auth/oidc/login`+`/callback`, кнопка в консоли; end-to-end тесты против локального IdP с реальной RS256-криптой + callback против живого PG. Осталось: SAML/SCIM, MFA (обычно закрывается на стороне IdP). | Вход через OIDC ✅; роли admin/viewer ✅; сессии с истечением ✅ |
| P0-3 | **Нет мультитенантности** 🟡 | ADR `docs/design/multitenancy.md` (модель B+A). **Этапы 1–2 готовы**: (1) `TenantResolve` middleware (route+host, mismatch/unresolved→404, срез `X-Tenant-*`), конфиг+валидация, `TenantID(ctx)`. (2) **PG-изоляция**: `tenant_id` во всех 5 таблицах (каталог+forensic), composite PK, tenant-leading индексы, идемпотентная миграция+backfill `default`, `WHERE tenant_id` в каждом запросе, проброс через листовой пакет `internal/tenant`; cross-tenant deny-тест. (3) **Redis-изоляция**: все ~15 семейств ключей через `tkey(ctx)` → `gw:t:<tenant>:<suffix>`, `GetMetrics` скоупится; cross-tenant deny-тесты (blocklist/metrics/rate/session/forensic). (4) **Console sessions + RBAC**: пакет `internal/iam` (таблицы `tenants`/`admin_users`, bcrypt, BootstrapRoot), сессия несёт `tenant_id`+`role` (admin/viewer), `AdminAuth` пинит запрос к tenant сессии и блокирует мутации viewer'а (403). Bearer secret = super-admin/default (бэкстоп). Логин принимает `{secret}` или `{email,password,tenant}`. Cross-tenant deny подтверждено: VerifyPassword (чужой tenant ⇒ ErrUserNotFound, без enumeration), middleware (viewer mutation ⇒ 403). (5) **Tenant + user CRUD API**: `/api/tenants` (super-admin) + `/api/users` (admin own-tenant or super-admin), `iam.SuperAdmin` в context, 12 cross-tenant deny + RBAC тестов против live PG. (2b) **RLS fail-closed backstop**: `ENABLE/FORCE ROW LEVEL SECURITY` + policy `current_setting('app.tenant_id', true)` на всех 5 таблицах каталога+forensic; `pgStore.withTenantTx` пинит GUC через `set_config(...,is_local=true)` в транзакции; `TestPG_RLS_FailsClosedWithoutGUC` (unscoped SELECT=0 rows) + `TestPG_RLS_RejectsCrossTenantWrite` (`WITH CHECK` блокирует кросс-tenant INSERT). (6) **Нагрузка/HA**: `tests/load/multitenant_load.js` — k6-сценарий с tenant-микс трафиком и optional attack-каналом, per-tenant p50/p95/p99 в summary; `docs/runbooks/ha.md` — топология (Sentinel + PG streaming repl), матрица failure modes (что fail-open/fail-closed), capacity rules-of-thumb + **RLS-gotcha role hardening** (`ALTER ROLE … NOSUPERUSER NOBYPASSRLS`, startup-warning в `newPGStore`). Первый прогон в `tests/load/results-2026-06-21.md`: **MT overhead в шуме** (373.6→375.7 RPS, p50 +0.6ms). **МТ закрыта на 6/6 этапов** end-to-end (код + тесты + доки + жива валідація). | Данные каталога/forensic скоупятся по tenant_id |
| P0-4 | **JA3 фіктивний** ✅ | Зроблено: спуфящийся заголовок `X-JA3-Fingerprint` тепер зрізається (`CleanHeaders`); реальний фінгерпринт рахується з TLS ClientHello на gateway (`internal/tlsfp`, JA3-style по доступних у stdlib полях, GREASE відфільтровано), і gateway реально термінує TLS (`ListenAndServeTLS`). Канонічний JA3 (список розширень) — майбутнє уточнення. | Фінгерпринт із ClientHello, не із заголовка ✅ |
| P0-5 | **Fail-open при падінні Redis** 🟡 | Зроблено: `fail_closed` для rate limiter **і** IP-guard (deny при недоступності Redis, покрито тестами). Behavior-scoring навмисно лишається fail-open (gap у скорингу безпечніший за блок усього трафіку). Залишилось: HA Redis (Sentinel/Cluster) у docs. | `fail_closed` для enforcement-контролів + тести ✅ |

### 🟠 P1 — нужно для реальных сделок

| # | Разрыв | Что сделать |
|---|--------|-------------|
| P1-1 | **OWASP API Top-10 detection** 🟡 | Сделано: BOLA/BFLA (`AbuseDetection`, + adaptive baseline A2 + allowlist A6); **data-exposure findings** (`discovery.DetectFindings`): API3 (PII без auth — confirmed critical при анонимном трафике, latent warning при не-enforced auth), API9 (shadow-endpoint, отдающий PII); вид `GET /api/findings` (critical-first, by_severity). Дальше: mass assignment (API6), injection-паттерны, broken-auth velocity. **GraphQL:** BOLA/BFLA и discovery уже видят GraphQL-трафик (B5, Часть II); data-exposure findings (API3/API9) — ещё нет, PII детектится content-based, но не привязывается к GraphQL-операции по схеме. **Главная продуктовая ценность.** |
| P1-2 | **Anomaly detection** | Поведенческий baseline per-consumer, анализ последовательностей, отклонения объёма/паттернов. |
| P1-3 | **Интеграции/алертинг** | Slack / PagerDuty / SIEM (Splunk, Elastic), настраиваемые вебхуки, экспорт событий. Сейчас webhook захардкожен пустым. |
| P1-4 | **OpenAPI / spec drift** | Импорт спецификации; сравнение «задокументировано vs реально в трафике»; валидация схемы. |
| P1-5 | **Модели развёртывания** 🟡 | Сделано: **observe / pilot режим** (`observe: true`) — гарантированно-безопасная inline-посадка для первого пилота: `ApplyObserveMode` коэрсит всю security-конфигурацию (после Validate, на старте и hot-reload) в «инспектируй и записывай, но ничего не блокируй / не модифицируй / никогда не fail-closed». WAF→DetectionOnly (built-in `deny`-правила тоже, не только CRS), DLP классифицирует PII но не редактирует тело, JWT soft (identity из валидного токена, иначе pass-through, без 401), abuse/schema detect-only, чисто-enforcement контроли выключены, per-route rate-limit override снят. Юнит-тесты (config/DLP/JWT) + живая проверка на бинаре (SQLi/XSS/no-JWT/rate-limit → 200 pass-through, PII не редактируется, enforce всё ещё блокирует), плюс живой BOLA-сценарий против готового `config/gateway.pilot.yaml` (`owner_fields` в шаблоне, confirmed IDOR виден в `/api/compliance`+`/api/block-log`, запрос не блокируется). Latency/throughput на железе (NUC, 20 VUs): observe не медленнее enforce — `tests/load/observe-mode-results-2026-07-31.md`. Док `docs/pilot-mode.md`. Дальше: **out-of-band** (зеркалирование трафика/eBPF, снимает inline-хоп) + интеграция с Kong/Apigee/AWS API GW. |
| P1-6 | **Retention / масштаб данных** 🟡 | Сделано: фоновый retention-sweep (`internal/retention`) — периодически удаляет строки старше настроенного окна из растущих без ограничений таблиц: `forensic_logs`, `admin_audit_log`, consumer-граф (`api_consumers`/`api_endpoint_consumers` + orphan-очистка). Каталог `api_endpoints` намеренно не трогается (ограничен нормализацией). Конфиг `retention` (interval + per-table `*_days`, 0 = хранить вечно); одна maintenance-транзакция с RLS escape-hatch `app.tenant_id='*'` чистит кросс-tenant; интеграционные тесты против живого PG + живой прогон бинаря (`forensic_deleted:1`). Осталось: rollup агрегатов (свёртка старого в суммарники вместо удаления), бэкапы/PITR (ops), батчинг больших DELETE. |
| P1-7 | **HA / scale** | Бенчмарки латентности/RPS, описание кластеризации, отказоустойчивость PG. |

### 🟡 P2 — конкурентная дифференциация

| # | Разрыв | Что сделать |
|---|--------|-------------|
| P2-1 | **Compliance-отчётность** 🟡 v1 | Сделано: `GET /api/compliance` + вкладка Compliance — находки (PII-exposure, shadow-API) и рантайм access-control abuse (BOLA/BFLA) маппятся на контроли **NIS2** (Art. 21(2)) и **ISO/IEC 27001:2022** (Annex A) через OWASP API Top-10 (напр. IDOR → NIS2 Art.21(2)(i) / ISO A.8.3), с severity и списком issues; чистая функция маппинга под тестом. Дальше: PCI-DSS/HIPAA/GDPR/DORA-шаблоны, экспорт отчёта (PDF/CSV), data residency, DSAR. |
| P2-2 | **Лицензирование/метеринг** 🟡 v1 | Сделано: `internal/license` + офлайн `cmd/licensegen` — подписанные Ed25519 лицензии (licensee/tier/expiry/features/max_rps/**hardware_id**), встраиваемый паблик-ключ (`-ldflags`, приватный ключ никогда не в репозитории), проверка на старте и на каждом hot-reload как **жёсткий гейт** — отсутствующая/просроченная/подделанная/выданная под другое железо лицензия получает то же обращение, что и провал `config.Validate` (старт отказывает; hot-reload отклоняется, старый конфиг продолжает работать). **Node-locking**: `license.Fingerprint()` — детерминированный отпечаток машины (SHA-256 от MAC-адресов сетевых интерфейсов), клиент снимает его командой `gateway -print-fingerprint` на своей машине и присылает вам, вы вшиваете в лицензию через `-hardware-id`; смена железа → 72-часовой grace-период (полностью функционален, громкий WARN в логах и в консоли) → по истечении grace — жёсткий отказ, как при просрочке. **Self-service переиздание** (`cmd/licenseserver`): отдельный HTTP-сервис держит приватный ключ онлайн и по `POST /reissue` (подпись старой лицензии + новый отпечаток) сам переиздаёт лицензию с тем же сроком/тарифом — без участия человека. Явный компромисс: ключ перестаёт быть чисто оффлайновым, это описано и предупреждено в `docs/licensing.md` (запускать на отдельной жёстко контролируемой инфраструктуре, за TLS, с осознанием, что это функционально сервис выдачи сертификатов). Известный нюанс — в Docker/k8s без закреплённого MAC обычный редеплой контейнера выглядит как «смена железа»; см. `docs/licensing.md`. **`GET /api/license` + баннер в консоли** — статус (valid/grace/причина/срок) виден в UI на всех страницах (`web/console/src/components/LicenseBanner.tsx`), не только в логах гейтвея; молчит, когда всё в порядке, предупреждает за 14 дней до истечения. Никакого бесплатного урезанного режима — без лицензии гейтвей просто не запускается. **Tier/feature/RPS-enforcement**: `trial`/`pilot` физически не может enforce'ить (принудительный Observe вне зависимости от конфига оператора — `license.RequiresObserve`); `-features` гейтует `multitenancy`/`oidc` через `CheckFeatureGates` (жёсткий отказ старта, если в конфиге включена фича не по лицензии; пустой список — безрестрикционно, обратная совместимость со всеми ранее выданными лицензиями); `-max-rps` — реальный потолок пропускной способности всего гейтвея (`middleware.LicenseRateLimit`, near-outermost в цепочке), коммерческое ограничение, не security-контроль — fail-open на Redis-outage. Репозиторий переведён с MIT на **BUSL 1.1** (`LICENSE`). Дальше: реальный usage-metering (учёт фактического потребления для биллинга), тарифные планы, revocation-лист. |
| P2-3 | **WAF maturity** 🟡 v1 | Сделано: полный **OWASP CRS v4** через Coraza (`waf.use_crs`, embedded `coraza-coreruleset`), anomaly scoring с настраиваемыми `paranoia_level` (1–4) и `anomaly_threshold`, monitor-режим (DetectionOnly при `block_mode:false`) для тюнинга FP перед enforcement, `ruleset_path` для операторских исключений. Дальше: управление false-positive и тюнинг правил из UI. |
| P2-4 | **UI-зрелость** 🟡 | Сделано: редизайн Overview/Findings/Compliance/Map под утверждённое направление; страница Settings (tenant/user CRUD + audit log — API уже существовал, UI не было); `GET /api/session` для восстановления сессии после reload. Дальше: временные диапазоны, пагинация каталога, нормальная библиотека графиков, drill-down фильтры. |
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
| A1. **BOLA/BFLA** ✅ v2 | Сделано: middleware `AbuseDetection` — (1) BOLA-**enumeration** через детект перебора object-ID одним потребителем (HLL distinct-count в окне) + adaptive baseline (A2); (2) BFLA через privileged-path + required-roles на проверенных JWT-ролях; (3) **BOLA-object-ownership / single-object IDOR**: учит, какие потребители трогают какие объекты (`TrackObjectOwner`, per-object owner-set в Redis, tenant-scoped), и флагует потребителя, который **успешно (2xx)** читает объект, принадлежащий другому малому набору потребителей и им ранее не тронутый — та самая одиночная IDOR, которую enumeration и сигнатурный WAF не видят. Ключевой discriminator: 4xx от бэкенда = авторизация сработала, не флагуем (детект после ответа). Detect-only/block режимы. **Confirmed-ownership (v2):** владелец берётся из **тела ответа** (`owner_fields`, напр. `user_id` — top-level или под `data`) и сверяется с subject — превращает эвристику в подтверждённую привязку объект→владелец (severity critical vs warning). **Proactive-block:** зная подтверждённого владельца, cross-owner доступ блокируется **до форварда** (`object_ownership_block`), а не только фиксируется; `ownership_bypass_roles` для support/admin. **Identity-claim:** владелец сверяется с настраиваемым claim'ом (`auth.identity_claim`, напр. `uid` → `X-Gateway-Identity`), а не только с `sub` — работает когда владелец ресурса не совпадает с subject (sub=email, owner=числовой id). **Method-независимое владение:** ключ владельца больше не содержит HTTP-метод, поэтому владелец, выученный из чтения (GET), защищает объект и от cross-owner **записи/удаления** (PUT/PATCH/DELETE) — блок tampering'а до форварда. Дальше: вложенные owner-поля/массивы, peer-group, ownership из POST-create (id из тела ответа). **GraphQL:** с B5 (v2) детект также видит id-образные аргументы top-level полей GraphQL-операций (`user(id: 42)`), не только REST path/query/body — единственное необойдённое ограничение сейчас: вложенные поля/фрагменты внутри GraphQL-запроса не обходятся, только top-level. | consumer-граф + catalog | сделано |
| A2. **Behavioral baseline на потребителя** 🟡 v1 | Сделано: онлайн per-consumer baseline для BOLA — EWMA (alpha=0.05) distinct-object-count на endpoint в Redis (`TrackBaseline`, Lua-атомарно), адаптивный порог `current > baseline*sensitivity` поверх абсолютного hard-ceiling `enum_threshold`; ловит спайк потребителя с низкой нормой (3→30), НЕ флагует легитимно-высокий профиль (норма 60); `adaptive_min_objects` floor против шума на крошечной базе; baseline не отравляется атакой (learn=false при пробое ceiling). Дальше: объём/время/гео/error-rate профиль, percentile вместо EWMA-множителя, peer-group, режим обучения. | observations | 3–4 нед |
| A3. **Account Takeover / credential stuffing** | Velocity логинов, impossible travel, смена устройства/JA3, всплеск 401→200. Отдельный высокоценный сценарий. | forensic + consumer | 2–3 нед |
| A4. **Business-logic abuse** | Enumeration, scraping, inventory-hoarding: детект перебора ID, аномальной полноты обхода ресурса. | normalize + catalog | 2 нед |
| A5. **Sequence anomaly** | Цепочки вызовов (Markov/n-gram); необычные последовательности как сигнал. | observations | 3–4 нед |
| A6. **Low false-positive tuning** 🟡 v1 | Сделано: `abuse.allowlist` — потребители (JWT subject или `ip:<addr>`), полностью исключённые из детекта (главный FP-killer для батч-джоб/индексеров/админов); severity на каждом событии (BFLA=critical на проверенных ролях, BOLA=warning как эвристика); поле `why` с человекочитаемым объяснением в forensic-записи (объяснимость «почему алерт»). Дальше: режим обучения (auto-baseline порогов, A2), per-rule severity-override. | весь detect | сквозной |

## Фаза B. Discovery breadth (рычаг внедрения)

| Ставка | Что построить | Усилие |
|---|---|---|
| B1. **Out-of-band сенсор (mirror/eBPF)** | Обнаружение без inline-развёртывания: приём зеркалированного трафика или eBPF-сенсор. Снимает барьер «боюсь ставить в прод». Часто решает сделку. | 4–8 нед |
| B2. **OpenAPI import + drift + enforcement** 🟡 v1 | Сделано: импорт спеки (OpenAPI 3 / Swagger 2), drift «задокументировано vs реально» (`GET /api/discovery/drift`), и **positive-security enforcement** (`security.schema`, `middleware.SchemaValidation`): запрос валидируется против документированной операции — query-параметры (required/type/enum) и JSON-тело (type/required/enum + `additionalProperties:false` ⇒ reject недокументированных полей, anti mass-assignment, API6). Monitor/block (422). Контракт v1 — config-level спека. Дальше: enforce per-tenant uploaded-спеки, path/header-параметры, форматы/bounds, авто-генерация спеки из трафика. | 2–3 нед |
| B3. **Мульти-источники** | Логи cloud-LB (ALB/Cloud Armor), service mesh, gateway-логи — не только наш прокси. | 3–4 нед |
| B4. **Zombie/deprecated/versioning** | Трекинг устаревших и неиспользуемых API, версий. | 1–2 нед |
| B5. **GraphQL support** 🟡 v3 (discovery + BOLA + DLP-attribution) | Сделано: `internal/gql` — парсер GraphQL-over-HTTP тела (`vektah/gqlparser`, без схемы/валидации), достаёт тип операции/имя/top-level поля и аргументы (резолвит `$variables`). Вайринг в `middleware.Discovery`: `security.api_inventory.graphql_path` (по умолчанию пусто = выключено) — catalog-ключ становится `/graphql/query/GetUser` вместо плоского `/graphql`. **BOLA/BFLA (A1, killer-фича) видит GraphQL**: id-образные аргументы top-level полей прокидываются в те же `TrackObjectAccess`/`TrackObjectOwner`, что и REST, scope по операции+полю. **DLP-привязка к операции подтверждена тестом, не просто предположение**: DLP пишет PII-находку в тот же `*discovery.Observation`, что Discovery уже создаёт с GraphQL-путём (Discovery оборачивает DLP в реальной цепочке) — находка на `query GetUser {...}` уже сегодня попадает на `/graphql/query/GetUser`, а не в общий бакет `/graphql` (`TestDiscovery_GraphQLOperationGetsPIIAttribution`); никакого отдельного GraphQL-кода в DLP не понадобилось. Fail-safe везде: неразбираемое тело молча падает на старое поведение, тело всегда восстанавливается байт-в-байт. `docs/graphql.md`. Побочно уже прикрыто: WAF (Coraza) инспектирует `application/json`-тело, сигнатурный слой видит GraphQL variables без доработок. **Ещё не сделано:** (1) **импорт схемы** (introspection/SDL) по образцу готового OpenAPI-импорта (B2) — декларативное знание, какое поле PII, какой аргумент — ID объекта, вместо детекта по контенту/эвристики по имени; без схемы также нет «undocumented operation» drift-детекта, аналога API9 для GraphQL; (2) вложенные поля/фрагменты не обходятся (только top-level селекшены) — актуально и для BOLA, и для DLP-атрибуции. | сделано (парсинг+discovery+BOLA+DLP-attribution); schema-импорт — 2–3 нед |

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
| E2. SSO 🟡: **OIDC + RBAC готовы** (`internal/sso`, Auth Code+PKCE, JIT-provisioning, claim→tenant/role); осталось SAML + SCIM + MFA | 2–3 нед |
| E3. Audit log 🟡 v1, retention/residency | Сделано: пакет `internal/audit` — персистентный лог админ-действий в PostgreSQL (`admin_audit_log`, та же БД, что forensic/catalog). `AdminAuth` пишет login/login_failed/logout/mutation/`denied:<reason>` через async best-effort writer (буфер 4096, неблокирующий путь запроса); запись несёт actor/role/super_admin/tenant/method/path/status/ip. Чтение `GET /api/audit` скоупится по tenant сессии, super-admin спанит все через `?all=true`. Осталось: retention/rollup, data-residency, экспорт, RLS-политика на `admin_audit_log` (пока изоляция на уровне приложения). | 2–3 нед |
| E4. Лицензирование/метеринг/тарифы 🟡 v1 (`internal/license`, см. P2-2) | осталось: 1–2 нед (metering + tier enforcement) |
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
3. **B5 GraphQL** — discovery, BOLA и DLP-привязка к операции (самое ценное)
   уже сделаны; осталось только импорт схемы, это уже не блокер продаж, можно
   не форсировать выше остальных пунктов.
4. **B1 out-of-band** — снять барьер внедрения.
5. **C1–C2 data-centric** — обоснование бюджета для покупателя.
6. **D1–D3 интеграции** — встраивание в стек клиента.
7. **A3/A4/B2 → E → F** — добивание до enterprise/scale.

> Реальность: фазы A–D в одиночку — это ~год плотной работы; E–F добавляют ещё
> столько же. «До идеала всё» = многолетний проект. Поэтому порядок критичен:
> каждый доведённый пункт уже даёт ценность, даже если следующие ещё не начаты.
