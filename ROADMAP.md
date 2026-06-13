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
| P0-1 | **Тесты почти отсутствуют** | Unit (middleware, store, proxy, jwt, dlp) + интеграционные (с Redis/PG в CI) + нагрузочные (k6/vegeta). CI-гейт на покрытие. | ≥70% покрытие критичных пакетов; CI блокирует merge при падении |
| P0-2 | **Нет реальной аутентификации консоли** | Логин/сессии, RBAC, MFA, SSO (OIDC/SAML). Сейчас статический bearer в sessionStorage. | Вход через OIDC; роли admin/viewer; сессии с истечением |
| P0-3 | **Нет мультитенантности** | Организации, пользователи, изоляция данных по tenant. | Данные каталога/forensic скоупятся по tenant_id |
| P0-4 | **JA3 фиктивный** | Реальный JA3/JA4 через TLS-терминацию (или убрать из обещаний). | Фингерпринт извлекается из TLS ClientHello, не из заголовка |
| P0-5 | **Fail-open при падении Redis** | Частково зроблено: rate limiter має opt-in `fail_closed` (deny при недоступності Redis). Залишилось: поширити на інші контролі + HA Redis (Sentinel/Cluster) у docs. | `fail_closed` для всіх контролів + перевірено тестом |

### 🟠 P1 — нужно для реальных сделок

| # | Разрыв | Что сделать |
|---|--------|-------------|
| P1-1 | **OWASP API Top-10 detection** | BOLA/BFLA, mass assignment, data-exfil. Использовать существующий catalog+consumer-граф как основу. **Главная продуктовая ценность.** |
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
