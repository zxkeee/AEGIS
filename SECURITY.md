# 🔐 Политика безопасности

## Отчет об уязвимостях

Если вы обнаружили уязвимость безопасности в AEGIS, **пожалуйста, НЕ создавайте public issue**. Вместо этого используйте:

### GitHub Security Advisory

Самый безопасный способ отправить отчет:

1. Перейдите на страницу [Security](https://github.com/zxkeee/AEGIS/security/advisories)
2. Нажмите **"Report a vulnerability"**
3. Заполните форму с деталями уязвимости
4. GitHub уведомит maintainers приватно

### Email (когда будет опубликован)

Альтернативный способ для экстренных ситуаций:
- 📧 security@aegis-gateway.io _(будет добавлено позже)_

---

## Ответ и разрешение

Мы обещаем:
- ✅ **Быстрый ответ** — В течение 24 часов рабочего дня
- ✅ **Справедливая оценка** — Детальный анализ уязвимости
- ✅ **Координация** — Вместе найти решение
- ✅ **Кредит** — Упомянем вас в patch release (если хотите)
- ✅ **90 дней** — Обычный срок для патча (или ранее, если возможно)

**Процесс разрешения:**
1. **Day 0** — Получение отчета и acknowledgement
2. **Day 1-7** — Анализ и разработка патча
3. **Day 8-14** — Тестирование и подготовка к release
4. **Day 15** — Release patch с благодарностью в CHANGELOG
5. **Day 90** — Публичное раскрытие уязвимости (если вы согласны)

---

## Известные уязвимости в зависимостях

Мы используем `go mod` для управления зависимостями. Проверить уязвимости можно:

```bash
# Встроенная проверка безопасности Go 1.22+
go list -json -m all | nancy sleuth

# Или используйте Dependabot (автоматически на GitHub)
# Или запустите локально: snyk test
```

Если вы нашли уязвимость в зависимости AEGIS:
- ✅ Мы немедленно обновим зависимость
- ✅ Выпустим patch version

---

## Рекомендации по безопасности при использовании

### 1. Конфигурация

- 🔒 **Admin Secret** — используйте сильный пароль (минимум 32 символа):
  ```yaml
  admin_secret: "super-long-random-secret-with-special-chars-!@#$%"
  ```

- 🔒 **Redis Password** — если Redis доступен по сети:
  ```yaml
  redis:
    addr: "redis-host:6379"
    password: "strong-redis-password"
  ```

- 🔒 **PostgreSQL Connection** — используйте SSL:
  ```yaml
  forensic_dsn: "postgres://user:pass@host:5432/aegis?sslmode=require"
  ```

### 2. Развертывание

- 🔒 **TLS/HTTPS** — всегда используйте HTTPS в production:
  ```bash
  # Используйте reverse proxy (nginx, Envoy) с TLS
  # или добавьте TLS поддержку в AEGIS (coming soon)
  ```

- 🔒 **Network Isolation** — поместите Redis и PostgreSQL в приватную сеть:
  ```bash
  # Правильно:
  Redis: приватная сеть (только AEGIS может подключаться)
  
  # Неправильно:
  Redis на 0.0.0.0 доступен для всех
  ```

- 🔒 **Firewall Rules** — ограничьте доступ:
  ```bash
  # Только нужные порты открыты
  :8080 — только внешний трафик (выключить в продакшене)
  :8081 — только внутри VPN/приватной сети
  :6379 — только AEGIS pods
  :5432 — только AEGIS pods
  ```

### 3. Мониторинг

- 📊 **Логирование** — включите логирование всех атак:
  ```yaml
  forensic_dsn: "postgres://..." # для Compliance
  ```

- 📊 **Alerts** — настройте оповещения в Prometheus/Grafana:
  ```
  - alert: HighWAFBlockRate
    expr: rate(aegis_waf_blocks_total[5m]) > 100
    for: 5m
  ```

- 📊 **Аудит** — регулярно проверяйте логи атак:
  ```sql
  SELECT * FROM aegis_forensic 
  WHERE timestamp > NOW() - INTERVAL '24 hours' 
  ORDER BY timestamp DESC;
  ```

### 4. Обновления

- 🔄 **Регулярные обновления** — проверяйте обновления еженедельно:
  ```bash
  git pull origin main  # Или проверьте GitHub releases
  ```

- 🔄 **Тестирование перед production** — всегда тестируйте патчи:
  ```bash
  # В staging environment
  make test
  docker-compose -f docker-compose.test.yml up
  ```

---

## Защита собственных backendов

AEGIS защищает ваши backendы, но они тоже должны быть безопасны:

### Backend должен проверять:
1. ✅ **X-Gateway-Signature** — криптографическую подпись AEGIS:
   ```go
   // Пример на Go
   import "crypto/hmac"
   import "crypto/sha256"
   
   func verifyGatewaySignature(body, signature, secret string) bool {
       h := hmac.New(sha256.New, []byte(secret))
       h.Write([]byte(body))
       expected := h.Sum(nil)
       return hmac.Equal(expected, []byte(signature))
   }
   ```

2. ✅ **X-Gateway-Subject** — информацию о user'е из JWT:
   ```
   X-Gateway-Subject: user:12345@example.com
   ```

3. ✅ **Origin запроса** — Referer/Origin headers не доверять

### Чего НЕ должен делать backend:
- ❌ Не проверять IP адреса (AEGIS может идти через load balancer)
- ❌ Не вырезать заголовки X-Gateway-* (их вырезает AEGIS)
- ❌ Не повторно проверять JWT (AEGIS уже проверил)

---

## Уязвимости, которые AEGIS защищает от

| Уязвимость | OWASP | AEGIS защита |
|-----------|-------|-------------|
| SQL Injection | A03:2021 | WAF (Coraza CRS) ✅ |
| Cross-Site Scripting (XSS) | A07:2021 | WAF (Coraza CRS) ✅ |
| Remote Code Execution (RCE) | A06:2021 | WAF (Coraza CRS) ✅ |
| Path Traversal / LFI | A01:2021 | WAF (Coraza CRS) ✅ |
| SSRF | A10:2021 | WAF (Coraza CRS) ✅ |
| XXE (XML External Entity) | A05:2021 | WAF (Coraza CRS) ✅ |
| HTTP Request Smuggling | Custom | WAF + Header Validation ✅ |
| DDoS / Flood | - | Rate Limiting ✅ |
| Bot Attacks | - | JA3 + Behavioral Scoring ✅ |
| Brute Force | - | Rate Limiting + Behavioral Scoring ✅ |
| Data Exfiltration | - | DLP (PII Masking) ✅ |
| Unauthorized Access | A01:2021 | JWT + JWKS ✅ |
| Man-in-the-Middle (MITM) | - | TLS (при HTTPS) ✅ |

---

## Тестирование безопасности

AEGIS регулярно тестируется на уязвимости:

```bash
# Static Analysis
make lint

# Security scanning
go run github.com/securego/gosec/v2/cmd/gosec ./...

# Dependency vulnerabilities
go list -json -m all | nancy sleuth

# Integration testing
go test ./... -v -race

# Load testing (помимо прочего, для DoS resistance)
# ab -n 100000 -c 100 http://localhost:8080/api/v1/health
```

---

## PCI-DSS Соответствие

AEGIS помогает соответствовать требованиям **PCI-DSS** (Payment Card Industry Data Security Standard):

| Требование PCI | AEGIS функция | Поддержка |
|---------------|--------------|----------|
| 6.5.1 SQL Injection | WAF (SQL-инъекции) | ✅ |
| 6.5.7 XSS | WAF (XSS) | ✅ |
| 6.5.10 Broken Authentication | JWT JWKS | ✅ |
| 3.4 Render PAN unreadable | DLP (Card Masking) | ✅ |
| 6.2 Source code review | Code scanning + logging | ✅ |
| 6.5.10 Security Testing | Prometheus metrics + Logging | ✅ |
| 10.1 Audit Trail | PostgreSQL Forensic | ✅ |
| 10.7 Retain history 1 year | PostgreSQL + архивирование | ✅ |

---

## Контакты и ресурсы

- 🐛 **Report vulnerability:** [GitHub Security Advisory](https://github.com/zxkeee/AEGIS/security/advisories)
- 📚 **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- 📚 **CWE Top 25:** https://cwe.mitre.org/top25/
- 📚 **Coraza WAF:** https://coraza.io/docs/

---

**Спасибо за помощь в защите AEGIS! 🙏**
