# 🚀 Быстрый старт AEGIS

Этот гайд поможет вам запустить AEGIS в течение 5 минут.

## Шаг 1: Клонирование репозитория

```bash
git clone https://github.com/zxkeee/AEGIS.git
cd AEGIS
```

## Шаг 2: Запуск с Docker Compose (Рекомендуется)

```bash
# Запустите все сервисы
docker-compose up -d --build

# Проверьте статус
docker-compose ps
```

Все сервисы будут запущены за 30-60 секунд.

## Шаг 3: Проверьте доступность

```bash
# Gateway API (Port 8080)
curl http://localhost:8080/api/v1/health

# Admin Dashboard (Port 8081)
open http://localhost:8081  # Или откройте в браузере вручную

# Prometheus
open http://localhost:9090

# Grafana
open http://localhost:3000  # admin/admin
```

## Шаг 4: Тестирование защиты WAF

Попробуйте SQL-инъекцию (должна быть заблокирована):

```bash
curl "http://localhost:8080/api/v1/users?id=1' OR '1'='1"
# Ответ: 403 Forbidden (WAF Block)
```

Попробуйте XSS (должна быть заблокирована):

```bash
curl "http://localhost:8080/api/v1/data?search=<script>alert(1)</script>"
# Ответ: 403 Forbidden (WAF Block)
```

Нормальный запрос (должен пройти):

```bash
curl http://localhost:8080/api/v1/health
# Ответ: 200 OK
```

## Шаг 5: Изучите Admin Dashboard

Откройте http://localhost:8081 в браузере и посмотрите:
- Real-time метрики
- Логирование атак
- API Inventory (обнаруженные эндпоинты)
- Управление конфигурацией

## Что дальше?

1. **Читайте полную документацию:** [README.md](../README.md)
2. **Конфигурируйте:** Отредактируйте `config/gateway.yaml`
3. **Разрабатывайте:** Смотрите [CONTRIBUTING.md](../CONTRIBUTING.md)
4. **Разворачивайте в production:** Читайте [DEPLOYMENT.md](./DEPLOYMENT.md) _(coming soon)_

## Остановка сервисов

```bash
docker-compose down
```

## Troubleshooting

### Порты уже заняты

```bash
# Найти какой процесс использует порт
lsof -i :8080

# Или используйте другие порты в docker-compose.yml
```

### Redis/PostgreSQL не подключается

```bash
# Проверить логи
docker-compose logs redis
docker-compose logs postgres

# Перезагрузить сервисы
docker-compose restart
```

### Admin Panel не открывается

```bash
# Проверить логи Gateway
docker-compose logs gateway

# Убедитесь, что Gateway запущен
docker-compose ps gateway
```

---

**Готово! AEGIS работает. Поздравляем! 🎉**
