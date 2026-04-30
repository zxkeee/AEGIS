# 🤝 Руководство по контрибуции в AEGIS

Спасибо, что хотите внести вклад в AEGIS! Это руководство поможет вам начать.

## 📋 Процесс внесения изменений

### 1. Подготовка окружения

```bash
# Клонируйте репозиторий
git clone https://github.com/zxkeee/AEGIS.git
cd AEGIS

# Установите Go 1.22+
# На macOS: brew install go
# На Linux: wget https://go.dev/dl/go1.22.linux-amd64.tar.gz && tar -xzf ...

# Загрузите зависимости
go mod download

# Установите обязательные инструменты для разработки
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install golang.org/x/tools/cmd/goimports@latest
```

### 2. Создание ветки для работы

```bash
# Убедитесь, что вы в главной ветке
git checkout main

# Создайте новую ветку для вашей фичи/баг-фикса
git checkout -b feature/my-feature
# или
git checkout -b bugfix/issue-description
```

**Соглашение об именовании веток:**
- `feature/` — для новых функций
- `bugfix/` — для исправления ошибок
- `perf/` — для оптимизации производительности
- `docs/` — для улучшения документации
- `refactor/` — для рефакторинга кода

### 3. Разработка

#### Структура проекта

```
.
├── cmd/
│   └── gateway/           # Точка входа приложения
├── internal/
│   ├── api/               # API хендлеры (Admin API, метрики)
│   ├── middleware/        # Цепочка защиты (WAF, Rate Limit, Auth и т.д.)
│   ├── config/            # Парсинг конфигурации
│   ├── forensic/          # Логирование попыток атак
│   ├── store/             # Работа с Redis/PostgreSQL
│   ├── proxy/             # Логика обратного прокси
│   ├── logger/            # Структурированное логирование
│   └── alert/             # Система оповещений
└── charts/
    └── aegis/             # Helm Chart для K8s
```

#### Кодовые стандарты

1. **Форматирование кода:**
   ```bash
   make fmt
   # или вручную:
   go fmt ./...
   goimports -w .
   ```

2. **Линтинг:**
   ```bash
   make lint
   # или
   golangci-lint run ./...
   ```

3. **Тестирование:**
   ```bash
   make test
   # или
   go test ./... -v -race -cover
   ```

4. **Именование переменных и функций:**
   - Используйте ясные, описательные названия
   - Экспортированные функции должны начинаться с заглавной буквы
   - Локальные переменные в camelCase
   - Константы в UPPER_SNAKE_CASE

5. **Комментарии:**
   - Комментируйте экспортированные функции и типы
   - Комментарии к функциям должны начинаться с названия функции
   - Объясняйте "почему", а не "что"

#### Пример структуры функции

```go
// ValidateJWT проверяет и парсит JWT токен из заголовка.
// Возвращает claims если токен валиден, иначе ошибку.
func ValidateJWT(token string) (*Claims, error) {
	// реализация
}
```

### 4. Тестирование локально

```bash
# Запустите все тесты
make test

# Запустите тесты с покрытием
go test ./... -v -race -coverprofile=coverage.out

# Посмотрите отчет о покрытии
go tool cover -html=coverage.out
```

### 5. Локальное тестирование с Docker

```bash
# Запустите окружение полностью
make docker

# Проверьте работу:
# - Gateway API: http://localhost:8080
# - Admin Dashboard: http://localhost:8081
# - Prometheus: http://localhost:9090
# - Grafana: http://localhost:3000

# Остановите контейнеры
make docker-down
```

### 6. Коммиты

**Соглашение о сообщениях коммитов (Conventional Commits):**

```
type(scope): subject

body

footer
```

**Типы коммитов:**
- `feat:` — новая функция
- `fix:` — исправление ошибки
- `perf:` — оптимизация производительности
- `refactor:` — рефакторинг кода
- `test:` — добавление/изменение тестов
- `docs:` — изменения в документации
- `chore:` — изменения в build процессе, зависимостях и т.д.
- `style:` — форматирование кода

**Примеры:**

```bash
git commit -m "feat(middleware): add JA3 fingerprinting for bot detection"
git commit -m "fix(auth): prevent JWT signature bypass in RSA mode"
git commit -m "perf(waf): optimize regex compilation with caching"
```

### 7. Push и Pull Request

```bash
# Убедитесь, что все тесты проходят локально
make test lint

# Запушьте вашу ветку
git push origin feature/my-feature

# Создайте Pull Request на GitHub
```

**Требования к Pull Request:**

1. **Описание:**
   - Четко описывайте, что вы изменили и почему
   - Ссылайтесь на связанные issues (например: `Fixes #123`)
   - Добавьте скриншоты или логи при необходимости

2. **Чек-лист:**
   - [ ] Код прошел `go fmt` и `golangci-lint`
   - [ ] Все тесты проходят (`go test ./... -v -race`)
   - [ ] Добавлены/обновлены тесты для новой функции
   - [ ] Обновлена документация (README, комментарии в коде)
   - [ ] Нет merge conflicts

3. **Пример PR Description:**
   ```markdown
   ## Описание
   Добавлена поддержка ECDSA в валидации JWT токенов.
   
   ## Связанные issues
   Fixes #45
   
   ## Изменения
   - [ ] Добавлена поддержка алгоритма ES256
   - [ ] Обновлены тесты для ECDSA ключей
   - [ ] Добавлены примеры конфигурации в документацию
   
   ## Как протестировать
   ```bash
   make test
   docker-compose up -d
   # Проверить через админ-панель на http://localhost:8081
   ```
   ```

## 🐛 Отчеты об ошибках

Если вы нашли ошибку, пожалуйста, создайте issue с:

1. **Описанием проблемы** — что произошло
2. **Шагами воспроизведения** — как повторить ошибку
3. **Ожидаемое поведение** — что должно было произойти
4. **Окружением** — версия Go, ОС, конфигурация
5. **Логами** — вывод ошибки, логи приложения

Пример:

```markdown
## Bug Report

### Описание
Rate limiter не блокирует при превышении лимита.

### Шаги воспроизведения
1. Установите rate_limit: 10 req/sec в config
2. Отправьте 20 запросов подряд
3. Ожидайте блокировки после 10-го запроса

### Ожидаемое поведение
Запросы после 10-го должны быть отклонены с 429 Too Many Requests

### Окружение
- Go 1.22.1
- macOS 14.2
- Redis 7.2

### Логи
```
ERROR rate_limit exceeded for IP 192.168.1.1
```
```

## 📚 Ресурсы для разработки

- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Effective Go](https://golang.org/doc/effective_go)
- [Coraza WAF Documentation](https://coraza.io/docs/)
- [Redis Documentation](https://redis.io/documentation)
- [Kubernetes Helm Documentation](https://helm.sh/docs/)

## 🎯 Области приоритета для контрибуции

1. **Безопасность** — улучшение существующих механизмов защиты
2. **Производительность** — оптимизация критических путей
3. **Удобство использования** — улучшение документации и API
4. **Тестирование** — добавление unit-тестов и integration-тестов

## 📞 Вопросы и обсуждения

- Вопросы можно задавать в [GitHub Discussions](https://github.com/zxkeee/AEGIS/discussions)
- Для срочных проблем безопасности используйте GitHub Security Advisory

---

**Спасибо за вклад в AEGIS! 🙏**
