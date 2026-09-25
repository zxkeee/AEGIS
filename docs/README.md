# Документация AEGIS — карта

Двадцать с лишним файлов без входной точки — это не документация, а архив.
Здесь порядок чтения под конкретную задачу.

**Если вы вернулись к проекту после перерыва — читайте `handoff.md` в корне.**
Он один отвечает на вопрос «что происходит и почему».

---

## Мне надо выступать / отвечать на вопросы

| | |
|---|---|
| **[`qa-defence.md`](qa-defence.md)** | **Начните отсюда.** Что спросят, что отвечать, чем доказать за минуту. Отдельно — вопросы, на которые ответ слабый |
| [`product-brief-en.md`](product-brief-en.md) | Продуктовый бриф на английском: партнёру, инвестору, оценщику гранта, первому клиенту |
| [`PRODUCT.md`](PRODUCT.md) | Позиционирование — источник правды. Все остальные тексты наследуют формулировки отсюда |
| [`presentation-en.md`](presentation-en.md), [`presentation-uk.md`](presentation-uk.md) | Черновики презентаций |

Перед выступлением: `make stand`, потом `make demo` целиком, до конца.

## Мне надо это развернуть или интегрировать

| | |
|---|---|
| [`QUICK_START.md`](QUICK_START.md) | Первый запуск |
| [`DEPLOYMENT.md`](DEPLOYMENT.md) | Продакшен: Helm, Compose, секреты, TLS |
| [`mirror-mode.md`](mirror-mode.md) | Зеркало: копия трафика, ноль риска для клиента. **Так начинается пилот** |
| [`pilot-mode.md`](pilot-mode.md) | Observe: inline, но ничего не блокирует |
| [`../sdk/gatewayverify/README.md`](../sdk/gatewayverify/README.md) | Как бэкенд проверяет подпись личности — **защита от обхода шлюза** |
| [`siem.md`](siem.md) | Splunk, Elasticsearch |
| [`ticketing.md`](ticketing.md) | Jira, ServiceNow |
| [`runbooks/ha.md`](runbooks/ha.md) | Отказоустойчивость |
| [`runbooks/secret-rotation.md`](runbooks/secret-rotation.md) | Смена секретов |

## Мне надо понять, как это устроено

| | |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Два сервера в одном процессе, цепочка middleware, модель угроз |
| [`ARCHITECTURE_DEEP_DIVE.md`](ARCHITECTURE_DEEP_DIVE.md) | Длинный технический разбор: все 26 пакетов, 23 шага конвейера, схемы ключей, инварианты. Для технического due diligence |
| [`aegis-explained.md`](aegis-explained.md) | Длинное объяснение продукта своими словами |
| [`design/multitenancy.md`](design/multitenancy.md) | ADR-001: изоляция между организациями |
| [`behaviour-profile.md`](behaviour-profile.md) | Профиль потребителя — и почему не ML |
| [`graphql.md`](graphql.md) | Что видит и чего не видит в GraphQL |
| [`licensing.md`](licensing.md) | Лицензии, привязка к железу |

## Мне надо доказательства для регулятора

| | |
|---|---|
| [`compliance-evidence.md`](compliance-evidence.md) | NIS2, DORA, ISO 27001 — что чем закрывается и **что не закрывается** |
| [`forensic-seals.md`](forensic-seals.md) | Печати журнала: что обнаружимо, а что нет |
| [`support.md`](support.md) | Уровни важности, целевые сроки, что покрыто |

## Мне надо денег

| | |
|---|---|
| [`grants/poland.md`](grants/poland.md) | **Ścieżka SMART: заявки 29.10–29.12.2026.** Календарь, требования, ловушка R&D-гранта |
| [`eic-accelerator-roadmap.md`](eic-accelerator-roadmap.md) | EIC Accelerator — основной европейский трек |
| [`diana-grant-roadmap.md`](diana-grant-roadmap.md), [`unite-brave-nato-roadmap.md`](unite-brave-nato-roadmap.md) | Проверены и отклонены, с причинами |
| [`sales/offer.md`](sales/offer.md), [`sales/emails.md`](sales/emails.md), [`sales/pilot-checklist.md`](sales/pilot-checklist.md) | Материалы первого пилота |

## Мне надо проверить безопасность

| | |
|---|---|
| [`security/external-pentest-scope.md`](security/external-pentest-scope.md) | Scope независимого пентеста — написан, не заказан |
| [`../SECURITY.md`](../SECURITY.md) | Как сообщать об уязвимости |
| [`../RELEASE-CHECKLIST.md`](../RELEASE-CHECKLIST.md) | Гейт релиза: 52 закрыто, 17 наполовину, 3 открыто |

---

## Чего в документации нет, и это честно

- **Польской версии.** Всё на русском, английском или украинском.
- **Единого справочника API.** Маршруты описаны в README, отдельного
  справочника с примерами запросов и ответов нет.
- **Видеозаписи демо.** `make demo` работает вживую; записи, которую можно
  показать без интернета, нет — а на площадке Wi-Fi не работает никогда.
