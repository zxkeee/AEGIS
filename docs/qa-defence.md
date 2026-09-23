# Подготовка к вопросам — что спросят и что отвечать

> Внутренний документ. Для того, кто отвечает за техническую часть на
> презентации, звонке с клиентом, встрече с инвестором или защите гранта.
>
> Устроен так: **вопрос → честный ответ → чем доказать за минуту**. Английская
> формулировка дана там, где её произносить вслух.
>
> Главное правило всего документа: **на вопрос, ответа на который нет, надо
> отвечать «нет» и говорить, что вместо этого.** Пойманная неправда стоит
> сделки целиком; честное «нет» стоит одного пункта.

---

## 0. Что делать, когда не знаешь ответа

Это самое важное в документе, потому что этот случай точно будет.

Скажите: **"I don't know — I'll check and come back with the exact answer."**
Запишите вопрос при них. Ответьте письмом в тот же день.

Технический оценщик проверяет не эрудицию, а то, врёте ли вы под давлением.
Человек, который в одном случае из десяти говорит «не знаю» и потом присылает
точный ответ, выглядит **сильнее** того, у кого на всё готов ответ. Второму
перестают верить на первой же неточности, и дальше проверяют уже всё.

Что нельзя: придумывать цифру, говорить «наверное», обещать функцию, которой
нет. Любое из трёх, пойманное один раз, обнуляет всё остальное.

---

## 1. Вопросы, на которые ответ сильный

### «Меня можно обойти? Что мешает ходить в бэкенд мимо вас?»

Это первый вопрос любого грамотного инженера, и на него есть настоящий ответ,
а не сетевой совет.

**Ответ:** сеть — первый рубеж (бэкенд слушает только адрес шлюза), но он не
единственный. После проверки JWT шлюз **подписывает личность**:
`HMAC-SHA256` по длиннопрефиксной канонической строке в заголовке
`X-Gateway-Signature`. Бэкенд проверяет подпись, свежесть отметки времени и
повтор nonce через референсный SDK (`sdk/gatewayverify`). Запрос, пришедший
мимо шлюза, такой подписи не имеет и отвергается **самим бэкендом**.
Входящие `X-Gateway-*` от клиента срезаются на входе, поэтому подделать их
нельзя.

> "Network isolation is the first layer, not the only one. After authentication
> the gateway signs the forwarded identity, and your backend verifies that
> signature with our SDK. A request that did not come through AEGIS has no
> valid signature, so your own service rejects it."

**Чем доказать:** `sdk/gatewayverify/verify.go`, 30 строк для интеграции.
Длиннопрефиксность — не мелочь: склейка через разделитель однажды позволила
одной подписи аутентифицировать **двух разных пользователей**, это найдено
аудитом и починено.

### «Сколько миллисекунд вы добавляете?»

**Ответ:** observe-режим +1,1…1,6 мс, полная защита +1,8…2,7 мс на медиане.
Диапазон, а не число: два одинаковых прогона разошлись на 0,9 мс.

> "Under three milliseconds at the median with the whole chain enabled. I can
> show you the method and the raw runs — it's published with its caveats."

**Чем доказать:** `tests/load/overhead-results-2026-09-23.md`, и там же честно
написано, чем замер **не** является: это не замер пропускной способности и не
то, что видит удалённый клиент.

Если спросят про пропускную способность — цифры есть в
`tests/load/capacity-sweep-2026-07-31.md`, но **упирались в демо-бэкенд, а не
в нас**, и это там написано.

### «А если ваш шлюз упадёт? Вы же в разрыве моего трафика.»

**Ответ, который снимает возражение целиком:** начинайте не в разрыве.
Зеркальный режим — клиентский nginx шлёт **копию** запроса, ответ
отбрасывается, трафик клиента через нас не идёт вообще. Можно остановить AEGIS
посреди пилота, и у клиента ничего не изменится.

> "For a pilot you don't put us in the path at all. Your nginx mirrors a copy of
> the request; we never touch the response. Stop the gateway mid-pilot and your
> traffic doesn't notice."

Дальше, для inline: graceful shutdown с дренированием, hot-reload конфига без
перезапуска, `observe: true` — инспектирует и записывает, но ничего не
блокирует. Для отказа Redis есть `fail_closed` на контроль: опционально
запрещать вместо того, чтобы пропускать.

**Чем доказать:** `docs/mirror-mode.md`, `docs/pilot-mode.md`.

### «Чем вы лучше WAF, который у меня уже есть?»

**Ответ:** сигнатурный WAF знает «похоже на SQL-инъекцию». Он не знает, что
*этот конкретный потребитель обычно трогает три объекта, а сейчас перебрал
триста*. Это класс BOLA, он номер один в OWASP API Top 10, и сигнатурами не
ловится в принципе — каждый отдельный запрос выглядит легитимным.

> "A signature firewall sees one request at a time. BOLA is invisible that way:
> every single request is valid. What catches it is knowing who normally touches
> what — which needs a consumer graph, and most firewall-derived products don't
> have one."

**Чем доказать:** демо. `make demo` и живой сценарий перебора.

### «Где мои данные?»

**Ответ:** у вас. Один Go-бинарник в вашей инфраструктуре, без агентов, без
SaaS, ни байта трафика наружу. Salt, Noname, Imperva и Akamai — SaaS, им нужна
копия вашего трафика в их облаке.

> "Nothing leaves your network. One binary, your hardware, your database. That
> is the whole reason we exist — for a DORA-regulated bank the SaaS model isn't
> a preference problem, it's a legal one."

### «Чем докажете регулятору?»

**Ответ:** подписанный отчёт, который **проверяет сам аудитор**, на своей
машине, отдельным бинарником, не доверяя ни вам, ни нам. Плюс маппинг на NIS2
ст. 21, DORA ст. 8–10 и 17–19, ISO 27001.

И сразу, не дожидаясь вопроса: **ключ подписи держит тот, кого проверяют.**
Подпись доказывает «документ не изменён после создания», а не «собран из
полных данных». Это написано **внутри** самого подписанного документа.

> "The signature proves the document wasn't altered after it was produced. It
> does not prove it was assembled from complete data — the key is held by the
> party being audited. We say that inside the signed document rather than let a
> reader assume otherwise."

**Чем доказать:** `make demo` — восемь шагов до отказа верификатора на
испорченном отчёте.

**Почему это стоит говорить самому:** аудитор всё равно это спросит, и
разница между «они сами сказали» и «я это выяснил» — это разница между
партнёром и продавцом.

---

## 2. Вопросы, на которые ответ слабый — и что говорить

### «Кто этим уже пользуется?»

**Никто.** Пилотов нет, платящих клиентов нет.

> "Nobody yet. You'd be the first, and that's exactly why the pilot is mirror
> mode — zero risk to your traffic, and you can stop it any moment."

Не изобретайте «мы в закрытой бете с несколькими компаниями». Это проверяется
одним вопросом «с какими» и заканчивает разговор.

Что добавить: продукт сделан не за выходные. Гейт релиза — 52 пункта закрыто.
Тестового кода больше, чем продуктового.

### «Вас кто-нибудь проверял снаружи? Есть пентест?»

**Независимого пентеста нет.** Он не заказан — нужен подрядчик и деньги.

> "No external pentest yet — the scope document is written, it isn't
> commissioned. What we do have is an internal audit that found and fixed three
> real vulnerabilities, and the discipline that found them."

И дальше — то, что действительно отличает: **мутационное тестирование**. Код
намеренно ломается, чтобы проверить, что тесты это замечают. Этим способом
найдено **четырнадцать тестов, которые проходили на сломанном коде**. Это
редкая практика, и она проверяема.

**Чем доказать:** `docs/security/external-pentest-scope.md` — scope готов,
можно показать, что вы знаете, что именно надо проверять.

### «Сертификация? SOC 2, ISO?»

**Нет.** Это процесс на месяцы и аудитор, не код.

> "No. SOC 2 is a process, not a feature, and it needs a company with a track
> record — which is what we're building now. What I can give you today is the
> technical evidence that would go into one."

### «Какой у вас SLA?»

**Ответ есть, и он честный:** `docs/support.md`. Уровни важности, целевые
сроки, что покрыто и что нет. Там прямо написано: один инженер, целевые сроки
не контрактные, европейские рабочие дни.

> "It's written down, including the part where it says we're one engineer and
> these are intentions rather than contractual terms. If you need contractual
> response times backed by a company, say so — that's a reasonable requirement
> and we don't meet it yet."

Сказать это первым — сильнее, чем быть пойманным на этом.

### «Сколько вы выдерживаете? Сколько RPS?»

**Слабое место.** Цифры есть, но упирались в тестовый бэкенд, а не в нас, и
прогона на выделенном железе через реальную сеть нет.

> "The honest answer is that our published numbers hit the test backend's
> ceiling before ours, so they're a floor and not a limit. A proper capacity
> run on dedicated hardware is work we haven't done."

Не называйте цифру, которой нет.

### «HA? Что если упадёт Redis или PostgreSQL?»

**Половина есть.** Redis HA через Sentinel — в коде. Для PostgreSQL — только
руководство (`docs/runbooks/ha.md`), кода нет. Поведение при отказе обоих
проверено нагрузочными прогонами и записано.

> "Redis HA through Sentinel is in the code. PostgreSQL failover is documented
> as an operational runbook, not automated by us. What is tested is the
> behaviour during an outage — we ran it under load and published what happens."

### «Есть машинное обучение?»

Тут легко соврать, и не надо.

> "No trained model, deliberately. A model needs labelled traffic that doesn't
> exist before a deployment does, and it can't explain a finding. What we ship
> is per-consumer behavioural baselines across four named dimensions, and every
> finding says which dimension and by how much."

Это **сильная** позиция, если произнести её уверенно: «модель без данных —
это зеркало, а не детект». Слабой она становится, только если начать
оправдываться.

---

## 3. Вопросы про бизнес, которые задаст инвестор

### «Почему вы, а не Akamai?»

Не отвечайте «мы дешевле». Отвечайте местом исполнения:

> "Akamai will not run inside your datacentre. For a regulated bank that's not a
> price question, it's a compliance one. We're not competing on features with a
> company that has a thousand engineers — we're the option that exists where
> they structurally cannot go."

### «Что мешает Akamai сделать то же самое?»

Честно: технически — ничего. Мешает бизнес-модель. SaaS-компания, построенная
на своём облаке, не станет продавать бинарник, который убивает её же
операционную модель и маржу.

### «Сколько времени до первого клиента?»

Не называйте срок, которого не знаете. Назовите **условия**:

> "The product is ready for a mirror pilot today — the technical blocker is
> gone. What's left is a legal entity and the first conversations, which is what
> the Polish registration is for."

---

## 4. Перед каждой презентацией — чек-лист на 10 минут

1. `make stand` — стенд поднимается за ~6 секунд. Проверьте, что поднялся.
2. `make demo-auto` — прогоните демо целиком и досмотрите до конца. Если оно
   падает, вы узнаете об этом сейчас, а не при них. (`make demo` — то же самое,
   но с паузами: на публике лучше оно, вы управляете темпом.)
3. Откройте консоль и посмотрите на неё глазами человека, который видит её
   впервые.
4. Перечитайте раздел 2 этого файла — слабые места. Их надо знать наизусть,
   потому что именно их спросят.
5. Проверьте, что ноутбук показывает демо **без интернета**. Wi-Fi на площадке
   не работает никогда.

---

## 5. Три правила, если всё пойдёт не так

**Демо упало.** Не чините при зрителях. «This is the part where I say I'll
show you a recording — the live version needs a database I don't have on this
network.» Имейте записанное видео демо заранее.

**Вопрос, которого вы не поняли.** «Can you rephrase that?» — это нормальный
вопрос, а не слабость. Отвечать на неправильно понятый вопрос хуже.

**Вас поймали на неточности.** Признайте сразу и точно: «You're right, I
overstated that. The accurate version is …». Одна признанная неточность стоит
дёшево. Защищаемая неточность стоит доверия ко всему остальному.
