# Outreach

Three templates. Each assumes the reader owes you nothing and stops reading at
the second line unless something in it is about them.

Rules that apply to all three: no "I hope this finds you well", no "revolutionary",
no attachments on first contact, one question at the end, under 150 words.

---

## 1. Someone you know

The most valuable email here. Send it first, today, before the list exists.

> Subject: можно попросить твой API на три недели?
>
> Привет, [имя].
>
> Я сделал штуку, которая строит карту API по живому трафику: какие эндпоинты
> реально дёргают, кто в них ходит, что не задокументировано.
>
> Мне нужен первый реальный API, чтобы понять, работает ли она вне моих тестов.
> Твой трафик я не трогаю — ставится зеркалом в nginx, копия запроса идёт ко
> мне, ответ выбрасывается. Можешь выключить меня в любой момент, у тебя ничего
> не изменится.
>
> Бесплатно. Взамен прошу честный отзыв — включая «это бесполезно», если так.
>
> Дашь попробовать?

The ask is *"дай посмотреть"*, not *"купи"*. Anything more from a friend costs
the friendship a little and buys nothing.

---

## 2. Cold, to a CTO in a regulated company

> Subject: карта вашего API — без единого байта через нас
>
> [Имя], делаю оценку API-периметра для компаний под DORA/NIS2.
>
> За три недели вы получаете: все эндпоинты, которые реально вызывают, кто в
> них ходит, и какие из них не описаны в вашей спецификации. Отчёт подписан —
> проверяется отдельным бинарником, который остаётся у вас.
>
> Ваш трафик через нас не идёт. Ваш nginx отправляет **копию** запроса, ответ
> отбрасывается. В середине пилота можете нас выключить и посмотреть на свои
> графики — ничего не изменится. Это и есть проверка.
>
> Первым трём компаниям бесплатно, взамен — письменный отзыв.
>
> Показать трёхминутное демо?

Two things do the work: *"ваш трафик через нас не идёт"* in the first screen,
and an invitation to switch you off. Everything else is replaceable.

---

## 3. To a community (OWASP chapter, CTO Slack, meetup)

Not a pitch. A question that happens to reveal what you built.

> Собираю обратную связь: делаю инструмент, который строит карту API по
> зеркалированному трафику — эндпоинты, потребители, недокументированные ручки.
> Без inline, ваш трафик не трогается.
>
> Вопрос к тем, кто под NIS2/DORA: что у вас реально спрашивает аудитор про
> API? Инвентаризацию? Кто имеет доступ? Или что-то, чего я не предусмотрел?
>
> Если кому-то интересно посмотреть на своём трафике — напишите, поставлю
> бесплатно.

Asking what the auditor actually demands is the cheapest market research
available, and the answers will change the product more than another month of
building.

---

## Replying to "what about PII / can you find vulnerabilities?"

Do not stretch. The honest answer converts better at this stage:

> В зеркальном режиме — нет. Зеркало отдаёт только запрос, ответа я не вижу, а
> чтобы сказать «этот эндпоинт отдаёт карты анонимам», нужно тело ответа.
>
> Это второй этап: если карта окажется полезной и вы решите поставить меня в
> путь запроса — в режиме наблюдения, ничего не блокирует, — тогда появятся
> находки по данным и по доступу к чужим объектам.

Two reasons this works. It is true. And a vendor who says "no" to one question
is believed on the rest.

---

## Follow-up

One, after four working days, on the same thread:

> [Имя], поднимаю наверх — вдруг утонуло. Если сейчас не ко времени, скажите,
> и я не буду писать дальше.

Then stop. A second follow-up buys nothing and costs the option of writing again
in six months.
