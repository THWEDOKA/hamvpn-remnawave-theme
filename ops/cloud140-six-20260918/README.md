# CLOUDru: подготовительная инвентаризация шести выходов

Снимок только безопасных полей панели и сетевые наблюдения:
**2026-09-17 22:12–22:15 UTC** (2026-09-18 по Europe/Minsk).
Это не развёртывание и не доказательство работоспособности VPN.

Вход: `CLOUDru #650`, `176.108.245.140`, SSH `gasan` с `sudo -n`.
Self-steal согласован для всех шести маршрутов. FQDN ниже согласованы главным
агентом; этот исполнитель не проверял и не менял DNS.

| Хост | Фактическая нода / IP | Текущий основной протокол | Авто-хост | Согласованный FQDN |
|---|---|---|---|---|
| 🇦🇹 Австрия | 🇦🇹 Австрия / 147.45.71.38 | Hysteria2, UDP 443 | ABP-52-AT-HIDDEN | in-at38.torcalc.ru |
| 🇵🇱 Польша | Польша / 31.77.59.141 | VLESS REALITY, TCP 443 | ABP-43-PL-HIDDEN | in-pl141.torcalc.ru |
| 🇨🇿 Чехия | Чехия / 45.151.180.85 | VLESS REALITY, TCP 443 | ABP-44-CZ-HIDDEN | in-cz85.torcalc.ru |
| 🇬🇧 Великобритания | GASAN GB (BS MOST Danya) / 51.194.240.216 | Ошибка привязки: хост 443, активный inbound 7443 | ABP-29-GB-HIDDEN, та же ошибка | in-gb216.torcalc.ru |
| 🇺🇸 США - 1 | GASAN US [util-nl-1] / 162.141.185.231 | Hysteria2, UDP 443 | ABP-37-US-HIDDEN | in-us1.torcalc.ru |
| 🇬🇧 Великобритания — Мощный | GASAN GB [util-be-1] / 51.194.240.225 | Hysteria2, UDP 4500 | Не найден | in-gb225.torcalc.ru |

Все шесть нод были connected, ни одна не disabled. Это статус связи панели с
нодой, а не клиентская проверка. Фактические egress IP ещё не измерены.

## Точные связи

### Австрия

- Node: `7f9b7a9d-fee8-4f64-ac6e-dceb59afe715`.
- Main host: `8a734066-a484-4b17-b1ac-c02f52f62c06`.
- Auto host: `17323e32-fb2c-4e4c-896d-07313101248a`.
- Profile: `e58ae413-cd68-4d6d-9000-da42b33173e1`, `AT38-HYSTERIA2`, один потребитель.
- Main/auto inbound: `cac11ead-ca8e-47f8-b07b-f79ab9429c3b`, `AT38_HYSTERIA2`,
  TLS `at38.torcalc.ru`, UDP 443, fingerprint firefox.
- Сохранить также legacy REALITY `a1d26d2a-1d09-4a62-afd3-fb2dcc871b64`,
  `AT38_LEGACY_REALITY`, TCP 443, target `google.com:443`.

### Польша и Чехия

- Общий profile: `d354e2ac-4b86-40a7-a0b3-ef9499d329b1`, `G-CONFIG`,
  **11 нод-потребителей**; не изменять общий профиль ради выбранных нод.
- Inbound: `41b6c310-32dd-4845-acc6-816ed48e2ff9`, `vless-reality-shared`,
  TCP 443, REALITY target `google.com:443`.
- PL node: `e7cb39c6-81b5-419c-bf3c-ca07a0237674`;
  main `64f97c2b-0c9d-4a09-8909-08f8c15e3219`, fingerprint firefox;
  auto `858a888d-a7fe-4459-9762-fb3e92bee10e`, fingerprint qq.
- CZ node: `efb5048a-7e25-427e-94bd-de469e7bca1e`;
  main `5de1d4d2-9bd7-42f3-993c-d218bc6bd98a`;
  auto `b8047ae6-2472-410c-9303-af78c3441682`; оба fingerprint qq.

### Великобритания

- Node: `a456b92a-8372-45fa-b007-117ef785abc5`.
- Main `75133919-61a5-47ba-929e-3a27c9a361cf` и auto
  `ff845a81-3183-4439-990a-07089a776418` сейчас указывают на **G-CONFIG**,
  TCP 443, SNI `global.hambot.ru`, fingerprint qq.
- Фактически активен выделенный profile `447f780a-3a46-4f7e-ba55-74e80f4f2dfb`,
  `polandbs`, один потребитель; inbound `5543c7d0-4b2f-4097-a4b6-6fd43066ca82`,
  `VLESS_TCP_REALITY_GBD`, TCP **7443**, serverNames только `google.com`.
- Эта же нода обслуживает отдельный, не выбранный для переноса хост
  `🇬🇧 Обход все операторы`, `92f1e0c1-90d3-4ed1-b532-88f3c5f0fdfc`,
  endpoint `188.225.62.121:9443`. Его рабочую схему и действующий inbound
  необходимо сохранить. `9443` здесь — порт другого входа, не ноды `.216`.
- Права активного `polandbs` inbound имеют WHITE/site, но права выбранных
  main/auto через G-CONFIG имеют все четыре клиентских сквада. Для нового
  frontend брать права выбранных клиентских хостов, не только активной ноды.

### США - 1

- Node: `f6e49f98-3d96-46aa-b79e-0b636f625a61`.
- Main: `762610b7-944a-4ed1-ae25-55f0d906cb15`.
- Auto: `2935d939-15da-4c96-9f20-2060497fb4fa`.
- Profile `ac712c79-d525-4d1d-a9ec-02cb48a6219b`, `HYSTERIA-PL-BRIDGE-V2`,
  один потребитель, **только один активный inbound**:
  `b957303a-a0d1-4c03-bb9d-6d5b27354ab8`, `PL2_HYSTERIA`, UDP 443,
  TLS `nlgas.hambot.ru`, fingerprint firefox.
- На момент снимка в панели отображались 66 пользователей online. Сохранять
  действующую Hysteria2-схему, не считать её TCP/VLESS по названию старого профиля.

### Великобритания — Мощный

- Node: `a101da45-16eb-4eb1-807a-a49ac956add6`.
- Main: `439b1267-ef6e-4ca0-8509-567879863d1d`.
- Profile `06906074-699a-417d-9635-ce6e53ac74c7`, `HYSTERIA-LT-BRIDGE-V2`,
  один потребитель.
- Main inbound `66eeef65-7fce-4aea-a0ef-882985275280`, `LT2_HYSTERIA`,
  UDP 4500, TLS `ltgas.hambot.ru`, fingerprint firefox.
- Дополнительно активны REALITY TCP inbounds: 10443 `LT2_MWS1`,
  8443 `LT2_MWS6`, 7443 `LT2_MWS2`, 9443 `LT2_MWS3`, 2053 `LT2_WHITE5`,
  2096 `LT2_WHITE4`. Target `api-maps.yandex.ru:443`.
- Ни привязанного к ноде скрытого хоста, ни другого хоста на этот адрес или
  active inbound не найдено. Не создавать автоматически без решения главного
  исполнителя об области публикации.
- На момент снимка 51 пользователь online. Сохранять все действующие inbounds.

## Права доступа

Для **выбранного основного хоста каждого из шести выходов**:

- WHITE: `c131dde6-f5f7-4a7a-880a-868316104db1`.
- BASE: `fbbac611-42b0-4d4a-8be4-8f2faf555f5d`.
- OLD: `50c06fa3-ec93-4ee4-8ed3-d8b6efb0eb9f`.
- site: `37517a10-4ed2-47e1-98b4-eed77c24b904`.

`HAM-RU140-BACKEND`, `a9ad8966-91da-457c-b83b-d2c14a6c5dcb`, также имеет
некоторые исходные inbounds (AT и G-CONFIG), но является служебным сквадом:
**не выдавать ему новый клиентский frontend**. Union прав выполнять по свежему
состоянию при реализации, не по этому текстовому снимку.

## Сеть с CLOUDru: только подготовительные наблюдения

На всех шести `IP:22` TCP connect и чтение SSH banner успешны (~90–105 мс).
Авторизации, KEX/проверки ключа, копирования ключей и настройки SSH не было.
Это только направление entry → exit, не проверка обратного туннеля.

| Endpoint / SNI | Результат |
|---|---|
| AT `147.45.71.38:443`, google.com | TCP connect успешен, TLS timeout 5 с |
| PL `31.77.59.141:443`, google.com | TCP connect timeout 5 с |
| CZ `45.151.180.85:443`, google.com | TCP connect, затем TLS connection reset |
| GB `51.194.240.216:7443`, google.com | TCP connect timeout 5 с |
| US1 `162.141.185.231:443`, nlgas.hambot.ru | TCP connection refused; **это не проверка UDP/Hysteria2** |
| GBpower `51.194.240.225:10443`, api-maps.yandex.ru | Доверенный TLS 1.3 + h2, ~180 мс |
| GBpower TCP 8443/7443/9443/2053/2096 | TCP connect, затем TLS timeout 5 с |

TLS проверяет цепочку и имя; `skip-verify` не использовался. Ни успешный cover
TLS, ни его ошибка не заменяют аутентифицированный VPN-тест. Нужен отдельный
временный технический аккаунт и реальные 204 + egress с entry. Причина
таймаутов/сбросов этими наблюдениями не установлена, ТСПУ не доказан.

## Доступы и границы выполненного

Для **всех шести нынешних IP** `ssh-keygen -F <IP>` в локальном known_hosts
не нашёл записей. Поэтому новые ключи не принимались и авторизация не
пробовалась. Нужны подтверждённые SSH host keys (либо явно согласованный TOFU)
и актуальные логины/разрешённые ключи или закрытые файлы с доступами. Старые
пароли других IP не перебирались. Приватные ключи не читались/не выводились.

`inventory.py` выполняет только GET панели и bounded TCP/TLS-пробы по
разрешённым IP; печатает whitelist без rawInbound, clients и конфигурационных
секретов. На панель/entry передавался в память для read-only исполнения с `-B`;
файлы релиза на серверах не создавались. Никаких DNS/API/firewall/service writes,
новых аккаунтов, перезапусков или commits/push не сделано.

Проверены fixtures: шесть целей, GET-only, отсутствие вложенных секретов,
обнаружение несовпадения binding, запрет посторонних IP/невалидных портов,
разделение UDP endpoint и TCP website observation. `git diff --check` чистый.
Публикация этих двух файлов — только главным исполнителем после ревью.
