# HAMVPN Remnawave Infrastructure

Нативная вкладка управления инфраструктурой для текущего production-образа Remnawave. Сборка сохраняет штатный дизайн панели, не обновляет backend Remnawave, не запускает его миграции и не меняет схему его базы данных.

## Что меняется

- нативная вкладка `Инфраструктура` внутри React-интерфейса Remnawave;
- штатное визуальное оформление Remnawave без пользовательского CSS и фоновых изображений.

## Инфраструктура

Вкладка доступна по `/dashboard/management/infrastructure` внутри обычной оболочки панели. Она собрана из официального исходника Remnawave `2.8.1` (commit `9d671520067f73b2beb96c282f2ce2ff7b7a9a00`) и использует штатные роутер, навигацию и компоненты Mantine. Служебный API запускается отдельным изолированным контейнером на `/ham-infrastructure/api/`. Токен приходит из существующей авторизованной сессии Remnawave; модуль не сохраняет токены, SSH-пароли и приватные ключи.

Возможности:

- инвентаризация нод, хостов, профилей и внутренних сквадов;
- безопасный план смены IP со связанными хостами и точными значениями в профилях;
- автоматическое обновление A-записей Hysteria в Cloudflare при смене IPv4 ноды;
- снимок перед изменением, проверка результата и автоматический откат;
- установка новой Remnawave Node по SSH без перезаписи существующей `/opt/remnanode`;
- создание ноды и хоста с явным выбором профиля, inbound и доступных сквадов;
- отдельный локальный журнал операций без учётных данных.

SSH host key фиксируется на этапе предварительной проверки и повторно проверяется перед установкой. На новой ноде создаётся отдельное правило файрвола: Node Port принимает соединения только от публичного IP панели.

## Сборка

```bash
docker build --pull=false \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  -t hamvpn/remnawave:2-default-infra .
```

Операторский контейнер собирается отдельно:

```bash
docker build --pull=false \
  -t hamvpn/remnawave-infrastructure:1 \
  orchestrator
```

Базовый backend-образ, frontend commit и Node.js build-образ закреплены по digest/commit, поэтому сборка не получает обновление Remnawave неожиданно.

## Проверка

```bash
docker run --rm --entrypoint sh hamvpn/remnawave:2-default-infra -lc \
  "grep -q /dashboard/management/infrastructure /opt/app/frontend/assets/index-*.js && \
   ! grep -q /hamvpn/hamvpn-theme.css /opt/app/frontend/index.html"
```

Production запускается с дополнительным Compose-файлом `deploy/docker-compose.theme.yml`. Исходный Compose Remnawave при этом остаётся неизменным.

Перед запуском в `/opt/remnawave/.env` задаются:

```dotenv
PANEL_PUBLIC_IP=203.0.113.10
INFRA_NODE_IMAGE=remnawave/node:latest
CLOUDFLARE_TOKEN=replace-with-scoped-token
CLOUDFLARE_ZONE_IDS={"hambot.ru":"replace-with-zone-id"}
CLOUDFLARE_DNS_TTL=60
```

Cloudflare можно подключить прямо во вкладке `Смена IP`. Токен проверяется сервером и сохраняется в `/opt/hamvpn-infrastructure/cloudflare.json` с правами `0600`; значение не возвращается в интерфейс, не попадает в журнал операций и не хранится в GitHub. Переменные production `.env` остаются резервным способом настройки. Рекомендуемые права токена: `Zone / DNS / Edit` и `Zone / Zone / Read` только для нужной зоны. При заданном `CLOUDFLARE_ZONE_IDS` право чтения зон после первоначальной привязки не требуется.

Для связанных доменных Hysteria-хостов смена IP блокируется до мутаций, если Cloudflare не настроен, найдена не одна точная A-запись или запись уже указывает не на текущий IP ноды. После обновления запись принудительно переводится в `DNS only`, получает TTL не ниже 60 секунд и повторно читается через API. Оранжевое проксирование Cloudflare не используется: обычный прокси Cloudflare не пропускает Hysteria/UDP. При ошибке последующих проверок обновлённая DNS-запись включается в автоматический откат.

В HTTPS `server` домена панели перед общим `location /` добавляется содержимое `deploy/nginx-ham-infrastructure.conf`. Каталог данных создаётся отдельно:

```bash
install -d -o 10001 -g 10001 -m 700 /opt/hamvpn-infrastructure
```

## Обновление Remnawave

Базовый образ панели закреплён по digest версии 2.8.1. Новый официальный digest может быть внесён только отдельным осознанным коммитом после проверки загрузки панели, авторизации, API и адаптивности. Обычная сборка темы или инфраструктурного модуля Remnawave не обновляет.

## Откат

Для отката вернуть предыдущий `hamvpn/remnawave:2-theme`. Если служебный API больше не нужен, отдельно удалить location `/ham-infrastructure/` из Nginx и сервис `hamvpn-infrastructure`. База данных Remnawave и её volumes при этом не изменяются.

## Лицензия

Модуль распространяется по GNU Affero General Public License v3.0. Базовый Remnawave также распространяется по AGPL-3.0.
