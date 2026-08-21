# HAMVPN Remnawave Theme & Infrastructure

Тонкая визуальная надстройка и изолированный операторский модуль для текущего production-образа Remnawave. Они не обновляют backend Remnawave, не запускают его миграции и не меняют схему его базы данных.

## Что меняется

- глубокий фиолетовый фон панели;
- фирменный маскот HAMVPN на прозрачном фоне;
- полупрозрачные верхняя панель и навигация;
- название вкладки и цвет системной темы;
- нативная вкладка `Инфраструктура` внутри React-интерфейса Remnawave;
- постоянная ссылка на исходный код темы для соблюдения AGPL-3.0.

## Инфраструктура

Вкладка доступна по `/dashboard/management/infrastructure` внутри обычной оболочки панели. Она собрана из официального исходника Remnawave `2.8.1` (commit `9d671520067f73b2beb96c282f2ce2ff7b7a9a00`) и использует штатные роутер, навигацию и компоненты Mantine. Служебный API запускается отдельным изолированным контейнером на `/ham-infrastructure/api/`. Токен приходит из существующей авторизованной сессии Remnawave; модуль не сохраняет токены, SSH-пароли и приватные ключи.

Возможности:

- инвентаризация нод, хостов, профилей и внутренних сквадов;
- безопасный план смены IP со связанными хостами и точными значениями в профилях;
- снимок перед изменением, проверка результата и автоматический откат;
- установка новой Remnawave Node по SSH без перезаписи существующей `/opt/remnanode`;
- создание ноды и хоста с явным выбором профиля, inbound и доступных сквадов;
- отдельный локальный журнал операций без учётных данных.

SSH host key фиксируется на этапе предварительной проверки и повторно проверяется перед установкой. На новой ноде создаётся отдельное правило файрвола: Node Port принимает соединения только от публичного IP панели.

## Сборка

```bash
docker build --pull=false \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  -t hamvpn/remnawave:2-theme .
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
docker run --rm --entrypoint sh hamvpn/remnawave:2-theme -lc \
  "test -s /opt/app/frontend/hamvpn/hamvpn-mascot.png && \
   grep -q /dashboard/management/infrastructure /opt/app/frontend/assets/index-*.js && \
   grep -q /hamvpn/hamvpn-theme.css /opt/app/frontend/index.html && \
   grep -q hamvpn-source-link /opt/app/frontend/index.html"
```

Production запускается с дополнительным Compose-файлом `deploy/docker-compose.theme.yml`. Исходный Compose Remnawave при этом остаётся неизменным.

Перед запуском в `/opt/remnawave/.env` задаются:

```dotenv
PANEL_PUBLIC_IP=203.0.113.10
INFRA_NODE_IMAGE=remnawave/node:latest
```

В HTTPS `server` домена панели перед общим `location /` добавляется содержимое `deploy/nginx-ham-infrastructure.conf`. Каталог данных создаётся отдельно:

```bash
install -d -o 10001 -g 10001 -m 700 /opt/hamvpn-infrastructure
```

## Обновление Remnawave

Базовый образ панели закреплён по digest версии 2.8.1. Новый официальный digest может быть внесён только отдельным осознанным коммитом после проверки загрузки панели, авторизации, API и адаптивности. Обычная сборка темы или инфраструктурного модуля Remnawave не обновляет.

## Откат

Для отката вернуть предыдущий `hamvpn/remnawave:2-theme`. Если служебный API больше не нужен, отдельно удалить location `/ham-infrastructure/` из Nginx и сервис `hamvpn-infrastructure`. База данных Remnawave и её volumes при этом не изменяются.

## Лицензия

Тема распространяется по GNU Affero General Public License v3.0. Базовый Remnawave также распространяется по AGPL-3.0.
