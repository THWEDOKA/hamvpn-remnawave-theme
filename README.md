# HAMVPN Remnawave Theme

Тонкая визуальная надстройка для текущего production-образа Remnawave. Она не изменяет backend, API, миграции или базу данных.

## Что меняется

- глубокий фиолетовый фон панели;
- фирменный маскот HAMVPN на прозрачном фоне;
- полупрозрачные верхняя панель и навигация;
- название вкладки и цвет системной темы;
- постоянная ссылка на исходный код темы для соблюдения AGPL-3.0.

## Сборка

```bash
docker build --pull=false \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  -t hamvpn/remnawave:2-theme .
```

Базовый образ закреплён по digest, поэтому сборка воспроизводима и не получает обновления Remnawave неожиданно.

## Проверка

```bash
docker run --rm --entrypoint sh hamvpn/remnawave:2-theme -lc \
  "test -s /opt/app/frontend/hamvpn/hamvpn-mascot.png && \
   grep -q /hamvpn/hamvpn-theme.css /opt/app/frontend/index.html && \
   grep -q hamvpn-source-link /opt/app/frontend/index.html"
```

Production запускается с дополнительным Compose-файлом `deploy/docker-compose.theme.yml`. Исходный Compose Remnawave при этом остаётся неизменным.

## Обновление Remnawave

Новый официальный digest сначала обновляется отдельным коммитом. После сборки проверяются загрузка панели, авторизация, API и адаптивность. Только затем меняется production-образ.

## Откат

Вернуть исходный `image: remnawave/backend:2` в production Compose и пересоздать только сервис Remnawave. База данных и volumes при этом не изменяются.

## Лицензия

Тема распространяется по GNU Affero General Public License v3.0. Базовый Remnawave также распространяется по AGPL-3.0.
