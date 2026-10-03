# yandex2mqtt — версия на Go

Самостоятельный мост между **Яндекс Умным домом / Алисой** и MQTT. Перенос проекта
[alvlapo/yandex2mqtt](https://gitverse.ru/alvlapo/yandex2mqtt), ветка `master`,
коммит `d26960b8fcc34ba0f4cc6f62114e957b3cc0f0f3`.

Рабочий сервер написан на Go; Node.js нужен только для необязательного однократного
экспорта старого JavaScript-конфига. PostgreSQL, Redis и внешняя база не требуются.
Данные авторизации сохраняются в локальном JSON-файле. MQTT-клиент — Eclipse Paho.
Лицензия MIT, исходное авторство сохранено в LICENSE.

## Что входит

- HTTP API Яндекса: проверка доступности, список устройств, состояния, команды, отвязка.
- OAuth: вход, согласие пользователя, одноразовый код, access/refresh-токены, PKCE S256.
- MQTT 3.1.1 по TCP/TLS и WebSocket, QoS 0/1, автоматическое переподключение и подписка.
- Свет, розетки, датчики; `on_off`, `toggle`, `range`, `mode`, `color_setting`;
  свойства `float`, `event`. RGB, HSV, температура цвета и сцены.
- Преобразования `valueMapping`, относительные команды диапазона, проверка значений.
- Права `allowedUsers` во всех операциях; уведомления только для разрешённых устройств.
- JSON-конфигурация, отдельные JSON-файлы устройств, миграция старого `config.js`.
- Готовые программы Linux amd64/arm64, Windows amd64, macOS arm64 в `bin/`.
- Dockerfile, Compose, systemd и пример конфигурации Nginx.

Подробный анализ оригинала и изменения: **[FIXES.md](FIXES.md)**.
Фактические результаты проверки и ограничения: **[TESTING.md](TESTING.md)**.

## Быстрый запуск готовой программы

Все команды выполняются из корня распакованного проекта.
Нужен действующий MQTT-брокер и ваши собственные настройки устройств.

Linux amd64:

```bash
cp config.example.json config.json
chmod 600 config.json
./bin/linux-amd64/yandex2mqtt -hash-password
```

Windows PowerShell:

```powershell
Copy-Item config.example.json config.json
.\bin\windows-amd64\yandex2mqtt.exe -hash-password
```

Введите пароль: символы в терминале не отображаются. Вставьте выданный bcrypt-хеш
в `users[0].passwordHash`. Замените `clientSecret` длинной случайной строкой,
укажите адрес/учётные данные MQTT и реальные топики устройств.
Конфиг с оставленным `REPLACE_WITH_BCRYPT_HASH` намеренно не запускается.
Не включайте `config.json` и файл токенов в публичный репозиторий.

Затем:

```bash
./bin/linux-amd64/yandex2mqtt -config config.json -check
./bin/linux-amd64/yandex2mqtt -config config.json
```

В Windows аналогично:

```powershell
.\bin\windows-amd64\yandex2mqtt.exe -config config.json -check
.\bin\windows-amd64\yandex2mqtt.exe -config config.json
```

`-check` проверяет структуру и логические связи конфига, но не подключается к MQTT
и не проверяет учётные данные внешних сервисов. `/healthz` показывает, что процесс
работает, `/readyz` возвращает 503 до подключения и успешной MQTT-подписки.

В примере `cookieSecure: true`: полноценный вход работает по HTTPS.
Для проверки входа только на локальном HTTP временно установите `false`.
При публичном размещении снова используйте `true`.

## Подключение к Яндексу

Разместите сервер по публичному HTTPS-адресу с доверенным сертификатом.
Можно поставить Nginx перед `127.0.0.1:8080` — пример в `deploy/`.
В настройках навыка умного дома укажите:

| Поле | Значение для домена `smart.example.ru` |
|---|---|
| Endpoint URL | `https://smart.example.ru/provider` |
| URL авторизации | `https://smart.example.ru/dialog/authorize` |
| URL получения токена | `https://smart.example.ru/oauth/token` |
| URL обновления токена | `https://smart.example.ru/oauth/token` |
| Client ID | значение `clients[].clientId` |
| Client secret | значение `clients[].clientSecret` |

`redirectUris` должен содержать **точный** адрес возврата Яндекса:
`https://social.yandex.net/broker/redirect`.
Откройте привязку аккаунта в приложении «Дом с Алисой», войдите своим локальным
логином/паролем и подтвердите доступ. Проверяйте определения устройств на вкладке
«Тестирование» консоли Яндекс Диалогов: допустимые сочетания параметров и единиц
измерения также зависят от правил платформы.

Для собственного TLS вместо Nginx добавьте в конфиг:

```json
"http": {"listen": "0.0.0.0:4433", "cookieSecure": true},
"https": {
  "privateKey": "/etc/letsencrypt/live/smart.example.ru/privkey.pem",
  "certificate": "/etc/letsencrypt/live/smart.example.ru/fullchain.pem"
}
```

Используйте один способ публикации HTTPS; при обратном прокси TLS-файлы самому
Go-процессу не нужны. Путь к сертификатам должен быть доступен пользователю службы.

## Настройки устройств и MQTT

В `config.example.json` перенесены пять примеров оригинала: два светильника,
температура/влажность, розетка с мощностью, датчик движения.
`examples/thermostat.json` и `examples/color-lamp.json` — дополнительные примеры.
Чтобы подключить отдельные файлы, укажите `"devicesDir": "examples"`.
Будут прочитаны все `.json` в каталоге и вложенных каталогах в порядке имён;
каждый файл может содержать объект устройства или массив. ID не должны повторяться.
`devicesDir` дополняет, а не заменяет основной массив `devices`.
Все относительные пути разрешаются от каталога `config.json`.

| Поле | Назначение |
|---|---|
| `id` | стабильный уникальный ID устройства |
| `allowedUsers` | ID разрешённых пользователей; пустой массив запрещает всем |
| `mqtt[].instance` | функция, например `on`, `temperature`, `motion` |
| `mqtt[].type` | необязательное уточнение полного типа при одинаковом instance |
| `mqtt[].set` | топик команды; у датчика отсутствует |
| `mqtt[].state` | топик фактического состояния |
| `mqtt[].confirmTimeoutMs` | 0 — без ожидания эха; 1..2000 — ждать matching state |
| `retrievable` | функция выдаётся при запросе состояния |
| `reportable` | функция включается в уведомления Яндекса |
| `valueMapping[].type` | короткий (`on_off`) или полный тип функции |
| `valueMapping[].instance` | необязательный фильтр для конкретной функции |
| `valueMapping[].mapping` | два массива: `[значения Яндекса, значения MQTT]` |

Например `[[false,true],[0,1]]`: выключить → MQTT `0`, включить → `1`;
при входящем MQTT `1` Яндексу возвращается булево `true`.
Входящие строковые числовые значения корректно сопоставляются с числами конфига.
Булевы значения без mapping: `true/false`, `on/off`, `1/0`, без учёта регистра.
Числа разбираются полностью: `22junk`, `NaN`, `Inf` отклоняются.
Топики MQTT всегда чувствительны к регистру; wildcard-топики не поддерживаются.
Один state-топик может обновлять несколько устройств.

**Что означает DONE.** При `confirmTimeoutMs > 0` мост ждёт новое состояние,
равное запрошенному. При нуле подтверждается публикация в брокер: для QoS 1 —
PUBACK, для QoS 0 — завершение отправки клиентом. Подтверждение брокера само по себе
не подтверждает физическое переключение устройства. Пример конфига включает ожидание
для света и розетки; перенесённые старые конфиги сохраняют режим без ожидания.
Состояние никогда не заменяется значением команды; его обновляет MQTT state.
При тайм-ауте уже отправленная команда всё же может выполниться позднее.
Общий бюджет одного HTTP-запроса команд — 3,5 с; остальные команды большого
пакета после исчерпания бюджета получат ошибку без новой публикации.

После подключения/переподключения старые входящие состояния сбрасываются.
До свежего state/retained сообщения возвращается `DEVICE_UNREACHABLE`.
Рекомендуется публиковать состояния с `retain`, чтобы восстановить их сразу.
Отключение конкретного устройства при работающем брокере автоматически не определяется:
в этой версии нет привязки к LWT/availability и TTL измерений.

Для MQTT TLS используйте `mqtt.url: "ssl://broker.example.ru:8883"`.
Необязательные `caFile`, `certFile`, `keyFile` позволяют задать CA и клиентский
сертификат. Проверка серверного сертификата включена; TLS ниже 1.2 запрещён.
Для нескольких экземпляров задайте разные MQTT `clientId` и отдельные файлы токенов.
Один файл токенов одновременно может использовать только один процесс.

## Уведомления Яндекса

Добавьте в массив `notification`:

```json
{
  "skill_id": "ВАШ_SKILL_ID",
  "oauth_token": "OAUTH_ТОКЕН_ВЛАДЕЛЬЦА_НАВЫКА",
  "user_id": "1",
  "client_id": "yandex2mqtt"
}
```

`user_id` — ID локального пользователя, который выдаётся в discovery, **не ID
аккаунта Яндекса**. Токен уведомлений — отдельный токен владельца навыка для API
Диалогов; это не access-токен, выданный самим мостом.
Функции должны иметь `reportable: true`. Для event-функций одинаковые повторные
события тоже отправляются. Отправка разрешена после привязки аккаунта; после unlink
очередь для этой связи не отправляется. `client_id` обязателен при нескольких
OAuth-клиентах; рекомендуется указывать всегда.

Очередь — 256 сообщений, один worker сохраняет порядок отправки, до трёх попыток
на сетевых ошибках/HTTP 429/5xx. Постоянные HTTP 4xx повторно не отправляются.
Проверяются HTTP-статус и JSON `status: "ok"`, логируется `request_id` ответа.
Секреты и тела запросов в журнал не пишутся. Очередь не сохраняется на диск:
при переполнении или перезапуске уведомление может быть потеряно, состояние доступно
через query. Для больших потоков телеметрии нужна отдельная доработка очереди.

## Перенос существующей конфигурации

Экспортируйте **только собственный доверенный** `config.js`: Node.js выполняет код
файла и его `require`. Не запускайте экспорт для неизвестных чужих файлов.

```bash
node tools/export-config.cjs /opt/old-yandex2mqtt/config.js > legacy.json
./bin/linux-amd64/yandex2mqtt -migrate legacy.json -output config.json
```

Выходной файл не должен уже существовать. Пользовательские пароли заменяются
bcrypt-хешами; добавляются redirectUris Яндекса и значения по умолчанию.
Сохраняются ID, allowedUsers, топики, определения и mappings.
После переноса проверьте `http.listen` и HTTPS: оригинальный `config.orig.js`
содержит сертификаты-заглушки. Для Nginx удалите блок `https` и используйте HTTP
на loopback. Исправьте MQTT-учётные данные и включите `cookieSecure` для HTTPS.
При нескольких клиентах явно задайте `notification[].client_id`.

Если устройства хранятся фабриками в `devices/rooms` и старый room index сломан,
сначала сделайте копию конфига без `require('./devices')`, затем:

```bash
node tools/export-config.cjs /path/to/config-without-device-import.js /path/to/devices/rooms > legacy.json
```

В таком режиме `index.js` комнат не исполняется, загружаются только `.js`-фабрики
устройств. Имя комнаты по умолчанию — имя её каталога: проверьте его в JSON.
В PowerShell для UTF-8 экспорта используйте:

```powershell
node tools/export-config.cjs C:\old\config.js | Set-Content -Encoding utf8NoBOM legacy.json
.\bin\windows-amd64\yandex2mqtt.exe -migrate legacy.json -output config.json
```

`utf8NoBOM` есть в PowerShell 7; в старом PowerShell перенаправьте вывод через
`cmd /c "node tools\export-config.cjs C:\old\config.js > legacy.json"`.
`legacy.json` содержит исходные пароли: после успешного переноса удалите его.
**Старые loki.json и токены не импортируются** — привяжите аккаунт заново.
OAuth implicit/password/client_credentials реализованы для совместимости,
но выключены по умолчанию. Основная интеграция использует code + refresh.
Для ручной диагностики при необходимости включите `allowPasswordGrant` в `oauth`.
Клиентский токен не даёт доступа к пользовательским устройствам.

## Сборка и проверка из исходников

Установите Go **1.26 или новее** с актуальными исправлениями безопасности.
В архив включён `vendor/`, поэтому для сборки не требуется скачивание модулей.
Для воспроизведения проверки с `-race` нужны CGO и C-компилятор.

```bash
go test -mod=vendor -race ./...
go vet -mod=vendor ./...
CGO_ENABLED=0 go build -buildvcs=false -mod=vendor -trimpath -ldflags="-s -w" -o yandex2mqtt ./cmd/yandex2mqtt
```

Для Windows/arm64/Linux-amd64 задайте `GOOS` и `GOARCH`; готовые варианты есть в bin.
`SHA256SUMS` позволяет проверить файлы программы из комплекта.

## Docker

В конфиге задайте `http.listen: "0.0.0.0:8080"` и MQTT URL, доступный из контейнера.
`127.0.0.1` внутри контейнера означает сам контейнер, а не хост с брокером.
Создайте каталог данных и укажите UID/GID пользователя, которому принадлежат
`config.json` и `data/`:

```bash
mkdir -p data
chmod 700 data
export Y2M_UID=$(id -u)
export Y2M_GID=$(id -g)
docker compose up -d --build
docker compose logs -f
```

Образ работает без shell и от непривилегированного пользователя. Compose по умолчанию
использует UID/GID 1000; под root задайте отдельного непривилегированного владельца
и соответствующие UID/GID. Снаружи доступен только `127.0.0.1:8080`; HTTPS даёт прокси.
Dockerfile проверен структурно, Docker в среде разработки был недоступен.

## systemd / Linux

Скопируйте подходящую программу из bin в `/opt/yandex2mqtt/yandex2mqtt`:

```bash
sudo useradd --system --home /opt/yandex2mqtt --shell /usr/sbin/nologin yandex2mqtt
sudo install -d -o root -g yandex2mqtt -m 750 /opt/yandex2mqtt
sudo install -m 755 bin/linux-amd64/yandex2mqtt /opt/yandex2mqtt/yandex2mqtt
sudo install -o root -g yandex2mqtt -m 640 config.json /opt/yandex2mqtt/config.json
sudo install -d -o yandex2mqtt -g yandex2mqtt -m 700 /opt/yandex2mqtt/data
sudo cp deploy/yandex2mqtt.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now yandex2mqtt
sudo journalctl -u yandex2mqtt -f
```

Сервер пишет структурированные JSON-журналы в stdout. Для API Яндекса записывается
`X-Request-Id`. Заголовки Authorization, пароли и OAuth query-параметры не логируются.
Вход и получение токенов ограничены 30 запросами в минуту с адреса соединения.
За прокси это общий лимит адреса прокси; для большого числа пользователей настройте
отдельный лимит в прокси и измените `limited()` под вашу инфраструктуру.
Изменения конфига вступают в силу после перезапуска; горячего редактирования нет.
Файловое хранилище рассчитано на один процесс, а не на кластер серверов.

## Документация протоколов

- [Авторизация Яндекса](https://yandex.ru/dev/dialogs/smart-home/doc/en/auth/how-it-works)
- [Список устройств](https://yandex.ru/dev/dialogs/smart-home/doc/ru/reference/get-devices)
- [Состояния](https://yandex.ru/dev/dialogs/smart-home/doc/en/reference/post-devices-query)
- [Команды](https://yandex.ru/dev/dialogs/smart-home/doc/en/reference/post-action)
- [Коды ошибок](https://yandex.ru/dev/dialogs/smart-home/doc/en/concepts/response-codes)
- [Уведомления](https://yandex.ru/dev/dialogs/smart-home/doc/en/reference-alerts/post-skill_id-callback-state)
- [Eclipse Paho Go](https://pkg.go.dev/github.com/eclipse/paho.mqtt.golang)

Реальная привязка к вашему навыку Яндекса и вашим устройствам требует проверки
после заполнения конфига. Этот комплект прошёл локальные функциональные и MQTT-тесты,
но не является результатом испытаний на вашем оборудовании.
