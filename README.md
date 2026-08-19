<div align="center">

<img src="docs/banner-github.png" alt="MultiGate — прослойка подписок для панели Remnawave" width="100%">

<p>
  <a href="https://github.com/qwe8nxtroud/multigate/actions/workflows/ci.yml"><img src="https://github.com/qwe8nxtroud/multigate/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/qwe8nxtroud/multigate/releases"><img src="https://img.shields.io/github/v/release/qwe8nxtroud/multigate?label=релиз&color=fcb874" alt="Релиз"></a>
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white" alt="Go 1.26">
  <a href="LICENSE"><img src="https://img.shields.io/badge/лицензия-MIT-0d1117" alt="MIT"></a>
  <img src="https://img.shields.io/badge/Remnawave-2.7.4%2B%20%C2%B7%203.x-6e5cf5" alt="Remnawave 2.7.4+">
</p>

<p>
  <a href="https://vpn-hub.pro"><img src="https://img.shields.io/badge/VPN_HUB-vpn--hub.pro-fcb874?style=for-the-badge" alt="vpn-hub.pro"></a>
  <a href="https://t.me/vpnhub_community"><img src="https://img.shields.io/badge/сообщество-@vpnhub__community-26A5E4?style=for-the-badge&logo=telegram&logoColor=white" alt="Сообщество в Telegram"></a>
</p>

</div>

# MultiGate

Прослойка подписок для панели [Remnawave](https://remna.st): встаёт между клиентом и панелью,
даёт российский домен подписки, показывает кто и с чего подключается, и позволяет управлять
выдачей, не трогая саму панель.

Один статический бинарник без зависимостей. SQLite из коробки, MySQL для крупных установок.

> [!WARNING]
> **Статус: ранняя версия.** Ставьте на тестовом контуре, прежде чем выпускать на клиентов.
> Функция грейса меняет данные в живой панели и по умолчанию выключена: включайте осознанно.

**Содержание:** [Что решает](#что-решает) · [Возможности](#возможности) · [Как выглядит](#как-выглядит) ·
[Установка](#установка) · [Настройка](#настройка) · [Токен панели](#токен-панели) ·
[Совместимость](#совместимость) · [Помощь](#помощь-и-сообщество) · [Разработка](#разработка)

## Что решает

Подписка в Remnawave живёт по адресу панели. Если панель за Cloudflare или за границей,
её адрес рано или поздно перестаёт открываться из России, и подписка не обновляется у всех
разом. При этом узлы работают, а пользователь видит «подписка недоступна» и пишет в поддержку.

Ещё панель не отвечает на ежедневные вопросы: с какого приложения пришёл клиент, сколько
у него устройств, кто раздал одну подписку на общежитие. И отдаёт всем одинаковые заголовки,
хотя приложения понимают разное.

MultiGate закрывает это, оставаясь снаружи панели.

## Возможности

- **Два режима**: зеркало подписки на российском домене либо самостоятельная выдача через API панели. Переключается в админке без перезапуска.
- **Кто пришёл**: определение приложения, его версии, ядра и устройства по User-Agent. Для приложений, которые не шлют свои заголовки, идентификатор устройства собирается из User-Agent.
- **Журнал запросов** с фильтрами по пользователю, устройству, адресу, приложению и решению.
- **Блокировки** пользователя целиком или отдельного устройства. Локальные: панель не трогается.
- **Правила ответа** под конкретные приложения: подмена названия профиля, ссылки поддержки, интервала обновления.
- **Грейс** для истёкших подписок: временный сквад вместо полного отключения, со снимком для отката.
- **Пул конфигов** WireGuard и AmneziaWG с привязкой к устройству.
- **Страница-маскировка** для тех, кто зашёл браузером: адрес не выглядит как сервис подписок.
- **Ретрансляция вебхуков** панели на несколько адресов, каждому своя подпись.
- **Чат поддержки** с пересылкой в Telegram, с возможностью указать своё зеркало Bot API.
- **Админка** со всем перечисленным, встроенная в бинарник.

Подробности устройства: [docs/architecture.md](docs/architecture.md).
Разбор с примерами из практики: [статья на VPN HUB](https://vpn-hub.pro/a/multigate) — доступ PRO.

## Как выглядит

<div align="center">
  <img src="docs/screens/mg-overview.png" alt="Сводка: запросы, приложения, устройства" width="80%">
</div>

<details>
<summary><b>Ещё экраны админки</b> — журнал, пользователи, правила, настройки</summary>

<br>

**Журнал запросов.** Кто пришёл, с какого приложения и устройства, что получил в ответ.

<img src="docs/screens/mg-reqlog.png" alt="Журнал запросов" width="100%">

**Пользователи.** Устройства, приложения, блокировки — без захода в панель.

<img src="docs/screens/mg-users.png" alt="Список пользователей" width="100%">

**Правила ответа.** Заголовки и параметры подписки под конкретное приложение.

<img src="docs/screens/mg-headerrules.png" alt="Правила заголовков" width="100%">

**Переопределения.** Точечные исключения для отдельных пользователей.

<img src="docs/screens/mg-overrides.png" alt="Переопределения" width="100%">

**Настройки.** Режим, панель, домен, грейс, вебхуки, чат.

<img src="docs/screens/mg-settings.png" alt="Настройки" width="100%">

</details>

## Установка

### Из исходников

Самый прямой путь, пока проект в ранней стадии: собирается одной командой, ничего лишнего
в систему не ставит.

```bash
git clone https://github.com/qwe8nxtroud/multigate.git
cd multigate
make build
./multigate --listen 127.0.0.1:8080 --data ./data
```

### Отдельный сервер, systemd

```bash
curl -fsSL https://raw.githubusercontent.com/qwe8nxtroud/multigate/main/deploy/install.sh -o install.sh
sudo bash install.sh
```

Установщик ставит один бинарник, заводит системного пользователя и юнит systemd.
Он **не трогает ваш веб-сервер**: не сносит nginx, не выпускает сертификаты, не правит
чужие конфигурации. В конце печатает готовые куски конфигурации для nginx и Caddy.

Обновление — **только** `sudo bash install.sh --update`: эта ветка делает резервную копию
бинарника и откатывается сама, если новая версия не поднялась. Повторный запуск без флага
перезаписывает бинарник без страховки.

### Рядом с панелью, Docker

```bash
curl -fsSL https://raw.githubusercontent.com/qwe8nxtroud/multigate/main/deploy/docker-compose.yml -o docker-compose.yml
# задайте MULTIGATE_PANEL_TOKEN и MULTIGATE_ADMIN_PASSWORD
docker compose up -d
```

> [!NOTE]
> Образ `ghcr.io/qwe8nxtroud/multigate:v1` появляется в GHCR после первого релиза
> (`git tag v1.0.0 && git push origin v1.0.0`), и пакет нужно один раз переключить
> в публичные: **Packages → multigate → Package settings → Change visibility → Public**.
> Пока этого не сделано, `docker compose up -d` отвечает `error from registry: denied`.
> Обходной путь без реестра — собрать образ на самом сервере:
> ```bash
> make docker VERSION=v1 && docker compose up -d
> ```

Прослойка слушает `127.0.0.1:8080`. Наружу её выставляет тот же обратный прокси,
который уже обслуживает панель.

## Настройка

Всё, кроме адреса прослушивания и пути к базе, настраивается в админке и хранится в базе.
Переменные окружения нужны только для первого запуска, чтобы контейнер поднялся без
ручного мастера:

| Переменная | Назначение |
|---|---|
| `MULTIGATE_LISTEN` | адрес и порт, по умолчанию `127.0.0.1:8080` |
| `MULTIGATE_DATA_DIR` | каталог данных, по умолчанию `/var/lib/multigate` |
| `MULTIGATE_DB` | DSN базы: `sqlite:///путь/multigate.db` или `mysql://user:pass@host/db` |
| `MULTIGATE_MODE` | режим при первом запуске: `mirror` или `panel` |
| `MULTIGATE_PANEL_URL` | адрес API панели |
| `MULTIGATE_PANEL_TOKEN` | токен API панели |
| `MULTIGATE_MIRROR_TARGET` | домен origin панели для режима зеркала |
| `MULTIGATE_DOMAIN` | домен самой прослойки |
| `MULTIGATE_ADMIN_USER` `MULTIGATE_ADMIN_PASSWORD` | учётные данные админки при первом запуске |
| `MULTIGATE_LOG_LEVEL` | `debug`, `info`, `warn`, `error` |

Эти значения применяются **один раз, на пустой базе**. Дальше настройки живут в базе,
и перезапуск не затирает то, что вы поменяли в админке.

## Токен панели

Прослойке нужен токен API Remnawave. Выдавайте токен с минимально необходимыми правами:
на панели 2.8.0 и новее права ограничиваются при создании токена.

Токен хранится в базе прослойки. Это значит, что доступ к серверу прослойки равносилен
доступу к токену панели: держите базу на своём сервере, ограничьте права токена и не
выставляйте админку в интернет без нужды. Подробнее — [SECURITY.md](SECURITY.md).

## Совместимость

| | |
|---|---|
| Панель Remnawave | 2.7.4 и новее, включая 3.x |
| Клиенты | Happ, v2rayNG, Streisand, Hiddify, NekoBox, Clash Meta и Verge, FlClash, Shadowrocket, sing-box, Karing и другие |
| Форматы подписки | base64, обычный список, Clash (YAML), sing-box (JSON) |
| Архитектуры | linux/amd64, linux/arm64 |
| База | SQLite (по умолчанию), MySQL или MariaDB |

## Помощь и сообщество

<table>
<tr>
<td width="50%">

### 💬 [@vpnhub_community](https://t.me/vpnhub_community)

Сообщество VPN HUB в Telegram: вопросы по установке и настройке,
разбор проблем по горячим следам, анонсы обновлений.
Открыто для всех.

</td>
<td width="50%">

### 📚 [vpn-hub.pro](https://vpn-hub.pro)

База знаний по запуску и обслуживанию коммерческого VPN-сервиса:
панель, узлы, маскировка, приём платежей, работа с блокировками.

</td>
</tr>
</table>

Нашли ошибку — [заведите задачу](https://github.com/qwe8nxtroud/multigate/issues/new/choose).
Нашли уязвимость — не в публичную задачу, а по [SECURITY.md](SECURITY.md).
Хотите поучаствовать — [CONTRIBUTING.md](CONTRIBUTING.md).

## Разработка

```bash
make check   # go vet и тесты
make test    # только тесты
make dist    # архивы под linux/amd64 и linux/arm64
make docker  # образ
```

## Автор

MultiGate сделан в [VPN HUB](https://vpn-hub.pro): база знаний и сообщество для тех,
кто запускает и держит коммерческий VPN-сервис.

Ещё продукты VPN HUB для той же задачи:

- **[MultiScript](https://vpn-hub.pro/a/multiscript-about)** — VPN-сервис под ключ: панель Remnawave, ноды и бот продаж разворачиваются из одного меню.
- **[MultiRoller](https://vpn-hub.pro/a/33-multiroller)** — чистые IP, которых нет у конкурентов.

## Лицензия

[MIT](LICENSE).

Проект написан с нуля и не содержит кода других решений. Совпадения в наборе возможностей
объясняются тем, что задачи у прослоек подписки одинаковые: протокол Remnawave и поведение
клиентских приложений заданы снаружи.

<div align="center">
<br>
<a href="https://vpn-hub.pro"><b>vpn-hub.pro</b></a> · <a href="https://t.me/vpnhub_community">@vpnhub_community</a>
</div>
