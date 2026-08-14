#!/usr/bin/env bash
#
# Установщик MultiGate для Debian 12+ и Ubuntu 22.04+.
#
# Что делает: ставит один бинарник, заводит системного пользователя,
# каталог данных и юнит systemd. Больше ничего.
#
# Чего НЕ делает намеренно: не трогает ваш веб-сервер, не сносит nginx,
# не выпускает сертификаты и не правит чужие конфигурации. Прослойка
# слушает localhost, а наружу её выставляет тот обратный прокси, который
# у вас уже есть. Готовые куски конфигурации скрипт покажет в конце.
#
#   Установка:  bash install.sh
#   Обновление: bash install.sh --update
#   Удаление:   bash install.sh --uninstall
#
set -euo pipefail

REPO="qwe8nxtroud/multigate"
BIN_PATH="/usr/local/bin/multigate"
DATA_DIR="/var/lib/multigate"
ETC_DIR="/etc/multigate"
UNIT_PATH="/etc/systemd/system/multigate.service"
SERVICE_USER="multigate"
LISTEN="127.0.0.1:8080"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; OFF=$'\033[0m'

info()  { printf '%s\n' "${GREEN}==>${OFF} $*"; }
warn()  { printf '%s\n' "${YELLOW}[!]${OFF} $*"; }
die()   { printf '%s\n' "${RED}[x]${OFF} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Запускать нужно от root: sudo bash install.sh"

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "Архитектура $(uname -m) не поддерживается: соберите бинарник сами командой make build" ;;
  esac
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Не найдена утилита $1: установите её и повторите"
}

latest_tag() {
  # Тег последнего релиза берём из API GitHub. Если сети нет или лимит
  # исчерпан, пользователь может задать версию сам: VERSION=v1.2.3 bash install.sh
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4
}

download_binary() {
  local tag="$1" arch="$2" tmp
  tmp="$(mktemp -d)"
  local url="https://github.com/${REPO}/releases/download/${tag}/multigate_${tag#v}_linux_${arch}.tar.gz"

  info "Скачиваю ${tag} для linux/${arch}"
  curl -fsSL "$url" -o "${tmp}/multigate.tar.gz" \
    || die "Не удалось скачать релиз по адресу ${url}"

  # Проверяем контрольную сумму, если она опубликована рядом с релизом.
  if curl -fsSL "https://github.com/${REPO}/releases/download/${tag}/checksums.txt" -o "${tmp}/checksums.txt" 2>/dev/null; then
    ( cd "$tmp" && grep " multigate_${tag#v}_linux_${arch}.tar.gz\$" checksums.txt | sha256sum -c - >/dev/null 2>&1 ) \
      && info "Контрольная сумма совпала" \
      || die "Контрольная сумма НЕ совпала: установка остановлена"
  else
    warn "Файл контрольных сумм не найден, пропускаю проверку"
  fi

  tar -xzf "${tmp}/multigate.tar.gz" -C "$tmp"
  install -m 0755 "${tmp}/multigate" "$BIN_PATH"
  rm -rf "$tmp"
}

ensure_user() {
  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    info "Создаю системного пользователя ${SERVICE_USER}"
    useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
  mkdir -p "$DATA_DIR" "$ETC_DIR"
  chown -R "${SERVICE_USER}:${SERVICE_USER}" "$DATA_DIR"
  chmod 0750 "$DATA_DIR"
}

install_unit() {
  info "Ставлю юнит systemd"
  local src
  src="$(dirname "$0")/multigate.service"
  if [[ -f "$src" ]]; then
    install -m 0644 "$src" "$UNIT_PATH"
  else
    curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/deploy/multigate.service" -o "$UNIT_PATH" \
      || die "Не удалось получить файл юнита"
  fi
  systemctl daemon-reload
}

first_setup_env() {
  # Файл окружения нужен только для первого запуска: он задаёт логин и пароль
  # администратора и адрес панели. Дальше всё живёт в базе и правится в админке.
  [[ -f "${ETC_DIR}/multigate.env" ]] && return 0

  local pass
  pass="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | head -c 20)"

  cat > "${ETC_DIR}/multigate.env" <<EOF
# Первичная настройка MultiGate. Применяется ОДИН раз, на пустой базе.
# После первого запуска настройки живут в базе и меняются в админке.

MULTIGATE_ADMIN_USER=admin
MULTIGATE_ADMIN_PASSWORD=${pass}

# Режим: mirror (зеркало подписки на внешний домен панели) или panel
# (прослойка сама ходит в API панели).
#MULTIGATE_MODE=panel
#MULTIGATE_PANEL_URL=https://panel.example.com
#MULTIGATE_PANEL_TOKEN=
#MULTIGATE_MIRROR_TARGET=panel.example.com
#MULTIGATE_DOMAIN=sub.example.com
EOF
  chmod 0600 "${ETC_DIR}/multigate.env"
  chown root:root "${ETC_DIR}/multigate.env"

  ADMIN_PASS_GENERATED="$pass"
}

show_proxy_snippets() {
  cat <<'EOF'

Осталось выставить прослойку наружу вашим обратным прокси.

Caddy:

    sub.example.com {
        reverse_proxy 127.0.0.1:8080
    }

nginx:

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
    }

EOF
}

do_install() {
  need_cmd curl; need_cmd tar; need_cmd systemctl
  local arch tag
  arch="$(detect_arch)"
  tag="${VERSION:-$(latest_tag)}"
  [[ -n "$tag" ]] || die "Не удалось определить последнюю версию: задайте её вручную, VERSION=v1.0.0 bash install.sh"

  ensure_user
  download_binary "$tag" "$arch"
  install_unit
  first_setup_env

  systemctl enable --now multigate
  sleep 2

  if systemctl is-active --quiet multigate; then
    info "MultiGate ${tag} запущен и слушает ${LISTEN}"
  else
    warn "Служба не поднялась, смотрите: journalctl -u multigate -n 50 --no-pager"
    exit 1
  fi

  if [[ -n "${ADMIN_PASS_GENERATED:-}" ]]; then
    printf '\n%s\n' "${BOLD}Данные для входа в админку:${OFF}"
    printf '  адрес:  https://ваш-домен/admin\n'
    printf '  логин:  admin\n'
    printf '  пароль: %s\n' "$ADMIN_PASS_GENERATED"
    printf '\nПароль сохранён в %s/multigate.env, смените его после первого входа.\n' "$ETC_DIR"
  fi

  show_proxy_snippets
}

do_update() {
  need_cmd curl; need_cmd tar
  local arch tag
  arch="$(detect_arch)"
  tag="${VERSION:-$(latest_tag)}"
  [[ -n "$tag" ]] || die "Не удалось определить последнюю версию"

  # База не трогается: обновляется только бинарник, схема мигрирует сама на старте.
  info "Обновляю до ${tag}"
  cp -a "$BIN_PATH" "${BIN_PATH}.bak" 2>/dev/null || true
  download_binary "$tag" "$arch"
  install_unit
  systemctl restart multigate
  sleep 2

  if systemctl is-active --quiet multigate; then
    info "Обновление прошло, версия $("$BIN_PATH" --version 2>/dev/null || echo "$tag")"
    rm -f "${BIN_PATH}.bak"
  else
    warn "Новая версия не поднялась, откатываюсь на предыдущую"
    [[ -f "${BIN_PATH}.bak" ]] && mv "${BIN_PATH}.bak" "$BIN_PATH" && systemctl restart multigate
    die "Откат выполнен, смотрите journalctl -u multigate -n 50 --no-pager"
  fi
}

do_uninstall() {
  info "Останавливаю службу"
  systemctl disable --now multigate 2>/dev/null || true
  rm -f "$UNIT_PATH"
  systemctl daemon-reload
  rm -f "$BIN_PATH"
  # Данные и настройки не удаляем: база с журналами и блокировками остаётся,
  # чтобы случайный запуск удаления не стёр историю. Удалите вручную при необходимости.
  warn "Каталог данных ${DATA_DIR} и настройки ${ETC_DIR} оставлены на месте"
  info "MultiGate удалён"
}

case "${1:-}" in
  --update)    do_update ;;
  --uninstall) do_uninstall ;;
  ""|--install) do_install ;;
  *) die "Неизвестный аргумент: $1 (доступно: --install, --update, --uninstall)" ;;
esac
