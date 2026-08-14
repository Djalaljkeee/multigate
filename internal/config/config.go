// Package config: параметры запуска процесса.
//
// Здесь только то, что нужно знать ДО открытия базы: адрес прослушивания,
// DSN базы, каталог данных. Всё остальное (режим работы, адрес панели, токен,
// правила) живёт в таблице settings и правится из админки без перезапуска.
package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config: параметры запуска.
type Config struct {
	Listen     string // адрес HTTP, например 127.0.0.1:8080
	DSN        string // DSN базы
	DataDir    string // каталог для базы и файлов
	LogLevel   string // debug | info | warn | error
	LogJSON    bool   // писать журнал процесса в JSON
	TrustProxy bool   // верить заголовкам X-Forwarded-For и X-Real-IP

	// Первичная настройка. Значения применяются один раз, на пустой базе,
	// и дальше игнорируются: живут они в settings, а не в окружении.
	// Так контейнер поднимается из compose без ручного мастера,
	// но перезапуск не затирает то, что администратор поменял в админке.
	Bootstrap Bootstrap

	ShowVersion bool
}

// Bootstrap: начальные настройки для первого старта.
type Bootstrap struct {
	Mode          string
	PanelURL      string
	PanelToken    string
	MirrorTarget  string
	SubPageURL    string
	Domain        string
	AdminUser     string
	AdminPassword string
	AdminPath     string
}

// Any сообщает, задано ли хоть что-то для первичной настройки.
func (b Bootstrap) Any() bool {
	return b.Mode != "" || b.PanelURL != "" || b.PanelToken != "" || b.MirrorTarget != "" ||
		b.SubPageURL != "" || b.Domain != "" || b.AdminUser != "" || b.AdminPassword != "" || b.AdminPath != ""
}

const envPrefix = "MULTIGATE_"

// Load собирает конфигурацию из флагов и окружения.
// Приоритет: флаг, затем переменная окружения, затем значение по умолчанию.
func Load(args []string) (Config, error) {
	var c Config

	fs := flag.NewFlagSet("multigate", flag.ContinueOnError)
	fs.StringVar(&c.Listen, "listen", env("LISTEN", "127.0.0.1:8080"), "адрес и порт HTTP")
	fs.StringVar(&c.DSN, "db", env("DB", ""), "DSN базы: sqlite:///path/multigate.db или mysql://user:pass@host/db")
	fs.StringVar(&c.DataDir, "data", env("DATA_DIR", defaultDataDir()), "каталог данных")
	fs.StringVar(&c.LogLevel, "log-level", env("LOG_LEVEL", "info"), "уровень журнала: debug, info, warn, error")
	fs.BoolVar(&c.LogJSON, "log-json", envBool("LOG_JSON", false), "писать журнал процесса в JSON")
	fs.BoolVar(&c.TrustProxy, "trust-proxy", envBool("TRUST_PROXY", true), "верить X-Forwarded-For от обратного прокси")
	fs.BoolVar(&c.ShowVersion, "version", false, "показать версию и выйти")

	fs.StringVar(&c.Bootstrap.Mode, "mode", env("MODE", ""), "режим при первом запуске: mirror или panel")
	fs.StringVar(&c.Bootstrap.PanelURL, "panel-url", env("PANEL_URL", ""), "адрес API панели Remnawave")
	fs.StringVar(&c.Bootstrap.PanelToken, "panel-token", env("PANEL_TOKEN", ""), "токен API панели")
	fs.StringVar(&c.Bootstrap.MirrorTarget, "mirror-target", env("MIRROR_TARGET", ""), "домен origin для режима зеркала")
	fs.StringVar(&c.Bootstrap.SubPageURL, "subpage-url", env("SUBPAGE_URL", ""), "адрес страницы подписки Remnawave")
	fs.StringVar(&c.Bootstrap.Domain, "domain", env("DOMAIN", ""), "домен самой прослойки")
	fs.StringVar(&c.Bootstrap.AdminUser, "admin-user", env("ADMIN_USER", ""), "логин админки при первом запуске")
	fs.StringVar(&c.Bootstrap.AdminPassword, "admin-password", env("ADMIN_PASSWORD", ""), "пароль админки при первом запуске")
	fs.StringVar(&c.Bootstrap.AdminPath, "admin-path", env("ADMIN_PATH", ""), "путь админки, по умолчанию /admin")

	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if c.ShowVersion {
		return c, nil
	}
	if err := c.normalize(); err != nil {
		return c, err
	}
	return c, nil
}

func (c *Config) normalize() error {
	c.Listen = strings.TrimSpace(c.Listen)
	if c.Listen == "" {
		return fmt.Errorf("config: не задан адрес прослушивания")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		// Разрешаем короткую форму ":8080" и "8080".
		if !strings.Contains(c.Listen, ":") {
			if _, perr := strconv.Atoi(c.Listen); perr == nil {
				c.Listen = ":" + c.Listen
			} else {
				return fmt.Errorf("config: не разобрать адрес %q: %w", c.Listen, err)
			}
		}
	}

	if c.DataDir == "" {
		c.DataDir = defaultDataDir()
	}
	abs, err := filepath.Abs(c.DataDir)
	if err != nil {
		return fmt.Errorf("config: не получить полный путь каталога данных: %w", err)
	}
	c.DataDir = abs

	if c.DSN == "" {
		c.DSN = "sqlite://" + filepath.Join(c.DataDir, "multigate.db")
	}
	if !strings.Contains(c.DSN, "://") {
		// Голый путь к файлу трактуем как SQLite.
		c.DSN = "sqlite://" + c.DSN
	}

	switch c.Bootstrap.Mode {
	case "", "mirror", "panel":
	default:
		return fmt.Errorf("config: режим %q не поддерживается, ожидается mirror или panel", c.Bootstrap.Mode)
	}

	if c.Bootstrap.AdminPath != "" && !strings.HasPrefix(c.Bootstrap.AdminPath, "/") {
		c.Bootstrap.AdminPath = "/" + c.Bootstrap.AdminPath
	}

	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
		c.LogLevel = strings.ToLower(c.LogLevel)
	default:
		return fmt.Errorf("config: неизвестный уровень журнала %q", c.LogLevel)
	}
	return nil
}

// defaultDataDir выбирает каталог данных: системный, если процесс запущен от root
// (обычный случай для systemd и контейнера), иначе локальный ./data.
func defaultDataDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/multigate"
	}
	return "data"
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(envPrefix + name); ok && v != "" {
		return v
	}
	return def
}

func envBool(name string, def bool) bool {
	v, ok := os.LookupEnv(envPrefix + name)
	if !ok || v == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}
