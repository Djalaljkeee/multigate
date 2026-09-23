package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Ключи настроек. Всё, что можно поменять из админки, живёт в базе,
// а не в файле конфигурации: перезапуск процесса для смены режима не нужен.
const (
	KeyMode          = "mode"             // mirror | panel
	KeyPanelURL      = "panel_url"        // внутренний адрес API панели
	KeyPanelToken    = "panel_token"      // токен API панели
	KeyMirrorTarget  = "mirror_target"    // домен origin для режима зеркала
	KeySubPageURL    = "subpage_url"      // адрес контейнера страницы подписки
	KeyOwnDomain     = "own_domain"       // домен самой прослойки
	KeyAdminUser     = "admin_user"       // логин админки
	KeyAdminHash     = "admin_hash"       // хеш пароля админки
	KeyAdminPath     = "admin_path"       // путь админки, по умолчанию /admin
	KeyLogEnabled    = "log_enabled"      // писать журнал запросов
	KeyLogKeepDays   = "log_keep_days"    // сколько дней хранить журнал
	KeyLogBodies     = "log_bodies"       // писать ли тела ответов (тяжело, по умолчанию нет)
	KeyHWIDEnforce   = "hwid_enforce"     // включить блокировку по HWID
	KeyHWIDFromUA    = "hwid_from_ua"     // вытаскивать HWID из User-Agent
	KeyGraceEnabled  = "grace_enabled"    // включить грейс для истёкших
	KeyGraceSquad    = "grace_squad"      // uuid сквада для грейса
	KeyGraceHours    = "grace_hours"      // длительность грейса в часах
	KeyDecoyEnabled  = "decoy_enabled"    // отдавать маскировку не-клиентам
	KeyDecoyTheme    = "decoy_theme"      // оформление страницы-маскировки
	KeyChatEnabled   = "chat_enabled"     // виджет поддержки
	KeyChatTGToken   = "chat_tg_token"    // токен бота Telegram
	KeyChatTGChat    = "chat_tg_chat"     // чат, куда падают обращения
	KeyChatTGAPIBase = "chat_tg_api_base" // зеркало api.telegram.org, если он недоступен
	// KeyChatTGWebhookSecret: секрет, который Telegram присылает в заголовке
	// X-Telegram-Bot-Api-Secret-Token. Без него подлинность апдейта проверяется
	// только по идентификатору чата, а он утекает из скриншотов и конфигов.
	KeyChatTGWebhookSecret = "chat_tg_webhook_secret"
	KeyCacheTTL            = "cache_ttl"         // сколько секунд держать ответ в кэше
	KeyUpstreamTimeout     = "upstream_timeout"  // таймаут запроса к панели, секунды
	KeyBrandTitle          = "brand_title"       // заголовок профиля по умолчанию
	KeyBrandSupportURL     = "brand_support_url" // ссылка поддержки по умолчанию
	KeyUpdateInterval      = "update_interval"   // profile-update-interval в часах
	KeyTrustedProxies      = "trusted_proxies"   // сети, чьему X-Forwarded-For можно верить
	KeyWebhookSecret       = "webhook_secret"    // секрет входящих вебхуков от панели
	KeyWGPoolEnabled       = "wg_pool_enabled"   // выдавать конфиги WireGuard из пула
	KeyInstalled           = "installed"         // мастер первичной настройки пройден

	// KeyMarzbanLegacyKeys: секреты Marzban через запятую. С ними прослойка
	// понимает старые ссылки подписки Marzban (см. internal/legacy). Секрет:
	// в админке показывается только факт «задан».
	KeyMarzbanLegacyKeys = "marzban_legacy_keys"
	// KeySubpageEnabled: показывать браузеру по живой ссылке страницу
	// подписки с инструкциями (internal/subpage) вместо маскировки.
	KeySubpageEnabled = "subpage_enabled"
	// KeySubpageLogoURL: логотип на странице подписки; пусто, значит
	// logoUrl из конфига страницы в панели.
	KeySubpageLogoURL = "subpage_logo_url"
)

// defaults: значения, с которыми прослойка стартует на пустой базе.
var defaults = map[string]string{
	KeyMode:            string("mirror"),
	KeyAdminPath:       "/admin",
	KeyLogEnabled:      "1",
	KeyLogKeepDays:     "14",
	KeyLogBodies:       "0",
	KeyHWIDEnforce:     "0",
	KeyHWIDFromUA:      "1",
	KeyGraceEnabled:    "0", // трогает живую панель, поэтому по умолчанию выключено
	KeyGraceHours:      "24",
	KeyDecoyEnabled:    "1",
	KeyDecoyTheme:      "blank",
	KeyChatEnabled:     "0",
	KeyChatTGAPIBase:   "https://api.telegram.org",
	KeyCacheTTL:        "0", // кэш по умолчанию выключен: подписка должна быть свежей
	KeyUpstreamTimeout: "15",
	KeyUpdateInterval:  "12",
	KeyWGPoolEnabled:   "0",
	KeyInstalled:       "0",
	KeySubpageEnabled:  "0",
}

// settingsCache держит настройки в памяти: их читают на каждом запросе подписки,
// а меняют раз в месяц. Инвалидация полная: настроек десятки, не тысячи.
type settingsCache struct {
	db  *DB
	mu  sync.RWMutex
	val map[string]string
	at  time.Time
	ttl time.Duration
}

func newSettingsCache(db *DB) *settingsCache {
	return &settingsCache{db: db, ttl: 30 * time.Second}
}

// Settings возвращает все настройки, подставляя значения по умолчанию.
func (d *DB) Settings(ctx context.Context) (map[string]string, error) {
	c := d.settings
	c.mu.RLock()
	fresh := c.val != nil && time.Since(c.at) < c.ttl
	if fresh {
		out := make(map[string]string, len(c.val))
		for k, v := range c.val {
			out[k] = v
		}
		c.mu.RUnlock()
		return out, nil
	}
	c.mu.RUnlock()

	rows, err := d.ro.QueryContext(ctx, "SELECT k, v FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	val := make(map[string]string, len(defaults)+8)
	for k, v := range defaults {
		val[k] = v
	}
	for rows.Next() {
		var k string
		var v sql.NullString
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		val[k] = v.String
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.val, c.at = val, time.Now()
	c.mu.Unlock()

	out := make(map[string]string, len(val))
	for k, v := range val {
		out[k] = v
	}
	return out, nil
}

// Get возвращает одну настройку.
func (d *DB) Get(ctx context.Context, key string) string {
	all, err := d.Settings(ctx)
	if err != nil {
		return defaults[key]
	}
	return all[key]
}

// GetInt возвращает настройку числом; при разборе ошибки отдаёт def.
func (d *DB) GetInt(ctx context.Context, key string, def int) int {
	v := strings.TrimSpace(d.Get(ctx, key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// GetBool трактует "1", "true", "yes", "on" как истину.
func (d *DB) GetBool(ctx context.Context, key string) bool {
	switch strings.ToLower(strings.TrimSpace(d.Get(ctx, key))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// GetDuration читает настройку как число секунд.
func (d *DB) GetDuration(ctx context.Context, key string, def time.Duration) time.Duration {
	sec := d.GetInt(ctx, key, -1)
	if sec < 0 {
		return def
	}
	return time.Duration(sec) * time.Second
}

// Set записывает настройку и сбрасывает кэш.
func (d *DB) Set(ctx context.Context, key, value string) error {
	if strings.TrimSpace(key) == "" {
		return errors.New("store: пустой ключ настройки")
	}
	var q string
	switch d.dialect {
	case DialectMySQL:
		q = "INSERT INTO settings (k, v, updated_at) VALUES (?, ?, ?) " +
			"ON DUPLICATE KEY UPDATE v = VALUES(v), updated_at = VALUES(updated_at)"
	default:
		q = "INSERT INTO settings (k, v, updated_at) VALUES (?, ?, ?) " +
			"ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at"
	}
	if _, err := d.rw.ExecContext(ctx, q, key, value, nowUnix()); err != nil {
		return err
	}
	d.InvalidateSettings()
	return nil
}

// SetMany записывает пачку настроек одной транзакцией.
func (d *DB) SetMany(ctx context.Context, kv map[string]string) error {
	if len(kv) == 0 {
		return nil
	}
	tx, err := d.rw.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	var q string
	switch d.dialect {
	case DialectMySQL:
		q = "INSERT INTO settings (k, v, updated_at) VALUES (?, ?, ?) " +
			"ON DUPLICATE KEY UPDATE v = VALUES(v), updated_at = VALUES(updated_at)"
	default:
		q = "INSERT INTO settings (k, v, updated_at) VALUES (?, ?, ?) " +
			"ON CONFLICT(k) DO UPDATE SET v = excluded.v, updated_at = excluded.updated_at"
	}
	now := nowUnix()
	for k, v := range kv {
		if _, err := tx.ExecContext(ctx, q, k, v, now); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	d.InvalidateSettings()
	return nil
}

// InvalidateSettings сбрасывает кэш настроек.
func (d *DB) InvalidateSettings() {
	c := d.settings
	c.mu.Lock()
	c.val, c.at = nil, time.Time{}
	c.mu.Unlock()
}
