// Package model содержит общие типы, которыми обмениваются пакеты MultiGate.
// Здесь не должно быть ни обращений к сети, ни к базе: только данные.
package model

import (
	"errors"
	"time"
)

// ErrNotFound: общий признак «сущности нет», единый для всех пакетов.
//
// Он живёт здесь, а не в хранилище или в клиенте панели, потому что
// проверяет его третья сторона: ядро прокси решает по нему, отдать 404
// или 502, и ему всё равно, кто именно не нашёл пользователя. Пакеты
// оборачивают этот сентинел своими сообщениями через %w.
var ErrNotFound = errors.New("не найдено")

// Mode: режим работы прослойки.
type Mode string

const (
	// ModeMirror: зеркало, запрос проксируется на внешний домен панели.
	// Используется, когда панель живёт за Cloudflare и плохо доступна из РФ.
	ModeMirror Mode = "mirror"
	// ModePanel: прослойка сама ходит в API панели и отдаёт подписку.
	ModePanel Mode = "panel"
)

// Decision: что прослойка решила сделать с запросом подписки.
type Decision string

const (
	DecisionNormal   Decision = "normal"   // отдать подписку как есть
	DecisionBlocked  Decision = "blocked"  // устройство или пользователь заблокированы
	DecisionExpired  Decision = "expired"  // срок подписки истёк
	DecisionNotFound Decision = "notfound" // такого shortUuid нет
	DecisionDecoy    Decision = "decoy"    // не похоже на клиент подписки, отдать маскировку
	DecisionPage     Decision = "page"     // браузер пришёл по живой ссылке, отдать страницу подписки
	// DecisionError: сбой связи с апстримом (панель/зеркало недоступны).
	// Отдельно от DecisionNormal: иначе в журнале сбой апстрима неотличим
	// от настоящей успешной выдачи подписки.
	DecisionError Decision = "error"
)

// Core: ядро, на котором работает клиентское приложение.
// От ядра зависит, какой формат конфигов ему отдавать.
type Core string

const (
	CoreXray    Core = "xray"
	CoreMihomo  Core = "mihomo"
	CoreSingBox Core = "singbox"
	CoreUnknown Core = "unknown"
)

// Format: формат тела ответа подписки.
type Format string

const (
	FormatBase64  Format = "base64"  // список ссылок vless:// в base64
	FormatPlain   Format = "plain"   // список ссылок без кодирования
	FormatClash   Format = "clash"   // YAML для mihomo/Clash
	FormatSingBox Format = "singbox" // JSON для sing-box
	FormatJSON    Format = "json"    // ответ API панели
	FormatHTML    Format = "html"    // страница подписки для браузера
	FormatUnknown Format = "unknown"
)

// Platform: операционная система клиента.
type Platform string

const (
	PlatformIOS     Platform = "ios"
	PlatformAndroid Platform = "android"
	PlatformWindows Platform = "windows"
	PlatformMacOS   Platform = "macos"
	PlatformLinux   Platform = "linux"
	PlatformUnknown Platform = "unknown"
)

// Client: то, что удалось понять про клиента по запросу.
// Заполняется пакетом ua из User-Agent и заголовков.
type Client struct {
	App        string   // "Happ", "v2rayNG", "Streisand", ...
	AppVersion string   // версия приложения, если её видно
	Core       Core     // ядро приложения
	Platform   Platform // ОС
	OSVersion  string   // версия ОС, если её видно
	Device     string   // модель устройства
	HWID       string   // идентификатор устройства: из заголовка или вытащенный из UA
	HWIDSource string   // "header" | "ua" | "": откуда взялся HWID
	IsBrowser  bool     // запрос сделан браузером, а не клиентом подписки
	UserAgent  string   // исходная строка User-Agent
}

// SupportsWireGuard сообщает, понимает ли приложение конфиги WireGuard/AmneziaWG.
func (c Client) SupportsWireGuard() bool {
	return c.Core == CoreSingBox || c.Core == CoreMihomo
}

// UserInfo: разобранный заголовок subscription-userinfo.
type UserInfo struct {
	Upload   int64
	Download int64
	Total    int64 // 0 означает безлимит
	Expire   int64 // unix-время, 0 означает бессрочно
}

// Used возвращает суммарно израсходованный трафик.
func (u UserInfo) Used() int64 { return u.Upload + u.Download }

// IsExpired сообщает, истёк ли срок на момент now.
func (u UserInfo) IsExpired(now time.Time) bool {
	return u.Expire > 0 && now.Unix() > u.Expire
}

// PanelUser: пользователь панели Remnawave в виде, не зависящем от версии панели.
type PanelUser struct {
	// Ref: ссылка на пользователя для запросов к API.
	// В панели 2.x это uuid, в 3.x это числовой id. Пакет remnawave прячет разницу.
	Ref               string
	UUID              string
	ShortUUID         string
	Username          string
	Status            string // ACTIVE | DISABLED | LIMITED | EXPIRED
	ExpireAt          time.Time
	TrafficLimitBytes int64
	UsedTrafficBytes  int64
	HWIDDeviceLimit   int
	TelegramID        int64
	Email             string
	Squads            []string // uuid внутренних сквадов
	Tag               string
}

// IsActive сообщает, считается ли пользователь действующим по данным панели.
func (u PanelUser) IsActive() bool { return u.Status == "ACTIVE" }

// Device: устройство пользователя из реестра HWID панели.
type Device struct {
	HWID       string
	UserRef    string
	Platform   string
	OSVersion  string
	Device     string
	AppVersion string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Squad: внутренний сквад панели.
type Squad struct {
	UUID    string
	Name    string
	Members int
}

// PanelInfo: сведения о подключённой панели.
type PanelInfo struct {
	Version   string // например "3.2.2"
	Major     int    // 2 или 3, определяет форму запросов к API
	Reachable bool
	CheckedAt time.Time
	Err       string // текст последней ошибки связи, если она была
}

// SubResponse: ответ подписки, который прослойка получила и готовит к отдаче.
type SubResponse struct {
	Status  int
	Headers map[string]string
	Body    []byte
	Format  Format
}

// SubInfo: сведения о подписке для страницы, которую видит браузер.
// Это ответ публичного маршрута панели /api/sub/{shortUuid}/info:
// тот же источник, из которого страница подписки Remnawave рисует карточку.
type SubInfo struct {
	ShortUUID         string
	Username          string
	Status            string // ACTIVE | DISABLED | LIMITED | EXPIRED
	IsActive          bool
	ExpiresAt         time.Time
	DaysLeft          int
	TrafficUsedBytes  int64
	TrafficLimitBytes int64 // 0: без лимита
	SubscriptionURL   string
}

// SubpageRef: какой конфиг страницы подписки панель назначила пользователю
// и разрешена ли ему страница вообще (правила SRR в панели).
type SubpageRef struct {
	ConfigUUID     string
	WebpageAllowed bool
}

// Override: локальное правило по конкретному пользователю или устройству.
// Живёт в базе прослойки и не трогает панель.
type Override struct {
	ID        int64
	ShortUUID string // пусто, если правило про устройство
	HWID      string // пусто, если правило про пользователя целиком
	Action    string // "block" | "allow"
	Reason    string
	CreatedAt time.Time
	CreatedBy string
}

// RequestLog: строка журнала запросов подписки.
type RequestLog struct {
	ID         int64
	At         time.Time
	ShortUUID  string
	Username   string
	IP         string
	Country    string
	UserAgent  string
	App        string
	AppVersion string
	Platform   string
	Core       string
	HWID       string
	Format     string
	Decision   string
	Status     int
	Bytes      int
	DurationMS int
	Mode       string
	Err        string
}

// HeaderRule: правило подмены заголовков ответа под конкретное приложение.
type HeaderRule struct {
	ID        int64
	Name      string
	Enabled   bool
	Priority  int
	MatchApp  string // имя приложения или пусто (любое)
	MatchOS   string // платформа или пусто (любая)
	MatchUA   string // подстрока или регулярное выражение по UA
	UARegex   bool
	SetHeader map[string]string // какие заголовки выставить
	DelHeader []string          // какие заголовки убрать
	CreatedAt time.Time
}

// GraceRecord: снимок пользователя перед переводом в грейс.
// Без него откат невозможен, поэтому запись создаётся до обращения к панели.
type GraceRecord struct {
	ID             int64
	UserRef        string
	ShortUUID      string
	Username       string
	StartedAt      time.Time
	ExpiresAt      time.Time
	Restored       bool
	RestoredAt     time.Time
	SnapshotJSON   string // исходное состояние пользователя в панели
	AppliedSquad   string
	OriginalSquads string
	Err            string
}

// WGLease: выданный из пула конфиг WireGuard/AmneziaWG.
type WGLease struct {
	ID         int64
	Pool       string
	ConfigName string
	Config     string
	ShortUUID  string
	HWID       string
	IssuedAt   time.Time
	ReleasedAt time.Time
	InUse      bool
}

// WebhookEvent: принятое от панели событие.
type WebhookEvent struct {
	ID        int64
	At        time.Time
	Event     string
	Payload   string
	SigValid  bool
	Forwarded int
	Err       string
}

// ForwardTarget: адрес, на который ретранслируются вебхуки.
// У каждого адреса свой секрет: подпись пересчитывается под получателя.
type ForwardTarget struct {
	ID        int64
	Name      string
	URL       string
	Secret    string
	Enabled   bool
	Events    []string // пустой список означает все события
	CreatedAt time.Time
}

// ChatMessage: сообщение виджета поддержки.
type ChatMessage struct {
	ID        int64
	SessionID string
	At        time.Time
	FromUser  bool
	Text      string
	TGMsgID   int64
	Delivered bool
}
