// Package admin: веб-админка прослойки MultiGate.
//
// Всё, что видит администратор: обзор, журнал запросов, пользователи панели,
// локальные блокировки, правила подмены заголовков, настройки и сведения
// о сборке. Шаблоны и статика встроены в бинарник через web.TemplatesFS и
// web.StaticFS, поэтому продукт остаётся одним файлом без внешних ассетов.
//
// Панель Remnawave может быть не настроена (Deps.Panel == nil) или быть
// недоступной по сети: админка обязана в обоих случаях открываться и
// работать, просто показывая понятное состояние вместо данных панели.
package admin

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// Panel: то, что админке нужно от панели Remnawave. Реализацию поставляет
// пакет remnawave; здесь только интерфейс, чтобы не тянуть его зависимости.
type Panel interface {
	Info(ctx context.Context) (model.PanelInfo, error)
	ListUsers(ctx context.Context, offset, limit int, search string) ([]model.PanelUser, int, error)
	UserByShortUUID(ctx context.Context, shortUUID string) (model.PanelUser, error)
	Devices(ctx context.Context, userRef string) ([]model.Device, error)
	DeleteDevice(ctx context.Context, userRef, hwid string) error
	Squads(ctx context.Context) ([]model.Squad, error)
	SystemStats(ctx context.Context) (map[string]any, error)
}

// Deps: зависимости админки.
type Deps struct {
	Store  *store.DB
	Panel  Panel // может быть nil, если панель ещё не настроена
	Logger *slog.Logger
	// BasePath: префикс путей админки, например "/admin". Пустая строка
	// заменяется значением по умолчанию.
	BasePath string

	// ReqLog: счётчик выброшенных записей журнала запросов. Поле необязательное:
	// сам объект живёт в main (пишущая горутина заводится там же, где открыта
	// база), а сюда передаётся только для отображения на вкладке «Обзор».
	// Методы ReqLogger безопасны для вызова на nil-получателе, так что здесь
	// достаточно того же соглашения: если не задано, просто не показываем счётчик.
	ReqLog *store.ReqLogger

	// TrustProxy: доверять ли заголовкам X-Forwarded-For/X-Real-IP при
	// определении IP клиента для антибрутфорса входа и журнала. По умолчанию
	// false, это безопасное поведение: заголовки, которые выставляет сам
	// клиент, игнорируются, IP берётся только из RemoteAddr. Включать имеет
	// смысл, только если админка действительно стоит за обратным прокси,
	// который сам проставляет эти заголовки и недоступен напрямую (тот же
	// смысл, что у cfg.TrustProxy для ядра прокси подписки).
	TrustProxy bool
}

// Handler: HTTP-обработчик админки.
type Handler struct {
	store  *store.DB
	panel  Panel
	log    *slog.Logger
	reqLog *store.ReqLogger

	base string // нормализованный BasePath, без хвостового слеша
	mux  *http.ServeMux
	tmpl *templateSet

	sessions   *sessionStore
	limiter    *loginLimiter
	trustProxy bool

	startedAt time.Time // момент создания обработчика, для аптайма на вкладке «О системе»
}

// New собирает обработчик админки и регистрирует маршруты.
func New(d Deps) (*Handler, error) {
	if d.Store == nil {
		return nil, errString("admin: не задан Store")
	}
	log := d.Logger
	if log == nil {
		log = slog.Default()
	}

	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}

	h := &Handler{
		store:      d.Store,
		panel:      d.Panel,
		log:        log,
		reqLog:     d.ReqLog,
		base:       normalizeBasePath(d.BasePath),
		tmpl:       tmpl,
		sessions:   newSessionStore(),
		limiter:    newLoginLimiter(),
		trustProxy: d.TrustProxy,
		startedAt:  time.Now(),
	}
	h.routes()
	return h, nil
}

// Close останавливает фоновые горутины админки (пока что только уборку
// просроченных сессий по таймеру, см. sessionStore). Процесс и так убивает
// их при выходе, так что в проде вызывать Close необязательно; явный метод
// нужен прежде всего тестам, которые создают Handler многократно и иначе
// копили бы висящие горутины между тест-кейсами.
func (h *Handler) Close() {
	h.sessions.Stop()
}

// ServeHTTP реализует http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hdr := w.Header()
	// Вся статика встроена и своя, внешних ресурсов нет: можно держать
	// CSP по умолчанию только на 'self' и совсем без inline-скриптов и стилей.
	hdr.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("Referrer-Policy", "same-origin")
	h.mux.ServeHTTP(w, r)
}

// normalizeBasePath приводит путь к виду без хвостового слеша, с ведущим.
// Корень ("/" или пусто) даёт пустую строку: дальше пути собираются
// конкатенацией base+"/overview" и не должны задваивать слеш.
func normalizeBasePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		p = "/admin"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimSuffix(p, "/")
	return p
}

// path собирает путь внутри админки относительно BasePath.
func (h *Handler) path(suffix string) string {
	if suffix == "" || suffix == "/" {
		if h.base == "" {
			return "/"
		}
		return h.base
	}
	return h.base + suffix
}

// errString: маленький конструктор ошибки без формата, чтобы не тащить
// fmt туда, где хватает статического текста.
type errString string

func (e errString) Error() string { return string(e) }
