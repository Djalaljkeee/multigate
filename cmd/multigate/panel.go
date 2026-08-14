package main

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/remnawave"
	"github.com/qwe8nxtroud/multigate/internal/store"
	"github.com/qwe8nxtroud/multigate/internal/version"
)

// panelHolder: клиент панели, который можно заменить на ходу.
//
// Адрес и токен панели правятся в админке, и раньше это не действовало до
// перезапуска процесса: клиент собирался один раз на старте. Администратор
// менял протухший токен, видел «настройки сохранены» и продолжал получать
// 502, пока кто-нибудь не перезапускал сервис.
//
// Держатель раздаётся всем пакетам вместо самого клиента и реализует те же
// интерфейсы (proxy.Panel, admin.Panel, grace.Panel), а внутри подменяет
// клиента, когда настройки изменились.
type panelHolder struct {
	db  *store.DB
	log *slog.Logger

	cur atomic.Pointer[remnawave.Client]
	// key: отпечаток настроек, по которым собран текущий клиент.
	// Пересобираем только при его изменении, а не по таймеру.
	mu  sync.Mutex
	key string
}

// errNoPanel возвращается, когда панель ещё не настроена.
// Это не сбой связи, а отсутствие конфигурации: сообщение должно
// подсказывать администратору, что делать.
var errNoPanel = errNotConfigured{}

type errNotConfigured struct{}

func (errNotConfigured) Error() string {
	return "панель не настроена: укажите адрес и токен в админке"
}

func newPanelHolder(ctx context.Context, db *store.DB, log *slog.Logger) *panelHolder {
	h := &panelHolder{db: db, log: log}
	h.refresh(ctx)
	return h
}

// refresh пересобирает клиента, если настройки изменились.
func (h *panelHolder) refresh(ctx context.Context) {
	url := strings.TrimSpace(h.db.Get(ctx, store.KeyPanelURL))
	token := strings.TrimSpace(h.db.Get(ctx, store.KeyPanelToken))
	timeout := h.db.GetDuration(ctx, store.KeyUpstreamTimeout, 15*time.Second)

	// В отпечаток идёт длина токена, а не он сам: отпечаток попадает
	// в отладочный журнал, и секрету там не место.
	key := url + "|" + timeout.String() + "|" + lenKey(token)

	h.mu.Lock()
	defer h.mu.Unlock()
	if key == h.key {
		return
	}

	if url == "" {
		h.cur.Store(nil)
		h.key = key
		h.log.Info("адрес панели не задан: клиент API не создан")
		return
	}

	c, err := remnawave.New(remnawave.Options{
		BaseURL:   url,
		Token:     token,
		Timeout:   timeout,
		UserAgent: version.UserAgent(),
		Logger:    h.log,
	})
	if err != nil {
		// Неверный адрес не повод останавливать сервис: администратор
		// поправит его в той же админке, а до тех пор работает зеркало.
		h.log.Error("клиент панели не создан", "ошибка", err)
		h.cur.Store(nil)
		h.key = key
		return
	}

	h.cur.Store(c)
	h.key = key
	h.log.Info("клиент панели пересобран", "адрес", url, "таймаут", timeout)
}

// watch следит за настройками и подхватывает изменения без перезапуска.
func (h *panelHolder) watch(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.refresh(ctx)
		}
	}
}

func (h *panelHolder) client() (*remnawave.Client, error) {
	c := h.cur.Load()
	if c == nil {
		return nil, errNoPanel
	}
	return c, nil
}

// Configured сообщает, настроена ли панель. Нужно там, где интерфейс
// пробрасывается дальше как необязательная зависимость.
func (h *panelHolder) Configured() bool { return h.cur.Load() != nil }

// Дальше идут делегаты. Они существуют, чтобы держатель подходил под
// интерфейсы Panel в пакетах proxy, admin и grace: те объявляют свои
// требования сами, а сюда достаточно проксировать вызовы.

func (h *panelHolder) Info(ctx context.Context) (model.PanelInfo, error) {
	c, err := h.client()
	if err != nil {
		return model.PanelInfo{Reachable: false, Err: err.Error(), CheckedAt: time.Now()}, err
	}
	return c.Info(ctx)
}

func (h *panelHolder) Subscription(ctx context.Context, shortUUID string, in http.Header) (*model.SubResponse, error) {
	c, err := h.client()
	if err != nil {
		return nil, err
	}
	return c.Subscription(ctx, shortUUID, in)
}

func (h *panelHolder) UserByShortUUID(ctx context.Context, shortUUID string) (model.PanelUser, error) {
	c, err := h.client()
	if err != nil {
		return model.PanelUser{}, err
	}
	return c.UserByShortUUID(ctx, shortUUID)
}

func (h *panelHolder) ListUsers(ctx context.Context, offset, limit int, search string) ([]model.PanelUser, int, error) {
	c, err := h.client()
	if err != nil {
		return nil, 0, err
	}
	return c.ListUsers(ctx, offset, limit, search)
}

func (h *panelHolder) UpdateUser(ctx context.Context, ref string, patch map[string]any) error {
	c, err := h.client()
	if err != nil {
		return err
	}
	return c.UpdateUser(ctx, ref, patch)
}

func (h *panelHolder) Devices(ctx context.Context, userRef string) ([]model.Device, error) {
	c, err := h.client()
	if err != nil {
		return nil, err
	}
	return c.Devices(ctx, userRef)
}

func (h *panelHolder) DeleteDevice(ctx context.Context, userRef, hwid string) error {
	c, err := h.client()
	if err != nil {
		return err
	}
	return c.DeleteDevice(ctx, userRef, hwid)
}

func (h *panelHolder) Squads(ctx context.Context) ([]model.Squad, error) {
	c, err := h.client()
	if err != nil {
		return nil, err
	}
	return c.Squads(ctx)
}

func (h *panelHolder) SystemStats(ctx context.Context) (map[string]any, error) {
	c, err := h.client()
	if err != nil {
		return nil, err
	}
	return c.SystemStats(ctx)
}

// lenKey превращает секрет в безопасный для журнала признак изменения.
func lenKey(s string) string {
	if s == "" {
		return "нет"
	}
	return "len" + itoa(len(s))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
