package legacy

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

const (
	// hitTTL: сколько помнить соответствие «токен Marzban -> shortUuid».
	// shortUuid меняется только при перевыпуске ссылки в панели, а клиенты
	// тянут подписку раз в час-другой: без кэша каждый такой запрос стоил бы
	// лишнего похода в панель.
	hitTTL = 10 * time.Minute
	// missTTL: сколько помнить, что пользователя из токена в панели нет.
	// Короче, чем hitTTL: пользователя могут завести заново.
	missTTL = time.Minute
	// maxEntries: предел кэша. Перебор токенов с верной подписью невозможен
	// без секрета, так что кэш растёт только на реальных клиентах; предел
	// нужен на всякий случай и сбрасывает кэш целиком.
	maxEntries = 50000
)

// UserLookup: то, что резолверу нужно от панели.
type UserLookup interface {
	UserByUsername(ctx context.Context, username string) (model.PanelUser, error)
}

type entry struct {
	shortUUID string // пусто: пользователя нет
	until     time.Time
}

// Resolver переводит старую ссылку Marzban в текущий shortUuid пользователя.
type Resolver struct {
	db    *store.DB
	panel UserLookup
	log   *slog.Logger

	mu    sync.Mutex
	cache map[string]entry
}

// NewResolver собирает резолвер. Секреты читаются из настроек на каждый
// запрос (настройки и так кэшируются в памяти), поэтому правка в админке
// действует сразу.
func NewResolver(db *store.DB, panel UserLookup, log *slog.Logger) *Resolver {
	if log == nil {
		log = slog.Default()
	}
	return &Resolver{db: db, panel: panel, log: log, cache: map[string]entry{}}
}

// Resolve возвращает текущий shortUuid пользователя, если token: проверенная
// ссылка Marzban, а пользователь есть в панели. ok=false значит «это не
// старая ссылка или пользователя нет»: запрос тогда идёт дальше как обычно.
func (r *Resolver) Resolve(ctx context.Context, token string) (string, bool) {
	if r == nil || r.panel == nil {
		return "", false
	}
	keys := ParseKeys(r.db.Get(ctx, store.KeyMarzbanLegacyKeys))
	if len(keys) == 0 {
		return "", false
	}

	now := time.Now()
	r.mu.Lock()
	e, found := r.cache[token]
	r.mu.Unlock()
	if found && now.Before(e.until) {
		return e.shortUUID, e.shortUUID != ""
	}

	t, ok := Decode(token, keys)
	if !ok {
		return "", false
	}

	u, err := r.panel.UserByUsername(ctx, t.Username)
	switch {
	case err == nil && u.ShortUUID != "":
		r.remember(token, entry{shortUUID: u.ShortUUID, until: now.Add(hitTTL)})
		return u.ShortUUID, true
	case err == nil || errors.Is(err, model.ErrNotFound):
		r.log.Info("legacy: пользователь из ссылки Marzban не найден в панели", "username", t.Username)
		r.remember(token, entry{until: now.Add(missTTL)})
		return "", false
	default:
		// Панель недоступна: ничего не запоминаем, следующий запрос
		// попробует снова.
		r.log.Warn("legacy: не найти пользователя из ссылки Marzban", "username", t.Username, "err", err)
		return "", false
	}
}

func (r *Resolver) remember(token string, e entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= maxEntries {
		r.cache = map[string]entry{}
	}
	r.cache[token] = e
}
