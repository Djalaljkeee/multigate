package proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// cacheKey складывает ключ короткого кэша ответа подписки из shortUuid,
// ядра клиента и формата: разным клиентам одного пользователя (xray и
// sing-box, например) нужны разные тела ответа, общий ключ их бы перепутал.
func cacheKey(shortUUID string, core model.Core, format model.Format) string {
	return shortUUID + "|" + string(core) + "|" + string(format)
}

type cachedResponse struct {
	status  int
	headers http.Header
	body    []byte
}

// cacheGet ищет свежую запись в sub_cache. Таблица уже есть в схеме store,
// готового метода для неё store не даёт, поэтому читаем напрямую через
// RO() - тот же приём, что и в пакете hwid для request_log.
func (h *Handler) cacheGet(ctx context.Context, key string) (cachedResponse, bool) {
	var (
		status               int
		bodyB64, headersJSON string
		expiresAt            int64
	)
	row := h.deps.Store.RO().QueryRowContext(ctx,
		"SELECT status, body, headers, expires_at FROM sub_cache WHERE cache_key = ?", key)
	if err := row.Scan(&status, &bodyB64, &headersJSON, &expiresAt); err != nil {
		return cachedResponse{}, false
	}
	if expiresAt <= time.Now().Unix() {
		return cachedResponse{}, false
	}

	body, err := base64.StdEncoding.DecodeString(bodyB64)
	if err != nil {
		return cachedResponse{}, false
	}
	hdr := http.Header{}
	if headersJSON != "" {
		var plain map[string]string
		if err := json.Unmarshal([]byte(headersJSON), &plain); err == nil {
			for k, v := range plain {
				hdr.Set(k, v)
			}
		}
	}
	return cachedResponse{status: status, headers: hdr, body: body}, true
}

// cacheSet сохраняет ответ на ttl. Тело хранится в base64: колонка body
// текстовая, а тело апстрима не гарантированно валидный UTF-8, - это
// защита от порчи данных на MySQL с его строгим utf8mb4.
//
// Кэшируется только заведомо безопасный набор заголовков (forwardedHeaders):
// если когда-нибудь список расширится, в кэше не окажется лишнего мусора
// из внутренних заголовков апстрима.
func (h *Handler) cacheSet(ctx context.Context, key string, status int, src http.Header, body []byte, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	plain := make(map[string]string, len(forwardedHeaders))
	for _, name := range forwardedHeaders {
		if v := src.Get(name); v != "" {
			plain[name] = v
		}
	}
	headersJSON, err := json.Marshal(plain)
	if err != nil {
		h.deps.Logger.Warn("proxy: не сериализовать заголовки для кэша", "err", err)
		return
	}
	bodyB64 := base64.StdEncoding.EncodeToString(body)

	now := time.Now()
	var q string
	switch h.deps.Store.Dialect() {
	case store.DialectMySQL:
		q = `INSERT INTO sub_cache (cache_key, body, headers, status, stored_at, expires_at) VALUES (?,?,?,?,?,?)
			ON DUPLICATE KEY UPDATE body=VALUES(body), headers=VALUES(headers), status=VALUES(status),
				stored_at=VALUES(stored_at), expires_at=VALUES(expires_at)`
	default:
		q = `INSERT INTO sub_cache (cache_key, body, headers, status, stored_at, expires_at) VALUES (?,?,?,?,?,?)
			ON CONFLICT(cache_key) DO UPDATE SET body=excluded.body, headers=excluded.headers, status=excluded.status,
				stored_at=excluded.stored_at, expires_at=excluded.expires_at`
	}
	if _, err := h.deps.Store.RW().ExecContext(ctx, q, key, bodyB64, string(headersJSON),
		status, now.Unix(), now.Add(ttl).Unix()); err != nil {
		h.deps.Logger.Warn("proxy: не записать кэш подписки", "err", err)
	}
}
