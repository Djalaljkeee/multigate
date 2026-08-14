// Package remnawave: HTTP-клиент к API панели Remnawave.
//
// Панель существует в двух линейках, несовместимых по идентификатору
// пользователя: 2.x адресует пользователя строковым uuid, а 3.x адресует числовым id.
// Пакет прячет это отличие внутри себя: наружу отдаётся только
// model.PanelUser.Ref, уже готовый для подстановки в следующий запрос
// к этой же панели. Вызывающему коду (store, admin, proxy) версия панели
// не важна.
package remnawave

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// ErrNotFound возвращается, когда панель ответила 404: пользователя,
// устройства или другого ресурса по такому ref не существует.
// Оборачивает общий сентинел: ядро прокси проверяет именно его, чтобы
// отличить «такого пользователя нет» (404 клиенту) от «панель не отвечает» (502).
var ErrNotFound = fmt.Errorf("remnawave: не найдено: %w", model.ErrNotFound)

// ErrUnauthorized возвращается на 401/403: панель не приняла токен.
var ErrUnauthorized = errors.New("remnawave: токен не принят")

const (
	defaultTimeout = 15 * time.Second

	// maxRetries: сколько раз повторить идемпотентный GET сверх первой
	// попытки. PATCH и POST не ретраятся никогда: reset-traffic или
	// удаление устройства, повторённые вслепую, могут применить эффект дважды.
	maxRetries     = 2
	retryBaseDelay = 200 * time.Millisecond

	// defaultMaxBody: предел на обычные ответы API (списки пользователей
	// и устройств могут быть большими, но не безграничными).
	defaultMaxBody int64 = 16 << 20
	// maxSubBodyBytes: отдельный, более жёсткий предел для тела публичной
	// подписки: этот путь не защищён токеном и виден извне.
	maxSubBodyBytes int64 = 8 << 20

	infoCacheTTL = 5 * time.Minute
)

// Options: параметры подключения к панели.
type Options struct {
	BaseURL   string        // http://remnawave:3000 или https://panel.example.com
	Token     string        // токен API панели
	Timeout   time.Duration // по умолчанию 15s
	UserAgent string
	Logger    *slog.Logger
}

// Client: клиент к API панели Remnawave. Держит один пул соединений и
// кэш версии панели, безопасен для параллельного использования из многих
// горутин (каждый запрос подписки обслуживается своей горутиной).
type Client struct {
	base  *url.URL
	token string
	ua    string
	log   *slog.Logger
	hc    *http.Client

	infoMu   sync.RWMutex
	info     model.PanelInfo
	updating sync.Mutex // не даёт параллельным запросам одновременно перевыяснять версию панели
}

// New создаёt клиент. Сеть на этом шаге не трогается: соединения открываются
// лениво, при первом реальном вызове.
func New(opts Options) (*Client, error) {
	raw := strings.TrimSpace(opts.BaseURL)
	if raw == "" {
		return nil, errors.New("remnawave: не задан адрес панели")
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("remnawave: не разобрать адрес панели %q", raw)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	log := opts.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	ua := strings.TrimSpace(opts.UserAgent)
	if ua == "" {
		ua = "multigate-remnawave-client"
	}

	c := &Client{
		base:  u,
		token: opts.Token,
		ua:    ua,
		log:   log,
		hc: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        64,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
	return c, nil
}

// apiResult: сырой результат одного HTTP-вызова панели.
type apiResult struct {
	status  int
	headers http.Header
	body    []byte
}

// doRequest выполняет один HTTP-запрос к API панели без ретраев.
// auth=true добавляет заголовок Authorization; extra позволяет докинуть
// или подменить заголовки поверх стандартных (нужно Subscription, чтобы
// пробросить заголовки клиента подписки как есть).
func (c *Client) doRequest(ctx context.Context, method, path string, query url.Values, body io.Reader, auth bool, extra http.Header, maxBody int64) (apiResult, error) {
	u := *c.base
	u.Path = c.base.Path + path
	if query != nil {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return apiResult{}, fmt.Errorf("remnawave: собрать запрос %s %s: %w", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Заголовки клиента подписки заменяют наши по умолчанию, а не дописываются
	// к ним: два значения User-Agent в одном запросе панель поймёт хуже, чем ни одного.
	for k, vv := range extra {
		if len(vv) == 0 {
			continue
		}
		req.Header.Del(k)
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.ua)
	}
	if auth && c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	start := time.Now()
	resp, err := c.hc.Do(req)
	if err != nil {
		// Текст ошибки http-клиента может содержать URL запроса, но не заголовки:
		// токен туда не попадает, он живёт только в Authorization.
		return apiResult{}, fmt.Errorf("remnawave: запрос %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return apiResult{}, fmt.Errorf("remnawave: прочитать ответ %s %s: %w", method, path, err)
	}

	c.log.DebugContext(ctx, "remnawave: запрос выполнен",
		"method", method, "path", path, "status", resp.StatusCode, "dur", time.Since(start))

	return apiResult{status: resp.StatusCode, headers: resp.Header, body: data}, nil
}

// getRaw выполняет GET с ретраями: до maxRetries повторов при сетевых сбоях,
// 5xx и 429. Остальные статусы (в т.ч. 404, 401/403) возвращаются сразу:
// повтор того же запроса их не исправит.
func (c *Client) getRaw(ctx context.Context, path string, query url.Values, auth bool, extra http.Header, maxBody int64) (apiResult, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := retryBaseDelay * time.Duration(int64(1)<<uint(attempt-1))
			select {
			case <-ctx.Done():
				return apiResult{}, ctx.Err()
			case <-time.After(delay):
			}
		}

		res, err := c.doRequest(ctx, http.MethodGet, path, query, nil, auth, extra, maxBody)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return apiResult{}, err
			}
			c.log.WarnContext(ctx, "remnawave: сбой запроса, повторяю", "path", path, "attempt", attempt, "err", err)
			continue
		}
		if res.status >= http.StatusInternalServerError || res.status == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("remnawave: %s ответил %d", path, res.status)
			continue
		}
		return res, nil
	}
	return apiResult{}, lastErr
}

// getJSON делает GET, разворачивает конверт {"response": ...} (или голый
// объект) и раскладывает результат в out. out==nil, если тело не нужно,
// достаточно факта успешного ответа.
func (c *Client) getJSON(ctx context.Context, path string, query url.Values, auth bool, out any) (apiResult, error) {
	res, err := c.getRaw(ctx, path, query, auth, nil, defaultMaxBody)
	if err != nil {
		return apiResult{}, err
	}
	if res.status < 200 || res.status >= 300 {
		return res, apiErr(http.MethodGet, path, res)
	}
	if err := decodeInto(res.body, out); err != nil {
		return res, fmt.Errorf("remnawave: разобрать ответ %s: %w", path, err)
	}
	return res, nil
}

// writeJSON делает PATCH/POST без ретраев. payload==nil отправляет запрос
// без тела (например, actions/reset-traffic).
func (c *Client) writeJSON(ctx context.Context, method, path string, payload, out any) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("remnawave: собрать тело %s %s: %w", method, path, err)
		}
		body = bytes.NewReader(data)
	}

	res, err := c.doRequest(ctx, method, path, nil, body, true, nil, defaultMaxBody)
	if err != nil {
		return err
	}
	if res.status < 200 || res.status >= 300 {
		return apiErr(method, path, res)
	}
	if out != nil {
		if err := decodeInto(res.body, out); err != nil {
			return fmt.Errorf("remnawave: разобрать ответ %s %s: %w", method, path, err)
		}
	}
	return nil
}

// decodeInto разворачивает конверт {"response": ...}, в который Remnawave
// обычно заворачивает успешные ответы, и раскладывает результат в out.
// Голый объект (без конверта) тоже поддержан: так проще переживать
// изменения формата ответа между версиями панели.
func decodeInto(body []byte, out any) error {
	if out == nil || len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var env struct {
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(body, &env); err == nil && len(env.Response) > 0 {
		return json.Unmarshal(env.Response, out)
	}
	return json.Unmarshal(body, out)
}

// apiErr превращает неуспешный HTTP-ответ в ошибку пакета. 401/403 и 404
// сворачиваются в sentinel-ошибки (проверяются через errors.Is), остальное
// идёт с текстом, который панель прислала в теле. Токен в тело панель не
// возвращает, поэтому он в ошибку попасть не может.
func apiErr(method, path string, res apiResult) error {
	msg := extractMessage(res.body)
	switch res.status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("remnawave: %s %s: %w (%s)", method, path, ErrUnauthorized, msg)
	case http.StatusNotFound:
		return fmt.Errorf("remnawave: %s %s: %w (%s)", method, path, ErrNotFound, msg)
	default:
		return fmt.Errorf("remnawave: %s %s: панель ответила %d (%s)", method, path, res.status, msg)
	}
}

// extractMessage вытаскивает человеко-читаемый текст из тела ошибки Nest-style
// API: {"message": "...", "error": "..."}. message бывает и строкой, и
// массивом строк (так формируются ошибки валидации), поддерживаем оба вида.
func extractMessage(body []byte) string {
	var e struct {
		Message json.RawMessage `json:"message"`
		Error   string          `json:"error"`
	}
	if err := json.Unmarshal(body, &e); err == nil {
		if len(e.Message) > 0 {
			var s string
			if json.Unmarshal(e.Message, &s) == nil && s != "" {
				return s
			}
			var arr []string
			if json.Unmarshal(e.Message, &arr) == nil && len(arr) > 0 {
				return strings.Join(arr, "; ")
			}
		}
		if e.Error != "" {
			return e.Error
		}
	}
	const maxSnippet = 200
	s := strings.TrimSpace(string(body))
	if len(s) > maxSnippet {
		s = s[:maxSnippet] + "…"
	}
	if s == "" {
		s = "пустой ответ"
	}
	return s
}
