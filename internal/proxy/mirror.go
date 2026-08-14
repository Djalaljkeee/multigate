package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/store"
)

// fetchMirror проксирует запрос на внешний домен панели (store.KeyMirrorTarget),
// сохраняя путь и query исходного запроса, - обычный обратный прокси поверх
// h.deps.HTTPClient. Формат ответа заранее неизвестен, поэтому
// upstream.format остаётся model.FormatUnknown: его дальше уточняет вызывающая
// сторона по суффиксу пути или ядру клиента.
func (h *Handler) fetchMirror(ctx context.Context, r *http.Request, ip string) (upstream, error) {
	target := strings.TrimSpace(h.deps.Store.Get(ctx, store.KeyMirrorTarget))
	if target == "" {
		return upstream{}, errors.New("proxy: режим mirror, но mirror_target не настроен")
	}
	base, err := url.Parse(ensureScheme(target))
	if err != nil || base.Host == "" {
		return upstream{}, fmt.Errorf("proxy: не разобрать mirror_target %q: %w", target, err)
	}

	dst := *r.URL
	dst.Scheme = base.Scheme
	dst.Host = base.Host

	outReq, err := http.NewRequestWithContext(ctx, r.Method, dst.String(), nil)
	if err != nil {
		return upstream{}, err
	}
	outReq.Header = cloneForwardHeaders(r.Header)
	stripConditionalRequest(outReq.Header)
	stripAcceptEncoding(outReq.Header)
	appendForwardedFor(outReq.Header, ip)

	resp, err := h.deps.HTTPClient.Do(outReq)
	if err != nil {
		return upstream{}, err
	}
	defer resp.Body.Close()

	body, err := readLimited(resp.Body)
	if err != nil {
		return upstream{}, err
	}
	return upstream{
		status: resp.StatusCode,
		header: resp.Header.Clone(),
		body:   body,
	}, nil
}

// ensureScheme дополняет адрес схемой по умолчанию, если админ в настройках
// указал голый домен без "https://".
func ensureScheme(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	return "https://" + target
}
