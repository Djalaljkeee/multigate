package proxy

import (
	"context"
	"errors"
	"net/http"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// hdrFormatHint - собственный заголовок прослойки, которым path-суффикс
// (/clash, /singbox) передаётся в реализацию Panel. Контракт
// Panel.Subscription принимает только shortUUID и заголовки запроса, без
// отдельного параметра формата, поэтому суффикс пути, если он был,
// прокидывается именно так. Реализация панели вольна как использовать эту
// подсказку, так и определять формат сама по User-Agent - это на её
// усмотрение.
const hdrFormatHint = "X-Multigate-Sub-Format"

// fetchPanel получает подписку через d.Panel.Subscription. reqHeader - это
// заголовки исходного запроса клиента; они прокидываются панели как
// подсказка (например, для эмуляции формата под конкретный User-Agent).
func (h *Handler) fetchPanel(ctx context.Context, shortUUID, suffix string, reqHeader http.Header) (upstream, error) {
	if h.deps.Panel == nil {
		return upstream{}, errors.New("proxy: режим panel, но Panel не настроен")
	}

	in := cloneForwardHeaders(reqHeader)
	stripConditionalRequest(in)
	stripAcceptEncoding(in)
	if f := formatFromSuffix(suffix); f != model.FormatUnknown {
		in.Set(hdrFormatHint, string(f))
	}

	resp, err := h.deps.Panel.Subscription(ctx, shortUUID, in)
	if err != nil {
		return upstream{}, err
	}
	if resp == nil {
		return upstream{}, errors.New("proxy: панель вернула пустой ответ подписки")
	}

	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	return upstream{
		status: status,
		header: headerFromMap(resp.Headers),
		body:   resp.Body,
		format: resp.Format,
	}, nil
}

// headerFromMap строит http.Header из плоской карты SubResponse.Headers.
func headerFromMap(m map[string]string) http.Header {
	h := make(http.Header, len(m))
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}
