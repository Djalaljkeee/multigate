package remnawave

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// forwardedSubHeaders: заголовки клиента подписки, которые пробрасываются
// панели как есть: по ним она определяет платформу и отдаёт нужный формат
// (base64/clash/sing-box) и правильные значения subscription-userinfo.
//
// Accept-Encoding сюда сознательно НЕ входит: если пробросить значение
// клиента как есть, наш HTTP-транспорт решит, что распаковку ответа взял на
// себя вызывающий код, и перестанет сам разжимать gzip от панели. Тело тогда
// уйдёт клиенту сжатым, а Content-Encoding мы клиенту не пробрасываем (его
// нет в белом списке internal/proxy/headers.go) - в итоге клиент получает
// нечитаемый бинарный мусор вместо подписки. Без этого заголовка в запросе
// Go либо не получит от панели сжатый ответ вовсе, либо разожмёт его сам.
var forwardedSubHeaders = map[string]bool{
	"user-agent":       true,
	"accept":           true,
	"x-requested-with": true,
}

// hdrFormatHint: заголовок, которым ядро прослойки сообщает запрошенный
// формат подписки. Имя должно совпадать с тем, что ставит internal/proxy.
const hdrFormatHint = "x-multigate-sub-format"

// subPathSuffix переводит имя формата в хвост пути, который понимает панель.
// Неизвестные значения отбрасываются: лучше отдать базовый формат,
// чем получить от панели ошибку на выдуманном пути.
func subPathSuffix(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "clash", "clashmeta", "clash-meta", "mihomo":
		return "clash"
	case "singbox", "sing-box":
		return "singbox"
	case "outline":
		return "outline"
	case "base64", "plain", "":
		return ""
	default:
		return ""
	}
}

// Subscription запрашивает у панели тело подписки БЕЗ токена авторизации:
// это тот же публичный маршрут, что дергают клиентские приложения и браузер
// напрямую. in: заголовки исходного запроса клиента; часть из них (User-Agent
// и специфичные x-* от приложений) прокидывается панели без изменений,
// а служебные заголовки самого HTTP-соединения (Host, Cookie и т.п.) не пробрасываются.
//
// Статус и тело возвращаются как есть, без интерпретации: решает, что с ними
// делать (в т.ч. как воспринимать 404), вызывающий код.
func (c *Client) Subscription(ctx context.Context, shortUUID string, in http.Header) (*model.SubResponse, error) {
	shortUUID = strings.TrimSpace(shortUUID)
	if shortUUID == "" {
		return nil, errors.New("remnawave: пустой shortUuid")
	}

	extra := make(http.Header)
	for k, vv := range in {
		lower := strings.ToLower(k)
		if lower == hdrFormatHint {
			// Служебный заголовок ядра прослойки, панели он не нужен.
			continue
		}
		if !forwardedSubHeaders[lower] && !strings.HasPrefix(lower, "x-") {
			continue
		}
		for _, v := range vv {
			extra.Add(k, v)
		}
	}

	// Формат подписки панель определяет по хвосту пути, а не по заголовку.
	// Ядро прослойки знает, какой формат просил клиент (он пришёл в пути вида
	// /{shortUuid}/clash), и сообщает его этим заголовком. Без переноса
	// в путь клиент на mihomo получал бы базовый формат вместо YAML.
	path := "/api/sub/" + url.PathEscape(shortUUID)
	if f := strings.TrimSpace(in.Get(hdrFormatHint)); f != "" {
		if suffix := subPathSuffix(f); suffix != "" {
			path += "/" + suffix
		}
	}

	res, err := c.getRaw(ctx, path, nil, false, extra, maxSubBodyBytes)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string, len(res.headers))
	for k, vv := range res.headers {
		if len(vv) > 0 {
			headers[k] = vv[0]
		}
	}

	return &model.SubResponse{
		Status:  res.status,
		Headers: headers,
		Body:    res.body,
		// Формат тела (base64/clash/sing-box/...) панель не сообщает отдельным
		// полем: его определяет пакет subfmt по Content-Type и содержимому.
		Format: model.FormatUnknown,
	}, nil
}
