package proxy

import (
	"encoding/base64"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// forwardedHeaders - единственные заголовки ответа подписки, которые
// прослойка пробрасывает клиенту. Список закрытый и намеренно короткий:
// всё остальное (ETag, Date, Server, куки апстрима и т.п.) до клиента
// доходить не должно, это и есть основная защита от прилипания старой
// подписки через условные запросы (см. stripConditionalRequest/Response).
var forwardedHeaders = []string{
	"Profile-Title",
	"Support-Url",
	"Profile-Update-Interval",
	"Profile-Web-Page-Url",
	"Subscription-Userinfo",
	"Announce",
	"Announce-Url",
	"Content-Disposition",
	"Content-Type",
}

// copyAllowedHeaders переносит из src в dst только заголовки из
// forwardedHeaders. http.Header сам приводит имена к канонической форме,
// поэтому регистр исходных заголовков значения не имеет.
func copyAllowedHeaders(dst, src http.Header) {
	for _, name := range forwardedHeaders {
		if v := src.Get(name); v != "" {
			dst.Set(name, v)
		}
	}
}

// hopByHopHeaders - заголовки одного TCP-хопа, которые reverse-proxy не
// должен пробрасывать дальше (RFC 7230 6.1). Host сюда же: реальный Host
// для исходящего запроса берётся из URL цели, а не из запроса клиента.
var hopByHopHeaders = []string{
	"Host", "Connection", "Keep-Alive", "Proxy-Connection",
	"Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// cloneForwardHeaders копирует заголовки клиента для исходящего запроса
// (в mirror-режиме - к origin, в panel-режиме - как подсказку панели),
// вычищая hop-by-hop заголовки.
func cloneForwardHeaders(src http.Header) http.Header {
	dst := src.Clone()
	if dst == nil {
		dst = http.Header{}
	}
	for _, h := range hopByHopHeaders {
		dst.Del(h)
	}
	return dst
}

// stripConditionalRequest убирает заголовки условного запроса перед
// отправкой апстриму. Если этого не сделать, апстрим может ответить 304 на
// If-None-Match клиента, и тогда прослойка не увидит тело для проверки
// блокировок/срока действия, а клиент продолжит показывать то, что у него
// уже закэшировано локально - подписка «залипнет» на устройстве.
func stripConditionalRequest(h http.Header) {
	h.Del("If-None-Match")
	h.Del("If-Modified-Since")
}

// stripAcceptEncoding убирает Accept-Encoding клиента перед отправкой
// апстриму - по той же причине, что стрижём условные заголовки в
// stripConditionalRequest, только для другого класса поломки.
//
// http.Transport в Go сам добавляет "Accept-Encoding: gzip" и прозрачно
// разжимает ответ, НО только если вызывающий код не выставил этот заголовок
// сам. Если оставить значение клиента как есть (а мобильные клиенты и
// браузеры почти всегда шлют Accept-Encoding: gzip), апстрим сжимает
// ответ, транспорт считает, что распаковку взял на себя вызывающий код, и
// отдаёт сырые gzip-байты как есть. В белом списке заголовков ответа
// (см. forwardedHeaders) нет Content-Encoding, поэтому клиент получает
// нечитаемое сжатое тело без единого заголовка, объясняющего, что с ним
// делать. Без Accept-Encoding в исходящем запросе Go либо не встретит
// сжатия вовсе, либо разожмёт его сам до того, как тело попадёт к нам.
func stripAcceptEncoding(h http.Header) {
	h.Del("Accept-Encoding")
}

// stripCachingResponse убирает из ответа клиенту заголовки, по которым он
// мог бы в следующий раз сделать условный запрос. Без этого шага цепочка
// защиты из stripConditionalRequest не имеет смысла: клиент всё равно
// получит ETag и на следующем заходе пришлёт If-None-Match сам.
func stripCachingResponse(h http.Header) {
	h.Del("ETag")
	h.Del("Last-Modified")
}

// appendForwardedFor добавляет реальный IP клиента в X-Forwarded-For перед
// походом к origin в mirror-режиме, чтобы у origin была настоящая картина,
// а не адрес самой прослойки на каждый запрос.
func appendForwardedFor(h http.Header, ip string) {
	if ip == "" {
		return
	}
	if prior := h.Get("X-Forwarded-For"); prior != "" {
		h.Set("X-Forwarded-For", prior+", "+ip)
	} else {
		h.Set("X-Forwarded-For", ip)
	}
	if h.Get("X-Real-Ip") == "" {
		h.Set("X-Real-Ip", ip)
	}
}

// clientIP определяет адрес клиента. Заголовкам X-Forwarded-For/X-Real-IP
// верим только если trustProxy включён (запрос действительно приходит
// через известный обратный прокси) - иначе их легко подделать напрямую.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := xff
			if idx := strings.IndexByte(xff, ','); idx >= 0 {
				first = xff[:idx]
			}
			if ip := strings.TrimSpace(first); ip != "" {
				return ip
			}
		}
		if ri := strings.TrimSpace(r.Header.Get("X-Real-IP")); ri != "" {
			return ri
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// parseUserInfo разбирает заголовок subscription-userinfo вида
// "upload=1;download=2;total=3;expire=4". Неизвестные поля и мусор
// пропускаются молча: формат этого заголовка нигде формально не
// стандартизован, разные панели допускают вариации в пробелах.
func parseUserInfo(v string) model.UserInfo {
	var info model.UserInfo
	if v == "" {
		return info
	}
	for _, part := range strings.Split(v, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64)
		if err != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(kv[0])) {
		case "upload":
			info.Upload = n
		case "download":
			info.Download = n
		case "total":
			info.Total = n
		case "expire":
			info.Expire = n
		}
	}
	return info
}

// encodeProfileTitle кодирует заголовок profile-title по конвенции,
// принятой в экосистеме клиентов подписки (Happ, v2rayNG, NekoBox и
// другие): значение с префиксом "base64:" считается base64 от UTF-8
// строки. Так в заголовке можно передать кириллицу - сами HTTP-заголовки
// требуют ASCII, а «Подписка заблокирована» без кодирования туда не влезет.
func encodeProfileTitle(title string) string {
	return "base64:" + base64.StdEncoding.EncodeToString([]byte(title))
}
