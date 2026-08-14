package webhooks

import (
	"net"
	"net/http"
	"time"
)

// Пакет store не экспортирует свои мелкие хелперы (nowUnix, truncate,
// boolInt, unixTime): они private. Дублируем их здесь в миниатюре, как это
// уже сделано в internal/rules, вместо того чтобы тянуть store вширь ради
// пары функций.

func nowUnix() int64 { return time.Now().Unix() }

// unixTime переводит unix-секунды во время; ноль означает «не задано».
func unixTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// truncate обрезает строку до n рун: колонки в базе ограничены по длине.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// boolInt переводит флаг в число для колонок INTEGER.
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// clientIP берёт адрес из RemoteAddr без разбора заголовков вроде
// X-Forwarded-For. Доверенные прокси и их сети настраивает слой, который
// монтирует Handler в общий мультиплексор, а не этот пакет (тот же принцип,
// что и в internal/chat).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
