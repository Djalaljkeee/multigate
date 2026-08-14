package store

import (
	"strings"
	"time"
)

// nowUnix: текущее время в секундах. Время в базе хранится числом:
// так одинаково ведут себя SQLite и MySQL и не путаются часовые пояса.
func nowUnix() int64 { return time.Now().Unix() }

// unixTime переводит секунды в время; ноль означает «не задано».
func unixTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

// timeUnix переводит время в секунды; нулевое время даёт 0.
func timeUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// isDuplicateIndex распознаёт ошибку MySQL «такой индекс уже есть» (1061).
func isDuplicateIndex(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "duplicate key name") || strings.Contains(s, "error 1061")
}

// truncate обрезает строку до n символов: колонки журналов ограничены по длине,
// а User-Agent у некоторых клиентов бывает неприлично длинным.
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
