package chat

import "time"

// Пакет store не экспортирует свои мелкие хелперы: они private.
// Дублируем нужные здесь в миниатюре, как это уже сделано в internal/rules
// и internal/webhooks, вместо того чтобы тянуть store вширь ради пары функций.

func nowUnix() int64 { return time.Now().Unix() }

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
