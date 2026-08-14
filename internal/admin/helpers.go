package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// pageSize: размер страницы для всех постраничных списков админки.
const pageSize = 50

// parsePage читает номер страницы из query (1-based, минимум 1).
func parsePage(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// totalPages считает число страниц по общему количеству записей.
func totalPages(total int) int {
	if total <= 0 {
		return 1
	}
	return (total + pageSize - 1) / pageSize
}

// pagination: данные для partial-шаблона "pagination": путь текущей
// страницы и её query без параметра page, чтобы ссылки Prev/Next сохраняли
// остальные фильтры списка.
type pagination struct {
	Path       string
	Query      string
	Page       int
	TotalPages int
}

func newPagination(r *http.Request, page, total int) pagination {
	return pagination{
		Path:       r.URL.Path,
		Query:      queryWithout(r, "page").Encode(),
		Page:       page,
		TotalPages: totalPages(total),
	}
}

// parseLocalDateTime разбирает значение <input type="datetime-local">.
// Пустая строка или ошибка разбора дают нулевое время: фильтр по нему
// не применяется.
func parseLocalDateTime(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04", v, time.Local); err == nil {
		return t
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04:05", v, time.Local); err == nil {
		return t
	}
	return time.Time{}
}

// formatLocalDateTime переводит время обратно в формат поля datetime-local,
// чтобы после отправки фильтра его значения остались в форме.
func formatLocalDateTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format("2006-01-02T15:04")
}

// queryWithout возвращает текущий query запроса без перечисленных ключей:
// используется, чтобы ссылки пагинации сохраняли остальные фильтры.
func queryWithout(r *http.Request, drop ...string) url.Values {
	q := r.URL.Query()
	out := url.Values{}
	for k, vs := range q {
		skip := false
		for _, d := range drop {
			if k == d {
				skip = true
				break
			}
		}
		if !skip {
			out[k] = vs
		}
	}
	return out
}

// currentURL: путь с полным текущим query, используется как «вернуться сюда»
// в формах быстрых действий (блокировка из строки журнала и т.п.).
func currentURL(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}
	return r.URL.Path + "?" + r.URL.RawQuery
}
