// Package rules подменяет заголовки ответа подписки под конкретное
// клиентское приложение: часть клиентов capризна к формату служебных
// заголовков (profile-title, support-url и т.п.), и админ может завести
// точечное правило вместо правки кода.
package rules

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// ruleTTL - как долго держим правила в памяти между перечитываниями базы.
// Правила меняют из админки редко, а Apply вызывается на каждом запросе
// подписки, поэтому короткий TTL с явной инвалидацией при записи, тот же
// приём, что и у settingsCache в store.
const ruleTTL = 30 * time.Second

type cacheEntry struct {
	val []model.HeaderRule
	at  time.Time
}

// Кэш держим по каждому *store.DB отдельно (не глобальной переменной на
// процесс): так тесты, открывающие свою базу, не видят чужой кэш, а на
// проде инстанс *store.DB один на весь процесс, и разницы нет.
var (
	cacheMu sync.RWMutex
	caches  = map[*store.DB]cacheEntry{}
)

// Load отдаёт список правил, подставляя значения из кэша, если он ещё
// свежий. Порядок элементов - как в базе (по id); сортировку по приоритету
// делает Apply.
func Load(ctx context.Context, db *store.DB) ([]model.HeaderRule, error) {
	cacheMu.RLock()
	e, ok := caches[db]
	cacheMu.RUnlock()
	if ok && time.Since(e.at) < ruleTTL {
		return e.val, nil
	}

	rows, err := db.RO().QueryContext(ctx, `SELECT id, name, enabled, priority,
		match_app, match_os, COALESCE(match_ua, ''), ua_regex,
		COALESCE(set_headers, ''), COALESCE(del_headers, ''), created_at
		FROM header_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.HeaderRule
	for rows.Next() {
		var (
			r                model.HeaderRule
			enabled, uaRegex int
			setJSON, delJSON string
			created          int64
		)
		if err := rows.Scan(&r.ID, &r.Name, &enabled, &r.Priority,
			&r.MatchApp, &r.MatchOS, &r.MatchUA, &uaRegex,
			&setJSON, &delJSON, &created); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		r.UARegex = uaRegex != 0
		r.CreatedAt = unixTime(created)
		if setJSON != "" {
			if err := json.Unmarshal([]byte(setJSON), &r.SetHeader); err != nil {
				slog.Default().Warn("rules: не разобрать set_headers, пропускаю поле",
					"rule_id", r.ID, "err", err)
			}
		}
		if delJSON != "" {
			if err := json.Unmarshal([]byte(delJSON), &r.DelHeader); err != nil {
				slog.Default().Warn("rules: не разобрать del_headers, пропускаю поле",
					"rule_id", r.ID, "err", err)
			}
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	cacheMu.Lock()
	caches[db] = cacheEntry{val: out, at: time.Now()}
	cacheMu.Unlock()
	return out, nil
}

// Apply применяет к заголовкам ответа h все правила из rulesList, которые
// подходят клиенту c. Правило подходит, если ВСЕ заданные в нём условия
// совпали; пустое условие означает «любое значение».
//
// Порядок применения - по возрастанию Priority (значение по умолчанию у
// новых правил - 100). При конфликте по одному и тому же заголовку
// побеждает правило с БОЛЬШИМ приоритетом: оно применяется позже и
// перезаписывает то, что выставило более раннее правило. Внутри одного
// правила del_headers применяется раньше set_headers, поэтому если один и
// тот же заголовок упомянут в обоих списках, в итоге он будет установлен,
// а не удалён.
//
// Отключённые правила (Enabled=false) пропускаются. Правило с невалидным
// регулярным выражением в UA не совпадает ни с чем - обработку запроса это
// не останавливает.
func Apply(rulesList []model.HeaderRule, c model.Client, h http.Header) {
	if len(rulesList) == 0 || h == nil {
		return
	}

	ordered := make([]model.HeaderRule, len(rulesList))
	copy(ordered, rulesList)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority < ordered[j].Priority
		}
		return ordered[i].ID < ordered[j].ID
	})

	for _, r := range ordered {
		if !r.Enabled {
			continue
		}
		if !matches(r, c) {
			continue
		}
		for _, name := range r.DelHeader {
			h.Del(name)
		}
		for name, val := range r.SetHeader {
			h.Set(name, val)
		}
	}
}

// matches проверяет, подходит ли правило клиенту.
func matches(r model.HeaderRule, c model.Client) bool {
	if r.MatchApp != "" && !strings.EqualFold(r.MatchApp, c.App) {
		return false
	}
	if r.MatchOS != "" && !strings.EqualFold(r.MatchOS, string(c.Platform)) {
		return false
	}
	if r.MatchUA == "" {
		return true
	}
	if r.UARegex {
		re, err := compileCached(r.MatchUA)
		if err != nil {
			// Невалидное выражение уже залогировано при первой попытке
			// компиляции в compileCached - здесь просто считаем, что
			// правило ни к чему не подходит.
			return false
		}
		return re.MatchString(c.UserAgent)
	}
	return strings.Contains(strings.ToLower(c.UserAgent), strings.ToLower(r.MatchUA))
}

// regexEntry - результат компиляции одного паттерна, успешный или нет.
// Кэшируем оба исхода: невалидный паттерн не должен пытаться
// перекомпилироваться на каждый запрос подписки.
type regexEntry struct {
	re  *regexp.Regexp
	err error
}

var reCache sync.Map // string -> *regexEntry

func compileCached(pattern string) (*regexp.Regexp, error) {
	if v, ok := reCache.Load(pattern); ok {
		e := v.(*regexEntry)
		return e.re, e.err
	}
	re, err := regexp.Compile(pattern)
	e := &regexEntry{re: re, err: err}
	actual, loaded := reCache.LoadOrStore(pattern, e)
	ae := actual.(*regexEntry)
	if !loaded && ae.err != nil {
		// Логируем один раз, при первой успешной записи в кэш: правило
		// сломано, но выдачу подписки это ронять не должно.
		slog.Default().Warn("rules: невалидное регулярное выражение в правиле, правило будет пропускаться",
			"pattern", pattern, "err", ae.err)
	}
	return ae.re, ae.err
}

// Save создаёт или обновляет правило (если r.ID != 0 - обновление) и
// сбрасывает кэш этой базы.
func Save(ctx context.Context, db *store.DB, r model.HeaderRule) (int64, error) {
	setJSON, err := marshalOrEmpty(r.SetHeader)
	if err != nil {
		return 0, err
	}
	delJSON, err := marshalOrEmpty(r.DelHeader)
	if err != nil {
		return 0, err
	}

	var id int64
	if r.ID != 0 {
		_, err = db.RW().ExecContext(ctx, `UPDATE header_rules SET
			name = ?, enabled = ?, priority = ?, match_app = ?, match_os = ?,
			match_ua = ?, ua_regex = ?, set_headers = ?, del_headers = ?
			WHERE id = ?`,
			r.Name, boolInt(r.Enabled), r.Priority, r.MatchApp, r.MatchOS,
			r.MatchUA, boolInt(r.UARegex), setJSON, delJSON, r.ID)
		id = r.ID
	} else {
		var res sql.Result
		res, err = db.RW().ExecContext(ctx, `INSERT INTO header_rules
			(name, enabled, priority, match_app, match_os, match_ua, ua_regex,
			 set_headers, del_headers, created_at)
			VALUES (?,?,?,?,?,?,?,?,?,?)`,
			r.Name, boolInt(r.Enabled), r.Priority, r.MatchApp, r.MatchOS,
			r.MatchUA, boolInt(r.UARegex), setJSON, delJSON, time.Now().Unix())
		if err == nil {
			id, err = res.LastInsertId()
		}
	}
	if err != nil {
		return 0, err
	}

	invalidate(db)
	return id, nil
}

// Delete удаляет правило по id и сбрасывает кэш этой базы.
func Delete(ctx context.Context, db *store.DB, id int64) error {
	if _, err := db.RW().ExecContext(ctx, "DELETE FROM header_rules WHERE id = ?", id); err != nil {
		return err
	}
	invalidate(db)
	return nil
}

func invalidate(db *store.DB) {
	cacheMu.Lock()
	delete(caches, db)
	cacheMu.Unlock()
}

func marshalOrEmpty(v any) (string, error) {
	if v == nil {
		return "", nil
	}
	switch t := v.(type) {
	case map[string]string:
		if len(t) == 0 {
			return "", nil
		}
	case []string:
		if len(t) == 0 {
			return "", nil
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// unixTime переводит unix-секунды во время; ноль означает «не задано».
// Свой маленький аналог store.unixTime: та функция не экспортирована.
func unixTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}
