package store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// ReqLogger: асинхронная запись журнала запросов.
//
// Журнал пишется на каждый запрос подписки, а SQLite умеет ровно одного
// писателя. Поэтому обработчик запроса не ходит в базу сам: он кладёт запись
// в буфер, а отдельная горутина сбрасывает их пачками. Если буфер переполнен,
// запись выбрасывается: журнал не должен задерживать выдачу подписки.
type ReqLogger struct {
	db    *DB
	ch    chan model.RequestLog
	done  chan struct{}
	once  sync.Once
	mu    sync.Mutex
	drops int64
}

// NewReqLogger запускает писателя журнала. Останавливается через Close.
func (d *DB) NewReqLogger(ctx context.Context) *ReqLogger {
	l := &ReqLogger{
		db:   d,
		ch:   make(chan model.RequestLog, 2048),
		done: make(chan struct{}),
	}
	go l.run(ctx)
	return l
}

// Add ставит запись в очередь. Не блокирует.
func (l *ReqLogger) Add(rec model.RequestLog) {
	if l == nil {
		return
	}
	if rec.At.IsZero() {
		rec.At = time.Now()
	}
	select {
	case l.ch <- rec:
	default:
		l.mu.Lock()
		l.drops++
		l.mu.Unlock()
	}
}

// Drops сообщает, сколько записей журнала было выброшено из-за переполнения.
// Это видно на вкладке «О системе» и означает, что база не успевает.
func (l *ReqLogger) Drops() int64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.drops
}

// Close дожидается сброса очереди.
func (l *ReqLogger) Close() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		close(l.ch)
		<-l.done
	})
}

func (l *ReqLogger) run(ctx context.Context) {
	defer close(l.done)

	const maxBatch = 128
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	batch := make([]model.RequestLog, 0, maxBatch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Собственный контекст: при остановке сервиса накопленное всё равно дописываем.
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_ = l.db.insertRequestLogs(wctx, batch)
		cancel()
		batch = batch[:0]
	}

	for {
		select {
		case rec, ok := <-l.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, rec)
			if len(batch) >= maxBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (d *DB) insertRequestLogs(ctx context.Context, recs []model.RequestLog) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := d.rw.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO request_log
		(at, short_uuid, username, ip, country, user_agent, app, app_version, platform, core,
		 hwid, format, decision, status, bytes, duration_ms, mode, err)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, r := range recs {
		if _, err := stmt.ExecContext(ctx,
			timeUnix(r.At), truncate(r.ShortUUID, 190), truncate(r.Username, 190),
			truncate(r.IP, 64), truncate(r.Country, 8), truncate(r.UserAgent, 500),
			truncate(r.App, 64), truncate(r.AppVersion, 64), truncate(r.Platform, 32),
			truncate(r.Core, 32), truncate(r.HWID, 190), truncate(r.Format, 32),
			truncate(r.Decision, 32), r.Status, r.Bytes, r.DurationMS,
			truncate(r.Mode, 16), truncate(r.Err, 500),
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// ReqLogFilter: набор фильтров журнала для админки.
type ReqLogFilter struct {
	ShortUUID string
	Username  string
	HWID      string
	IP        string
	App       string
	Decision  string
	Search    string // подстрока по User-Agent
	Since     time.Time
	Until     time.Time
	Limit     int
	Offset    int
}

// ListRequestLog отдаёт журнал по фильтру, свежие записи первыми.
func (d *DB) ListRequestLog(ctx context.Context, f ReqLogFilter) ([]model.RequestLog, int, error) {
	var (
		where []string
		args  []any
	)
	add := func(cond string, v any) {
		where = append(where, cond)
		args = append(args, v)
	}
	if f.ShortUUID != "" {
		add("short_uuid = ?", f.ShortUUID)
	}
	if f.Username != "" {
		add("username = ?", f.Username)
	}
	if f.HWID != "" {
		add("hwid = ?", f.HWID)
	}
	if f.IP != "" {
		add("ip = ?", f.IP)
	}
	if f.App != "" {
		add("app = ?", f.App)
	}
	if f.Decision != "" {
		add("decision = ?", f.Decision)
	}
	if f.Search != "" {
		add("user_agent LIKE ?", "%"+f.Search+"%")
	}
	if !f.Since.IsZero() {
		add("at >= ?", f.Since.Unix())
	}
	if !f.Until.IsZero() {
		add("at <= ?", f.Until.Unix())
	}

	cond := ""
	if len(where) > 0 {
		cond = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := d.ro.QueryRowContext(ctx, "SELECT COUNT(*) FROM request_log"+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := "SELECT id, at, short_uuid, username, ip, country, user_agent, app, app_version, platform, core," +
		" hwid, format, decision, status, bytes, duration_ms, mode, err FROM request_log" + cond +
		" ORDER BY at DESC, id DESC LIMIT ? OFFSET ?"
	rows, err := d.ro.QueryContext(ctx, q, append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []model.RequestLog
	for rows.Next() {
		var r model.RequestLog
		var at int64
		if err := rows.Scan(&r.ID, &at, &r.ShortUUID, &r.Username, &r.IP, &r.Country,
			&r.UserAgent, &r.App, &r.AppVersion, &r.Platform, &r.Core, &r.HWID,
			&r.Format, &r.Decision, &r.Status, &r.Bytes, &r.DurationMS, &r.Mode, &r.Err); err != nil {
			return nil, 0, err
		}
		r.At = unixTime(at)
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// PruneRequestLog удаляет записи старше keepDays. Вызывается по расписанию.
func (d *DB) PruneRequestLog(ctx context.Context, keepDays int) (int64, error) {
	if keepDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -keepDays).Unix()
	res, err := d.rw.ExecContext(ctx, "DELETE FROM request_log WHERE at < ?", cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// TopClients считает разбивку по приложениям за период: используется для вкладки «О системе».
func (d *DB) TopClients(ctx context.Context, since time.Time, limit int) (map[string]int, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := d.ro.QueryContext(ctx,
		"SELECT app, COUNT(*) FROM request_log WHERE at >= ? AND app <> '' GROUP BY app ORDER BY COUNT(*) DESC LIMIT ?",
		since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var app string
		var n int
		if err := rows.Scan(&app, &n); err != nil {
			return nil, err
		}
		out[app] = n
	}
	return out, rows.Err()
}

// CountRequests считает запросы за период: основа детектора всплесков нагрузки.
func (d *DB) CountRequests(ctx context.Context, since time.Time) (int64, error) {
	var n int64
	err := d.ro.QueryRowContext(ctx, "SELECT COUNT(*) FROM request_log WHERE at >= ?", since.Unix()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: не посчитать запросы: %w", err)
	}
	return n, nil
}
