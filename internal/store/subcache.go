package store

import (
	"context"
	"time"
)

// PruneSubCache удаляет протухшие ответы подписки.
//
// Без этой чистки таблица растёт бесконтрольно: в режиме зеркала origin
// отвечает на любой путь, поэтому перебор случайных адресов наполняет её
// телами до нескольких мегабайт каждое. Вызывается фоновой задачей.
func (d *DB) PruneSubCache(ctx context.Context) (int64, error) {
	res, err := d.rw.ExecContext(ctx,
		"DELETE FROM sub_cache WHERE expires_at > 0 AND expires_at < ?", time.Now().Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// TrimSubCache держит размер кэша в разумных пределах, срезая самые старые
// записи сверх лимита. Протухшие удаляет PruneSubCache, а этот предел нужен
// на случай, когда записей много, а срок у них ещё не вышел.
func (d *DB) TrimSubCache(ctx context.Context, maxRows int) (int64, error) {
	if maxRows <= 0 {
		return 0, nil
	}
	var total int64
	if err := d.ro.QueryRowContext(ctx, "SELECT COUNT(*) FROM sub_cache").Scan(&total); err != nil {
		return 0, err
	}
	if total <= int64(maxRows) {
		return 0, nil
	}
	// Удаляем самые давние по времени укладки: свежие ответы полезнее.
	res, err := d.rw.ExecContext(ctx,
		"DELETE FROM sub_cache WHERE id IN (SELECT id FROM sub_cache ORDER BY stored_at ASC LIMIT ?)",
		total-int64(maxRows))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
