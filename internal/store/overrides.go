package store

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// Локальные блокировки проверяются на каждом запросе подписки, поэтому
// держатся в памяти целиком: их единицы или сотни, а не миллионы.
type overrideCache struct {
	mu     sync.RWMutex
	byUser map[string]model.Override
	byHWID map[string]model.Override
	pair   map[string]model.Override // "shortUuid|hwid": блокировка устройства у конкретного пользователя
	at     time.Time
}

const overrideTTL = 15 * time.Second

func pairKey(shortUUID, hwid string) string { return shortUUID + "|" + hwid }

// loadOverrides перечитывает блокировки, если кэш устарел.
func (d *DB) loadOverrides(ctx context.Context) error {
	d.ov.mu.RLock()
	fresh := d.ov.byUser != nil && time.Since(d.ov.at) < overrideTTL
	d.ov.mu.RUnlock()
	if fresh {
		return nil
	}

	rows, err := d.ro.QueryContext(ctx,
		"SELECT id, short_uuid, hwid, action, reason, created_at, created_by FROM overrides")
	if err != nil {
		return err
	}
	defer rows.Close()

	byUser := map[string]model.Override{}
	byHWID := map[string]model.Override{}
	pairs := map[string]model.Override{}
	for rows.Next() {
		var o model.Override
		var created int64
		if err := rows.Scan(&o.ID, &o.ShortUUID, &o.HWID, &o.Action, &o.Reason, &created, &o.CreatedBy); err != nil {
			return err
		}
		o.CreatedAt = unixTime(created)
		switch {
		case o.ShortUUID != "" && o.HWID != "":
			pairs[pairKey(o.ShortUUID, o.HWID)] = o
		case o.HWID != "":
			byHWID[o.HWID] = o
		case o.ShortUUID != "":
			byUser[o.ShortUUID] = o
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	d.ov.mu.Lock()
	d.ov.byUser, d.ov.byHWID, d.ov.pair, d.ov.at = byUser, byHWID, pairs, time.Now()
	d.ov.mu.Unlock()
	return nil
}

// FindOverride ищет блокировку для пары пользователь-устройство.
// Порядок проверки от частного к общему: устройство у пользователя,
// затем устройство целиком, затем пользователь целиком.
func (d *DB) FindOverride(ctx context.Context, shortUUID, hwid string) (model.Override, bool) {
	if err := d.loadOverrides(ctx); err != nil {
		// Ошибка чтения не должна оборвать выдачу подписки:
		// считаем, что блокировок нет, и пишем это в журнал вызывающей стороны.
		return model.Override{}, false
	}
	d.ov.mu.RLock()
	defer d.ov.mu.RUnlock()

	if hwid != "" && shortUUID != "" {
		if o, ok := d.ov.pair[pairKey(shortUUID, hwid)]; ok {
			return o, true
		}
	}
	if hwid != "" {
		if o, ok := d.ov.byHWID[hwid]; ok {
			return o, true
		}
	}
	if shortUUID != "" {
		if o, ok := d.ov.byUser[shortUUID]; ok {
			return o, true
		}
	}
	return model.Override{}, false
}

// AddOverride создаёт блокировку.
func (d *DB) AddOverride(ctx context.Context, o model.Override) (int64, error) {
	if o.Action == "" {
		o.Action = "block"
	}
	res, err := d.rw.ExecContext(ctx,
		"INSERT INTO overrides (short_uuid, hwid, action, reason, created_at, created_by) VALUES (?,?,?,?,?,?)",
		strings.TrimSpace(o.ShortUUID), strings.TrimSpace(o.HWID), o.Action,
		truncate(o.Reason, 500), nowUnix(), truncate(o.CreatedBy, 190))
	if err != nil {
		return 0, err
	}
	d.invalidateOverrides()
	id, _ := res.LastInsertId()
	return id, nil
}

// DeleteOverride снимает блокировку по идентификатору.
func (d *DB) DeleteOverride(ctx context.Context, id int64) error {
	if _, err := d.rw.ExecContext(ctx, "DELETE FROM overrides WHERE id = ?", id); err != nil {
		return err
	}
	d.invalidateOverrides()
	return nil
}

// ListOverrides отдаёт все блокировки, свежие первыми.
func (d *DB) ListOverrides(ctx context.Context) ([]model.Override, error) {
	rows, err := d.ro.QueryContext(ctx,
		"SELECT id, short_uuid, hwid, action, reason, created_at, created_by FROM overrides ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Override
	for rows.Next() {
		var o model.Override
		var created int64
		if err := rows.Scan(&o.ID, &o.ShortUUID, &o.HWID, &o.Action, &o.Reason, &created, &o.CreatedBy); err != nil {
			return nil, err
		}
		o.CreatedAt = unixTime(created)
		out = append(out, o)
	}
	return out, rows.Err()
}

func (d *DB) invalidateOverrides() {
	d.ov.mu.Lock()
	d.ov.byUser, d.ov.byHWID, d.ov.pair, d.ov.at = nil, nil, nil, time.Time{}
	d.ov.mu.Unlock()
}
