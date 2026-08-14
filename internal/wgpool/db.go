package wgpool

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// unixTime и timeUnix переводят время туда-обратно так же, как это делает
// пакет store (см. internal/store/helpers.go). Свои копии здесь по той же
// причине, что и в пакете grace: store их не экспортирует.
func unixTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0)
}

func timeUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func nowUnix() int64 { return time.Now().Unix() }

// scanner: общий интерфейс *sql.Row и *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

const leaseColumns = `id, pool, config_name, config, short_uuid, hwid, issued_at, released_at, in_use`

func scanLease(sc scanner) (model.WGLease, error) {
	var l model.WGLease
	var issued, released int64
	var inUse int
	if err := sc.Scan(&l.ID, &l.Pool, &l.ConfigName, &l.Config, &l.ShortUUID, &l.HWID,
		&issued, &released, &inUse); err != nil {
		return model.WGLease{}, err
	}
	l.IssuedAt = unixTime(issued)
	l.ReleasedAt = unixTime(released)
	l.InUse = inUse != 0
	return l, nil
}

// findActiveLease ищет уже выданный конфиг для пары пользователь-устройство.
// Это обеспечивает требование 1: повторное обращение отдаёт тот же конфиг.
func (s *Service) findActiveLease(ctx context.Context, pool, shortUUID, hwid string) (model.WGLease, bool, error) {
	row := s.db.RO().QueryRowContext(ctx,
		"SELECT "+leaseColumns+" FROM wg_leases WHERE pool = ? AND short_uuid = ? AND hwid = ? AND in_use = 1"+
			" ORDER BY id LIMIT 1",
		pool, shortUUID, hwid)
	lease, err := scanLease(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.WGLease{}, false, nil
	}
	if err != nil {
		return model.WGLease{}, false, err
	}
	return lease, true, nil
}

// errLeaseRace сигнализирует, что свободную запись перехватили между выбором
// и обновлением. При корректной работе блокировки строки (FOR UPDATE на MySQL,
// единственное соединение на запись у SQLite) это не должно происходить:
// ошибка тут страховка, а не ожидаемый путь.
var errLeaseRace = errors.New("гонка при выдаче конфига")

// acquireFree атомарно занимает один свободный конфиг пула транзакцией:
// строка выбирается и тут же блокируется (FOR UPDATE для MySQL; для SQLite
// пул на запись держит одно-единственное соединение, так что конкурентные
// запросы уже сериализованы самим драйвером), поэтому два параллельных
// вызова физически не могут получить одну и ту же запись.
func (s *Service) acquireFree(ctx context.Context, pool, shortUUID, hwid string) (model.WGLease, error) {
	tx, err := s.db.RW().BeginTx(ctx, nil)
	if err != nil {
		return model.WGLease{}, fmt.Errorf("wgpool: не начать транзакцию: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op после успешного Commit

	q := "SELECT id FROM wg_leases WHERE pool = ? AND in_use = 0 ORDER BY id LIMIT 1"
	if s.db.Dialect() == store.DialectMySQL {
		q += " FOR UPDATE"
	}
	var id int64
	if err := tx.QueryRowContext(ctx, q, pool).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.WGLease{}, ErrPoolEmpty
		}
		return model.WGLease{}, fmt.Errorf("wgpool: поиск свободного конфига: %w", err)
	}

	res, err := tx.ExecContext(ctx,
		"UPDATE wg_leases SET in_use = 1, short_uuid = ?, hwid = ?, issued_at = ?, released_at = 0"+
			" WHERE id = ? AND in_use = 0",
		shortUUID, hwid, nowUnix(), id)
	if err != nil {
		return model.WGLease{}, fmt.Errorf("wgpool: не занять конфиг: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return model.WGLease{}, fmt.Errorf("wgpool: не занять конфиг: %w", err)
	}
	if n == 0 {
		// Кто-то перехватил запись между выбором и обновлением: страховка
		// на случай, если блокировка выше почему-то не сработала.
		return model.WGLease{}, errLeaseRace
	}

	row := tx.QueryRowContext(ctx, "SELECT "+leaseColumns+" FROM wg_leases WHERE id = ?", id)
	lease, err := scanLease(row)
	if err != nil {
		return model.WGLease{}, fmt.Errorf("wgpool: не прочитать выданный конфиг: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return model.WGLease{}, fmt.Errorf("wgpool: не зафиксировать выдачу: %w", err)
	}
	return lease, nil
}
