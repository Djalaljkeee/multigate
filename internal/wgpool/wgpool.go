// Package wgpool: пул готовых конфигов WireGuard и AmneziaWG.
//
// Конфиги на выдачу заранее сгенерированы и лежат в базе; служба лишь
// раздаёт их устройствам и следит, чтобы один и тот же конфиг не ушёл
// сразу двум клиентам. Устройство должно получать один и тот же конфиг
// при каждом повторном обращении, иначе у него на каждом обновлении
// подписки будет меняться адрес интерфейса, а сам пул опустеет за сутки.
package wgpool

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// ErrPoolEmpty возвращается, когда в пуле нет ни одного свободного конфига.
var ErrPoolEmpty = errors.New("wgpool: в пуле нет свободных конфигов")

// defaultPool: имя пула, если вызывающая сторона не указала своё.
// Совпадает со значением по умолчанию колонки pool в схеме (см. migrate.go).
const defaultPool = "default"

// PoolStat: сколько конфигов свободно и сколько занято в конкретном пуле.
type PoolStat struct {
	Free  int
	InUse int
}

// Service: служба пула WireGuard/AmneziaWG.
type Service struct {
	db  *store.DB
	log *slog.Logger

	locks keyLock // по pool+shortUuid+hwid: не даём одному устройству занять два конфига гонкой
}

// New собирает службу.
func New(db *store.DB, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{db: db, log: log}
}

func normalizePool(pool string) string {
	pool = strings.TrimSpace(pool)
	if pool == "" {
		return defaultPool
	}
	return pool
}

// Import добавляет в пул конфиги, чьё содержимое прошло валидацию как
// WireGuard/AmneziaWG. Возвращает число реально добавленных: невалидные
// записи молча пропускаются (с предупреждением в журнал процесса), а не
// заваливают весь импорт целиком.
//
// Повторный импорт файла с тем же именем в тот же пул не трогает уже
// существующую запись, даже если она сейчас выдана клиенту: перезапись
// содержимого активной выдачи сломала бы подключение устройства, которое
// этим конфигом уже пользуется.
func (s *Service) Import(ctx context.Context, pool string, configs map[string]string) (int, error) {
	pool = normalizePool(pool)
	if len(configs) == 0 {
		return 0, nil
	}

	tx, err := s.db.RW().BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("wgpool: не начать транзакцию: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op после успешного Commit

	imported := 0
	for name, content := range configs {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if err := validateConfig(content); err != nil {
			s.log.Warn("wgpool: конфиг не похож на WireGuard/AmneziaWG, пропускаю",
				"pool", pool, "name", name, "err", err)
			continue
		}

		res, err := tx.ExecContext(ctx, `
			INSERT INTO wg_leases (pool, config_name, config, short_uuid, hwid, issued_at, released_at, in_use)
			SELECT ?, ?, ?, '', '', 0, 0, 0
			WHERE NOT EXISTS (SELECT 1 FROM wg_leases WHERE pool = ? AND config_name = ?)`,
			pool, name, content, pool, name)
		if err != nil {
			return imported, fmt.Errorf("wgpool: не импортировать %q: %w", name, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return imported, fmt.Errorf("wgpool: не импортировать %q: %w", name, err)
		}
		if n > 0 {
			imported++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("wgpool: не зафиксировать импорт: %w", err)
	}
	return imported, nil
}

// Lease выдаёт конфиг устройству. Повторный вызов для той же пары
// пользователь-устройство отдаёт ранее выданный конфиг без изменений.
func (s *Service) Lease(ctx context.Context, pool, shortUUID, hwid string) (model.WGLease, error) {
	pool = normalizePool(pool)
	shortUUID = strings.TrimSpace(shortUUID)
	hwid = strings.TrimSpace(hwid)
	if shortUUID == "" {
		return model.WGLease{}, errors.New("wgpool: не задан shortUuid")
	}
	if hwid == "" {
		return model.WGLease{}, errors.New("wgpool: не задан hwid устройства")
	}

	// Разделитель \x00 не может встретиться в uuid/hwid, поэтому ключ однозначен.
	unlock := s.locks.lock(pool + "\x00" + shortUUID + "\x00" + hwid)
	defer unlock()

	if lease, ok, err := s.findActiveLease(ctx, pool, shortUUID, hwid); err != nil {
		return model.WGLease{}, fmt.Errorf("wgpool: поиск текущей выдачи: %w", err)
	} else if ok {
		return lease, nil
	}

	const attempts = 3
	var lastErr error
	for i := 0; i < attempts; i++ {
		lease, err := s.acquireFree(ctx, pool, shortUUID, hwid)
		switch {
		case err == nil:
			return lease, nil
		case errors.Is(err, ErrPoolEmpty):
			return model.WGLease{}, err
		case errors.Is(err, errLeaseRace):
			lastErr = err
			continue // кто-то перехватил ту же запись, пробуем ещё раз на следующей свободной
		default:
			return model.WGLease{}, err
		}
	}
	return model.WGLease{}, fmt.Errorf("wgpool: не удалось выдать конфиг после повторных попыток: %w", lastErr)
}

// Release освобождает конфиг обратно в пул. Идемпотентен: освобождение уже
// свободной или несуществующей записи не считается ошибкой.
func (s *Service) Release(ctx context.Context, id int64) error {
	_, err := s.db.RW().ExecContext(ctx,
		"UPDATE wg_leases SET in_use = 0, short_uuid = '', hwid = '', released_at = ? WHERE id = ? AND in_use = 1",
		nowUnix(), id)
	if err != nil {
		return fmt.Errorf("wgpool: не освободить конфиг %d: %w", id, err)
	}
	return nil
}

// Stats считает свободные и занятые конфиги по каждому пулу. Нужно для
// вкладки админки, где видно, не пора ли досыпать конфигов.
func (s *Service) Stats(ctx context.Context) (map[string]PoolStat, error) {
	rows, err := s.db.RO().QueryContext(ctx, "SELECT pool, in_use, COUNT(*) FROM wg_leases GROUP BY pool, in_use")
	if err != nil {
		return nil, fmt.Errorf("wgpool: не посчитать статистику: %w", err)
	}
	defer rows.Close()

	out := map[string]PoolStat{}
	for rows.Next() {
		var pool string
		var inUse, n int
		if err := rows.Scan(&pool, &inUse, &n); err != nil {
			return nil, err
		}
		st := out[pool]
		if inUse != 0 {
			st.InUse = n
		} else {
			st.Free = n
		}
		out[pool] = st
	}
	return out, rows.Err()
}

// List отдаёт конфиги пула для админки. Пустой pool означает все пулы сразу.
func (s *Service) List(ctx context.Context, pool string, onlyInUse bool) ([]model.WGLease, error) {
	var where []string
	var args []any
	if pool = strings.TrimSpace(pool); pool != "" {
		where = append(where, "pool = ?")
		args = append(args, pool)
	}
	if onlyInUse {
		where = append(where, "in_use = 1")
	}

	q := "SELECT " + leaseColumns + " FROM wg_leases"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY pool, config_name"

	rows, err := s.db.RO().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("wgpool: не прочитать список: %w", err)
	}
	defer rows.Close()

	var out []model.WGLease
	for rows.Next() {
		lease, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, lease)
	}
	return out, rows.Err()
}

// requiredWGKeys: ключи, без которых содержимое не похоже на рабочий
// конфиг WireGuard. Присутствие параметров AmneziaWG (Jc, Jmin, Jmax, S1,
// S2, H1-H4) не требуется: обычный WireGuard-конфиг их не содержит и всё
// равно остаётся валидным. Их проверять не нужно, они лишь дополняют базовый
// набор, когда конфиг сгенерирован под AmneziaWG.
var requiredWGKeys = []string{"privatekey", "address", "publickey", "endpoint"}

// validateConfig проверяет, что содержимое похоже на конфиг WireGuard:
// есть секции [Interface] и [Peer] и обязательные ключи. Полноценный
// парсинг INI не нужен: задача validateConfig отсеять явный мусор,
// а не проверить корректность каждого значения.
func validateConfig(content string) error {
	sections := map[string]bool{}
	keys := map[string]bool{}

	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sections[strings.ToLower(strings.TrimSpace(line[1:len(line)-1]))] = true
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			keys[strings.ToLower(strings.TrimSpace(line[:i]))] = true
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("wgpool: не прочитать конфиг: %w", err)
	}

	if !sections["interface"] {
		return errors.New("wgpool: нет секции [Interface]")
	}
	if !sections["peer"] {
		return errors.New("wgpool: нет секции [Peer]")
	}
	for _, k := range requiredWGKeys {
		if !keys[k] {
			return fmt.Errorf("wgpool: нет обязательного ключа %s", k)
		}
	}
	return nil
}
