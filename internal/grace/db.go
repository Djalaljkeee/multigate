package grace

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// unixTime и timeUnix переводят время туда-обратно так же, как это делает
// пакет store (см. internal/store/helpers.go). Свои копии здесь, потому что
// store не экспортирует эти мелочи, а тащить их наружу ради двух функций
// не стоит: время в базе всегда хранится числом секунд.
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

// scanner: общий интерфейс *sql.Row и *sql.Rows, чтобы не дублировать разбор строки.
type scanner interface {
	Scan(dest ...any) error
}

// scanGraceRecord разбирает одну строку grace_users.
func scanGraceRecord(sc scanner) (model.GraceRecord, error) {
	var rec model.GraceRecord
	var started, expires, restoredAt int64
	var restored int
	if err := sc.Scan(&rec.ID, &rec.UserRef, &rec.ShortUUID, &rec.Username, &started, &expires,
		&restored, &restoredAt, &rec.SnapshotJSON, &rec.AppliedSquad, &rec.OriginalSquads, &rec.Err); err != nil {
		return model.GraceRecord{}, err
	}
	rec.StartedAt = unixTime(started)
	rec.ExpiresAt = unixTime(expires)
	rec.Restored = restored != 0
	rec.RestoredAt = unixTime(restoredAt)
	return rec, nil
}

const graceColumns = `id, user_ref, short_uuid, username, started_at, expires_at, restored, restored_at,
	snapshot, applied_squad, original_squads, err`

// tryClaim атомарно заводит новую запись грейса, если для этого пользователя
// ещё нет активной (restored = 0). WHERE NOT EXISTS делает проверку и вставку
// одной SQL-командой: между "посмотреть" и "записать" не остаётся окна для
// гонки, даже если Maybe вызван из двух разных процессов прослойки одновременно.
//
// Снимок в rec должен быть заполнен ДО вызова: это единственное место, где
// он попадает в базу, и происходит это раньше любого обращения к панели.
func (s *Service) tryClaim(ctx context.Context, rec model.GraceRecord) (id int64, claimed bool, err error) {
	res, err := s.db.RW().ExecContext(ctx, `
		INSERT INTO grace_users
			(user_ref, short_uuid, username, started_at, expires_at, restored, restored_at,
			 snapshot, applied_squad, original_squads, err)
		SELECT ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ''
		WHERE NOT EXISTS (SELECT 1 FROM grace_users WHERE short_uuid = ? AND restored = 0)`,
		rec.UserRef, rec.ShortUUID, rec.Username, timeUnix(rec.StartedAt), timeUnix(rec.ExpiresAt),
		rec.SnapshotJSON, rec.AppliedSquad, rec.OriginalSquads, rec.ShortUUID)
	if err != nil {
		return 0, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, false, err
	}
	if n == 0 {
		return 0, false, nil
	}
	id, err = res.LastInsertId()
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

// activeByShortUUID возвращает текущую незавершённую запись грейса пользователя, если она есть.
func (s *Service) activeByShortUUID(ctx context.Context, shortUUID string) (*model.GraceRecord, error) {
	row := s.db.RO().QueryRowContext(ctx,
		"SELECT "+graceColumns+" FROM grace_users WHERE short_uuid = ? AND restored = 0 ORDER BY id DESC LIMIT 1",
		shortUUID)
	rec, err := scanGraceRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// getRecord читает запись грейса по идентификатору.
func (s *Service) getRecord(ctx context.Context, id int64) (model.GraceRecord, error) {
	row := s.db.RO().QueryRowContext(ctx, "SELECT "+graceColumns+" FROM grace_users WHERE id = ?", id)
	rec, err := scanGraceRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.GraceRecord{}, store.ErrNotFound
	}
	return rec, err
}

// pendingExpiredIDs отдаёт id записей, которым пора восстанавливаться:
// грейс не восстановлен и срок уже прошёл.
func (s *Service) pendingExpiredIDs(ctx context.Context, now time.Time) ([]int64, error) {
	rows, err := s.db.RO().QueryContext(ctx,
		"SELECT id FROM grace_users WHERE restored = 0 AND expires_at > 0 AND expires_at <= ? ORDER BY id",
		now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// setErr фиксирует ошибку обращения к панели в записи, чтобы её было видно в админке.
func (s *Service) setErr(ctx context.Context, id int64, msg string) error {
	_, err := s.db.RW().ExecContext(ctx, "UPDATE grace_users SET err = ? WHERE id = ?", truncate(msg, 500), id)
	return err
}

// clearErr снимает ранее записанную ошибку: очередная попытка удалась.
func (s *Service) clearErr(ctx context.Context, id int64) error {
	_, err := s.db.RW().ExecContext(ctx, "UPDATE grace_users SET err = '' WHERE id = ?", id)
	return err
}

// markRestored помечает запись восстановленной. Идемпотентно само по себе:
// повторная простановка тех же значений ничего не портит.
func (s *Service) markRestored(ctx context.Context, id int64) error {
	_, err := s.db.RW().ExecContext(ctx,
		"UPDATE grace_users SET restored = 1, restored_at = ?, err = '' WHERE id = ?", nowUnix(), id)
	return err
}

// truncate обрезает строку до n рун: колонка err ограничена по длине.
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
