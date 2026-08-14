package webhooks

import (
	"context"
	"fmt"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// Log отдаёт журнал принятых событий, свежие первыми: для вкладки
// админки с историей вебхуков.
func (s *Service) Log(ctx context.Context, limit, offset int) ([]model.WebhookEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := s.db.RO().QueryContext(ctx,
		`SELECT id, at, event, payload, sig_valid, forwarded, err
		 FROM webhook_log ORDER BY at DESC, id DESC LIMIT ? OFFSET ?`,
		limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.WebhookEvent
	for rows.Next() {
		var (
			e                   model.WebhookEvent
			at                  int64
			sigValid, forwarded int
		)
		if err := rows.Scan(&e.ID, &at, &e.Event, &e.Payload, &sigValid, &forwarded, &e.Err); err != nil {
			return nil, err
		}
		e.At = unixTime(at)
		e.SigValid = sigValid != 0
		e.Forwarded = forwarded
		out = append(out, e)
	}
	return out, rows.Err()
}

// Prune удаляет из webhook_log и forward_log записи старше keepDays дней
// (по полю at). Находка ревью 2: обе таблицы никем не чистились, а
// webhook_log хранит тело каждого принятого события целиком - без чистки
// это неограниченный рост базы.
//
// Вызывающий код (обычно фоновая задача в cmd/multigate) должен звать этот
// метод по расписанию: сам пакет webhooks фоновых задач не заводит.
// keepDays <= 0 ничего не удаляет - это осознанный выключатель, а не ошибка
// вызова, чтобы забытый некорректный параметр не подчистил всю историю.
//
// Возвращает суммарное число удалённых строк по обеим таблицам.
func (s *Service) Prune(ctx context.Context, keepDays int) (int64, error) {
	if keepDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -keepDays).Unix()

	var total int64
	// Имена таблиц - статический список ниже, подстановки извне нет.
	for _, table := range []string{"webhook_log", "forward_log"} {
		res, err := s.db.RW().ExecContext(ctx, "DELETE FROM "+table+" WHERE at < ?", cutoff)
		if err != nil {
			return total, fmt.Errorf("webhooks: чистка %s: %w", table, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("webhooks: чистка %s: не посчитать удалённые строки: %w", table, err)
		}
		total += n
	}
	return total, nil
}
