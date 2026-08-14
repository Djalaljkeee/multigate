package chat

import (
	"context"
	"fmt"
	"time"
)

// Prune удаляет сообщения и сессии виджета поддержки, неактивные дольше
// keepDays дней (по last_at сессии). Находка ревью 4: таблицы chat_sessions
// и chat_messages никем не чистились, а виджет открыт всему интернету -
// без чистки chat_messages растёт неограниченно.
//
// Сообщения удаляются вместе со своей сессией: история без сессии-владельца
// никому не видна (handleHistory пускает только по кукам существующей
// сессии, см. находку ревью 4 там же), оставлять её в базе бессмысленно.
//
// Вызывающий код (обычно фоновая задача в cmd/multigate) должен звать этот
// метод по расписанию: сам пакет chat фоновых задач не заводит. keepDays <= 0
// ничего не удаляет - это осознанный выключатель, а не ошибка вызова, как и
// в internal/webhooks.
//
// Возвращает суммарное число удалённых строк (сообщения + сессии).
func (s *Service) Prune(ctx context.Context, keepDays int) (int64, error) {
	if keepDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().AddDate(0, 0, -keepDays).Unix()

	// Сообщения удаляем по тому же условию, что чуть ниже определит удаляемые
	// сессии: если сессия неактивна дольше keepDays, её сообщения тоже уходят.
	res, err := s.db.RW().ExecContext(ctx,
		`DELETE FROM chat_messages WHERE session_id IN (
			SELECT session_id FROM chat_sessions WHERE last_at < ?
		)`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("chat: чистка сообщений: %w", err)
	}
	deletedMsgs, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("chat: чистка сообщений: не посчитать удалённые строки: %w", err)
	}

	res, err = s.db.RW().ExecContext(ctx, "DELETE FROM chat_sessions WHERE last_at < ?", cutoff)
	if err != nil {
		return deletedMsgs, fmt.Errorf("chat: чистка сессий: %w", err)
	}
	deletedSessions, err := res.RowsAffected()
	if err != nil {
		return deletedMsgs, fmt.Errorf("chat: чистка сессий: не посчитать удалённые строки: %w", err)
	}
	return deletedMsgs + deletedSessions, nil
}
