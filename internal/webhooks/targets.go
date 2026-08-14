package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// Targets отдаёт все адреса рассылки, свежие первыми.
func (s *Service) Targets(ctx context.Context) ([]model.ForwardTarget, error) {
	rows, err := s.db.RO().QueryContext(ctx,
		"SELECT id, name, url, secret, enabled, COALESCE(events, ''), created_at FROM forward_targets ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.ForwardTarget
	for rows.Next() {
		var (
			t          model.ForwardTarget
			enabled    int
			eventsJSON string
			created    int64
		)
		if err := rows.Scan(&t.ID, &t.Name, &t.URL, &t.Secret, &enabled, &eventsJSON, &created); err != nil {
			return nil, err
		}
		t.Enabled = enabled != 0
		t.Events = decodeEvents(eventsJSON)
		t.CreatedAt = unixTime(created)
		out = append(out, t)
	}
	return out, rows.Err()
}

// SaveTarget создаёт адрес рассылки или обновляет существующий, если t.ID != 0.
func (s *Service) SaveTarget(ctx context.Context, t model.ForwardTarget) (int64, error) {
	name := strings.TrimSpace(t.Name)
	url := strings.TrimSpace(t.URL)
	if url == "" {
		return 0, errors.New("webhooks: не указан адрес получателя")
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return 0, errors.New("webhooks: адрес получателя должен начинаться с http:// или https://")
	}

	eventsJSON, err := marshalEvents(t.Events)
	if err != nil {
		return 0, err
	}
	secret := truncate(t.Secret, 500)

	if t.ID == 0 {
		res, err := s.db.RW().ExecContext(ctx,
			"INSERT INTO forward_targets (name, url, secret, enabled, events, created_at) VALUES (?,?,?,?,?,?)",
			truncate(name, 190), truncate(url, 500), secret, boolInt(t.Enabled), eventsJSON, nowUnix())
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}

	if _, err := s.db.RW().ExecContext(ctx,
		"UPDATE forward_targets SET name=?, url=?, secret=?, enabled=?, events=? WHERE id=?",
		truncate(name, 190), truncate(url, 500), secret, boolInt(t.Enabled), eventsJSON, t.ID); err != nil {
		return 0, err
	}
	return t.ID, nil
}

// DeleteTarget убирает адрес рассылки.
func (s *Service) DeleteTarget(ctx context.Context, id int64) error {
	_, err := s.db.RW().ExecContext(ctx, "DELETE FROM forward_targets WHERE id = ?", id)
	return err
}

func decodeEvents(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

func marshalEvents(events []string) (string, error) {
	if len(events) == 0 {
		return "", nil
	}
	b, err := json.Marshal(events)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
