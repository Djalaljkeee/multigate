package webhooks

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/version"
)

// dispatch рассылает одно событие всем подходящим получателям параллельно
// и обновляет счётчик успешных доставок в журнале. Вызывается воркером,
// уже вне HTTP-запроса панели: таймаут свой, с исходным запросом не связан.
func (s *Service) dispatch(ev queuedEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), dispatchTimeout)
	defer cancel()

	targets, err := s.Targets(ctx)
	if err != nil {
		s.log.Error("вебхуки: не прочитать получателей рассылки", "err", err)
		return
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		sent int
	)
	for _, t := range targets {
		if !t.Enabled || !eventMatches(t.Events, ev.event) {
			continue
		}
		wg.Add(1)
		go func(t model.ForwardTarget) {
			defer wg.Done()
			if s.forwardOne(ctx, ev, t) {
				mu.Lock()
				sent++
				mu.Unlock()
			}
		}(t)
	}
	wg.Wait()

	if _, err := s.db.RW().ExecContext(context.Background(),
		"UPDATE webhook_log SET forwarded = ? WHERE id = ?", sent, ev.logID); err != nil {
		s.log.Error("вебхуки: не обновить счётчик доставок", "err", err)
	}
}

// eventMatches сообщает, подписан ли получатель на событие.
// Пустой список у получателя означает подписку на все события.
func eventMatches(events []string, event string) bool {
	if len(events) == 0 {
		return true
	}
	for _, e := range events {
		if e == event {
			return true
		}
	}
	return false
}

// forwardOne доставляет событие одному получателю с повторами при сбое.
// Каждая попытка фиксируется в forward_log независимо от исхода: по
// журналу должно быть видно, сколько раз и с каким результатом прослойка
// пыталась достучаться. Повторов не больше maxAttempts, растущая пауза
// между ними не даёт упавшему получателю захлебнуться потоком запросов.
func (s *Service) forwardOne(ctx context.Context, ev queuedEvent, t model.ForwardTarget) bool {
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		status, err := s.sendOnce(ctx, ev.payload, t)
		errText := ""
		if err != nil {
			errText = err.Error()
		}
		s.writeForwardLog(t.Name, ev.event, status, attempt, errText)

		if err == nil && status >= 200 && status < 300 {
			return true
		}
		if attempt == maxAttempts {
			return false
		}

		backoff := time.Duration(1<<uint(attempt-1)) * time.Second // 1s, 2s, ...
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return false
		}
	}
	return false
}

// sendOnce делает одну попытку доставки. Подпись пересчитывается под
// секрет ИМЕННО этого получателя: секрет входящего вебхука или секрет
// другого получателя наружу никогда не уходит.
func (s *Service) sendOnce(ctx context.Context, payload []byte, t model.ForwardTarget) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", version.UserAgent())
	if t.Secret != "" {
		req.Header.Set(signatureHeader, computeSignature(t.Secret, payload))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// Сливаем тело ответа получателя, чтобы соединение вернулось в пул;
	// само содержимое ответа прослойке не нужно.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, nil
}

func (s *Service) writeForwardLog(target, event string, status, attempt int, errText string) {
	if _, err := s.db.RW().ExecContext(context.Background(),
		"INSERT INTO forward_log (at, target, event, status, attempt, err) VALUES (?,?,?,?,?,?)",
		nowUnix(), truncate(target, 190), truncate(event, 190), status, attempt, truncate(errText, 500)); err != nil {
		s.log.Error("вебхуки: не записать попытку доставки", "err", err)
	}
}
