package webhooks

import (
	"sync"
	"time"
)

// limiter ограничивает частоту событий по скользящему окну. Ключ - обычно
// IP отправителя.
//
// Копия того же типа, что уже есть в internal/chat: пакеты специально не
// делят его через импорт, чтобы не тащить чат в зависимости вебхуков ради
// сорока строк (тот же принцип, что и с nowUnix/truncate/boolInt в
// internal/webhooks/helpers.go).
type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time

	stop chan struct{}
	once sync.Once
}

func newLimiter(max int, window time.Duration) *limiter {
	l := &limiter{max: max, window: window, hits: map[string][]time.Time{}, stop: make(chan struct{})}
	go l.gc()
	return l
}

// Allow сообщает, можно ли пропустить ещё одно событие под этим ключом
// прямо сейчас, и сразу фиксирует его, если можно: раздельного вызова
// "записать факт" не требуется.
func (l *limiter) Allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

// gc чистит ключи без свежих попаданий. Без этого память росла бы
// неограниченно: эндпоинт вебхуков может увидеть трафик с большого числа
// уникальных IP (в том числе паразитный, находка ревью 2).
func (l *limiter) gc() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.sweep()
		case <-l.stop:
			return
		}
	}
}

func (l *limiter) sweep() {
	cutoff := time.Now().Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, times := range l.hits {
		fresh := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				fresh = append(fresh, t)
			}
		}
		if len(fresh) == 0 {
			delete(l.hits, k)
		} else {
			l.hits[k] = fresh
		}
	}
}

// Close останавливает фоновую уборку. Безопасно вызывать один раз.
func (l *limiter) Close() {
	l.once.Do(func() { close(l.stop) })
}
