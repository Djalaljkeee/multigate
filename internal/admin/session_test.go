package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestAnonymousRequestsDoNotCreateSessions: прямое воспроизведение находки,
// поток анонимных запросов к защищённой странице (которые всё равно
// заканчиваются редиректом на /login) не должен заводить по сессии на
// каждый запрос.
func TestAnonymousRequestsDoNotCreateSessions(t *testing.T) {
	db := newTestStore(t)
	markInstalled(t, db, "admin", "correct-horse-battery")
	h := newTestHandler(t, db, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	const n = 2000
	c := &http.Client{
		// Не идём по Location сами: проверяем именно то, что сам запрос к
		// защищённой странице не заводит сессию. Страница логина, на
		// которую он редиректит, законно заводит анонимную сессию под
		// CSRF-токен формы. Это отдельный путь, не тот, что тут проверяется.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for i := 0; i < n; i++ {
		resp, err := c.Get(srv.URL + "/admin/overview")
		if err != nil {
			t.Fatalf("запрос %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("запрос %d: ожидали редирект 303, получили %d", i, resp.StatusCode)
		}
	}

	if got := h.sessions.count(); got != 0 {
		t.Fatalf("%d анонимных запросов к защищённой странице создали %d сессий, ожидали 0", n, got)
	}
}

// TestSessionStoreCapEviction проверяет, что число сессий не растёт за
// потолок maxSessions: при его превышении вытесняется самая старая.
func TestSessionStoreCapEviction(t *testing.T) {
	ss := newSessionStore()
	t.Cleanup(ss.Stop)

	const extra = 500
	var last *session
	for i := 0; i < maxSessions+extra; i++ {
		last = ss.create()
	}

	if got := ss.count(); got != maxSessions {
		t.Fatalf("после %d вставок ожидали ровно потолок %d сессий, получили %d", maxSessions+extra, maxSessions, got)
	}
	if _, ok := ss.get(last.id); !ok {
		t.Fatalf("последняя созданная сессия не пережила вытеснение")
	}
}

// TestSessionStoreEvictsAnonymousBeforeAuthenticated проверяет, что под
// потоком новых анонимных сессий не вытесняется сессия уже вошедшего
// администратора, хотя по чистому времени создания она может быть самой
// старой в хранилище.
func TestSessionStoreEvictsAnonymousBeforeAuthenticated(t *testing.T) {
	ss := newSessionStore()
	t.Cleanup(ss.Stop)

	admin := ss.create()
	admin.user = "root" // имитируем уже вошедшего администратора

	for i := 0; i < maxSessions+100; i++ {
		ss.create()
	}

	if _, ok := ss.get(admin.id); !ok {
		t.Fatalf("сессию вошедшего администратора вытеснили под потоком анонимных сессий")
	}
}

// TestSessionStorePruneExpiredRemovesOnlyStale проверяет фоновую чистку
// просроченных сессий отдельно от вытеснения по потолку: она должна убирать
// только то, что реально истекло, не трогая живые сессии.
func TestSessionStorePruneExpiredRemovesOnlyStale(t *testing.T) {
	ss := newSessionStore()
	t.Cleanup(ss.Stop)

	fresh := ss.create()
	stale := ss.create()
	stale.expiresAt = time.Now().Add(-time.Minute) // искусственно просрочена

	ss.pruneExpired()

	if got := ss.count(); got != 1 {
		t.Fatalf("после чистки просроченных ожидали одну сессию, осталось %d", got)
	}
	if _, ok := ss.get(fresh.id); !ok {
		t.Fatalf("живая сессия не должна была пропасть при чистке просроченных")
	}
}

// TestSessionStoreStopIsIdempotent проверяет, что фоновую горутину можно
// остановить, и повторный вызов Stop не паникует.
func TestSessionStoreStopIsIdempotent(t *testing.T) {
	ss := newSessionStore()
	ss.Stop()
	ss.Stop()
}
