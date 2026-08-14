package admin

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestClientIPTrustProxy проверяет обе ветки clientIP: без доверия к прокси
// заголовки клиента не должны влиять на результат вообще, а с доверием
// нужно брать ПОСЛЕДНИЙ элемент X-Forwarded-For (его дописывает прокси),
// а не первый (его пишет сам клиент и может вписать что угодно).
func TestClientIPTrustProxy(t *testing.T) {
	newReq := func(remote, xff, xreal string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		if xreal != "" {
			r.Header.Set("X-Real-IP", xreal)
		}
		return r
	}

	t.Run("без доверия прокси заголовки клиента игнорируются", func(t *testing.T) {
		r := newReq("203.0.113.9:5555", "10.0.0.1, 10.0.0.2", "10.0.0.3")
		if got := clientIP(r, false); got != "203.0.113.9" {
			t.Fatalf("ожидали RemoteAddr без порта, получили %q", got)
		}
	})

	t.Run("с доверием берётся последний элемент XFF, а не первый", func(t *testing.T) {
		r := newReq("203.0.113.9:5555", "1.2.3.4, 5.6.7.8, 9.10.11.12", "")
		if got := clientIP(r, true); got != "9.10.11.12" {
			t.Fatalf("ожидали последний элемент цепочки XFF (9.10.11.12), получили %q", got)
		}
	})

	t.Run("с доверием и без XFF используется X-Real-IP", func(t *testing.T) {
		r := newReq("203.0.113.9:5555", "", "9.9.9.9")
		if got := clientIP(r, true); got != "9.9.9.9" {
			t.Fatalf("ожидали X-Real-IP, получили %q", got)
		}
	})

	t.Run("с доверием и без заголовков используется RemoteAddr", func(t *testing.T) {
		r := newReq("203.0.113.9:5555", "", "")
		if got := clientIP(r, true); got != "203.0.113.9" {
			t.Fatalf("ожидали RemoteAddr, получили %q", got)
		}
	})
}

// TestLoginXFFSpoofDoesNotBypassRateLimit: прямое воспроизведение находки.
// Без доверия прокси (значение по умолчанию) подмена X-Forwarded-For на
// каждый запрос не должна помогать обойти лимит попыток входа, потому что
// заголовок вообще не участвует в определении IP: все попытки считаются
// одним и тем же клиентом (RemoteAddr от локального соединения теста).
func TestLoginXFFSpoofDoesNotBypassRateLimit(t *testing.T) {
	db := newTestStore(t)
	markInstalled(t, db, "admin", "correct-horse-battery")
	h := newTestHandler(t, db, nil) // TrustProxy не задан => false
	srv := httptest.NewServer(h)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	_, body := getBody(t, c, srv.URL+"/admin/login")
	csrf := extractCSRF(t, body)

	const attempts = 10
	blocked := 0
	for i := 0; i < attempts; i++ {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/admin/login", strings.NewReader(url.Values{
			"username": {"admin"},
			"password": {"wrong-password"},
			"csrf":     {csrf},
		}.Encode()))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// Атакующий на каждый запрос подменяет X-Forwarded-For новым
		// адресом, рассчитывая, что лимитер сочтёт его каждый раз новым
		// клиентом и не станет копить неудачи по одному IP.
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i+1))

		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("попытка %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			blocked++
		}
	}

	if blocked == 0 {
		t.Fatalf("ни одна из %d попыток входа с разным X-Forwarded-For не была отбита лимитером: подмена заголовка обходит защиту от подбора пароля", attempts)
	}
}

// TestLoginLimiterGlobalCap проверяет вторую линию защиты: общий потолок
// неудач на всю админку. Каждый отдельный IP делает меньше попыток, чем
// его личный порог (loginMaxFails), но суммарно по всем IP их больше
// общего порога, и распределённый перебор должен всё равно упереться в лимит.
func TestLoginLimiterGlobalCap(t *testing.T) {
	l := newLoginLimiter()

	perIP := loginMaxFails - 1 // ни один IP не доходит до личной блокировки
	ipCount := (loginGlobalMaxFails / perIP) + 2
	for i := 0; i < ipCount; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		for j := 0; j < perIP; j++ {
			l.registerFail(ip)
		}
		// Проверяем персональный счётчик напрямую, а не через allowed():
		// как только сработает общий лимит, allowed() вернёт false для
		// вообще любого IP (в этом и смысл общей защиты), и по одному
		// только bool не отличить "заблокирован лично" от "задет общим
		// потолком", а тест должен убедиться именно в первом.
		if a := l.byIP[ip]; a != nil && !a.blockedTil.IsZero() {
			t.Fatalf("IP %s получил персональную блокировку после всего %d неудач при пороге %d", ip, perIP, loginMaxFails)
		}
	}

	freshIP := "198.51.100.77"
	if l.allowed(freshIP) {
		t.Fatalf("после %d неудачных попыток с %d разных IP общий лимит не сработал: совершенно новый IP всё ещё разрешён", ipCount*perIP, ipCount)
	}
}

// TestLoginLimiterSuccessResetsGlobalCounter фиксирует осознанное решение:
// успешный вход сбрасывает не только персональный счётчик неудач по IP, но
// и общий, ведь раз пароль подобран (кем бы то ни было), дальше держать
// заблокированной всю админку смысла нет.
func TestLoginLimiterSuccessResetsGlobalCounter(t *testing.T) {
	l := newLoginLimiter()
	for i := 0; i < loginGlobalMaxFails; i++ {
		l.registerFail(fmt.Sprintf("203.0.113.%d", i+1))
	}
	if l.allowed("198.51.100.1") {
		t.Fatalf("общий лимит должен был сработать после %d неудач", loginGlobalMaxFails)
	}

	l.registerSuccess("203.0.113.1")

	if !l.allowed("198.51.100.1") {
		t.Fatalf("успешный вход должен снимать общую блокировку, а не только персональную по IP")
	}
}
