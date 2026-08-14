package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// stubPanel: управляемая заглушка Panel для тестов: пусть сами тесты решают,
// отвечает ли "панель" и что именно.
type stubPanel struct {
	info    model.PanelInfo
	infoErr error
	listErr error
}

func (p *stubPanel) Info(ctx context.Context) (model.PanelInfo, error) { return p.info, p.infoErr }
func (p *stubPanel) ListUsers(ctx context.Context, offset, limit int, search string) ([]model.PanelUser, int, error) {
	return nil, 0, p.listErr
}
func (p *stubPanel) UserByShortUUID(ctx context.Context, shortUUID string) (model.PanelUser, error) {
	return model.PanelUser{}, p.listErr
}
func (p *stubPanel) Devices(ctx context.Context, userRef string) ([]model.Device, error) {
	return nil, p.listErr
}
func (p *stubPanel) DeleteDevice(ctx context.Context, userRef, hwid string) error { return p.listErr }
func (p *stubPanel) Squads(ctx context.Context) ([]model.Squad, error)            { return nil, p.listErr }
func (p *stubPanel) SystemStats(ctx context.Context) (map[string]any, error)      { return nil, p.listErr }

// newTestStore поднимает настоящую SQLite-базу во временном каталоге:
// admin пользуется публичными RW()/RO() напрямую (правила заголовков),
// поэтому мок хранилища здесь не годится: нужна реальная схема.
func newTestStore(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "admin_test.db")
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	return db
}

// newTestHandler собирает обработчик поверх временной базы. panel может быть nil.
func newTestHandler(t *testing.T, db *store.DB, panel Panel) *Handler {
	t.Helper()
	h, err := New(Deps{
		Store:    db,
		Panel:    panel,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		BasePath: "/admin",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Close останавливает фоновую уборку просроченных сессий (см. session.go):
	// без этого каждый тест, создающий Handler, оставлял бы висеть горутину
	// с тикером до конца всего прогона пакета.
	t.Cleanup(h.Close)
	return h
}

// markInstalled проводит "мастер настройки" напрямую через store, без HTTP:
// тестам входа не нужно каждый раз гонять форму мастера. bcrypt.MinCost
// вместо боевого DefaultCost: иначе тесты входа заметно тормозят.
func markInstalled(t *testing.T, db *store.DB, user, pass string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	err = db.SetMany(context.Background(), map[string]string{
		store.KeyInstalled: "1",
		store.KeyAdminUser: user,
		store.KeyAdminHash: string(hash),
		store.KeyMode:      "mirror",
	})
	if err != nil {
		t.Fatalf("SetMany: %v", err)
	}
}

// noRedirectClient не ходит по Location сам: тестам редиректов нужен именно
// код 303 и адрес, а не то, что лежит по другую сторону.
func noRedirectClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// extractCSRF вытаскивает токен формы из тела HTML-страницы.
func extractCSRF(t *testing.T, body string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("не нашли csrf-токен в ответе: %s", body)
	}
	return m[1]
}

func getBody(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("читаем тело: %v", err)
	}
	return resp, string(b)
}

// ---------- редирект неавторизованного ----------

func TestUnauthenticatedRedirects(t *testing.T) {
	t.Run("мастер настройки, если ничего не установлено", func(t *testing.T) {
		db := newTestStore(t)
		h := newTestHandler(t, db, nil)
		srv := httptest.NewServer(h)
		defer srv.Close()

		c := noRedirectClient()
		resp, _ := getBody(t, c, srv.URL+"/admin/overview")
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("ожидали 303, получили %d", resp.StatusCode)
		}
		loc := resp.Header.Get("Location")
		if !strings.HasSuffix(loc, "/admin/setup") {
			t.Fatalf("ожидали редирект на /admin/setup, получили %q", loc)
		}
	})

	t.Run("логин, если настройка пройдена, но сессии нет", func(t *testing.T) {
		db := newTestStore(t)
		markInstalled(t, db, "admin", "correct-horse")
		h := newTestHandler(t, db, nil)
		srv := httptest.NewServer(h)
		defer srv.Close()

		c := noRedirectClient()
		resp, _ := getBody(t, c, srv.URL+"/admin/overview")
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("ожидали 303, получили %d", resp.StatusCode)
		}
		loc := resp.Header.Get("Location")
		if !strings.HasSuffix(loc, "/admin/login") {
			t.Fatalf("ожидали редирект на /admin/login, получили %q", loc)
		}
	})

	t.Run("защищённые POST тоже требуют сессию", func(t *testing.T) {
		db := newTestStore(t)
		markInstalled(t, db, "admin", "correct-horse")
		h := newTestHandler(t, db, nil)
		srv := httptest.NewServer(h)
		defer srv.Close()

		c := noRedirectClient()
		resp, err := c.PostForm(srv.URL+"/admin/overrides", url.Values{"short_uuid": {"x"}})
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("ожидали 303 на неавторизованный POST, получили %d", resp.StatusCode)
		}
	})
}

// ---------- вход по паролю ----------

func TestLoginFlow(t *testing.T) {
	db := newTestStore(t)
	markInstalled(t, db, "admin", "correct-horse-battery")
	h := newTestHandler(t, db, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	t.Run("неверный пароль не пускает", func(t *testing.T) {
		_, body := getBody(t, c, srv.URL+"/admin/login")
		csrf := extractCSRF(t, body)

		resp, err := c.PostForm(srv.URL+"/admin/login", url.Values{
			"username": {"admin"},
			"password": {"wrong-password"},
			"csrf":     {csrf},
		})
		if err != nil {
			t.Fatalf("POST /login: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("ожидали 401 при неверном пароле, получили %d", resp.StatusCode)
		}
	})

	t.Run("верный пароль пускает в админку", func(t *testing.T) {
		_, body := getBody(t, c, srv.URL+"/admin/login")
		csrf := extractCSRF(t, body)

		resp, err := c.PostForm(srv.URL+"/admin/login", url.Values{
			"username": {"admin"},
			"password": {"correct-horse-battery"},
			"csrf":     {csrf},
		})
		if err != nil {
			t.Fatalf("POST /login: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ожидали 200 после перехода по редиректу входа, получили %d", resp.StatusCode)
		}

		// Сессия из формы логина должна давать доступ к защищённым страницам.
		resp2, body2 := getBody(t, c, srv.URL+"/admin/overview")
		if resp2.StatusCode != http.StatusOK {
			t.Fatalf("ожидали 200 на /overview после входа, получили %d", resp2.StatusCode)
		}
		if !strings.Contains(body2, "Обзор") {
			t.Fatalf("на странице обзора нет ожидаемого заголовка")
		}
	})
}

// ---------- отказ при неверном CSRF ----------

func TestCSRFRejected(t *testing.T) {
	db := newTestStore(t)
	markInstalled(t, db, "admin", "correct-horse-battery")
	h := newTestHandler(t, db, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	_, body := getBody(t, c, srv.URL+"/admin/login")
	csrf := extractCSRF(t, body)
	resp, err := c.PostForm(srv.URL+"/admin/login", url.Values{
		"username": {"admin"}, "password": {"correct-horse-battery"}, "csrf": {csrf},
	})
	if err != nil {
		t.Fatalf("вход: %v", err)
	}
	resp.Body.Close()

	t.Run("подделанный токен отклоняется", func(t *testing.T) {
		resp, err := c.PostForm(srv.URL+"/admin/overrides", url.Values{
			"short_uuid": {"deadbeef"},
			"csrf":       {"это-не-тот-токен"},
		})
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("ожидали 403 при неверном csrf, получили %d", resp.StatusCode)
		}
	})

	t.Run("пустой токен отклоняется", func(t *testing.T) {
		resp, err := c.PostForm(srv.URL+"/admin/overrides", url.Values{
			"short_uuid": {"deadbeef"},
		})
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("ожидали 403 при отсутствии csrf, получили %d", resp.StatusCode)
		}
	})

	list, err := db.ListOverrides(context.Background())
	if err != nil {
		t.Fatalf("ListOverrides: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("подделанный запрос не должен был ничего создать, а в базе %d записей", len(list))
	}
}

// ---------- админка открывается при недоступной панели ----------

func TestAdminWorksWithoutPanel(t *testing.T) {
	t.Run("панель вообще не настроена", func(t *testing.T) {
		db := newTestStore(t)
		markInstalled(t, db, "admin", "correct-horse-battery")
		h := newTestHandler(t, db, nil) // Panel == nil
		srv := httptest.NewServer(h)
		defer srv.Close()

		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar}
		_, body := getBody(t, c, srv.URL+"/admin/login")
		csrf := extractCSRF(t, body)
		resp, err := c.PostForm(srv.URL+"/admin/login", url.Values{
			"username": {"admin"}, "password": {"correct-horse-battery"}, "csrf": {csrf},
		})
		if err != nil {
			t.Fatalf("вход: %v", err)
		}
		resp.Body.Close()

		resp2, body2 := getBody(t, c, srv.URL+"/admin/overview")
		if resp2.StatusCode != http.StatusOK {
			t.Fatalf("обзор должен открываться и без панели, получили %d", resp2.StatusCode)
		}

		resp3, body3 := getBody(t, c, srv.URL+"/admin/users")
		if resp3.StatusCode != http.StatusOK {
			t.Fatalf("список пользователей должен открываться и без панели, получили %d", resp3.StatusCode)
		}
		if !strings.Contains(body3, "не подключена") && !strings.Contains(body3, "недоступна") {
			t.Fatalf("страница пользователей должна объяснять, что панели нет: %s", body3)
		}
		_ = body2
	})

	t.Run("панель настроена, но недоступна по сети", func(t *testing.T) {
		db := newTestStore(t)
		markInstalled(t, db, "admin", "correct-horse-battery")
		panel := &stubPanel{
			info:    model.PanelInfo{Reachable: false, Err: "connection refused"},
			listErr: context.DeadlineExceeded,
		}
		h := newTestHandler(t, db, panel)
		srv := httptest.NewServer(h)
		defer srv.Close()

		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar}
		_, body := getBody(t, c, srv.URL+"/admin/login")
		csrf := extractCSRF(t, body)
		resp, err := c.PostForm(srv.URL+"/admin/login", url.Values{
			"username": {"admin"}, "password": {"correct-horse-battery"}, "csrf": {csrf},
		})
		if err != nil {
			t.Fatalf("вход: %v", err)
		}
		resp.Body.Close()

		resp2, body2 := getBody(t, c, srv.URL+"/admin/overview")
		if resp2.StatusCode != http.StatusOK {
			t.Fatalf("обзор должен открываться при недоступной панели, получили %d", resp2.StatusCode)
		}
		if !strings.Contains(body2, "недоступна") && !strings.Contains(body2, "connection refused") {
			t.Fatalf("обзор должен показывать недоступность панели: %s", body2)
		}

		resp3, body3 := getBody(t, c, srv.URL+"/admin/users")
		if resp3.StatusCode != http.StatusOK {
			t.Fatalf("список пользователей должен открываться при недоступной панели, получили %d", resp3.StatusCode)
		}
		if !strings.Contains(body3, "Не удалось получить список пользователей") {
			t.Fatalf("страница пользователей должна объяснять ошибку панели: %s", body3)
		}
	})
}
