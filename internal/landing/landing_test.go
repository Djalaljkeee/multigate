package landing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/store"
)

func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "landing_test.db")
	db, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	return db
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestServesBlankByDefault(t *testing.T) {
	db := openTestDB(t) // store.KeyDecoyTheme по умолчанию "blank"
	h := New(db)

	rec := get(t, h, "/sub/whatever-looks-like-a-subscription-path")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, ждали 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type %q, ждали text/html", ct)
	}
	if rec.Header().Get("X-Robots-Tag") != "noindex, nofollow" {
		t.Errorf("X-Robots-Tag %q, ждали noindex, nofollow", rec.Header().Get("X-Robots-Tag"))
	}
	if rec.Body.Len() > 1024 {
		t.Errorf("пустая тема весит %d байт, ждали единицы сотен байт", rec.Body.Len())
	}
	if !strings.Contains(rec.Body.String(), "<body></body>") {
		t.Errorf("пустая тема должна отдавать пустой body: %s", rec.Body.String())
	}
}

func TestServesMaintenanceTheme(t *testing.T) {
	db := openTestDB(t)
	if err := db.Set(context.Background(), store.KeyDecoyTheme, "maintenance"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}
	h := New(db)

	rec := get(t, h, "/")
	body := rec.Body.String()
	if !strings.Contains(strings.ToLower(body), "maintenance") {
		t.Errorf("ожидали упоминание maintenance в теле: %s", body)
	}
}

func TestServesParkingTheme(t *testing.T) {
	db := openTestDB(t)
	if err := db.Set(context.Background(), store.KeyDecoyTheme, "parking"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}
	h := New(db)

	rec := get(t, h, "/")
	body := strings.ToLower(rec.Body.String())
	if !strings.Contains(body, "domain") {
		t.Errorf("ожидали упоминание domain в теле заглушки парковки: %s", body)
	}
}

func TestUnknownThemeFallsBackToBlank(t *testing.T) {
	db := openTestDB(t)
	if err := db.Set(context.Background(), store.KeyDecoyTheme, "this-theme-does-not-exist"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}
	h := New(db)

	rec := get(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, ждали 200 даже для неизвестной темы", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<body></body>") {
		t.Errorf("неизвестная тема должна откатываться на blank: %s", rec.Body.String())
	}
}

func TestNilDBUsesDefaultTheme(t *testing.T) {
	h := New(nil)
	rec := get(t, h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, ждали 200 при db=nil", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<body></body>") {
		t.Errorf("db=nil должен давать тему по умолчанию (blank): %s", rec.Body.String())
	}
}

func TestRobotsTxt(t *testing.T) {
	db := openTestDB(t)
	h := New(db)

	rec := get(t, h, "/robots.txt")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, ждали 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type %q, ждали text/plain", ct)
	}
	if rec.Header().Get("X-Robots-Tag") == "" {
		t.Error("robots.txt тоже должен сопровождаться заголовком X-Robots-Tag")
	}
	if !strings.Contains(rec.Body.String(), "Disallow: /") {
		t.Errorf("robots.txt должен запрещать индексацию целиком: %s", rec.Body.String())
	}
}

// forbiddenWords перечисляет всё, что выдало бы истинное назначение сервиса.
// Ни одно из этих слов не должно встречаться в HTML ни одной темы,
// ни в её заголовках ответа.
var forbiddenWords = []string{
	"vpn", "vless", "vmess", "xray", "sing-box", "mihomo", "clash",
	"remnawave", "multigate", "panel", "панел", "прослойк", "подписк",
	"subscription", "proxy", "прокси", "webhook", "wireguard", "amnezia",
}

func TestThemesHaveNoServiceHints(t *testing.T) {
	db := openTestDB(t)

	for theme := range themeFiles {
		t.Run(theme, func(t *testing.T) {
			if err := db.Set(context.Background(), store.KeyDecoyTheme, theme); err != nil {
				t.Fatalf("db.Set: %v", err)
			}
			h := New(db)
			rec := get(t, h, "/")
			body := strings.ToLower(rec.Body.String())

			for _, w := range forbiddenWords {
				if strings.Contains(body, w) {
					t.Errorf("тема %q содержит запрещённое слово %q", theme, w)
				}
			}
			for name, vals := range rec.Header() {
				for _, v := range vals {
					low := strings.ToLower(name + ": " + v)
					for _, w := range forbiddenWords {
						if strings.Contains(low, w) {
							t.Errorf("заголовок %s темы %q содержит запрещённое слово %q", name, theme, w)
						}
					}
				}
			}
		})
	}
}

func TestThemesHaveNoExternalReferences(t *testing.T) {
	db := openTestDB(t)
	for theme := range themeFiles {
		t.Run(theme, func(t *testing.T) {
			if err := db.Set(context.Background(), store.KeyDecoyTheme, theme); err != nil {
				t.Fatalf("db.Set: %v", err)
			}
			h := New(db)
			rec := get(t, h, "/")
			body := rec.Body.String()
			if strings.Contains(body, "://") {
				t.Errorf("тема %q ссылается на внешний ресурс: %s", theme, body)
			}
		})
	}
}

func TestThemesAreLightweight(t *testing.T) {
	db := openTestDB(t)
	for theme := range themeFiles {
		t.Run(theme, func(t *testing.T) {
			if err := db.Set(context.Background(), store.KeyDecoyTheme, theme); err != nil {
				t.Fatalf("db.Set: %v", err)
			}
			h := New(db)
			rec := get(t, h, "/")
			// "единицы килобайт", с большим запасом ограничиваем 8 КБ.
			if rec.Body.Len() > 8*1024 {
				t.Errorf("тема %q весит %d байт, это больше единиц килобайт", theme, rec.Body.Len())
			}
		})
	}
}

func TestThemesSupportBothColorSchemes(t *testing.T) {
	db := openTestDB(t)
	for theme := range themeFiles {
		t.Run(theme, func(t *testing.T) {
			if err := db.Set(context.Background(), store.KeyDecoyTheme, theme); err != nil {
				t.Fatalf("db.Set: %v", err)
			}
			h := New(db)
			rec := get(t, h, "/")
			body := rec.Body.String()
			if !strings.Contains(body, "prefers-color-scheme") && !strings.Contains(body, "color-scheme") {
				t.Errorf("тема %q не учитывает тёмную/светлую схему браузера", theme)
			}
		})
	}
}
