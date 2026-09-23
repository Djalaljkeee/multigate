package subpage

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// testConfig повторяет форму конфига «Default» из панели: платформы
// объектом (порядок важен), у приложения шаги с кнопками обоих типов.
const testConfig = `{
  "locales": ["ru", "en"],
  "version": "1",
  "brandingSettings": {"title": "DJ VPN", "logoUrl": "https://example.com/logo.jpg", "supportUrl": "https://t.me/help"},
  "baseSettings": {"metaTitle": "Sub", "hideGetLinkButton": false, "showConnectionKeys": false},
  "baseTranslations": {"expires": {"ru": "Истекает", "en": "Expires"}},
  "svgLibrary": {"Plus": "<svg id=\"plus\"></svg>", "Happ": "<svg id=\"happ-icon\"></svg>"},
  "platforms": {
    "windows": {"displayName": {"ru": "Windows"}, "svgIconKey": "Windows", "apps": [
      {"name": "INCY", "featured": true, "blocks": [
        {"title": {"ru": "Установка"}, "description": {"ru": "Скачайте"}, "svgIconColor": "violet",
         "buttons": [{"type": "external", "link": "https://example.com/incy.exe", "text": {"ru": "Скачать"}}]},
        {"title": {"ru": "Подписка"}, "svgIconColor": "cyan",
         "buttons": [{"type": "subscriptionLink", "link": "incy://import/{{SUBSCRIPTION_LINK}}", "text": {"ru": "Добавить"}, "svgIconKey": "Plus"}]}
      ]}
    ]},
    "android": {"displayName": {"ru": "Android"}, "apps": [
      {"name": "Happ", "blocks": [
        {"title": {"ru": "Подписка"}, "buttons": [
          {"type": "subscriptionLink", "link": "{{HAPP_CRYPT4_LINK}}", "text": {"ru": "Добавить в Happ"}},
          {"type": "external", "link": "javascript:alert(1)", "text": {"ru": "Плохая"}}
        ]}
      ]}
    ]},
    "linux": {"displayName": {"ru": "Linux"}, "apps": []}
  }
}`

func TestParseConfigKeepsPlatformOrder(t *testing.T) {
	cfg, err := ParseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, p := range cfg.Platforms {
		keys = append(keys, p.Key)
	}
	// linux без приложений отбрасывается, остальные в порядке из панели.
	if got := strings.Join(keys, ","); got != "windows,android" {
		t.Fatalf("платформы = %s", got)
	}
	if cfg.Branding.Title != "DJ VPN" || cfg.SVG["Plus"] == "" {
		t.Fatalf("оформление не разобрано: %+v", cfg.Branding)
	}
}

func TestParseConfigRejectsEmpty(t *testing.T) {
	if _, err := ParseConfig([]byte(`{"platforms": {}}`)); err == nil {
		t.Fatal("конфиг без платформ принят")
	}
}

type fakePanel struct {
	info    model.SubInfo
	infoErr error
	ref     model.SubpageRef
	config  string
	calls   int
}

func (f *fakePanel) SubscriptionInfo(context.Context, string) (model.SubInfo, error) {
	return f.info, f.infoErr
}

func (f *fakePanel) SubpageRef(context.Context, string, http.Header) (model.SubpageRef, error) {
	return f.ref, nil
}

func (f *fakePanel) SubpageConfig(context.Context, string) (json.RawMessage, error) {
	f.calls++
	return json.RawMessage(f.config), nil
}

func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), "sqlite://"+filepath.Join(t.TempDir(), "subpage.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db
}

func activePanel() *fakePanel {
	return &fakePanel{
		info: model.SubInfo{
			ShortUUID: "abc", Username: "us_1", Status: "ACTIVE", IsActive: true,
			ExpiresAt: time.Date(2026, 10, 11, 14, 0, 0, 0, time.UTC), DaysLeft: 18,
			TrafficUsedBytes: 5 << 30, TrafficLimitBytes: 800 << 30,
			SubscriptionURL: "https://sub.example.com/sub/abc",
		},
		ref:    model.SubpageRef{WebpageAllowed: true},
		config: testConfig,
	}
}

func serve(t *testing.T, p *Page, platform model.Platform) (*httptest.ResponseRecorder, error) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/sub/abc", nil)
	rec := httptest.NewRecorder()
	_, _, err := p.Serve(rec, req, "abc", platform)
	return rec, err
}

func TestServeRendersPage(t *testing.T) {
	db := openTestDB(t)
	panel := activePanel()
	p := New(db, panel, nil)

	rec, err := serve(t, p, model.PlatformAndroid)
	if err != nil {
		t.Fatal(err)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"DJ VPN",
		"https://example.com/logo.jpg",
		"11.10.2026", "ещё 18 дней",
		">5 ГБ<", ">из 800 ГБ<",
		`href="incy://import/https://sub.example.com/sub/abc"`,
		`href="happ://crypt4/`,
		`<svg id="plus"></svg>`,
		`id="sub-url">https://sub.example.com/sub/abc<`,
		`data-platform="android" aria-selected="true"`,
		"Истекает",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("на странице нет %q", want)
		}
	}
	if strings.Contains(body, "javascript:") {
		t.Error("опасная ссылка попала на страницу")
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q", got)
	}

	// Конфиг кэшируется: вторая страница не ходит за ним в панель.
	if _, err := serve(t, p, model.PlatformIOS); err != nil {
		t.Fatal(err)
	}
	if panel.calls != 1 {
		t.Errorf("конфиг запрошен %d раз, ждали 1", panel.calls)
	}
}

func TestServeSettingsOverrideBranding(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeySubpageLogoURL, "https://lk.example.com/favicon.svg"); err != nil {
		t.Fatal(err)
	}
	if err := db.Set(ctx, store.KeyBrandSupportURL, "https://t.me/new_support"); err != nil {
		t.Fatal(err)
	}
	rec, err := serve(t, New(db, activePanel(), nil), model.PlatformUnknown)
	if err != nil {
		t.Fatal(err)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "https://lk.example.com/favicon.svg") || strings.Contains(body, "logo.jpg") {
		t.Error("логотип из настроек не подменил логотип панели")
	}
	if !strings.Contains(body, "https://t.me/new_support") {
		t.Error("ссылка поддержки из настроек не подменила ссылку панели")
	}
	// Неизвестная платформа: открыта первая вкладка.
	if !strings.Contains(body, `data-platform="windows" aria-selected="true"`) {
		t.Error("для неизвестной платформы не открыта первая вкладка")
	}
}

func TestServeUnavailable(t *testing.T) {
	db := openTestDB(t)

	notFound := activePanel()
	notFound.infoErr = model.ErrNotFound
	forbidden := activePanel()
	forbidden.ref.WebpageAllowed = false
	broken := activePanel()
	broken.config = `{"platforms": {}}`

	for name, panel := range map[string]*fakePanel{"нет подписки": notFound, "панель запретила": forbidden, "пустой конфиг": broken} {
		t.Run(name, func(t *testing.T) {
			rec, err := serve(t, New(db, panel, nil), model.PlatformIOS)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err = %v, ждали ErrUnavailable", err)
			}
			if rec.Body.Len() != 0 || rec.Code != http.StatusOK || len(rec.Header()) != 0 {
				t.Fatal("при ошибке в ответ что-то записано")
			}
		})
	}
}

func TestHappCryptoLink(t *testing.T) {
	for _, v := range []string{"v3", "v4"} {
		l, err := HappCryptoLink("https://sub.example.com/sub/abc", v)
		if err != nil {
			t.Fatal(err)
		}
		// RSA-4096: 512 байт шифротекста, 684 символа base64.
		if !strings.HasPrefix(l, "happ://crypt"+v[1:]+"/") || len(l) != len("happ://cryptN/")+684 {
			t.Fatalf("%s: неожиданная ссылка %q", v, l)
		}
	}
}

func TestDaysText(t *testing.T) {
	for n, want := range map[int]string{1: "ещё 1 день", 3: "ещё 3 дня", 5: "ещё 5 дней", 11: "ещё 11 дней", 21: "ещё 21 день", 112: "ещё 112 дней"} {
		if got := daysText(n); got != want {
			t.Errorf("daysText(%d) = %q, ждали %q", n, got, want)
		}
	}
}

func TestPickLang(t *testing.T) {
	cases := []struct {
		accept  string
		locales []string
		want    string
	}{
		{"en-US,en;q=0.9", []string{"ru", "en"}, "en"},
		{"fr-FR", []string{"ru", "en"}, "ru"},
		{"", []string{"ru", "en"}, "ru"},
	}
	for _, c := range cases {
		if got := pickLang(c.accept, c.locales); got != c.want {
			t.Errorf("pickLang(%q) = %q, ждали %q", c.accept, got, c.want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{512: "512 Б", 1536: "1,5 КБ", 5 << 30: "5 ГБ", 17898668994: "16,7 ГБ"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, ждали %q", n, got, want)
		}
	}
}
