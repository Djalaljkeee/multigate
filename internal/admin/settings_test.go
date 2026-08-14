package admin

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/store"
)

// settingsTestLogin логинится через настоящий HTTP-путь и возвращает клиента
// с валидной сессией: форме настроек ниже нужен CSRF-токен именно этой сессии.
func settingsTestLogin(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
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
	return c
}

// baseSettingsForm собирает минимальный валидный набор полей формы
// настроек (всё, что require'ится независимо от новых флагов): тесты ниже
// дополняют его конкретными полями через v.Set(...).
func baseSettingsForm(csrf string) url.Values {
	return url.Values{
		"mode":             {"mirror"},
		"mirror_target":    {"panel.example.com"},
		"log_keep_days":    {"14"},
		"cache_ttl":        {"0"},
		"upstream_timeout": {"15"},
		"update_interval":  {"12"},
		"grace_hours":      {"24"},
		"csrf":             {csrf},
	}
}

// TestSettingsSaveNewFeatureFlags проверяет находку «половину возможностей
// нельзя включить»: все перечисленные в ней ключи должны сохраняться через
// обычную форму настроек.
func TestSettingsSaveNewFeatureFlags(t *testing.T) {
	db := newTestStore(t)
	markInstalled(t, db, "admin", "correct-horse-battery")
	h := newTestHandler(t, db, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := settingsTestLogin(t, srv)

	_, formBody := getBody(t, c, srv.URL+"/admin/settings")
	csrf := extractCSRF(t, formBody)

	form := baseSettingsForm(csrf)
	form.Set("hwid_enforce", "on")
	form.Set("grace_enabled", "on")
	form.Set("grace_squad", "11111111-1111-1111-1111-111111111111")
	form.Set("grace_hours", "48")
	form.Set("chat_enabled", "on")
	form.Set("chat_tg_chat", "-100123456")
	form.Set("chat_tg_api_base", "https://api.telegram.org")
	form.Set("chat_tg_token", "secret-bot-token")
	form.Set("webhook_secret", "secret-webhook-value")
	form.Set("wg_pool_enabled", "on")
	form.Set("trusted_proxies", "10.0.0.0/8")

	resp, err := c.PostForm(srv.URL+"/admin/settings", form)
	if err != nil {
		t.Fatalf("POST /settings: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("ожидали 200 после сохранения (клиент сам идёт по редиректу), получили %d: %s", resp.StatusCode, b)
	}

	ctx := context.Background()
	checks := map[string]string{
		store.KeyHWIDEnforce:    "1",
		store.KeyGraceEnabled:   "1",
		store.KeyGraceSquad:     "11111111-1111-1111-1111-111111111111",
		store.KeyGraceHours:     "48",
		store.KeyChatEnabled:    "1",
		store.KeyChatTGChat:     "-100123456",
		store.KeyChatTGAPIBase:  "https://api.telegram.org",
		store.KeyChatTGToken:    "secret-bot-token",
		store.KeyWebhookSecret:  "secret-webhook-value",
		store.KeyWGPoolEnabled:  "1",
		store.KeyTrustedProxies: "10.0.0.0/8",
	}
	for key, want := range checks {
		if got := db.Get(ctx, key); got != want {
			t.Fatalf("%s: ожидали %q, получили %q", key, want, got)
		}
	}
}

// TestSettingsSaveValidatesNewFields проверяет требуемую валидацию полей:
// часы грейса принимаются только числом, адрес API Telegram только
// корректным URL, а сквад грейса не должен быть пустым.
func TestSettingsSaveValidatesNewFields(t *testing.T) {
	db := newTestStore(t)
	markInstalled(t, db, "admin", "correct-horse-battery")
	h := newTestHandler(t, db, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := settingsTestLogin(t, srv)

	cases := []struct {
		name   string
		mutate func(url.Values)
	}{
		{
			name: "грейс включён без идентификатора сквада",
			mutate: func(v url.Values) {
				v.Set("grace_enabled", "on")
				v.Set("grace_squad", "")
			},
		},
		{
			name: "часы грейса не число",
			mutate: func(v url.Values) {
				v.Set("grace_hours", "не число")
			},
		},
		{
			name: "адрес API Telegram не похож на URL",
			mutate: func(v url.Values) {
				v.Set("chat_tg_api_base", "совсем-не-url")
			},
		},
		{
			name: "чат включён без адреса API",
			mutate: func(v url.Values) {
				v.Set("chat_enabled", "on")
				v.Set("chat_tg_api_base", "")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, formBody := getBody(t, c, srv.URL+"/admin/settings")
			csrf := extractCSRF(t, formBody)
			form := baseSettingsForm(csrf)
			tc.mutate(form)

			resp, err := c.PostForm(srv.URL+"/admin/settings", form)
			if err != nil {
				t.Fatalf("POST /settings: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnprocessableEntity {
				t.Fatalf("ожидали 422 при некорректных данных, получили %d", resp.StatusCode)
			}
		})
	}
}

// TestSettingsClearSecrets проверяет чекбоксы «убрать сохранённый
// токен/секрет» для новых замаскированных полей: по тому же образцу, что
// уже работает для токена панели.
func TestSettingsClearSecrets(t *testing.T) {
	db := newTestStore(t)
	markInstalled(t, db, "admin", "correct-horse-battery")
	if err := db.SetMany(context.Background(), map[string]string{
		store.KeyChatTGToken:   "old-bot-token",
		store.KeyWebhookSecret: "old-webhook-secret",
	}); err != nil {
		t.Fatalf("SetMany: %v", err)
	}
	h := newTestHandler(t, db, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := settingsTestLogin(t, srv)

	_, formBody := getBody(t, c, srv.URL+"/admin/settings")
	csrf := extractCSRF(t, formBody)
	form := baseSettingsForm(csrf)
	form.Set("chat_tg_token_clear", "1")
	form.Set("webhook_secret_clear", "1")

	resp, err := c.PostForm(srv.URL+"/admin/settings", form)
	if err != nil {
		t.Fatalf("POST /settings: %v", err)
	}
	resp.Body.Close()

	ctx := context.Background()
	if got := db.Get(ctx, store.KeyChatTGToken); got != "" {
		t.Fatalf("токен бота должен был очиститься, остался %q", got)
	}
	if got := db.Get(ctx, store.KeyWebhookSecret); got != "" {
		t.Fatalf("секрет вебхука должен был очиститься, остался %q", got)
	}
}

// TestSettingsFormNoLongerHasLogBodiesCheckbox: фиксация решения по
// находке о переключателях журнала. Раз тела ответов прослойка пока не
// умеет писать условно, галочку убрали из формы, чтобы интерфейс не врал
// о несуществующей возможности. «Писать журнал запросов» при этом остаётся.
func TestSettingsFormNoLongerHasLogBodiesCheckbox(t *testing.T) {
	db := newTestStore(t)
	markInstalled(t, db, "admin", "correct-horse-battery")
	h := newTestHandler(t, db, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := settingsTestLogin(t, srv)

	_, body := getBody(t, c, srv.URL+"/admin/settings")
	if !strings.Contains(body, `name="log_enabled"`) {
		t.Fatalf("форма настроек должна оставить переключатель «Писать журнал запросов»")
	}
	if strings.Contains(body, `name="log_bodies"`) {
		t.Fatalf("форма настроек всё ещё показывает нереализованную галочку «Писать тела ответов»")
	}
}
