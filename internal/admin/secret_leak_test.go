package admin

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/store"
)

// TestPanelTokenNeverLeaksToHTML проверяет требование безопасности отдельно
// от остальных сценариев: токен панели не должен появляться в HTML ни на
// одной странице, даже если он уже сохранён в базе: форма настроек обязана
// показывать только факт "токен задан", а не его значение.
func TestPanelTokenNeverLeaksToHTML(t *testing.T) {
	db := newTestStore(t)
	markInstalled(t, db, "admin", "correct-horse-battery")
	secret := "SUPER-SECRET-PANEL-TOKEN-VALUE"
	if err := db.Set(context.Background(), store.KeyPanelToken, secret); err != nil {
		t.Fatalf("Set: %v", err)
	}
	h := newTestHandler(t, db, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	_, lbody := getBody(t, c, srv.URL+"/admin/login")
	csrf := extractCSRF(t, lbody)
	resp, err := c.PostForm(srv.URL+"/admin/login", url.Values{
		"username": {"admin"}, "password": {"correct-horse-battery"}, "csrf": {csrf},
	})
	if err != nil {
		t.Fatalf("вход: %v", err)
	}
	resp.Body.Close()

	pages := []string{"/admin/overview", "/admin/settings", "/admin/about"}
	for _, p := range pages {
		_, body := getBody(t, c, srv.URL+p)
		if strings.Contains(body, secret) {
			t.Fatalf("%s: секрет токена панели утёк в HTML", p)
		}
	}
}

// TestChatAndWebhookSecretsNeverLeakToHTML проверяет то же требование, что и
// TestPanelTokenNeverLeaksToHTML, для двух новых секретных полей формы
// настроек: токена бота Telegram и секрета входящих вебхуков. Оба обязаны
// показываться только флагом «задан», а не настоящим значением.
func TestChatAndWebhookSecretsNeverLeakToHTML(t *testing.T) {
	db := newTestStore(t)
	markInstalled(t, db, "admin", "correct-horse-battery")
	botToken := "TELEGRAM-BOT-SUPER-SECRET-TOKEN"
	webhookSecret := "WEBHOOK-SUPER-SECRET-VALUE"
	if err := db.SetMany(context.Background(), map[string]string{
		store.KeyChatTGToken:   botToken,
		store.KeyWebhookSecret: webhookSecret,
	}); err != nil {
		t.Fatalf("SetMany: %v", err)
	}
	h := newTestHandler(t, db, nil)
	srv := httptest.NewServer(h)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	_, lbody := getBody(t, c, srv.URL+"/admin/login")
	csrf := extractCSRF(t, lbody)
	resp, err := c.PostForm(srv.URL+"/admin/login", url.Values{
		"username": {"admin"}, "password": {"correct-horse-battery"}, "csrf": {csrf},
	})
	if err != nil {
		t.Fatalf("вход: %v", err)
	}
	resp.Body.Close()

	pages := []string{"/admin/overview", "/admin/settings", "/admin/about"}
	for _, p := range pages {
		_, body := getBody(t, c, srv.URL+p)
		if strings.Contains(body, botToken) {
			t.Fatalf("%s: секрет токена бота Telegram утёк в HTML", p)
		}
		if strings.Contains(body, webhookSecret) {
			t.Fatalf("%s: секрет вебхука утёк в HTML", p)
		}
	}

	// Форма настроек обязана явно сообщать, что секреты уже заданы (иначе
	// администратор не отличит «секрет не задан» от «значение скрыто»), но
	// именно фактом задания, а не значением.
	_, settingsBody := getBody(t, c, srv.URL+"/admin/settings")
	if !strings.Contains(settingsBody, "оставьте пустым, чтобы не менять") {
		t.Fatalf("форма настроек не показывает, что секреты уже заданы")
	}
}
