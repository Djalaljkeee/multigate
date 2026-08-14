package admin

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
)

// fullStubPanel: заглушка Panel, отвечающая настоящими данными: часть
// шаблонов (карточка пользователя, список с результатами) ни разу не
// исполняется в сценарных тестах выше, где панель либо nil, либо ошибается.
type fullStubPanel struct{}

func (fullStubPanel) Info(ctx context.Context) (model.PanelInfo, error) {
	return model.PanelInfo{Version: "3.2.2", Major: 3, Reachable: true, CheckedAt: time.Now()}, nil
}

func (fullStubPanel) ListUsers(ctx context.Context, offset, limit int, search string) ([]model.PanelUser, int, error) {
	return []model.PanelUser{{
		Ref: "1", UUID: "u-1", ShortUUID: "short-1", Username: "ivan",
		Status: "ACTIVE", ExpireAt: time.Now().Add(30 * 24 * time.Hour),
		TrafficLimitBytes: 10 << 30, UsedTrafficBytes: 1 << 30, HWIDDeviceLimit: 3,
		Squads: []string{"sq-1"},
	}}, 1, nil
}

func (fullStubPanel) UserByShortUUID(ctx context.Context, shortUUID string) (model.PanelUser, error) {
	return model.PanelUser{
		Ref: "1", UUID: "u-1", ShortUUID: shortUUID, Username: "ivan",
		Status: "ACTIVE", ExpireAt: time.Now().Add(30 * 24 * time.Hour),
		TrafficLimitBytes: 10 << 30, UsedTrafficBytes: 1 << 30, HWIDDeviceLimit: 3,
		TelegramID: 12345, Email: "ivan@example.com", Tag: "vip",
		Squads: []string{"sq-1", "sq-missing"},
	}, nil
}

func (fullStubPanel) Devices(ctx context.Context, userRef string) ([]model.Device, error) {
	return []model.Device{{
		HWID: "hwid-1", Platform: "ios", OSVersion: "17.1", Device: "iPhone",
		AppVersion: "2.1", CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}}, nil
}

func (fullStubPanel) DeleteDevice(ctx context.Context, userRef, hwid string) error { return nil }

func (fullStubPanel) Squads(ctx context.Context) ([]model.Squad, error) {
	return []model.Squad{{UUID: "sq-1", Name: "Основной", Members: 5}}, nil
}

func (fullStubPanel) SystemStats(ctx context.Context) (map[string]any, error) {
	return map[string]any{"users_online": 42, "nodes": 3}, nil
}

// TestAllPagesRender проходит по всем защищённым GET-страницам и проверяет,
// что каждая отдаёт 200 без "внутренняя ошибка шаблона": сценарные тесты
// выше не заходят на часть вкладок (журнал, блокировки, настройки, о системе,
// карточка пользователя), а именно там чаще всего опечатка в имени поля
// шаблона превращается в панику ExecuteTemplate.
func TestAllPagesRender(t *testing.T) {
	db := newTestStore(t)
	markInstalled(t, db, "admin", "correct-horse-battery")

	// Немного данных, чтобы таблицы страниц не были все сплошь пустыми.
	ctx := context.Background()
	if _, err := db.AddOverride(ctx, model.Override{ShortUUID: "short-1", Action: "block", Reason: "тест", CreatedBy: "admin"}); err != nil {
		t.Fatalf("AddOverride: %v", err)
	}

	h := newTestHandler(t, db, fullStubPanel{})
	if _, err := h.createHeaderRule(ctx, model.HeaderRule{
		Name: "правило", Enabled: true, Priority: 10,
		SetHeader: map[string]string{"Server": "nginx"},
	}); err != nil {
		t.Fatalf("createHeaderRule: %v", err)
	}

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

	pages := []string{
		"/admin/overview",
		"/admin/reqlog",
		"/admin/users",
		"/admin/users/short-1",
		"/admin/overrides",
		"/admin/headerrules",
		"/admin/headerrules/new",
		"/admin/settings",
		"/admin/about",
		"/admin/does-not-exist",
	}
	for _, p := range pages {
		t.Run(p, func(t *testing.T) {
			resp, body := getBody(t, c, srv.URL+p)
			wantStatus := http.StatusOK
			if p == "/admin/does-not-exist" {
				wantStatus = http.StatusNotFound
			}
			if resp.StatusCode != wantStatus {
				t.Fatalf("%s: ожидали %d, получили %d", p, wantStatus, resp.StatusCode)
			}
			if strings.Contains(body, "внутренняя ошибка шаблона") {
				t.Fatalf("%s: страница отдала ошибку рендера шаблона", p)
			}
		})
	}

	// Статика раздаётся без авторизации (нужна ещё на странице логина)
	// и приходит из embed.FS, а не с диска: продукт остаётся одним файлом.
	t.Run("static css", func(t *testing.T) {
		anon, _ := cookiejar.New(nil)
		anonC := &http.Client{Jar: anon}
		resp, body := getBody(t, anonC, srv.URL+"/admin/static/css/admin.css")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("статика css: ожидали 200, получили %d", resp.StatusCode)
		}
		if !strings.Contains(body, "prefers-color-scheme") {
			t.Fatalf("статика css: не похоже на наш admin.css")
		}
	})
	t.Run("static js", func(t *testing.T) {
		anon, _ := cookiejar.New(nil)
		anonC := &http.Client{Jar: anon}
		resp, body := getBody(t, anonC, srv.URL+"/admin/static/js/admin.js")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("статика js: ожидали 200, получили %d", resp.StatusCode)
		}
		if !strings.Contains(body, "initMobileMenu") {
			t.Fatalf("статика js: не похоже на наш admin.js")
		}
	})
}
