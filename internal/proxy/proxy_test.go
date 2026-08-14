package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/rules"
	"github.com/qwe8nxtroud/multigate/internal/store"
	"github.com/qwe8nxtroud/multigate/internal/wgpool"
)

// discardLogger - логгер для тестов, где сам факт логирования не проверяется.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testWGConfig - минимальный валидный конфиг WireGuard для тестов пула.
const testWGConfig = `[Interface]
PrivateKey = kL5UwZjfV6dEQeuJ+RaP8pOu9OFRDN6dhcDDsN0Iv1w=
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
`

// --- вспомогательные функции теста ---

func openProxyTestDB(t *testing.T) *store.DB {
	t.Helper()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "proxy_test.db")
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

func mustSet(t *testing.T, db *store.DB, key, value string) {
	t.Helper()
	if err := db.Set(context.Background(), key, value); err != nil {
		t.Fatalf("db.Set(%s): %v", key, err)
	}
}

// testParseUA - тестовая замена пакету ua: читает клиента из специальных
// заголовков запроса, которые расставляет сам тест. Настоящий разбор
// User-Agent пишет параллельный агент, здесь он не нужен и не импортируется.
func testParseUA(r *http.Request) model.Client {
	c := model.Client{UserAgent: r.Header.Get("User-Agent")}
	if r.Header.Get("X-Test-Browser") == "1" {
		c.IsBrowser = true
	}
	c.App = r.Header.Get("X-Test-App")
	if hw := r.Header.Get("X-Test-Hwid"); hw != "" {
		c.HWID = hw
		c.HWIDSource = "header"
	}
	if core := r.Header.Get("X-Test-Core"); core != "" {
		c.Core = model.Core(core)
	}
	if pl := r.Header.Get("X-Test-Platform"); pl != "" {
		c.Platform = model.Platform(pl)
	}
	return c
}

// fakePanel - управляемая тестом реализация proxy.Panel.
type fakePanel struct {
	subFunc     func(ctx context.Context, shortUUID string, in http.Header) (*model.SubResponse, error)
	userFunc    func(ctx context.Context, shortUUID string) (model.PanelUser, error)
	devicesFunc func(ctx context.Context, userRef string) ([]model.Device, error)
}

func (f *fakePanel) Subscription(ctx context.Context, shortUUID string, in http.Header) (*model.SubResponse, error) {
	if f.subFunc != nil {
		return f.subFunc(ctx, shortUUID, in)
	}
	return &model.SubResponse{Status: http.StatusOK, Body: []byte("ok")}, nil
}

func (f *fakePanel) UserByShortUUID(ctx context.Context, shortUUID string) (model.PanelUser, error) {
	if f.userFunc != nil {
		return f.userFunc(ctx, shortUUID)
	}
	return model.PanelUser{ShortUUID: shortUUID}, nil
}

func (f *fakePanel) Info(ctx context.Context) (model.PanelInfo, error) {
	return model.PanelInfo{Reachable: true}, nil
}

func (f *fakePanel) Devices(ctx context.Context, userRef string) ([]model.Device, error) {
	if f.devicesFunc != nil {
		return f.devicesFunc(ctx, userRef)
	}
	return nil, nil
}

func (f *fakePanel) DeleteDevice(context.Context, string, string) error {
	return errors.New("fakePanel: DeleteDevice не используется в этих тестах")
}

// fakeGrace - управляемая тестом реализация proxy.Grace.
type fakeGrace struct {
	maybeFunc func(ctx context.Context, u model.PanelUser) (bool, error)
	calls     int
}

func (f *fakeGrace) Maybe(ctx context.Context, u model.PanelUser) (bool, error) {
	f.calls++
	if f.maybeFunc != nil {
		return f.maybeFunc(ctx, u)
	}
	return false, nil
}

// --- сценарий: нормальная выдача через режим panel ---

func TestServeHTTP_Normal_PanelMode(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")

	future := time.Now().Add(24 * time.Hour).Unix()
	panel := &fakePanel{subFunc: func(_ context.Context, shortUUID string, _ http.Header) (*model.SubResponse, error) {
		if shortUUID != "abc123" {
			t.Errorf("Panel.Subscription получил shortUUID=%q, хотели abc123", shortUUID)
		}
		return &model.SubResponse{
			Status: http.StatusOK,
			Headers: map[string]string{
				"profile-title":         "base64:VGVzdA==",
				"subscription-userinfo": fmt.Sprintf("upload=1;download=2;total=1000;expire=%d", future),
				"content-type":          "text/plain; charset=utf-8",
				"x-not-in-allowlist":    "should-not-leak",
			},
			Body:   []byte("dmxlc3M6Ly90ZXN0"),
			Format: model.FormatBase64,
		}, nil
	}}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/abc123", nil)
	req.Header.Set("X-Test-Hwid", "device-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("код ответа = %d, тело=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "dmxlc3M6Ly90ZXN0" {
		t.Fatalf("тело не совпало: %q", got)
	}
	if rec.Header().Get("Profile-Title") == "" {
		t.Fatal("ожидали Profile-Title в ответе")
	}
	if rec.Header().Get("X-Not-In-Allowlist") != "" {
		t.Fatal("заголовок вне allowlist не должен попадать в ответ")
	}

	rl.Close()
	logs, _, err := db.ListRequestLog(ctx, store.ReqLogFilter{})
	if err != nil {
		t.Fatalf("ListRequestLog: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("ожидали одну запись журнала, получили %d", len(logs))
	}
	if logs[0].Decision != string(model.DecisionNormal) {
		t.Fatalf("decision = %q, хотели normal", logs[0].Decision)
	}
	if logs[0].Status != http.StatusOK || logs[0].Bytes == 0 {
		t.Fatalf("запись журнала выглядит неполной: %+v", logs[0])
	}
}

// --- сценарий: нормальная выдача через режим mirror ---

func TestServeHTTP_Normal_MirrorMode(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc123" {
			t.Errorf("origin получил неожиданный путь %s", r.URL.Path)
		}
		if r.URL.RawQuery != "foo=bar" {
			t.Errorf("origin получил неожиданный query %q", r.URL.RawQuery)
		}
		w.Header().Set("Profile-Title", "base64:TXk=")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body-from-origin"))
	}))
	defer origin.Close()

	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMirrorTarget, origin.URL)

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/abc123?foo=bar", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d, тело=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "body-from-origin" {
		t.Fatalf("тело = %q", rec.Body.String())
	}
	rl.Close()
}

// --- сценарий: апстрим жмёт ответ gzip'ом, клиент должен получить читаемое тело ---
//
// Воспроизводит находку ревью: curl -H 'Accept-Encoding: gzip' получал сырой
// gzip вместо тела подписки, потому что клиентский заголовок Accept-Encoding
// пробрасывался апстриму как есть, а Go не разжимает ответ сам, если
// Accept-Encoding в исходящем запросе выставлен вручную.

func TestServeHTTP_Mirror_UpstreamGzip_ClientGetsReadableBody(t *testing.T) {
	const plain = "vless://readable-body-not-raw-gzip-bytes"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write([]byte(plain))
		_ = gz.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}))
	defer origin.Close()

	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMirrorTarget, origin.URL)

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/abc123", nil)
	// Именно так был воспроизведён баг: curl -H 'Accept-Encoding: gzip'.
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}
	if got := rec.Body.String(); got != plain {
		t.Fatalf("клиент должен получить разжатое тело %q, получил %q (похоже на сырой gzip: %v)",
			plain, got, strings.HasPrefix(got, "\x1f\x8b"))
	}
	rl.Close()
}

// --- сценарий: блокировка по локальному override ---

func TestServeHTTP_Blocked_Override(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")
	if _, err := db.AddOverride(ctx, model.Override{ShortUUID: "blocked-user", Action: "block", Reason: "test"}); err != nil {
		t.Fatalf("AddOverride: %v", err)
	}

	panel := &fakePanel{subFunc: func(context.Context, string, http.Header) (*model.SubResponse, error) {
		t.Fatal("Panel.Subscription не должен вызываться для заблокированного пользователя")
		return nil, nil
	}}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/blocked-user", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("заблокированный клиент должен получать 200 (клиенты плохо переносят 4xx/5xx), получили %d", rec.Code)
	}
	if rec.Header().Get("Profile-Title") == "" {
		t.Fatal("ожидали понятный Profile-Title в заглушке блокировки")
	}

	rl.Close()
	logs, _, _ := db.ListRequestLog(ctx, store.ReqLogFilter{})
	if len(logs) != 1 || logs[0].Decision != string(model.DecisionBlocked) {
		t.Fatalf("ожидали decision=blocked в журнале, получили %+v", logs)
	}
}

// --- сценарий: истёкшая подписка ---

func TestServeHTTP_Expired(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")

	expired := time.Now().Add(-1 * time.Hour).Unix()
	panel := &fakePanel{subFunc: func(context.Context, string, http.Header) (*model.SubResponse, error) {
		return &model.SubResponse{
			Status: http.StatusOK,
			Headers: map[string]string{
				"subscription-userinfo": fmt.Sprintf("upload=1;download=2;total=1000;expire=%d", expired),
			},
			Body: []byte("real-body-should-not-reach-client"),
		}, nil
	}}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/expired-user", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("истёкшая подписка тоже должна отдаваться с 200, получили %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "real-body-should-not-reach-client") {
		t.Fatal("реальное тело истёкшей подписки не должно доходить до клиента")
	}

	rl.Close()
	logs, _, _ := db.ListRequestLog(ctx, store.ReqLogFilter{})
	if len(logs) != 1 || logs[0].Decision != string(model.DecisionExpired) {
		t.Fatalf("ожидали decision=expired, получили %+v", logs)
	}
}

// --- сценарий: срез ETag/If-None-Match ---

func TestServeHTTP_StripsETagAndConditionalHeaders(t *testing.T) {
	var gotINM string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotINM = r.Header.Get("If-None-Match")
		w.Header().Set("ETag", `"abc"`)
		w.Header().Set("Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fresh-body"))
	}))
	defer origin.Close()

	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMirrorTarget, origin.URL)

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/abc123", nil)
	req.Header.Set("If-None-Match", `"stale-etag-from-client-cache"`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if gotINM != "" {
		t.Fatalf("апстрим не должен видеть If-None-Match клиента, получил %q", gotINM)
	}
	if rec.Code == http.StatusNotModified {
		t.Fatal("клиент не должен получать 304 - иначе подписка залипнет на старой версии")
	}
	if rec.Header().Get("ETag") != "" {
		t.Fatal("ETag должен быть срезан из ответа клиенту")
	}
	if rec.Header().Get("Last-Modified") != "" {
		t.Fatal("Last-Modified должен быть срезан из ответа клиенту")
	}
	if rec.Body.String() != "fresh-body" {
		t.Fatalf("тело = %q", rec.Body.String())
	}
	rl.Close()
}

// --- сценарий: маскировка для браузера ---

func TestServeHTTP_Decoy_Browser(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	// store.KeyDecoyEnabled включён по умолчанию на пустой базе.

	landingCalled := false
	landing := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		landingCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>landing</html>"))
	})

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, ReqLog: rl, ParseUA: testParseUA, Landing: landing})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/abc123", nil)
	req.Header.Set("X-Test-Browser", "1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !landingCalled {
		t.Fatal("ожидали, что Landing будет вызван для браузера")
	}
	if rec.Body.String() != "<html>landing</html>" {
		t.Fatalf("тело = %q", rec.Body.String())
	}

	rl.Close()
	logs, _, _ := db.ListRequestLog(ctx, store.ReqLogFilter{})
	if len(logs) != 1 || logs[0].Decision != string(model.DecisionDecoy) {
		t.Fatalf("ожидали decision=decoy, получили %+v", logs)
	}
}

func TestServeHTTP_Decoy_NoLandingGives404(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, ReqLog: rl, ParseUA: testParseUA}) // Landing не задан
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/abc123", nil)
	req.Header.Set("X-Test-Browser", "1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("без Landing браузер должен получать 404, получили %d", rec.Code)
	}
	rl.Close()
}

// --- сценарий: пустой/нераспознанный путь ---

func TestServeHTTP_NotFound_EmptyPath(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyDecoyEnabled, "0")

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("код = %d", rec.Code)
	}
	rl.Close()
	logs, _, _ := db.ListRequestLog(ctx, store.ReqLogFilter{})
	if len(logs) != 1 || logs[0].Decision != string(model.DecisionNotFound) {
		t.Fatalf("ожидали decision=notfound, получили %+v", logs)
	}
}

// --- грейс для истёкшей подписки ---

func TestServeHTTP_Grace_AppliedGivesFreshSubscription(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")
	mustSet(t, db, store.KeyGraceEnabled, "1")

	expired := time.Now().Add(-1 * time.Hour).Unix()
	future := time.Now().Add(24 * time.Hour).Unix()

	fetches := 0
	panel := &fakePanel{
		userFunc: func(_ context.Context, shortUUID string) (model.PanelUser, error) {
			return model.PanelUser{ShortUUID: shortUUID, Ref: "ref-" + shortUUID}, nil
		},
		subFunc: func(context.Context, string, http.Header) (*model.SubResponse, error) {
			fetches++
			if fetches == 1 {
				return &model.SubResponse{
					Status: http.StatusOK,
					Headers: map[string]string{
						"subscription-userinfo": fmt.Sprintf("upload=1;download=2;total=1000;expire=%d", expired),
					},
					Body: []byte("stale-expired-body"),
				}, nil
			}
			return &model.SubResponse{
				Status: http.StatusOK,
				Headers: map[string]string{
					"subscription-userinfo": fmt.Sprintf("upload=1;download=2;total=1000;expire=%d", future),
				},
				Body: []byte("fresh-body-after-grace"),
			}, nil
		},
	}

	grace := &fakeGrace{maybeFunc: func(_ context.Context, u model.PanelUser) (bool, error) {
		if u.ShortUUID != "grace-user" {
			t.Errorf("Grace.Maybe получил ShortUUID=%q, хотели grace-user", u.ShortUUID)
		}
		return true, nil
	}}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA, Grace: grace, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/grace-user", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}
	if rec.Body.String() != "fresh-body-after-grace" {
		t.Fatalf("после успешного грейса клиент должен получить свежую подписку, получили %q", rec.Body.String())
	}
	if grace.calls != 1 {
		t.Fatalf("Grace.Maybe должен вызваться один раз, вызван %d раз", grace.calls)
	}
	if fetches != 2 {
		t.Fatalf("Panel.Subscription должен вызваться дважды (до и после грейса), вызван %d раз", fetches)
	}

	rl.Close()
	logs, _, _ := db.ListRequestLog(ctx, store.ReqLogFilter{})
	if len(logs) != 1 || logs[0].Decision != string(model.DecisionNormal) {
		t.Fatalf("ожидали decision=normal после успешного грейса, получили %+v", logs)
	}
}

// TestServeHTTP_Grace_DisabledSettingKeepsStub проверяет, что заданная
// зависимость Grace сама по себе ничего не включает: без явной настройки
// store.KeyGraceEnabled панель за грейсом даже не дёргается.
func TestServeHTTP_Grace_DisabledSettingKeepsStub(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")
	// store.KeyGraceEnabled НЕ включаем - по умолчанию "0".

	expired := time.Now().Add(-1 * time.Hour).Unix()
	panel := &fakePanel{
		userFunc: func(_ context.Context, shortUUID string) (model.PanelUser, error) {
			t.Fatal("UserByShortUUID не должен вызываться, когда грейс выключен настройкой")
			return model.PanelUser{}, nil
		},
		subFunc: func(context.Context, string, http.Header) (*model.SubResponse, error) {
			return &model.SubResponse{
				Status: http.StatusOK,
				Headers: map[string]string{
					"subscription-userinfo": fmt.Sprintf("upload=1;download=2;total=1000;expire=%d", expired),
				},
				Body: []byte("real-body-should-not-reach-client"),
			}, nil
		},
	}
	grace := &fakeGrace{}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA, Grace: grace, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/expired-user", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "real-body-should-not-reach-client") {
		t.Fatal("выключенная настройка грейса не должна отдавать реальное тело истёкшей подписки")
	}
	if grace.calls != 0 {
		t.Fatalf("Grace.Maybe не должен вызываться при выключенной настройке, вызван %d раз", grace.calls)
	}
	rl.Close()
}

// TestServeHTTP_Grace_ErrorFallsBackToStub проверяет требование ревью:
// ошибка грейса не должна ломать выдачу - клиент получает обычную заглушку
// истёкшей подписки, как будто грейса нет вовсе.
func TestServeHTTP_Grace_ErrorFallsBackToStub(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")
	mustSet(t, db, store.KeyGraceEnabled, "1")

	expired := time.Now().Add(-1 * time.Hour).Unix()
	panel := &fakePanel{subFunc: func(context.Context, string, http.Header) (*model.SubResponse, error) {
		return &model.SubResponse{
			Status: http.StatusOK,
			Headers: map[string]string{
				"subscription-userinfo": fmt.Sprintf("upload=1;download=2;total=1000;expire=%d", expired),
			},
			Body: []byte("real-body-should-not-reach-client"),
		}, nil
	}}
	grace := &fakeGrace{maybeFunc: func(context.Context, model.PanelUser) (bool, error) {
		return false, errors.New("панель отклонила обновление")
	}}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA, Grace: grace, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/expired-user", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "real-body-should-not-reach-client") {
		t.Fatal("ошибка грейса не должна протащить настоящее тело истёкшей подписки клиенту")
	}
	rl.Close()
	logs, _, _ := db.ListRequestLog(ctx, store.ReqLogFilter{})
	if len(logs) != 1 || logs[0].Decision != string(model.DecisionExpired) {
		t.Fatalf("ожидали decision=expired при сорвавшемся грейсе, получили %+v", logs)
	}
}

// --- пул WireGuard ---

func TestServeHTTP_WGPool_AppendsConfigForSupportedCore(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")
	mustSet(t, db, store.KeyWGPoolEnabled, "1")

	pool := wgpool.New(db, discardLogger())
	if _, err := pool.Import(ctx, "", map[string]string{"wg1.conf": testWGConfig}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	panel := &fakePanel{subFunc: func(context.Context, string, http.Header) (*model.SubResponse, error) {
		return &model.SubResponse{
			Status:  http.StatusOK,
			Body:    []byte(`{"outbounds":[{"type":"direct","tag":"direct"}]}`),
			Headers: map[string]string{"content-type": "application/json"},
			Format:  model.FormatSingBox,
		}, nil
	}}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA, WGPool: pool, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/wg-user", nil)
	req.Header.Set("X-Test-Core", "singbox")
	req.Header.Set("X-Test-Hwid", "device-wg-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d, тело=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "wireguard") {
		t.Fatalf("ожидали outbound типа wireguard в теле, получили %s", rec.Body.String())
	}

	// Повторный запрос того же устройства должен получить ТУ ЖЕ лизу
	// (идемпотентность wgpool.Lease), а не занять вторую запись пула.
	req2 := httptest.NewRequest(http.MethodGet, "/wg-user", nil)
	req2.Header.Set("X-Test-Core", "singbox")
	req2.Header.Set("X-Test-Hwid", "device-wg-1")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Body.String() != rec.Body.String() {
		t.Fatalf("повторный запрос должен получить тот же довесок WireGuard:\n%s\n!=\n%s", rec2.Body.String(), rec.Body.String())
	}

	rl.Close()
}

// TestServeHTTP_WGPool_SkipsWithoutHWID проверяет, что без HWID лиза не
// выдаётся: закрепить конфиг не за чем, а раздавать его без привязки к
// устройству значило бы делиться одним приватным ключом WireGuard с кем
// попало.
func TestServeHTTP_WGPool_SkipsWithoutHWID(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")
	mustSet(t, db, store.KeyWGPoolEnabled, "1")

	pool := wgpool.New(db, discardLogger())
	if _, err := pool.Import(ctx, "", map[string]string{"wg1.conf": testWGConfig}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	panel := &fakePanel{subFunc: func(context.Context, string, http.Header) (*model.SubResponse, error) {
		return &model.SubResponse{
			Status: http.StatusOK,
			Body:   []byte(`{"outbounds":[{"type":"direct","tag":"direct"}]}`),
			Format: model.FormatSingBox,
		}, nil
	}}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA, WGPool: pool, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/wg-user", nil)
	req.Header.Set("X-Test-Core", "singbox")
	// Заголовок X-Test-Hwid намеренно не выставлен - HWID пустой.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "wireguard") {
		t.Fatal("без HWID довесок WireGuard не должен добавляться")
	}
	rl.Close()
}

// TestServeHTTP_WGPool_SkipsOnNotFound проверяет, что довесок WireGuard не
// выдаётся на ответ апстрима с не-2xx статусом (например, панель не нашла
// такой shortUuid): иначе кто угодно, перебирая случайные ссылки, вымывал
// бы реальные лизы из пула, ничего не оплатив.
func TestServeHTTP_WGPool_SkipsOnNotFound(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")
	mustSet(t, db, store.KeyWGPoolEnabled, "1")

	pool := wgpool.New(db, discardLogger())
	if _, err := pool.Import(ctx, "", map[string]string{"wg1.conf": testWGConfig}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	panel := &fakePanel{subFunc: func(context.Context, string, http.Header) (*model.SubResponse, error) {
		return &model.SubResponse{Status: http.StatusNotFound, Body: []byte("not found"), Format: model.FormatSingBox}, nil
	}}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA, WGPool: pool, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/no-such-user", nil)
	req.Header.Set("X-Test-Core", "singbox")
	req.Header.Set("X-Test-Hwid", "device-scan-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "wireguard") {
		t.Fatal("404 не должен получать довесок WireGuard из пула")
	}

	stats, err := pool.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats["default"].InUse != 0 {
		t.Fatalf("пул не должен был выдать ни одной лизы на 404, статистика: %+v", stats)
	}
	rl.Close()
}

// --- store.KeyLogEnabled ---

func TestServeHTTP_LogDisabled_NormalRequestNotLogged(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")
	mustSet(t, db, store.KeyLogEnabled, "0")

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: &fakePanel{}, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/abc123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}

	rl.Close()
	logs, _, _ := db.ListRequestLog(ctx, store.ReqLogFilter{})
	if len(logs) != 0 {
		t.Fatalf("при выключенном журнале обычная выдача не должна писаться, получили %+v", logs)
	}
}

// TestServeHTTP_LogDisabled_DenialsStillLogged проверяет задокументированное
// в ServeHTTP решение: даже при выключенном журнале отказы (blocked,
// expired, error) всё равно пишутся - иначе диагностировать процесс нечем.
func TestServeHTTP_LogDisabled_DenialsStillLogged(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")
	mustSet(t, db, store.KeyLogEnabled, "0")
	if _, err := db.AddOverride(ctx, model.Override{ShortUUID: "blocked-user", Action: "block"}); err != nil {
		t.Fatalf("AddOverride: %v", err)
	}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: &fakePanel{}, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/blocked-user", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	rl.Close()
	logs, _, _ := db.ListRequestLog(ctx, store.ReqLogFilter{})
	if len(logs) != 1 || logs[0].Decision != string(model.DecisionBlocked) {
		t.Fatalf("отказ (blocked) должен писаться в журнал, даже когда галочка выключена, получили %+v", logs)
	}
}

// --- stubBody: заглушки безопасны и минимальны под каждый формат ---

func TestStubBody_EmptyAndSafeByFormat(t *testing.T) {
	if body, ct := stubBody(model.FormatBase64); len(body) != 0 || ct == "" {
		t.Fatalf("base64: тело = %q, content-type = %q", body, ct)
	}
	if body, ct := stubBody(model.FormatPlain); len(body) != 0 || ct == "" {
		t.Fatalf("plain: тело = %q, content-type = %q", body, ct)
	}
	if body, _ := stubBody(model.FormatClash); !strings.Contains(string(body), "MATCH,DIRECT") {
		t.Fatalf("clash: ожидали безопасный fallback MATCH,DIRECT, получили %q", body)
	}
	if body, _ := stubBody(model.FormatSingBox); !strings.Contains(string(body), `"type":"direct"`) {
		t.Fatalf("singbox: ожидали безопасный outbound direct, получили %q", body)
	}
}

// --- формы пути ---

func TestSplitSubPath(t *testing.T) {
	cases := []struct{ path, wantUUID, wantSuffix string }{
		{"/abc123", "abc123", ""},
		{"/sub/abc123", "abc123", ""},
		{"/api/sub/abc123", "abc123", ""},
		{"/api/sub/abc123/clash", "abc123", "clash"},
		{"/abc123/singbox", "abc123", "singbox"},
		{"/", "", ""},
		{"", "", ""},
	}
	for _, tc := range cases {
		gotUUID, gotSuffix := splitSubPath(tc.path)
		if gotUUID != tc.wantUUID || gotSuffix != tc.wantSuffix {
			t.Errorf("splitSubPath(%q) = (%q, %q), хотели (%q, %q)", tc.path, gotUUID, gotSuffix, tc.wantUUID, tc.wantSuffix)
		}
	}
}

func TestServeHTTP_PathForms(t *testing.T) {
	paths := []string{"/abc123", "/sub/abc123", "/api/sub/abc123", "/api/sub/abc123/clash", "/abc123/singbox"}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			db := openProxyTestDB(t)
			ctx := context.Background()
			mustSet(t, db, store.KeyMode, "panel")

			var gotShortUUID string
			panel := &fakePanel{subFunc: func(_ context.Context, shortUUID string, _ http.Header) (*model.SubResponse, error) {
				gotShortUUID = shortUUID
				return &model.SubResponse{Status: http.StatusOK, Body: []byte("ok")}, nil
			}}

			rl := db.NewReqLogger(ctx)
			h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, p, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if gotShortUUID != "abc123" {
				t.Fatalf("путь %s: shortUUID = %q, хотели abc123", p, gotShortUUID)
			}
			rl.Close()
		})
	}
}

// --- кэш ответа ---

func TestServeHTTP_Cache(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")
	mustSet(t, db, store.KeyCacheTTL, "60")

	calls := 0
	panel := &fakePanel{subFunc: func(context.Context, string, http.Header) (*model.SubResponse, error) {
		calls++
		return &model.SubResponse{
			Status:  http.StatusOK,
			Body:    []byte("cached-body"),
			Headers: map[string]string{"content-type": "text/plain"},
		}, nil
	}}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/abc123", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Body.String() != "cached-body" {
			t.Fatalf("запрос %d: тело = %q", i, rec.Body.String())
		}
	}
	if calls != 1 {
		t.Fatalf("Panel.Subscription должен был вызваться один раз, вызван %d раз", calls)
	}
	rl.Close()
}

// --- лимит устройств по HWID ---

func TestServeHTTP_HWIDLimitBlocks(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")
	mustSet(t, db, store.KeyHWIDEnforce, "1")

	// Лимит считается по данным панели (реестр устройств), а не по
	// локальному журналу запросов: одно устройство панель уже знает.
	panel := &fakePanel{
		userFunc: func(_ context.Context, shortUUID string) (model.PanelUser, error) {
			return model.PanelUser{ShortUUID: shortUUID, Ref: "ref-" + shortUUID, HWIDDeviceLimit: 1}, nil
		},
		devicesFunc: func(_ context.Context, userRef string) ([]model.Device, error) {
			if userRef != "ref-limited-user" {
				t.Errorf("Panel.Devices получил userRef=%q, хотели ref-limited-user", userRef)
			}
			return []model.Device{{HWID: "device-a"}}, nil
		},
		subFunc: func(context.Context, string, http.Header) (*model.SubResponse, error) {
			t.Fatal("Panel.Subscription не должен вызываться для устройства сверх лимита")
			return nil, nil
		},
	}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/limited-user", nil)
	req.Header.Set("X-Test-Hwid", "device-b")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}
	rl.Close()

	logs, _, _ := db.ListRequestLog(ctx, store.ReqLogFilter{ShortUUID: "limited-user"})
	var found bool
	for _, l := range logs {
		if l.HWID != "device-b" {
			continue
		}
		found = true
		if l.Decision != string(model.DecisionBlocked) {
			t.Fatalf("decision = %q, хотели blocked", l.Decision)
		}
	}
	if !found {
		t.Fatal("не нашли запись журнала для device-b")
	}
}

// TestServeHTTP_HWIDLimit_NotBypassedByCache воспроизводит находку ревью:
// cache_ttl=60, лимит устройств 1. Первое (уже известное панели) устройство
// получает подписку, ответ ложится в кэш. Второе, новое устройство того же
// пользователя на том же ядре не должно получить эту подписку из кэша в
// обход проверки лимита - лимит проверяется раньше, чем прослойка вообще
// заглядывает в кэш.
func TestServeHTTP_HWIDLimit_NotBypassedByCache(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")
	mustSet(t, db, store.KeyHWIDEnforce, "1")
	mustSet(t, db, store.KeyCacheTTL, "60")

	subCalls := 0
	panel := &fakePanel{
		userFunc: func(_ context.Context, shortUUID string) (model.PanelUser, error) {
			return model.PanelUser{ShortUUID: shortUUID, Ref: "ref-" + shortUUID, HWIDDeviceLimit: 1}, nil
		},
		devicesFunc: func(context.Context, string) ([]model.Device, error) {
			// Панель уже знает про device-a - лимит 1/1 занят им.
			return []model.Device{{HWID: "device-a"}}, nil
		},
		subFunc: func(context.Context, string, http.Header) (*model.SubResponse, error) {
			subCalls++
			return &model.SubResponse{Status: http.StatusOK, Body: []byte("real-subscription-body")}, nil
		},
	}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Первое, уже известное устройство - получает подписку, кладёт её в кэш.
	req1 := httptest.NewRequest(http.MethodGet, "/cache-hwid-user", nil)
	req1.Header.Set("X-Test-Hwid", "device-a")
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	if rec1.Body.String() != "real-subscription-body" {
		t.Fatalf("известное устройство должно получить настоящую подписку, получили %q", rec1.Body.String())
	}

	// Второе, новое устройство сверх лимита - не должно получить тот же
	// ответ из кэша в обход проверки.
	req2 := httptest.NewRequest(http.MethodGet, "/cache-hwid-user", nil)
	req2.Header.Set("X-Test-Hwid", "device-b")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Body.String() == "real-subscription-body" {
		t.Fatal("устройство сверх лимита получило настоящую подписку из кэша в обход проверки лимита")
	}
	if rec2.Header().Get("Profile-Title") == "" {
		t.Fatal("ожидали заглушку блокировки с понятным Profile-Title")
	}
	if subCalls != 1 {
		t.Fatalf("Panel.Subscription должен был вызваться только один раз (для первого устройства), вызван %d раз", subCalls)
	}

	rl.Close()
	logs, _, _ := db.ListRequestLog(ctx, store.ReqLogFilter{ShortUUID: "cache-hwid-user"})
	var blockedFound bool
	for _, l := range logs {
		if l.HWID == "device-b" && l.Decision == string(model.DecisionBlocked) {
			blockedFound = true
		}
	}
	if !blockedFound {
		t.Fatalf("ожидали decision=blocked для device-b в журнале, получили %+v", logs)
	}
}

// --- правила подмены заголовков применяются к финальному ответу ---

func TestServeHTTP_HeaderRulesApplied(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMode, "panel")

	if _, err := rules.Save(ctx, db, model.HeaderRule{
		Name: "happ-title", Enabled: true, Priority: 100,
		MatchApp:  "Happ",
		SetHeader: map[string]string{"Profile-Title": "base64:SGFwcA=="},
	}); err != nil {
		t.Fatalf("rules.Save: %v", err)
	}

	panel := &fakePanel{subFunc: func(context.Context, string, http.Header) (*model.SubResponse, error) {
		return &model.SubResponse{
			Status:  http.StatusOK,
			Body:    []byte("ok"),
			Headers: map[string]string{"profile-title": "base64:T3JpZ2luYWw="},
		}, nil
	}}

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/abc123", nil)
	req.Header.Set("X-Test-App", "Happ")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Profile-Title"); got != "base64:SGFwcA==" {
		t.Fatalf("правило должно было перезаписать Profile-Title, получили %q", got)
	}
	rl.Close()
}

// --- сбой апстрима не маскируется под 200 ---

func TestServeHTTP_MirrorUnreachableGives502(t *testing.T) {
	db := openProxyTestDB(t)
	ctx := context.Background()
	mustSet(t, db, store.KeyMirrorTarget, "http://127.0.0.1:1") // заведомо недоступный порт

	rl := db.NewReqLogger(ctx)
	h, err := New(Deps{Store: db, ReqLog: rl, ParseUA: testParseUA})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/abc123", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("недоступный апстрим должен давать 502, получили %d", rec.Code)
	}

	rl.Close()
	// Сбой связи с апстримом - не бизнес-решение вроде обычной выдачи,
	// поэтому в журнале он должен быть виден отдельным decision=error,
	// а не смешиваться с настоящими успешными выдачами (decision=normal).
	logs, _, _ := db.ListRequestLog(ctx, store.ReqLogFilter{})
	if len(logs) != 1 || logs[0].Decision != string(model.DecisionError) {
		t.Fatalf("ожидали decision=error в журнале при сбое апстрима, получили %+v", logs)
	}
}
