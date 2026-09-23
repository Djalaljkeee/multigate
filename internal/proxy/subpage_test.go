package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

type fakeLegacy map[string]string

func (f fakeLegacy) Resolve(_ context.Context, token string) (string, bool) {
	su, ok := f[token]
	return su, ok
}

type fakeSubPage struct {
	err   error
	got   string
	calls int
}

func (f *fakeSubPage) Serve(w http.ResponseWriter, _ *http.Request, shortUUID string, _ model.Platform) (int, int, error) {
	f.calls++
	f.got = shortUUID
	if f.err != nil {
		return 0, 0, f.err
	}
	w.WriteHeader(http.StatusOK)
	n, _ := w.Write([]byte("PAGE"))
	return http.StatusOK, n, nil
}

func TestServeHTTP_LegacyLinkUsesCurrentShortUUID(t *testing.T) {
	db := openProxyTestDB(t)
	mustSet(t, db, store.KeyMode, "panel")

	var asked string
	panel := &fakePanel{subFunc: func(_ context.Context, shortUUID string, _ http.Header) (*model.SubResponse, error) {
		asked = shortUUID
		return &model.SubResponse{Status: http.StatusOK, Body: []byte("sub")}, nil
	}}
	h, err := New(Deps{Store: db, Panel: panel, ReqLog: db.NewReqLogger(context.Background()), ParseUA: testParseUA,
		Legacy: fakeLegacy{"dXNfMzIxLDE3NDIzODQzOTczBxt2KEkzn": "current-short"}})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub/dXNfMzIxLDE3NDIzODQzOTczBxt2KEkzn", nil))
	if rec.Code != http.StatusOK || asked != "current-short" {
		t.Fatalf("код %d, панель спросили про %q, ждали current-short", rec.Code, asked)
	}

	// Обычная ссылка резолвером не трогается.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub/plainShort", nil))
	if asked != "plainShort" {
		t.Fatalf("обычная ссылка ушла в панель как %q", asked)
	}
}

func TestServeHTTP_BrowserGetsSubPage(t *testing.T) {
	db := openProxyTestDB(t)
	mustSet(t, db, store.KeyMode, "panel")
	mustSet(t, db, store.KeyDecoyEnabled, "1")

	page := &fakeSubPage{}
	h, err := New(Deps{Store: db, Panel: &fakePanel{}, ReqLog: db.NewReqLogger(context.Background()), ParseUA: testParseUA,
		SubPage: page, Legacy: fakeLegacy{"legacyTok": "resolved"}})
	if err != nil {
		t.Fatal(err)
	}
	browser := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Test-Browser", "1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Страница выключена (по умолчанию): браузер получает маскировку, как раньше.
	if rec := browser("/sub/abc"); rec.Body.String() == "PAGE" || page.calls != 0 {
		t.Fatal("страница показана, хотя выключена")
	}

	mustSet(t, db, store.KeySubpageEnabled, "1")
	if rec := browser("/sub/legacyTok"); rec.Body.String() != "PAGE" || page.got != "resolved" {
		t.Fatalf("ответ %q, страница для %q", rec.Body.String(), page.got)
	}

	// Страницу показать нельзя: браузер получает то же, что и без неё.
	page.err = errors.New("нет подписки")
	if rec := browser("/sub/abc"); rec.Body.String() == "PAGE" {
		t.Fatal("при ошибке страницы ответ не упал в маскировку")
	}

	// Режим зеркала: страницу не трогаем вовсе.
	page.err, page.calls = nil, 0
	mustSet(t, db, store.KeyMode, "mirror")
	browser("/sub/abc")
	if page.calls != 0 {
		t.Fatal("в режиме зеркала вызвана страница панели")
	}
}
