package remnawave

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// mux строит тестовый сервер панели по карте путь -> обработчик, с общим
// счётчиком обращений на путь: тестам версии важно и что ответил сервер,
// и сколько раз к нему сходили.
func newPanelMux(t *testing.T, handlers map[string]http.HandlerFunc) (*httptest.Server, *hitCounter) {
	t.Helper()
	hits := &hitCounter{n: map[string]*atomic.Int32{}}
	mux := http.NewServeMux()
	for path, h := range handlers {
		hits.n[path] = &atomic.Int32{}
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			hits.n[path].Add(1)
			h(w, r)
		})
	}
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, hits
}

type hitCounter struct {
	n map[string]*atomic.Int32
}

func (h *hitCounter) get(path string) int32 {
	if c, ok := h.n[path]; ok {
		return c.Load()
	}
	return 0
}

func jsonOK(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"message":"Cannot GET"}`))
}

func TestDetectVersion_MetadataV2(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata": jsonOK(`{"response":{"version":"2.7.4"}}`),
	})
	c := newTestClient(t, ts.URL)

	info, err := c.Info(context.Background())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if !info.Reachable || info.Major != 2 || info.Version != "2.7.4" {
		t.Fatalf("неожиданный PanelInfo: %+v", info)
	}
}

func TestDetectVersion_MetadataV3_AlsoProbesConfiguration(t *testing.T) {
	ts, hits := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata":      jsonOK(`{"response":{"version":"3.2.2"}}`),
		"/api/system/configuration": jsonOK(`{"response":{"someField":true}}`),
	})
	c := newTestClient(t, ts.URL)

	info, err := c.Info(context.Background())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if !info.Reachable || info.Major != 3 || info.Version != "3.2.2" {
		t.Fatalf("неожиданный PanelInfo: %+v", info)
	}
	if hits.get("/api/system/configuration") == 0 {
		t.Fatal("на major>=3 ожидал дополнительный запрос /api/system/configuration")
	}
}

func TestDetectVersion_FallbackFromUsers_V2(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata": notFound,
		"/api/users":           jsonOK(`{"users":[{"uuid":"11111111-1111-1111-1111-111111111111","username":"a"}],"total":1}`),
	})
	c := newTestClient(t, ts.URL)

	info, err := c.Info(context.Background())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if !info.Reachable || info.Major != 2 {
		t.Fatalf("ожидал Major=2 по форме ответа /api/users, got %+v", info)
	}
}

func TestDetectVersion_FallbackFromUsers_V3(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata": notFound,
		"/api/users":           jsonOK(`{"users":[{"id":42,"username":"a"}],"total":1}`),
	})
	c := newTestClient(t, ts.URL)

	info, err := c.Info(context.Background())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if !info.Reachable || info.Major != 3 {
		t.Fatalf("ожидал Major=3 по форме ответа /api/users, got %+v", info)
	}
}

func TestDetectVersion_UnauthorizedButAlive(t *testing.T) {
	ts, _ := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
		},
		"/api/auth/status": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				t.Errorf("auth/status публичный, не должен получать Authorization")
			}
			jsonOK(`{"response":{"isLoggedIn":false}}`)(w, r)
		},
	})
	c := newTestClient(t, ts.URL)

	info, err := c.Info(context.Background())
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if !info.Reachable {
		t.Fatalf("панель ответила (пусть и 401), должна считаться достижимой: %+v", info)
	}
	if info.Major != 0 {
		t.Fatalf("версию по 401 узнать неоткуда, ожидал Major=0, got %d", info.Major)
	}
	if info.Err == "" {
		t.Fatal("ожидал текст ошибки про неверный токен")
	}
}

func TestDetectVersion_Unreachable(t *testing.T) {
	// Реальный сетевой сбой: сервер поднят и сразу закрыт, порт никто не слушает.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	addr := ts.URL
	ts.Close()

	c := newTestClient(t, addr)
	info, err := c.Info(context.Background())
	if err != nil {
		t.Fatalf("Info не должен возвращать error на сетевой сбой, только PanelInfo: %v", err)
	}
	if info.Reachable {
		t.Fatal("ожидал Reachable=false")
	}
	if info.Err == "" {
		t.Fatal("ожидал текст ошибки связи в PanelInfo.Err")
	}
}

func TestInfo_CachesResultForFollowingCalls(t *testing.T) {
	ts, hits := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata": jsonOK(`{"response":{"version":"3.2.2"}}`),
	})
	c := newTestClient(t, ts.URL)

	if _, err := c.Info(context.Background()); err != nil {
		t.Fatalf("Info #1: %v", err)
	}
	if _, err := c.Info(context.Background()); err != nil {
		t.Fatalf("Info #2: %v", err)
	}
	if got := hits.get("/api/system/metadata"); got != 1 {
		t.Fatalf("второй вызов Info() должен был взять кэш, обращений к metadata: %d", got)
	}
}

// TestInfo_ConcurrentCallsShareOneNetworkFetch проверяет защиту от "стада":
// когда кэш остыл, много одновременных запросов подписки не должны каждый
// сходить в панель за версией: реальный запрос должен сделать только один.
func TestInfo_ConcurrentCallsShareOneNetworkFetch(t *testing.T) {
	ts, hits := newPanelMux(t, map[string]http.HandlerFunc{
		"/api/system/metadata": jsonOK(`{"response":{"version":"3.2.2"}}`),
	})
	c := newTestClient(t, ts.URL)

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			info, err := c.Info(context.Background())
			if err == nil && !info.Reachable {
				err = errFakeUnreachable
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Info() из горутины: %v", err)
		}
	}

	if got := hits.get("/api/system/metadata"); got != 1 {
		t.Fatalf("ожидал ровно 1 обращение к metadata на %d параллельных Info(), было %d", n, got)
	}
}

var errFakeUnreachable = errors.New("panel info unreachable in test")

func TestMajorFromVersion(t *testing.T) {
	cases := map[string]int{
		"3.2.2":   3,
		"2.7.4":   2,
		"v3.0.0":  3,
		"":        0,
		"garbage": 0,
	}
	for in, want := range cases {
		if got := majorFromVersion(in); got != want {
			t.Errorf("majorFromVersion(%q) = %d, want %d", in, got, want)
		}
	}
}
