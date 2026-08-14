package remnawave

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient поднимает клиент на адрес тестового сервера. Таймаут короткий,
// чтобы тесты с недоступным адресом не растягивали прогон пакета.
func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	c, err := New(Options{BaseURL: baseURL, Token: "test-token", Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNew_RejectsEmptyOrBadURL(t *testing.T) {
	if _, err := New(Options{BaseURL: ""}); err == nil {
		t.Fatal("ожидал ошибку на пустой BaseURL")
	}
	if _, err := New(Options{BaseURL: "not a url"}); err == nil {
		t.Fatal("ожидал ошибку на BaseURL без схемы/хоста")
	}
	if _, err := New(Options{BaseURL: "http://panel.example.com/"}); err != nil {
		t.Fatalf("нормальный адрес не должен возвращать ошибку: %v", err)
	}
}

func TestDecodeInto_EnvelopeAndBare(t *testing.T) {
	var out struct {
		Name string `json:"name"`
	}

	if err := decodeInto([]byte(`{"response":{"name":"вложено"}}`), &out); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if out.Name != "вложено" {
		t.Fatalf("envelope: got %q", out.Name)
	}

	out.Name = ""
	if err := decodeInto([]byte(`{"name":"голо"}`), &out); err != nil {
		t.Fatalf("bare: %v", err)
	}
	if out.Name != "голо" {
		t.Fatalf("bare: got %q", out.Name)
	}

	// out == nil: вызывающему нужен только факт успеха, тело не разбираем и не падаем.
	if err := decodeInto([]byte(`{"anything":1}`), nil); err != nil {
		t.Fatalf("nil out: %v", err)
	}

	// Пустое тело (например, ответ на reset-traffic) тоже не ошибка.
	if err := decodeInto(nil, &out); err != nil {
		t.Fatalf("empty body: %v", err)
	}
}

func TestApiErr_MapsStatusToSentinel(t *testing.T) {
	notFound := apiErr(http.MethodGet, "/api/users/by-username/x", apiResult{status: http.StatusNotFound, body: []byte(`{"message":"User not found","error":"Not Found"}`)})
	if !errors.Is(notFound, ErrNotFound) {
		t.Fatalf("404 должен разворачиваться в ErrNotFound, got %v", notFound)
	}

	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		unauth := apiErr(http.MethodGet, "/api/users", apiResult{status: status, body: []byte(`{"message":"Unauthorized"}`)})
		if !errors.Is(unauth, ErrUnauthorized) {
			t.Fatalf("%d должен разворачиваться в ErrUnauthorized, got %v", status, unauth)
		}
	}

	other := apiErr(http.MethodPatch, "/api/users", apiResult{status: http.StatusBadRequest, body: []byte(`{"message":["id should not be empty"]}`)})
	if errors.Is(other, ErrNotFound) || errors.Is(other, ErrUnauthorized) {
		t.Fatalf("400 не должен маппиться на sentinel-ошибки: %v", other)
	}
	if !strings.Contains(other.Error(), "id should not be empty") {
		t.Fatalf("текст ошибки должен включать сообщение валидации: %v", other)
	}
}

func TestApiErr_DoesNotLeakToken(t *testing.T) {
	const secret = "super-secret-token-abc123"
	c := newTestClient(t, "http://127.0.0.1:0")
	c.token = secret

	res := apiResult{status: http.StatusUnauthorized, body: []byte(`{"message":"Unauthorized"}`)}
	err := apiErr(http.MethodGet, "/api/users", res)
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("текст ошибки не должен содержать токен: %v", err)
	}
}

// TestGetRaw_RetriesOn5xxThenSucceeds проверяет, что GET повторяется на 5xx
// и укладывается в лимит maxRetries.
func TestGetRaw_RetriesOn5xxThenSucceeds(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL)
	var out struct {
		OK bool `json:"ok"`
	}
	if _, err := c.getJSON(context.Background(), "/probe", nil, false, &out); err != nil {
		t.Fatalf("getJSON: %v", err)
	}
	if !out.OK {
		t.Fatal("ожидал ok:true после повторов")
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("ожидал 3 попытки (1 + 2 повтора), было %d", got)
	}
}

// TestGetRaw_NoRetryOn404 проверяет, что 404 не запускает повторы: искать
// заново несуществующего пользователя бессмысленно.
func TestGetRaw_NoRetryOn404(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL)
	_, err := c.getJSON(context.Background(), "/probe", nil, false, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ожидал ErrNotFound, got %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("404 не должен ретраиться, было запросов: %d", got)
	}
}

// TestWriteJSON_NeverRetries проверяет, что PATCH/POST не повторяются даже
// на временную ошибку сервера: повторное применение действия (например,
// reset-traffic) не должно быть побочным эффектом сетевого сбоя.
func TestWriteJSON_NeverRetries(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL)
	err := c.writeJSON(context.Background(), http.MethodPost, "/probe", map[string]any{"x": 1}, nil)
	if err == nil {
		t.Fatal("ожидал ошибку от 503")
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("PATCH/POST не должны ретраиться, было запросов: %d", got)
	}
}

// TestDoRequest_ClientHeaderOverridesDefaultUA проверяет, что заголовки,
// переданные через extra (как это делает Subscription), заменяют, а не
// дублируют заголовки клиента по умолчанию.
func TestDoRequest_ClientHeaderOverridesDefaultUA(t *testing.T) {
	var gotUA []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Values("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL)
	extra := http.Header{"User-Agent": {"Happ/1.2.3"}}
	if _, err := c.doRequest(context.Background(), http.MethodGet, "/probe", nil, nil, false, extra, defaultMaxBody); err != nil {
		t.Fatalf("doRequest: %v", err)
	}
	if len(gotUA) != 1 || gotUA[0] != "Happ/1.2.3" {
		t.Fatalf("ожидал единственный User-Agent %q, got %v", "Happ/1.2.3", gotUA)
	}
}

func TestExtractMessage_ArrayAndString(t *testing.T) {
	if got := extractMessage([]byte(`{"message":"simple"}`)); got != "simple" {
		t.Fatalf("string message: got %q", got)
	}
	if got := extractMessage([]byte(`{"message":["a","b"]}`)); got != "a; b" {
		t.Fatalf("array message: got %q", got)
	}
	if got := extractMessage([]byte(`{"error":"Bad Request"}`)); got != "Bad Request" {
		t.Fatalf("error field: got %q", got)
	}
	if got := extractMessage([]byte(`not json`)); got != "not json" {
		t.Fatalf("raw fallback: got %q", got)
	}
}
