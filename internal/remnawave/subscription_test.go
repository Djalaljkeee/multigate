package remnawave

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSubscription_ForwardsUAAndXHeadersButNotAuthOrCookie(t *testing.T) {
	var gotUA, gotCustom, gotAuth, gotCookie string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotCustom = r.Header.Get("X-Client-Info")
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
		w.Header().Set("Content-Disposition", `attachment; filename="sub"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("vless://example"))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL)
	in := http.Header{
		"User-Agent":    {"v2rayNG/1.8.0"},
		"X-Client-Info": {"custom-app-data"},
		"Authorization": {"Bearer client-side-should-not-leak"},
		"Cookie":        {"session=abc"},
	}

	res, err := c.Subscription(context.Background(), "short-1", in)
	if err != nil {
		t.Fatalf("Subscription: %v", err)
	}

	if gotUA != "v2rayNG/1.8.0" {
		t.Errorf("User-Agent не пробросился: got %q", gotUA)
	}
	if gotCustom != "custom-app-data" {
		t.Errorf("X-* заголовок не пробросился: got %q", gotCustom)
	}
	if gotAuth != "" {
		t.Errorf("Subscription: публичный маршрут, Authorization не должен уйти вообще: got %q", gotAuth)
	}
	if gotCookie != "" {
		t.Errorf("Cookie клиента подписки пробрасывать не нужно: got %q", gotCookie)
	}

	if res.Status != http.StatusOK {
		t.Errorf("статус не проброшен как есть: got %d", res.Status)
	}
	if string(res.Body) != "vless://example" {
		t.Errorf("тело не проброшено как есть: got %q", res.Body)
	}
	if res.Headers["Content-Disposition"] == "" {
		t.Errorf("заголовки ответа панели должны попасть в SubResponse.Headers: %+v", res.Headers)
	}
}

// TestSubscription_DoesNotForwardAcceptEncoding проверяет, что клиентское
// значение Accept-Encoding не долетает до панели как есть.
//
// Заголовок специально не пустой на "любое значение": сам Go, если запрос
// уходит вообще без Accept-Encoding, сам подставит на уровне транспорта
// "Accept-Encoding: gzip" (это и даёт прозрачную распаковку). Поэтому
// проверить, что панель "не видит Accept-Encoding вовсе", нельзя - она
// всегда что-то увидит. Проверяем другое: клиент шлёт "identity" (явно
// отключает сжатие), а если бы это значение долетело до панели как есть,
// сжатия бы не случилось и следующий тест был бы недостоверен. Панель
// должна увидеть значение по умолчанию от Go ("gzip"), а не "identity".
func TestSubscription_DoesNotForwardAcceptEncoding(t *testing.T) {
	var gotAE string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAE = r.Header.Get("Accept-Encoding")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("vless://example"))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL)
	in := http.Header{"Accept-Encoding": {"identity"}}
	if _, err := c.Subscription(context.Background(), "short-1", in); err != nil {
		t.Fatalf("Subscription: %v", err)
	}
	if gotAE == "identity" {
		t.Errorf("клиентский Accept-Encoding не должен долетать до панели как есть, панель увидела %q", gotAE)
	}
}

// TestSubscription_UpstreamGzip_TransparentlyDecoded проверяет обратную
// сторону того же требования: если панель сама решает сжать ответ (не
// дожидаясь Accept-Encoding от нас), клиент remnawave.Client получает уже
// разжатое тело - это и есть эффект от того, что Accept-Encoding в
// исходящем запросе не выставлен вручную (см. stripAcceptEncoding в
// internal/proxy и комментарий у forwardedSubHeaders).
func TestSubscription_UpstreamGzip_TransparentlyDecoded(t *testing.T) {
	const want = "vless://plain-body-must-be-readable"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write([]byte(want))
		_ = gz.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL)
	res, err := c.Subscription(context.Background(), "short-1", nil)
	if err != nil {
		t.Fatalf("Subscription: %v", err)
	}
	if string(res.Body) != want {
		t.Fatalf("тело должно быть прозрачно разжато, got %q", res.Body)
	}
}

func TestSubscription_StatusPassedThroughOn404(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL)
	res, err := c.Subscription(context.Background(), "missing", nil)
	// Subscription не интерпретирует статус, а прозрачно возвращает его вызывающему:
	// решение "это DecisionNotFound или маскировка" остаётся за пакетом proxy.
	if err != nil {
		t.Fatalf("Subscription не должен сам превращать 404 в error: %v", err)
	}
	if res.Status != http.StatusNotFound {
		t.Errorf("ожидал статус 404 в SubResponse, got %d", res.Status)
	}
}

func TestSubscription_BodyIsLimited(t *testing.T) {
	const oversize = int(maxSubBodyBytes) + (1 << 20) // на 1 МБ больше лимита
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("a", oversize)))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL)
	res, err := c.Subscription(context.Background(), "big", nil)
	if err != nil {
		t.Fatalf("Subscription: %v", err)
	}
	if int64(len(res.Body)) != maxSubBodyBytes {
		t.Fatalf("тело должно быть обрезано лимитом %d, got %d", maxSubBodyBytes, len(res.Body))
	}
}

func TestSubscription_RejectsEmptyShortUUID(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:0")
	if _, err := c.Subscription(context.Background(), "", nil); err == nil {
		t.Fatal("ожидал ошибку на пустой shortUUID")
	}
}
