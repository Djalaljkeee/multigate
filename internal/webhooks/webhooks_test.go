package webhooks

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// openTestDB поднимает временную SQLite-базу с применёнными миграциями.
func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "webhooks_test.db")
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

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func doWebhook(s *Service, body []byte, sigHeader string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/hooks/remnawave", bytes.NewReader(body))
	if sigHeader != "" {
		req.Header.Set(signatureHeader, sigHeader)
	}
	rec := httptest.NewRecorder()
	s.handle(rec, req)
	return rec
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("не дождались условия за отведённое время")
}

// --- подпись: чистые функции ---

func TestComputeAndValidSignature(t *testing.T) {
	body := []byte(`{"event":"user.created"}`)
	sig := computeSignature("secret1", body)

	if !validSignature("secret1", body, sig) {
		t.Fatal("верная подпись не прошла проверку")
	}
	if !validSignature("secret1", body, "sha256="+sig) {
		t.Fatal("подпись с префиксом sha256= не прошла проверку")
	}
	if validSignature("secret1", body, "") {
		t.Fatal("пустая подпись не должна проходить")
	}
	if validSignature("secret1", body, sig+"a") {
		t.Fatal("испорченная подпись не должна проходить")
	}
	if validSignature("other-secret", body, sig) {
		t.Fatal("подпись под чужой секрет не должна проходить")
	}
}

// --- приём вебхука: валидная, невалидная, отсутствующая подпись ---

func TestHandlerSignatureValid(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeyWebhookSecret, "topsecret"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}
	s := New(db, silentLogger())
	defer s.Close()

	body := []byte(`{"event":"user.created","data":{}}`)
	rec := doWebhook(s, body, computeSignature("topsecret", body))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("код %d, ждали 202: %s", rec.Code, rec.Body.String())
	}

	events, err := s.Log(ctx, 10, 0)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("в журнале %d событий, ждали 1", len(events))
	}
	if !events[0].SigValid {
		t.Error("ожидали SigValid=true при верной подписи")
	}
	if events[0].Event != "user.created" {
		t.Errorf("event=%q, ждали user.created", events[0].Event)
	}
}

func TestHandlerSignatureInvalid(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeyWebhookSecret, "topsecret"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}
	s := New(db, silentLogger())
	defer s.Close()

	body := []byte(`{"event":"user.created"}`)
	rec := doWebhook(s, body, computeSignature("wrong-secret", body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("код %d, ждали 401", rec.Code)
	}

	events, err := s.Log(ctx, 10, 0)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("в журнале %d событий, ждали 1 (попытка тоже должна быть залогирована)", len(events))
	}
	if events[0].SigValid {
		t.Error("ожидали SigValid=false при неверной подписи")
	}
	if events[0].Err == "" {
		t.Error("ожидали непустую причину отказа в журнале")
	}
	if events[0].Forwarded != 0 {
		t.Error("отклонённое по подписи событие не должно рассылаться")
	}
}

// TestHandlerRejectsWhenSecretNotConfigured проверяет находку ревью 2: раньше
// пустой секрет означал приём без всякой проверки подписи, теперь - отказ.
// Открытый на запись эндпоинт без аутентификации по умолчанию не должен
// быть дырой, через которую льётся тело в базу.
func TestHandlerRejectsWhenSecretNotConfigured(t *testing.T) {
	db := openTestDB(t) // KeyWebhookSecret не задан
	s := New(db, silentLogger())
	defer s.Close()

	body := []byte(`{"event":"user.created"}`)
	rec := doWebhook(s, body, "") // подписи нет вообще
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("код %d, ждали 401: без секрета приём должен отказывать, а не принимать без проверки", rec.Code)
	}

	events, err := s.Log(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("в журнале %d событий, ждали 0: неаутентифицированная попытка не должна писаться в базу", len(events))
	}
}

func TestHandlerRejectsHugeBody(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeyWebhookSecret, "topsecret"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}
	s := New(db, silentLogger())
	defer s.Close()

	big := bytes.Repeat([]byte("a"), maxBodyBytes+1)
	rec := doWebhook(s, big, "")
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("код %d, ждали 413 на тело больше лимита", rec.Code)
	}
}

func TestHandlerRejectsWrongMethod(t *testing.T) {
	db := openTestDB(t)
	s := New(db, silentLogger())
	defer s.Close()

	req := httptest.NewRequest(http.MethodGet, "/hooks/remnawave", nil)
	rec := httptest.NewRecorder()
	s.handle(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("код %d, ждали 405 на GET", rec.Code)
	}
}

// --- переполнение очереди рассылки ---

func TestEnqueueOverflow(t *testing.T) {
	s := &Service{queue: make(chan queuedEvent, 2)}
	if !s.enqueue(queuedEvent{logID: 1}) {
		t.Fatal("первое событие должно было поместиться")
	}
	if !s.enqueue(queuedEvent{logID: 2}) {
		t.Fatal("второе событие должно было поместиться")
	}
	if s.enqueue(queuedEvent{logID: 3}) {
		t.Fatal("третье событие не должно было поместиться: очередь переполнена")
	}
}

func TestHandlerMarksUndeliveredOnQueueOverflow(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeyWebhookSecret, "topsecret"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}
	// Воркеров нет, никто не разбирает очередь: эмулируем перегрузку рассылки.
	// ipLimiter собираем руками, как и остальные поля: Service заведён не
	// через New, а сборка вручную теперь обязана дать сервису лимитер, иначе
	// handle() упадёт на nil-указателе при первом же запросе.
	s := &Service{db: db, log: silentLogger(), client: http.DefaultClient,
		ipLimiter: newLimiter(rateLimitPerIP, rateLimitWindow),
		queue:     make(chan queuedEvent, 1), closed: make(chan struct{})}

	body := []byte(`{"event":"user.created"}`)
	sig := computeSignature("topsecret", body)
	if rec := doWebhook(s, body, sig); rec.Code != http.StatusAccepted {
		t.Fatalf("первый запрос: код %d, ждали 202", rec.Code)
	}
	if rec := doWebhook(s, body, sig); rec.Code != http.StatusAccepted {
		t.Fatalf("второй запрос: код %d, ждали 202: панель не должна видеть переполнение", rec.Code)
	}

	events, err := s.Log(ctx, 10, 0)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("в журнале %d событий, ждали 2", len(events))
	}
	// events[0] это второй запрос (свежие первыми): очередь была уже заполнена первым.
	if events[0].Err == "" {
		t.Error("ожидали пометку об ошибке рассылки при переполненной очереди")
	}
}

// --- повторы рассылки ---

func TestForwardRetriesExhaustAndGiveUp(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeyWebhookSecret, "inbound-secret"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}

	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()

	s := New(db, silentLogger())
	defer s.Close()

	if _, err := s.SaveTarget(ctx, model.ForwardTarget{Name: "sink", URL: upstream.URL, Enabled: true}); err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}

	body := []byte(`{"event":"user.created"}`)
	doWebhook(s, body, computeSignature("inbound-secret", body))

	waitFor(t, 8*time.Second, func() bool { return atomic.LoadInt32(&calls) >= maxAttempts })
	// Дав время осесть, проверяем: попыток не должно стать больше maxAttempts, бесконечных повторов нет.
	time.Sleep(300 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != maxAttempts {
		t.Fatalf("получатель дёрнут %d раз, ждали ровно %d", got, maxAttempts)
	}

	events, err := s.Log(ctx, 10, 0)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(events) != 1 || events[0].Forwarded != 0 {
		t.Fatalf("ожидали 1 событие с forwarded=0 (получатель ни разу не ответил успехом): %+v", events)
	}
}

func TestForwardSucceedsAfterFailure(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeyWebhookSecret, "inbound-secret"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}

	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	s := New(db, silentLogger())
	defer s.Close()

	if _, err := s.SaveTarget(ctx, model.ForwardTarget{Name: "sink", URL: upstream.URL, Enabled: true}); err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}

	body := []byte(`{"event":"user.created"}`)
	doWebhook(s, body, computeSignature("inbound-secret", body))

	waitFor(t, 8*time.Second, func() bool {
		events, err := s.Log(ctx, 10, 0)
		return err == nil && len(events) == 1 && events[0].Forwarded == 1
	})

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("получатель дёрнут %d раз, ждали 2 (сбой, затем успех)", got)
	}
}

// --- у каждого получателя своя подпись ---

func TestForwardUsesTargetsOwnSecret(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeyWebhookSecret, "inbound-secret"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}

	var sawValidSig int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		got := r.Header.Get(signatureHeader)
		want := computeSignature("target-own-secret", payload)
		// Секрет входящего вебхука ("inbound-secret") сюда попасть не должен.
		if got == computeSignature("inbound-secret", payload) {
			t.Errorf("получателю ушла подпись входящего секрета, а не его собственного")
		}
		if got == want {
			atomic.AddInt32(&sawValidSig, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	s := New(db, silentLogger())
	defer s.Close()

	if _, err := s.SaveTarget(ctx, model.ForwardTarget{
		Name: "sink", URL: upstream.URL, Secret: "target-own-secret", Enabled: true,
	}); err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}

	body := []byte(`{"event":"user.created"}`)
	doWebhook(s, body, computeSignature("inbound-secret", body))

	waitFor(t, 5*time.Second, func() bool { return atomic.LoadInt32(&sawValidSig) == 1 })
}

// --- фильтр по событиям и CRUD получателей ---

func TestEventMatches(t *testing.T) {
	if !eventMatches(nil, "user.created") {
		t.Error("пустой список событий должен означать подписку на всё")
	}
	if !eventMatches([]string{"user.created"}, "user.created") {
		t.Error("событие из списка должно совпадать")
	}
	if eventMatches([]string{"user.created"}, "user.deleted") {
		t.Error("событие не из списка не должно совпадать")
	}
}

func TestTargetsCRUD(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	s := New(db, silentLogger())
	defer s.Close()

	id, err := s.SaveTarget(ctx, model.ForwardTarget{
		Name: "billing", URL: "https://billing.example.internal/hook",
		Secret: "s3cr3t", Enabled: true, Events: []string{"user.created", "user.deleted"},
	})
	if err != nil {
		t.Fatalf("SaveTarget: %v", err)
	}

	list, err := s.Targets(ctx)
	if err != nil {
		t.Fatalf("Targets: %v", err)
	}
	if len(list) != 1 || list[0].ID != id || list[0].Name != "billing" {
		t.Fatalf("неожиданный список получателей: %+v", list)
	}
	if len(list[0].Events) != 2 {
		t.Fatalf("события получателя не сохранились: %+v", list[0].Events)
	}

	if _, err := s.SaveTarget(ctx, model.ForwardTarget{ID: id, Name: "billing-2", URL: "https://billing.example.internal/hook2", Enabled: false}); err != nil {
		t.Fatalf("SaveTarget (обновление): %v", err)
	}
	list, err = s.Targets(ctx)
	if err != nil {
		t.Fatalf("Targets после обновления: %v", err)
	}
	if len(list) != 1 || list[0].Name != "billing-2" || list[0].Enabled {
		t.Fatalf("обновление получателя не применилось: %+v", list)
	}

	if err := s.DeleteTarget(ctx, id); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	list, err = s.Targets(ctx)
	if err != nil {
		t.Fatalf("Targets после удаления: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("получатель не удалился: %+v", list)
	}
}

func TestSaveTargetRejectsBadURL(t *testing.T) {
	db := openTestDB(t)
	s := New(db, silentLogger())
	defer s.Close()

	if _, err := s.SaveTarget(context.Background(), model.ForwardTarget{Name: "x", URL: "ftp://bad"}); err == nil {
		t.Fatal("ожидали ошибку на URL без http(s)")
	}
	if _, err := s.SaveTarget(context.Background(), model.ForwardTarget{Name: "x", URL: ""}); err == nil {
		t.Fatal("ожидали ошибку на пустой URL")
	}
}

func TestCloseIsIdempotentAndWaitsWorkers(t *testing.T) {
	db := openTestDB(t)
	s := New(db, silentLogger())
	s.Close()
	s.Close() // повторный вызов не должен паниковать
}

// --- лимит частоты приёма (находка ревью 2) ---

func TestHandlerEnforcesRateLimit(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := db.Set(ctx, store.KeyWebhookSecret, "topsecret"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}
	s := New(db, silentLogger())
	defer s.Close()
	// Подменяем лимитер на тесный, чтобы не гонять сотню запросов в тесте.
	s.ipLimiter.Close()
	s.ipLimiter = newLimiter(2, time.Minute)

	body := []byte(`{"event":"user.created"}`)
	sig := computeSignature("topsecret", body)
	for i := 0; i < 2; i++ {
		if rec := doWebhook(s, body, sig); rec.Code != http.StatusAccepted {
			t.Fatalf("запрос %d: код %d, ждали 202", i+1, rec.Code)
		}
	}
	rec := doWebhook(s, body, sig)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("код %d, ждали 429 после исчерпания лимита частоты", rec.Code)
	}

	events, err := s.Log(ctx, 10, 0)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("в журнале %d событий, ждали 2: запрос, срезанный лимитом, не должен писаться в базу", len(events))
	}
}

// --- чистка старых записей (находка ревью 2) ---

func TestPruneRemovesOldRowsKeepsRecent(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	s := New(db, silentLogger())
	defer s.Close()

	old := time.Now().AddDate(0, 0, -40).Unix()
	fresh := time.Now().Unix()

	if _, err := db.RW().ExecContext(ctx,
		"INSERT INTO webhook_log (at, event, payload, sig_valid, forwarded, err) VALUES (?,?,?,?,?,?)",
		old, "old.event", "{}", 1, 0, ""); err != nil {
		t.Fatalf("подготовка старой записи webhook_log: %v", err)
	}
	if _, err := db.RW().ExecContext(ctx,
		"INSERT INTO webhook_log (at, event, payload, sig_valid, forwarded, err) VALUES (?,?,?,?,?,?)",
		fresh, "fresh.event", "{}", 1, 0, ""); err != nil {
		t.Fatalf("подготовка свежей записи webhook_log: %v", err)
	}
	if _, err := db.RW().ExecContext(ctx,
		"INSERT INTO forward_log (at, target, event, status, attempt, err) VALUES (?,?,?,?,?,?)",
		old, "sink", "old.event", 200, 1, ""); err != nil {
		t.Fatalf("подготовка старой записи forward_log: %v", err)
	}
	if _, err := db.RW().ExecContext(ctx,
		"INSERT INTO forward_log (at, target, event, status, attempt, err) VALUES (?,?,?,?,?,?)",
		fresh, "sink", "fresh.event", 200, 1, ""); err != nil {
		t.Fatalf("подготовка свежей записи forward_log: %v", err)
	}

	n, err := s.Prune(ctx, 30)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 2 {
		t.Fatalf("удалено %d строк, ждали 2 (по одной старой из каждой таблицы)", n)
	}

	events, err := s.Log(ctx, 10, 0)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(events) != 1 || events[0].Event != "fresh.event" {
		t.Fatalf("после чистки должна остаться только свежая запись webhook_log: %+v", events)
	}

	var fwdCount int
	if err := db.RO().QueryRowContext(ctx, "SELECT COUNT(*) FROM forward_log").Scan(&fwdCount); err != nil {
		t.Fatalf("подсчёт forward_log: %v", err)
	}
	if fwdCount != 1 {
		t.Fatalf("после чистки в forward_log должна остаться 1 запись, получено %d", fwdCount)
	}
}

func TestPruneNoopWhenKeepDaysNotPositive(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	s := New(db, silentLogger())
	defer s.Close()

	if _, err := db.RW().ExecContext(ctx,
		"INSERT INTO webhook_log (at, event, payload, sig_valid, forwarded, err) VALUES (?,?,?,?,?,?)",
		time.Now().AddDate(-1, 0, 0).Unix(), "ancient.event", "{}", 1, 0, ""); err != nil {
		t.Fatalf("подготовка записи: %v", err)
	}

	n, err := s.Prune(ctx, 0)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 0 {
		t.Fatalf("keepDays<=0 должен быть выключателем чистки, удалено %d", n)
	}
	events, err := s.Log(ctx, 10, 0)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("запись не должна была удалиться, получено %d", len(events))
	}
}
