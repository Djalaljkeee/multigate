package chat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/store"
)

func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "chat_test.db")
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

// mockTelegram поднимает подложку под Bot API: отдаёт message_id
// растущим счётчиком и запоминает последнее полученное тело.
type mockTelegram struct {
	*httptest.Server
	calls    int32
	lastForm url.Values
}

func newMockTelegram(t *testing.T) *mockTelegram {
	t.Helper()
	m := &mockTelegram{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("mockTelegram: не разобрать форму: %v", err)
		}
		m.lastForm = r.PostForm
		n := atomic.AddInt32(&m.calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"ok":true,"result":{"message_id":%d}}`, 1000+n)
	}))
	t.Cleanup(m.Close)
	return m
}

func configureChat(t *testing.T, db *store.DB, tgURL, tgChatID string) {
	t.Helper()
	ctx := context.Background()
	if err := db.SetMany(ctx, map[string]string{
		store.KeyChatEnabled:   "1",
		store.KeyChatTGToken:   "TEST:TOKEN123",
		store.KeyChatTGChat:    tgChatID,
		store.KeyChatTGAPIBase: tgURL,
	}); err != nil {
		t.Fatalf("настройка чата: %v", err)
	}
}

func doSend(s *Service, cookie *http.Cookie, text string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(sendRequest{Text: text})
	req := httptest.NewRequest(http.MethodPost, "/widget", strings.NewReader(string(body)))
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	s.handleWidget(rec, req)
	return rec
}

func doHistory(s *Service, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/widget", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	s.handleWidget(rec, req)
	return rec
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatal("в ответе нет куки сессии")
	return nil
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

// --- отправка сообщения и доставка в Telegram ---

func TestSendMessageCreatesSessionAndDelivers(t *testing.T) {
	db := openTestDB(t)
	tg := newMockTelegram(t)
	configureChat(t, db, tg.URL, "555")

	s := New(db, silentLogger())
	defer s.Close()

	rec := doSend(s, nil, "  Привет, есть вопрос по подписке  ")
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d, ждали 200: %s", rec.Code, rec.Body.String())
	}
	cookie := sessionCookie(t, rec)
	if !cookie.HttpOnly || !cookie.Secure {
		t.Errorf("кука сессии обязана быть HttpOnly и Secure: %+v", cookie)
	}
	if !validSessionFormat(cookie.Value) {
		t.Errorf("значение куки не проходит проверку формата: %q", cookie.Value)
	}

	var resp messageDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("ответ не JSON: %v", err)
	}
	if resp.Text != "Привет, есть вопрос по подписке" {
		t.Errorf("текст в ответе %q, пробелы по краям должны были обрезаться", resp.Text)
	}

	waitFor(t, 3*time.Second, func() bool { return atomic.LoadInt32(&tg.calls) == 1 })
	if got := tg.lastForm.Get("chat_id"); got != "555" {
		t.Errorf("chat_id в запросе к telegram %q, ждали 555", got)
	}
	if !strings.Contains(tg.lastForm.Get("text"), "Привет, есть вопрос по подписке") {
		t.Errorf("текст сообщения не дошёл до telegram: %q", tg.lastForm.Get("text"))
	}

	// delivered проставляется асинхронно после ответа Bot API. Опрашиваем базу
	// напрямую, а не через /history: у истории свой лимит запросов в минуту,
	// и polling через HTTP мог бы сам упереться в rate limit теста.
	waitFor(t, 3*time.Second, func() bool { return messageDelivered(t, s, cookie.Value) })

	// Убеждаемся, что и сам виджет теперь отдаёт delivered=true.
	h := doHistory(s, cookie)
	var hr historyResponse
	if err := json.Unmarshal(h.Body.Bytes(), &hr); err != nil {
		t.Fatalf("ответ не JSON: %v", err)
	}
	if len(hr.Messages) != 1 || !hr.Messages[0].Delivered {
		t.Fatalf("история виджета не отражает доставку: %+v", hr.Messages)
	}
}

func messageDelivered(t *testing.T, s *Service, sessionID string) bool {
	t.Helper()
	var delivered int
	err := s.db.RO().QueryRowContext(context.Background(),
		"SELECT delivered FROM chat_messages WHERE session_id = ? ORDER BY id DESC LIMIT 1", sessionID).Scan(&delivered)
	return err == nil && delivered == 1
}

func TestSendWhenChatDisabled(t *testing.T) {
	db := openTestDB(t) // chat_enabled по умолчанию "0"
	s := New(db, silentLogger())
	defer s.Close()

	rec := doSend(s, nil, "привет")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("код %d, ждали 503 при выключенном чате", rec.Code)
	}
}

func TestSendRejectsEmptyAndTooLong(t *testing.T) {
	db := openTestDB(t)
	tg := newMockTelegram(t)
	configureChat(t, db, tg.URL, "1")
	s := New(db, silentLogger())
	defer s.Close()

	if rec := doSend(s, nil, "   "); rec.Code != http.StatusBadRequest {
		t.Errorf("пустое сообщение: код %d, ждали 400", rec.Code)
	}
	if rec := doSend(s, nil, strings.Repeat("a", maxMessageRunes+1)); rec.Code != http.StatusBadRequest {
		t.Errorf("слишком длинное сообщение: код %d, ждали 400", rec.Code)
	}
}

// --- история доступна только владельцу сессии ---

func TestHistoryIsolatedByCookie(t *testing.T) {
	db := openTestDB(t)
	tg := newMockTelegram(t)
	configureChat(t, db, tg.URL, "1")
	s := New(db, silentLogger())
	defer s.Close()

	rec := doSend(s, nil, "моё сообщение")
	cookie := sessionCookie(t, rec)

	// Без куки должна быть пустая история, а не ошибка.
	h := doHistory(s, nil)
	var hr historyResponse
	if err := json.Unmarshal(h.Body.Bytes(), &hr); err != nil {
		t.Fatalf("ответ не JSON: %v", err)
	}
	if len(hr.Messages) != 0 {
		t.Errorf("без куки получили %d сообщений, ждали 0", len(hr.Messages))
	}

	// С поддельной, но корректной по формату сессией тоже должно быть пусто:
	// её нет в базе, значит она никому не принадлежит.
	fakeID, err := newSessionID()
	if err != nil {
		t.Fatalf("newSessionID: %v", err)
	}
	fake := &http.Cookie{Name: cookieName, Value: fakeID}
	h = doHistory(s, fake)
	hr = historyResponse{}
	_ = json.Unmarshal(h.Body.Bytes(), &hr)
	if len(hr.Messages) != 0 {
		t.Errorf("с чужим (несуществующим) session id получили %d сообщений, ждали 0", len(hr.Messages))
	}

	// А с настоящей кукой своя история видна.
	h = doHistory(s, cookie)
	hr = historyResponse{}
	if err := json.Unmarshal(h.Body.Bytes(), &hr); err != nil {
		t.Fatalf("ответ не JSON: %v", err)
	}
	if len(hr.Messages) != 1 || hr.Messages[0].Text != "моё сообщение" {
		t.Fatalf("владелец сессии не увидел своё сообщение: %+v", hr.Messages)
	}
}

// --- ограничение частоты ---

func TestRateLimiterAllowsUpToMaxThenBlocks(t *testing.T) {
	l := newLimiter(3, time.Minute)
	defer l.Close()

	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("попытка %d должна была пройти", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("четвёртая попытка должна была быть отклонена")
	}
	// У другого ключа свой независимый счётчик.
	if !l.Allow("other") {
		t.Fatal("другой ключ не должен быть ограничен чужим счётчиком")
	}
}

func TestHandlerEnforcesPerIPRateLimit(t *testing.T) {
	db := openTestDB(t)
	tg := newMockTelegram(t)
	configureChat(t, db, tg.URL, "1")
	s := New(db, silentLogger())
	defer s.Close()

	// httptest.NewRequest подставляет один и тот же RemoteAddr всем запросам:
	// это то же самое, как если бы все запросы пришли с одного IP.
	for i := 0; i < rateLimitPerIP; i++ {
		if rec := doSend(s, nil, fmt.Sprintf("сообщение %d", i)); rec.Code != http.StatusOK {
			t.Fatalf("сообщение %d: код %d, ждали 200: %s", i, rec.Code, rec.Body.String())
		}
	}
	rec := doSend(s, nil, "лишнее сообщение")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("код %d, ждали 429 после исчерпания лимита по IP", rec.Code)
	}
}

func TestHandlerEnforcesPerSessionRateLimit(t *testing.T) {
	db := openTestDB(t)
	tg := newMockTelegram(t)
	configureChat(t, db, tg.URL, "1")
	s := New(db, silentLogger())
	defer s.Close()

	// В этом тесте проверяем ИМЕННО лимит по сессии, а не по IP: у него порог
	// ниже, и все запросы теста идут с одного тестового RemoteAddr, поэтому
	// лимит по IP тут раздвинут.
	s.ipLimiter.Close()
	s.ipLimiter = newLimiter(rateLimitPerSession*10, rateLimitWindow)

	rec := doSend(s, nil, "первое")
	cookie := sessionCookie(t, rec)

	// Одно сообщение уже отправлено при создании сессии, досчитываем остальное.
	for i := 1; i < rateLimitPerSession; i++ {
		if rec := doSend(s, cookie, fmt.Sprintf("сообщение %d", i)); rec.Code != http.StatusOK {
			t.Fatalf("сообщение %d: код %d, ждали 200: %s", i, rec.Code, rec.Body.String())
		}
	}
	rec = doSend(s, cookie, "лишнее сообщение в той же сессии")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("код %d, ждали 429 после исчерпания лимита по сессии", rec.Code)
	}
}

// --- очередь отправки в telegram ---

func TestEnqueueOutboundOverflow(t *testing.T) {
	s := &Service{queue: make(chan tgOutbound, 1)}
	if !s.enqueueOutbound(tgOutbound{msgRowID: 1}) {
		t.Fatal("первое сообщение должно было поместиться")
	}
	if s.enqueueOutbound(tgOutbound{msgRowID: 2}) {
		t.Fatal("второе сообщение не должно было поместиться: очередь переполнена")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	s := New(db, silentLogger())
	s.Close()
	s.Close()
}

// --- ответ оператора из Telegram ---

func doTelegramWebhook(s *Service, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/tg/webhook", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleTelegramWebhook(rec, req)
	return rec
}

func TestOperatorReplyReachesWidget(t *testing.T) {
	db := openTestDB(t)
	tg := newMockTelegram(t)
	configureChat(t, db, tg.URL, "424242")
	s := New(db, silentLogger())
	defer s.Close()

	rec := doSend(s, nil, "вопрос от посетителя")
	cookie := sessionCookie(t, rec)

	// Дожидаемся, пока сообщение доставится и у него появится tg_msg_id.
	var tgMsgID int64
	waitFor(t, 3*time.Second, func() bool {
		id, ok := lastTGMsgID(t, s)
		if !ok {
			return false
		}
		tgMsgID = id
		return true
	})

	update := fmt.Sprintf(`{"message":{"message_id":%d,"text":"Ответ оператора","chat":{"id":424242},
		"reply_to_message":{"message_id":%d}}}`, tgMsgID+1, tgMsgID)
	if rec := doTelegramWebhook(s, update); rec.Code != http.StatusOK {
		t.Fatalf("код %d, ждали 200", rec.Code)
	}

	// Опрашиваем базу напрямую: polling через /history сам расходовал бы
	// лимит запросов виджета.
	waitFor(t, 2*time.Second, func() bool {
		var n int
		err := s.db.RO().QueryRowContext(context.Background(),
			"SELECT COUNT(*) FROM chat_messages WHERE session_id = ? AND from_user = 0 AND text = ?",
			cookie.Value, "Ответ оператора").Scan(&n)
		return err == nil && n == 1
	})

	// И финально убеждаемся, что через сам виджет ответ тоже виден.
	h := doHistory(s, cookie)
	var hr historyResponse
	if err := json.Unmarshal(h.Body.Bytes(), &hr); err != nil {
		t.Fatalf("ответ не JSON: %v", err)
	}
	found := false
	for _, m := range hr.Messages {
		if !m.FromUser && m.Text == "Ответ оператора" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ответ оператора не виден в истории виджета: %+v", hr.Messages)
	}
}

func lastTGMsgID(t *testing.T, s *Service) (int64, bool) {
	t.Helper()
	var id int64
	err := s.db.RO().QueryRowContext(context.Background(),
		"SELECT tg_msg_id FROM chat_messages WHERE from_user = 1 AND delivered = 1 ORDER BY id DESC LIMIT 1").Scan(&id)
	if err != nil {
		return 0, false
	}
	return id, true
}

func TestWebhookIgnoresWrongChat(t *testing.T) {
	db := openTestDB(t)
	tg := newMockTelegram(t)
	configureChat(t, db, tg.URL, "424242")
	s := New(db, silentLogger())
	defer s.Close()

	rec := doSend(s, nil, "вопрос")
	cookie := sessionCookie(t, rec)
	var tgMsgID int64
	waitFor(t, 3*time.Second, func() bool {
		id, ok := lastTGMsgID(t, s)
		tgMsgID = id
		return ok
	})

	// Апдейт из ЧУЖОГО чата не должен попасть в историю сессии.
	update := fmt.Sprintf(`{"message":{"message_id":999,"text":"чужой ответ","chat":{"id":1},
		"reply_to_message":{"message_id":%d}}}`, tgMsgID)
	doTelegramWebhook(s, update)

	time.Sleep(200 * time.Millisecond)
	h := doHistory(s, cookie)
	var hr historyResponse
	_ = json.Unmarshal(h.Body.Bytes(), &hr)
	for _, m := range hr.Messages {
		if m.Text == "чужой ответ" {
			t.Fatal("апдейт из постороннего чата не должен был попасть в историю")
		}
	}
}

func TestWebhookIgnoresNonReplyAndBadJSON(t *testing.T) {
	db := openTestDB(t)
	// Чат должен быть включён: иначе обработчик выйдет раньше по находке
	// ревью 4 и тест перестанет проверять то, что заявлено в его имени.
	if err := db.Set(context.Background(), store.KeyChatEnabled, "1"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}
	s := New(db, silentLogger())
	defer s.Close()

	if rec := doTelegramWebhook(s, `{"message":{"message_id":1,"text":"просто сообщение","chat":{"id":1}}}`); rec.Code != http.StatusOK {
		t.Errorf("код %d, ждали 200 (не reply, просто игнорируем)", rec.Code)
	}
	if rec := doTelegramWebhook(s, `не json вовсе`); rec.Code != http.StatusOK {
		t.Errorf("код %d, ждали 200 даже на битый JSON: Telegram не должен получать ошибку", rec.Code)
	}
}

// --- секрет вебхука Telegram (находка ревью 3) ---

// TestTelegramWebhookRequiresSecretToken проверяет: если секрет настроен,
// апдейт без верного заголовка X-Telegram-Bot-Api-Secret-Token отклоняется
// и не попадает в историю, даже если chat.id совпал.
func TestTelegramWebhookRequiresSecretToken(t *testing.T) {
	db := openTestDB(t)
	tg := newMockTelegram(t)
	configureChat(t, db, tg.URL, "424242")
	ctx := context.Background()
	if err := db.Set(ctx, KeyChatTGWebhookSecret, "wh-secret"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}
	s := New(db, silentLogger())
	defer s.Close()

	rec := doSend(s, nil, "вопрос")
	cookie := sessionCookie(t, rec)
	var tgMsgID int64
	waitFor(t, 3*time.Second, func() bool {
		id, ok := lastTGMsgID(t, s)
		tgMsgID = id
		return ok
	})

	sendUpdate := func(msgID int64, secretHeader string) int {
		update := fmt.Sprintf(`{"message":{"message_id":%d,"text":"ответ через вебхук","chat":{"id":424242},
			"reply_to_message":{"message_id":%d}}}`, msgID, tgMsgID)
		req := httptest.NewRequest(http.MethodPost, "/tg/webhook", strings.NewReader(update))
		if secretHeader != "" {
			req.Header.Set(tgSecretTokenHeader, secretHeader)
		}
		rr := httptest.NewRecorder()
		s.handleTelegramWebhook(rr, req)
		return rr.Code
	}

	if code := sendUpdate(tgMsgID+1, ""); code != http.StatusForbidden {
		t.Fatalf("без secret_token: код %d, ждали 403", code)
	}
	if code := sendUpdate(tgMsgID+2, "not-the-secret"); code != http.StatusForbidden {
		t.Fatalf("с неверным secret_token: код %d, ждали 403", code)
	}

	time.Sleep(200 * time.Millisecond)
	h := doHistory(s, cookie)
	var hr historyResponse
	_ = json.Unmarshal(h.Body.Bytes(), &hr)
	for _, m := range hr.Messages {
		if !m.FromUser {
			t.Fatal("без верного secret_token в истории не должно быть ответов оператора")
		}
	}

	if code := sendUpdate(tgMsgID+3, "wh-secret"); code != http.StatusOK {
		t.Fatalf("с верным secret_token: код %d, ждали 200", code)
	}
	waitFor(t, 2*time.Second, func() bool {
		h := doHistory(s, cookie)
		var hr historyResponse
		_ = json.Unmarshal(h.Body.Bytes(), &hr)
		for _, m := range hr.Messages {
			if !m.FromUser {
				return true
			}
		}
		return false
	})
}

// TestTelegramWebhookRateLimit проверяет находку ревью 3: приём апдейтов
// ограничен по частоте, отдельно от лимитов самого виджета.
func TestTelegramWebhookRateLimit(t *testing.T) {
	db := openTestDB(t)
	tg := newMockTelegram(t)
	configureChat(t, db, tg.URL, "1")
	s := New(db, silentLogger())
	defer s.Close()
	// Подменяем лимитер на тесный, чтобы не гонять сотню запросов в тесте.
	s.tgWebhookLimiter.Close()
	s.tgWebhookLimiter = newLimiter(2, time.Minute)

	body := `{"message":{"message_id":1,"text":"привет","chat":{"id":1}}}` // не reply, повод дойти до лимитера тот же
	for i := 0; i < 2; i++ {
		if rec := doTelegramWebhook(s, body); rec.Code != http.StatusOK {
			t.Fatalf("запрос %d: код %d, ждали 200", i+1, rec.Code)
		}
	}
	rec := doTelegramWebhook(s, body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("код %d, ждали 429 после исчерпания лимита частоты", rec.Code)
	}
}

// --- выключенный чат (находка ревью 4) ---

func TestHandleHistoryRespectsDisabledChat(t *testing.T) {
	db := openTestDB(t)
	tg := newMockTelegram(t)
	configureChat(t, db, tg.URL, "1")
	s := New(db, silentLogger())
	defer s.Close()

	rec := doSend(s, nil, "моё сообщение")
	cookie := sessionCookie(t, rec)

	// Пока чат включён, история по своей куке видна.
	if h := doHistory(s, cookie); h.Code != http.StatusOK {
		t.Fatalf("код %d при включённом чате, ждали 200", h.Code)
	}

	// Выключаем чат: история не должна отдаваться даже по куке уже
	// существующей сессии.
	if err := db.Set(context.Background(), store.KeyChatEnabled, "0"); err != nil {
		t.Fatalf("db.Set: %v", err)
	}
	if h := doHistory(s, cookie); h.Code != http.StatusServiceUnavailable {
		t.Fatalf("код %d при выключенном чате, ждали 503", h.Code)
	}
}

// --- чистка старых сессий и сообщений (находка ревью 4) ---

func TestPruneRemovesInactiveSessionsAndMessages(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	s := New(db, silentLogger())
	defer s.Close()

	old := time.Now().AddDate(0, 0, -100).Unix()
	fresh := time.Now().Unix()

	if _, err := db.RW().ExecContext(ctx,
		"INSERT INTO chat_sessions (session_id, created_at, last_at) VALUES (?,?,?)", "old-session", old, old); err != nil {
		t.Fatalf("подготовка старой сессии: %v", err)
	}
	if _, err := db.RW().ExecContext(ctx,
		"INSERT INTO chat_sessions (session_id, created_at, last_at) VALUES (?,?,?)", "fresh-session", fresh, fresh); err != nil {
		t.Fatalf("подготовка свежей сессии: %v", err)
	}
	if _, err := db.RW().ExecContext(ctx,
		"INSERT INTO chat_messages (session_id, at, from_user, text, tg_msg_id, delivered) VALUES (?,?,?,?,?,?)",
		"old-session", old, 1, "старое сообщение", 0, 0); err != nil {
		t.Fatalf("подготовка старого сообщения: %v", err)
	}
	if _, err := db.RW().ExecContext(ctx,
		"INSERT INTO chat_messages (session_id, at, from_user, text, tg_msg_id, delivered) VALUES (?,?,?,?,?,?)",
		"fresh-session", fresh, 1, "свежее сообщение", 0, 0); err != nil {
		t.Fatalf("подготовка свежего сообщения: %v", err)
	}

	n, err := s.Prune(ctx, 30)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 2 {
		t.Fatalf("удалено %d строк, ждали 2 (старая сессия + её сообщение)", n)
	}

	if s.sessionExists(ctx, "old-session") {
		t.Fatal("старая сессия должна была удалиться")
	}
	if !s.sessionExists(ctx, "fresh-session") {
		t.Fatal("свежая сессия не должна была удалиться")
	}
	msgs, err := s.listMessages(ctx, "fresh-session")
	if err != nil || len(msgs) != 1 {
		t.Fatalf("свежие сообщения должны были остаться: %v %v", err, msgs)
	}
	msgs, err = s.listMessages(ctx, "old-session")
	if err != nil || len(msgs) != 0 {
		t.Fatalf("сообщения старой сессии должны были удалиться: %v %v", err, msgs)
	}
}

func TestPruneNoopWhenKeepDaysNotPositive(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	s := New(db, silentLogger())
	defer s.Close()

	old := time.Now().AddDate(-1, 0, 0).Unix()
	if _, err := db.RW().ExecContext(ctx,
		"INSERT INTO chat_sessions (session_id, created_at, last_at) VALUES (?,?,?)", "ancient", old, old); err != nil {
		t.Fatalf("подготовка сессии: %v", err)
	}

	n, err := s.Prune(ctx, 0)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 0 {
		t.Fatalf("keepDays<=0 должен быть выключателем чистки, удалено %d", n)
	}
	if !s.sessionExists(ctx, "ancient") {
		t.Fatal("сессия не должна была удалиться при keepDays<=0")
	}
}

// --- токен никогда не должен утекать в текст ошибки ---

func TestRedactTokenHidesSecret(t *testing.T) {
	token := "123456789:AAExampleTokenAbsolutelySecretValue"
	urlErr := &url.Error{
		Op:  "Post",
		URL: "https://api.telegram.org/bot" + token + "/sendMessage",
		Err: errors.New("connection refused"),
	}
	redacted := redactToken(urlErr, token)
	if redacted == nil {
		t.Fatal("redactToken вернул nil")
	}
	if strings.Contains(redacted.Error(), token) {
		t.Fatalf("токен утёк в текст ошибки: %q", redacted.Error())
	}
	if !strings.Contains(redacted.Error(), "***") {
		t.Errorf("ожидали маску *** в тексте ошибки: %q", redacted.Error())
	}
}

// --- формат идентификатора сессии ---

func TestSessionIDFormat(t *testing.T) {
	id, err := newSessionID()
	if err != nil {
		t.Fatalf("newSessionID: %v", err)
	}
	if !validSessionFormat(id) {
		t.Fatalf("сгенерированный id не проходит собственную проверку формата: %q", id)
	}

	bad := []string{"", "not-hex", strings.Repeat("g", 48), strings.Repeat("a", 47), strings.Repeat("a", 49)}
	for _, b := range bad {
		if validSessionFormat(b) {
			t.Errorf("значение %q не должно проходить проверку формата", b)
		}
	}
}
