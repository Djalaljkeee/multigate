package chat

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/qwe8nxtroud/multigate/internal/store"
)

const (
	maxMessageBodyBytes = 8 << 10 // 8 КБ, с большим запасом на JSON-обвязку одного сообщения
	maxMessageRunes     = 4000    // предел Telegram на одно сообщение: 4096 символов
	historyLimit        = 200     // сколько последних сообщений отдаём в историю виджета
)

// Handler отдаёт JSON API виджета на одном пути: POST отправляет
// сообщение, GET возвращает историю текущей сессии. Разделение по методу,
// а не по под-пути, сделано так, чтобы обработчик работал независимо от того,
// как вызывающий код смонтирует его в общий мультиплексор.
func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(s.handleWidget)
}

func (s *Service) handleWidget(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleSend(w, r)
	case http.MethodGet:
		s.handleHistory(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// sendRequest задаёт тело запроса на отправку сообщения посетителем.
type sendRequest struct {
	Text string `json:"text"`
}

// messageDTO представляет сообщение в ответе виджета.
type messageDTO struct {
	ID        int64  `json:"id"`
	At        int64  `json:"at"`
	FromUser  bool   `json:"from_user"`
	Text      string `json:"text"`
	Delivered bool   `json:"delivered"`
}

func (s *Service) handleSend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.db.GetBool(ctx, store.KeyChatEnabled) {
		http.Error(w, "чат поддержки выключен", http.StatusServiceUnavailable)
		return
	}

	// Лимит по IP проверяем до чего бы то ни было ещё: он должен резать
	// спам максимально дёшево, не тратя на это сессию или базу.
	if !s.ipLimiter.Allow("ip:" + clientIP(r)) {
		s.tooManyRequests(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxMessageBodyBytes)
	var req sendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "не удалось разобрать тело запроса", http.StatusBadRequest)
		return
	}

	text := sanitizeMessage(req.Text)
	if text == "" {
		http.Error(w, "пустое сообщение", http.StatusBadRequest)
		return
	}
	if utf8.RuneCountInString(text) > maxMessageRunes {
		http.Error(w, "сообщение слишком длинное", http.StatusBadRequest)
		return
	}

	sessionID, err := s.ensureSession(ctx, w, r)
	if err != nil {
		s.log.Error("чат: не создать сессию посетителя", "err", err)
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}
	if !s.sessionLimiter.Allow("sess:" + sessionID) {
		s.tooManyRequests(w)
		return
	}

	msgID, at, err := s.storeMessage(ctx, sessionID, true, text, 0, false)
	if err != nil {
		s.log.Error("чат: не сохранить сообщение посетителя", "err", err)
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}
	s.touchSession(ctx, sessionID)

	// Отправка в Telegram выполняется асинхронно: посетитель не должен ждать
	// чужое зеркало Bot API. Сообщение уже сохранено и видно в истории
	// виджета независимо от исхода доставки.
	if !s.enqueueOutbound(tgOutbound{msgRowID: msgID, sessionID: sessionID, text: text}) {
		s.log.Warn("чат: очередь отправки в telegram переполнена, сообщение сохранено локально")
	}

	writeJSON(w, http.StatusOK, messageDTO{ID: msgID, At: at, FromUser: true, Text: text})
}

func (s *Service) handleHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Находка ревью 4: раньше история отдавалась даже при выключенном чате,
	// если у посетителя оставалась старая кука сессии. Выключенный чат
	// должен вести себя одинаково что на отправке (см. handleSend выше),
	// что на чтении.
	if !s.db.GetBool(ctx, store.KeyChatEnabled) {
		http.Error(w, "чат поддержки выключен", http.StatusServiceUnavailable)
		return
	}
	if !s.ipLimiter.Allow("history:" + clientIP(r)) {
		s.tooManyRequests(w)
		return
	}

	// Единственный источник сессии: httpOnly-кука. Идентификатор из
	// query или тела запроса сюда сознательно не подмешивается: иначе чужую
	// историю можно было бы прочитать, просто подставив чужой id в адрес.
	sessionID, ok := sessionFromCookie(r)
	if !ok || !s.sessionExists(ctx, sessionID) {
		writeJSON(w, http.StatusOK, historyResponse{Messages: []messageDTO{}})
		return
	}

	msgs, err := s.listMessages(ctx, sessionID)
	if err != nil {
		s.log.Error("чат: не прочитать историю", "err", err)
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, historyResponse{Messages: msgs})
}

type historyResponse struct {
	Messages []messageDTO `json:"messages"`
}

func (s *Service) listMessages(ctx context.Context, sessionID string) ([]messageDTO, error) {
	rows, err := s.db.RO().QueryContext(ctx,
		`SELECT id, at, from_user, text, delivered FROM chat_messages
		 WHERE session_id = ? ORDER BY at ASC, id ASC LIMIT ?`,
		sessionID, historyLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []messageDTO{}
	for rows.Next() {
		var (
			m         messageDTO
			fromUser  int
			delivered int
		)
		if err := rows.Scan(&m.ID, &m.At, &fromUser, &m.Text, &delivered); err != nil {
			return nil, err
		}
		m.FromUser = fromUser != 0
		m.Delivered = delivered != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Service) storeMessage(ctx context.Context, sessionID string, fromUser bool, text string, tgMsgID int64, delivered bool) (id int64, at int64, err error) {
	at = nowUnix()
	res, err := s.db.RW().ExecContext(ctx,
		"INSERT INTO chat_messages (session_id, at, from_user, text, tg_msg_id, delivered) VALUES (?,?,?,?,?,?)",
		sessionID, at, boolInt(fromUser), truncate(text, maxMessageRunes), tgMsgID, boolInt(delivered))
	if err != nil {
		return 0, 0, err
	}
	id, err = res.LastInsertId()
	return id, at, err
}

func (s *Service) markDelivered(ctx context.Context, rowID, tgMsgID int64) {
	if _, err := s.db.RW().ExecContext(ctx,
		"UPDATE chat_messages SET delivered = 1, tg_msg_id = ? WHERE id = ?", tgMsgID, rowID); err != nil {
		s.log.Error("чат: не отметить доставку сообщения", "err", err)
	}
}

func (s *Service) tooManyRequests(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "30")
	http.Error(w, "слишком много сообщений, попробуйте позже", http.StatusTooManyRequests)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// sanitizeMessage готовит текст к сохранению и отправке: убирает края
// пробелов и гарантирует валидный UTF-8, чтобы дальше текст спокойно
// ложился в JSON ответа и в form-urlencoded тело запроса к Bot API.
func sanitizeMessage(s string) string {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	return s
}

// clientIP берёт адрес из RemoteAddr без разбора заголовков вроде
// X-Forwarded-For. Доверенные прокси и их сети настраивает слой, который
// монтирует Handler в общий мультиплексор (там же, где известен
// store.KeyTrustedProxies), а не этот пакет.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
