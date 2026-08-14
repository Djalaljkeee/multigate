package webhooks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/qwe8nxtroud/multigate/internal/store"
)

// Handler отдаёт обработчик входящих вебхуков панели.
func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(s.handle)
}

func (s *Service) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Лимит частоты - первым делом и максимально дёшево: до чтения тела и
	// обращений к базе. Находка ревью 2: без него шторм POST-запросов (в том
	// числе на случайно открытый в интернет эндпоинт) кладёт базу телами
	// вебхуков раньше, чем сработает любая другая защита.
	if !s.ipLimiter.Allow(clientIP(r)) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "слишком много запросов", http.StatusTooManyRequests)
		return
	}

	ctx := r.Context()
	secret := s.db.Get(ctx, store.KeyWebhookSecret)
	if secret == "" {
		// Находка ревью 2: раньше при пустом секрете приём просто не проверял
		// подпись и принимал тело от кого угодно. Открытый на запись эндпоинт
		// без проверки - дыра по умолчанию, поэтому теперь отказываем всем,
		// пока администратор не задаст секрет в админке. Тело даже не читаем
		// и в webhook_log ничего не пишем: неаутентифицированной попытке в
		// базе делать нечего, а лимит выше уже ограничил, сколько раз в
		// минуту с одного IP вообще дойдёт до этой проверки.
		http.Error(w, "приём вебхуков не настроен: не задан секрет", http.StatusUnauthorized)
		return
	}

	// Тело ограничиваем ДО чтения: приём не должен стать способом положить
	// базу гигабайтным телом запроса.
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "тело запроса слишком большое или повреждено", http.StatusRequestEntityTooLarge)
		return
	}

	if !validSignature(secret, body, r.Header.Get(signatureHeader)) {
		// Несовпадение означает подделку или рассинхронизацию секретов,
		// дальше событие не идёт, но попытка видна в журнале.
		s.recordRejected(ctx, body)
		http.Error(w, "неверная подпись", http.StatusUnauthorized)
		return
	}

	// До этой строки подпись всегда проверена и верна: секрет обязателен
	// (проверка выше), а без совпадения подписи функция уже вернула 401.
	event := extractEvent(body)
	logID, err := s.insertLog(ctx, event, body, true, "")
	if err != nil {
		s.log.Error("вебхуки: не записать событие в журнал", "err", err)
		http.Error(w, "внутренняя ошибка", http.StatusInternalServerError)
		return
	}

	if !s.enqueue(queuedEvent{logID: logID, event: event, payload: body}) {
		s.log.Warn("вебхуки: очередь рассылки переполнена, событие принято без рассылки", "event", event)
		s.markUndelivered(ctx, logID, "очередь рассылки переполнена, событие не разослано")
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// recordRejected фиксирует в журнале попытку с неверной подписью.
// Само событие в очередь на рассылку не ставится: принять решение
// доверять ли телу с чужой (или неверной) подписью прослойка не может.
func (s *Service) recordRejected(ctx context.Context, body []byte) {
	event := extractEvent(body)
	if _, err := s.insertLog(ctx, event, body, false, "подпись не прошла проверку"); err != nil {
		s.log.Error("вебхуки: не записать отклонённое событие", "err", err)
	}
}

// eventEnvelope: минимальный разбор тела для определения имени события.
// Разные версии панели могут называть поле по-разному, поэтому пробуем
// несколько вероятных вариантов; само тело в любом случае сохраняется
// целиком и как есть.
type eventEnvelope struct {
	Event  string `json:"event"`
	Type   string `json:"type"`
	Action string `json:"action"`
}

func extractEvent(body []byte) string {
	var e eventEnvelope
	if json.Unmarshal(body, &e) == nil {
		switch {
		case e.Event != "":
			return e.Event
		case e.Type != "":
			return e.Type
		case e.Action != "":
			return e.Action
		}
	}
	return "unknown"
}

func (s *Service) insertLog(ctx context.Context, event string, body []byte, sigValid bool, errText string) (int64, error) {
	res, err := s.db.RW().ExecContext(ctx,
		"INSERT INTO webhook_log (at, event, payload, sig_valid, forwarded, err) VALUES (?,?,?,?,?,?)",
		nowUnix(), truncate(event, 190), string(body), boolInt(sigValid), 0, truncate(errText, 500))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Service) markUndelivered(ctx context.Context, logID int64, errText string) {
	if _, err := s.db.RW().ExecContext(ctx,
		"UPDATE webhook_log SET err = ? WHERE id = ?", truncate(errText, 500), logID); err != nil {
		s.log.Error("вебхуки: не отметить недоставленное событие", "err", err)
	}
}
