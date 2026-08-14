package chat

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"time"
)

const (
	// cookieName: кука, которой сервер помечает сессию посетителя.
	// HttpOnly, поэтому скрипту на странице значение недоступно, а значит и
	// украсть его через XSS на самой странице подписки нельзя.
	cookieName = "mg_chat_sid"

	sessionIDBytes   = 24                   // 192 бита энтропии, угадать перебором нереально
	sessionCookieTTL = 180 * 24 * time.Hour // посетитель может вернуться к диалогу спустя недели
)

// sessionIDPattern задаёт формат идентификатора сессии: ровно то, что выдаёт
// newSessionID. Любое значение другой формы (в том числе присланное
// клиентом руками) отбрасывается ДО того, как попадёт в SQL-запрос.
var sessionIDPattern = regexp.MustCompile(`^[0-9a-f]{48}$`)

// newSessionID генерирует идентификатор сессии на сервере. Клиент никогда
// не выбирает свой id: это единственный способ гарантировать, что чужую
// сессию нельзя ни угадать, ни навязать.
func newSessionID() (string, error) {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validSessionFormat(id string) bool {
	return sessionIDPattern.MatchString(id)
}

// sessionFromCookie достаёт id сессии из куки посетителя. Формат
// проверяется тут же, дальше по коду это значение можно использовать
// как обычный идентификатор без дополнительных оглядок.
func sessionFromCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil || !validSessionFormat(c.Value) {
		return "", false
	}
	return c.Value, true
}

// setSessionCookie выставляет куку сессии. Secure стоит безусловно:
// прослойка всегда работает за TLS-терминирующим обратным прокси
// (см. deploy/install.sh), сам процесс с браузером напрямую по HTTPS
// не общается, но снаружи соединение всегда защищённое.
func setSessionCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionCookieTTL.Seconds()),
	})
}

// ensureSession возвращает id сессии посетителя, создавая новую запись
// и куку при необходимости. Кука с валидным форматом, но без записи в
// базе (сессия устарела и была вычищена, либо база пересоздана) не
// восстанавливается: заводим новую, ничего не гадая о судьбе старой.
func (s *Service) ensureSession(ctx context.Context, w http.ResponseWriter, r *http.Request) (string, error) {
	if id, ok := sessionFromCookie(r); ok && s.sessionExists(ctx, id) {
		return id, nil
	}

	id, err := newSessionID()
	if err != nil {
		return "", err
	}
	if err := s.createSession(ctx, id); err != nil {
		return "", err
	}
	setSessionCookie(w, id)
	return id, nil
}

func (s *Service) sessionExists(ctx context.Context, id string) bool {
	var n int
	err := s.db.RO().QueryRowContext(ctx, "SELECT 1 FROM chat_sessions WHERE session_id = ?", id).Scan(&n)
	return err == nil
}

func (s *Service) createSession(ctx context.Context, id string) error {
	now := nowUnix()
	_, err := s.db.RW().ExecContext(ctx,
		"INSERT INTO chat_sessions (session_id, created_at, last_at) VALUES (?,?,?)", id, now, now)
	return err
}

func (s *Service) touchSession(ctx context.Context, id string) {
	if _, err := s.db.RW().ExecContext(ctx,
		"UPDATE chat_sessions SET last_at = ? WHERE session_id = ?", nowUnix(), id); err != nil {
		s.log.Error("чат: не обновить время последней активности сессии", "err", err)
	}
}
