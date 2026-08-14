package admin

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/qwe8nxtroud/multigate/internal/store"
)

// loginPageData: данные страницы входа.
type loginPageData struct {
	pageBase
	Error string
	Next  string
}

// handleLoginForm показывает форму входа. Если мастер настройки ещё не
// пройден или администратор уже вошёл, отправляет дальше по маршруту.
//
// Порядок проверок специально такой: сначала оба редиректа без создания
// сессии (оба читают уже существующую через currentSession, которая может
// вернуть nil, это ок: authenticated() безопасен на nil), и только если
// дело реально дошло до показа формы, заводим анонимную сессию под её
// CSRF-токен. Иначе поток запросов на /login от кого-то, кто уже вошёл
// (или ещё не прошёл мастер), плодил бы по сессии на каждый заход.
func (h *Handler) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if !h.installed(r.Context()) {
		http.Redirect(w, r, h.path("/setup"), http.StatusSeeOther)
		return
	}
	if h.currentSession(r).authenticated() {
		http.Redirect(w, r, h.path("/overview"), http.StatusSeeOther)
		return
	}
	s := h.ensureSession(w, r)
	h.render(w, http.StatusOK, "login.html", loginPageData{
		pageBase: h.newPageBase(r, s, "Вход", ""),
		Next:     safeNext(r.URL.Query().Get("next"), h.base),
	})
}

// handleLoginSubmit проверяет пароль и заводит аутентифицированную сессию.
func (h *Handler) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	h.requirePOSTGuest(h.doLogin)(w, r)
}

func (h *Handler) doLogin(w http.ResponseWriter, r *http.Request, s *session) {
	if !h.installed(r.Context()) {
		http.Redirect(w, r, h.path("/setup"), http.StatusSeeOther)
		return
	}

	ip := clientIP(r, h.trustProxy)
	// Отдельная от bcrypt задержка: даже при неверном логине (когда bcrypt
	// вообще не вызывается, см. ниже) ответ приходит не мгновенно, поэтому
	// по времени ответа нельзя отличить «нет такого логина» от «неверный пароль».
	defer func() { time.Sleep(loginDelay) }()

	if !h.limiter.allowed(ip) {
		h.render(w, http.StatusTooManyRequests, "login.html", loginPageData{
			pageBase: h.newPageBase(r, s, "Вход", ""),
			Error:    "Слишком много попыток входа, попробуйте позже",
			Next:     safeNext(r.PostFormValue("next"), h.base),
		})
		return
	}

	user := strings.TrimSpace(r.PostFormValue("username"))
	pass := r.PostFormValue("password")
	next := safeNext(r.PostFormValue("next"), h.base)

	wantUser := h.store.Get(r.Context(), store.KeyAdminUser)
	hash := h.store.Get(r.Context(), store.KeyAdminHash)

	// Сравнение логина тоже постоянным по времени: он менее чувствителен,
	// чем пароль, но не стоит давать даже намёк через ветвление раньше bcrypt.
	validUser := user != "" && subtle.ConstantTimeCompare([]byte(user), []byte(wantUser)) == 1

	ok := false
	if validUser && hash != "" {
		ok = bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil
	}

	if !ok {
		h.limiter.registerFail(ip)
		h.log.Warn("admin: неудачная попытка входа", "ip", ip)
		h.render(w, http.StatusUnauthorized, "login.html", loginPageData{
			pageBase: h.newPageBase(r, s, "Вход", ""),
			Error:    "Неверный логин или пароль",
			Next:     next,
		})
		return
	}

	h.limiter.registerSuccess(ip)

	// Новая сессия на успешный вход вместо переиспользования анонимной:
	// это защита от session fixation, если кто-то заранее подсунул жертве
	// свою cookie.
	h.sessions.destroy(s.id)
	ns := h.sessions.create()
	ns.user = user
	setSessionCookie(w, r, h.base, ns.id, ns.expiresAt)
	h.sessions.setFlash(ns.id, "ok", "Добро пожаловать")

	h.log.Info("admin: вход выполнен", "user", user, "ip", ip)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// handleLogout завершает сессию. Сессию только читаем (currentSession), не
// заводим: без валидной cookie CSRF заведомо не пройдёт, и голый POST без
// cookie не должен порождать сессию специально ради собственного отказа.
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	s := h.currentSession(r)
	h.withCSRF(func(w http.ResponseWriter, r *http.Request, s *session) {
		h.sessions.destroy(s.id)
		clearSessionCookie(w, r, h.base)
		http.Redirect(w, r, h.path("/login"), http.StatusSeeOther)
	})(w, r, s)
}

// safeNext допускает редирект только внутрь самой админки: значение next
// приходит от клиента, и без проверки префикса это открытый редирект.
func safeNext(next, base string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return fallbackNext(base)
	}
	if base != "" && !strings.HasPrefix(next, base) {
		return fallbackNext(base)
	}
	return next
}

func fallbackNext(base string) string {
	if base == "" {
		return "/overview"
	}
	return base + "/overview"
}
