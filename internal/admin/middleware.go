package admin

import (
	"context"
	"crypto/subtle"
	"net/http"

	"github.com/qwe8nxtroud/multigate/internal/store"
)

// ensureSession возвращает сессию запроса, заводя анонимную, если cookie
// нет или она невалидна. Анонимная сессия нужна уже на страницах логина
// и мастера настройки: без неё CSRF-токен негде хранить до входа.
//
// Вызывать эту функцию стоит только там, где сессия действительно будет
// использована (рендер формы с CSRF, обработка её отправки). Для путей,
// которые могут закончиться редиректом без показа формы, используйте
// currentSession: иначе поток анонимных запросов (например, кто-то дёргает
// защищённую страницу без входа) заводит по новой сессии на каждый запрос
// впустую, именно так админку и укладывали неограниченным ростом памяти.
func (h *Handler) ensureSession(w http.ResponseWriter, r *http.Request) *session {
	if s := h.currentSession(r); s != nil {
		return s
	}
	s := h.sessions.create()
	setSessionCookie(w, r, h.base, s.id, s.expiresAt)
	return s
}

// currentSession читает сессию из cookie запроса, ничего не создавая: если
// cookie нет или она невалидна/просрочена, возвращает nil. session.authenticated()
// и checkCSRF безопасны на nil-получателе, так что вызывающему коду не нужно
// отдельно проверять nil перед этими вызовами.
func (h *Handler) currentSession(r *http.Request) *session {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	s, ok := h.sessions.get(c.Value)
	if !ok {
		return nil
	}
	return s
}

// checkCSRF сверяет токен формы с токеном сессии постоянным по времени
// сравнением: обычное сравнение строк допускает временную атаку по префиксу.
func checkCSRF(r *http.Request, s *session) bool {
	if s == nil {
		return false
	}
	token := r.PostFormValue("csrf")
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.csrf)) == 1
}

// installed сообщает, пройден ли мастер первичной настройки. Проверяем не
// только явный флаг store.KeyInstalled: если в базе уже есть хеш пароля
// администратора, настройка фактически состоялась, даже если флаг почему-то
// не выставлен (например, его сбросили вручную в базе, или бутстрап из
// окружения отработал частично). Без этой второй проверки сброс одного
// флага заново открывает мастер первичной настройки на уже
// сконфигурированном инстансе, и тот, кто откроет его первым, назначит себя
// администратором поверх существующего.
func (h *Handler) installed(ctx context.Context) bool {
	if h.store.Get(ctx, store.KeyInstalled) == "1" {
		return true
	}
	return h.store.Get(ctx, store.KeyAdminHash) != ""
}

// requireInstalled редиректит на мастер настройки, если он ещё не пройден.
// Оборачивает обработчики, которым для работы нужна готовая конфигурация.
//
// Сессию заранее не заводит: если мастер ещё не пройден, next не вызывается
// вовсе, и заведённая для него сессия была бы потрачена впустую на каждый
// такой запрос. next получает то, что реально лежит в cookie сейчас (может
// быть nil), этого достаточно для requireAuth ниже, а для обработчиков,
// которым сессия нужна безусловно, её явно заводит сам обработчик (см. handleLoginForm).
func (h *Handler) requireInstalled(next func(w http.ResponseWriter, r *http.Request, s *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.installed(r.Context()) {
			http.Redirect(w, r, h.path("/setup"), http.StatusSeeOther)
			return
		}
		next(w, r, h.currentSession(r))
	}
}

// requireAuth дополнительно к requireInstalled требует вошедшего
// администратора. Анонимную сессию не заводит: неаутентифицированный запрос
// в любом случае уходит на /login, не начав работать со страницей, а значит
// сессия ему не нужна вообще. Без этого разделения поток анонимных запросов
// к любой защищённой странице (например, кто-то долбит /overview без входа)
// плодил бы по новой сессии на каждый запрос.
func (h *Handler) requireAuth(next func(w http.ResponseWriter, r *http.Request, s *session)) http.HandlerFunc {
	return h.requireInstalled(func(w http.ResponseWriter, r *http.Request, s *session) {
		if !s.authenticated() {
			http.Redirect(w, r, h.path("/login"), http.StatusSeeOther)
			return
		}
		next(w, r, s)
	})
}

// withCSRF разбирает форму и проверяет CSRF-токен до вызова next.
// Общая часть для форм, требующих входа, и для форм логина/мастера
// настройки, которые работают ещё без аутентифицированной сессии.
func (h *Handler) withCSRF(next func(w http.ResponseWriter, r *http.Request, s *session)) func(w http.ResponseWriter, r *http.Request, s *session) {
	return func(w http.ResponseWriter, r *http.Request, s *session) {
		if err := r.ParseForm(); err != nil {
			h.renderError(w, r, s, http.StatusBadRequest, "Не удалось разобрать форму")
			return
		}
		if !checkCSRF(r, s) {
			h.renderError(w, r, s, http.StatusForbidden, "Форма устарела или подделана, обновите страницу и попробуйте снова")
			return
		}
		next(w, r, s)
	}
}

// requirePOSTAuth: то же самое, что requireAuth, но дополнительно
// проверяет CSRF-токен формы: используется для всех обработчиков POST,
// которым нужен вошедший администратор.
func (h *Handler) requirePOSTAuth(next func(w http.ResponseWriter, r *http.Request, s *session)) http.HandlerFunc {
	return h.requireAuth(h.withCSRF(next))
}

// requirePOSTGuest: то же самое, но для форм логина и мастера настройки,
// у которых ещё нет вошедшего администратора: сессия при этом обязательно
// анонимная, но CSRF-токен в ней уже есть, форма получила его при показе
// через GET (см. handleLoginForm/handleSetupForm), которые как раз и
// заводят анонимную сессию явно. Здесь сессию не заводим, а только читаем:
// если cookie нет или она невалидна, CSRF гарантированно не совпадёт (сверять
// не с чем), и withCSRF откажет запросу без лишней сессии, заведённой
// специально под этот отказ. Иначе голый POST-спам без cookie точно так же
// плодил бы сессии, как и запросы GET, для которых это уже починили выше.
func (h *Handler) requirePOSTGuest(next func(w http.ResponseWriter, r *http.Request, s *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := h.currentSession(r)
		h.withCSRF(next)(w, r, s)
	}
}
