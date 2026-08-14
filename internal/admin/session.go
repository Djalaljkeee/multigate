package admin

import (
	"container/list"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"
)

// cookieName: имя cookie сессии админки.
const cookieName = "mg_admin_sid"

// sessionTTL: на сколько продлевается сессия при каждом обращении.
// Значение небольшое: админку открывают редко, а долгоживущая сессия несёт
// лишний риск при краже cookie.
const sessionTTL = 8 * time.Hour

// maxSessions: потолок одновременно хранимых сессий (включая анонимные,
// заведённые под формы входа и мастера настройки). Даже неограниченный
// поток запросов на страницу логина не даст карте сессий расти
// бесконечно: после потолка каждая новая сессия вытесняет самую старую.
// Значение с большим запасом над реальным использованием (пара
// администраторов, десятки вкладок), но конечное: без потолка карта
// растёт линейно с числом запросов, а это и есть дешёвый для атакующего
// отказ в обслуживании по памяти.
const maxSessions = 10000

// sessionCleanupInterval: как часто фоновая горутина проходит по всем
// сессиям и убирает просроченные. TTL сессии измеряется часами, поэтому раз в
// несколько минут более чем достаточно; сам обход тут не на пути ни одного
// HTTP-запроса, так что его линейная стоимость не создаёт проблем.
const sessionCleanupInterval = 5 * time.Minute

// flashMsg: одноразовое сообщение, показывается один раз после редиректа.
type flashMsg struct {
	Kind string // "ok" | "err"
	Text string
}

// session: состояние одной сессии администратора.
//
// user пуст у анонимной сессии: такая заводится уже на странице логина
// и мастера первичной настройки, чтобы у формы был CSRF-токен ещё до входа.
// После успешного логина сессия заменяется на новую (см. login.go):
// это защита от session fixation.
type session struct {
	id        string
	user      string
	csrf      string
	expiresAt time.Time
	flash     *flashMsg
}

func (s *session) authenticated() bool { return s != nil && s.user != "" }

// sessionStore: сессии в памяти процесса.
//
// Порядок создания хранится в ord (голова списка это самая старая сессия):
// это даёт O(1) вставку, O(1) удаление по id (map хранит *list.Element) и
// O(1) вытеснение самой старой сессии при достижении потолка, без линейного
// обхода всей карты на каждой вставке, который раньше делал create() и
// который под нагрузкой давал квадратичную стоимость на поток запросов.
// Просроченные сессии чистит отдельная горутина по таймеру (см. cleanupLoop),
// а не сама вставка.
type sessionStore struct {
	mu   sync.Mutex
	data map[string]*list.Element // id -> элемент ord, Value = *session
	ord  *list.List               // порядок по времени создания, Front = самая старая

	stop     chan struct{}
	stopOnce sync.Once
}

func newSessionStore() *sessionStore {
	ss := &sessionStore{
		data: make(map[string]*list.Element),
		ord:  list.New(),
		stop: make(chan struct{}),
	}
	go ss.cleanupLoop()
	return ss
}

// cleanupLoop периодически убирает просроченные сессии. Останавливается
// корректно по закрытию ss.stop (см. Stop), а не живёт вечно вне контроля:
// в тестах, создающих множество sessionStore, иначе копились бы висящие
// горутины на весь прогон пакета.
func (ss *sessionStore) cleanupLoop() {
	t := time.NewTicker(sessionCleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-ss.stop:
			return
		case <-t.C:
			ss.pruneExpired()
		}
	}
}

// Stop останавливает фоновую уборку. Безопасно вызывать более одного раза.
func (ss *sessionStore) Stop() {
	ss.stopOnce.Do(func() { close(ss.stop) })
}

// pruneExpired удаляет все просроченные на текущий момент сессии.
// Единственное место, где store проходит по всей карте целиком, и делает
// это по таймеру, а не на пути запроса.
func (ss *sessionStore) pruneExpired() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	now := time.Now()
	for id, el := range ss.data {
		if now.After(el.Value.(*session).expiresAt) {
			ss.ord.Remove(el)
			delete(ss.data, id)
		}
	}
}

// create заводит новую сессию. Если после вставки число сессий превысило
// потолок, вытесняет одну самую старую (см. evictOldestLocked).
func (ss *sessionStore) create() *session {
	s := &session{
		id:        randomToken(32),
		csrf:      randomToken(32),
		expiresAt: time.Now().Add(sessionTTL),
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	el := ss.ord.PushBack(s)
	ss.data[s.id] = el
	if len(ss.data) > maxSessions {
		ss.evictOldestLocked()
	}
	return s
}

// evictOldestLocked вызывается под ss.mu, когда потолок превышен. Ищет
// самую старую сессию БЕЗ вошедшего администратора и вытесняет именно её:
// слепое вытеснение головы списка позволило бы потоку анонимных запросов
// (например, флудом по /login) в какой-то момент вытеснить сессию самого
// администратора, который в это время просто работает в другой вкладке.
// Настоящих вошедших сессий всегда мало (по числу администраторов), так что
// проход в поисках первой анонимной короткий даже в худшем случае.
func (ss *sessionStore) evictOldestLocked() {
	for e := ss.ord.Front(); e != nil; e = e.Next() {
		s := e.Value.(*session)
		if s.user == "" {
			ss.ord.Remove(e)
			delete(ss.data, s.id)
			return
		}
	}
	// Все сессии в хранилище оказались аутентифицированными: реалистично
	// только если администраторов физически больше потолка. Тогда вытесняем
	// самую старую как есть, это лучше, чем расти без предела.
	if e := ss.ord.Front(); e != nil {
		s := e.Value.(*session)
		ss.ord.Remove(e)
		delete(ss.data, s.id)
	}
}

// get возвращает живую сессию и продлевает её срок. Просроченная сессия
// удаляется и трактуется как отсутствующая.
func (ss *sessionStore) get(id string) (*session, bool) {
	if id == "" {
		return nil, false
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	el, ok := ss.data[id]
	if !ok {
		return nil, false
	}
	s := el.Value.(*session)
	if time.Now().After(s.expiresAt) {
		ss.ord.Remove(el)
		delete(ss.data, id)
		return nil, false
	}
	s.expiresAt = time.Now().Add(sessionTTL)
	return s, true
}

func (ss *sessionStore) destroy(id string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if el, ok := ss.data[id]; ok {
		ss.ord.Remove(el)
		delete(ss.data, id)
	}
}

// count возвращает текущее число хранимых сессий. Используется в тестах:
// отдельный метод читается яснее, чем прямое обращение к приватному полю.
func (ss *sessionStore) count() int {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return len(ss.data)
}

// setFlash кладёт одноразовое сообщение в сессию.
func (ss *sessionStore) setFlash(id string, kind, text string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if el, ok := ss.data[id]; ok {
		el.Value.(*session).flash = &flashMsg{Kind: kind, Text: text}
	}
}

// takeFlash отдаёт сообщение и сразу его стирает: повторный рендер той же
// сессии (обновление страницы) больше его не покажет.
func (ss *sessionStore) takeFlash(id string) *flashMsg {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	el, ok := ss.data[id]
	if !ok {
		return nil
	}
	s := el.Value.(*session)
	if s.flash == nil {
		return nil
	}
	f := s.flash
	s.flash = nil
	return f
}

// randomToken генерирует URL-safe случайную строку из n байт энтропии.
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand практически никогда не отказывает на живой ОС; если это
		// всё же случилось, лучше упасть на предсказуемо пустом токене,
		// чем тихо выдать сессию без энтропии.
		panic("admin: не удалось прочитать crypto/rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// isHTTPS сообщает, пришёл ли запрос по HTTPS: напрямую или через прокси,
// который проставляет X-Forwarded-Proto. От этого зависит флаг Secure
// у cookie сессии.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// setSessionCookie выставляет cookie сессии.
func setSessionCookie(w http.ResponseWriter, r *http.Request, base, id string, exp time.Time) {
	path := base
	if path == "" {
		path = "/"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    id,
		Path:     path,
		Expires:  exp,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie стирает cookie сессии на клиенте.
func clearSessionCookie(w http.ResponseWriter, r *http.Request, base string) {
	path := base
	if path == "" {
		path = "/"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}
