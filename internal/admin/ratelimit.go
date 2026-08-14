package admin

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Параметры защиты от подбора пароля. Окно сбрасывает счётчик неудач,
// если давно не было ни одной попытки; после порога IP блокируется
// на растущее время: каждая новая неудача после блокировки продлевает её.
const (
	loginFailWindow = 15 * time.Minute
	loginMaxFails   = 5
	loginBlockBase  = 30 * time.Second
	loginBlockMax   = 15 * time.Minute
	loginDelay      = 400 * time.Millisecond

	// Общий потолок неудачных попыток по ВСЕЙ админке сразу, а не по
	// конкретному IP: без него распределённый перебор (запрос с каждого
	// нового адреса ботнета, у каждого всего пара попыток) обходит
	// поштучный лимит выше, ведь ни один отдельный IP до loginMaxFails не
	// доходит, хотя суммарная скорость подбора пароля та же. Порог заметно
	// выше поштучного, чтобы обычный фон случайных ошибок разных
	// администраторов не заблокировал всех разом.
	loginGlobalFailWindow = 15 * time.Minute
	loginGlobalMaxFails   = 30
	loginGlobalBlockBase  = 30 * time.Second
	loginGlobalBlockMax   = 15 * time.Minute
)

// loginLimiter: ограничение попыток входа в памяти процесса. Две линии
// защиты сразу: персональная, по IP (byIP), и общая, на всю админку
// (global). Распределённый перебор упирается во вторую, даже если каждый
// отдельный адрес ни разу не превысил личный лимит.
type loginLimiter struct {
	mu     sync.Mutex
	byIP   map[string]*loginAttempts
	global loginAttempts
}

type loginAttempts struct {
	fails      int
	lastFail   time.Time
	blockedTil time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{byIP: make(map[string]*loginAttempts)}
}

// allowed сообщает, можно ли сейчас пробовать пароль для этого IP: смотрим
// и общую блокировку всей админки, и персональную блокировку конкретного IP.
func (l *loginLimiter) allowed(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Before(l.global.blockedTil) {
		return false
	}
	a, ok := l.byIP[ip]
	if !ok {
		return true
	}
	return now.After(a.blockedTil)
}

// registerFail отмечает неудачную попытку и по IP, и в общем счётчике;
// при превышении соответствующего порога включает блокировку.
func (l *loginLimiter) registerFail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()

	a, ok := l.byIP[ip]
	if !ok || now.Sub(a.lastFail) > loginFailWindow {
		a = &loginAttempts{}
		l.byIP[ip] = a
	}
	bumpAttempts(a, now, loginMaxFails, loginBlockBase, loginBlockMax)

	if now.Sub(l.global.lastFail) > loginGlobalFailWindow {
		l.global = loginAttempts{}
	}
	bumpAttempts(&l.global, now, loginGlobalMaxFails, loginGlobalBlockBase, loginGlobalBlockMax)
}

// bumpAttempts: общая логика эскалации для персонального и общего
// счётчика, отличаются только пороги и длительности блокировки.
func bumpAttempts(a *loginAttempts, now time.Time, maxFails int, blockBase, blockCap time.Duration) {
	a.fails++
	a.lastFail = now
	if a.fails >= maxFails {
		// Эскалация: каждая попытка сверх порога удваивает блокировку до потолка.
		mult := a.fails - maxFails + 1
		wait := blockBase * time.Duration(1<<min(mult, 8))
		if wait > blockCap {
			wait = blockCap
		}
		a.blockedTil = now.Add(wait)
	}
}

// registerSuccess сбрасывает счётчик неудач по IP и общий счётчик:
// администратор ввёл верный пароль, значит атака (если она была) на этом
// исходе закончилась, и держать блокировку дальше смысла нет.
func (l *loginLimiter) registerSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.byIP, ip)
	l.global = loginAttempts{}
}

// clientIP вытаскивает адрес клиента для антибрутфорса входа и журнала.
// Поведение зависит от trustProxy (см. Deps.TrustProxy):
//
//   - не доверяем (значение по умолчанию): используем ТОЛЬКО r.RemoteAddr.
//     Заголовки X-Forwarded-For/X-Real-IP в этом случае не смотрим вовсе:
//     их выставляет сам клиент в прямом запросе к прослойке, и если им
//     верить безусловно, лимит по IP обходится тривиально, ведь меняя
//     заголовок на каждый запрос, атакующий каждый раз выглядит для
//     лимитера новым адресом, хотя физически это один и тот же клиент.
//   - доверяем: единственный источник, который клиент не может подделать,
//     это то, что дописал сам доверенный прокси. Прокси всегда ДОПИСЫВАЕТ
//     адрес клиента в конец цепочки X-Forwarded-For, поэтому берём
//     ПОСЛЕДНИЙ элемент, а не первый: первый элемент заполняет сам клиент
//     и может вписать туда что угодно (тот же приём, что для журнала
//     подписки в internal/proxy/headers.go, только с точностью до порядка
//     чтения элемента: здесь он специально другой конец списка).
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
		if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
			return xr
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
