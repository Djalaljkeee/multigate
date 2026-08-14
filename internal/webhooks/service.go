// Package webhooks принимает события панели Remnawave по HTTP и ретранслирует
// их подписчикам (например внутренним системам учёта).
//
// Приём и рассылка разнесены: панель получает ответ сразу, не дожидаясь,
// пока прослойка достучится до всех получателей, часть из которых может
// быть медленной или вовсе недоступной.
package webhooks

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/store"
)

const (
	// maxBodyBytes: предел тела входящего вебхука. Эндпоинт открыт панели
	// (а иногда и интернету при неверной настройке firewall), поэтому вход
	// не должен становиться дешёвым вектором нагрузки на базу.
	maxBodyBytes = 1 << 20 // 1 МБ

	// queueSize: сколько событий может ждать рассылки одновременно.
	// При переполнении событие всё равно принимается и логируется,
	// но рассылка по нему не выполняется, и это фиксируется в журнале.
	queueSize = 256

	// workerCount: сколько горутин параллельно разбирают очередь рассылки.
	// Одного воркера достаточно по нагрузке, но при медленном получателе
	// он придерживал бы вообще все следующие события.
	workerCount = 4

	// maxAttempts: сколько раз пробуем достучаться до одного получателя.
	// Бесконечные повторы недопустимы: сломанный получатель не должен
	// копить в базе неограниченный forward_log.
	maxAttempts = 3

	// sendTimeout: таймаут одного HTTP-запроса к получателю.
	sendTimeout = 10 * time.Second

	// dispatchTimeout: таймаут на рассылку одного события всем получателям
	// вместе с их повторами.
	dispatchTimeout = 45 * time.Second

	// Находка ревью 2: приём вебхуков открыт панели, а иногда и всему
	// интернету при неверной настройке firewall. Без предела частоты шторм
	// POST-запросов с телами до maxBodyBytes уходит прямо в базу впереди
	// любой другой защиты.
	rateLimitWindow = time.Minute
	rateLimitPerIP  = 120 // запросов в минуту с одного IP
)

// Service принимает вебхуки панели и ретранслирует их подписчикам.
type Service struct {
	db     *store.DB
	log    *slog.Logger
	client *http.Client

	ipLimiter *limiter

	queue     chan queuedEvent
	closed    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// queuedEvent описывает событие, поставленное в очередь на асинхронную рассылку.
type queuedEvent struct {
	logID   int64
	event   string
	payload []byte
}

// New создаёт сервис и запускает воркеров рассылки.
func New(db *store.DB, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	s := &Service{
		db:        db,
		log:       log,
		client:    &http.Client{Timeout: sendTimeout},
		ipLimiter: newLimiter(rateLimitPerIP, rateLimitWindow),
		queue:     make(chan queuedEvent, queueSize),
		closed:    make(chan struct{}),
	}
	for i := 0; i < workerCount; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	return s
}

// Close останавливает приём новых событий воркерами и дожидается,
// пока начатая рассылка (если она уже шла) закончится.
// Накопленное в очереди, но ещё не взятое в работу, при остановке теряется:
// это осознанный выбор, потому что ждать всю очередь на выключении сервиса нельзя.
func (s *Service) Close() {
	s.closeOnce.Do(func() { close(s.closed) })
	s.wg.Wait()
	s.client.CloseIdleConnections()
	s.ipLimiter.Close()
}

// worker разбирает очередь до сигнала остановки. Событие, попавшее в работу
// (s.dispatch), доводится до конца даже после Close: сигнал закрытия
// прерывает только ожидание СЛЕДУЮЩЕГО события, а не текущую рассылку.
func (s *Service) worker() {
	defer s.wg.Done()
	for {
		select {
		case ev, ok := <-s.queue:
			if !ok {
				return
			}
			s.dispatch(ev)
		case <-s.closed:
			return
		}
	}
}

// enqueue пытается поставить событие в очередь, не блокируясь.
// false означает, что очередь переполнена и рассылки по событию не будет.
func (s *Service) enqueue(ev queuedEvent) bool {
	select {
	case s.queue <- ev:
		return true
	default:
		return false
	}
}
