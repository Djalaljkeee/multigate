// Package chat реализует виджет поддержки на странице подписки с пересылкой
// обращений в Telegram и доставкой ответа оператора обратно посетителю.
//
// Виджет открыт всему интернету (в отличие от админки), поэтому у пакета
// на входе всегда: ограничение размера тела, ограничение частоты запросов
// и проверка, что читающий историю действительно владеет своей сессией.
package chat

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/store"
)

const (
	// sendTimeout: таймаут одного обращения к Bot API (в том числе к
	// зеркалу api.telegram.org, если основной адрес заблокирован).
	sendTimeout = 10 * time.Second

	// outboundQueueSize: сколько сообщений посетителей могут ждать отправки
	// в Telegram одновременно. Само сообщение при этом уже сохранено в базе
	// и видно в истории виджета независимо от того, доставлено ли оно в чат.
	outboundQueueSize = 128
	// outboundWorkers: параллельных отправителей в Telegram.
	outboundWorkers = 2

	// Ограничение частоты: виджет это открытая всему интернету форма,
	// очевидная мишень для спама и для переполнения чата поддержки.
	rateLimitWindow     = time.Minute
	rateLimitPerIP      = 12 // сообщений в минуту с одного IP
	rateLimitPerSession = 20 // сообщений в минуту у одной сессии

	// tgWebhookRateLimitPerIP: находка ревью 3 - вебхук Telegram (ответы
	// оператора) открыт интернету так же, как и сам виджет, и подбор
	// reply_to_message.message_id не должен упираться в разбор JSON и базу
	// раньше, чем в этот счётчик. Отдельный от лимитов виджета, чтобы всплеск
	// на одном не резал другой.
	tgWebhookRateLimitPerIP = 30 // апдейтов в минуту с одного IP
)

// Service реализует виджет поддержки: приём сообщений от посетителей и обмен
// с Telegram, где сидит оператор.
type Service struct {
	db     *store.DB
	log    *slog.Logger
	client *http.Client

	ipLimiter        *limiter
	sessionLimiter   *limiter
	tgWebhookLimiter *limiter

	queue     chan tgOutbound
	closed    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// tgOutbound описывает сообщение посетителя, ожидающее отправки в Telegram.
// Само сообщение уже лежит в chat_messages, здесь только то, что нужно
// довезти до Bot API и потом связать со строкой в базе.
type tgOutbound struct {
	msgRowID  int64
	sessionID string
	text      string
}

// New создаёт сервис и запускает воркеров доставки в Telegram.
func New(db *store.DB, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	s := &Service{
		db:               db,
		log:              log,
		client:           &http.Client{Timeout: sendTimeout},
		ipLimiter:        newLimiter(rateLimitPerIP, rateLimitWindow),
		sessionLimiter:   newLimiter(rateLimitPerSession, rateLimitWindow),
		tgWebhookLimiter: newLimiter(tgWebhookRateLimitPerIP, rateLimitWindow),
		queue:            make(chan tgOutbound, outboundQueueSize),
		closed:           make(chan struct{}),
	}
	for i := 0; i < outboundWorkers; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	return s
}

// Close останавливает приём новых сообщений в очередь и дожидается,
// пока начатая отправка в Telegram (если она уже шла) закончится.
func (s *Service) Close() {
	s.closeOnce.Do(func() { close(s.closed) })
	s.wg.Wait()
	s.client.CloseIdleConnections()
	s.ipLimiter.Close()
	s.sessionLimiter.Close()
	s.tgWebhookLimiter.Close()
}

// worker разбирает очередь отправки до сигнала остановки. Сообщение,
// уже взятое в работу, доводится до конца: Close прерывает только
// ожидание следующего элемента очереди.
func (s *Service) worker() {
	defer s.wg.Done()
	for {
		select {
		case ev, ok := <-s.queue:
			if !ok {
				return
			}
			s.deliverToTelegram(ev)
		case <-s.closed:
			return
		}
	}
}

// enqueueOutbound пытается поставить сообщение в очередь на отправку,
// не блокируясь. false означает переполнение: сообщение остаётся видно
// в истории виджета, но в Telegram в этот раз не уйдёт.
func (s *Service) enqueueOutbound(ev tgOutbound) bool {
	select {
	case s.queue <- ev:
		return true
	default:
		return false
	}
}
