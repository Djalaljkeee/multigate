package chat

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/qwe8nxtroud/multigate/internal/store"
	"github.com/qwe8nxtroud/multigate/internal/version"
)

// errChatNotConfigured сигнализирует, что токен или чат оператора ещё не
// заданы в админке. Не ошибка сама по себе: сообщение остаётся в истории
// виджета, просто в Telegram его пока некому доставлять.
var errChatNotConfigured = errors.New("chat: telegram не настроен")

// deliverToTelegram обрабатывает один элемент очереди отправки.
func (s *Service) deliverToTelegram(ev tgOutbound) {
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()

	tgMsgID, err := s.sendToTelegram(ctx, ev.sessionID, ev.text)
	if err != nil {
		if !errors.Is(err, errChatNotConfigured) {
			s.log.Warn("чат: не доставить сообщение в telegram", "err", err)
		}
		return
	}
	s.markDelivered(context.Background(), ev.msgRowID, tgMsgID)
}

// sendToTelegram шлёт текст в чат поддержки и возвращает id сообщения в
// Telegram: он нужен, чтобы позже связать reply оператора с сессией
// через reply_to_message.
func (s *Service) sendToTelegram(ctx context.Context, sessionID, text string) (int64, error) {
	token := strings.TrimSpace(s.db.Get(ctx, store.KeyChatTGToken))
	chatID := strings.TrimSpace(s.db.Get(ctx, store.KeyChatTGChat))
	if token == "" || chatID == "" {
		return 0, errChatNotConfigured
	}

	form := url.Values{}
	form.Set("chat_id", chatID)
	// parse_mode сознательно не выставляем: без него Bot API показывает
	// текст как есть, и экранировать под Markdown/HTML не нужно вообще.
	// Это надёжнее, чем аккуратно исполнять правила экранирования каждого режима.
	form.Set("text", formatForOperator(sessionID, text))

	endpoint := s.tgAPIBase(ctx) + "/bot" + token + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, redactToken(err, token)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", version.UserAgent())

	resp, err := s.client.Do(req)
	if err != nil {
		// *url.Error от net/http включает адрес запроса целиком, а токен это
		// часть пути запроса. Вычищаем до того, как ошибка попадёт в лог
		// или наружу вызывающему коду.
		return 0, redactToken(err, token)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return 0, fmt.Errorf("chat: чтение ответа telegram: %w", err)
	}

	var out struct {
		OK     bool `json:"ok"`
		Result struct {
			MessageID int64 `json:"message_id"`
		} `json:"result"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, fmt.Errorf("chat: telegram вернул неразборчивый ответ, статус %d", resp.StatusCode)
	}
	if !out.OK {
		return 0, fmt.Errorf("chat: telegram отклонил сообщение: %s", truncate(out.Description, 200))
	}
	return out.Result.MessageID, nil
}

// tgAPIBase возвращает адрес Bot API. Настраиваемый, потому что на части
// серверов api.telegram.org недоступен напрямую, и владелец должен иметь
// возможность указать своё зеркало.
func (s *Service) tgAPIBase(ctx context.Context) string {
	base := strings.TrimSpace(s.db.Get(ctx, store.KeyChatTGAPIBase))
	if base == "" {
		base = "https://api.telegram.org"
	}
	return strings.TrimRight(base, "/")
}

// formatForOperator подписывает сообщение коротким хвостом id сессии,
// чтобы оператор в общем чате видел, из какого диалога прилетело
// сообщение. Сама связь сессии с ответом идёт не по этому тексту,
// а по tg_msg_id/reply_to_message: на подпись это никак не влияет.
func formatForOperator(sessionID, text string) string {
	tag := sessionID
	if len(tag) > 8 {
		tag = tag[:8]
	}
	return fmt.Sprintf("Посетитель [%s]:\n%s", tag, text)
}

// redactToken прячет токен бота внутри текста ошибки. Токен никогда не
// должен попасть ни в лог, ни наружу, а net/http вкладывает в *url.Error
// полный адрес неудавшегося запроса, частью которого токен и является.
func redactToken(err error, token string) error {
	if err == nil || token == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token, "***"))
}

// --- приём ответов оператора ---

// maxTGUpdateBytes задаёт предел тела апдейта Telegram. Апдейты с текстовым
// сообщением укладываются в единицы килобайт с большим запасом.
const maxTGUpdateBytes = 256 << 10

// tgSecretTokenHeader - заголовок, которым Telegram передаёт secret_token,
// заданный при setWebhook (https://core.telegram.org/bots/api#setwebhook).
// Заголовок с телом апдейта никак не связан, поэтому его отсутствие или
// несовпадение проверяется отдельно от разбора JSON.
const tgSecretTokenHeader = "X-Telegram-Bot-Api-Secret-Token"

// KeyChatTGWebhookSecret: ключ настройки с секретом вебхука Telegram
// (значением secret_token, которое администратор передаёт в setWebhook).
//
// Теперь это псевдоним для ключа из internal/store: сам ключ переехал туда,
// к остальным настройкам, чтобы админка могла завести под него поле формы.
// Псевдоним оставлен, чтобы не переписывать обращения внутри пакета.
const KeyChatTGWebhookSecret = store.KeyChatTGWebhookSecret

type tgUpdate struct {
	Message *tgMessage `json:"message"`
}

type tgMessage struct {
	MessageID      int64      `json:"message_id"`
	Text           string     `json:"text"`
	Chat           tgChat     `json:"chat"`
	ReplyToMessage *tgMessage `json:"reply_to_message"`
}

type tgChat struct {
	ID int64 `json:"id"`
}

// WebhookHandler принимает апдейты от Telegram. Интересует только ответ
// оператора (reply) на сообщение, отправленное сюда же ранее.
func (s *Service) WebhookHandler() http.Handler {
	return http.HandlerFunc(s.handleTelegramWebhook)
}

func (s *Service) handleTelegramWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Лимит частоты - первым делом и максимально дёшево: находка ревью 3,
	// эндпоинт открыт интернету, и подбор reply_to_message.message_id или
	// простой флуд не должны упираться в разбор тела раньше, чем в счётчик.
	if !s.tgWebhookLimiter.Allow(clientIP(r)) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "слишком много запросов", http.StatusTooManyRequests)
		return
	}

	ctx := r.Context()
	if !s.db.GetBool(ctx, store.KeyChatEnabled) {
		// Находка ревью 4: чат выключен администратором, ответы оператора не
		// должны попадать в базу и "оживать" в истории, если чат потом снова
		// включат. Тело даже не читаем: Telegram всё равно получает 200,
		// чтобы не повторять доставку, а разбирать нечего.
		w.WriteHeader(http.StatusOK)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxTGUpdateBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "тело запроса слишком большое", http.StatusRequestEntityTooLarge)
		return
	}

	// Находка ревью 3: раньше единственной проверкой подлинности апдейта
	// было совпадение chat.id с настройкой, а id чата не секрет (виден на
	// скриншотах, подбирается для публичных групп). Telegram поддерживает
	// secret_token в setWebhook и присылает его в заголовке при каждом
	// апдейте - сверяем константным сравнением, чтобы не подсказывать
	// значение по времени ответа. Если секрет ещё не настроен в админке,
	// откатываемся на прежнюю (более слабую) проверку по chat.id ниже:
	// иначе этот код молча оборвал бы уже работающие интеграции, где
	// secret_token в setWebhook ещё не прописан.
	secret := strings.TrimSpace(s.db.Get(ctx, KeyChatTGWebhookSecret))
	if secret != "" {
		got := r.Header.Get(tgSecretTokenHeader)
		if subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	} else {
		s.log.Warn("чат: secret_token вебхука telegram не настроен, апдейты защищены только сверкой chat_id")
	}

	// Telegram не ждёт содержательного ответа, только 200: иначе будет
	// повторно доставлять апдейт. Отвечаем сразу, чтобы чужой мусор в теле
	// не превращался в проблему для вебхука.
	w.WriteHeader(http.StatusOK)

	var upd tgUpdate
	if err := json.Unmarshal(raw, &upd); err != nil {
		return
	}
	msg := upd.Message
	if msg == nil || msg.ReplyToMessage == nil {
		return // не ответ на сообщение, обрабатывать нечего
	}

	// Единственная (до secret_token выше) проверка подлинности апдейта:
	// Telegram сам тело не подписывает, поэтому сверяем chat_id с тем, что
	// настроено как чат поддержки. Апдейт из любого другого чата (в том
	// числе если бота добавили в постороннюю группу) молча игнорируется.
	chatID := strings.TrimSpace(s.db.Get(ctx, store.KeyChatTGChat))
	if chatID == "" || strconv.FormatInt(msg.Chat.ID, 10) != chatID {
		return
	}

	sessionID, ok := s.sessionByTGMsgID(ctx, msg.ReplyToMessage.MessageID)
	if !ok {
		return
	}

	text := sanitizeMessage(msg.Text)
	if text == "" {
		return
	}
	if _, _, err := s.storeMessage(ctx, sessionID, false, text, msg.MessageID, true); err != nil {
		s.log.Error("чат: не сохранить ответ оператора", "err", err)
		return
	}
	s.touchSession(ctx, sessionID)
}

// sessionByTGMsgID находит сессию по id сообщения посетителя в Telegram:
// именно на него оператор отвечает через reply.
func (s *Service) sessionByTGMsgID(ctx context.Context, tgMsgID int64) (string, bool) {
	var sessionID string
	err := s.db.RO().QueryRowContext(ctx,
		"SELECT session_id FROM chat_messages WHERE tg_msg_id = ? AND from_user = 1 ORDER BY id DESC LIMIT 1",
		tgMsgID).Scan(&sessionID)
	if err != nil {
		return "", false
	}
	return sessionID, true
}
