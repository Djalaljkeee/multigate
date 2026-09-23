// Package proxy - ядро MultiGate: обработчик HTTP-запроса подписки.
//
// Разбирает клиента, решает, что ему показать (реальную подписку, страницу
// маскировки, заглушку блокировки или заглушку истёкшего срока), достаёт
// подписку из панели или зеркала, приводит заголовки ответа к безопасному
// виду и журналирует запрос. Все внешние зависимости (хранилище, панель,
// разбор User-Agent, страница маскировки) приходят через Deps - сам пакет
// не знает, кто их реализует.
package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/qwe8nxtroud/multigate/internal/hwid"
	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/rules"
	"github.com/qwe8nxtroud/multigate/internal/store"
	"github.com/qwe8nxtroud/multigate/internal/wgpool"
)

// Panel - то, что прослойке нужно от панели Remnawave, в виде, не
// зависящем от версии панели. Реализуется пакетом remnawave.
type Panel interface {
	Subscription(ctx context.Context, shortUUID string, in http.Header) (*model.SubResponse, error)
	UserByShortUUID(ctx context.Context, shortUUID string) (model.PanelUser, error)
	Info(ctx context.Context) (model.PanelInfo, error)
	// Devices и DeleteDevice нужны для лимита устройств: hwid.Enforce
	// принимает Panel напрямую как источник устройств (её набора методов
	// достаточно, чтобы удовлетворить интерфейсу hwid.Devices). Сам proxy
	// DeleteDevice не вызывает - метод здесь только ради этого соответствия.
	Devices(ctx context.Context, userRef string) ([]model.Device, error)
	DeleteDevice(ctx context.Context, userRef, hwid string) error
}

// Grace - выдача временной отсрочки для истёкшей подписки. Реализуется
// пакетом grace (Service.Maybe), но proxy получает его через этот узкий
// интерфейс, а не через прямую зависимость от пакета grace: тот правит
// параллельный агент, а proxy для своей задачи нужен ровно один метод.
type Grace interface {
	// Maybe выдаёт грейс пользователю u, если он положен (включённость
	// настройки, реальный факт истечения и т.д. - целиком на стороне
	// реализации). Сигнатура совпадает с grace.Service.Maybe.
	Maybe(ctx context.Context, u model.PanelUser) (applied bool, err error)
}

// LegacyResolver - см. Deps.Legacy. Реализуется legacy.Resolver.
type LegacyResolver interface {
	Resolve(ctx context.Context, token string) (shortUUID string, ok bool)
}

// SubPage - см. Deps.SubPage. Реализуется subpage.Page. Ошибка значит,
// что в ответ ничего не записано.
type SubPage interface {
	Serve(w http.ResponseWriter, r *http.Request, shortUUID string, platform model.Platform) (status, bytes int, err error)
}

// Deps - зависимости обработчика подписки.
type Deps struct {
	Store *store.DB
	// Panel может быть nil в режиме зеркала: там прослойка вообще не ходит
	// в API панели, только проксирует байты на внешний домен.
	Panel  Panel
	ReqLog *store.ReqLogger
	// ParseUA разбирает запрос в model.Client. Реализуется пакетом ua.
	ParseUA func(*http.Request) model.Client
	// Landing - страница-маскировка для не-клиентских (браузерных)
	// запросов. Может быть nil - тогда браузеру просто отдаётся 404.
	Landing    http.Handler
	Logger     *slog.Logger
	TrustProxy bool
	HTTPClient *http.Client
	// Grace - см. тип Grace выше. Может быть nil - тогда грейс не
	// пытается применяться, как будто store.KeyGraceEnabled всегда выключен.
	Grace Grace
	// Legacy переводит старую ссылку Marzban в текущий shortUuid
	// пользователя (пакет internal/legacy). Может быть nil.
	Legacy LegacyResolver
	// SubPage - страница подписки для браузера, пришедшего по живой ссылке
	// (пакет internal/subpage). Может быть nil - тогда браузер получает
	// маскировку, как раньше.
	SubPage SubPage
	// WGPool - пул готовых конфигов WireGuard/AmneziaWG (пакет
	// internal/wgpool). Может быть nil - тогда довесок WireGuard в
	// подписку не добавляется, даже если store.KeyWGPoolEnabled включён.
	WGPool *wgpool.Service
}

// Handler обрабатывает HTTP-запросы подписки.
type Handler struct {
	deps Deps
}

// New проверяет обязательные зависимости и подставляет значения по
// умолчанию для необязательных.
func New(d Deps) (*Handler, error) {
	if d.Store == nil {
		return nil, errors.New("proxy: не задан Store")
	}
	if d.ParseUA == nil {
		return nil, errors.New("proxy: не задана функция ParseUA")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.HTTPClient == nil {
		d.HTTPClient = &http.Client{
			// Подписку проксируем как есть, включая редиректы: решать, идти
			// ли по Location, - дело клиента, а не прослойки.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Handler{deps: d}, nil
}

// ServeHTTP - точка входа для всех запросов подписки.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	client := h.deps.ParseUA(r)
	shortUUID, suffix := splitSubPath(r.URL.Path)
	ip := clientIP(r, h.deps.TrustProxy)

	rec := model.RequestLog{
		ShortUUID:  shortUUID,
		IP:         ip,
		UserAgent:  client.UserAgent,
		App:        client.App,
		AppVersion: client.AppVersion,
		Platform:   string(client.Platform),
		Core:       string(client.Core),
		HWID:       client.HWID,
	}

	var (
		decision = model.DecisionNormal
		status   = http.StatusOK
		bytesN   = 0
		errText  = ""
		mode     model.Mode
		// format попадает в журнал: по нему видно, что именно ушло клиенту
		// (base64, clash, sing-box). Без этого колонка формата в админке
		// всегда пустая, и разбираться, почему у mihomo не завёлся конфиг,
		// приходится по одному лишь User-Agent.
		format = model.FormatUnknown
	)
	// Журналируем запрос при любом выходе из функции, что бы ни случилось
	// дальше: незалогированный отказ хуже, чем чуть более дорогой defer.
	// ReqLog.Add сам по себе не блокирует (кладёт запись в очередь).
	//
	// store.KeyLogEnabled даёт администратору выключить журнал целиком (не
	// копить IP и User-Agent сверх необходимого). Но решили: полностью
	// слепой процесс диагностировать нельзя, поэтому отказы всё равно
	// пишутся, даже при выключенной галочке (см. isDenialDecision) - иначе
	// единственный способ заметить, что кого-то не пускают к подписке, это
	// читать живые логи процесса построчно в поисках нужного запроса.
	// Обычная успешная выдача, маскировка и шум сканеров по
	// несуществующим shortUuid - самый объёмный и наименее ценный для
	// диагностики трафик, и именно от него избавляет выключение галочки.
	defer func() {
		rec.Decision = string(decision)
		rec.Status = status
		rec.Bytes = bytesN
		rec.DurationMS = int(time.Since(start) / time.Millisecond)
		rec.Mode = string(mode)
		if format != model.FormatUnknown {
			rec.Format = string(format)
		}
		rec.Err = errText
		if h.deps.Store.GetBool(ctx, store.KeyLogEnabled) || isDenialDecision(decision) {
			h.deps.ReqLog.Add(rec)
		}
	}()

	mode = model.Mode(h.deps.Store.Get(ctx, store.KeyMode))

	// Старая ссылка Marzban: подпись проверена секретом, пользователь найден
	// в панели. Дальше запрос обслуживается ровно как по его текущей ссылке.
	if mode == model.ModePanel && shortUUID != "" && h.deps.Legacy != nil {
		if su, ok := h.deps.Legacy.Resolve(ctx, shortUUID); ok {
			shortUUID = su
			rec.ShortUUID = su
		}
	}

	// Браузер по живой ссылке получает страницу подписки с инструкциями.
	// Если подписки нет или панель страницу не разрешила, всё как раньше:
	// маскировка ниже.
	if client.IsBrowser && mode == model.ModePanel && shortUUID != "" && h.deps.SubPage != nil &&
		h.deps.Store.GetBool(ctx, store.KeySubpageEnabled) {
		if st, n, err := h.deps.SubPage.Serve(w, r, shortUUID, client.Platform); err == nil {
			decision, status, bytesN = model.DecisionPage, st, n
			return
		}
	}

	// Браузер при включённой маскировке не должен увидеть ничего похожего
	// на прослойку подписки.
	if client.IsBrowser && h.deps.Store.GetBool(ctx, store.KeyDecoyEnabled) {
		decision = model.DecisionDecoy
		if h.deps.Landing != nil {
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			h.deps.Landing.ServeHTTP(sw, r)
			status, bytesN = sw.status, sw.n
		} else {
			status = http.StatusNotFound
			w.WriteHeader(status)
		}
		return
	}

	if shortUUID == "" {
		decision = model.DecisionNotFound
		status = http.StatusNotFound
		w.WriteHeader(status)
		return
	}

	// Формат заглушки нужен и на самых ранних (override) и на поздних
	// (после fetch) стадиях - оценка по суффиксу пути и ядру клиента,
	// без знания настоящего формата апстрима.
	guessedFormat := guessFormat(suffix, client, model.FormatUnknown)
	format = guessedFormat

	// Локальная блокировка - самая дешёвая проверка, не зависит ни от
	// режима, ни от доступности панели, поэтому идёт первой.
	if ov, ok := h.deps.Store.FindOverride(ctx, shortUUID, client.HWID); ok && ov.Action == "block" {
		decision = model.DecisionBlocked
		errText = overrideReason(ov)
		bytesN = h.writeStub(ctx, w, guessedFormat, "Подписка заблокирована", "")
		return
	}

	// Лимит устройств по данным панели - идёт ДО обращения к кэшу и ДО
	// самого похода за телом подписки. Это принципиально: ключ кэша (см.
	// cacheKey) складывается из shortUuid, ядра клиента и формата -
	// устройства в нём нет. Если проверять лимит после чтения кэша, первое
	// устройство, прошедшее лимит, кладёт ответ в кэш, и любое следующее
	// устройство того же пользователя на этом же ядре получает полную
	// подписку прямо из кэша в обход проверки, пока запись не протухла.
	//
	// В панель ходим только в режиме panel и только если фича включена
	// явно: лишний сетевой поход на каждый запрос подписки того не стоит,
	// когда она выключена (а выключена по умолчанию).
	if mode == model.ModePanel && h.deps.Panel != nil && h.deps.Store.GetBool(ctx, store.KeyHWIDEnforce) {
		pu, err := h.deps.Panel.UserByShortUUID(ctx, shortUUID)
		if err != nil {
			h.deps.Logger.Warn("proxy: не проверить лимит устройств, панель недоступна",
				"short_uuid", shortUUID, "err", err)
		} else if allowed, reason := hwid.Enforce(ctx, h.deps.Store, h.deps.Panel, h.deps.Logger, client, pu); !allowed {
			decision = model.DecisionBlocked
			errText = reason
			bytesN = h.writeStub(ctx, w, guessedFormat, "Подписка заблокирована", "")
			return
		}
	}

	ttl := h.deps.Store.GetDuration(ctx, store.KeyCacheTTL, 0)
	useCache := ttl > 0
	var ck string
	if useCache {
		ck = cacheKey(shortUUID, client.Core, guessedFormat)
		if cached, ok := h.cacheGet(ctx, ck); ok {
			decision, status, bytesN = h.finalize(ctx, w, client, shortUUID, guessedFormat, cached.status, cached.headers, cached.body)
			return
		}
	}

	timeout := h.deps.Store.GetDuration(ctx, store.KeyUpstreamTimeout, 15*time.Second)
	uctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var (
		up  upstream
		err error
	)
	switch mode {
	case model.ModePanel:
		up, err = h.fetchPanel(uctx, shortUUID, suffix, r.Header)
	default:
		// Всё, что не "panel" (включая пустую настройку из свежей базы),
		// считаем зеркалом - это значение по умолчанию у store.KeyMode.
		up, err = h.fetchMirror(uctx, r, ip)
	}
	if err != nil {
		errText = err.Error()
		if errors.Is(err, model.ErrNotFound) {
			decision = model.DecisionNotFound
			status = http.StatusNotFound
		} else {
			// Настоящий сбой связи с апстримом - это не наше бизнес-решение
			// вроде блокировки, поэтому 200 тут не форсируем: как обычный
			// reverse-proxy, честно отдаём 502. Решение помечаем отдельным
			// DecisionError, а не оставляем DecisionNormal по умолчанию:
			// иначе в журнале сбой апстрима неотличим от настоящей успешной
			// выдачи подписки, и фильтр по "выдана" вводит в заблуждение.
			decision = model.DecisionError
			status = http.StatusBadGateway
		}
		w.WriteHeader(status)
		return
	}

	// Грейс пробуем только на "живом" походе к апстриму, не на попадании в
	// короткий кэш ответа: если пользователю положена отсрочка, она
	// сработает максимум через cache_ttl секунд, на следующем запросе без
	// кэша. Городить грейс поверх кэша ради этой небольшой задержки не
	// стоит - обе фичи по умолчанию выключены и почти не пересекаются на
	// практике. ctx (не uctx) - у грейса свой собственный таймаут, отдельно
	// от только что использованного на fetch (см. afterExpiry).
	up = h.afterExpiry(ctx, mode, shortUUID, suffix, r, ip, up)

	if useCache && up.status >= http.StatusOK && up.status < http.StatusMultipleChoices {
		h.cacheSet(ctx, ck, up.status, up.header, up.body, ttl)
	}

	finalFormat := guessFormat(suffix, client, up.format)
	format = finalFormat
	decision, status, bytesN = h.finalize(ctx, w, client, shortUUID, finalFormat, up.status, up.header, up.body)
}

// finalize проверяет срок действия по заголовку subscription-userinfo и
// либо отдаёт заглушку "срок истёк", либо собирает нормальный ответ:
// довесок WireGuard из пула (если включён), разрешённые заголовки, срез
// ETag/Last-Modified, бренд по умолчанию и правила подмены заголовков под
// конкретное приложение.
//
// shortUUID нужен только для довеска WireGuard (лиза привязана к паре
// пользователь-устройство) - вызывается и на "живом" ответе апстрима, и на
// ответе из кэша, поэтому довесок каждый раз собирается заново под
// текущего клиента, а не хранится в самом кэше (иначе разные устройства
// одного пользователя получали бы чужую лизу друг друга, см. cacheKey).
func (h *Handler) finalize(ctx context.Context, w http.ResponseWriter, client model.Client, shortUUID string, format model.Format,
	status int, header http.Header, body []byte) (model.Decision, int, int) {
	rawUserInfo := header.Get("Subscription-Userinfo")
	if parseUserInfo(rawUserInfo).IsExpired(time.Now()) {
		n := h.writeStub(ctx, w, format, "Срок подписки истёк", rawUserInfo)
		return model.DecisionExpired, http.StatusOK, n
	}

	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		// Довесок WireGuard - только на настоящей успешной выдаче (тот же
		// диапазон статусов, что даёт право на кэширование в cacheSet). Без
		// этой проверки кто угодно, перебирая случайные shortUuid, получал
		// бы от нас реальную лизу из пула на каждый 404 - оплаченный ресурс
		// пула не должен расходоваться на несуществующих пользователей.
		body = h.appendWireGuard(ctx, client, shortUUID, format, body)
	}

	out := http.Header{}
	copyAllowedHeaders(out, header)
	stripCachingResponse(out)
	h.applyBrandDefaults(ctx, out)

	if rs, err := rules.Load(ctx, h.deps.Store); err != nil {
		h.deps.Logger.Warn("proxy: не загрузить правила подмены заголовков", "err", err)
	} else {
		rules.Apply(rs, client, out)
	}

	n := h.respond(w, status, out, body)
	decision := model.DecisionNormal
	if status == http.StatusNotFound {
		decision = model.DecisionNotFound
	}
	return decision, status, n
}

// writeStub отдаёт клиенту валидную пустую подписку с понятным заголовком
// вместо реального содержимого - используется и для блокировки, и для
// истёкшего срока. Статус всегда 200: клиенты подписки на 4xx/5xx обычно
// просто показывают ошибку сети, а не текст из profile-title.
func (h *Handler) writeStub(ctx context.Context, w http.ResponseWriter, format model.Format, title, carryUserInfo string) int {
	body, contentType := stubBody(format)
	hdr := http.Header{}
	hdr.Set("Content-Type", contentType)
	hdr.Set("Profile-Title", encodeProfileTitle(title))
	if carryUserInfo != "" {
		hdr.Set("Subscription-Userinfo", carryUserInfo)
	}
	h.applyBrandDefaults(ctx, hdr)
	return h.respond(w, http.StatusOK, hdr, body)
}

// respond пишет заголовки, статус и тело, возвращает число записанных
// байт тела - для журнала запроса.
func (h *Handler) respond(w http.ResponseWriter, status int, hdr http.Header, body []byte) int {
	dst := w.Header()
	for k, vv := range hdr {
		dst[k] = vv
	}
	w.WriteHeader(status)
	n, _ := w.Write(body)
	return n
}

// applyBrandDefaults подставляет значения по умолчанию из настроек бренда
// (store.KeyBrandTitle, KeyBrandSupportURL, KeyUpdateInterval) туда, где
// апстрим или заглушка не задали заголовок сами. Так профиль подписки
// всегда выглядит осмысленно, даже если панель не прислала свой
// profile-title.
func (h *Handler) applyBrandDefaults(ctx context.Context, header http.Header) {
	if header.Get("Profile-Title") == "" {
		if t := h.deps.Store.Get(ctx, store.KeyBrandTitle); t != "" {
			header.Set("Profile-Title", encodeProfileTitle(t))
		}
	}
	if header.Get("Support-Url") == "" {
		if s := h.deps.Store.Get(ctx, store.KeyBrandSupportURL); s != "" {
			header.Set("Support-Url", s)
		}
	}
	if header.Get("Profile-Update-Interval") == "" {
		if n := h.deps.Store.GetInt(ctx, store.KeyUpdateInterval, 0); n > 0 {
			header.Set("Profile-Update-Interval", strconv.Itoa(n))
		}
	}
}

func overrideReason(o model.Override) string {
	if o.Reason != "" {
		return "локальная блокировка: " + o.Reason
	}
	return "локальная блокировка"
}

// isDenialDecision сообщает, писать ли решение в журнал запросов, даже
// когда store.KeyLogEnabled выключен целиком. Решение задокументировано
// подробно у места использования (defer в ServeHTTP): коротко - отказы
// видеть нужно всегда, объёмный некритичный трафик подчиняется галочке.
func isDenialDecision(d model.Decision) bool {
	switch d {
	case model.DecisionBlocked, model.DecisionExpired, model.DecisionError:
		return true
	default:
		return false
	}
}

// statusWriter оборачивает http.ResponseWriter, чтобы после вызова
// стороннего http.Handler (Landing) узнать, какой статус и сколько байт
// тела он в итоге отдал - это нужно только для журнала запроса.
type statusWriter struct {
	http.ResponseWriter
	status      int
	n           int
	wroteHeader bool
}

func (sw *statusWriter) WriteHeader(code int) {
	if sw.wroteHeader {
		return
	}
	sw.wroteHeader = true
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if !sw.wroteHeader {
		sw.WriteHeader(http.StatusOK)
	}
	n, err := sw.ResponseWriter.Write(b)
	sw.n += n
	return n, err
}
