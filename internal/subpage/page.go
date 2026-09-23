// Package subpage рисует страницу подписки для тех, кто открыл ссылку
// подписки в браузере: карточка подписки, выбор платформы и приложения,
// пошаговая установка с кнопками «скачать» и «добавить подписку», ссылка
// и QR-код. Механика та же, что у страницы подписки Remnawave, и конфиг
// (платформы, приложения, шаги, тексты) берётся оттуда же, из панели:
// администратор правит его в привычном месте, а прослойка только рисует.
package subpage

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// defaultConfigUUID: конфиг «Default» есть в любой панели.
const defaultConfigUUID = "00000000-0000-0000-0000-000000000000"

// configTTL: сколько держать разобранный конфиг страницы. Правка в панели
// появится на странице не позже чем через это время.
const configTTL = 5 * time.Minute

// ErrUnavailable: страницу показать нельзя (нет такой подписки, панель
// запретила страницу или не ответила). Вызывающий код тогда показывает
// маскировку, как и раньше.
var ErrUnavailable = errors.New("subpage: страница недоступна")

// Panel: то, что странице нужно от панели.
type Panel interface {
	SubscriptionInfo(ctx context.Context, shortUUID string) (model.SubInfo, error)
	SubpageRef(ctx context.Context, shortUUID string, in http.Header) (model.SubpageRef, error)
	SubpageConfig(ctx context.Context, uuid string) (json.RawMessage, error)
}

//go:embed page.html
var pageHTML string

var pageTmpl = template.Must(template.New("page").Parse(pageHTML))

type cachedConfig struct {
	cfg   *Config
	until time.Time
}

// Page рисует страницу подписки.
type Page struct {
	db    *store.DB
	panel Panel
	log   *slog.Logger

	mu      sync.Mutex
	configs map[string]cachedConfig
}

// New собирает обработчик страницы.
func New(db *store.DB, panel Panel, log *slog.Logger) *Page {
	if log == nil {
		log = slog.Default()
	}
	return &Page{db: db, panel: panel, log: log, configs: map[string]cachedConfig{}}
}

// Serve отдаёт страницу подписки shortUUID. Ошибка значит, что в ответ
// ничего не записано и вызывающий код волен показать что-то другое.
// Возвращает статус и число байт тела для журнала запросов.
func (p *Page) Serve(w http.ResponseWriter, r *http.Request, shortUUID string, platform model.Platform) (int, int, error) {
	if p == nil || p.panel == nil {
		return 0, 0, ErrUnavailable
	}
	ctx := r.Context()

	info, err := p.panel.SubscriptionInfo(ctx, shortUUID)
	if err != nil {
		if !errors.Is(err, model.ErrNotFound) {
			p.log.Warn("subpage: не получить сведения о подписке", "err", err)
		}
		return 0, 0, ErrUnavailable
	}

	ref, err := p.panel.SubpageRef(ctx, shortUUID, r.Header)
	if err != nil {
		p.log.Warn("subpage: не получить конфиг страницы для пользователя", "err", err)
		return 0, 0, ErrUnavailable
	}
	if !ref.WebpageAllowed {
		return 0, 0, ErrUnavailable
	}
	cfgUUID := ref.ConfigUUID
	if cfgUUID == "" {
		cfgUUID = defaultConfigUUID
	}
	cfg, err := p.config(ctx, cfgUUID)
	if err != nil {
		p.log.Warn("subpage: не получить конфиг страницы", "uuid", cfgUUID, "err", err)
		return 0, 0, ErrUnavailable
	}

	v := p.buildView(ctx, cfg, info, pickLang(r.Header.Get("Accept-Language"), cfg.Locales), platform)

	var buf bytes.Buffer
	if err := pageTmpl.Execute(&buf, v); err != nil {
		p.log.Error("subpage: не отрисовать страницу", "err", err)
		return 0, 0, ErrUnavailable
	}

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	// На странице ссылка подписки: она не должна уходить в Referer
	// сайтам магазинов приложений и прочим внешним ссылкам.
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	n, _ := w.Write(buf.Bytes())
	return http.StatusOK, n, nil
}

func (p *Page) config(ctx context.Context, uuid string) (*Config, error) {
	now := time.Now()
	p.mu.Lock()
	c, ok := p.configs[uuid]
	p.mu.Unlock()
	if ok && now.Before(c.until) {
		return c.cfg, nil
	}

	raw, err := p.panel.SubpageConfig(ctx, uuid)
	if err != nil {
		if ok {
			// Панель не ответила, а старый конфиг есть: лучше показать
			// чуть устаревшие инструкции, чем маскировку.
			return c.cfg, nil
		}
		return nil, err
	}
	cfg, err := ParseConfig(raw)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.configs[uuid] = cachedConfig{cfg: cfg, until: now.Add(configTTL)}
	p.mu.Unlock()
	return cfg, nil
}

// ---- данные для шаблона ----

type view struct {
	Lang        string
	MetaTitle   string
	Title       string
	LogoURL     string
	SupportURL  template.URL
	T           map[string]string
	Status      string
	StatusClass string
	Expires     string
	DaysLeft    string
	Traffic     string
	TrafficOf   string
	TrafficPct  int
	Limited     bool
	SubURL      string
	QR          template.HTML
	HideGetLink bool
	Platforms   []platformView
	Active      string
}

type platformView struct {
	Key   string
	Name  string
	Icon  template.HTML
	Apps  []appView
	First bool
}

type appView struct {
	ID       string
	Name     string
	Icon     template.HTML
	Featured bool
	First    bool
	Blocks   []blockView
}

type blockView struct {
	N           int
	Title       string
	Description string
	Icon        template.HTML
	Color       string
	Buttons     []buttonView
}

type buttonView struct {
	Text    string
	Link    template.URL
	Icon    template.HTML
	Primary bool
}

// defaultTexts: подписи на случай, если в конфиге панели их нет.
var defaultTexts = map[string]string{
	"active":                  "Активна",
	"inactive":                "Неактивна",
	"expired":                 "Истекла",
	"expires":                 "Действует до",
	"bandwidth":               "Трафик",
	"indefinitely":            "Бессрочно",
	"status":                  "Статус",
	"copyLink":                "Скопировать ссылку",
	"linkCopied":              "Ссылка скопирована",
	"getLink":                 "Ссылка на подписку",
	"scanQrCode":              "Отсканируйте QR-код в приложении",
	"scanQrCodeDescription":   "Или скопируйте ссылку и вставьте её в приложение вручную.",
	"installationGuideHeader": "Установка",
}

func (p *Page) buildView(ctx context.Context, cfg *Config, info model.SubInfo, lang string, platform model.Platform) view {
	t := make(map[string]string, len(defaultTexts))
	for k, def := range defaultTexts {
		t[k] = def
		if l, ok := cfg.BaseTranslations[k]; ok {
			if s := l.In(lang); s != "" {
				t[k] = s
			}
		}
	}

	title := strings.TrimSpace(cfg.Branding.Title)
	logo := strings.TrimSpace(p.db.Get(ctx, store.KeySubpageLogoURL))
	if logo == "" {
		logo = strings.TrimSpace(cfg.Branding.LogoURL)
	}
	meta := title
	if meta == "" {
		meta = cfg.Base.MetaTitle
	}

	v := view{
		Lang:        lang,
		MetaTitle:   meta,
		Title:       title,
		LogoURL:     logo,
		T:           t,
		SubURL:      info.SubscriptionURL,
		HideGetLink: cfg.Base.HideGetLinkButton,
	}
	// Ссылка поддержки из настроек прослойки главнее конфига панели: там
	// она общая для всех страниц, а поддержку сервис меняет чаще, чем конфиг.
	support := strings.TrimSpace(p.db.Get(ctx, store.KeyBrandSupportURL))
	if support == "" {
		support = strings.TrimSpace(cfg.Branding.SupportURL)
	}
	v.SupportURL = ""
	if support != "" {
		v.SupportURL = safeURL(support)
	}

	v.Status, v.StatusClass = statusText(info, t)
	if info.ExpiresAt.IsZero() || info.ExpiresAt.Year() > 2090 {
		v.Expires = t["indefinitely"]
	} else {
		v.Expires = info.ExpiresAt.In(moscow).Format("02.01.2006")
		if info.IsActive && info.DaysLeft >= 0 {
			v.DaysLeft = daysText(info.DaysLeft)
		}
	}
	v.Traffic, v.TrafficOf, v.TrafficPct, v.Limited = trafficText(info)

	if info.SubscriptionURL != "" {
		if code, err := qr.Encode(info.SubscriptionURL, qr.M); err == nil {
			v.QR = qrSVG(code)
		}
	}

	ld := linkData{SubURL: info.SubscriptionURL, Username: info.Username}
	for i, pl := range cfg.Platforms {
		pv := platformView{
			Key:   pl.Key,
			Name:  pl.DisplayName.In(lang),
			Icon:  svg(cfg, pl.SVGIconKey),
			First: i == 0,
		}
		if pv.Name == "" {
			pv.Name = pl.Key
		}
		for j, app := range pl.Apps {
			av := appView{
				ID:       fmt.Sprintf("%s-%d", pl.Key, j),
				Name:     app.Name,
				Icon:     svg(cfg, strings.ReplaceAll(app.Name, " ", "")),
				Featured: app.Featured,
				First:    j == 0,
			}
			for k, b := range app.Blocks {
				bv := blockView{
					N:           k + 1,
					Title:       b.Title.In(lang),
					Description: b.Description.In(lang),
					Icon:        svg(cfg, b.SVGIconKey),
					Color:       colorName(b.SVGIconColor),
				}
				for _, btn := range b.Buttons {
					bv.Buttons = append(bv.Buttons, buttonView{
						Text:    btn.Text.In(lang),
						Link:    safeURL(fillLink(btn.Link, ld)),
						Icon:    svg(cfg, btn.SVGIconKey),
						Primary: btn.Type == "subscriptionLink",
					})
				}
				av.Blocks = append(av.Blocks, bv)
			}
			pv.Apps = append(pv.Apps, av)
		}
		v.Platforms = append(v.Platforms, pv)
	}
	v.Active = pickPlatform(cfg.Platforms, platform)
	return v
}

var moscow = func() *time.Location {
	if loc, err := time.LoadLocation("Europe/Moscow"); err == nil {
		return loc
	}
	return time.FixedZone("MSK", 3*60*60)
}()

func statusText(info model.SubInfo, t map[string]string) (string, string) {
	switch {
	case info.IsActive || info.Status == "ACTIVE":
		return t["active"], "ok"
	case info.Status == "EXPIRED":
		return t["expired"], "bad"
	case info.Status == "LIMITED":
		return "Лимит трафика", "warn"
	default:
		return t["inactive"], "bad"
	}
}

func daysText(n int) string {
	word := "дней"
	switch {
	case n%100 >= 11 && n%100 <= 14:
	case n%10 == 1:
		word = "день"
	case n%10 >= 2 && n%10 <= 4:
		word = "дня"
	}
	return fmt.Sprintf("ещё %d %s", n, word)
}

// trafficText отдаёт израсходованный объём, подпись под ним («из 800 ГБ»
// или «без лимита»), процент для полосы и есть ли лимит вообще.
func trafficText(info model.SubInfo) (string, string, int, bool) {
	used := humanBytes(info.TrafficUsedBytes)
	if info.TrafficLimitBytes <= 0 {
		return used, "без лимита", 0, false
	}
	pct := int(info.TrafficUsedBytes * 100 / info.TrafficLimitBytes)
	if pct > 100 {
		pct = 100
	}
	return used, "из " + humanBytes(info.TrafficLimitBytes), pct, true
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d Б", n)
	}
	units := []string{"КБ", "МБ", "ГБ", "ТБ", "ПБ"}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < len(units)-1; m /= unit {
		div *= unit
		exp++
	}
	s := strings.TrimSuffix(fmt.Sprintf("%.1f", float64(n)/float64(div)), ".0")
	return strings.Replace(s, ".", ",", 1) + " " + units[exp]
}

func svg(cfg *Config, key string) template.HTML {
	if key == "" {
		return ""
	}
	// SVG задаёт администратор панели в библиотеке иконок конфига страницы:
	// та же доверенная граница, что у страницы подписки Remnawave.
	return template.HTML(cfg.SVG[key])
}

// colorName сводит цвета иконок из конфига (палитра Mantine) к трём
// акцентам страницы.
func colorName(c string) string {
	switch c {
	case "cyan", "blue", "indigo", "teal", "green", "lime":
		return c
	default:
		return "violet"
	}
}

// pickPlatform выбирает вкладку, которую открыть сразу: платформу
// устройства, с которого открыли страницу, а если её в конфиге нет, то первую.
func pickPlatform(pls []Platform, platform model.Platform) string {
	want := string(platform)
	for _, pl := range pls {
		if strings.EqualFold(pl.Key, want) {
			return pl.Key
		}
	}
	return pls[0].Key
}

// pickLang выбирает язык страницы по Accept-Language среди языков конфига.
// По умолчанию русский: это страница российского сервиса.
func pickLang(acceptLanguage string, locales []string) string {
	has := func(l string) bool {
		if len(locales) == 0 {
			return l == "ru"
		}
		for _, x := range locales {
			if strings.EqualFold(x, l) {
				return true
			}
		}
		return false
	}
	for _, part := range strings.Split(acceptLanguage, ",") {
		tag := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		base := strings.ToLower(strings.SplitN(tag, "-", 2)[0])
		if base != "" && has(base) {
			return base
		}
	}
	return "ru"
}

// qrSVG рисует QR-код одной path-линией: без картинок и внешних скриптов.
func qrSVG(c *qr.Code) template.HTML {
	const quiet = 2
	size := c.Size + 2*quiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="QR"><rect width="%d" height="%d" fill="#fff"/><path fill="#14071f" d="`, size, size, size, size)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String())
}
