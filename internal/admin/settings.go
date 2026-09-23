package admin

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// settingsForm: поля формы настроек. Секреты (токен панели, токен бота
// Telegram, секрет вебхуков) сюда никогда не попадают настоящим значением,
// только флаг «задан ли он»: см. поля с суффиксом *Set. Настоящее значение
// в HTML не выводится ни при каких обстоятельствах (см. secret_leak_test.go).
type settingsForm struct {
	Mode            string
	PanelURL        string
	PanelTokenSet   bool
	MirrorTarget    string
	OwnDomain       string
	SubPageURL      string
	DecoyEnabled    bool
	DecoyTheme      string
	LogEnabled      bool
	LogKeepDays     string
	CacheTTL        string
	UpstreamTimeout string
	BrandTitle      string
	BrandSupportURL string
	UpdateInterval  string
	TrustedProxies  string

	// Устройства.
	HWIDEnforce bool

	// Грейс: единственный блок настроек, который меняет данные в живой
	// панели (продлевает пользователей через реальный API), а не только
	// локальные записи прослойки. Предупреждение об этом есть в самой
	// форме (settings.html).
	GraceEnabled bool
	GraceSquad   string
	GraceHours   string

	// Чат поддержки.
	ChatEnabled    bool
	ChatTGTokenSet bool
	ChatTGChat     string
	ChatTGAPIBase  string

	// Вебхуки от панели.
	WebhookSecretSet bool

	// WireGuard.
	WGPoolEnabled bool

	// Страница подписки и старые ссылки Marzban.
	SubpageEnabled       bool
	SubpageLogoURL       string
	MarzbanLegacyKeysSet bool
}

// settingsPageData: данные вкладки «Настройки».
type settingsPageData struct {
	pageBase
	Form  settingsForm
	Error string
}

// handleSettingsForm показывает текущие настройки.
func (h *Handler) handleSettingsForm(w http.ResponseWriter, r *http.Request, s *session) {
	h.render(w, http.StatusOK, "settings.html", settingsPageData{
		pageBase: h.newPageBase(r, s, "Настройки", "settings"),
		Form:     h.currentSettingsForm(r),
	})
}

// currentSettingsForm читает настройки из хранилища и раскладывает их в форму.
func (h *Handler) currentSettingsForm(r *http.Request) settingsForm {
	ctx := r.Context()
	all, err := h.store.Settings(ctx)
	if err != nil {
		// Settings() уже подставляет значения по умолчанию сама, ошибка
		// здесь означает недоступную базу, а не отсутствие настроек,
		// и в этом случае форма просто останется пустой, без падения страницы.
		h.log.Warn("admin: не прочитать настройки", "err", err)
		all = map[string]string{}
	}
	return settingsForm{
		Mode:            all[store.KeyMode],
		PanelURL:        all[store.KeyPanelURL],
		PanelTokenSet:   all[store.KeyPanelToken] != "",
		MirrorTarget:    all[store.KeyMirrorTarget],
		OwnDomain:       all[store.KeyOwnDomain],
		SubPageURL:      all[store.KeySubPageURL],
		DecoyEnabled:    isTrue(all[store.KeyDecoyEnabled]),
		DecoyTheme:      all[store.KeyDecoyTheme],
		LogEnabled:      isTrue(all[store.KeyLogEnabled]),
		LogKeepDays:     all[store.KeyLogKeepDays],
		CacheTTL:        all[store.KeyCacheTTL],
		UpstreamTimeout: all[store.KeyUpstreamTimeout],
		BrandTitle:      all[store.KeyBrandTitle],
		BrandSupportURL: all[store.KeyBrandSupportURL],
		UpdateInterval:  all[store.KeyUpdateInterval],
		TrustedProxies:  all[store.KeyTrustedProxies],

		HWIDEnforce: isTrue(all[store.KeyHWIDEnforce]),

		GraceEnabled: isTrue(all[store.KeyGraceEnabled]),
		GraceSquad:   all[store.KeyGraceSquad],
		GraceHours:   all[store.KeyGraceHours],

		ChatEnabled:    isTrue(all[store.KeyChatEnabled]),
		ChatTGTokenSet: all[store.KeyChatTGToken] != "",
		ChatTGChat:     all[store.KeyChatTGChat],
		ChatTGAPIBase:  all[store.KeyChatTGAPIBase],

		WebhookSecretSet: all[store.KeyWebhookSecret] != "",

		WGPoolEnabled: isTrue(all[store.KeyWGPoolEnabled]),

		SubpageEnabled:       isTrue(all[store.KeySubpageEnabled]),
		SubpageLogoURL:       all[store.KeySubpageLogoURL],
		MarzbanLegacyKeysSet: all[store.KeyMarzbanLegacyKeys] != "",
	}
}

// handleSettingsSave проверяет и сохраняет настройки.
func (h *Handler) handleSettingsSave(w http.ResponseWriter, r *http.Request, s *session) {
	form := settingsForm{
		Mode:            r.PostFormValue("mode"),
		PanelURL:        strings.TrimSpace(r.PostFormValue("panel_url")),
		MirrorTarget:    strings.TrimSpace(r.PostFormValue("mirror_target")),
		OwnDomain:       strings.TrimSpace(r.PostFormValue("own_domain")),
		SubPageURL:      strings.TrimSpace(r.PostFormValue("subpage_url")),
		DecoyEnabled:    r.PostFormValue("decoy_enabled") != "",
		DecoyTheme:      strings.TrimSpace(r.PostFormValue("decoy_theme")),
		LogEnabled:      r.PostFormValue("log_enabled") != "",
		LogKeepDays:     strings.TrimSpace(r.PostFormValue("log_keep_days")),
		CacheTTL:        strings.TrimSpace(r.PostFormValue("cache_ttl")),
		UpstreamTimeout: strings.TrimSpace(r.PostFormValue("upstream_timeout")),
		BrandTitle:      strings.TrimSpace(r.PostFormValue("brand_title")),
		BrandSupportURL: strings.TrimSpace(r.PostFormValue("brand_support_url")),
		UpdateInterval:  strings.TrimSpace(r.PostFormValue("update_interval")),
		TrustedProxies:  strings.TrimSpace(r.PostFormValue("trusted_proxies")),

		HWIDEnforce: r.PostFormValue("hwid_enforce") != "",

		GraceEnabled: r.PostFormValue("grace_enabled") != "",
		GraceSquad:   strings.TrimSpace(r.PostFormValue("grace_squad")),
		GraceHours:   strings.TrimSpace(r.PostFormValue("grace_hours")),

		ChatEnabled:   r.PostFormValue("chat_enabled") != "",
		ChatTGChat:    strings.TrimSpace(r.PostFormValue("chat_tg_chat")),
		ChatTGAPIBase: strings.TrimSpace(r.PostFormValue("chat_tg_api_base")),

		WGPoolEnabled: r.PostFormValue("wg_pool_enabled") != "",

		SubpageEnabled: r.PostFormValue("subpage_enabled") != "",
		SubpageLogoURL: strings.TrimSpace(r.PostFormValue("subpage_logo_url")),
	}

	newToken := r.PostFormValue("panel_token")
	clearToken := r.PostFormValue("panel_token_clear") != ""
	tokenWasSet := h.store.Get(r.Context(), store.KeyPanelToken) != ""
	form.PanelTokenSet = (tokenWasSet && !clearToken) || newToken != ""

	newChatToken := r.PostFormValue("chat_tg_token")
	clearChatToken := r.PostFormValue("chat_tg_token_clear") != ""
	chatTokenWasSet := h.store.Get(r.Context(), store.KeyChatTGToken) != ""
	form.ChatTGTokenSet = (chatTokenWasSet && !clearChatToken) || newChatToken != ""

	newWebhookSecret := r.PostFormValue("webhook_secret")
	clearWebhookSecret := r.PostFormValue("webhook_secret_clear") != ""
	webhookSecretWasSet := h.store.Get(r.Context(), store.KeyWebhookSecret) != ""
	form.WebhookSecretSet = (webhookSecretWasSet && !clearWebhookSecret) || newWebhookSecret != ""

	newLegacyKeys := strings.TrimSpace(r.PostFormValue("marzban_legacy_keys"))
	clearLegacyKeys := r.PostFormValue("marzban_legacy_keys_clear") != ""
	legacyKeysWereSet := h.store.Get(r.Context(), store.KeyMarzbanLegacyKeys) != ""
	form.MarzbanLegacyKeysSet = (legacyKeysWereSet && !clearLegacyKeys) || newLegacyKeys != ""

	logKeepDays, errMsg := parsePositiveInt(form.LogKeepDays, "срок хранения журнала")
	var cacheTTL, upstreamTimeout, updateInterval, graceHours int
	if errMsg == "" {
		cacheTTL, errMsg = parseNonNegativeInt(form.CacheTTL, "кэш")
	}
	if errMsg == "" {
		upstreamTimeout, errMsg = parsePositiveInt(form.UpstreamTimeout, "таймаут запроса к панели")
	}
	if errMsg == "" {
		updateInterval, errMsg = parsePositiveInt(form.UpdateInterval, "интервал обновления профиля")
	}
	if errMsg == "" {
		graceHours, errMsg = parsePositiveInt(form.GraceHours, "часы грейса")
	}
	if errMsg == "" && form.Mode != string(model.ModeMirror) && form.Mode != string(model.ModePanel) {
		errMsg = "Выберите режим работы"
	}
	if errMsg == "" && form.Mode == string(model.ModeMirror) && form.MirrorTarget == "" {
		errMsg = "Для режима зеркала нужен домен origin"
	}
	if errMsg == "" && form.Mode == string(model.ModePanel) && form.PanelURL == "" {
		errMsg = "Для режима панели нужен адрес API панели"
	}
	if errMsg == "" && form.GraceEnabled && !looksLikeIdentifier(form.GraceSquad) {
		errMsg = "Для грейса нужен идентификатор сквада"
	}
	if errMsg == "" && form.ChatTGAPIBase != "" && !isValidHTTPURL(form.ChatTGAPIBase) {
		errMsg = "Адрес API Telegram должен быть корректным URL (http или https)"
	}
	if errMsg == "" && form.SubpageLogoURL != "" && !isValidHTTPURL(form.SubpageLogoURL) {
		errMsg = "Адрес логотипа должен быть корректным URL (http или https)"
	}
	if errMsg == "" && form.ChatEnabled && form.ChatTGAPIBase == "" {
		errMsg = "Для виджета чата нужен адрес API Telegram"
	}

	if errMsg != "" {
		h.render(w, http.StatusUnprocessableEntity, "settings.html", settingsPageData{
			pageBase: h.newPageBase(r, s, "Настройки", "settings"),
			Form:     form,
			Error:    errMsg,
		})
		return
	}

	kv := map[string]string{
		store.KeyMode:            form.Mode,
		store.KeyPanelURL:        form.PanelURL,
		store.KeyMirrorTarget:    form.MirrorTarget,
		store.KeyOwnDomain:       form.OwnDomain,
		store.KeySubPageURL:      form.SubPageURL,
		store.KeyDecoyEnabled:    boolStr(form.DecoyEnabled),
		store.KeyDecoyTheme:      form.DecoyTheme,
		store.KeyLogEnabled:      boolStr(form.LogEnabled),
		store.KeyLogKeepDays:     strconv.Itoa(logKeepDays),
		store.KeyCacheTTL:        strconv.Itoa(cacheTTL),
		store.KeyUpstreamTimeout: strconv.Itoa(upstreamTimeout),
		store.KeyBrandTitle:      form.BrandTitle,
		store.KeyBrandSupportURL: form.BrandSupportURL,
		store.KeyUpdateInterval:  strconv.Itoa(updateInterval),
		store.KeyTrustedProxies:  form.TrustedProxies,

		store.KeyHWIDEnforce: boolStr(form.HWIDEnforce),

		store.KeyGraceEnabled: boolStr(form.GraceEnabled),
		store.KeyGraceSquad:   form.GraceSquad,
		store.KeyGraceHours:   strconv.Itoa(graceHours),

		store.KeyChatEnabled:   boolStr(form.ChatEnabled),
		store.KeyChatTGChat:    form.ChatTGChat,
		store.KeyChatTGAPIBase: form.ChatTGAPIBase,

		store.KeyWGPoolEnabled: boolStr(form.WGPoolEnabled),

		store.KeySubpageEnabled: boolStr(form.SubpageEnabled),
		store.KeySubpageLogoURL: form.SubpageLogoURL,
	}
	switch {
	case clearToken:
		kv[store.KeyPanelToken] = ""
	case newToken != "":
		kv[store.KeyPanelToken] = newToken
	}
	switch {
	case clearChatToken:
		kv[store.KeyChatTGToken] = ""
	case newChatToken != "":
		kv[store.KeyChatTGToken] = newChatToken
	}
	switch {
	case clearWebhookSecret:
		kv[store.KeyWebhookSecret] = ""
	case newWebhookSecret != "":
		kv[store.KeyWebhookSecret] = newWebhookSecret
	}

	switch {
	case clearLegacyKeys:
		kv[store.KeyMarzbanLegacyKeys] = ""
	case newLegacyKeys != "":
		kv[store.KeyMarzbanLegacyKeys] = newLegacyKeys
	}

	if err := h.store.SetMany(r.Context(), kv); err != nil {
		h.log.Error("admin: не сохранить настройки", "err", err)
		h.render(w, http.StatusInternalServerError, "settings.html", settingsPageData{
			pageBase: h.newPageBase(r, s, "Настройки", "settings"),
			Form:     form,
			Error:    "Не удалось сохранить настройки",
		})
		return
	}

	h.log.Info("admin: настройки сохранены", "by", s.user)
	h.redirectWithFlash(w, r, s, "ok", "Настройки сохранены", h.path("/settings"))
}

func isTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// parsePositiveInt разбирает число из формы, требуя значение не меньше 1.
func parsePositiveInt(v, label string) (int, string) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, "Поле «" + label + "» должно быть целым числом не меньше 1"
	}
	return n, ""
}

// parseNonNegativeInt: то же самое, но допускает 0 (например, кэш можно выключить).
func parseNonNegativeInt(v, label string) (int, string) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, "Поле «" + label + "» должно быть целым числом не меньше 0"
	}
	return n, ""
}

// looksLikeIdentifier: грубая проверка «похоже на идентификатор» (uuid
// сквада и т.п.), без пробелов и управляющих символов. Строгий формат UUID
// не требуем: конкретная схема id зависит от версии панели.
func looksLikeIdentifier(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// isValidHTTPURL проверяет, что строка является абсолютным http(s) URL с
// хостом. Используется для адреса API Telegram: прослойка сама туда ходит, так что
// мусор в этом поле лучше отсечь при сохранении, а не при первом же вызове API.
func isValidHTTPURL(v string) bool {
	u, err := url.Parse(v)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.Host != ""
}
