package admin

import (
	"io/fs"
	"net/http"

	"github.com/qwe8nxtroud/multigate/web"
)

// routes регистрирует все маршруты админки под h.base.
func (h *Handler) routes() {
	mux := http.NewServeMux()

	static, err := fs.Sub(web.StaticFS, "static")
	if err != nil {
		// Каталог встроен через go:embed на этапе сборки, так что этот путь
		// недостижим в рабочем бинарнике; паника здесь эквивалентна ошибке
		// компиляции, которую мы обязаны были поймать раньше.
		panic("admin: не открыть встроенную статику: " + err.Error())
	}
	mux.Handle(h.path("/static/"), http.StripPrefix(h.path("/static/"), http.FileServerFS(static)))

	// Мастер первичной настройки и вход: доступны без сессии администратора.
	mux.HandleFunc("GET "+h.path("/setup"), h.handleSetupForm)
	mux.HandleFunc("POST "+h.path("/setup"), h.handleSetupSubmit)
	mux.HandleFunc("GET "+h.path("/login"), h.handleLoginForm)
	mux.HandleFunc("POST "+h.path("/login"), h.handleLoginSubmit)
	mux.HandleFunc("POST "+h.path("/logout"), h.handleLogout)

	// Корень админки: просто уводит на обзор (или на login/setup через requireAuth).
	mux.HandleFunc("GET "+h.path(""), h.requireAuth(func(w http.ResponseWriter, r *http.Request, s *session) {
		http.Redirect(w, r, h.path("/overview"), http.StatusSeeOther)
	}))

	mux.HandleFunc("GET "+h.path("/overview"), h.requireAuth(h.handleOverview))

	mux.HandleFunc("GET "+h.path("/reqlog"), h.requireAuth(h.handleReqLog))
	mux.HandleFunc("POST "+h.path("/reqlog/block"), h.requirePOSTAuth(h.handleReqLogBlock))

	mux.HandleFunc("GET "+h.path("/users"), h.requireAuth(h.handleUsersList))
	mux.HandleFunc("GET "+h.path("/users/{shortUUID}"), h.requireAuth(h.handleUserCard))
	mux.HandleFunc("POST "+h.path("/users/{shortUUID}/devices/{hwid}/delete"), h.requirePOSTAuth(h.handleDeviceDelete))

	mux.HandleFunc("GET "+h.path("/overrides"), h.requireAuth(h.handleOverridesList))
	mux.HandleFunc("POST "+h.path("/overrides"), h.requirePOSTAuth(h.handleOverrideAdd))
	mux.HandleFunc("POST "+h.path("/overrides/{id}/delete"), h.requirePOSTAuth(h.handleOverrideDelete))

	mux.HandleFunc("GET "+h.path("/headerrules"), h.requireAuth(h.handleHeaderRulesList))
	mux.HandleFunc("GET "+h.path("/headerrules/new"), h.requireAuth(h.handleHeaderRuleNewForm))
	mux.HandleFunc("POST "+h.path("/headerrules/new"), h.requirePOSTAuth(h.handleHeaderRuleCreate))
	mux.HandleFunc("GET "+h.path("/headerrules/{id}"), h.requireAuth(h.handleHeaderRuleEditForm))
	mux.HandleFunc("POST "+h.path("/headerrules/{id}"), h.requirePOSTAuth(h.handleHeaderRuleUpdate))
	mux.HandleFunc("POST "+h.path("/headerrules/{id}/delete"), h.requirePOSTAuth(h.handleHeaderRuleDelete))

	mux.HandleFunc("GET "+h.path("/settings"), h.requireAuth(h.handleSettingsForm))
	mux.HandleFunc("POST "+h.path("/settings"), h.requirePOSTAuth(h.handleSettingsSave))

	mux.HandleFunc("GET "+h.path("/about"), h.requireAuth(h.handleAbout))

	// Catch-all под базовым путём: всё, что не подошло более специфичным
	// маршрутам выше (у ServeMux литерал всегда побеждает шаблон той же
	// длины), получает красивую 404-страницу вместо голого текста stdlib.
	catchAllPath := h.base + "/"
	if h.base == "" {
		catchAllPath = "/"
	}
	mux.HandleFunc(catchAllPath, h.requireAuth(func(w http.ResponseWriter, r *http.Request, s *session) {
		h.renderError(w, r, s, http.StatusNotFound, "Такой страницы нет")
	}))

	h.mux = mux
}
