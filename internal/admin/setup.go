package admin

import (
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/qwe8nxtroud/multigate/internal/model"
	"github.com/qwe8nxtroud/multigate/internal/store"
)

// setupPageData: данные страницы мастера первичной настройки.
type setupPageData struct {
	pageBase
	Error string
	Form  setupForm
}

// setupForm: то, что администратор ввёл на предыдущей попытке. При ошибке
// валидации незачем заставлять перепечатывать адрес панели и токен заново.
// Пароль сюда не попадает: его после ошибки нужно ввести повторно.
type setupForm struct {
	Username     string
	Mode         string
	PanelURL     string
	PanelToken   string
	MirrorTarget string
	Domain       string
}

// handleSetupForm показывает мастер. Доступен только на пустой базе:
// если первичная настройка уже пройдена, мастер отправляет на вход,
// чтобы им нельзя было воспользоваться для смены чужого пароля.
//
// Проверка installed идёт до ensureSession: если мастер уже закрыт (обычный
// случай в штатной работе), сессия под него не нужна вообще, и заводить её
// на каждый такой запрос незачем.
func (h *Handler) handleSetupForm(w http.ResponseWriter, r *http.Request) {
	if h.installed(r.Context()) {
		http.Redirect(w, r, h.path("/login"), http.StatusSeeOther)
		return
	}
	s := h.ensureSession(w, r)
	h.render(w, http.StatusOK, "setup.html", setupPageData{
		pageBase: h.newPageBase(r, s, "Первичная настройка", ""),
		Form: setupForm{
			Mode: string(model.ModeMirror),
		},
	})
}

// handleSetupSubmit сохраняет первичную настройку и сразу открывает сессию,
// чтобы администратор не вводил только что заданный пароль второй раз подряд.
func (h *Handler) handleSetupSubmit(w http.ResponseWriter, r *http.Request) {
	h.requirePOSTGuest(h.doSetup)(w, r)
}

func (h *Handler) doSetup(w http.ResponseWriter, r *http.Request, s *session) {
	if h.installed(r.Context()) {
		http.Redirect(w, r, h.path("/login"), http.StatusSeeOther)
		return
	}

	form := setupForm{
		Username:     strings.TrimSpace(r.PostFormValue("username")),
		Mode:         r.PostFormValue("mode"),
		PanelURL:     strings.TrimSpace(r.PostFormValue("panel_url")),
		PanelToken:   r.PostFormValue("panel_token"),
		MirrorTarget: strings.TrimSpace(r.PostFormValue("mirror_target")),
		Domain:       strings.TrimSpace(r.PostFormValue("domain")),
	}
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("password_confirm")

	if errMsg := validateSetup(form, password, confirm); errMsg != "" {
		h.render(w, http.StatusUnprocessableEntity, "setup.html", setupPageData{
			pageBase: h.newPageBase(r, s, "Первичная настройка", ""),
			Error:    errMsg,
			Form:     form,
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		h.log.Error("admin: не хешировать пароль администратора", "err", err)
		h.render(w, http.StatusInternalServerError, "setup.html", setupPageData{
			pageBase: h.newPageBase(r, s, "Первичная настройка", ""),
			Error:    "Не удалось сохранить пароль, попробуйте ещё раз",
			Form:     form,
		})
		return
	}

	kv := map[string]string{
		store.KeyAdminUser:    form.Username,
		store.KeyAdminHash:    string(hash),
		store.KeyMode:         form.Mode,
		store.KeyPanelURL:     form.PanelURL,
		store.KeyMirrorTarget: form.MirrorTarget,
		store.KeyOwnDomain:    form.Domain,
		store.KeyInstalled:    "1",
	}
	// Токен панели пишем отдельным ключом только если его вообще ввели:
	// в setMany он всё равно попадёт, но так виднее, что поле необязательное.
	if form.PanelToken != "" {
		kv[store.KeyPanelToken] = form.PanelToken
	}

	if err := h.store.SetMany(r.Context(), kv); err != nil {
		h.log.Error("admin: не сохранить первичную настройку", "err", err)
		h.render(w, http.StatusInternalServerError, "setup.html", setupPageData{
			pageBase: h.newPageBase(r, s, "Первичная настройка", ""),
			Error:    "Не удалось сохранить настройки, попробуйте ещё раз",
			Form:     form,
		})
		return
	}

	// Сразу открываем сессию тем же способом, что и обычный вход: новая
	// сессия вместо анонимной, чтобы не тащить её CSRF-токен дальше.
	h.sessions.destroy(s.id)
	ns := h.sessions.create()
	ns.user = form.Username
	setSessionCookie(w, r, h.base, ns.id, ns.expiresAt)
	h.sessions.setFlash(ns.id, "ok", "Настройка завершена, добро пожаловать")

	h.log.Info("admin: мастер первичной настройки завершён", "user", form.Username, "mode", form.Mode)
	http.Redirect(w, r, h.path("/overview"), http.StatusSeeOther)
}

// validateSetup проверяет форму мастера и возвращает текст ошибки для
// администратора (пустая строка: форма годная).
func validateSetup(f setupForm, password, confirm string) string {
	switch {
	case f.Username == "":
		return "Укажите логин администратора"
	case len(f.Username) > 190:
		return "Логин слишком длинный"
	case len(password) < 8:
		return "Пароль должен быть не короче 8 символов"
	case password != confirm:
		return "Пароли не совпадают"
	case f.Mode != string(model.ModeMirror) && f.Mode != string(model.ModePanel):
		return "Выберите режим работы"
	case f.Mode == string(model.ModePanel) && f.PanelURL == "":
		return "Для режима панели нужен адрес API панели"
	case f.Mode == string(model.ModeMirror) && f.MirrorTarget == "":
		return "Для режима зеркала нужен домен origin"
	default:
		return ""
	}
}
